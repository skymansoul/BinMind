
C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\test_samples\fmt_cve\fmt_08_snprintf_fmtarg\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 0f 85 00 00       	call   140009538 <fflush>
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
   1400010e8:	48 8b 05 51 f1 00 00 	mov    rax,QWORD PTR [rip+0xf151]        # 140010240 <__imp_Sleep>
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
   14000113b:	e8 b8 83 00 00       	call   1400094f8 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 b8 7d 00 00       	call   140008f20 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 f7 83 00 00       	call   140009578 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 87 83 00 00       	call   140009520 <abort>
   140001199:	e8 32 11 00 00       	call   1400022d0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 89 f0 00 00 	mov    rax,QWORD PTR [rip+0xf089]        # 140010238 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 f6 7c 00 00       	call   140008ec0 <_set_invalid_parameter_handler>
   1400011ca:	e8 11 1a 00 00       	call   140002be0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 f7 82 00 00       	call   1400094e8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 eb 82 00 00       	call   1400094e8 <__set_app_type>
   1400011fd:	e8 8e 7c 00 00       	call   140008e90 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 8e 7c 00 00       	call   140008ea0 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 8e 06 00 00       	call   1400018b0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 c3 82 00 00       	call   1400094f8 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 98 11 00 00       	call   1400023ea <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 96 7c 00 00       	call   140008f00 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 b0 7b 00 00       	call   140008e30 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 6a 82 00 00       	call   1400094f8 <_amsg_exit>
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
   1400012cb:	e8 08 82 00 00       	call   1400094d8 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 15 82 00 00       	call   1400094f8 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 ee 81 00 00       	call   1400094f8 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 f0 81 00 00       	call   140009510 <_initterm>
   140001320:	e8 62 05 00 00       	call   140001887 <__main>
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
   14000138d:	e8 1e 7b 00 00       	call   140008eb0 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 a6 03 00 00       	call   140001760 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 5f 81 00 00       	call   140009530 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 20 81 00 00       	call   140009500 <_cexit>
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
   140001511:	e8 4a 80 00 00       	call   140009560 <malloc>
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
   14000155c:	e8 2f 80 00 00       	call   140009590 <strlen>
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
   140001585:	e8 d6 7f 00 00       	call   140009560 <malloc>
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
   1400015e8:	e8 7b 7f 00 00       	call   140009568 <memcpy>
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
   140001642:	e8 d1 7e 00 00       	call   140009518 <_crt_atexit>
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
   140001682:	ff 15 80 eb 00 00    	call   QWORD PTR [rip+0xeb80]        # 140010208 <__imp_GetModuleHandleA>
   140001688:	48 89 c3             	mov    rbx,rax
   14000168b:	48 85 c0             	test   rax,rax
   14000168e:	74 70                	je     140001700 <__gcc_register_frame+0x90>
   140001690:	48 8d 0d 69 99 00 00 	lea    rcx,[rip+0x9969]        # 14000b000 <.rdata>
   140001697:	ff 15 8b eb 00 00    	call   QWORD PTR [rip+0xeb8b]        # 140010228 <__imp_LoadLibraryA>
   14000169d:	4c 8b 0d 6c eb 00 00 	mov    r9,QWORD PTR [rip+0xeb6c]        # 140010210 <__imp_GetProcAddress>
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
   14000174e:	48 ff 25 9b ea 00 00 	rex.W jmp QWORD PTR [rip+0xea9b]        # 1400101f0 <__imp_FreeLibrary>
   140001755:	0f 1f 00             	nop    DWORD PTR [rax]
   140001758:	48 83 c4 20          	add    rsp,0x20
   14000175c:	5d                   	pop    rbp
   14000175d:	c3                   	ret
   14000175e:	90                   	nop
   14000175f:	90                   	nop

0000000140001760 <main>:
   140001760:	55                   	push   rbp
   140001761:	48 81 ec 20 01 00 00 	sub    rsp,0x120
   140001768:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   14000176f:	00 
   140001770:	89 8d b0 00 00 00    	mov    DWORD PTR [rbp+0xb0],ecx
   140001776:	48 89 95 b8 00 00 00 	mov    QWORD PTR [rbp+0xb8],rdx
   14000177d:	e8 05 01 00 00       	call   140001887 <__main>
   140001782:	48 8b 85 b8 00 00 00 	mov    rax,QWORD PTR [rbp+0xb8]
   140001789:	48 83 c0 08          	add    rax,0x8
   14000178d:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140001790:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140001794:	41 b9 07 00 00 00    	mov    r9d,0x7
   14000179a:	49 89 d0             	mov    r8,rdx
   14000179d:	ba 00 01 00 00       	mov    edx,0x100
   1400017a2:	48 89 c1             	mov    rcx,rax
   1400017a5:	e8 36 19 00 00       	call   1400030e0 <__mingw_snprintf>
   1400017aa:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400017ae:	48 89 c1             	mov    rcx,rax
   1400017b1:	e8 ba 7d 00 00       	call   140009570 <puts>
   1400017b6:	b8 00 00 00 00       	mov    eax,0x0
   1400017bb:	48 81 c4 20 01 00 00 	add    rsp,0x120
   1400017c2:	5d                   	pop    rbp
   1400017c3:	c3                   	ret
   1400017c4:	90                   	nop
   1400017c5:	90                   	nop
   1400017c6:	90                   	nop
   1400017c7:	90                   	nop
   1400017c8:	90                   	nop
   1400017c9:	90                   	nop
   1400017ca:	90                   	nop
   1400017cb:	90                   	nop
   1400017cc:	90                   	nop
   1400017cd:	90                   	nop
   1400017ce:	90                   	nop
   1400017cf:	90                   	nop

00000001400017d0 <__do_global_dtors>:
   1400017d0:	55                   	push   rbp
   1400017d1:	48 89 e5             	mov    rbp,rsp
   1400017d4:	48 83 ec 20          	sub    rsp,0x20
   1400017d8:	eb 1e                	jmp    1400017f8 <__do_global_dtors+0x28>
   1400017da:	48 8b 05 2f 88 00 00 	mov    rax,QWORD PTR [rip+0x882f]        # 14000a010 <p.0>
   1400017e1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017e4:	ff d0                	call   rax
   1400017e6:	48 8b 05 23 88 00 00 	mov    rax,QWORD PTR [rip+0x8823]        # 14000a010 <p.0>
   1400017ed:	48 83 c0 08          	add    rax,0x8
   1400017f1:	48 89 05 18 88 00 00 	mov    QWORD PTR [rip+0x8818],rax        # 14000a010 <p.0>
   1400017f8:	48 8b 05 11 88 00 00 	mov    rax,QWORD PTR [rip+0x8811]        # 14000a010 <p.0>
   1400017ff:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001802:	48 85 c0             	test   rax,rax
   140001805:	75 d3                	jne    1400017da <__do_global_dtors+0xa>
   140001807:	90                   	nop
   140001808:	90                   	nop
   140001809:	48 83 c4 20          	add    rsp,0x20
   14000180d:	5d                   	pop    rbp
   14000180e:	c3                   	ret

000000014000180f <__do_global_ctors>:
   14000180f:	55                   	push   rbp
   140001810:	48 89 e5             	mov    rbp,rsp
   140001813:	48 83 ec 30          	sub    rsp,0x30
   140001817:	48 8b 05 52 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d52]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000181e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001821:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001824:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001828:	75 25                	jne    14000184f <__do_global_ctors+0x40>
   14000182a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001831:	eb 04                	jmp    140001837 <__do_global_ctors+0x28>
   140001833:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001837:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000183a:	8d 50 01             	lea    edx,[rax+0x1]
   14000183d:	48 8b 05 2c 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d2c]        # 14000b570 <.refptr.__CTOR_LIST__>
   140001844:	89 d2                	mov    edx,edx
   140001846:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000184a:	48 85 c0             	test   rax,rax
   14000184d:	75 e4                	jne    140001833 <__do_global_ctors+0x24>
   14000184f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001852:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001855:	eb 14                	jmp    14000186b <__do_global_ctors+0x5c>
   140001857:	48 8b 05 12 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d12]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000185e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001861:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001865:	ff d0                	call   rax
   140001867:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000186b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000186f:	75 e6                	jne    140001857 <__do_global_ctors+0x48>
   140001871:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400017d0 <__do_global_dtors>
   140001878:	48 89 c1             	mov    rcx,rax
   14000187b:	e8 af fd ff ff       	call   14000162f <atexit>
   140001880:	90                   	nop
   140001881:	48 83 c4 30          	add    rsp,0x30
   140001885:	5d                   	pop    rbp
   140001886:	c3                   	ret

0000000140001887 <__main>:
   140001887:	55                   	push   rbp
   140001888:	48 89 e5             	mov    rbp,rsp
   14000188b:	48 83 ec 20          	sub    rsp,0x20
   14000188f:	8b 05 eb d7 00 00    	mov    eax,DWORD PTR [rip+0xd7eb]        # 14000f080 <initialized>
   140001895:	85 c0                	test   eax,eax
   140001897:	75 0f                	jne    1400018a8 <__main+0x21>
   140001899:	c7 05 dd d7 00 00 01 	mov    DWORD PTR [rip+0xd7dd],0x1        # 14000f080 <initialized>
   1400018a0:	00 00 00 
   1400018a3:	e8 67 ff ff ff       	call   14000180f <__do_global_ctors>
   1400018a8:	90                   	nop
   1400018a9:	48 83 c4 20          	add    rsp,0x20
   1400018ad:	5d                   	pop    rbp
   1400018ae:	c3                   	ret
   1400018af:	90                   	nop

00000001400018b0 <_setargv>:
   1400018b0:	55                   	push   rbp
   1400018b1:	48 89 e5             	mov    rbp,rsp
   1400018b4:	b8 00 00 00 00       	mov    eax,0x0
   1400018b9:	5d                   	pop    rbp
   1400018ba:	c3                   	ret
   1400018bb:	90                   	nop
   1400018bc:	90                   	nop
   1400018bd:	90                   	nop
   1400018be:	90                   	nop
   1400018bf:	90                   	nop

00000001400018c0 <__dyn_tls_init>:
   1400018c0:	55                   	push   rbp
   1400018c1:	48 89 e5             	mov    rbp,rsp
   1400018c4:	48 83 ec 30          	sub    rsp,0x30
   1400018c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400018cc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400018cf:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400018d3:	48 8b 05 76 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c76]        # 14000b550 <.refptr._CRT_MT>
   1400018da:	8b 00                	mov    eax,DWORD PTR [rax]
   1400018dc:	83 f8 02             	cmp    eax,0x2
   1400018df:	74 0d                	je     1400018ee <__dyn_tls_init+0x2e>
   1400018e1:	48 8b 05 68 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c68]        # 14000b550 <.refptr._CRT_MT>
   1400018e8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400018ee:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   1400018f2:	74 1e                	je     140001912 <__dyn_tls_init+0x52>
   1400018f4:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   1400018f8:	75 5b                	jne    140001955 <__dyn_tls_init+0x95>
   1400018fa:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400018fe:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001901:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001905:	49 89 c8             	mov    r8,rcx
   140001908:	48 89 c1             	mov    rcx,rax
   14000190b:	e8 d1 11 00 00       	call   140002ae1 <__mingw_TLScallback>
   140001910:	eb 43                	jmp    140001955 <__dyn_tls_init+0x95>
   140001912:	48 8d 05 bf 9f 00 00 	lea    rax,[rip+0x9fbf]        # 14000b8d8 <___crt_xd_start__>
   140001919:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000191d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001922:	eb 22                	jmp    140001946 <__dyn_tls_init+0x86>
   140001924:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001928:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000192c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001930:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001933:	48 85 c0             	test   rax,rax
   140001936:	74 09                	je     140001941 <__dyn_tls_init+0x81>
   140001938:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000193c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000193f:	ff d0                	call   rax
   140001941:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001946:	48 8d 05 93 9f 00 00 	lea    rax,[rip+0x9f93]        # 14000b8e0 <__xd_z>
   14000194d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001951:	75 d1                	jne    140001924 <__dyn_tls_init+0x64>
   140001953:	eb 01                	jmp    140001956 <__dyn_tls_init+0x96>
   140001955:	90                   	nop
   140001956:	48 83 c4 30          	add    rsp,0x30
   14000195a:	5d                   	pop    rbp
   14000195b:	c3                   	ret

000000014000195c <__tlregdtor>:
   14000195c:	55                   	push   rbp
   14000195d:	48 89 e5             	mov    rbp,rsp
   140001960:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001964:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001969:	75 07                	jne    140001972 <__tlregdtor+0x16>
   14000196b:	b8 00 00 00 00       	mov    eax,0x0
   140001970:	eb 05                	jmp    140001977 <__tlregdtor+0x1b>
   140001972:	b8 00 00 00 00       	mov    eax,0x0
   140001977:	5d                   	pop    rbp
   140001978:	c3                   	ret

0000000140001979 <__dyn_tls_dtor>:
   140001979:	55                   	push   rbp
   14000197a:	48 89 e5             	mov    rbp,rsp
   14000197d:	48 83 ec 20          	sub    rsp,0x20
   140001981:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001985:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001988:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000198c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001990:	74 06                	je     140001998 <__dyn_tls_dtor+0x1f>
   140001992:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001996:	75 18                	jne    1400019b0 <__dyn_tls_dtor+0x37>
   140001998:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000199c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   14000199f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019a3:	49 89 c8             	mov    r8,rcx
   1400019a6:	48 89 c1             	mov    rcx,rax
   1400019a9:	e8 33 11 00 00       	call   140002ae1 <__mingw_TLScallback>
   1400019ae:	eb 01                	jmp    1400019b1 <__dyn_tls_dtor+0x38>
   1400019b0:	90                   	nop
   1400019b1:	48 83 c4 20          	add    rsp,0x20
   1400019b5:	5d                   	pop    rbp
   1400019b6:	c3                   	ret
   1400019b7:	90                   	nop
   1400019b8:	90                   	nop
   1400019b9:	90                   	nop
   1400019ba:	90                   	nop
   1400019bb:	90                   	nop
   1400019bc:	90                   	nop
   1400019bd:	90                   	nop
   1400019be:	90                   	nop
   1400019bf:	90                   	nop

00000001400019c0 <_matherr>:
   1400019c0:	55                   	push   rbp
   1400019c1:	53                   	push   rbx
   1400019c2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400019c9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400019ce:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   1400019d2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   1400019d6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   1400019db:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   1400019df:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   1400019e3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019e5:	83 f8 06             	cmp    eax,0x6
   1400019e8:	74 56                	je     140001a40 <_matherr+0x80>
   1400019ea:	83 f8 06             	cmp    eax,0x6
   1400019ed:	7f 78                	jg     140001a67 <_matherr+0xa7>
   1400019ef:	83 f8 05             	cmp    eax,0x5
   1400019f2:	74 59                	je     140001a4d <_matherr+0x8d>
   1400019f4:	83 f8 05             	cmp    eax,0x5
   1400019f7:	7f 6e                	jg     140001a67 <_matherr+0xa7>
   1400019f9:	83 f8 04             	cmp    eax,0x4
   1400019fc:	74 5c                	je     140001a5a <_matherr+0x9a>
   1400019fe:	83 f8 04             	cmp    eax,0x4
   140001a01:	7f 64                	jg     140001a67 <_matherr+0xa7>
   140001a03:	83 f8 03             	cmp    eax,0x3
   140001a06:	74 2b                	je     140001a33 <_matherr+0x73>
   140001a08:	83 f8 03             	cmp    eax,0x3
   140001a0b:	7f 5a                	jg     140001a67 <_matherr+0xa7>
   140001a0d:	83 f8 01             	cmp    eax,0x1
   140001a10:	74 07                	je     140001a19 <_matherr+0x59>
   140001a12:	83 f8 02             	cmp    eax,0x2
   140001a15:	74 0f                	je     140001a26 <_matherr+0x66>
   140001a17:	eb 4e                	jmp    140001a67 <_matherr+0xa7>
   140001a19:	48 8d 05 80 96 00 00 	lea    rax,[rip+0x9680]        # 14000b0a0 <.rdata>
   140001a20:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a24:	eb 4d                	jmp    140001a73 <_matherr+0xb3>
   140001a26:	48 8d 05 92 96 00 00 	lea    rax,[rip+0x9692]        # 14000b0bf <.rdata+0x1f>
   140001a2d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a31:	eb 40                	jmp    140001a73 <_matherr+0xb3>
   140001a33:	48 8d 05 a6 96 00 00 	lea    rax,[rip+0x96a6]        # 14000b0e0 <.rdata+0x40>
   140001a3a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a3e:	eb 33                	jmp    140001a73 <_matherr+0xb3>
   140001a40:	48 8d 05 b9 96 00 00 	lea    rax,[rip+0x96b9]        # 14000b100 <.rdata+0x60>
   140001a47:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a4b:	eb 26                	jmp    140001a73 <_matherr+0xb3>
   140001a4d:	48 8d 05 d4 96 00 00 	lea    rax,[rip+0x96d4]        # 14000b128 <.rdata+0x88>
   140001a54:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a58:	eb 19                	jmp    140001a73 <_matherr+0xb3>
   140001a5a:	48 8d 05 ef 96 00 00 	lea    rax,[rip+0x96ef]        # 14000b150 <.rdata+0xb0>
   140001a61:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a65:	eb 0c                	jmp    140001a73 <_matherr+0xb3>
   140001a67:	48 8d 05 18 97 00 00 	lea    rax,[rip+0x9718]        # 14000b186 <.rdata+0xe6>
   140001a6e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a72:	90                   	nop
   140001a73:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a77:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001a7d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a81:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001a86:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a8a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001a8f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a93:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001a97:	b9 02 00 00 00       	mov    ecx,0x2
   140001a9c:	e8 7f 74 00 00       	call   140008f20 <__acrt_iob_func>
   140001aa1:	48 89 c1             	mov    rcx,rax
   140001aa4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001aa8:	48 8d 05 e9 96 00 00 	lea    rax,[rip+0x96e9]        # 14000b198 <.rdata+0xf8>
   140001aaf:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001ab6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001abc:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001ac2:	49 89 d9             	mov    r9,rbx
   140001ac5:	49 89 d0             	mov    r8,rdx
   140001ac8:	48 89 c2             	mov    rdx,rax
   140001acb:	e8 70 7a 00 00       	call   140009540 <fprintf>
   140001ad0:	b8 00 00 00 00       	mov    eax,0x0
   140001ad5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001ad9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001add:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001ae2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001ae9:	5b                   	pop    rbx
   140001aea:	5d                   	pop    rbp
   140001aeb:	c3                   	ret
   140001aec:	90                   	nop
   140001aed:	90                   	nop
   140001aee:	90                   	nop
   140001aef:	90                   	nop

0000000140001af0 <__report_error>:
   140001af0:	55                   	push   rbp
   140001af1:	53                   	push   rbx
   140001af2:	48 83 ec 38          	sub    rsp,0x38
   140001af6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001afb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001aff:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b03:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b07:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b0b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b0f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b13:	b9 02 00 00 00       	mov    ecx,0x2
   140001b18:	e8 03 74 00 00       	call   140008f20 <__acrt_iob_func>
   140001b1d:	48 89 c1             	mov    rcx,rax
   140001b20:	48 8d 05 a9 96 00 00 	lea    rax,[rip+0x96a9]        # 14000b1d0 <.rdata>
   140001b27:	48 89 c2             	mov    rdx,rax
   140001b2a:	e8 11 7a 00 00       	call   140009540 <fprintf>
   140001b2f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b33:	b9 02 00 00 00       	mov    ecx,0x2
   140001b38:	e8 e3 73 00 00       	call   140008f20 <__acrt_iob_func>
   140001b3d:	48 89 c1             	mov    rcx,rax
   140001b40:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b44:	49 89 d8             	mov    r8,rbx
   140001b47:	48 89 c2             	mov    rdx,rax
   140001b4a:	e8 51 7a 00 00       	call   1400095a0 <vfprintf>
   140001b4f:	e8 cc 79 00 00       	call   140009520 <abort>
   140001b54:	90                   	nop

0000000140001b55 <mark_section_writable>:
   140001b55:	55                   	push   rbp
   140001b56:	48 89 e5             	mov    rbp,rsp
   140001b59:	48 83 ec 60          	sub    rsp,0x60
   140001b5d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b61:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001b68:	e9 82 00 00 00       	jmp    140001bef <mark_section_writable+0x9a>
   140001b6d:	48 8b 0d 6c d5 00 00 	mov    rcx,QWORD PTR [rip+0xd56c]        # 14000f0e0 <the_secs>
   140001b74:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b77:	48 63 d0             	movsxd rdx,eax
   140001b7a:	48 89 d0             	mov    rax,rdx
   140001b7d:	48 c1 e0 02          	shl    rax,0x2
   140001b81:	48 01 d0             	add    rax,rdx
   140001b84:	48 c1 e0 03          	shl    rax,0x3
   140001b88:	48 01 c8             	add    rax,rcx
   140001b8b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001b8f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001b93:	72 56                	jb     140001beb <mark_section_writable+0x96>
   140001b95:	48 8b 0d 44 d5 00 00 	mov    rcx,QWORD PTR [rip+0xd544]        # 14000f0e0 <the_secs>
   140001b9c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b9f:	48 63 d0             	movsxd rdx,eax
   140001ba2:	48 89 d0             	mov    rax,rdx
   140001ba5:	48 c1 e0 02          	shl    rax,0x2
   140001ba9:	48 01 d0             	add    rax,rdx
   140001bac:	48 c1 e0 03          	shl    rax,0x3
   140001bb0:	48 01 c8             	add    rax,rcx
   140001bb3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001bb7:	4c 8b 05 22 d5 00 00 	mov    r8,QWORD PTR [rip+0xd522]        # 14000f0e0 <the_secs>
   140001bbe:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bc1:	48 63 d0             	movsxd rdx,eax
   140001bc4:	48 89 d0             	mov    rax,rdx
   140001bc7:	48 c1 e0 02          	shl    rax,0x2
   140001bcb:	48 01 d0             	add    rax,rdx
   140001bce:	48 c1 e0 03          	shl    rax,0x3
   140001bd2:	4c 01 c0             	add    rax,r8
   140001bd5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001bd9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001bdc:	89 c0                	mov    eax,eax
   140001bde:	48 01 c8             	add    rax,rcx
   140001be1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001be5:	0f 82 41 02 00 00    	jb     140001e2c <mark_section_writable+0x2d7>
   140001beb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001bef:	8b 05 f3 d4 00 00    	mov    eax,DWORD PTR [rip+0xd4f3]        # 14000f0e8 <maxSections>
   140001bf5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001bf8:	0f 8c 6f ff ff ff    	jl     140001b6d <mark_section_writable+0x18>
   140001bfe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c02:	48 89 c1             	mov    rcx,rax
   140001c05:	e8 c1 11 00 00       	call   140002dcb <__mingw_GetSectionForAddress>
   140001c0a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c0e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c13:	75 13                	jne    140001c28 <mark_section_writable+0xd3>
   140001c15:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c19:	48 8d 0d d0 95 00 00 	lea    rcx,[rip+0x95d0]        # 14000b1f0 <.rdata+0x20>
   140001c20:	48 89 c2             	mov    rdx,rax
   140001c23:	e8 c8 fe ff ff       	call   140001af0 <__report_error>
   140001c28:	48 8b 0d b1 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd4b1]        # 14000f0e0 <the_secs>
   140001c2f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c32:	48 63 d0             	movsxd rdx,eax
   140001c35:	48 89 d0             	mov    rax,rdx
   140001c38:	48 c1 e0 02          	shl    rax,0x2
   140001c3c:	48 01 d0             	add    rax,rdx
   140001c3f:	48 c1 e0 03          	shl    rax,0x3
   140001c43:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c47:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c4b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c4f:	48 8b 0d 8a d4 00 00 	mov    rcx,QWORD PTR [rip+0xd48a]        # 14000f0e0 <the_secs>
   140001c56:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c59:	48 63 d0             	movsxd rdx,eax
   140001c5c:	48 89 d0             	mov    rax,rdx
   140001c5f:	48 c1 e0 02          	shl    rax,0x2
   140001c63:	48 01 d0             	add    rax,rdx
   140001c66:	48 c1 e0 03          	shl    rax,0x3
   140001c6a:	48 01 c8             	add    rax,rcx
   140001c6d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001c73:	e8 9f 12 00 00       	call   140002f17 <_GetPEImageBase>
   140001c78:	48 89 c1             	mov    rcx,rax
   140001c7b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c7f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001c82:	41 89 c1             	mov    r9d,eax
   140001c85:	4c 8b 05 54 d4 00 00 	mov    r8,QWORD PTR [rip+0xd454]        # 14000f0e0 <the_secs>
   140001c8c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c8f:	48 63 d0             	movsxd rdx,eax
   140001c92:	48 89 d0             	mov    rax,rdx
   140001c95:	48 c1 e0 02          	shl    rax,0x2
   140001c99:	48 01 d0             	add    rax,rdx
   140001c9c:	48 c1 e0 03          	shl    rax,0x3
   140001ca0:	4c 01 c0             	add    rax,r8
   140001ca3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001ca7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001cab:	48 8b 0d 2e d4 00 00 	mov    rcx,QWORD PTR [rip+0xd42e]        # 14000f0e0 <the_secs>
   140001cb2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cb5:	48 63 d0             	movsxd rdx,eax
   140001cb8:	48 89 d0             	mov    rax,rdx
   140001cbb:	48 c1 e0 02          	shl    rax,0x2
   140001cbf:	48 01 d0             	add    rax,rdx
   140001cc2:	48 c1 e0 03          	shl    rax,0x3
   140001cc6:	48 01 c8             	add    rax,rcx
   140001cc9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001ccd:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001cd1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001cd7:	48 89 c1             	mov    rcx,rax
   140001cda:	48 8b 05 77 e5 00 00 	mov    rax,QWORD PTR [rip+0xe577]        # 140010258 <__imp_VirtualQuery>
   140001ce1:	ff d0                	call   rax
   140001ce3:	48 85 c0             	test   rax,rax
   140001ce6:	75 3f                	jne    140001d27 <mark_section_writable+0x1d2>
   140001ce8:	48 8b 0d f1 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3f1]        # 14000f0e0 <the_secs>
   140001cef:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cf2:	48 63 d0             	movsxd rdx,eax
   140001cf5:	48 89 d0             	mov    rax,rdx
   140001cf8:	48 c1 e0 02          	shl    rax,0x2
   140001cfc:	48 01 d0             	add    rax,rdx
   140001cff:	48 c1 e0 03          	shl    rax,0x3
   140001d03:	48 01 c8             	add    rax,rcx
   140001d06:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d0a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d0e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d11:	89 c1                	mov    ecx,eax
   140001d13:	48 8d 05 f6 94 00 00 	lea    rax,[rip+0x94f6]        # 14000b210 <.rdata+0x40>
   140001d1a:	49 89 d0             	mov    r8,rdx
   140001d1d:	89 ca                	mov    edx,ecx
   140001d1f:	48 89 c1             	mov    rcx,rax
   140001d22:	e8 c9 fd ff ff       	call   140001af0 <__report_error>
   140001d27:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d2a:	83 f8 40             	cmp    eax,0x40
   140001d2d:	0f 84 e8 00 00 00    	je     140001e1b <mark_section_writable+0x2c6>
   140001d33:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d36:	83 f8 04             	cmp    eax,0x4
   140001d39:	0f 84 dc 00 00 00    	je     140001e1b <mark_section_writable+0x2c6>
   140001d3f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d42:	3d 80 00 00 00       	cmp    eax,0x80
   140001d47:	0f 84 ce 00 00 00    	je     140001e1b <mark_section_writable+0x2c6>
   140001d4d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d50:	83 f8 08             	cmp    eax,0x8
   140001d53:	0f 84 c2 00 00 00    	je     140001e1b <mark_section_writable+0x2c6>
   140001d59:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d5c:	83 f8 02             	cmp    eax,0x2
   140001d5f:	75 09                	jne    140001d6a <mark_section_writable+0x215>
   140001d61:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001d68:	eb 07                	jmp    140001d71 <mark_section_writable+0x21c>
   140001d6a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001d71:	48 8b 0d 68 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd368]        # 14000f0e0 <the_secs>
   140001d78:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d7b:	48 63 d0             	movsxd rdx,eax
   140001d7e:	48 89 d0             	mov    rax,rdx
   140001d81:	48 c1 e0 02          	shl    rax,0x2
   140001d85:	48 01 d0             	add    rax,rdx
   140001d88:	48 c1 e0 03          	shl    rax,0x3
   140001d8c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d90:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001d94:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001d98:	48 8b 0d 41 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd341]        # 14000f0e0 <the_secs>
   140001d9f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001da2:	48 63 d0             	movsxd rdx,eax
   140001da5:	48 89 d0             	mov    rax,rdx
   140001da8:	48 c1 e0 02          	shl    rax,0x2
   140001dac:	48 01 d0             	add    rax,rdx
   140001daf:	48 c1 e0 03          	shl    rax,0x3
   140001db3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001db7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001dbb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001dbf:	48 8b 0d 1a d3 00 00 	mov    rcx,QWORD PTR [rip+0xd31a]        # 14000f0e0 <the_secs>
   140001dc6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dc9:	48 63 d0             	movsxd rdx,eax
   140001dcc:	48 89 d0             	mov    rax,rdx
   140001dcf:	48 c1 e0 02          	shl    rax,0x2
   140001dd3:	48 01 d0             	add    rax,rdx
   140001dd6:	48 c1 e0 03          	shl    rax,0x3
   140001dda:	48 01 c8             	add    rax,rcx
   140001ddd:	49 89 c0             	mov    r8,rax
   140001de0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001de4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001de8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001deb:	4d 89 c1             	mov    r9,r8
   140001dee:	41 89 c8             	mov    r8d,ecx
   140001df1:	48 89 c1             	mov    rcx,rax
   140001df4:	48 8b 05 55 e4 00 00 	mov    rax,QWORD PTR [rip+0xe455]        # 140010250 <__imp_VirtualProtect>
   140001dfb:	ff d0                	call   rax
   140001dfd:	85 c0                	test   eax,eax
   140001dff:	75 1a                	jne    140001e1b <mark_section_writable+0x2c6>
   140001e01:	48 8b 05 f8 e3 00 00 	mov    rax,QWORD PTR [rip+0xe3f8]        # 140010200 <__imp_GetLastError>
   140001e08:	ff d0                	call   rax
   140001e0a:	89 c2                	mov    edx,eax
   140001e0c:	48 8d 05 35 94 00 00 	lea    rax,[rip+0x9435]        # 14000b248 <.rdata+0x78>
   140001e13:	48 89 c1             	mov    rcx,rax
   140001e16:	e8 d5 fc ff ff       	call   140001af0 <__report_error>
   140001e1b:	8b 05 c7 d2 00 00    	mov    eax,DWORD PTR [rip+0xd2c7]        # 14000f0e8 <maxSections>
   140001e21:	83 c0 01             	add    eax,0x1
   140001e24:	89 05 be d2 00 00    	mov    DWORD PTR [rip+0xd2be],eax        # 14000f0e8 <maxSections>
   140001e2a:	eb 01                	jmp    140001e2d <mark_section_writable+0x2d8>
   140001e2c:	90                   	nop
   140001e2d:	48 83 c4 60          	add    rsp,0x60
   140001e31:	5d                   	pop    rbp
   140001e32:	c3                   	ret

0000000140001e33 <restore_modified_sections>:
   140001e33:	55                   	push   rbp
   140001e34:	48 89 e5             	mov    rbp,rsp
   140001e37:	48 83 ec 30          	sub    rsp,0x30
   140001e3b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e42:	e9 ad 00 00 00       	jmp    140001ef4 <restore_modified_sections+0xc1>
   140001e47:	48 8b 0d 92 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd292]        # 14000f0e0 <the_secs>
   140001e4e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e51:	48 63 d0             	movsxd rdx,eax
   140001e54:	48 89 d0             	mov    rax,rdx
   140001e57:	48 c1 e0 02          	shl    rax,0x2
   140001e5b:	48 01 d0             	add    rax,rdx
   140001e5e:	48 c1 e0 03          	shl    rax,0x3
   140001e62:	48 01 c8             	add    rax,rcx
   140001e65:	8b 00                	mov    eax,DWORD PTR [rax]
   140001e67:	85 c0                	test   eax,eax
   140001e69:	0f 84 80 00 00 00    	je     140001eef <restore_modified_sections+0xbc>
   140001e6f:	48 8b 0d 6a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd26a]        # 14000f0e0 <the_secs>
   140001e76:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e79:	48 63 d0             	movsxd rdx,eax
   140001e7c:	48 89 d0             	mov    rax,rdx
   140001e7f:	48 c1 e0 02          	shl    rax,0x2
   140001e83:	48 01 d0             	add    rax,rdx
   140001e86:	48 c1 e0 03          	shl    rax,0x3
   140001e8a:	48 01 c8             	add    rax,rcx
   140001e8d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001e90:	48 8b 0d 49 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd249]        # 14000f0e0 <the_secs>
   140001e97:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e9a:	48 63 d0             	movsxd rdx,eax
   140001e9d:	48 89 d0             	mov    rax,rdx
   140001ea0:	48 c1 e0 02          	shl    rax,0x2
   140001ea4:	48 01 d0             	add    rax,rdx
   140001ea7:	48 c1 e0 03          	shl    rax,0x3
   140001eab:	48 01 c8             	add    rax,rcx
   140001eae:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001eb2:	4c 8b 05 27 d2 00 00 	mov    r8,QWORD PTR [rip+0xd227]        # 14000f0e0 <the_secs>
   140001eb9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ebc:	48 63 d0             	movsxd rdx,eax
   140001ebf:	48 89 d0             	mov    rax,rdx
   140001ec2:	48 c1 e0 02          	shl    rax,0x2
   140001ec6:	48 01 d0             	add    rax,rdx
   140001ec9:	48 c1 e0 03          	shl    rax,0x3
   140001ecd:	4c 01 c0             	add    rax,r8
   140001ed0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001ed4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001ed8:	49 89 d1             	mov    r9,rdx
   140001edb:	45 89 d0             	mov    r8d,r10d
   140001ede:	48 89 ca             	mov    rdx,rcx
   140001ee1:	48 89 c1             	mov    rcx,rax
   140001ee4:	48 8b 05 65 e3 00 00 	mov    rax,QWORD PTR [rip+0xe365]        # 140010250 <__imp_VirtualProtect>
   140001eeb:	ff d0                	call   rax
   140001eed:	eb 01                	jmp    140001ef0 <restore_modified_sections+0xbd>
   140001eef:	90                   	nop
   140001ef0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001ef4:	8b 05 ee d1 00 00    	mov    eax,DWORD PTR [rip+0xd1ee]        # 14000f0e8 <maxSections>
   140001efa:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001efd:	0f 8c 44 ff ff ff    	jl     140001e47 <restore_modified_sections+0x14>
   140001f03:	90                   	nop
   140001f04:	90                   	nop
   140001f05:	48 83 c4 30          	add    rsp,0x30
   140001f09:	5d                   	pop    rbp
   140001f0a:	c3                   	ret

0000000140001f0b <__write_memory>:
   140001f0b:	55                   	push   rbp
   140001f0c:	48 89 e5             	mov    rbp,rsp
   140001f0f:	48 83 ec 20          	sub    rsp,0x20
   140001f13:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f17:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f1b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f1f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f24:	74 25                	je     140001f4b <__write_memory+0x40>
   140001f26:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f2a:	48 89 c1             	mov    rcx,rax
   140001f2d:	e8 23 fc ff ff       	call   140001b55 <mark_section_writable>
   140001f32:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f36:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f3a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f3e:	49 89 c8             	mov    r8,rcx
   140001f41:	48 89 c1             	mov    rcx,rax
   140001f44:	e8 1f 76 00 00       	call   140009568 <memcpy>
   140001f49:	eb 01                	jmp    140001f4c <__write_memory+0x41>
   140001f4b:	90                   	nop
   140001f4c:	48 83 c4 20          	add    rsp,0x20
   140001f50:	5d                   	pop    rbp
   140001f51:	c3                   	ret

0000000140001f52 <do_pseudo_reloc>:
   140001f52:	55                   	push   rbp
   140001f53:	48 89 e5             	mov    rbp,rsp
   140001f56:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001f5a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f5e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f62:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f66:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001f6a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001f6e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001f72:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f76:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001f7a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001f7f:	0f 8e 44 03 00 00    	jle    1400022c9 <do_pseudo_reloc+0x377>
   140001f85:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001f8a:	7e 25                	jle    140001fb1 <do_pseudo_reloc+0x5f>
   140001f8c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f90:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f92:	85 c0                	test   eax,eax
   140001f94:	75 1b                	jne    140001fb1 <do_pseudo_reloc+0x5f>
   140001f96:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f9a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001f9d:	85 c0                	test   eax,eax
   140001f9f:	75 10                	jne    140001fb1 <do_pseudo_reloc+0x5f>
   140001fa1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fa5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001fa8:	85 c0                	test   eax,eax
   140001faa:	75 05                	jne    140001fb1 <do_pseudo_reloc+0x5f>
   140001fac:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140001fb1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fb5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fb7:	85 c0                	test   eax,eax
   140001fb9:	75 0b                	jne    140001fc6 <do_pseudo_reloc+0x74>
   140001fbb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fbf:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fc2:	85 c0                	test   eax,eax
   140001fc4:	74 59                	je     14000201f <do_pseudo_reloc+0xcd>
   140001fc6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fca:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001fce:	eb 40                	jmp    140002010 <do_pseudo_reloc+0xbe>
   140001fd0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001fd4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fd7:	89 c2                	mov    edx,eax
   140001fd9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001fdd:	48 01 d0             	add    rax,rdx
   140001fe0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001fe4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001fe8:	8b 10                	mov    edx,DWORD PTR [rax]
   140001fea:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001fee:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ff0:	01 d0                	add    eax,edx
   140001ff2:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140001ff5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001ff9:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   140001ffd:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002003:	48 89 c1             	mov    rcx,rax
   140002006:	e8 00 ff ff ff       	call   140001f0b <__write_memory>
   14000200b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002010:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002014:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002018:	72 b6                	jb     140001fd0 <do_pseudo_reloc+0x7e>
   14000201a:	e9 ab 02 00 00       	jmp    1400022ca <do_pseudo_reloc+0x378>
   14000201f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002023:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002026:	83 f8 01             	cmp    eax,0x1
   140002029:	74 18                	je     140002043 <do_pseudo_reloc+0xf1>
   14000202b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000202f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002032:	89 c2                	mov    edx,eax
   140002034:	48 8d 05 35 92 00 00 	lea    rax,[rip+0x9235]        # 14000b270 <.rdata+0xa0>
   14000203b:	48 89 c1             	mov    rcx,rax
   14000203e:	e8 ad fa ff ff       	call   140001af0 <__report_error>
   140002043:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002047:	48 83 c0 0c          	add    rax,0xc
   14000204b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000204f:	e9 65 02 00 00       	jmp    1400022b9 <do_pseudo_reloc+0x367>
   140002054:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002058:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000205b:	89 c2                	mov    edx,eax
   14000205d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002061:	48 01 d0             	add    rax,rdx
   140002064:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002068:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000206c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000206e:	89 c2                	mov    edx,eax
   140002070:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002074:	48 01 d0             	add    rax,rdx
   140002077:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000207b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000207f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002082:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002086:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000208a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000208d:	0f b6 c0             	movzx  eax,al
   140002090:	83 f8 40             	cmp    eax,0x40
   140002093:	0f 84 b6 00 00 00    	je     14000214f <do_pseudo_reloc+0x1fd>
   140002099:	83 f8 40             	cmp    eax,0x40
   14000209c:	0f 87 ba 00 00 00    	ja     14000215c <do_pseudo_reloc+0x20a>
   1400020a2:	83 f8 20             	cmp    eax,0x20
   1400020a5:	74 77                	je     14000211e <do_pseudo_reloc+0x1cc>
   1400020a7:	83 f8 20             	cmp    eax,0x20
   1400020aa:	0f 87 ac 00 00 00    	ja     14000215c <do_pseudo_reloc+0x20a>
   1400020b0:	83 f8 08             	cmp    eax,0x8
   1400020b3:	74 0a                	je     1400020bf <do_pseudo_reloc+0x16d>
   1400020b5:	83 f8 10             	cmp    eax,0x10
   1400020b8:	74 38                	je     1400020f2 <do_pseudo_reloc+0x1a0>
   1400020ba:	e9 9d 00 00 00       	jmp    14000215c <do_pseudo_reloc+0x20a>
   1400020bf:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020c3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400020c6:	0f b6 c0             	movzx  eax,al
   1400020c9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020cd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020d1:	25 80 00 00 00       	and    eax,0x80
   1400020d6:	48 85 c0             	test   rax,rax
   1400020d9:	0f 84 9d 00 00 00    	je     14000217c <do_pseudo_reloc+0x22a>
   1400020df:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020e3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400020e9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020ed:	e9 8a 00 00 00       	jmp    14000217c <do_pseudo_reloc+0x22a>
   1400020f2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020f6:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400020f9:	0f b7 c0             	movzx  eax,ax
   1400020fc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002100:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002104:	25 00 80 00 00       	and    eax,0x8000
   140002109:	48 85 c0             	test   rax,rax
   14000210c:	74 71                	je     14000217f <do_pseudo_reloc+0x22d>
   14000210e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002112:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002118:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000211c:	eb 61                	jmp    14000217f <do_pseudo_reloc+0x22d>
   14000211e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002122:	8b 00                	mov    eax,DWORD PTR [rax]
   140002124:	89 c0                	mov    eax,eax
   140002126:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000212a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000212e:	25 00 00 00 80       	and    eax,0x80000000
   140002133:	48 85 c0             	test   rax,rax
   140002136:	74 4a                	je     140002182 <do_pseudo_reloc+0x230>
   140002138:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000213c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002143:	ff ff ff 
   140002146:	48 09 d0             	or     rax,rdx
   140002149:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000214d:	eb 33                	jmp    140002182 <do_pseudo_reloc+0x230>
   14000214f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002153:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002156:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000215a:	eb 27                	jmp    140002183 <do_pseudo_reloc+0x231>
   14000215c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002163:	00 
   140002164:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002168:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000216b:	0f b6 c0             	movzx  eax,al
   14000216e:	48 8d 0d 33 91 00 00 	lea    rcx,[rip+0x9133]        # 14000b2a8 <.rdata+0xd8>
   140002175:	89 c2                	mov    edx,eax
   140002177:	e8 74 f9 ff ff       	call   140001af0 <__report_error>
   14000217c:	90                   	nop
   14000217d:	eb 04                	jmp    140002183 <do_pseudo_reloc+0x231>
   14000217f:	90                   	nop
   140002180:	eb 01                	jmp    140002183 <do_pseudo_reloc+0x231>
   140002182:	90                   	nop
   140002183:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002187:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000218b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000218d:	89 c2                	mov    edx,eax
   14000218f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002193:	48 01 c2             	add    rdx,rax
   140002196:	48 89 c8             	mov    rax,rcx
   140002199:	48 29 d0             	sub    rax,rdx
   14000219c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021a0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021a4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400021a8:	48 01 d0             	add    rax,rdx
   1400021ab:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021af:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021b3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021b6:	25 ff 00 00 00       	and    eax,0xff
   1400021bb:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400021be:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400021c2:	77 67                	ja     14000222b <do_pseudo_reloc+0x2d9>
   1400021c4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021c7:	ba 01 00 00 00       	mov    edx,0x1
   1400021cc:	89 c1                	mov    ecx,eax
   1400021ce:	48 d3 e2             	shl    rdx,cl
   1400021d1:	48 89 d0             	mov    rax,rdx
   1400021d4:	48 83 e8 01          	sub    rax,0x1
   1400021d8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400021dc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021df:	83 e8 01             	sub    eax,0x1
   1400021e2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400021e9:	89 c1                	mov    ecx,eax
   1400021eb:	48 d3 e2             	shl    rdx,cl
   1400021ee:	48 89 d0             	mov    rax,rdx
   1400021f1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400021f5:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021f9:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   1400021fd:	7c 0a                	jl     140002209 <do_pseudo_reloc+0x2b7>
   1400021ff:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002203:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002207:	7e 22                	jle    14000222b <do_pseudo_reloc+0x2d9>
   140002209:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000220d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002211:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002215:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002218:	48 8d 0d b9 90 00 00 	lea    rcx,[rip+0x90b9]        # 14000b2d8 <.rdata+0x108>
   14000221f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002224:	89 c2                	mov    edx,eax
   140002226:	e8 c5 f8 ff ff       	call   140001af0 <__report_error>
   14000222b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000222f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002232:	0f b6 c0             	movzx  eax,al
   140002235:	83 f8 40             	cmp    eax,0x40
   140002238:	74 63                	je     14000229d <do_pseudo_reloc+0x34b>
   14000223a:	83 f8 40             	cmp    eax,0x40
   14000223d:	77 75                	ja     1400022b4 <do_pseudo_reloc+0x362>
   14000223f:	83 f8 20             	cmp    eax,0x20
   140002242:	74 41                	je     140002285 <do_pseudo_reloc+0x333>
   140002244:	83 f8 20             	cmp    eax,0x20
   140002247:	77 6b                	ja     1400022b4 <do_pseudo_reloc+0x362>
   140002249:	83 f8 08             	cmp    eax,0x8
   14000224c:	74 07                	je     140002255 <do_pseudo_reloc+0x303>
   14000224e:	83 f8 10             	cmp    eax,0x10
   140002251:	74 1a                	je     14000226d <do_pseudo_reloc+0x31b>
   140002253:	eb 5f                	jmp    1400022b4 <do_pseudo_reloc+0x362>
   140002255:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002259:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000225d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002263:	48 89 c1             	mov    rcx,rax
   140002266:	e8 a0 fc ff ff       	call   140001f0b <__write_memory>
   14000226b:	eb 47                	jmp    1400022b4 <do_pseudo_reloc+0x362>
   14000226d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002271:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002275:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000227b:	48 89 c1             	mov    rcx,rax
   14000227e:	e8 88 fc ff ff       	call   140001f0b <__write_memory>
   140002283:	eb 2f                	jmp    1400022b4 <do_pseudo_reloc+0x362>
   140002285:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002289:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000228d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002293:	48 89 c1             	mov    rcx,rax
   140002296:	e8 70 fc ff ff       	call   140001f0b <__write_memory>
   14000229b:	eb 17                	jmp    1400022b4 <do_pseudo_reloc+0x362>
   14000229d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022a1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022a5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400022ab:	48 89 c1             	mov    rcx,rax
   1400022ae:	e8 58 fc ff ff       	call   140001f0b <__write_memory>
   1400022b3:	90                   	nop
   1400022b4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400022b9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022bd:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400022c1:	0f 82 8d fd ff ff    	jb     140002054 <do_pseudo_reloc+0x102>
   1400022c7:	eb 01                	jmp    1400022ca <do_pseudo_reloc+0x378>
   1400022c9:	90                   	nop
   1400022ca:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400022ce:	5d                   	pop    rbp
   1400022cf:	c3                   	ret

00000001400022d0 <_pei386_runtime_relocator>:
   1400022d0:	55                   	push   rbp
   1400022d1:	48 89 e5             	mov    rbp,rsp
   1400022d4:	48 83 ec 30          	sub    rsp,0x30
   1400022d8:	8b 05 0e ce 00 00    	mov    eax,DWORD PTR [rip+0xce0e]        # 14000f0ec <was_init.0>
   1400022de:	85 c0                	test   eax,eax
   1400022e0:	0f 85 88 00 00 00    	jne    14000236e <_pei386_runtime_relocator+0x9e>
   1400022e6:	8b 05 00 ce 00 00    	mov    eax,DWORD PTR [rip+0xce00]        # 14000f0ec <was_init.0>
   1400022ec:	83 c0 01             	add    eax,0x1
   1400022ef:	89 05 f7 cd 00 00    	mov    DWORD PTR [rip+0xcdf7],eax        # 14000f0ec <was_init.0>
   1400022f5:	e8 21 0b 00 00       	call   140002e1b <__mingw_GetSectionCount>
   1400022fa:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400022fd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002300:	48 63 d0             	movsxd rdx,eax
   140002303:	48 89 d0             	mov    rax,rdx
   140002306:	48 c1 e0 02          	shl    rax,0x2
   14000230a:	48 01 d0             	add    rax,rdx
   14000230d:	48 c1 e0 03          	shl    rax,0x3
   140002311:	48 83 c0 0f          	add    rax,0xf
   140002315:	48 c1 e8 04          	shr    rax,0x4
   140002319:	48 c1 e0 04          	shl    rax,0x4
   14000231d:	e8 7e 0d 00 00       	call   1400030a0 <___chkstk_ms>
   140002322:	48 29 c4             	sub    rsp,rax
   140002325:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000232a:	48 83 c0 0f          	add    rax,0xf
   14000232e:	48 c1 e8 04          	shr    rax,0x4
   140002332:	48 c1 e0 04          	shl    rax,0x4
   140002336:	48 89 05 a3 cd 00 00 	mov    QWORD PTR [rip+0xcda3],rax        # 14000f0e0 <the_secs>
   14000233d:	c7 05 a1 cd 00 00 00 	mov    DWORD PTR [rip+0xcda1],0x0        # 14000f0e8 <maxSections>
   140002344:	00 00 00 
   140002347:	48 8b 0d 32 92 00 00 	mov    rcx,QWORD PTR [rip+0x9232]        # 14000b580 <.refptr.__ImageBase>
   14000234e:	48 8b 15 3b 92 00 00 	mov    rdx,QWORD PTR [rip+0x923b]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002355:	48 8b 05 44 92 00 00 	mov    rax,QWORD PTR [rip+0x9244]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000235c:	49 89 c8             	mov    r8,rcx
   14000235f:	48 89 c1             	mov    rcx,rax
   140002362:	e8 eb fb ff ff       	call   140001f52 <do_pseudo_reloc>
   140002367:	e8 c7 fa ff ff       	call   140001e33 <restore_modified_sections>
   14000236c:	eb 01                	jmp    14000236f <_pei386_runtime_relocator+0x9f>
   14000236e:	90                   	nop
   14000236f:	48 89 ec             	mov    rsp,rbp
   140002372:	5d                   	pop    rbp
   140002373:	c3                   	ret
   140002374:	90                   	nop
   140002375:	90                   	nop
   140002376:	90                   	nop
   140002377:	90                   	nop
   140002378:	90                   	nop
   140002379:	90                   	nop
   14000237a:	90                   	nop
   14000237b:	90                   	nop
   14000237c:	90                   	nop
   14000237d:	90                   	nop
   14000237e:	90                   	nop
   14000237f:	90                   	nop

0000000140002380 <__mingw_raise_matherr>:
   140002380:	55                   	push   rbp
   140002381:	48 89 e5             	mov    rbp,rsp
   140002384:	48 83 ec 50          	sub    rsp,0x50
   140002388:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000238b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000238f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002394:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002399:	48 8b 05 50 cd 00 00 	mov    rax,QWORD PTR [rip+0xcd50]        # 14000f0f0 <stUserMathErr>
   1400023a0:	48 85 c0             	test   rax,rax
   1400023a3:	74 3e                	je     1400023e3 <__mingw_raise_matherr+0x63>
   1400023a5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400023a8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400023ab:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400023af:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400023b3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400023b8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400023bd:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400023c2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400023c7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400023cc:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400023d1:	48 8b 15 18 cd 00 00 	mov    rdx,QWORD PTR [rip+0xcd18]        # 14000f0f0 <stUserMathErr>
   1400023d8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400023dc:	48 89 c1             	mov    rcx,rax
   1400023df:	ff d2                	call   rdx
   1400023e1:	eb 01                	jmp    1400023e4 <__mingw_raise_matherr+0x64>
   1400023e3:	90                   	nop
   1400023e4:	48 83 c4 50          	add    rsp,0x50
   1400023e8:	5d                   	pop    rbp
   1400023e9:	c3                   	ret

00000001400023ea <__mingw_setusermatherr>:
   1400023ea:	55                   	push   rbp
   1400023eb:	48 89 e5             	mov    rbp,rsp
   1400023ee:	48 83 ec 20          	sub    rsp,0x20
   1400023f2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400023f6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400023fa:	48 89 05 ef cc 00 00 	mov    QWORD PTR [rip+0xccef],rax        # 14000f0f0 <stUserMathErr>
   140002401:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002405:	48 89 c1             	mov    rcx,rax
   140002408:	e8 e3 70 00 00       	call   1400094f0 <__setusermatherr>
   14000240d:	90                   	nop
   14000240e:	48 83 c4 20          	add    rsp,0x20
   140002412:	5d                   	pop    rbp
   140002413:	c3                   	ret
   140002414:	90                   	nop
   140002415:	90                   	nop
   140002416:	90                   	nop
   140002417:	90                   	nop
   140002418:	90                   	nop
   140002419:	90                   	nop
   14000241a:	90                   	nop
   14000241b:	90                   	nop
   14000241c:	90                   	nop
   14000241d:	90                   	nop
   14000241e:	90                   	nop
   14000241f:	90                   	nop

0000000140002420 <__mingw_SEH_error_handler>:
   140002420:	55                   	push   rbp
   140002421:	48 89 e5             	mov    rbp,rsp
   140002424:	48 83 ec 30          	sub    rsp,0x30
   140002428:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000242c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002430:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002434:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002438:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000243f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002446:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000244a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000244d:	83 e0 02             	and    eax,0x2
   140002450:	85 c0                	test   eax,eax
   140002452:	74 0a                	je     14000245e <__mingw_SEH_error_handler+0x3e>
   140002454:	b8 01 00 00 00       	mov    eax,0x1
   140002459:	e9 16 02 00 00       	jmp    140002674 <__mingw_SEH_error_handler+0x254>
   14000245e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002462:	8b 00                	mov    eax,DWORD PTR [rax]
   140002464:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002469:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000246e:	75 18                	jne    140002488 <__mingw_SEH_error_handler+0x68>
   140002470:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002474:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002477:	83 e0 01             	and    eax,0x1
   14000247a:	85 c0                	test   eax,eax
   14000247c:	75 0a                	jne    140002488 <__mingw_SEH_error_handler+0x68>
   14000247e:	b8 00 00 00 00       	mov    eax,0x0
   140002483:	e9 ec 01 00 00       	jmp    140002674 <__mingw_SEH_error_handler+0x254>
   140002488:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000248c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000248e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002493:	0f 84 12 01 00 00    	je     1400025ab <__mingw_SEH_error_handler+0x18b>
   140002499:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000249e:	0f 87 c3 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   1400024a4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400024a9:	0f 87 b8 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   1400024af:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400024b4:	0f 83 4c 01 00 00    	jae    140002606 <__mingw_SEH_error_handler+0x1e6>
   1400024ba:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024bf:	0f 84 3a 01 00 00    	je     1400025ff <__mingw_SEH_error_handler+0x1df>
   1400024c5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024ca:	0f 87 97 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   1400024d0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024d5:	0f 84 83 01 00 00    	je     14000265e <__mingw_SEH_error_handler+0x23e>
   1400024db:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024e0:	0f 87 81 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   1400024e6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400024eb:	0f 87 76 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   1400024f1:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400024f6:	0f 83 03 01 00 00    	jae    1400025ff <__mingw_SEH_error_handler+0x1df>
   1400024fc:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002501:	0f 84 57 01 00 00    	je     14000265e <__mingw_SEH_error_handler+0x23e>
   140002507:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000250c:	0f 87 55 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   140002512:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002517:	0f 84 8e 00 00 00    	je     1400025ab <__mingw_SEH_error_handler+0x18b>
   14000251d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002522:	0f 87 3f 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   140002528:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000252d:	0f 84 2b 01 00 00    	je     14000265e <__mingw_SEH_error_handler+0x23e>
   140002533:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002538:	0f 87 29 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   14000253e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002543:	0f 84 15 01 00 00    	je     14000265e <__mingw_SEH_error_handler+0x23e>
   140002549:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000254e:	0f 85 13 01 00 00    	jne    140002667 <__mingw_SEH_error_handler+0x247>
   140002554:	ba 00 00 00 00       	mov    edx,0x0
   140002559:	b9 0b 00 00 00       	mov    ecx,0xb
   14000255e:	e8 1d 70 00 00       	call   140009580 <signal>
   140002563:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002567:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000256c:	75 1b                	jne    140002589 <__mingw_SEH_error_handler+0x169>
   14000256e:	ba 01 00 00 00       	mov    edx,0x1
   140002573:	b9 0b 00 00 00       	mov    ecx,0xb
   140002578:	e8 03 70 00 00       	call   140009580 <signal>
   14000257d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002584:	e9 e1 00 00 00       	jmp    14000266a <__mingw_SEH_error_handler+0x24a>
   140002589:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000258e:	0f 84 d6 00 00 00    	je     14000266a <__mingw_SEH_error_handler+0x24a>
   140002594:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002598:	b9 0b 00 00 00       	mov    ecx,0xb
   14000259d:	ff d0                	call   rax
   14000259f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025a6:	e9 bf 00 00 00       	jmp    14000266a <__mingw_SEH_error_handler+0x24a>
   1400025ab:	ba 00 00 00 00       	mov    edx,0x0
   1400025b0:	b9 04 00 00 00       	mov    ecx,0x4
   1400025b5:	e8 c6 6f 00 00       	call   140009580 <signal>
   1400025ba:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025be:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025c3:	75 1b                	jne    1400025e0 <__mingw_SEH_error_handler+0x1c0>
   1400025c5:	ba 01 00 00 00       	mov    edx,0x1
   1400025ca:	b9 04 00 00 00       	mov    ecx,0x4
   1400025cf:	e8 ac 6f 00 00       	call   140009580 <signal>
   1400025d4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025db:	e9 8d 00 00 00       	jmp    14000266d <__mingw_SEH_error_handler+0x24d>
   1400025e0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025e5:	0f 84 82 00 00 00    	je     14000266d <__mingw_SEH_error_handler+0x24d>
   1400025eb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025ef:	b9 04 00 00 00       	mov    ecx,0x4
   1400025f4:	ff d0                	call   rax
   1400025f6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025fd:	eb 6e                	jmp    14000266d <__mingw_SEH_error_handler+0x24d>
   1400025ff:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002606:	ba 00 00 00 00       	mov    edx,0x0
   14000260b:	b9 08 00 00 00       	mov    ecx,0x8
   140002610:	e8 6b 6f 00 00       	call   140009580 <signal>
   140002615:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002619:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000261e:	75 23                	jne    140002643 <__mingw_SEH_error_handler+0x223>
   140002620:	ba 01 00 00 00       	mov    edx,0x1
   140002625:	b9 08 00 00 00       	mov    ecx,0x8
   14000262a:	e8 51 6f 00 00       	call   140009580 <signal>
   14000262f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002633:	74 05                	je     14000263a <__mingw_SEH_error_handler+0x21a>
   140002635:	e8 a6 05 00 00       	call   140002be0 <_fpreset>
   14000263a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002641:	eb 2d                	jmp    140002670 <__mingw_SEH_error_handler+0x250>
   140002643:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002648:	74 26                	je     140002670 <__mingw_SEH_error_handler+0x250>
   14000264a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000264e:	b9 08 00 00 00       	mov    ecx,0x8
   140002653:	ff d0                	call   rax
   140002655:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000265c:	eb 12                	jmp    140002670 <__mingw_SEH_error_handler+0x250>
   14000265e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002665:	eb 0a                	jmp    140002671 <__mingw_SEH_error_handler+0x251>
   140002667:	90                   	nop
   140002668:	eb 07                	jmp    140002671 <__mingw_SEH_error_handler+0x251>
   14000266a:	90                   	nop
   14000266b:	eb 04                	jmp    140002671 <__mingw_SEH_error_handler+0x251>
   14000266d:	90                   	nop
   14000266e:	eb 01                	jmp    140002671 <__mingw_SEH_error_handler+0x251>
   140002670:	90                   	nop
   140002671:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002674:	48 83 c4 30          	add    rsp,0x30
   140002678:	5d                   	pop    rbp
   140002679:	c3                   	ret

000000014000267a <_gnu_exception_handler>:
   14000267a:	55                   	push   rbp
   14000267b:	48 89 e5             	mov    rbp,rsp
   14000267e:	48 83 ec 30          	sub    rsp,0x30
   140002682:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002686:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000268d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002694:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002698:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000269b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000269d:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400026a2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400026a7:	75 1b                	jne    1400026c4 <_gnu_exception_handler+0x4a>
   1400026a9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026ad:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026b0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400026b3:	83 e0 01             	and    eax,0x1
   1400026b6:	85 c0                	test   eax,eax
   1400026b8:	75 0a                	jne    1400026c4 <_gnu_exception_handler+0x4a>
   1400026ba:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400026bf:	e9 14 02 00 00       	jmp    1400028d8 <_gnu_exception_handler+0x25e>
   1400026c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026c8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026cb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026cd:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026d2:	0f 84 12 01 00 00    	je     1400027ea <_gnu_exception_handler+0x170>
   1400026d8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026dd:	0f 87 c3 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   1400026e3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400026e8:	0f 87 b8 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   1400026ee:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400026f3:	0f 83 4c 01 00 00    	jae    140002845 <_gnu_exception_handler+0x1cb>
   1400026f9:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400026fe:	0f 84 3a 01 00 00    	je     14000283e <_gnu_exception_handler+0x1c4>
   140002704:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002709:	0f 87 97 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   14000270f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002714:	0f 84 83 01 00 00    	je     14000289d <_gnu_exception_handler+0x223>
   14000271a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000271f:	0f 87 81 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   140002725:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000272a:	0f 87 76 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   140002730:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002735:	0f 83 03 01 00 00    	jae    14000283e <_gnu_exception_handler+0x1c4>
   14000273b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002740:	0f 84 57 01 00 00    	je     14000289d <_gnu_exception_handler+0x223>
   140002746:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000274b:	0f 87 55 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   140002751:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002756:	0f 84 8e 00 00 00    	je     1400027ea <_gnu_exception_handler+0x170>
   14000275c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002761:	0f 87 3f 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   140002767:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000276c:	0f 84 2b 01 00 00    	je     14000289d <_gnu_exception_handler+0x223>
   140002772:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002777:	0f 87 29 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   14000277d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002782:	0f 84 15 01 00 00    	je     14000289d <_gnu_exception_handler+0x223>
   140002788:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000278d:	0f 85 13 01 00 00    	jne    1400028a6 <_gnu_exception_handler+0x22c>
   140002793:	ba 00 00 00 00       	mov    edx,0x0
   140002798:	b9 0b 00 00 00       	mov    ecx,0xb
   14000279d:	e8 de 6d 00 00       	call   140009580 <signal>
   1400027a2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027a6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027ab:	75 1b                	jne    1400027c8 <_gnu_exception_handler+0x14e>
   1400027ad:	ba 01 00 00 00       	mov    edx,0x1
   1400027b2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027b7:	e8 c4 6d 00 00       	call   140009580 <signal>
   1400027bc:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027c3:	e9 e1 00 00 00       	jmp    1400028a9 <_gnu_exception_handler+0x22f>
   1400027c8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027cd:	0f 84 d6 00 00 00    	je     1400028a9 <_gnu_exception_handler+0x22f>
   1400027d3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027d7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027dc:	ff d0                	call   rax
   1400027de:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027e5:	e9 bf 00 00 00       	jmp    1400028a9 <_gnu_exception_handler+0x22f>
   1400027ea:	ba 00 00 00 00       	mov    edx,0x0
   1400027ef:	b9 04 00 00 00       	mov    ecx,0x4
   1400027f4:	e8 87 6d 00 00       	call   140009580 <signal>
   1400027f9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027fd:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002802:	75 1b                	jne    14000281f <_gnu_exception_handler+0x1a5>
   140002804:	ba 01 00 00 00       	mov    edx,0x1
   140002809:	b9 04 00 00 00       	mov    ecx,0x4
   14000280e:	e8 6d 6d 00 00       	call   140009580 <signal>
   140002813:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000281a:	e9 8d 00 00 00       	jmp    1400028ac <_gnu_exception_handler+0x232>
   14000281f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002824:	0f 84 82 00 00 00    	je     1400028ac <_gnu_exception_handler+0x232>
   14000282a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000282e:	b9 04 00 00 00       	mov    ecx,0x4
   140002833:	ff d0                	call   rax
   140002835:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000283c:	eb 6e                	jmp    1400028ac <_gnu_exception_handler+0x232>
   14000283e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002845:	ba 00 00 00 00       	mov    edx,0x0
   14000284a:	b9 08 00 00 00       	mov    ecx,0x8
   14000284f:	e8 2c 6d 00 00       	call   140009580 <signal>
   140002854:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002858:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000285d:	75 23                	jne    140002882 <_gnu_exception_handler+0x208>
   14000285f:	ba 01 00 00 00       	mov    edx,0x1
   140002864:	b9 08 00 00 00       	mov    ecx,0x8
   140002869:	e8 12 6d 00 00       	call   140009580 <signal>
   14000286e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002872:	74 05                	je     140002879 <_gnu_exception_handler+0x1ff>
   140002874:	e8 67 03 00 00       	call   140002be0 <_fpreset>
   140002879:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002880:	eb 2d                	jmp    1400028af <_gnu_exception_handler+0x235>
   140002882:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002887:	74 26                	je     1400028af <_gnu_exception_handler+0x235>
   140002889:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000288d:	b9 08 00 00 00       	mov    ecx,0x8
   140002892:	ff d0                	call   rax
   140002894:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000289b:	eb 12                	jmp    1400028af <_gnu_exception_handler+0x235>
   14000289d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028a4:	eb 0a                	jmp    1400028b0 <_gnu_exception_handler+0x236>
   1400028a6:	90                   	nop
   1400028a7:	eb 07                	jmp    1400028b0 <_gnu_exception_handler+0x236>
   1400028a9:	90                   	nop
   1400028aa:	eb 04                	jmp    1400028b0 <_gnu_exception_handler+0x236>
   1400028ac:	90                   	nop
   1400028ad:	eb 01                	jmp    1400028b0 <_gnu_exception_handler+0x236>
   1400028af:	90                   	nop
   1400028b0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400028b4:	75 1f                	jne    1400028d5 <_gnu_exception_handler+0x25b>
   1400028b6:	48 8b 05 53 c8 00 00 	mov    rax,QWORD PTR [rip+0xc853]        # 14000f110 <__mingw_oldexcpt_handler>
   1400028bd:	48 85 c0             	test   rax,rax
   1400028c0:	74 13                	je     1400028d5 <_gnu_exception_handler+0x25b>
   1400028c2:	48 8b 15 47 c8 00 00 	mov    rdx,QWORD PTR [rip+0xc847]        # 14000f110 <__mingw_oldexcpt_handler>
   1400028c9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028cd:	48 89 c1             	mov    rcx,rax
   1400028d0:	ff d2                	call   rdx
   1400028d2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400028d5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400028d8:	48 83 c4 30          	add    rsp,0x30
   1400028dc:	5d                   	pop    rbp
   1400028dd:	c3                   	ret
   1400028de:	90                   	nop
   1400028df:	90                   	nop

00000001400028e0 <___w64_mingwthr_add_key_dtor>:
   1400028e0:	55                   	push   rbp
   1400028e1:	48 89 e5             	mov    rbp,rsp
   1400028e4:	48 83 ec 30          	sub    rsp,0x30
   1400028e8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400028eb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400028ef:	8b 05 53 c8 00 00    	mov    eax,DWORD PTR [rip+0xc853]        # 14000f148 <__mingwthr_cs_init>
   1400028f5:	85 c0                	test   eax,eax
   1400028f7:	75 07                	jne    140002900 <___w64_mingwthr_add_key_dtor+0x20>
   1400028f9:	b8 00 00 00 00       	mov    eax,0x0
   1400028fe:	eb 7b                	jmp    14000297b <___w64_mingwthr_add_key_dtor+0x9b>
   140002900:	ba 18 00 00 00       	mov    edx,0x18
   140002905:	b9 01 00 00 00       	mov    ecx,0x1
   14000290a:	e8 19 6c 00 00       	call   140009528 <calloc>
   14000290f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002913:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002918:	75 07                	jne    140002921 <___w64_mingwthr_add_key_dtor+0x41>
   14000291a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000291f:	eb 5a                	jmp    14000297b <___w64_mingwthr_add_key_dtor+0x9b>
   140002921:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002925:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002928:	89 10                	mov    DWORD PTR [rax],edx
   14000292a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000292e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002932:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002936:	48 8d 05 e3 c7 00 00 	lea    rax,[rip+0xc7e3]        # 14000f120 <__mingwthr_cs>
   14000293d:	48 89 c1             	mov    rcx,rax
   140002940:	48 8b 05 a1 d8 00 00 	mov    rax,QWORD PTR [rip+0xd8a1]        # 1400101e8 <__imp_EnterCriticalSection>
   140002947:	ff d0                	call   rax
   140002949:	48 8b 15 00 c8 00 00 	mov    rdx,QWORD PTR [rip+0xc800]        # 14000f150 <key_dtor_list>
   140002950:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002954:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002958:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000295c:	48 89 05 ed c7 00 00 	mov    QWORD PTR [rip+0xc7ed],rax        # 14000f150 <key_dtor_list>
   140002963:	48 8d 05 b6 c7 00 00 	lea    rax,[rip+0xc7b6]        # 14000f120 <__mingwthr_cs>
   14000296a:	48 89 c1             	mov    rcx,rax
   14000296d:	48 8b 05 ac d8 00 00 	mov    rax,QWORD PTR [rip+0xd8ac]        # 140010220 <__imp_LeaveCriticalSection>
   140002974:	ff d0                	call   rax
   140002976:	b8 00 00 00 00       	mov    eax,0x0
   14000297b:	48 83 c4 30          	add    rsp,0x30
   14000297f:	5d                   	pop    rbp
   140002980:	c3                   	ret

0000000140002981 <___w64_mingwthr_remove_key_dtor>:
   140002981:	55                   	push   rbp
   140002982:	48 89 e5             	mov    rbp,rsp
   140002985:	48 83 ec 30          	sub    rsp,0x30
   140002989:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000298c:	8b 05 b6 c7 00 00    	mov    eax,DWORD PTR [rip+0xc7b6]        # 14000f148 <__mingwthr_cs_init>
   140002992:	85 c0                	test   eax,eax
   140002994:	75 0a                	jne    1400029a0 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002996:	b8 00 00 00 00       	mov    eax,0x0
   14000299b:	e9 9c 00 00 00       	jmp    140002a3c <___w64_mingwthr_remove_key_dtor+0xbb>
   1400029a0:	48 8d 05 79 c7 00 00 	lea    rax,[rip+0xc779]        # 14000f120 <__mingwthr_cs>
   1400029a7:	48 89 c1             	mov    rcx,rax
   1400029aa:	48 8b 05 37 d8 00 00 	mov    rax,QWORD PTR [rip+0xd837]        # 1400101e8 <__imp_EnterCriticalSection>
   1400029b1:	ff d0                	call   rax
   1400029b3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400029ba:	00 
   1400029bb:	48 8b 05 8e c7 00 00 	mov    rax,QWORD PTR [rip+0xc78e]        # 14000f150 <key_dtor_list>
   1400029c2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029c6:	eb 55                	jmp    140002a1d <___w64_mingwthr_remove_key_dtor+0x9c>
   1400029c8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029cc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400029ce:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   1400029d1:	75 36                	jne    140002a09 <___w64_mingwthr_remove_key_dtor+0x88>
   1400029d3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029d8:	75 11                	jne    1400029eb <___w64_mingwthr_remove_key_dtor+0x6a>
   1400029da:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029de:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   1400029e2:	48 89 05 67 c7 00 00 	mov    QWORD PTR [rip+0xc767],rax        # 14000f150 <key_dtor_list>
   1400029e9:	eb 10                	jmp    1400029fb <___w64_mingwthr_remove_key_dtor+0x7a>
   1400029eb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ef:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   1400029f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029f7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029fb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ff:	48 89 c1             	mov    rcx,rax
   140002a02:	e8 49 6b 00 00       	call   140009550 <free>
   140002a07:	eb 1b                	jmp    140002a24 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a09:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a0d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a11:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a15:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a19:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a1d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a22:	75 a4                	jne    1400029c8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a24:	48 8d 05 f5 c6 00 00 	lea    rax,[rip+0xc6f5]        # 14000f120 <__mingwthr_cs>
   140002a2b:	48 89 c1             	mov    rcx,rax
   140002a2e:	48 8b 05 eb d7 00 00 	mov    rax,QWORD PTR [rip+0xd7eb]        # 140010220 <__imp_LeaveCriticalSection>
   140002a35:	ff d0                	call   rax
   140002a37:	b8 00 00 00 00       	mov    eax,0x0
   140002a3c:	48 83 c4 30          	add    rsp,0x30
   140002a40:	5d                   	pop    rbp
   140002a41:	c3                   	ret

0000000140002a42 <__mingwthr_run_key_dtors>:
   140002a42:	55                   	push   rbp
   140002a43:	48 89 e5             	mov    rbp,rsp
   140002a46:	48 83 ec 30          	sub    rsp,0x30
   140002a4a:	8b 05 f8 c6 00 00    	mov    eax,DWORD PTR [rip+0xc6f8]        # 14000f148 <__mingwthr_cs_init>
   140002a50:	85 c0                	test   eax,eax
   140002a52:	0f 84 82 00 00 00    	je     140002ada <__mingwthr_run_key_dtors+0x98>
   140002a58:	48 8d 05 c1 c6 00 00 	lea    rax,[rip+0xc6c1]        # 14000f120 <__mingwthr_cs>
   140002a5f:	48 89 c1             	mov    rcx,rax
   140002a62:	48 8b 05 7f d7 00 00 	mov    rax,QWORD PTR [rip+0xd77f]        # 1400101e8 <__imp_EnterCriticalSection>
   140002a69:	ff d0                	call   rax
   140002a6b:	48 8b 05 de c6 00 00 	mov    rax,QWORD PTR [rip+0xc6de]        # 14000f150 <key_dtor_list>
   140002a72:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a76:	eb 46                	jmp    140002abe <__mingwthr_run_key_dtors+0x7c>
   140002a78:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a7c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a7e:	89 c1                	mov    ecx,eax
   140002a80:	48 8b 05 c1 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7c1]        # 140010248 <__imp_TlsGetValue>
   140002a87:	ff d0                	call   rax
   140002a89:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a8d:	48 8b 05 6c d7 00 00 	mov    rax,QWORD PTR [rip+0xd76c]        # 140010200 <__imp_GetLastError>
   140002a94:	ff d0                	call   rax
   140002a96:	85 c0                	test   eax,eax
   140002a98:	75 18                	jne    140002ab2 <__mingwthr_run_key_dtors+0x70>
   140002a9a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a9f:	74 11                	je     140002ab2 <__mingwthr_run_key_dtors+0x70>
   140002aa1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002aa5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002aa9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aad:	48 89 c1             	mov    rcx,rax
   140002ab0:	ff d2                	call   rdx
   140002ab2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ab6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002aba:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002abe:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ac3:	75 b3                	jne    140002a78 <__mingwthr_run_key_dtors+0x36>
   140002ac5:	48 8d 05 54 c6 00 00 	lea    rax,[rip+0xc654]        # 14000f120 <__mingwthr_cs>
   140002acc:	48 89 c1             	mov    rcx,rax
   140002acf:	48 8b 05 4a d7 00 00 	mov    rax,QWORD PTR [rip+0xd74a]        # 140010220 <__imp_LeaveCriticalSection>
   140002ad6:	ff d0                	call   rax
   140002ad8:	eb 01                	jmp    140002adb <__mingwthr_run_key_dtors+0x99>
   140002ada:	90                   	nop
   140002adb:	48 83 c4 30          	add    rsp,0x30
   140002adf:	5d                   	pop    rbp
   140002ae0:	c3                   	ret

0000000140002ae1 <__mingw_TLScallback>:
   140002ae1:	55                   	push   rbp
   140002ae2:	48 89 e5             	mov    rbp,rsp
   140002ae5:	48 83 ec 30          	sub    rsp,0x30
   140002ae9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002aed:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002af0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002af4:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002af8:	0f 84 cc 00 00 00    	je     140002bca <__mingw_TLScallback+0xe9>
   140002afe:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b02:	0f 87 ca 00 00 00    	ja     140002bd2 <__mingw_TLScallback+0xf1>
   140002b08:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b0c:	0f 84 b1 00 00 00    	je     140002bc3 <__mingw_TLScallback+0xe2>
   140002b12:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b16:	0f 87 b6 00 00 00    	ja     140002bd2 <__mingw_TLScallback+0xf1>
   140002b1c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b20:	74 33                	je     140002b55 <__mingw_TLScallback+0x74>
   140002b22:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b26:	0f 85 a6 00 00 00    	jne    140002bd2 <__mingw_TLScallback+0xf1>
   140002b2c:	8b 05 16 c6 00 00    	mov    eax,DWORD PTR [rip+0xc616]        # 14000f148 <__mingwthr_cs_init>
   140002b32:	85 c0                	test   eax,eax
   140002b34:	75 13                	jne    140002b49 <__mingw_TLScallback+0x68>
   140002b36:	48 8d 05 e3 c5 00 00 	lea    rax,[rip+0xc5e3]        # 14000f120 <__mingwthr_cs>
   140002b3d:	48 89 c1             	mov    rcx,rax
   140002b40:	48 8b 05 d1 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6d1]        # 140010218 <__imp_InitializeCriticalSection>
   140002b47:	ff d0                	call   rax
   140002b49:	c7 05 f5 c5 00 00 01 	mov    DWORD PTR [rip+0xc5f5],0x1        # 14000f148 <__mingwthr_cs_init>
   140002b50:	00 00 00 
   140002b53:	eb 7d                	jmp    140002bd2 <__mingw_TLScallback+0xf1>
   140002b55:	e8 e8 fe ff ff       	call   140002a42 <__mingwthr_run_key_dtors>
   140002b5a:	8b 05 e8 c5 00 00    	mov    eax,DWORD PTR [rip+0xc5e8]        # 14000f148 <__mingwthr_cs_init>
   140002b60:	83 f8 01             	cmp    eax,0x1
   140002b63:	75 6c                	jne    140002bd1 <__mingw_TLScallback+0xf0>
   140002b65:	48 8b 05 e4 c5 00 00 	mov    rax,QWORD PTR [rip+0xc5e4]        # 14000f150 <key_dtor_list>
   140002b6c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b70:	eb 20                	jmp    140002b92 <__mingw_TLScallback+0xb1>
   140002b72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b76:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b7a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b7e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b82:	48 89 c1             	mov    rcx,rax
   140002b85:	e8 c6 69 00 00       	call   140009550 <free>
   140002b8a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b8e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b92:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b97:	75 d9                	jne    140002b72 <__mingw_TLScallback+0x91>
   140002b99:	48 c7 05 ac c5 00 00 	mov    QWORD PTR [rip+0xc5ac],0x0        # 14000f150 <key_dtor_list>
   140002ba0:	00 00 00 00 
   140002ba4:	c7 05 9a c5 00 00 00 	mov    DWORD PTR [rip+0xc59a],0x0        # 14000f148 <__mingwthr_cs_init>
   140002bab:	00 00 00 
   140002bae:	48 8d 05 6b c5 00 00 	lea    rax,[rip+0xc56b]        # 14000f120 <__mingwthr_cs>
   140002bb5:	48 89 c1             	mov    rcx,rax
   140002bb8:	48 8b 05 21 d6 00 00 	mov    rax,QWORD PTR [rip+0xd621]        # 1400101e0 <__IAT_start__>
   140002bbf:	ff d0                	call   rax
   140002bc1:	eb 0e                	jmp    140002bd1 <__mingw_TLScallback+0xf0>
   140002bc3:	e8 18 00 00 00       	call   140002be0 <_fpreset>
   140002bc8:	eb 08                	jmp    140002bd2 <__mingw_TLScallback+0xf1>
   140002bca:	e8 73 fe ff ff       	call   140002a42 <__mingwthr_run_key_dtors>
   140002bcf:	eb 01                	jmp    140002bd2 <__mingw_TLScallback+0xf1>
   140002bd1:	90                   	nop
   140002bd2:	b8 01 00 00 00       	mov    eax,0x1
   140002bd7:	48 83 c4 30          	add    rsp,0x30
   140002bdb:	5d                   	pop    rbp
   140002bdc:	c3                   	ret
   140002bdd:	90                   	nop
   140002bde:	90                   	nop
   140002bdf:	90                   	nop

0000000140002be0 <_fpreset>:
   140002be0:	55                   	push   rbp
   140002be1:	48 89 e5             	mov    rbp,rsp
   140002be4:	db e3                	fninit
   140002be6:	90                   	nop
   140002be7:	5d                   	pop    rbp
   140002be8:	c3                   	ret
   140002be9:	90                   	nop
   140002bea:	90                   	nop
   140002beb:	90                   	nop
   140002bec:	90                   	nop
   140002bed:	90                   	nop
   140002bee:	90                   	nop
   140002bef:	90                   	nop

0000000140002bf0 <_ValidateImageBase>:
   140002bf0:	55                   	push   rbp
   140002bf1:	48 89 e5             	mov    rbp,rsp
   140002bf4:	48 83 ec 20          	sub    rsp,0x20
   140002bf8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002bfc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c00:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c04:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c08:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c0b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c0f:	74 07                	je     140002c18 <_ValidateImageBase+0x28>
   140002c11:	b8 00 00 00 00       	mov    eax,0x0
   140002c16:	eb 4e                	jmp    140002c66 <_ValidateImageBase+0x76>
   140002c18:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c1c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c1f:	48 63 d0             	movsxd rdx,eax
   140002c22:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c26:	48 01 d0             	add    rax,rdx
   140002c29:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c2d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c31:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c33:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c38:	74 07                	je     140002c41 <_ValidateImageBase+0x51>
   140002c3a:	b8 00 00 00 00       	mov    eax,0x0
   140002c3f:	eb 25                	jmp    140002c66 <_ValidateImageBase+0x76>
   140002c41:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c45:	48 83 c0 18          	add    rax,0x18
   140002c49:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c4d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c51:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c54:	66 3d 0b 02          	cmp    ax,0x20b
   140002c58:	74 07                	je     140002c61 <_ValidateImageBase+0x71>
   140002c5a:	b8 00 00 00 00       	mov    eax,0x0
   140002c5f:	eb 05                	jmp    140002c66 <_ValidateImageBase+0x76>
   140002c61:	b8 01 00 00 00       	mov    eax,0x1
   140002c66:	48 83 c4 20          	add    rsp,0x20
   140002c6a:	5d                   	pop    rbp
   140002c6b:	c3                   	ret

0000000140002c6c <_FindPESection>:
   140002c6c:	55                   	push   rbp
   140002c6d:	48 89 e5             	mov    rbp,rsp
   140002c70:	48 83 ec 20          	sub    rsp,0x20
   140002c74:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c78:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002c7c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c80:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c83:	48 63 d0             	movsxd rdx,eax
   140002c86:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c8a:	48 01 d0             	add    rax,rdx
   140002c8d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c91:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002c98:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c9c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002ca0:	0f b7 d0             	movzx  edx,ax
   140002ca3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ca7:	48 01 d0             	add    rax,rdx
   140002caa:	48 83 c0 18          	add    rax,0x18
   140002cae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cb2:	eb 36                	jmp    140002cea <_FindPESection+0x7e>
   140002cb4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cb8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002cbb:	89 c0                	mov    eax,eax
   140002cbd:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cc1:	72 1e                	jb     140002ce1 <_FindPESection+0x75>
   140002cc3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cc7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002cca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cce:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002cd1:	01 d0                	add    eax,edx
   140002cd3:	89 c0                	mov    eax,eax
   140002cd5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cd9:	73 06                	jae    140002ce1 <_FindPESection+0x75>
   140002cdb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cdf:	eb 1e                	jmp    140002cff <_FindPESection+0x93>
   140002ce1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002ce5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002cea:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cee:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002cf2:	0f b7 c0             	movzx  eax,ax
   140002cf5:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002cf8:	72 ba                	jb     140002cb4 <_FindPESection+0x48>
   140002cfa:	b8 00 00 00 00       	mov    eax,0x0
   140002cff:	48 83 c4 20          	add    rsp,0x20
   140002d03:	5d                   	pop    rbp
   140002d04:	c3                   	ret

0000000140002d05 <_FindPESectionByName>:
   140002d05:	55                   	push   rbp
   140002d06:	48 89 e5             	mov    rbp,rsp
   140002d09:	48 83 ec 40          	sub    rsp,0x40
   140002d0d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d11:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d15:	48 89 c1             	mov    rcx,rax
   140002d18:	e8 73 68 00 00       	call   140009590 <strlen>
   140002d1d:	48 83 f8 08          	cmp    rax,0x8
   140002d21:	76 0a                	jbe    140002d2d <_FindPESectionByName+0x28>
   140002d23:	b8 00 00 00 00       	mov    eax,0x0
   140002d28:	e9 98 00 00 00       	jmp    140002dc5 <_FindPESectionByName+0xc0>
   140002d2d:	48 8b 05 4c 88 00 00 	mov    rax,QWORD PTR [rip+0x884c]        # 14000b580 <.refptr.__ImageBase>
   140002d34:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d38:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d3c:	48 89 c1             	mov    rcx,rax
   140002d3f:	e8 ac fe ff ff       	call   140002bf0 <_ValidateImageBase>
   140002d44:	85 c0                	test   eax,eax
   140002d46:	75 07                	jne    140002d4f <_FindPESectionByName+0x4a>
   140002d48:	b8 00 00 00 00       	mov    eax,0x0
   140002d4d:	eb 76                	jmp    140002dc5 <_FindPESectionByName+0xc0>
   140002d4f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d53:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d56:	48 63 d0             	movsxd rdx,eax
   140002d59:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d5d:	48 01 d0             	add    rax,rdx
   140002d60:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002d64:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d6b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d6f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d73:	0f b7 d0             	movzx  edx,ax
   140002d76:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d7a:	48 01 d0             	add    rax,rdx
   140002d7d:	48 83 c0 18          	add    rax,0x18
   140002d81:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d85:	eb 29                	jmp    140002db0 <_FindPESectionByName+0xab>
   140002d87:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d8b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002d8f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002d95:	48 89 c1             	mov    rcx,rax
   140002d98:	e8 fb 67 00 00       	call   140009598 <strncmp>
   140002d9d:	85 c0                	test   eax,eax
   140002d9f:	75 06                	jne    140002da7 <_FindPESectionByName+0xa2>
   140002da1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002da5:	eb 1e                	jmp    140002dc5 <_FindPESectionByName+0xc0>
   140002da7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002dab:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002db0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002db4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002db8:	0f b7 c0             	movzx  eax,ax
   140002dbb:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002dbe:	72 c7                	jb     140002d87 <_FindPESectionByName+0x82>
   140002dc0:	b8 00 00 00 00       	mov    eax,0x0
   140002dc5:	48 83 c4 40          	add    rsp,0x40
   140002dc9:	5d                   	pop    rbp
   140002dca:	c3                   	ret

0000000140002dcb <__mingw_GetSectionForAddress>:
   140002dcb:	55                   	push   rbp
   140002dcc:	48 89 e5             	mov    rbp,rsp
   140002dcf:	48 83 ec 30          	sub    rsp,0x30
   140002dd3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002dd7:	48 8b 05 a2 87 00 00 	mov    rax,QWORD PTR [rip+0x87a2]        # 14000b580 <.refptr.__ImageBase>
   140002dde:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002de2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002de6:	48 89 c1             	mov    rcx,rax
   140002de9:	e8 02 fe ff ff       	call   140002bf0 <_ValidateImageBase>
   140002dee:	85 c0                	test   eax,eax
   140002df0:	75 07                	jne    140002df9 <__mingw_GetSectionForAddress+0x2e>
   140002df2:	b8 00 00 00 00       	mov    eax,0x0
   140002df7:	eb 1c                	jmp    140002e15 <__mingw_GetSectionForAddress+0x4a>
   140002df9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002dfd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e01:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e05:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e09:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e0d:	48 89 c1             	mov    rcx,rax
   140002e10:	e8 57 fe ff ff       	call   140002c6c <_FindPESection>
   140002e15:	48 83 c4 30          	add    rsp,0x30
   140002e19:	5d                   	pop    rbp
   140002e1a:	c3                   	ret

0000000140002e1b <__mingw_GetSectionCount>:
   140002e1b:	55                   	push   rbp
   140002e1c:	48 89 e5             	mov    rbp,rsp
   140002e1f:	48 83 ec 30          	sub    rsp,0x30
   140002e23:	48 8b 05 56 87 00 00 	mov    rax,QWORD PTR [rip+0x8756]        # 14000b580 <.refptr.__ImageBase>
   140002e2a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e2e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e32:	48 89 c1             	mov    rcx,rax
   140002e35:	e8 b6 fd ff ff       	call   140002bf0 <_ValidateImageBase>
   140002e3a:	85 c0                	test   eax,eax
   140002e3c:	75 07                	jne    140002e45 <__mingw_GetSectionCount+0x2a>
   140002e3e:	b8 00 00 00 00       	mov    eax,0x0
   140002e43:	eb 20                	jmp    140002e65 <__mingw_GetSectionCount+0x4a>
   140002e45:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e49:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e4c:	48 63 d0             	movsxd rdx,eax
   140002e4f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e53:	48 01 d0             	add    rax,rdx
   140002e56:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e5e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e62:	0f b7 c0             	movzx  eax,ax
   140002e65:	48 83 c4 30          	add    rsp,0x30
   140002e69:	5d                   	pop    rbp
   140002e6a:	c3                   	ret

0000000140002e6b <_FindPESectionExec>:
   140002e6b:	55                   	push   rbp
   140002e6c:	48 89 e5             	mov    rbp,rsp
   140002e6f:	48 83 ec 40          	sub    rsp,0x40
   140002e73:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e77:	48 8b 05 02 87 00 00 	mov    rax,QWORD PTR [rip+0x8702]        # 14000b580 <.refptr.__ImageBase>
   140002e7e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e82:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e86:	48 89 c1             	mov    rcx,rax
   140002e89:	e8 62 fd ff ff       	call   140002bf0 <_ValidateImageBase>
   140002e8e:	85 c0                	test   eax,eax
   140002e90:	75 07                	jne    140002e99 <_FindPESectionExec+0x2e>
   140002e92:	b8 00 00 00 00       	mov    eax,0x0
   140002e97:	eb 78                	jmp    140002f11 <_FindPESectionExec+0xa6>
   140002e99:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e9d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ea0:	48 63 d0             	movsxd rdx,eax
   140002ea3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ea7:	48 01 d0             	add    rax,rdx
   140002eaa:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002eae:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002eb5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002eb9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002ebd:	0f b7 d0             	movzx  edx,ax
   140002ec0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ec4:	48 01 d0             	add    rax,rdx
   140002ec7:	48 83 c0 18          	add    rax,0x18
   140002ecb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ecf:	eb 2b                	jmp    140002efc <_FindPESectionExec+0x91>
   140002ed1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ed5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002ed8:	25 00 00 00 20       	and    eax,0x20000000
   140002edd:	85 c0                	test   eax,eax
   140002edf:	74 12                	je     140002ef3 <_FindPESectionExec+0x88>
   140002ee1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002ee6:	75 06                	jne    140002eee <_FindPESectionExec+0x83>
   140002ee8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002eec:	eb 23                	jmp    140002f11 <_FindPESectionExec+0xa6>
   140002eee:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002ef3:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002ef7:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002efc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f00:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f04:	0f b7 c0             	movzx  eax,ax
   140002f07:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f0a:	72 c5                	jb     140002ed1 <_FindPESectionExec+0x66>
   140002f0c:	b8 00 00 00 00       	mov    eax,0x0
   140002f11:	48 83 c4 40          	add    rsp,0x40
   140002f15:	5d                   	pop    rbp
   140002f16:	c3                   	ret

0000000140002f17 <_GetPEImageBase>:
   140002f17:	55                   	push   rbp
   140002f18:	48 89 e5             	mov    rbp,rsp
   140002f1b:	48 83 ec 30          	sub    rsp,0x30
   140002f1f:	48 8b 05 5a 86 00 00 	mov    rax,QWORD PTR [rip+0x865a]        # 14000b580 <.refptr.__ImageBase>
   140002f26:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f2a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f2e:	48 89 c1             	mov    rcx,rax
   140002f31:	e8 ba fc ff ff       	call   140002bf0 <_ValidateImageBase>
   140002f36:	85 c0                	test   eax,eax
   140002f38:	75 07                	jne    140002f41 <_GetPEImageBase+0x2a>
   140002f3a:	b8 00 00 00 00       	mov    eax,0x0
   140002f3f:	eb 04                	jmp    140002f45 <_GetPEImageBase+0x2e>
   140002f41:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f45:	48 83 c4 30          	add    rsp,0x30
   140002f49:	5d                   	pop    rbp
   140002f4a:	c3                   	ret

0000000140002f4b <_IsNonwritableInCurrentImage>:
   140002f4b:	55                   	push   rbp
   140002f4c:	48 89 e5             	mov    rbp,rsp
   140002f4f:	48 83 ec 40          	sub    rsp,0x40
   140002f53:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f57:	48 8b 05 22 86 00 00 	mov    rax,QWORD PTR [rip+0x8622]        # 14000b580 <.refptr.__ImageBase>
   140002f5e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f62:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f66:	48 89 c1             	mov    rcx,rax
   140002f69:	e8 82 fc ff ff       	call   140002bf0 <_ValidateImageBase>
   140002f6e:	85 c0                	test   eax,eax
   140002f70:	75 07                	jne    140002f79 <_IsNonwritableInCurrentImage+0x2e>
   140002f72:	b8 00 00 00 00       	mov    eax,0x0
   140002f77:	eb 3d                	jmp    140002fb6 <_IsNonwritableInCurrentImage+0x6b>
   140002f79:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f7d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002f81:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f85:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002f89:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f8d:	48 89 c1             	mov    rcx,rax
   140002f90:	e8 d7 fc ff ff       	call   140002c6c <_FindPESection>
   140002f95:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f99:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002f9e:	75 07                	jne    140002fa7 <_IsNonwritableInCurrentImage+0x5c>
   140002fa0:	b8 00 00 00 00       	mov    eax,0x0
   140002fa5:	eb 0f                	jmp    140002fb6 <_IsNonwritableInCurrentImage+0x6b>
   140002fa7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002fab:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fae:	f7 d0                	not    eax
   140002fb0:	c1 e8 1f             	shr    eax,0x1f
   140002fb3:	0f b6 c0             	movzx  eax,al
   140002fb6:	48 83 c4 40          	add    rsp,0x40
   140002fba:	5d                   	pop    rbp
   140002fbb:	c3                   	ret

0000000140002fbc <__mingw_enum_import_library_names>:
   140002fbc:	55                   	push   rbp
   140002fbd:	48 89 e5             	mov    rbp,rsp
   140002fc0:	48 83 ec 50          	sub    rsp,0x50
   140002fc4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002fc7:	48 8b 05 b2 85 00 00 	mov    rax,QWORD PTR [rip+0x85b2]        # 14000b580 <.refptr.__ImageBase>
   140002fce:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fd2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fd6:	48 89 c1             	mov    rcx,rax
   140002fd9:	e8 12 fc ff ff       	call   140002bf0 <_ValidateImageBase>
   140002fde:	85 c0                	test   eax,eax
   140002fe0:	75 0a                	jne    140002fec <__mingw_enum_import_library_names+0x30>
   140002fe2:	b8 00 00 00 00       	mov    eax,0x0
   140002fe7:	e9 ab 00 00 00       	jmp    140003097 <__mingw_enum_import_library_names+0xdb>
   140002fec:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ff0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ff3:	48 63 d0             	movsxd rdx,eax
   140002ff6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ffa:	48 01 d0             	add    rax,rdx
   140002ffd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003001:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003005:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000300b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000300e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003012:	75 07                	jne    14000301b <__mingw_enum_import_library_names+0x5f>
   140003014:	b8 00 00 00 00       	mov    eax,0x0
   140003019:	eb 7c                	jmp    140003097 <__mingw_enum_import_library_names+0xdb>
   14000301b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000301e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003022:	48 89 c1             	mov    rcx,rax
   140003025:	e8 42 fc ff ff       	call   140002c6c <_FindPESection>
   14000302a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000302e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003033:	75 07                	jne    14000303c <__mingw_enum_import_library_names+0x80>
   140003035:	b8 00 00 00 00       	mov    eax,0x0
   14000303a:	eb 5b                	jmp    140003097 <__mingw_enum_import_library_names+0xdb>
   14000303c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000303f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003043:	48 01 d0             	add    rax,rdx
   140003046:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000304a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000304f:	75 07                	jne    140003058 <__mingw_enum_import_library_names+0x9c>
   140003051:	b8 00 00 00 00       	mov    eax,0x0
   140003056:	eb 3f                	jmp    140003097 <__mingw_enum_import_library_names+0xdb>
   140003058:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000305c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000305f:	85 c0                	test   eax,eax
   140003061:	75 0b                	jne    14000306e <__mingw_enum_import_library_names+0xb2>
   140003063:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003067:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000306a:	85 c0                	test   eax,eax
   14000306c:	74 23                	je     140003091 <__mingw_enum_import_library_names+0xd5>
   14000306e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003072:	7f 12                	jg     140003086 <__mingw_enum_import_library_names+0xca>
   140003074:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003078:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000307b:	89 c2                	mov    edx,eax
   14000307d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003081:	48 01 d0             	add    rax,rdx
   140003084:	eb 11                	jmp    140003097 <__mingw_enum_import_library_names+0xdb>
   140003086:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000308a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000308f:	eb c7                	jmp    140003058 <__mingw_enum_import_library_names+0x9c>
   140003091:	90                   	nop
   140003092:	b8 00 00 00 00       	mov    eax,0x0
   140003097:	48 83 c4 50          	add    rsp,0x50
   14000309b:	5d                   	pop    rbp
   14000309c:	c3                   	ret
   14000309d:	90                   	nop
   14000309e:	90                   	nop
   14000309f:	90                   	nop

00000001400030a0 <___chkstk_ms>:
   1400030a0:	51                   	push   rcx
   1400030a1:	50                   	push   rax
   1400030a2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030a8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400030ad:	72 19                	jb     1400030c8 <___chkstk_ms+0x28>
   1400030af:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400030b6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030ba:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400030c0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030c6:	77 e7                	ja     1400030af <___chkstk_ms+0xf>
   1400030c8:	48 29 c1             	sub    rcx,rax
   1400030cb:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030cf:	58                   	pop    rax
   1400030d0:	59                   	pop    rcx
   1400030d1:	c3                   	ret
   1400030d2:	90                   	nop
   1400030d3:	90                   	nop
   1400030d4:	90                   	nop
   1400030d5:	90                   	nop
   1400030d6:	90                   	nop
   1400030d7:	90                   	nop
   1400030d8:	90                   	nop
   1400030d9:	90                   	nop
   1400030da:	90                   	nop
   1400030db:	90                   	nop
   1400030dc:	90                   	nop
   1400030dd:	90                   	nop
   1400030de:	90                   	nop
   1400030df:	90                   	nop

00000001400030e0 <__mingw_snprintf>:
   1400030e0:	55                   	push   rbp
   1400030e1:	53                   	push   rbx
   1400030e2:	48 83 ec 38          	sub    rsp,0x38
   1400030e6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   1400030eb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400030ef:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400030f3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400030f7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   1400030fb:	48 8d 45 38          	lea    rax,[rbp+0x38]
   1400030ff:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003103:	4c 8b 45 f8          	mov    r8,QWORD PTR [rbp-0x8]
   140003107:	48 8b 4d 30          	mov    rcx,QWORD PTR [rbp+0x30]
   14000310b:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000310f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003113:	4d 89 c1             	mov    r9,r8
   140003116:	49 89 c8             	mov    r8,rcx
   140003119:	48 89 c1             	mov    rcx,rax
   14000311c:	e8 0f 00 00 00       	call   140003130 <__mingw_vsnprintf>
   140003121:	89 c3                	mov    ebx,eax
   140003123:	89 d8                	mov    eax,ebx
   140003125:	48 83 c4 38          	add    rsp,0x38
   140003129:	5b                   	pop    rbx
   14000312a:	5d                   	pop    rbp
   14000312b:	c3                   	ret
   14000312c:	90                   	nop
   14000312d:	90                   	nop
   14000312e:	90                   	nop
   14000312f:	90                   	nop

0000000140003130 <__mingw_vsnprintf>:
   140003130:	55                   	push   rbp
   140003131:	53                   	push   rbx
   140003132:	48 83 ec 38          	sub    rsp,0x38
   140003136:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   14000313b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000313f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140003143:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003147:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   14000314b:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   140003150:	75 29                	jne    14000317b <__mingw_vsnprintf+0x4b>
   140003152:	48 8b 4d 30          	mov    rcx,QWORD PTR [rbp+0x30]
   140003156:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000315a:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   14000315e:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003163:	49 89 c9             	mov    r9,rcx
   140003166:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000316c:	48 89 c2             	mov    rdx,rax
   14000316f:	b9 00 00 00 00       	mov    ecx,0x0
   140003174:	e8 ea 1f 00 00       	call   140005163 <__mingw_pformat>
   140003179:	eb 47                	jmp    1400031c2 <__mingw_vsnprintf+0x92>
   14000317b:	48 83 6d 28 01       	sub    QWORD PTR [rbp+0x28],0x1
   140003180:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003184:	41 89 c0             	mov    r8d,eax
   140003187:	48 8b 4d 30          	mov    rcx,QWORD PTR [rbp+0x30]
   14000318b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000318f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003193:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003198:	49 89 c9             	mov    r9,rcx
   14000319b:	48 89 c2             	mov    rdx,rax
   14000319e:	b9 00 00 00 00       	mov    ecx,0x0
   1400031a3:	e8 bb 1f 00 00       	call   140005163 <__mingw_pformat>
   1400031a8:	89 c3                	mov    ebx,eax
   1400031aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400031ae:	39 c3                	cmp    ebx,eax
   1400031b0:	0f 4e c3             	cmovle eax,ebx
   1400031b3:	48 63 d0             	movsxd rdx,eax
   1400031b6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400031ba:	48 01 d0             	add    rax,rdx
   1400031bd:	c6 00 00             	mov    BYTE PTR [rax],0x0
   1400031c0:	89 d8                	mov    eax,ebx
   1400031c2:	48 83 c4 38          	add    rsp,0x38
   1400031c6:	5b                   	pop    rbx
   1400031c7:	5d                   	pop    rbp
   1400031c8:	c3                   	ret
   1400031c9:	90                   	nop
   1400031ca:	90                   	nop
   1400031cb:	90                   	nop
   1400031cc:	90                   	nop
   1400031cd:	90                   	nop
   1400031ce:	90                   	nop
   1400031cf:	90                   	nop

00000001400031d0 <__pformat_putc>:
   1400031d0:	55                   	push   rbp
   1400031d1:	48 89 e5             	mov    rbp,rsp
   1400031d4:	48 83 ec 20          	sub    rsp,0x20
   1400031d8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031db:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400031df:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031e3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400031e6:	25 00 40 00 00       	and    eax,0x4000
   1400031eb:	85 c0                	test   eax,eax
   1400031ed:	75 12                	jne    140003201 <__pformat_putc+0x31>
   1400031ef:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031f3:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   1400031f6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031fa:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031fd:	39 c2                	cmp    edx,eax
   1400031ff:	7e 3b                	jle    14000323c <__pformat_putc+0x6c>
   140003201:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003205:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003208:	25 00 20 00 00       	and    eax,0x2000
   14000320d:	85 c0                	test   eax,eax
   14000320f:	74 13                	je     140003224 <__pformat_putc+0x54>
   140003211:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003215:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003218:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000321b:	89 c1                	mov    ecx,eax
   14000321d:	e8 26 63 00 00       	call   140009548 <fputc>
   140003222:	eb 18                	jmp    14000323c <__pformat_putc+0x6c>
   140003224:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003228:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   14000322b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000322f:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003232:	48 98                	cdqe
   140003234:	48 01 d0             	add    rax,rdx
   140003237:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   14000323a:	88 10                	mov    BYTE PTR [rax],dl
   14000323c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003240:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003243:	8d 50 01             	lea    edx,[rax+0x1]
   140003246:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000324a:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   14000324d:	90                   	nop
   14000324e:	48 83 c4 20          	add    rsp,0x20
   140003252:	5d                   	pop    rbp
   140003253:	c3                   	ret

0000000140003254 <__pformat_putchars>:
   140003254:	55                   	push   rbp
   140003255:	48 89 e5             	mov    rbp,rsp
   140003258:	48 83 ec 20          	sub    rsp,0x20
   14000325c:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003260:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003263:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003267:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000326b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000326e:	85 c0                	test   eax,eax
   140003270:	78 16                	js     140003288 <__pformat_putchars+0x34>
   140003272:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003276:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003279:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000327c:	7e 0a                	jle    140003288 <__pformat_putchars+0x34>
   14000327e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003282:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003285:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003288:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000328c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000328f:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003292:	7d 15                	jge    1400032a9 <__pformat_putchars+0x55>
   140003294:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003298:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000329b:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000329e:	89 c2                	mov    edx,eax
   1400032a0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032a4:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400032a7:	eb 0b                	jmp    1400032b4 <__pformat_putchars+0x60>
   1400032a9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032ad:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400032b4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032b8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032bb:	85 c0                	test   eax,eax
   1400032bd:	7e 57                	jle    140003316 <__pformat_putchars+0xc2>
   1400032bf:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032c3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400032c6:	25 00 04 00 00       	and    eax,0x400
   1400032cb:	85 c0                	test   eax,eax
   1400032cd:	75 47                	jne    140003316 <__pformat_putchars+0xc2>
   1400032cf:	eb 11                	jmp    1400032e2 <__pformat_putchars+0x8e>
   1400032d1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032d5:	48 89 c2             	mov    rdx,rax
   1400032d8:	b9 20 00 00 00       	mov    ecx,0x20
   1400032dd:	e8 ee fe ff ff       	call   1400031d0 <__pformat_putc>
   1400032e2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032e6:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032e9:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400032ec:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400032f0:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400032f3:	85 c0                	test   eax,eax
   1400032f5:	75 da                	jne    1400032d1 <__pformat_putchars+0x7d>
   1400032f7:	eb 1d                	jmp    140003316 <__pformat_putchars+0xc2>
   1400032f9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400032fd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003301:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003305:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003308:	0f be c0             	movsx  eax,al
   14000330b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000330f:	89 c1                	mov    ecx,eax
   140003311:	e8 ba fe ff ff       	call   1400031d0 <__pformat_putc>
   140003316:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003319:	8d 50 ff             	lea    edx,[rax-0x1]
   14000331c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000331f:	85 c0                	test   eax,eax
   140003321:	75 d6                	jne    1400032f9 <__pformat_putchars+0xa5>
   140003323:	eb 11                	jmp    140003336 <__pformat_putchars+0xe2>
   140003325:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003329:	48 89 c2             	mov    rdx,rax
   14000332c:	b9 20 00 00 00       	mov    ecx,0x20
   140003331:	e8 9a fe ff ff       	call   1400031d0 <__pformat_putc>
   140003336:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000333a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000333d:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003340:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003344:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003347:	85 c0                	test   eax,eax
   140003349:	7f da                	jg     140003325 <__pformat_putchars+0xd1>
   14000334b:	90                   	nop
   14000334c:	90                   	nop
   14000334d:	48 83 c4 20          	add    rsp,0x20
   140003351:	5d                   	pop    rbp
   140003352:	c3                   	ret

0000000140003353 <__pformat_puts>:
   140003353:	55                   	push   rbp
   140003354:	48 89 e5             	mov    rbp,rsp
   140003357:	48 83 ec 20          	sub    rsp,0x20
   14000335b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000335f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003363:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140003368:	75 0b                	jne    140003375 <__pformat_puts+0x22>
   14000336a:	48 8d 05 bf 7f 00 00 	lea    rax,[rip+0x7fbf]        # 14000b330 <.rdata>
   140003371:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003375:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003379:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000337c:	85 c0                	test   eax,eax
   14000337e:	78 2f                	js     1400033af <__pformat_puts+0x5c>
   140003380:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003384:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003387:	48 63 d0             	movsxd rdx,eax
   14000338a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000338e:	48 89 c1             	mov    rcx,rax
   140003391:	e8 4a 5a 00 00       	call   140008de0 <strnlen>
   140003396:	89 c1                	mov    ecx,eax
   140003398:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000339c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033a0:	49 89 d0             	mov    r8,rdx
   1400033a3:	89 ca                	mov    edx,ecx
   1400033a5:	48 89 c1             	mov    rcx,rax
   1400033a8:	e8 a7 fe ff ff       	call   140003254 <__pformat_putchars>
   1400033ad:	eb 23                	jmp    1400033d2 <__pformat_puts+0x7f>
   1400033af:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033b3:	48 89 c1             	mov    rcx,rax
   1400033b6:	e8 d5 61 00 00       	call   140009590 <strlen>
   1400033bb:	89 c1                	mov    ecx,eax
   1400033bd:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400033c1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033c5:	49 89 d0             	mov    r8,rdx
   1400033c8:	89 ca                	mov    edx,ecx
   1400033ca:	48 89 c1             	mov    rcx,rax
   1400033cd:	e8 82 fe ff ff       	call   140003254 <__pformat_putchars>
   1400033d2:	90                   	nop
   1400033d3:	48 83 c4 20          	add    rsp,0x20
   1400033d7:	5d                   	pop    rbp
   1400033d8:	c3                   	ret

00000001400033d9 <__pformat_wputchars>:
   1400033d9:	55                   	push   rbp
   1400033da:	48 89 e5             	mov    rbp,rsp
   1400033dd:	48 83 ec 50          	sub    rsp,0x50
   1400033e1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400033e5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400033e8:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400033ec:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   1400033f3:	00 
   1400033f4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033f8:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033fb:	85 c0                	test   eax,eax
   1400033fd:	78 16                	js     140003415 <__pformat_wputchars+0x3c>
   1400033ff:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003403:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003406:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003409:	7e 0a                	jle    140003415 <__pformat_wputchars+0x3c>
   14000340b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000340f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003412:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003415:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003419:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000341c:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000341f:	7d 15                	jge    140003436 <__pformat_wputchars+0x5d>
   140003421:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003425:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003428:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000342b:	89 c2                	mov    edx,eax
   14000342d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003431:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003434:	eb 0b                	jmp    140003441 <__pformat_wputchars+0x68>
   140003436:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000343a:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003441:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003445:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003448:	85 c0                	test   eax,eax
   14000344a:	7e 6e                	jle    1400034ba <__pformat_wputchars+0xe1>
   14000344c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003450:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003453:	25 00 04 00 00       	and    eax,0x400
   140003458:	85 c0                	test   eax,eax
   14000345a:	75 5e                	jne    1400034ba <__pformat_wputchars+0xe1>
   14000345c:	eb 11                	jmp    14000346f <__pformat_wputchars+0x96>
   14000345e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003462:	48 89 c2             	mov    rdx,rax
   140003465:	b9 20 00 00 00       	mov    ecx,0x20
   14000346a:	e8 61 fd ff ff       	call   1400031d0 <__pformat_putc>
   14000346f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003473:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003476:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003479:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000347d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003480:	85 c0                	test   eax,eax
   140003482:	75 da                	jne    14000345e <__pformat_wputchars+0x85>
   140003484:	eb 34                	jmp    1400034ba <__pformat_wputchars+0xe1>
   140003486:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   14000348a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000348e:	eb 1d                	jmp    1400034ad <__pformat_wputchars+0xd4>
   140003490:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003494:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003498:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000349c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000349f:	0f be c0             	movsx  eax,al
   1400034a2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034a6:	89 c1                	mov    ecx,eax
   1400034a8:	e8 23 fd ff ff       	call   1400031d0 <__pformat_putc>
   1400034ad:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400034b0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400034b3:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   1400034b6:	85 c0                	test   eax,eax
   1400034b8:	7f d6                	jg     140003490 <__pformat_wputchars+0xb7>
   1400034ba:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400034bd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400034c0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400034c3:	85 c0                	test   eax,eax
   1400034c5:	7e 41                	jle    140003508 <__pformat_wputchars+0x12f>
   1400034c7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400034cb:	48 8d 50 02          	lea    rdx,[rax+0x2]
   1400034cf:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   1400034d3:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400034d6:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   1400034da:	0f b7 d0             	movzx  edx,ax
   1400034dd:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400034e1:	49 89 c8             	mov    r8,rcx
   1400034e4:	48 89 c1             	mov    rcx,rax
   1400034e7:	e8 64 5a 00 00       	call   140008f50 <wcrtomb>
   1400034ec:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400034ef:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400034f3:	7f 91                	jg     140003486 <__pformat_wputchars+0xad>
   1400034f5:	eb 11                	jmp    140003508 <__pformat_wputchars+0x12f>
   1400034f7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034fb:	48 89 c2             	mov    rdx,rax
   1400034fe:	b9 20 00 00 00       	mov    ecx,0x20
   140003503:	e8 c8 fc ff ff       	call   1400031d0 <__pformat_putc>
   140003508:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000350c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000350f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003512:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003516:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003519:	85 c0                	test   eax,eax
   14000351b:	7f da                	jg     1400034f7 <__pformat_wputchars+0x11e>
   14000351d:	90                   	nop
   14000351e:	90                   	nop
   14000351f:	48 83 c4 50          	add    rsp,0x50
   140003523:	5d                   	pop    rbp
   140003524:	c3                   	ret

0000000140003525 <__pformat_wcputs>:
   140003525:	55                   	push   rbp
   140003526:	48 89 e5             	mov    rbp,rsp
   140003529:	48 83 ec 20          	sub    rsp,0x20
   14000352d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003531:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003535:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000353a:	75 0b                	jne    140003547 <__pformat_wcputs+0x22>
   14000353c:	48 8d 05 f5 7d 00 00 	lea    rax,[rip+0x7df5]        # 14000b338 <.rdata+0x8>
   140003543:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003547:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000354b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000354e:	85 c0                	test   eax,eax
   140003550:	78 2f                	js     140003581 <__pformat_wcputs+0x5c>
   140003552:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003556:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003559:	48 63 d0             	movsxd rdx,eax
   14000355c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003560:	48 89 c1             	mov    rcx,rax
   140003563:	e8 28 58 00 00       	call   140008d90 <wcsnlen>
   140003568:	89 c1                	mov    ecx,eax
   14000356a:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000356e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003572:	49 89 d0             	mov    r8,rdx
   140003575:	89 ca                	mov    edx,ecx
   140003577:	48 89 c1             	mov    rcx,rax
   14000357a:	e8 5a fe ff ff       	call   1400033d9 <__pformat_wputchars>
   14000357f:	eb 23                	jmp    1400035a4 <__pformat_wcputs+0x7f>
   140003581:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003585:	48 89 c1             	mov    rcx,rax
   140003588:	e8 1b 60 00 00       	call   1400095a8 <wcslen>
   14000358d:	89 c1                	mov    ecx,eax
   14000358f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003593:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003597:	49 89 d0             	mov    r8,rdx
   14000359a:	89 ca                	mov    edx,ecx
   14000359c:	48 89 c1             	mov    rcx,rax
   14000359f:	e8 35 fe ff ff       	call   1400033d9 <__pformat_wputchars>
   1400035a4:	90                   	nop
   1400035a5:	48 83 c4 20          	add    rsp,0x20
   1400035a9:	5d                   	pop    rbp
   1400035aa:	c3                   	ret

00000001400035ab <__pformat_int_bufsiz>:
   1400035ab:	55                   	push   rbp
   1400035ac:	48 89 e5             	mov    rbp,rsp
   1400035af:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400035b2:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400035b5:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400035b9:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035bc:	83 e8 01             	sub    eax,0x1
   1400035bf:	48 98                	cdqe
   1400035c1:	48 83 c0 40          	add    rax,0x40
   1400035c5:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400035c8:	48 63 ca             	movsxd rcx,edx
   1400035cb:	ba 00 00 00 00       	mov    edx,0x0
   1400035d0:	48 f7 f1             	div    rcx
   1400035d3:	89 c2                	mov    edx,eax
   1400035d5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400035d8:	01 d0                	add    eax,edx
   1400035da:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400035dd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035e1:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400035e4:	ba 00 00 00 00       	mov    edx,0x0
   1400035e9:	85 c0                	test   eax,eax
   1400035eb:	0f 48 c2             	cmovs  eax,edx
   1400035ee:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   1400035f1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035f5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400035f8:	25 00 10 00 00       	and    eax,0x1000
   1400035fd:	85 c0                	test   eax,eax
   1400035ff:	74 29                	je     14000362a <__pformat_int_bufsiz+0x7f>
   140003601:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003605:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003609:	66 85 c0             	test   ax,ax
   14000360c:	74 1c                	je     14000362a <__pformat_int_bufsiz+0x7f>
   14000360e:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003611:	48 63 d0             	movsxd rdx,eax
   140003614:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   14000361b:	48 89 d1             	mov    rcx,rdx
   14000361e:	48 c1 e9 20          	shr    rcx,0x20
   140003622:	99                   	cdq
   140003623:	89 c8                	mov    eax,ecx
   140003625:	29 d0                	sub    eax,edx
   140003627:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   14000362a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000362e:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140003631:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003634:	39 c2                	cmp    edx,eax
   140003636:	0f 4d c2             	cmovge eax,edx
   140003639:	5d                   	pop    rbp
   14000363a:	c3                   	ret

000000014000363b <__pformat_int>:
   14000363b:	55                   	push   rbp
   14000363c:	53                   	push   rbx
   14000363d:	48 83 ec 58          	sub    rsp,0x58
   140003641:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003646:	48 89 cb             	mov    rbx,rcx
   140003649:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   14000364c:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   140003650:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   140003654:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   140003658:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000365c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003660:	49 89 c0             	mov    r8,rax
   140003663:	ba 03 00 00 00       	mov    edx,0x3
   140003668:	b9 01 00 00 00       	mov    ecx,0x1
   14000366d:	e8 39 ff ff ff       	call   1400035ab <__pformat_int_bufsiz>
   140003672:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140003675:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   14000367c:	00 
   14000367d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140003680:	48 98                	cdqe
   140003682:	48 83 c0 0f          	add    rax,0xf
   140003686:	48 c1 e8 04          	shr    rax,0x4
   14000368a:	48 c1 e0 04          	shl    rax,0x4
   14000368e:	e8 0d fa ff ff       	call   1400030a0 <___chkstk_ms>
   140003693:	48 29 c4             	sub    rsp,rax
   140003696:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000369b:	48 83 c0 0f          	add    rax,0xf
   14000369f:	48 c1 e8 04          	shr    rax,0x4
   1400036a3:	48 c1 e0 04          	shl    rax,0x4
   1400036a7:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400036ab:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400036af:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400036b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036b7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400036ba:	25 80 00 00 00       	and    eax,0x80
   1400036bf:	85 c0                	test   eax,eax
   1400036c1:	0f 84 ea 00 00 00    	je     1400037b1 <__pformat_int+0x176>
   1400036c7:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400036cb:	48 85 c0             	test   rax,rax
   1400036ce:	79 10                	jns    1400036e0 <__pformat_int+0xa5>
   1400036d0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400036d4:	48 f7 d8             	neg    rax
   1400036d7:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400036db:	e9 d1 00 00 00       	jmp    1400037b1 <__pformat_int+0x176>
   1400036e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036e4:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400036e7:	24 7f                	and    al,0x7f
   1400036e9:	89 c2                	mov    edx,eax
   1400036eb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036ef:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400036f2:	e9 ba 00 00 00       	jmp    1400037b1 <__pformat_int+0x176>
   1400036f7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036fb:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400036ff:	74 54                	je     140003755 <__pformat_int+0x11a>
   140003701:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003705:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003708:	25 00 10 00 00       	and    eax,0x1000
   14000370d:	85 c0                	test   eax,eax
   14000370f:	74 44                	je     140003755 <__pformat_int+0x11a>
   140003711:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003715:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003719:	66 85 c0             	test   ax,ax
   14000371c:	74 37                	je     140003755 <__pformat_int+0x11a>
   14000371e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003722:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   140003726:	48 89 c2             	mov    rdx,rax
   140003729:	48 89 d0             	mov    rax,rdx
   14000372c:	48 c1 f8 3f          	sar    rax,0x3f
   140003730:	48 c1 e8 3e          	shr    rax,0x3e
   140003734:	48 01 c2             	add    rdx,rax
   140003737:	83 e2 03             	and    edx,0x3
   14000373a:	48 29 c2             	sub    rdx,rax
   14000373d:	48 89 d0             	mov    rax,rdx
   140003740:	48 83 f8 03          	cmp    rax,0x3
   140003744:	75 0f                	jne    140003755 <__pformat_int+0x11a>
   140003746:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000374a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000374e:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003752:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   140003755:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   140003759:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003760:	cc cc cc 
   140003763:	48 89 c8             	mov    rax,rcx
   140003766:	48 f7 e2             	mul    rdx
   140003769:	48 c1 ea 03          	shr    rdx,0x3
   14000376d:	48 89 d0             	mov    rax,rdx
   140003770:	48 c1 e0 02          	shl    rax,0x2
   140003774:	48 01 d0             	add    rax,rdx
   140003777:	48 01 c0             	add    rax,rax
   14000377a:	48 29 c1             	sub    rcx,rax
   14000377d:	48 89 ca             	mov    rdx,rcx
   140003780:	89 d0                	mov    eax,edx
   140003782:	8d 48 30             	lea    ecx,[rax+0x30]
   140003785:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003789:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000378d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003791:	89 ca                	mov    edx,ecx
   140003793:	88 10                	mov    BYTE PTR [rax],dl
   140003795:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003799:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400037a0:	cc cc cc 
   1400037a3:	48 f7 e2             	mul    rdx
   1400037a6:	48 89 d0             	mov    rax,rdx
   1400037a9:	48 c1 e8 03          	shr    rax,0x3
   1400037ad:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400037b1:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400037b5:	48 85 c0             	test   rax,rax
   1400037b8:	0f 85 39 ff ff ff    	jne    1400036f7 <__pformat_int+0xbc>
   1400037be:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037c2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400037c5:	85 c0                	test   eax,eax
   1400037c7:	7e 3e                	jle    140003807 <__pformat_int+0x1cc>
   1400037c9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037cd:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400037d0:	89 c1                	mov    ecx,eax
   1400037d2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037d6:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400037da:	89 c2                	mov    edx,eax
   1400037dc:	89 c8                	mov    eax,ecx
   1400037de:	29 d0                	sub    eax,edx
   1400037e0:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400037e3:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   1400037e7:	7e 1e                	jle    140003807 <__pformat_int+0x1cc>
   1400037e9:	eb 0f                	jmp    1400037fa <__pformat_int+0x1bf>
   1400037eb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037ef:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037f3:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037f7:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400037fa:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400037fd:	8d 50 ff             	lea    edx,[rax-0x1]
   140003800:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   140003803:	85 c0                	test   eax,eax
   140003805:	7f e4                	jg     1400037eb <__pformat_int+0x1b0>
   140003807:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000380b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000380f:	75 1a                	jne    14000382b <__pformat_int+0x1f0>
   140003811:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003815:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003818:	85 c0                	test   eax,eax
   14000381a:	74 0f                	je     14000382b <__pformat_int+0x1f0>
   14000381c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003820:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003824:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003828:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000382b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000382f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003832:	85 c0                	test   eax,eax
   140003834:	0f 8e ce 00 00 00    	jle    140003908 <__pformat_int+0x2cd>
   14000383a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000383e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003841:	89 c1                	mov    ecx,eax
   140003843:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003847:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000384b:	89 c2                	mov    edx,eax
   14000384d:	89 c8                	mov    eax,ecx
   14000384f:	29 d0                	sub    eax,edx
   140003851:	89 c2                	mov    edx,eax
   140003853:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003857:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000385a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000385e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003861:	85 c0                	test   eax,eax
   140003863:	0f 8e 9f 00 00 00    	jle    140003908 <__pformat_int+0x2cd>
   140003869:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000386d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003870:	25 c0 01 00 00       	and    eax,0x1c0
   140003875:	85 c0                	test   eax,eax
   140003877:	74 11                	je     14000388a <__pformat_int+0x24f>
   140003879:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000387d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003880:	8d 50 ff             	lea    edx,[rax-0x1]
   140003883:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003887:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000388a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000388e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003891:	85 c0                	test   eax,eax
   140003893:	79 3b                	jns    1400038d0 <__pformat_int+0x295>
   140003895:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003899:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000389c:	25 00 06 00 00       	and    eax,0x600
   1400038a1:	3d 00 02 00 00       	cmp    eax,0x200
   1400038a6:	75 28                	jne    1400038d0 <__pformat_int+0x295>
   1400038a8:	eb 0f                	jmp    1400038b9 <__pformat_int+0x27e>
   1400038aa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038ae:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038b2:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038b6:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400038b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038bd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038c0:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400038c3:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400038c7:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400038ca:	85 c0                	test   eax,eax
   1400038cc:	7f dc                	jg     1400038aa <__pformat_int+0x26f>
   1400038ce:	eb 38                	jmp    140003908 <__pformat_int+0x2cd>
   1400038d0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038d4:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038d7:	25 00 04 00 00       	and    eax,0x400
   1400038dc:	85 c0                	test   eax,eax
   1400038de:	75 28                	jne    140003908 <__pformat_int+0x2cd>
   1400038e0:	eb 11                	jmp    1400038f3 <__pformat_int+0x2b8>
   1400038e2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038e6:	48 89 c2             	mov    rdx,rax
   1400038e9:	b9 20 00 00 00       	mov    ecx,0x20
   1400038ee:	e8 dd f8 ff ff       	call   1400031d0 <__pformat_putc>
   1400038f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038f7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038fa:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400038fd:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003901:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003904:	85 c0                	test   eax,eax
   140003906:	7f da                	jg     1400038e2 <__pformat_int+0x2a7>
   140003908:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000390c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000390f:	25 80 00 00 00       	and    eax,0x80
   140003914:	85 c0                	test   eax,eax
   140003916:	74 11                	je     140003929 <__pformat_int+0x2ee>
   140003918:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000391c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003920:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003924:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   140003927:	eb 5a                	jmp    140003983 <__pformat_int+0x348>
   140003929:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000392d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003930:	25 00 01 00 00       	and    eax,0x100
   140003935:	85 c0                	test   eax,eax
   140003937:	74 11                	je     14000394a <__pformat_int+0x30f>
   140003939:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000393d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003941:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003945:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140003948:	eb 39                	jmp    140003983 <__pformat_int+0x348>
   14000394a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000394e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003951:	83 e0 40             	and    eax,0x40
   140003954:	85 c0                	test   eax,eax
   140003956:	74 2b                	je     140003983 <__pformat_int+0x348>
   140003958:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000395c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003960:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003964:	c6 00 20             	mov    BYTE PTR [rax],0x20
   140003967:	eb 1a                	jmp    140003983 <__pformat_int+0x348>
   140003969:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   14000396e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003972:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003975:	0f be c0             	movsx  eax,al
   140003978:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000397c:	89 c1                	mov    ecx,eax
   14000397e:	e8 4d f8 ff ff       	call   1400031d0 <__pformat_putc>
   140003983:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003987:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   14000398b:	72 dc                	jb     140003969 <__pformat_int+0x32e>
   14000398d:	eb 11                	jmp    1400039a0 <__pformat_int+0x365>
   14000398f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003993:	48 89 c2             	mov    rdx,rax
   140003996:	b9 20 00 00 00       	mov    ecx,0x20
   14000399b:	e8 30 f8 ff ff       	call   1400031d0 <__pformat_putc>
   1400039a0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039a4:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400039a7:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400039aa:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400039ae:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400039b1:	85 c0                	test   eax,eax
   1400039b3:	7f da                	jg     14000398f <__pformat_int+0x354>
   1400039b5:	90                   	nop
   1400039b6:	90                   	nop
   1400039b7:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   1400039bb:	5b                   	pop    rbx
   1400039bc:	5d                   	pop    rbp
   1400039bd:	c3                   	ret

00000001400039be <__pformat_xint>:
   1400039be:	55                   	push   rbp
   1400039bf:	53                   	push   rbx
   1400039c0:	48 83 ec 68          	sub    rsp,0x68
   1400039c4:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   1400039c9:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   1400039cc:	48 89 d3             	mov    rbx,rdx
   1400039cf:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   1400039d2:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   1400039d6:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400039da:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400039de:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400039e2:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   1400039e6:	74 1e                	je     140003a06 <__pformat_xint+0x48>
   1400039e8:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   1400039ec:	74 06                	je     1400039f4 <__pformat_xint+0x36>
   1400039ee:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   1400039f2:	75 09                	jne    1400039fd <__pformat_xint+0x3f>
   1400039f4:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400039fb:	eb 10                	jmp    140003a0d <__pformat_xint+0x4f>
   1400039fd:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003a04:	eb 07                	jmp    140003a0d <__pformat_xint+0x4f>
   140003a06:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140003a0d:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003a11:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003a14:	49 89 d0             	mov    r8,rdx
   140003a17:	89 c2                	mov    edx,eax
   140003a19:	b9 02 00 00 00       	mov    ecx,0x2
   140003a1e:	e8 88 fb ff ff       	call   1400035ab <__pformat_int_bufsiz>
   140003a23:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140003a26:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   140003a2d:	00 
   140003a2e:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140003a31:	48 98                	cdqe
   140003a33:	48 83 c0 0f          	add    rax,0xf
   140003a37:	48 c1 e8 04          	shr    rax,0x4
   140003a3b:	48 c1 e0 04          	shl    rax,0x4
   140003a3f:	e8 5c f6 ff ff       	call   1400030a0 <___chkstk_ms>
   140003a44:	48 29 c4             	sub    rsp,rax
   140003a47:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003a4c:	48 83 c0 0f          	add    rax,0xf
   140003a50:	48 c1 e8 04          	shr    rax,0x4
   140003a54:	48 c1 e0 04          	shl    rax,0x4
   140003a58:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140003a5c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003a60:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003a64:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a68:	74 1e                	je     140003a88 <__pformat_xint+0xca>
   140003a6a:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a6e:	74 06                	je     140003a76 <__pformat_xint+0xb8>
   140003a70:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a74:	75 09                	jne    140003a7f <__pformat_xint+0xc1>
   140003a76:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003a7d:	eb 10                	jmp    140003a8f <__pformat_xint+0xd1>
   140003a7f:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003a86:	eb 67                	jmp    140003aef <__pformat_xint+0x131>
   140003a88:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003a8f:	eb 5e                	jmp    140003aef <__pformat_xint+0x131>
   140003a91:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003a95:	89 c2                	mov    edx,eax
   140003a97:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003a9a:	21 d0                	and    eax,edx
   140003a9c:	8d 48 30             	lea    ecx,[rax+0x30]
   140003a9f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003aa3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003aa7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003aab:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003aaf:	89 ca                	mov    edx,ecx
   140003ab1:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003ab5:	88 10                	mov    BYTE PTR [rax],dl
   140003ab7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003abb:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003abe:	3c 39                	cmp    al,0x39
   140003ac0:	7e 1a                	jle    140003adc <__pformat_xint+0x11e>
   140003ac2:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003ac6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003ac9:	83 c0 07             	add    eax,0x7
   140003acc:	89 c2                	mov    edx,eax
   140003ace:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003ad1:	83 e0 20             	and    eax,0x20
   140003ad4:	09 c2                	or     edx,eax
   140003ad6:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003ada:	88 10                	mov    BYTE PTR [rax],dl
   140003adc:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003ae0:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003ae3:	89 c1                	mov    ecx,eax
   140003ae5:	48 d3 ea             	shr    rdx,cl
   140003ae8:	48 89 d0             	mov    rax,rdx
   140003aeb:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003aef:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003af3:	48 85 c0             	test   rax,rax
   140003af6:	75 99                	jne    140003a91 <__pformat_xint+0xd3>
   140003af8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003afc:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b00:	75 13                	jne    140003b15 <__pformat_xint+0x157>
   140003b02:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b06:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b09:	80 e4 f7             	and    ah,0xf7
   140003b0c:	89 c2                	mov    edx,eax
   140003b0e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b12:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003b15:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b19:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b1c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b1f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b23:	7e 3a                	jle    140003b5f <__pformat_xint+0x1a1>
   140003b25:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003b28:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b2c:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003b30:	89 c1                	mov    ecx,eax
   140003b32:	89 d0                	mov    eax,edx
   140003b34:	29 c8                	sub    eax,ecx
   140003b36:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b39:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b3d:	7e 20                	jle    140003b5f <__pformat_xint+0x1a1>
   140003b3f:	eb 0f                	jmp    140003b50 <__pformat_xint+0x192>
   140003b41:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b45:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b49:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b4d:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b50:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003b53:	8d 50 ff             	lea    edx,[rax-0x1]
   140003b56:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b59:	85 c0                	test   eax,eax
   140003b5b:	7f e4                	jg     140003b41 <__pformat_xint+0x183>
   140003b5d:	eb 25                	jmp    140003b84 <__pformat_xint+0x1c6>
   140003b5f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003b63:	75 1f                	jne    140003b84 <__pformat_xint+0x1c6>
   140003b65:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b69:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b6c:	25 00 08 00 00       	and    eax,0x800
   140003b71:	85 c0                	test   eax,eax
   140003b73:	74 0f                	je     140003b84 <__pformat_xint+0x1c6>
   140003b75:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b79:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b7d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b81:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b84:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b88:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b8c:	75 1a                	jne    140003ba8 <__pformat_xint+0x1ea>
   140003b8e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b92:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b95:	85 c0                	test   eax,eax
   140003b97:	74 0f                	je     140003ba8 <__pformat_xint+0x1ea>
   140003b99:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b9d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ba1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003ba5:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003ba8:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bac:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003baf:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003bb3:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003bb7:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bba:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003bbd:	7d 15                	jge    140003bd4 <__pformat_xint+0x216>
   140003bbf:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bc3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003bc6:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003bc9:	89 c2                	mov    edx,eax
   140003bcb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bcf:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003bd2:	eb 0b                	jmp    140003bdf <__pformat_xint+0x221>
   140003bd4:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bd8:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003bdf:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003be3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003be6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003be9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003bed:	7e 1a                	jle    140003c09 <__pformat_xint+0x24b>
   140003bef:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003bf3:	74 14                	je     140003c09 <__pformat_xint+0x24b>
   140003bf5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bf9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bfc:	25 00 08 00 00       	and    eax,0x800
   140003c01:	85 c0                	test   eax,eax
   140003c03:	74 04                	je     140003c09 <__pformat_xint+0x24b>
   140003c05:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003c09:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c0d:	7e 3c                	jle    140003c4b <__pformat_xint+0x28d>
   140003c0f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c13:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003c16:	85 c0                	test   eax,eax
   140003c18:	79 31                	jns    140003c4b <__pformat_xint+0x28d>
   140003c1a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c1e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c21:	25 00 06 00 00       	and    eax,0x600
   140003c26:	3d 00 02 00 00       	cmp    eax,0x200
   140003c2b:	75 1e                	jne    140003c4b <__pformat_xint+0x28d>
   140003c2d:	eb 0f                	jmp    140003c3e <__pformat_xint+0x280>
   140003c2f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c33:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c37:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c3b:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c3e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c41:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c44:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c47:	85 c0                	test   eax,eax
   140003c49:	7f e4                	jg     140003c2f <__pformat_xint+0x271>
   140003c4b:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c4f:	74 30                	je     140003c81 <__pformat_xint+0x2c3>
   140003c51:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c55:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c58:	25 00 08 00 00       	and    eax,0x800
   140003c5d:	85 c0                	test   eax,eax
   140003c5f:	74 20                	je     140003c81 <__pformat_xint+0x2c3>
   140003c61:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c65:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c69:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c6d:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003c70:	88 10                	mov    BYTE PTR [rax],dl
   140003c72:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c76:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c7a:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c7e:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c81:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c85:	7e 4c                	jle    140003cd3 <__pformat_xint+0x315>
   140003c87:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c8b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c8e:	25 00 04 00 00       	and    eax,0x400
   140003c93:	85 c0                	test   eax,eax
   140003c95:	75 3c                	jne    140003cd3 <__pformat_xint+0x315>
   140003c97:	eb 11                	jmp    140003caa <__pformat_xint+0x2ec>
   140003c99:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c9d:	48 89 c2             	mov    rdx,rax
   140003ca0:	b9 20 00 00 00       	mov    ecx,0x20
   140003ca5:	e8 26 f5 ff ff       	call   1400031d0 <__pformat_putc>
   140003caa:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003cad:	8d 50 ff             	lea    edx,[rax-0x1]
   140003cb0:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003cb3:	85 c0                	test   eax,eax
   140003cb5:	7f e2                	jg     140003c99 <__pformat_xint+0x2db>
   140003cb7:	eb 1a                	jmp    140003cd3 <__pformat_xint+0x315>
   140003cb9:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003cbe:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cc2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003cc5:	0f be c0             	movsx  eax,al
   140003cc8:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003ccc:	89 c1                	mov    ecx,eax
   140003cce:	e8 fd f4 ff ff       	call   1400031d0 <__pformat_putc>
   140003cd3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cd7:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003cdb:	72 dc                	jb     140003cb9 <__pformat_xint+0x2fb>
   140003cdd:	eb 11                	jmp    140003cf0 <__pformat_xint+0x332>
   140003cdf:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ce3:	48 89 c2             	mov    rdx,rax
   140003ce6:	b9 20 00 00 00       	mov    ecx,0x20
   140003ceb:	e8 e0 f4 ff ff       	call   1400031d0 <__pformat_putc>
   140003cf0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003cf3:	8d 50 ff             	lea    edx,[rax-0x1]
   140003cf6:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003cf9:	85 c0                	test   eax,eax
   140003cfb:	7f e2                	jg     140003cdf <__pformat_xint+0x321>
   140003cfd:	90                   	nop
   140003cfe:	90                   	nop
   140003cff:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003d03:	5b                   	pop    rbx
   140003d04:	5d                   	pop    rbp
   140003d05:	c3                   	ret

0000000140003d06 <init_fpreg_ldouble>:
   140003d06:	55                   	push   rbp
   140003d07:	53                   	push   rbx
   140003d08:	48 83 ec 28          	sub    rsp,0x28
   140003d0c:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003d11:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003d15:	48 89 d3             	mov    rbx,rdx
   140003d18:	db 2b                	fld    TBYTE PTR [rbx]
   140003d1a:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003d1d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003d20:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003d23:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003d27:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d2b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003d2f:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003d32:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003d36:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003d3a:	48 83 c4 28          	add    rsp,0x28
   140003d3e:	5b                   	pop    rbx
   140003d3f:	5d                   	pop    rbp
   140003d40:	c3                   	ret

0000000140003d41 <__pformat_cvt>:
   140003d41:	55                   	push   rbp
   140003d42:	53                   	push   rbx
   140003d43:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003d4a:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003d51:	00 
   140003d52:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003d55:	48 89 d3             	mov    rbx,rdx
   140003d58:	db 2b                	fld    TBYTE PTR [rbx]
   140003d5a:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003d5d:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003d61:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003d65:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003d6c:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003d70:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003d73:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003d76:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003d7a:	48 89 c1             	mov    rcx,rax
   140003d7d:	e8 84 ff ff ff       	call   140003d06 <init_fpreg_ldouble>
   140003d82:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003d85:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003d88:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003d8c:	48 89 c1             	mov    rcx,rax
   140003d8f:	e8 9c 4e 00 00       	call   140008c30 <__fpclassifyl>
   140003d94:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d97:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d9a:	25 00 01 00 00       	and    eax,0x100
   140003d9f:	85 c0                	test   eax,eax
   140003da1:	74 1d                	je     140003dc0 <__pformat_cvt+0x7f>
   140003da3:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003da6:	25 00 04 00 00       	and    eax,0x400
   140003dab:	85 c0                	test   eax,eax
   140003dad:	74 07                	je     140003db6 <__pformat_cvt+0x75>
   140003daf:	b8 03 00 00 00       	mov    eax,0x3
   140003db4:	eb 05                	jmp    140003dbb <__pformat_cvt+0x7a>
   140003db6:	b8 04 00 00 00       	mov    eax,0x4
   140003dbb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003dbe:	eb 4a                	jmp    140003e0a <__pformat_cvt+0xc9>
   140003dc0:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003dc3:	25 00 04 00 00       	and    eax,0x400
   140003dc8:	85 c0                	test   eax,eax
   140003dca:	74 37                	je     140003e03 <__pformat_cvt+0xc2>
   140003dcc:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003dcf:	25 00 40 00 00       	and    eax,0x4000
   140003dd4:	85 c0                	test   eax,eax
   140003dd6:	74 10                	je     140003de8 <__pformat_cvt+0xa7>
   140003dd8:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003ddf:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003de6:	eb 22                	jmp    140003e0a <__pformat_cvt+0xc9>
   140003de8:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003def:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003df3:	98                   	cwde
   140003df4:	25 ff 7f 00 00       	and    eax,0x7fff
   140003df9:	2d 3e 40 00 00       	sub    eax,0x403e
   140003dfe:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003e01:	eb 07                	jmp    140003e0a <__pformat_cvt+0xc9>
   140003e03:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003e0a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e0d:	83 f8 04             	cmp    eax,0x4
   140003e10:	74 0e                	je     140003e20 <__pformat_cvt+0xdf>
   140003e12:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e16:	98                   	cwde
   140003e17:	25 00 80 00 00       	and    eax,0x8000
   140003e1c:	89 c2                	mov    edx,eax
   140003e1e:	eb 05                	jmp    140003e25 <__pformat_cvt+0xe4>
   140003e20:	ba 00 00 00 00       	mov    edx,0x0
   140003e25:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003e29:	89 10                	mov    DWORD PTR [rax],edx
   140003e2b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003e2e:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003e32:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003e36:	48 8d 0d 33 62 00 00 	lea    rcx,[rip+0x6233]        # 14000a070 <fpi.0>
   140003e3d:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003e41:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003e46:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e4a:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003e4f:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003e52:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003e56:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003e59:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003e5d:	89 c2                	mov    edx,eax
   140003e5f:	e8 96 24 00 00       	call   1400062fa <__gdtoa>
   140003e64:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003e6b:	5b                   	pop    rbx
   140003e6c:	5d                   	pop    rbp
   140003e6d:	c3                   	ret

0000000140003e6e <__pformat_ecvt>:
   140003e6e:	55                   	push   rbp
   140003e6f:	53                   	push   rbx
   140003e70:	48 83 ec 58          	sub    rsp,0x58
   140003e74:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003e79:	48 89 cb             	mov    rbx,rcx
   140003e7c:	db 2b                	fld    TBYTE PTR [rbx]
   140003e7e:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003e81:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003e84:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003e88:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003e8c:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003e8f:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003e92:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003e96:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003e99:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e9d:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003ea1:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003ea6:	4d 89 c1             	mov    r9,r8
   140003ea9:	41 89 c8             	mov    r8d,ecx
   140003eac:	48 89 c2             	mov    rdx,rax
   140003eaf:	b9 02 00 00 00       	mov    ecx,0x2
   140003eb4:	e8 88 fe ff ff       	call   140003d41 <__pformat_cvt>
   140003eb9:	48 83 c4 58          	add    rsp,0x58
   140003ebd:	5b                   	pop    rbx
   140003ebe:	5d                   	pop    rbp
   140003ebf:	c3                   	ret

0000000140003ec0 <__pformat_fcvt>:
   140003ec0:	55                   	push   rbp
   140003ec1:	53                   	push   rbx
   140003ec2:	48 83 ec 58          	sub    rsp,0x58
   140003ec6:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003ecb:	48 89 cb             	mov    rbx,rcx
   140003ece:	db 2b                	fld    TBYTE PTR [rbx]
   140003ed0:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003ed3:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003ed6:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003eda:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003ede:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003ee1:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003ee4:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003ee8:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003eeb:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003eef:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003ef3:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003ef8:	4d 89 c1             	mov    r9,r8
   140003efb:	41 89 c8             	mov    r8d,ecx
   140003efe:	48 89 c2             	mov    rdx,rax
   140003f01:	b9 03 00 00 00       	mov    ecx,0x3
   140003f06:	e8 36 fe ff ff       	call   140003d41 <__pformat_cvt>
   140003f0b:	48 83 c4 58          	add    rsp,0x58
   140003f0f:	5b                   	pop    rbx
   140003f10:	5d                   	pop    rbp
   140003f11:	c3                   	ret

0000000140003f12 <__pformat_emit_radix_point>:
   140003f12:	55                   	push   rbp
   140003f13:	53                   	push   rbx
   140003f14:	48 83 ec 68          	sub    rsp,0x68
   140003f18:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003f1d:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003f21:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f25:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f28:	83 f8 fd             	cmp    eax,0xfffffffd
   140003f2b:	75 48                	jne    140003f75 <__pformat_emit_radix_point+0x63>
   140003f2d:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003f34:	00 
   140003f35:	e8 1e 56 00 00       	call   140009558 <localeconv>
   140003f3a:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003f3d:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003f41:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003f45:	49 89 c9             	mov    r9,rcx
   140003f48:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003f4e:	48 89 c1             	mov    rcx,rax
   140003f51:	e8 4a 50 00 00       	call   140008fa0 <mbrtowc>
   140003f56:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003f59:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003f5d:	7e 0c                	jle    140003f6b <__pformat_emit_radix_point+0x59>
   140003f5f:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003f63:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f67:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003f6b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f6f:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003f72:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003f75:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f79:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003f7d:	66 85 c0             	test   ax,ax
   140003f80:	0f 84 b8 00 00 00    	je     14000403e <__pformat_emit_radix_point+0x12c>
   140003f86:	48 89 e0             	mov    rax,rsp
   140003f89:	48 89 c3             	mov    rbx,rax
   140003f8c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f90:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f93:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003f96:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003f99:	48 63 d0             	movsxd rdx,eax
   140003f9c:	48 83 ea 01          	sub    rdx,0x1
   140003fa0:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140003fa4:	48 98                	cdqe
   140003fa6:	48 83 c0 0f          	add    rax,0xf
   140003faa:	48 c1 e8 04          	shr    rax,0x4
   140003fae:	48 c1 e0 04          	shl    rax,0x4
   140003fb2:	e8 e9 f0 ff ff       	call   1400030a0 <___chkstk_ms>
   140003fb7:	48 29 c4             	sub    rsp,rax
   140003fba:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003fbf:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003fc3:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   140003fca:	00 
   140003fcb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fcf:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003fd3:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140003fd7:	0f b7 d0             	movzx  edx,ax
   140003fda:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003fde:	49 89 c8             	mov    r8,rcx
   140003fe1:	48 89 c1             	mov    rcx,rax
   140003fe4:	e8 67 4f 00 00       	call   140008f50 <wcrtomb>
   140003fe9:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003fec:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003ff0:	7e 36                	jle    140004028 <__pformat_emit_radix_point+0x116>
   140003ff2:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003ff6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003ffa:	eb 1d                	jmp    140004019 <__pformat_emit_radix_point+0x107>
   140003ffc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004000:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004004:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004008:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000400b:	0f be c0             	movsx  eax,al
   14000400e:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004012:	89 c1                	mov    ecx,eax
   140004014:	e8 b7 f1 ff ff       	call   1400031d0 <__pformat_putc>
   140004019:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000401c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000401f:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140004022:	85 c0                	test   eax,eax
   140004024:	7f d6                	jg     140003ffc <__pformat_emit_radix_point+0xea>
   140004026:	eb 11                	jmp    140004039 <__pformat_emit_radix_point+0x127>
   140004028:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000402c:	48 89 c2             	mov    rdx,rax
   14000402f:	b9 2e 00 00 00       	mov    ecx,0x2e
   140004034:	e8 97 f1 ff ff       	call   1400031d0 <__pformat_putc>
   140004039:	48 89 dc             	mov    rsp,rbx
   14000403c:	eb 11                	jmp    14000404f <__pformat_emit_radix_point+0x13d>
   14000403e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004042:	48 89 c2             	mov    rdx,rax
   140004045:	b9 2e 00 00 00       	mov    ecx,0x2e
   14000404a:	e8 81 f1 ff ff       	call   1400031d0 <__pformat_putc>
   14000404f:	90                   	nop
   140004050:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140004054:	5b                   	pop    rbx
   140004055:	5d                   	pop    rbp
   140004056:	c3                   	ret

0000000140004057 <__pformat_emit_numeric_value>:
   140004057:	55                   	push   rbp
   140004058:	48 89 e5             	mov    rbp,rsp
   14000405b:	48 83 ec 30          	sub    rsp,0x30
   14000405f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004062:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004066:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   14000406a:	75 0e                	jne    14000407a <__pformat_emit_numeric_value+0x23>
   14000406c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004070:	48 89 c1             	mov    rcx,rax
   140004073:	e8 9a fe ff ff       	call   140003f12 <__pformat_emit_radix_point>
   140004078:	eb 43                	jmp    1400040bd <__pformat_emit_numeric_value+0x66>
   14000407a:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   14000407e:	75 2f                	jne    1400040af <__pformat_emit_numeric_value+0x58>
   140004080:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004084:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004088:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   14000408c:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   140004090:	66 85 c0             	test   ax,ax
   140004093:	74 28                	je     1400040bd <__pformat_emit_numeric_value+0x66>
   140004095:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004099:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   14000409d:	49 89 d0             	mov    r8,rdx
   1400040a0:	ba 01 00 00 00       	mov    edx,0x1
   1400040a5:	48 89 c1             	mov    rcx,rax
   1400040a8:	e8 2c f3 ff ff       	call   1400033d9 <__pformat_wputchars>
   1400040ad:	eb 0e                	jmp    1400040bd <__pformat_emit_numeric_value+0x66>
   1400040af:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400040b3:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400040b6:	89 c1                	mov    ecx,eax
   1400040b8:	e8 13 f1 ff ff       	call   1400031d0 <__pformat_putc>
   1400040bd:	90                   	nop
   1400040be:	48 83 c4 30          	add    rsp,0x30
   1400040c2:	5d                   	pop    rbp
   1400040c3:	c3                   	ret

00000001400040c4 <__pformat_emit_inf_or_nan>:
   1400040c4:	55                   	push   rbp
   1400040c5:	48 89 e5             	mov    rbp,rsp
   1400040c8:	48 83 ec 40          	sub    rsp,0x40
   1400040cc:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400040cf:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400040d3:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400040d7:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400040db:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400040df:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040e3:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   1400040ea:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400040ee:	74 11                	je     140004101 <__pformat_emit_inf_or_nan+0x3d>
   1400040f0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040f4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040f8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040fc:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   1400040ff:	eb 3e                	jmp    14000413f <__pformat_emit_inf_or_nan+0x7b>
   140004101:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004105:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004108:	25 00 01 00 00       	and    eax,0x100
   14000410d:	85 c0                	test   eax,eax
   14000410f:	74 11                	je     140004122 <__pformat_emit_inf_or_nan+0x5e>
   140004111:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004115:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004119:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000411d:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140004120:	eb 1d                	jmp    14000413f <__pformat_emit_inf_or_nan+0x7b>
   140004122:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004126:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004129:	83 e0 40             	and    eax,0x40
   14000412c:	85 c0                	test   eax,eax
   14000412e:	74 0f                	je     14000413f <__pformat_emit_inf_or_nan+0x7b>
   140004130:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004134:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004138:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000413c:	c6 00 20             	mov    BYTE PTR [rax],0x20
   14000413f:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140004146:	eb 38                	jmp    140004180 <__pformat_emit_inf_or_nan+0xbc>
   140004148:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000414c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004150:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004154:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004157:	83 e0 df             	and    eax,0xffffffdf
   14000415a:	41 89 c0             	mov    r8d,eax
   14000415d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004161:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004164:	83 e0 20             	and    eax,0x20
   140004167:	89 c1                	mov    ecx,eax
   140004169:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000416d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004171:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004175:	44 89 c2             	mov    edx,r8d
   140004178:	09 ca                	or     edx,ecx
   14000417a:	88 10                	mov    BYTE PTR [rax],dl
   14000417c:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004180:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004184:	7f c2                	jg     140004148 <__pformat_emit_inf_or_nan+0x84>
   140004186:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000418a:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   14000418e:	48 29 c2             	sub    rdx,rax
   140004191:	89 d1                	mov    ecx,edx
   140004193:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004197:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000419b:	49 89 d0             	mov    r8,rdx
   14000419e:	89 ca                	mov    edx,ecx
   1400041a0:	48 89 c1             	mov    rcx,rax
   1400041a3:	e8 ac f0 ff ff       	call   140003254 <__pformat_putchars>
   1400041a8:	90                   	nop
   1400041a9:	48 83 c4 40          	add    rsp,0x40
   1400041ad:	5d                   	pop    rbp
   1400041ae:	c3                   	ret

00000001400041af <__pformat_emit_float>:
   1400041af:	55                   	push   rbp
   1400041b0:	48 89 e5             	mov    rbp,rsp
   1400041b3:	48 83 ec 30          	sub    rsp,0x30
   1400041b7:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400041ba:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400041be:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400041c2:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400041c6:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400041ca:	7e 2e                	jle    1400041fa <__pformat_emit_float+0x4b>
   1400041cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041d0:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041d3:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   1400041d6:	7f 15                	jg     1400041ed <__pformat_emit_float+0x3e>
   1400041d8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041dc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041df:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   1400041e2:	89 c2                	mov    edx,eax
   1400041e4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041e8:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400041eb:	eb 29                	jmp    140004216 <__pformat_emit_float+0x67>
   1400041ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041f1:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400041f8:	eb 1c                	jmp    140004216 <__pformat_emit_float+0x67>
   1400041fa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041fe:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004201:	85 c0                	test   eax,eax
   140004203:	7e 11                	jle    140004216 <__pformat_emit_float+0x67>
   140004205:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004209:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000420c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000420f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004213:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004216:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000421a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000421d:	85 c0                	test   eax,eax
   14000421f:	78 2b                	js     14000424c <__pformat_emit_float+0x9d>
   140004221:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004225:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004228:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000422c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000422f:	39 c2                	cmp    edx,eax
   140004231:	7e 19                	jle    14000424c <__pformat_emit_float+0x9d>
   140004233:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004237:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   14000423a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000423e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004241:	29 c2                	sub    edx,eax
   140004243:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004247:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000424a:	eb 0b                	jmp    140004257 <__pformat_emit_float+0xa8>
   14000424c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004250:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004257:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000425b:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000425e:	85 c0                	test   eax,eax
   140004260:	7e 2c                	jle    14000428e <__pformat_emit_float+0xdf>
   140004262:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004266:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004269:	85 c0                	test   eax,eax
   14000426b:	7f 10                	jg     14000427d <__pformat_emit_float+0xce>
   14000426d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004271:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004274:	25 00 08 00 00       	and    eax,0x800
   140004279:	85 c0                	test   eax,eax
   14000427b:	74 11                	je     14000428e <__pformat_emit_float+0xdf>
   14000427d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004281:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004284:	8d 50 ff             	lea    edx,[rax-0x1]
   140004287:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000428b:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000428e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004292:	7e 64                	jle    1400042f8 <__pformat_emit_float+0x149>
   140004294:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004298:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000429b:	25 00 10 00 00       	and    eax,0x1000
   1400042a0:	85 c0                	test   eax,eax
   1400042a2:	74 54                	je     1400042f8 <__pformat_emit_float+0x149>
   1400042a4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a8:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400042ac:	66 85 c0             	test   ax,ax
   1400042af:	74 47                	je     1400042f8 <__pformat_emit_float+0x149>
   1400042b1:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400042b4:	83 c0 02             	add    eax,0x2
   1400042b7:	48 63 d0             	movsxd rdx,eax
   1400042ba:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   1400042c1:	48 c1 ea 20          	shr    rdx,0x20
   1400042c5:	c1 f8 1f             	sar    eax,0x1f
   1400042c8:	29 c2                	sub    edx,eax
   1400042ca:	8d 42 ff             	lea    eax,[rdx-0x1]
   1400042cd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400042d0:	eb 15                	jmp    1400042e7 <__pformat_emit_float+0x138>
   1400042d2:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400042d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042da:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042dd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042e4:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042e7:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400042eb:	7e 0b                	jle    1400042f8 <__pformat_emit_float+0x149>
   1400042ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042f1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042f4:	85 c0                	test   eax,eax
   1400042f6:	7f da                	jg     1400042d2 <__pformat_emit_float+0x123>
   1400042f8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042fc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042ff:	85 c0                	test   eax,eax
   140004301:	7e 27                	jle    14000432a <__pformat_emit_float+0x17b>
   140004303:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004307:	75 10                	jne    140004319 <__pformat_emit_float+0x16a>
   140004309:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000430d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004310:	25 c0 01 00 00       	and    eax,0x1c0
   140004315:	85 c0                	test   eax,eax
   140004317:	74 11                	je     14000432a <__pformat_emit_float+0x17b>
   140004319:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000431d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004320:	8d 50 ff             	lea    edx,[rax-0x1]
   140004323:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004327:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000432a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000432e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004331:	85 c0                	test   eax,eax
   140004333:	7e 38                	jle    14000436d <__pformat_emit_float+0x1be>
   140004335:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004339:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000433c:	25 00 06 00 00       	and    eax,0x600
   140004341:	85 c0                	test   eax,eax
   140004343:	75 28                	jne    14000436d <__pformat_emit_float+0x1be>
   140004345:	eb 11                	jmp    140004358 <__pformat_emit_float+0x1a9>
   140004347:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000434b:	48 89 c2             	mov    rdx,rax
   14000434e:	b9 20 00 00 00       	mov    ecx,0x20
   140004353:	e8 78 ee ff ff       	call   1400031d0 <__pformat_putc>
   140004358:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000435c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000435f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004362:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004366:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004369:	85 c0                	test   eax,eax
   14000436b:	7f da                	jg     140004347 <__pformat_emit_float+0x198>
   14000436d:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004371:	74 13                	je     140004386 <__pformat_emit_float+0x1d7>
   140004373:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004377:	48 89 c2             	mov    rdx,rax
   14000437a:	b9 2d 00 00 00       	mov    ecx,0x2d
   14000437f:	e8 4c ee ff ff       	call   1400031d0 <__pformat_putc>
   140004384:	eb 42                	jmp    1400043c8 <__pformat_emit_float+0x219>
   140004386:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000438a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000438d:	25 00 01 00 00       	and    eax,0x100
   140004392:	85 c0                	test   eax,eax
   140004394:	74 13                	je     1400043a9 <__pformat_emit_float+0x1fa>
   140004396:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000439a:	48 89 c2             	mov    rdx,rax
   14000439d:	b9 2b 00 00 00       	mov    ecx,0x2b
   1400043a2:	e8 29 ee ff ff       	call   1400031d0 <__pformat_putc>
   1400043a7:	eb 1f                	jmp    1400043c8 <__pformat_emit_float+0x219>
   1400043a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ad:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043b0:	83 e0 40             	and    eax,0x40
   1400043b3:	85 c0                	test   eax,eax
   1400043b5:	74 11                	je     1400043c8 <__pformat_emit_float+0x219>
   1400043b7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043bb:	48 89 c2             	mov    rdx,rax
   1400043be:	b9 20 00 00 00       	mov    ecx,0x20
   1400043c3:	e8 08 ee ff ff       	call   1400031d0 <__pformat_putc>
   1400043c8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043cc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043cf:	85 c0                	test   eax,eax
   1400043d1:	7e 3b                	jle    14000440e <__pformat_emit_float+0x25f>
   1400043d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043d7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043da:	25 00 06 00 00       	and    eax,0x600
   1400043df:	3d 00 02 00 00       	cmp    eax,0x200
   1400043e4:	75 28                	jne    14000440e <__pformat_emit_float+0x25f>
   1400043e6:	eb 11                	jmp    1400043f9 <__pformat_emit_float+0x24a>
   1400043e8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ec:	48 89 c2             	mov    rdx,rax
   1400043ef:	b9 30 00 00 00       	mov    ecx,0x30
   1400043f4:	e8 d7 ed ff ff       	call   1400031d0 <__pformat_putc>
   1400043f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043fd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004400:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004403:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004407:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000440a:	85 c0                	test   eax,eax
   14000440c:	7f da                	jg     1400043e8 <__pformat_emit_float+0x239>
   14000440e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004412:	0f 8e a7 00 00 00    	jle    1400044bf <__pformat_emit_float+0x310>
   140004418:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000441c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000441f:	84 c0                	test   al,al
   140004421:	74 14                	je     140004437 <__pformat_emit_float+0x288>
   140004423:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004427:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000442b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000442f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004432:	0f be c0             	movsx  eax,al
   140004435:	eb 05                	jmp    14000443c <__pformat_emit_float+0x28d>
   140004437:	b8 30 00 00 00       	mov    eax,0x30
   14000443c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004440:	89 c1                	mov    ecx,eax
   140004442:	e8 89 ed ff ff       	call   1400031d0 <__pformat_putc>
   140004447:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000444b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000444f:	74 62                	je     1400044b3 <__pformat_emit_float+0x304>
   140004451:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004455:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004458:	25 00 10 00 00       	and    eax,0x1000
   14000445d:	85 c0                	test   eax,eax
   14000445f:	74 52                	je     1400044b3 <__pformat_emit_float+0x304>
   140004461:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004465:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004469:	66 85 c0             	test   ax,ax
   14000446c:	74 45                	je     1400044b3 <__pformat_emit_float+0x304>
   14000446e:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   140004471:	48 63 c1             	movsxd rax,ecx
   140004474:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   14000447b:	48 c1 e8 20          	shr    rax,0x20
   14000447f:	48 89 c2             	mov    rdx,rax
   140004482:	89 c8                	mov    eax,ecx
   140004484:	c1 f8 1f             	sar    eax,0x1f
   140004487:	29 c2                	sub    edx,eax
   140004489:	89 d0                	mov    eax,edx
   14000448b:	01 c0                	add    eax,eax
   14000448d:	01 d0                	add    eax,edx
   14000448f:	29 c1                	sub    ecx,eax
   140004491:	89 ca                	mov    edx,ecx
   140004493:	85 d2                	test   edx,edx
   140004495:	75 1c                	jne    1400044b3 <__pformat_emit_float+0x304>
   140004497:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000449b:	48 83 c0 20          	add    rax,0x20
   14000449f:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044a3:	49 89 d0             	mov    r8,rdx
   1400044a6:	ba 01 00 00 00       	mov    edx,0x1
   1400044ab:	48 89 c1             	mov    rcx,rax
   1400044ae:	e8 26 ef ff ff       	call   1400033d9 <__pformat_wputchars>
   1400044b3:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044b7:	0f 8f 5b ff ff ff    	jg     140004418 <__pformat_emit_float+0x269>
   1400044bd:	eb 11                	jmp    1400044d0 <__pformat_emit_float+0x321>
   1400044bf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044c3:	48 89 c2             	mov    rdx,rax
   1400044c6:	b9 30 00 00 00       	mov    ecx,0x30
   1400044cb:	e8 00 ed ff ff       	call   1400031d0 <__pformat_putc>
   1400044d0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044d4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400044d7:	85 c0                	test   eax,eax
   1400044d9:	7f 10                	jg     1400044eb <__pformat_emit_float+0x33c>
   1400044db:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044df:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400044e2:	25 00 08 00 00       	and    eax,0x800
   1400044e7:	85 c0                	test   eax,eax
   1400044e9:	74 0c                	je     1400044f7 <__pformat_emit_float+0x348>
   1400044eb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044ef:	48 89 c1             	mov    rcx,rax
   1400044f2:	e8 1b fa ff ff       	call   140003f12 <__pformat_emit_radix_point>
   1400044f7:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044fb:	79 5f                	jns    14000455c <__pformat_emit_float+0x3ad>
   1400044fd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004501:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004504:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004507:	01 c2                	add    edx,eax
   140004509:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000450d:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004510:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004514:	48 89 c2             	mov    rdx,rax
   140004517:	b9 30 00 00 00       	mov    ecx,0x30
   14000451c:	e8 af ec ff ff       	call   1400031d0 <__pformat_putc>
   140004521:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   140004525:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004529:	78 e5                	js     140004510 <__pformat_emit_float+0x361>
   14000452b:	eb 2f                	jmp    14000455c <__pformat_emit_float+0x3ad>
   14000452d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004531:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004534:	84 c0                	test   al,al
   140004536:	74 14                	je     14000454c <__pformat_emit_float+0x39d>
   140004538:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000453c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004540:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004544:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004547:	0f be c0             	movsx  eax,al
   14000454a:	eb 05                	jmp    140004551 <__pformat_emit_float+0x3a2>
   14000454c:	b8 30 00 00 00       	mov    eax,0x30
   140004551:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004555:	89 c1                	mov    ecx,eax
   140004557:	e8 74 ec ff ff       	call   1400031d0 <__pformat_putc>
   14000455c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004560:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004563:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004566:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000456a:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   14000456d:	85 c0                	test   eax,eax
   14000456f:	7f bc                	jg     14000452d <__pformat_emit_float+0x37e>
   140004571:	90                   	nop
   140004572:	90                   	nop
   140004573:	48 83 c4 30          	add    rsp,0x30
   140004577:	5d                   	pop    rbp
   140004578:	c3                   	ret

0000000140004579 <__pformat_emit_efloat>:
   140004579:	55                   	push   rbp
   14000457a:	48 89 e5             	mov    rbp,rsp
   14000457d:	48 83 ec 50          	sub    rsp,0x50
   140004581:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004584:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004588:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   14000458c:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004590:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140004597:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000459b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000459f:	79 09                	jns    1400045aa <__pformat_emit_efloat+0x31>
   1400045a1:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400045a8:	eb 05                	jmp    1400045af <__pformat_emit_efloat+0x36>
   1400045aa:	b8 00 00 00 00       	mov    eax,0x0
   1400045af:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400045b3:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400045b6:	48 98                	cdqe
   1400045b8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400045bc:	eb 04                	jmp    1400045c2 <__pformat_emit_efloat+0x49>
   1400045be:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400045c2:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400045c5:	48 63 d0             	movsxd rdx,eax
   1400045c8:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   1400045cf:	48 c1 ea 20          	shr    rdx,0x20
   1400045d3:	89 d1                	mov    ecx,edx
   1400045d5:	c1 f9 02             	sar    ecx,0x2
   1400045d8:	99                   	cdq
   1400045d9:	89 c8                	mov    eax,ecx
   1400045db:	29 d0                	sub    eax,edx
   1400045dd:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   1400045e0:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400045e4:	75 d8                	jne    1400045be <__pformat_emit_efloat+0x45>
   1400045e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045ea:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   1400045ed:	83 f8 ff             	cmp    eax,0xffffffff
   1400045f0:	75 0b                	jne    1400045fd <__pformat_emit_efloat+0x84>
   1400045f2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045f6:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   1400045fd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004601:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004604:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004607:	7d 0a                	jge    140004613 <__pformat_emit_efloat+0x9a>
   140004609:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000460d:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004610:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004613:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004617:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000461a:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   14000461e:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004621:	7d 15                	jge    140004638 <__pformat_emit_efloat+0xbf>
   140004623:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004627:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000462a:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   14000462d:	89 c2                	mov    edx,eax
   14000462f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004633:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004636:	eb 0b                	jmp    140004643 <__pformat_emit_efloat+0xca>
   140004638:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000463c:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004643:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004647:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000464b:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000464e:	49 89 c9             	mov    r9,rcx
   140004651:	41 b8 01 00 00 00    	mov    r8d,0x1
   140004657:	89 c1                	mov    ecx,eax
   140004659:	e8 51 fb ff ff       	call   1400041af <__pformat_emit_float>
   14000465e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004662:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   140004665:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004669:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000466c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004670:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004673:	0d c0 01 00 00       	or     eax,0x1c0
   140004678:	89 c2                	mov    edx,eax
   14000467a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000467e:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004681:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004685:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004688:	83 e0 20             	and    eax,0x20
   14000468b:	83 c8 45             	or     eax,0x45
   14000468e:	89 c1                	mov    ecx,eax
   140004690:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004694:	48 89 c2             	mov    rdx,rax
   140004697:	e8 34 eb ff ff       	call   1400031d0 <__pformat_putc>
   14000469c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046a0:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400046a3:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400046a6:	83 ea 01             	sub    edx,0x1
   1400046a9:	01 c2                	add    edx,eax
   1400046ab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046af:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400046b2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400046b6:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400046ba:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400046be:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   1400046c2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400046c6:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400046ca:	48 89 c1             	mov    rcx,rax
   1400046cd:	e8 69 ef ff ff       	call   14000363b <__pformat_int>
   1400046d2:	90                   	nop
   1400046d3:	48 83 c4 50          	add    rsp,0x50
   1400046d7:	5d                   	pop    rbp
   1400046d8:	c3                   	ret

00000001400046d9 <__pformat_float>:
   1400046d9:	55                   	push   rbp
   1400046da:	53                   	push   rbx
   1400046db:	48 83 ec 58          	sub    rsp,0x58
   1400046df:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400046e4:	48 89 cb             	mov    rbx,rcx
   1400046e7:	db 2b                	fld    TBYTE PTR [rbx]
   1400046e9:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400046ec:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400046f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046f4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400046f7:	85 c0                	test   eax,eax
   1400046f9:	79 0b                	jns    140004706 <__pformat_float+0x2d>
   1400046fb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046ff:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004706:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000470a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000470d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004710:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004713:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   140004717:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000471b:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000471f:	4d 89 c1             	mov    r9,r8
   140004722:	49 89 c8             	mov    r8,rcx
   140004725:	48 89 c1             	mov    rcx,rax
   140004728:	e8 93 f7 ff ff       	call   140003ec0 <__pformat_fcvt>
   14000472d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004731:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004734:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   140004739:	75 17                	jne    140004752 <__pformat_float+0x79>
   14000473b:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000473e:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004742:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004746:	49 89 c8             	mov    r8,rcx
   140004749:	89 c1                	mov    ecx,eax
   14000474b:	e8 74 f9 ff ff       	call   1400040c4 <__pformat_emit_inf_or_nan>
   140004750:	eb 43                	jmp    140004795 <__pformat_float+0xbc>
   140004752:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004755:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004758:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000475c:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004760:	4d 89 c1             	mov    r9,r8
   140004763:	41 89 c8             	mov    r8d,ecx
   140004766:	89 c1                	mov    ecx,eax
   140004768:	e8 42 fa ff ff       	call   1400041af <__pformat_emit_float>
   14000476d:	eb 11                	jmp    140004780 <__pformat_float+0xa7>
   14000476f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004773:	48 89 c2             	mov    rdx,rax
   140004776:	b9 20 00 00 00       	mov    ecx,0x20
   14000477b:	e8 50 ea ff ff       	call   1400031d0 <__pformat_putc>
   140004780:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004784:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004787:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000478a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000478e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004791:	85 c0                	test   eax,eax
   140004793:	7f da                	jg     14000476f <__pformat_float+0x96>
   140004795:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004799:	48 89 c1             	mov    rcx,rax
   14000479c:	e8 4e 17 00 00       	call   140005eef <__freedtoa>
   1400047a1:	90                   	nop
   1400047a2:	48 83 c4 58          	add    rsp,0x58
   1400047a6:	5b                   	pop    rbx
   1400047a7:	5d                   	pop    rbp
   1400047a8:	c3                   	ret

00000001400047a9 <__pformat_efloat>:
   1400047a9:	55                   	push   rbp
   1400047aa:	53                   	push   rbx
   1400047ab:	48 83 ec 58          	sub    rsp,0x58
   1400047af:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400047b4:	48 89 cb             	mov    rbx,rcx
   1400047b7:	db 2b                	fld    TBYTE PTR [rbx]
   1400047b9:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400047bc:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400047c0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047c4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400047c7:	85 c0                	test   eax,eax
   1400047c9:	79 0b                	jns    1400047d6 <__pformat_efloat+0x2d>
   1400047cb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047cf:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400047d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047da:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400047dd:	8d 50 01             	lea    edx,[rax+0x1]
   1400047e0:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400047e3:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400047e6:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400047ea:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400047ee:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400047f2:	4d 89 c1             	mov    r9,r8
   1400047f5:	49 89 c8             	mov    r8,rcx
   1400047f8:	48 89 c1             	mov    rcx,rax
   1400047fb:	e8 6e f6 ff ff       	call   140003e6e <__pformat_ecvt>
   140004800:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004804:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004807:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000480c:	75 17                	jne    140004825 <__pformat_efloat+0x7c>
   14000480e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004811:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004815:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004819:	49 89 c8             	mov    r8,rcx
   14000481c:	89 c1                	mov    ecx,eax
   14000481e:	e8 a1 f8 ff ff       	call   1400040c4 <__pformat_emit_inf_or_nan>
   140004823:	eb 1b                	jmp    140004840 <__pformat_efloat+0x97>
   140004825:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004828:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000482b:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000482f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004833:	4d 89 c1             	mov    r9,r8
   140004836:	41 89 c8             	mov    r8d,ecx
   140004839:	89 c1                	mov    ecx,eax
   14000483b:	e8 39 fd ff ff       	call   140004579 <__pformat_emit_efloat>
   140004840:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004844:	48 89 c1             	mov    rcx,rax
   140004847:	e8 a3 16 00 00       	call   140005eef <__freedtoa>
   14000484c:	90                   	nop
   14000484d:	48 83 c4 58          	add    rsp,0x58
   140004851:	5b                   	pop    rbx
   140004852:	5d                   	pop    rbp
   140004853:	c3                   	ret

0000000140004854 <__pformat_gfloat>:
   140004854:	55                   	push   rbp
   140004855:	53                   	push   rbx
   140004856:	48 83 ec 58          	sub    rsp,0x58
   14000485a:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000485f:	48 89 cb             	mov    rbx,rcx
   140004862:	db 2b                	fld    TBYTE PTR [rbx]
   140004864:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140004867:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000486b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000486f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004872:	85 c0                	test   eax,eax
   140004874:	79 0d                	jns    140004883 <__pformat_gfloat+0x2f>
   140004876:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000487a:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004881:	eb 16                	jmp    140004899 <__pformat_gfloat+0x45>
   140004883:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004887:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000488a:	85 c0                	test   eax,eax
   14000488c:	75 0b                	jne    140004899 <__pformat_gfloat+0x45>
   14000488e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004892:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   140004899:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000489d:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400048a0:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400048a3:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400048a6:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400048aa:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400048ae:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400048b2:	4d 89 c1             	mov    r9,r8
   1400048b5:	49 89 c8             	mov    r8,rcx
   1400048b8:	48 89 c1             	mov    rcx,rax
   1400048bb:	e8 ae f5 ff ff       	call   140003e6e <__pformat_ecvt>
   1400048c0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400048c4:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048c7:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400048cc:	75 1a                	jne    1400048e8 <__pformat_gfloat+0x94>
   1400048ce:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400048d1:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400048d5:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048d9:	49 89 c8             	mov    r8,rcx
   1400048dc:	89 c1                	mov    ecx,eax
   1400048de:	e8 e1 f7 ff ff       	call   1400040c4 <__pformat_emit_inf_or_nan>
   1400048e3:	e9 14 01 00 00       	jmp    1400049fc <__pformat_gfloat+0x1a8>
   1400048e8:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048eb:	83 f8 fd             	cmp    eax,0xfffffffd
   1400048ee:	0f 8c b2 00 00 00    	jl     1400049a6 <__pformat_gfloat+0x152>
   1400048f4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048f8:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400048fb:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048fe:	39 c2                	cmp    edx,eax
   140004900:	0f 8c a0 00 00 00    	jl     1400049a6 <__pformat_gfloat+0x152>
   140004906:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000490a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000490d:	25 00 08 00 00       	and    eax,0x800
   140004912:	85 c0                	test   eax,eax
   140004914:	74 15                	je     14000492b <__pformat_gfloat+0xd7>
   140004916:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000491a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000491d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004920:	29 c2                	sub    edx,eax
   140004922:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004926:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004929:	eb 20                	jmp    14000494b <__pformat_gfloat+0xf7>
   14000492b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000492f:	48 89 c1             	mov    rcx,rax
   140004932:	e8 59 4c 00 00       	call   140009590 <strlen>
   140004937:	89 c1                	mov    ecx,eax
   140004939:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000493c:	89 c2                	mov    edx,eax
   14000493e:	89 c8                	mov    eax,ecx
   140004940:	29 d0                	sub    eax,edx
   140004942:	89 c2                	mov    edx,eax
   140004944:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004948:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000494b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000494f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004952:	85 c0                	test   eax,eax
   140004954:	79 0b                	jns    140004961 <__pformat_gfloat+0x10d>
   140004956:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000495a:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   140004961:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004964:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004967:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000496b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   14000496f:	4d 89 c1             	mov    r9,r8
   140004972:	41 89 c8             	mov    r8d,ecx
   140004975:	89 c1                	mov    ecx,eax
   140004977:	e8 33 f8 ff ff       	call   1400041af <__pformat_emit_float>
   14000497c:	eb 11                	jmp    14000498f <__pformat_gfloat+0x13b>
   14000497e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004982:	48 89 c2             	mov    rdx,rax
   140004985:	b9 20 00 00 00       	mov    ecx,0x20
   14000498a:	e8 41 e8 ff ff       	call   1400031d0 <__pformat_putc>
   14000498f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004993:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004996:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004999:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000499d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400049a0:	85 c0                	test   eax,eax
   1400049a2:	7f da                	jg     14000497e <__pformat_gfloat+0x12a>
   1400049a4:	eb 56                	jmp    1400049fc <__pformat_gfloat+0x1a8>
   1400049a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049aa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400049ad:	25 00 08 00 00       	and    eax,0x800
   1400049b2:	85 c0                	test   eax,eax
   1400049b4:	74 13                	je     1400049c9 <__pformat_gfloat+0x175>
   1400049b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049ba:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049bd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400049c0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049c4:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049c7:	eb 18                	jmp    1400049e1 <__pformat_gfloat+0x18d>
   1400049c9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400049cd:	48 89 c1             	mov    rcx,rax
   1400049d0:	e8 bb 4b 00 00       	call   140009590 <strlen>
   1400049d5:	83 e8 01             	sub    eax,0x1
   1400049d8:	89 c2                	mov    edx,eax
   1400049da:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049de:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049e1:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400049e4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400049e7:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400049eb:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400049ef:	4d 89 c1             	mov    r9,r8
   1400049f2:	41 89 c8             	mov    r8d,ecx
   1400049f5:	89 c1                	mov    ecx,eax
   1400049f7:	e8 7d fb ff ff       	call   140004579 <__pformat_emit_efloat>
   1400049fc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a00:	48 89 c1             	mov    rcx,rax
   140004a03:	e8 e7 14 00 00       	call   140005eef <__freedtoa>
   140004a08:	90                   	nop
   140004a09:	48 83 c4 58          	add    rsp,0x58
   140004a0d:	5b                   	pop    rbx
   140004a0e:	5d                   	pop    rbp
   140004a0f:	c3                   	ret

0000000140004a10 <__pformat_emit_xfloat>:
   140004a10:	55                   	push   rbp
   140004a11:	53                   	push   rbx
   140004a12:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140004a19:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140004a20:	00 
   140004a21:	48 89 cb             	mov    rbx,rcx
   140004a24:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004a28:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004a2c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004a30:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   140004a36:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a39:	48 85 c0             	test   rax,rax
   140004a3c:	75 09                	jne    140004a47 <__pformat_emit_xfloat+0x37>
   140004a3e:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a42:	66 85 c0             	test   ax,ax
   140004a45:	74 0b                	je     140004a52 <__pformat_emit_xfloat+0x42>
   140004a47:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a4b:	83 e8 03             	sub    eax,0x3
   140004a4e:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004a52:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a56:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a59:	85 c0                	test   eax,eax
   140004a5b:	0f 88 90 00 00 00    	js     140004af1 <__pformat_emit_xfloat+0xe1>
   140004a61:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a65:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a68:	83 f8 0e             	cmp    eax,0xe
   140004a6b:	0f 8f 80 00 00 00    	jg     140004af1 <__pformat_emit_xfloat+0xe1>
   140004a71:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a74:	48 d1 e8             	shr    rax,1
   140004a77:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a7a:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004a7d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a81:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a84:	b9 0e 00 00 00       	mov    ecx,0xe
   140004a89:	29 c1                	sub    ecx,eax
   140004a8b:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004a92:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004a98:	89 c1                	mov    ecx,eax
   140004a9a:	49 d3 e0             	shl    r8,cl
   140004a9d:	4c 89 c0             	mov    rax,r8
   140004aa0:	48 01 d0             	add    rax,rdx
   140004aa3:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004aa6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004aa9:	48 85 c0             	test   rax,rax
   140004aac:	78 0b                	js     140004ab9 <__pformat_emit_xfloat+0xa9>
   140004aae:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ab1:	48 01 c0             	add    rax,rax
   140004ab4:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004ab7:	eb 15                	jmp    140004ace <__pformat_emit_xfloat+0xbe>
   140004ab9:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004abd:	83 c0 04             	add    eax,0x4
   140004ac0:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004ac4:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ac7:	48 c1 e8 03          	shr    rax,0x3
   140004acb:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004ace:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004ad1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ad5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ad8:	b9 0f 00 00 00       	mov    ecx,0xf
   140004add:	29 c1                	sub    ecx,eax
   140004adf:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004ae6:	89 c1                	mov    ecx,eax
   140004ae8:	48 d3 ea             	shr    rdx,cl
   140004aeb:	48 89 d0             	mov    rax,rdx
   140004aee:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004af1:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004af4:	48 85 c0             	test   rax,rax
   140004af7:	75 0f                	jne    140004b08 <__pformat_emit_xfloat+0xf8>
   140004af9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004afd:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b00:	85 c0                	test   eax,eax
   140004b02:	0f 8e f8 00 00 00    	jle    140004c00 <__pformat_emit_xfloat+0x1f0>
   140004b08:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b0c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b0f:	83 f8 0e             	cmp    eax,0xe
   140004b12:	7f 1a                	jg     140004b2e <__pformat_emit_xfloat+0x11e>
   140004b14:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b18:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b1b:	85 c0                	test   eax,eax
   140004b1d:	78 0f                	js     140004b2e <__pformat_emit_xfloat+0x11e>
   140004b1f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b23:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b26:	83 c0 01             	add    eax,0x1
   140004b29:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004b2c:	eb 07                	jmp    140004b35 <__pformat_emit_xfloat+0x125>
   140004b2e:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004b35:	e9 bc 00 00 00       	jmp    140004bf6 <__pformat_emit_xfloat+0x1e6>
   140004b3a:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b3d:	83 e0 0f             	and    eax,0xf
   140004b40:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004b43:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004b47:	75 36                	jne    140004b7f <__pformat_emit_xfloat+0x16f>
   140004b49:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b4d:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b51:	72 1b                	jb     140004b6e <__pformat_emit_xfloat+0x15e>
   140004b53:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b57:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b5a:	25 00 08 00 00       	and    eax,0x800
   140004b5f:	85 c0                	test   eax,eax
   140004b61:	75 0b                	jne    140004b6e <__pformat_emit_xfloat+0x15e>
   140004b63:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b67:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b6a:	85 c0                	test   eax,eax
   140004b6c:	7e 2d                	jle    140004b9b <__pformat_emit_xfloat+0x18b>
   140004b6e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004b72:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004b76:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004b7a:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004b7d:	eb 1c                	jmp    140004b9b <__pformat_emit_xfloat+0x18b>
   140004b7f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b83:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b86:	85 c0                	test   eax,eax
   140004b88:	7e 11                	jle    140004b9b <__pformat_emit_xfloat+0x18b>
   140004b8a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b8e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b91:	8d 50 ff             	lea    edx,[rax-0x1]
   140004b94:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b98:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004b9b:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004b9f:	75 15                	jne    140004bb6 <__pformat_emit_xfloat+0x1a6>
   140004ba1:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004ba5:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004ba9:	72 0b                	jb     140004bb6 <__pformat_emit_xfloat+0x1a6>
   140004bab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004baf:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bb2:	85 c0                	test   eax,eax
   140004bb4:	78 32                	js     140004be8 <__pformat_emit_xfloat+0x1d8>
   140004bb6:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004bba:	76 16                	jbe    140004bd2 <__pformat_emit_xfloat+0x1c2>
   140004bbc:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004bbf:	8d 50 37             	lea    edx,[rax+0x37]
   140004bc2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bc6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004bc9:	83 e0 20             	and    eax,0x20
   140004bcc:	09 d0                	or     eax,edx
   140004bce:	89 c1                	mov    ecx,eax
   140004bd0:	eb 08                	jmp    140004bda <__pformat_emit_xfloat+0x1ca>
   140004bd2:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004bd5:	83 c0 30             	add    eax,0x30
   140004bd8:	89 c1                	mov    ecx,eax
   140004bda:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004bde:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004be2:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004be6:	88 08                	mov    BYTE PTR [rax],cl
   140004be8:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004beb:	48 c1 e8 04          	shr    rax,0x4
   140004bef:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004bf2:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004bf6:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004bfa:	0f 8f 3a ff ff ff    	jg     140004b3a <__pformat_emit_xfloat+0x12a>
   140004c00:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c04:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004c08:	75 39                	jne    140004c43 <__pformat_emit_xfloat+0x233>
   140004c0a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c0e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c11:	85 c0                	test   eax,eax
   140004c13:	7f 10                	jg     140004c25 <__pformat_emit_xfloat+0x215>
   140004c15:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c19:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c1c:	25 00 08 00 00       	and    eax,0x800
   140004c21:	85 c0                	test   eax,eax
   140004c23:	74 0f                	je     140004c34 <__pformat_emit_xfloat+0x224>
   140004c25:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c29:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c2d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c31:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004c34:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c38:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c3c:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c40:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004c43:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c47:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c4a:	85 c0                	test   eax,eax
   140004c4c:	0f 8e e3 00 00 00    	jle    140004d35 <__pformat_emit_xfloat+0x325>
   140004c52:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c56:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004c5a:	48 29 c2             	sub    rdx,rax
   140004c5d:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004c60:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004c64:	98                   	cwde
   140004c65:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004c68:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c6c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c6f:	85 c0                	test   eax,eax
   140004c71:	7e 0a                	jle    140004c7d <__pformat_emit_xfloat+0x26d>
   140004c73:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c77:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c7a:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c7d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c81:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c84:	25 c0 01 00 00       	and    eax,0x1c0
   140004c89:	85 c0                	test   eax,eax
   140004c8b:	74 07                	je     140004c94 <__pformat_emit_xfloat+0x284>
   140004c8d:	b8 06 00 00 00       	mov    eax,0x6
   140004c92:	eb 05                	jmp    140004c99 <__pformat_emit_xfloat+0x289>
   140004c94:	b8 05 00 00 00       	mov    eax,0x5
   140004c99:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c9c:	eb 0f                	jmp    140004cad <__pformat_emit_xfloat+0x29d>
   140004c9e:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004ca2:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004ca6:	83 c0 01             	add    eax,0x1
   140004ca9:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004cad:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004cb0:	48 63 d0             	movsxd rdx,eax
   140004cb3:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004cba:	48 c1 ea 20          	shr    rdx,0x20
   140004cbe:	89 d1                	mov    ecx,edx
   140004cc0:	c1 f9 02             	sar    ecx,0x2
   140004cc3:	99                   	cdq
   140004cc4:	89 c8                	mov    eax,ecx
   140004cc6:	29 d0                	sub    eax,edx
   140004cc8:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004ccb:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004ccf:	75 cd                	jne    140004c9e <__pformat_emit_xfloat+0x28e>
   140004cd1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cd5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004cd8:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004cdb:	7d 4d                	jge    140004d2a <__pformat_emit_xfloat+0x31a>
   140004cdd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ce1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004ce4:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004ce7:	89 c2                	mov    edx,eax
   140004ce9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ced:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004cf0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cf4:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cf7:	25 00 06 00 00       	and    eax,0x600
   140004cfc:	85 c0                	test   eax,eax
   140004cfe:	75 35                	jne    140004d35 <__pformat_emit_xfloat+0x325>
   140004d00:	eb 11                	jmp    140004d13 <__pformat_emit_xfloat+0x303>
   140004d02:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d06:	48 89 c2             	mov    rdx,rax
   140004d09:	b9 20 00 00 00       	mov    ecx,0x20
   140004d0e:	e8 bd e4 ff ff       	call   1400031d0 <__pformat_putc>
   140004d13:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d17:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d1a:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004d1d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d21:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004d24:	85 c0                	test   eax,eax
   140004d26:	7f da                	jg     140004d02 <__pformat_emit_xfloat+0x2f2>
   140004d28:	eb 0b                	jmp    140004d35 <__pformat_emit_xfloat+0x325>
   140004d2a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d2e:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004d35:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d39:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d3c:	25 80 00 00 00       	and    eax,0x80
   140004d41:	85 c0                	test   eax,eax
   140004d43:	74 13                	je     140004d58 <__pformat_emit_xfloat+0x348>
   140004d45:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d49:	48 89 c2             	mov    rdx,rax
   140004d4c:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004d51:	e8 7a e4 ff ff       	call   1400031d0 <__pformat_putc>
   140004d56:	eb 42                	jmp    140004d9a <__pformat_emit_xfloat+0x38a>
   140004d58:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d5c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d5f:	25 00 01 00 00       	and    eax,0x100
   140004d64:	85 c0                	test   eax,eax
   140004d66:	74 13                	je     140004d7b <__pformat_emit_xfloat+0x36b>
   140004d68:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d6c:	48 89 c2             	mov    rdx,rax
   140004d6f:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004d74:	e8 57 e4 ff ff       	call   1400031d0 <__pformat_putc>
   140004d79:	eb 1f                	jmp    140004d9a <__pformat_emit_xfloat+0x38a>
   140004d7b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d7f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d82:	83 e0 40             	and    eax,0x40
   140004d85:	85 c0                	test   eax,eax
   140004d87:	74 11                	je     140004d9a <__pformat_emit_xfloat+0x38a>
   140004d89:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d8d:	48 89 c2             	mov    rdx,rax
   140004d90:	b9 20 00 00 00       	mov    ecx,0x20
   140004d95:	e8 36 e4 ff ff       	call   1400031d0 <__pformat_putc>
   140004d9a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d9e:	48 89 c2             	mov    rdx,rax
   140004da1:	b9 30 00 00 00       	mov    ecx,0x30
   140004da6:	e8 25 e4 ff ff       	call   1400031d0 <__pformat_putc>
   140004dab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004daf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004db2:	83 e0 20             	and    eax,0x20
   140004db5:	83 c8 58             	or     eax,0x58
   140004db8:	89 c1                	mov    ecx,eax
   140004dba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dbe:	48 89 c2             	mov    rdx,rax
   140004dc1:	e8 0a e4 ff ff       	call   1400031d0 <__pformat_putc>
   140004dc6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dca:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004dcd:	85 c0                	test   eax,eax
   140004dcf:	7e 54                	jle    140004e25 <__pformat_emit_xfloat+0x415>
   140004dd1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dd5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dd8:	25 00 02 00 00       	and    eax,0x200
   140004ddd:	85 c0                	test   eax,eax
   140004ddf:	74 44                	je     140004e25 <__pformat_emit_xfloat+0x415>
   140004de1:	eb 11                	jmp    140004df4 <__pformat_emit_xfloat+0x3e4>
   140004de3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004de7:	48 89 c2             	mov    rdx,rax
   140004dea:	b9 30 00 00 00       	mov    ecx,0x30
   140004def:	e8 dc e3 ff ff       	call   1400031d0 <__pformat_putc>
   140004df4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004df8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004dfb:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004dfe:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e02:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004e05:	85 c0                	test   eax,eax
   140004e07:	7f da                	jg     140004de3 <__pformat_emit_xfloat+0x3d3>
   140004e09:	eb 1a                	jmp    140004e25 <__pformat_emit_xfloat+0x415>
   140004e0b:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004e10:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004e14:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004e17:	0f be c0             	movsx  eax,al
   140004e1a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e1e:	89 c1                	mov    ecx,eax
   140004e20:	e8 32 f2 ff ff       	call   140004057 <__pformat_emit_numeric_value>
   140004e25:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004e29:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004e2d:	72 dc                	jb     140004e0b <__pformat_emit_xfloat+0x3fb>
   140004e2f:	eb 11                	jmp    140004e42 <__pformat_emit_xfloat+0x432>
   140004e31:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e35:	48 89 c2             	mov    rdx,rax
   140004e38:	b9 30 00 00 00       	mov    ecx,0x30
   140004e3d:	e8 8e e3 ff ff       	call   1400031d0 <__pformat_putc>
   140004e42:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e46:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004e49:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e4c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e50:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004e53:	85 c0                	test   eax,eax
   140004e55:	7f da                	jg     140004e31 <__pformat_emit_xfloat+0x421>
   140004e57:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e5b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e5e:	83 e0 20             	and    eax,0x20
   140004e61:	83 c8 50             	or     eax,0x50
   140004e64:	89 c1                	mov    ecx,eax
   140004e66:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e6a:	48 89 c2             	mov    rdx,rax
   140004e6d:	e8 5e e3 ff ff       	call   1400031d0 <__pformat_putc>
   140004e72:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e76:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004e79:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004e7d:	01 c2                	add    edx,eax
   140004e7f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e83:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004e86:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e8a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e8d:	0d c0 01 00 00       	or     eax,0x1c0
   140004e92:	89 c2                	mov    edx,eax
   140004e94:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e98:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004e9b:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e9f:	66 85 c0             	test   ax,ax
   140004ea2:	79 09                	jns    140004ead <__pformat_emit_xfloat+0x49d>
   140004ea4:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004eab:	eb 05                	jmp    140004eb2 <__pformat_emit_xfloat+0x4a2>
   140004ead:	b8 00 00 00 00       	mov    eax,0x0
   140004eb2:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004eb6:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004eba:	48 0f bf c0          	movsx  rax,ax
   140004ebe:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004ec2:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004ec6:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004eca:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004ece:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004ed2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004ed6:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004eda:	48 89 c1             	mov    rcx,rax
   140004edd:	e8 59 e7 ff ff       	call   14000363b <__pformat_int>
   140004ee2:	90                   	nop
   140004ee3:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004eea:	5b                   	pop    rbx
   140004eeb:	5d                   	pop    rbp
   140004eec:	c3                   	ret

0000000140004eed <__pformat_xldouble>:
   140004eed:	55                   	push   rbp
   140004eee:	53                   	push   rbx
   140004eef:	48 83 ec 78          	sub    rsp,0x78
   140004ef3:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004ef8:	48 89 cb             	mov    rbx,rcx
   140004efb:	db 2b                	fld    TBYTE PTR [rbx]
   140004efd:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004f00:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004f04:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004f0b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004f0f:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f12:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f15:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004f19:	48 89 c1             	mov    rcx,rax
   140004f1c:	e8 e5 ed ff ff       	call   140003d06 <init_fpreg_ldouble>
   140004f21:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f24:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f27:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f2b:	48 89 c1             	mov    rcx,rax
   140004f2e:	e8 ed 3d 00 00       	call   140008d20 <__isnanl>
   140004f33:	85 c0                	test   eax,eax
   140004f35:	74 1d                	je     140004f54 <__pformat_xldouble+0x67>
   140004f37:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f3a:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f3e:	48 8d 15 01 64 00 00 	lea    rdx,[rip+0x6401]        # 14000b346 <.rdata+0x16>
   140004f45:	49 89 c8             	mov    r8,rcx
   140004f48:	89 c1                	mov    ecx,eax
   140004f4a:	e8 75 f1 ff ff       	call   1400040c4 <__pformat_emit_inf_or_nan>
   140004f4f:	e9 aa 00 00 00       	jmp    140004ffe <__pformat_xldouble+0x111>
   140004f54:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f58:	98                   	cwde
   140004f59:	25 00 80 00 00       	and    eax,0x8000
   140004f5e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004f61:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004f65:	74 12                	je     140004f79 <__pformat_xldouble+0x8c>
   140004f67:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f6b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004f6e:	0c 80                	or     al,0x80
   140004f70:	89 c2                	mov    edx,eax
   140004f72:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f76:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004f79:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f7c:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f7f:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f83:	48 89 c1             	mov    rcx,rax
   140004f86:	e8 a5 3c 00 00       	call   140008c30 <__fpclassifyl>
   140004f8b:	3d 00 05 00 00       	cmp    eax,0x500
   140004f90:	75 1a                	jne    140004fac <__pformat_xldouble+0xbf>
   140004f92:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f95:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f99:	48 8d 15 aa 63 00 00 	lea    rdx,[rip+0x63aa]        # 14000b34a <.rdata+0x1a>
   140004fa0:	49 89 c8             	mov    r8,rcx
   140004fa3:	89 c1                	mov    ecx,eax
   140004fa5:	e8 1a f1 ff ff       	call   1400040c4 <__pformat_emit_inf_or_nan>
   140004faa:	eb 52                	jmp    140004ffe <__pformat_xldouble+0x111>
   140004fac:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fb0:	66 25 ff 7f          	and    ax,0x7fff
   140004fb4:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004fb8:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fbc:	66 85 c0             	test   ax,ax
   140004fbf:	75 11                	jne    140004fd2 <__pformat_xldouble+0xe5>
   140004fc1:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004fc5:	48 85 c0             	test   rax,rax
   140004fc8:	74 14                	je     140004fde <__pformat_xldouble+0xf1>
   140004fca:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140004fd0:	eb 0c                	jmp    140004fde <__pformat_xldouble+0xf1>
   140004fd2:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fd6:	66 2d ff 3f          	sub    ax,0x3fff
   140004fda:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004fde:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004fe2:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140004fe6:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004fea:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   140004fee:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004ff2:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140004ff6:	48 89 c1             	mov    rcx,rax
   140004ff9:	e8 12 fa ff ff       	call   140004a10 <__pformat_emit_xfloat>
   140004ffe:	90                   	nop
   140004fff:	48 83 c4 78          	add    rsp,0x78
   140005003:	5b                   	pop    rbx
   140005004:	5d                   	pop    rbp
   140005005:	c3                   	ret

0000000140005006 <__pformat_xdouble>:
   140005006:	55                   	push   rbp
   140005007:	48 89 e5             	mov    rbp,rsp
   14000500a:	48 83 ec 60          	sub    rsp,0x60
   14000500e:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140005013:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005017:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000501e:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140005021:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140005025:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140005028:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   14000502c:	48 89 c1             	mov    rcx,rax
   14000502f:	e8 d2 ec ff ff       	call   140003d06 <init_fpreg_ldouble>
   140005034:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005038:	66 48 0f 6e c0       	movq   xmm0,rax
   14000503d:	e8 7e 3c 00 00       	call   140008cc0 <__isnan>
   140005042:	85 c0                	test   eax,eax
   140005044:	74 1d                	je     140005063 <__pformat_xdouble+0x5d>
   140005046:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005049:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   14000504d:	48 8d 15 f2 62 00 00 	lea    rdx,[rip+0x62f2]        # 14000b346 <.rdata+0x16>
   140005054:	49 89 c8             	mov    r8,rcx
   140005057:	89 c1                	mov    ecx,eax
   140005059:	e8 66 f0 ff ff       	call   1400040c4 <__pformat_emit_inf_or_nan>
   14000505e:	e9 f9 00 00 00       	jmp    14000515c <__pformat_xdouble+0x156>
   140005063:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005067:	98                   	cwde
   140005068:	25 00 80 00 00       	and    eax,0x8000
   14000506d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005070:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005074:	74 12                	je     140005088 <__pformat_xdouble+0x82>
   140005076:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000507a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000507d:	0c 80                	or     al,0x80
   14000507f:	89 c2                	mov    edx,eax
   140005081:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005085:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005088:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000508c:	66 48 0f 6e c0       	movq   xmm0,rax
   140005091:	e8 1a 3b 00 00       	call   140008bb0 <__fpclassify>
   140005096:	3d 00 05 00 00       	cmp    eax,0x500
   14000509b:	75 1d                	jne    1400050ba <__pformat_xdouble+0xb4>
   14000509d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400050a0:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   1400050a4:	48 8d 15 9f 62 00 00 	lea    rdx,[rip+0x629f]        # 14000b34a <.rdata+0x1a>
   1400050ab:	49 89 c8             	mov    r8,rcx
   1400050ae:	89 c1                	mov    ecx,eax
   1400050b0:	e8 0f f0 ff ff       	call   1400040c4 <__pformat_emit_inf_or_nan>
   1400050b5:	e9 a2 00 00 00       	jmp    14000515c <__pformat_xdouble+0x156>
   1400050ba:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050be:	66 25 ff 7f          	and    ax,0x7fff
   1400050c2:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400050c6:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050ca:	66 85 c0             	test   ax,ax
   1400050cd:	74 3b                	je     14000510a <__pformat_xdouble+0x104>
   1400050cf:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050d3:	66 3d 00 3c          	cmp    ax,0x3c00
   1400050d7:	7f 31                	jg     14000510a <__pformat_xdouble+0x104>
   1400050d9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050dd:	98                   	cwde
   1400050de:	ba 01 3c 00 00       	mov    edx,0x3c01
   1400050e3:	29 c2                	sub    edx,eax
   1400050e5:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   1400050e8:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   1400050ec:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400050ef:	89 c1                	mov    ecx,eax
   1400050f1:	48 d3 ea             	shr    rdx,cl
   1400050f4:	48 89 d0             	mov    rax,rdx
   1400050f7:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400050fb:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050ff:	89 c2                	mov    edx,eax
   140005101:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005104:	01 d0                	add    eax,edx
   140005106:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000510a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000510e:	66 85 c0             	test   ax,ax
   140005111:	75 11                	jne    140005124 <__pformat_xdouble+0x11e>
   140005113:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005117:	48 85 c0             	test   rax,rax
   14000511a:	74 14                	je     140005130 <__pformat_xdouble+0x12a>
   14000511c:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   140005122:	eb 0c                	jmp    140005130 <__pformat_xdouble+0x12a>
   140005124:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005128:	66 2d fc 3f          	sub    ax,0x3ffc
   14000512c:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005130:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005134:	48 c1 e8 03          	shr    rax,0x3
   140005138:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000513c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005140:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005144:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005148:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   14000514c:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140005150:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140005154:	48 89 c1             	mov    rcx,rax
   140005157:	e8 b4 f8 ff ff       	call   140004a10 <__pformat_emit_xfloat>
   14000515c:	90                   	nop
   14000515d:	48 83 c4 60          	add    rsp,0x60
   140005161:	5d                   	pop    rbp
   140005162:	c3                   	ret

0000000140005163 <__mingw_pformat>:
   140005163:	55                   	push   rbp
   140005164:	48 89 e5             	mov    rbp,rsp
   140005167:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   14000516e:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005171:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005175:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005179:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   14000517d:	e8 86 43 00 00       	call   140009508 <_errno>
   140005182:	8b 00                	mov    eax,DWORD PTR [rax]
   140005184:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140005187:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000518b:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   14000518f:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   140005196:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140005199:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000519c:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   1400051a3:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400051aa:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   1400051b1:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   1400051b7:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   1400051be:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   1400051c4:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   1400051cb:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400051ce:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   1400051d1:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   1400051d8:	e9 27 0c 00 00       	jmp    140005e04 <__mingw_pformat+0xca1>
   1400051dd:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400051e1:	0f 85 0f 0c 00 00    	jne    140005df6 <__mingw_pformat+0xc93>
   1400051e7:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400051ee:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400051f5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400051f9:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400051fd:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005201:	48 83 c0 0c          	add    rax,0xc
   140005205:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005209:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000520c:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000520f:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005216:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140005219:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000521c:	e9 c4 0b 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005221:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005225:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005229:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000522d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005230:	0f be c0             	movsx  eax,al
   140005233:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005236:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   14000523a:	0f 84 94 09 00 00    	je     140005bd4 <__mingw_pformat+0xa71>
   140005240:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   140005244:	0f 8f 02 0b 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000524a:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   14000524e:	0f 84 eb 03 00 00    	je     14000563f <__mingw_pformat+0x4dc>
   140005254:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   140005258:	0f 8f ee 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000525e:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   140005262:	0f 84 31 09 00 00    	je     140005b99 <__mingw_pformat+0xa36>
   140005268:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   14000526c:	0f 8f da 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005272:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005276:	0f 84 c3 03 00 00    	je     14000563f <__mingw_pformat+0x4dc>
   14000527c:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005280:	0f 8f c6 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005286:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   14000528a:	0f 84 31 09 00 00    	je     140005bc1 <__mingw_pformat+0xa5e>
   140005290:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   140005294:	0f 8f b2 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000529a:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   14000529e:	0f 84 31 03 00 00    	je     1400055d5 <__mingw_pformat+0x472>
   1400052a4:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   1400052a8:	0f 8f 9e 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400052ae:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   1400052b2:	0f 84 28 05 00 00    	je     1400057e0 <__mingw_pformat+0x67d>
   1400052b8:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   1400052bc:	0f 8f 8a 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400052c2:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   1400052c6:	0f 84 73 03 00 00    	je     14000563f <__mingw_pformat+0x4dc>
   1400052cc:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   1400052d0:	0f 8f 76 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400052d6:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   1400052da:	0f 84 4d 07 00 00    	je     140005a2d <__mingw_pformat+0x8ca>
   1400052e0:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   1400052e4:	0f 8f 62 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400052ea:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   1400052ee:	0f 84 2d 03 00 00    	je     140005621 <__mingw_pformat+0x4be>
   1400052f4:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   1400052f8:	0f 8f 4e 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400052fe:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   140005302:	0f 84 65 08 00 00    	je     140005b6d <__mingw_pformat+0xa0a>
   140005308:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   14000530c:	0f 8f 3a 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005312:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005316:	0f 84 db 07 00 00    	je     140005af7 <__mingw_pformat+0x994>
   14000531c:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005320:	0f 8f 26 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005326:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   14000532a:	0f 84 ee 03 00 00    	je     14000571e <__mingw_pformat+0x5bb>
   140005330:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   140005334:	0f 8f 12 0a 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000533a:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   14000533e:	0f 84 87 07 00 00    	je     140005acb <__mingw_pformat+0x968>
   140005344:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   140005348:	0f 8f fe 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000534e:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   140005352:	0f 84 f3 05 00 00    	je     14000594b <__mingw_pformat+0x7e8>
   140005358:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   14000535c:	0f 8f ea 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005362:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005366:	0f 84 61 05 00 00    	je     1400058cd <__mingw_pformat+0x76a>
   14000536c:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005370:	0f 8f d6 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005376:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   14000537a:	0f 84 cf 04 00 00    	je     14000584f <__mingw_pformat+0x6ec>
   140005380:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   140005384:	0f 8f c2 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000538a:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   14000538e:	0f 84 8a 03 00 00    	je     14000571e <__mingw_pformat+0x5bb>
   140005394:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   140005398:	0f 8f ae 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000539e:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   1400053a2:	0f 84 b5 01 00 00    	je     14000555d <__mingw_pformat+0x3fa>
   1400053a8:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   1400053ac:	0f 8f 9a 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400053b2:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   1400053b6:	0f 84 83 02 00 00    	je     14000563f <__mingw_pformat+0x4dc>
   1400053bc:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   1400053c0:	0f 8f 86 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400053c6:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   1400053ca:	0f 84 f9 05 00 00    	je     1400059c9 <__mingw_pformat+0x866>
   1400053d0:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   1400053d4:	0f 8f 72 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400053da:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   1400053de:	0f 84 5b 02 00 00    	je     14000563f <__mingw_pformat+0x4dc>
   1400053e4:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   1400053e8:	0f 8f 5e 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400053ee:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   1400053f2:	0f 84 d6 01 00 00    	je     1400055ce <__mingw_pformat+0x46b>
   1400053f8:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   1400053fc:	0f 8f 4a 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005402:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005406:	0f 84 a0 07 00 00    	je     140005bac <__mingw_pformat+0xa49>
   14000540c:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005410:	0f 8f 36 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005416:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   14000541a:	0f 84 ea 06 00 00    	je     140005b0a <__mingw_pformat+0x9a7>
   140005420:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   140005424:	0f 8f 22 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000542a:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   14000542e:	0f 84 20 05 00 00    	je     140005954 <__mingw_pformat+0x7f1>
   140005434:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   140005438:	0f 8f 0e 09 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000543e:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   140005442:	0f 84 8e 04 00 00    	je     1400058d6 <__mingw_pformat+0x773>
   140005448:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   14000544c:	0f 8f fa 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005452:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005456:	0f 84 fc 03 00 00    	je     140005858 <__mingw_pformat+0x6f5>
   14000545c:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005460:	0f 8f e6 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005466:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   14000546a:	0f 84 e6 00 00 00    	je     140005556 <__mingw_pformat+0x3f3>
   140005470:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   140005474:	0f 8f d2 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000547a:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   14000547e:	0f 84 bb 01 00 00    	je     14000563f <__mingw_pformat+0x4dc>
   140005484:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   140005488:	0f 8f be 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000548e:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   140005492:	0f 84 3a 05 00 00    	je     1400059d2 <__mingw_pformat+0x86f>
   140005498:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   14000549c:	0f 8f aa 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400054a2:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   1400054a6:	0f 84 8c 08 00 00    	je     140005d38 <__mingw_pformat+0xbd5>
   1400054ac:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   1400054b0:	0f 8f 96 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400054b6:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   1400054ba:	0f 84 27 07 00 00    	je     140005be7 <__mingw_pformat+0xa84>
   1400054c0:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   1400054c4:	0f 8f 82 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400054ca:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   1400054ce:	0f 84 db 07 00 00    	je     140005caf <__mingw_pformat+0xb4c>
   1400054d4:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   1400054d8:	0f 8f 6e 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400054de:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   1400054e2:	0f 84 af 07 00 00    	je     140005c97 <__mingw_pformat+0xb34>
   1400054e8:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   1400054ec:	0f 8f 5a 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   1400054f2:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   1400054f6:	0f 84 1c 07 00 00    	je     140005c18 <__mingw_pformat+0xab5>
   1400054fc:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005500:	0f 8f 46 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   140005506:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   14000550a:	0f 84 b7 07 00 00    	je     140005cc7 <__mingw_pformat+0xb64>
   140005510:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   140005514:	0f 8f 32 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000551a:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   14000551e:	74 23                	je     140005543 <__mingw_pformat+0x3e0>
   140005520:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005524:	0f 8f 22 08 00 00    	jg     140005d4c <__mingw_pformat+0xbe9>
   14000552a:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   14000552e:	0f 84 ec 07 00 00    	je     140005d20 <__mingw_pformat+0xbbd>
   140005534:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   140005538:	0f 84 41 07 00 00    	je     140005c7f <__mingw_pformat+0xb1c>
   14000553e:	e9 09 08 00 00       	jmp    140005d4c <__mingw_pformat+0xbe9>
   140005543:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005547:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000554a:	89 c1                	mov    ecx,eax
   14000554c:	e8 7f dc ff ff       	call   1400031d0 <__pformat_putc>
   140005551:	e9 82 fc ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005556:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   14000555d:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005564:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005568:	74 06                	je     140005570 <__mingw_pformat+0x40d>
   14000556a:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000556e:	75 30                	jne    1400055a0 <__mingw_pformat+0x43d>
   140005570:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005574:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005578:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000557c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000557e:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   140005582:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005586:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   14000558a:	49 89 d0             	mov    r8,rdx
   14000558d:	ba 01 00 00 00       	mov    edx,0x1
   140005592:	48 89 c1             	mov    rcx,rax
   140005595:	e8 3f de ff ff       	call   1400033d9 <__pformat_wputchars>
   14000559a:	90                   	nop
   14000559b:	e9 38 fc ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   1400055a0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055a4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055a8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055ac:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055ae:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   1400055b1:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055b5:	48 8d 45 90          	lea    rax,[rbp-0x70]
   1400055b9:	49 89 d0             	mov    r8,rdx
   1400055bc:	ba 01 00 00 00       	mov    edx,0x1
   1400055c1:	48 89 c1             	mov    rcx,rax
   1400055c4:	e8 8b dc ff ff       	call   140003254 <__pformat_putchars>
   1400055c9:	e9 0a fc ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   1400055ce:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400055d5:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400055d9:	74 06                	je     1400055e1 <__mingw_pformat+0x47e>
   1400055db:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055df:	75 20                	jne    140005601 <__mingw_pformat+0x49e>
   1400055e1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055e5:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055e9:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055ed:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400055f0:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055f4:	48 89 c1             	mov    rcx,rax
   1400055f7:	e8 29 df ff ff       	call   140003525 <__pformat_wcputs>
   1400055fc:	e9 d7 fb ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005601:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005605:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005609:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000560d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005610:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005614:	48 89 c1             	mov    rcx,rax
   140005617:	e8 37 dd ff ff       	call   140003353 <__pformat_puts>
   14000561c:	e9 b7 fb ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005621:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140005624:	89 c1                	mov    ecx,eax
   140005626:	e8 5d 3f 00 00       	call   140009588 <strerror>
   14000562b:	48 89 c1             	mov    rcx,rax
   14000562e:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005632:	48 89 c2             	mov    rdx,rax
   140005635:	e8 19 dd ff ff       	call   140003353 <__pformat_puts>
   14000563a:	e9 99 fb ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   14000563f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005642:	80 e4 fe             	and    ah,0xfe
   140005645:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005648:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000564c:	75 15                	jne    140005663 <__mingw_pformat+0x500>
   14000564e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005652:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005656:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000565a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000565d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005661:	eb 54                	jmp    1400056b7 <__mingw_pformat+0x554>
   140005663:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005667:	75 16                	jne    14000567f <__mingw_pformat+0x51c>
   140005669:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000566d:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005671:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005675:	8b 00                	mov    eax,DWORD PTR [rax]
   140005677:	89 c0                	mov    eax,eax
   140005679:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000567d:	eb 38                	jmp    1400056b7 <__mingw_pformat+0x554>
   14000567f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005683:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005687:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000568b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000568d:	89 c0                	mov    eax,eax
   14000568f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005693:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005697:	75 0d                	jne    1400056a6 <__mingw_pformat+0x543>
   140005699:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000569d:	0f b7 c0             	movzx  eax,ax
   1400056a0:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056a4:	eb 11                	jmp    1400056b7 <__mingw_pformat+0x554>
   1400056a6:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400056aa:	75 0b                	jne    1400056b7 <__mingw_pformat+0x554>
   1400056ac:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   1400056b0:	0f b6 c0             	movzx  eax,al
   1400056b3:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056b7:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400056bb:	75 2e                	jne    1400056eb <__mingw_pformat+0x588>
   1400056bd:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400056c1:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400056c5:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400056cc:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400056d3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400056d7:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400056de:	48 89 c1             	mov    rcx,rax
   1400056e1:	e8 55 df ff ff       	call   14000363b <__pformat_int>
   1400056e6:	e9 ed fa ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   1400056eb:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400056ef:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400056f3:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400056fa:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005701:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140005705:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   14000570c:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000570f:	49 89 c8             	mov    r8,rcx
   140005712:	89 c1                	mov    ecx,eax
   140005714:	e8 a5 e2 ff ff       	call   1400039be <__pformat_xint>
   140005719:	e9 ba fa ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   14000571e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005721:	0c 80                	or     al,0x80
   140005723:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005726:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000572a:	75 15                	jne    140005741 <__mingw_pformat+0x5de>
   14000572c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005730:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005734:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005738:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000573b:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000573f:	eb 56                	jmp    140005797 <__mingw_pformat+0x634>
   140005741:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005745:	75 16                	jne    14000575d <__mingw_pformat+0x5fa>
   140005747:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000574b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000574f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005753:	8b 00                	mov    eax,DWORD PTR [rax]
   140005755:	48 98                	cdqe
   140005757:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000575b:	eb 3a                	jmp    140005797 <__mingw_pformat+0x634>
   14000575d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005761:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005765:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005769:	8b 00                	mov    eax,DWORD PTR [rax]
   14000576b:	48 98                	cdqe
   14000576d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005771:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005775:	75 0e                	jne    140005785 <__mingw_pformat+0x622>
   140005777:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000577b:	48 0f bf c0          	movsx  rax,ax
   14000577f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005783:	eb 12                	jmp    140005797 <__mingw_pformat+0x634>
   140005785:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005789:	75 0c                	jne    140005797 <__mingw_pformat+0x634>
   14000578b:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   14000578f:	48 0f be c0          	movsx  rax,al
   140005793:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005797:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000579b:	48 85 c0             	test   rax,rax
   14000579e:	79 09                	jns    1400057a9 <__mingw_pformat+0x646>
   1400057a0:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400057a7:	eb 05                	jmp    1400057ae <__mingw_pformat+0x64b>
   1400057a9:	b8 00 00 00 00       	mov    eax,0x0
   1400057ae:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   1400057b2:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057b6:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400057ba:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400057c1:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400057c8:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400057cc:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400057d3:	48 89 c1             	mov    rcx,rax
   1400057d6:	e8 60 de ff ff       	call   14000363b <__pformat_int>
   1400057db:	e9 f8 f9 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   1400057e0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400057e4:	75 18                	jne    1400057fe <__mingw_pformat+0x69b>
   1400057e6:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057e9:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   1400057ec:	75 10                	jne    1400057fe <__mingw_pformat+0x69b>
   1400057ee:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057f1:	80 cc 02             	or     ah,0x2
   1400057f4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400057f7:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   1400057fe:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005802:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005806:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000580a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000580d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005811:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   140005818:	00 
   140005819:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000581d:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005821:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005828:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   14000582f:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005833:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000583a:	49 89 d0             	mov    r8,rdx
   14000583d:	48 89 c2             	mov    rdx,rax
   140005840:	b9 78 00 00 00       	mov    ecx,0x78
   140005845:	e8 74 e1 ff ff       	call   1400039be <__pformat_xint>
   14000584a:	e9 89 f9 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   14000584f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005852:	83 c8 20             	or     eax,0x20
   140005855:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005858:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000585b:	83 e0 04             	and    eax,0x4
   14000585e:	85 c0                	test   eax,eax
   140005860:	74 2f                	je     140005891 <__mingw_pformat+0x72e>
   140005862:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005866:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000586a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000586e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005871:	db 28                	fld    TBYTE PTR [rax]
   140005873:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005879:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000587d:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005884:	48 89 c1             	mov    rcx,rax
   140005887:	e8 1d ef ff ff       	call   1400047a9 <__pformat_efloat>
   14000588c:	e9 47 f9 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005891:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005895:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005899:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000589d:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   1400058a1:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   1400058a8:	ff 
   1400058a9:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400058af:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058b5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058b9:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058c0:	48 89 c1             	mov    rcx,rax
   1400058c3:	e8 e1 ee ff ff       	call   1400047a9 <__pformat_efloat>
   1400058c8:	e9 0b f9 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   1400058cd:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058d0:	83 c8 20             	or     eax,0x20
   1400058d3:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400058d6:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058d9:	83 e0 04             	and    eax,0x4
   1400058dc:	85 c0                	test   eax,eax
   1400058de:	74 2f                	je     14000590f <__mingw_pformat+0x7ac>
   1400058e0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058e4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058e8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058ec:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400058ef:	db 28                	fld    TBYTE PTR [rax]
   1400058f1:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058f7:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058fb:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005902:	48 89 c1             	mov    rcx,rax
   140005905:	e8 cf ed ff ff       	call   1400046d9 <__pformat_float>
   14000590a:	e9 c9 f8 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   14000590f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005913:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005917:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000591b:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   14000591f:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   140005926:	ff 
   140005927:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000592d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005933:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005937:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000593e:	48 89 c1             	mov    rcx,rax
   140005941:	e8 93 ed ff ff       	call   1400046d9 <__pformat_float>
   140005946:	e9 8d f8 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   14000594b:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000594e:	83 c8 20             	or     eax,0x20
   140005951:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005954:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005957:	83 e0 04             	and    eax,0x4
   14000595a:	85 c0                	test   eax,eax
   14000595c:	74 2f                	je     14000598d <__mingw_pformat+0x82a>
   14000595e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005962:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005966:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000596a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000596d:	db 28                	fld    TBYTE PTR [rax]
   14000596f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005975:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005979:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005980:	48 89 c1             	mov    rcx,rax
   140005983:	e8 cc ee ff ff       	call   140004854 <__pformat_gfloat>
   140005988:	e9 4b f8 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   14000598d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005991:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005995:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005999:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   14000599d:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   1400059a4:	ff 
   1400059a5:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400059ab:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059b1:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059b5:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059bc:	48 89 c1             	mov    rcx,rax
   1400059bf:	e8 90 ee ff ff       	call   140004854 <__pformat_gfloat>
   1400059c4:	e9 0f f8 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   1400059c9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059cc:	83 c8 20             	or     eax,0x20
   1400059cf:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400059d2:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059d5:	83 e0 04             	and    eax,0x4
   1400059d8:	85 c0                	test   eax,eax
   1400059da:	74 2f                	je     140005a0b <__mingw_pformat+0x8a8>
   1400059dc:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059e0:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059e4:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059e8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059eb:	db 28                	fld    TBYTE PTR [rax]
   1400059ed:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059f3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059f7:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059fe:	48 89 c1             	mov    rcx,rax
   140005a01:	e8 e7 f4 ff ff       	call   140004eed <__pformat_xldouble>
   140005a06:	e9 cd f7 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005a0b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a0f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a13:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a17:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a1a:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a1e:	66 48 0f 6e c0       	movq   xmm0,rax
   140005a23:	e8 de f5 ff ff       	call   140005006 <__pformat_xdouble>
   140005a28:	e9 ab f7 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005a2d:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005a31:	75 1b                	jne    140005a4e <__mingw_pformat+0x8eb>
   140005a33:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a36:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a3a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a3e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a42:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a45:	89 ca                	mov    edx,ecx
   140005a47:	88 10                	mov    BYTE PTR [rax],dl
   140005a49:	e9 8a f7 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005a4e:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005a52:	75 1c                	jne    140005a70 <__mingw_pformat+0x90d>
   140005a54:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a57:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a5b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a5f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a63:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a66:	89 ca                	mov    edx,ecx
   140005a68:	66 89 10             	mov    WORD PTR [rax],dx
   140005a6b:	e9 68 f7 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005a70:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005a74:	75 19                	jne    140005a8f <__mingw_pformat+0x92c>
   140005a76:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a7a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a7e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a82:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a85:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005a88:	89 10                	mov    DWORD PTR [rax],edx
   140005a8a:	e9 49 f7 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005a8f:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005a93:	75 1d                	jne    140005ab2 <__mingw_pformat+0x94f>
   140005a95:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a98:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a9c:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005aa0:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005aa4:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005aa7:	48 63 d1             	movsxd rdx,ecx
   140005aaa:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005aad:	e9 26 f7 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005ab2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005ab6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005aba:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005abe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ac1:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005ac4:	89 10                	mov    DWORD PTR [rax],edx
   140005ac6:	e9 0d f7 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005acb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005acf:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ad2:	3c 68                	cmp    al,0x68
   140005ad4:	75 0e                	jne    140005ae4 <__mingw_pformat+0x981>
   140005ad6:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005adb:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005ae2:	eb 07                	jmp    140005aeb <__mingw_pformat+0x988>
   140005ae4:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005aeb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005af2:	e9 ee 02 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005af7:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005afe:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b05:	e9 db 02 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005b0a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b0e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b11:	3c 36                	cmp    al,0x36
   140005b13:	75 1d                	jne    140005b32 <__mingw_pformat+0x9cf>
   140005b15:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b19:	48 83 c0 01          	add    rax,0x1
   140005b1d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b20:	3c 34                	cmp    al,0x34
   140005b22:	75 0e                	jne    140005b32 <__mingw_pformat+0x9cf>
   140005b24:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b2b:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b30:	eb 2f                	jmp    140005b61 <__mingw_pformat+0x9fe>
   140005b32:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b36:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b39:	3c 33                	cmp    al,0x33
   140005b3b:	75 1d                	jne    140005b5a <__mingw_pformat+0x9f7>
   140005b3d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b41:	48 83 c0 01          	add    rax,0x1
   140005b45:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b48:	3c 32                	cmp    al,0x32
   140005b4a:	75 0e                	jne    140005b5a <__mingw_pformat+0x9f7>
   140005b4c:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b53:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b58:	eb 07                	jmp    140005b61 <__mingw_pformat+0x9fe>
   140005b5a:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b61:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b68:	e9 78 02 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005b6d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b71:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b74:	3c 6c                	cmp    al,0x6c
   140005b76:	75 0e                	jne    140005b86 <__mingw_pformat+0xa23>
   140005b78:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b7d:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b84:	eb 07                	jmp    140005b8d <__mingw_pformat+0xa2a>
   140005b86:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b8d:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b94:	e9 4c 02 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005b99:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005ba0:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ba7:	e9 39 02 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005bac:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005baf:	83 c8 04             	or     eax,0x4
   140005bb2:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005bb5:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bbc:	e9 24 02 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005bc1:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bc8:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bcf:	e9 11 02 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005bd4:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bdb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005be2:	e9 fe 01 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005be7:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005beb:	77 1f                	ja     140005c0c <__mingw_pformat+0xaa9>
   140005bed:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005bf4:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005bf8:	48 83 c0 10          	add    rax,0x10
   140005bfc:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005c00:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005c07:	e9 d9 01 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005c0c:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c13:	e9 cd 01 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005c18:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005c1d:	74 4c                	je     140005c6b <__mingw_pformat+0xb08>
   140005c1f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c23:	74 06                	je     140005c2b <__mingw_pformat+0xac8>
   140005c25:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005c29:	75 40                	jne    140005c6b <__mingw_pformat+0xb08>
   140005c2b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005c2f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005c33:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005c37:	8b 10                	mov    edx,DWORD PTR [rax]
   140005c39:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c3d:	89 10                	mov    DWORD PTR [rax],edx
   140005c3f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c43:	8b 00                	mov    eax,DWORD PTR [rax]
   140005c45:	85 c0                	test   eax,eax
   140005c47:	79 29                	jns    140005c72 <__mingw_pformat+0xb0f>
   140005c49:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c4d:	75 13                	jne    140005c62 <__mingw_pformat+0xaff>
   140005c4f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c52:	80 cc 04             	or     ah,0x4
   140005c55:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c58:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005c5b:	f7 d8                	neg    eax
   140005c5d:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005c60:	eb 10                	jmp    140005c72 <__mingw_pformat+0xb0f>
   140005c62:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005c69:	eb 07                	jmp    140005c72 <__mingw_pformat+0xb0f>
   140005c6b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c72:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005c79:	00 
   140005c7a:	e9 66 01 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005c7f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c83:	0f 85 4f 01 00 00    	jne    140005dd8 <__mingw_pformat+0xc75>
   140005c89:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c8c:	80 cc 08             	or     ah,0x8
   140005c8f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c92:	e9 41 01 00 00       	jmp    140005dd8 <__mingw_pformat+0xc75>
   140005c97:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c9b:	0f 85 3a 01 00 00    	jne    140005ddb <__mingw_pformat+0xc78>
   140005ca1:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005ca4:	80 cc 01             	or     ah,0x1
   140005ca7:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005caa:	e9 2c 01 00 00       	jmp    140005ddb <__mingw_pformat+0xc78>
   140005caf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cb3:	0f 85 25 01 00 00    	jne    140005dde <__mingw_pformat+0xc7b>
   140005cb9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cbc:	80 cc 04             	or     ah,0x4
   140005cbf:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cc2:	e9 17 01 00 00       	jmp    140005dde <__mingw_pformat+0xc7b>
   140005cc7:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ccb:	0f 85 10 01 00 00    	jne    140005de1 <__mingw_pformat+0xc7e>
   140005cd1:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cd4:	80 cc 10             	or     ah,0x10
   140005cd7:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cda:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005ce1:	00 
   140005ce2:	e8 71 38 00 00       	call   140009558 <localeconv>
   140005ce7:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005ceb:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005cef:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005cf3:	49 89 c9             	mov    r9,rcx
   140005cf6:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005cfc:	48 89 c1             	mov    rcx,rax
   140005cff:	e8 9c 32 00 00       	call   140008fa0 <mbrtowc>
   140005d04:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005d07:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005d0b:	7e 08                	jle    140005d15 <__mingw_pformat+0xbb2>
   140005d0d:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005d11:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005d15:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005d18:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005d1b:	e9 c1 00 00 00       	jmp    140005de1 <__mingw_pformat+0xc7e>
   140005d20:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d24:	0f 85 ba 00 00 00    	jne    140005de4 <__mingw_pformat+0xc81>
   140005d2a:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d2d:	83 c8 40             	or     eax,0x40
   140005d30:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d33:	e9 ac 00 00 00       	jmp    140005de4 <__mingw_pformat+0xc81>
   140005d38:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d3c:	75 0e                	jne    140005d4c <__mingw_pformat+0xbe9>
   140005d3e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d41:	80 cc 02             	or     ah,0x2
   140005d44:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d47:	e9 99 00 00 00       	jmp    140005de5 <__mingw_pformat+0xc82>
   140005d4c:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005d50:	77 68                	ja     140005dba <__mingw_pformat+0xc57>
   140005d52:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005d56:	7f 62                	jg     140005dba <__mingw_pformat+0xc57>
   140005d58:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005d5c:	7e 5c                	jle    140005dba <__mingw_pformat+0xc57>
   140005d5e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d62:	75 09                	jne    140005d6d <__mingw_pformat+0xc0a>
   140005d64:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005d6b:	eb 0d                	jmp    140005d7a <__mingw_pformat+0xc17>
   140005d6d:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005d71:	75 07                	jne    140005d7a <__mingw_pformat+0xc17>
   140005d73:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005d7a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005d7f:	74 64                	je     140005de5 <__mingw_pformat+0xc82>
   140005d81:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d85:	8b 00                	mov    eax,DWORD PTR [rax]
   140005d87:	85 c0                	test   eax,eax
   140005d89:	79 0e                	jns    140005d99 <__mingw_pformat+0xc36>
   140005d8b:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d8e:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d91:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d95:	89 10                	mov    DWORD PTR [rax],edx
   140005d97:	eb 4c                	jmp    140005de5 <__mingw_pformat+0xc82>
   140005d99:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d9d:	8b 10                	mov    edx,DWORD PTR [rax]
   140005d9f:	89 d0                	mov    eax,edx
   140005da1:	c1 e0 02             	shl    eax,0x2
   140005da4:	01 d0                	add    eax,edx
   140005da6:	01 c0                	add    eax,eax
   140005da8:	89 c2                	mov    edx,eax
   140005daa:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005dad:	01 d0                	add    eax,edx
   140005daf:	8d 50 d0             	lea    edx,[rax-0x30]
   140005db2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005db6:	89 10                	mov    DWORD PTR [rax],edx
   140005db8:	eb 2b                	jmp    140005de5 <__mingw_pformat+0xc82>
   140005dba:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005dbe:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005dc2:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005dc6:	48 89 c2             	mov    rdx,rax
   140005dc9:	b9 25 00 00 00       	mov    ecx,0x25
   140005dce:	e8 fd d3 ff ff       	call   1400031d0 <__pformat_putc>
   140005dd3:	e9 00 f4 ff ff       	jmp    1400051d8 <__mingw_pformat+0x75>
   140005dd8:	90                   	nop
   140005dd9:	eb 0a                	jmp    140005de5 <__mingw_pformat+0xc82>
   140005ddb:	90                   	nop
   140005ddc:	eb 07                	jmp    140005de5 <__mingw_pformat+0xc82>
   140005dde:	90                   	nop
   140005ddf:	eb 04                	jmp    140005de5 <__mingw_pformat+0xc82>
   140005de1:	90                   	nop
   140005de2:	eb 01                	jmp    140005de5 <__mingw_pformat+0xc82>
   140005de4:	90                   	nop
   140005de5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005de9:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005dec:	84 c0                	test   al,al
   140005dee:	0f 85 2d f4 ff ff    	jne    140005221 <__mingw_pformat+0xbe>
   140005df4:	eb 0e                	jmp    140005e04 <__mingw_pformat+0xca1>
   140005df6:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005dfa:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005dfd:	89 c1                	mov    ecx,eax
   140005dff:	e8 cc d3 ff ff       	call   1400031d0 <__pformat_putc>
   140005e04:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e08:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e0c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005e10:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e13:	0f be c0             	movsx  eax,al
   140005e16:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005e19:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005e1d:	0f 85 ba f3 ff ff    	jne    1400051dd <__mingw_pformat+0x7a>
   140005e23:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005e26:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005e2d:	5d                   	pop    rbp
   140005e2e:	c3                   	ret
   140005e2f:	90                   	nop

0000000140005e30 <__rv_alloc_D2A>:
   140005e30:	55                   	push   rbp
   140005e31:	48 89 e5             	mov    rbp,rsp
   140005e34:	48 83 ec 30          	sub    rsp,0x30
   140005e38:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005e3b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005e42:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005e49:	eb 07                	jmp    140005e52 <__rv_alloc_D2A+0x22>
   140005e4b:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005e4f:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005e52:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005e55:	83 c0 17             	add    eax,0x17
   140005e58:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005e5b:	7f ee                	jg     140005e4b <__rv_alloc_D2A+0x1b>
   140005e5d:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005e60:	89 c1                	mov    ecx,eax
   140005e62:	e8 56 1e 00 00       	call   140007cbd <__Balloc_D2A>
   140005e67:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005e6b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e6f:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005e72:	89 10                	mov    DWORD PTR [rax],edx
   140005e74:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e78:	48 83 c0 04          	add    rax,0x4
   140005e7c:	48 83 c4 30          	add    rsp,0x30
   140005e80:	5d                   	pop    rbp
   140005e81:	c3                   	ret

0000000140005e82 <__nrv_alloc_D2A>:
   140005e82:	55                   	push   rbp
   140005e83:	48 89 e5             	mov    rbp,rsp
   140005e86:	48 83 ec 30          	sub    rsp,0x30
   140005e8a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005e8e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005e92:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005e96:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005e99:	89 c1                	mov    ecx,eax
   140005e9b:	e8 90 ff ff ff       	call   140005e30 <__rv_alloc_D2A>
   140005ea0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005ea4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ea8:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005eac:	eb 05                	jmp    140005eb3 <__nrv_alloc_D2A+0x31>
   140005eae:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005eb3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005eb7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005ebb:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005ebf:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005ec2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ec6:	88 10                	mov    BYTE PTR [rax],dl
   140005ec8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ecc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ecf:	84 c0                	test   al,al
   140005ed1:	75 db                	jne    140005eae <__nrv_alloc_D2A+0x2c>
   140005ed3:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005ed8:	74 0b                	je     140005ee5 <__nrv_alloc_D2A+0x63>
   140005eda:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005ede:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005ee2:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005ee5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ee9:	48 83 c4 30          	add    rsp,0x30
   140005eed:	5d                   	pop    rbp
   140005eee:	c3                   	ret

0000000140005eef <__freedtoa>:
   140005eef:	55                   	push   rbp
   140005ef0:	48 89 e5             	mov    rbp,rsp
   140005ef3:	48 83 ec 30          	sub    rsp,0x30
   140005ef7:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005efb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005eff:	48 83 e8 04          	sub    rax,0x4
   140005f03:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f07:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f0b:	8b 10                	mov    edx,DWORD PTR [rax]
   140005f0d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f11:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005f14:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f18:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005f1b:	ba 01 00 00 00       	mov    edx,0x1
   140005f20:	89 c1                	mov    ecx,eax
   140005f22:	d3 e2                	shl    edx,cl
   140005f24:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f28:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005f2b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f2f:	48 89 c1             	mov    rcx,rax
   140005f32:	e8 c7 1e 00 00       	call   140007dfe <__Bfree_D2A>
   140005f37:	90                   	nop
   140005f38:	48 83 c4 30          	add    rsp,0x30
   140005f3c:	5d                   	pop    rbp
   140005f3d:	c3                   	ret

0000000140005f3e <__quorem_D2A>:
   140005f3e:	55                   	push   rbp
   140005f3f:	48 89 e5             	mov    rbp,rsp
   140005f42:	48 83 ec 70          	sub    rsp,0x70
   140005f46:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f4a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005f4e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f52:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f55:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005f58:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f5c:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f5f:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005f62:	7e 0a                	jle    140005f6e <__quorem_D2A+0x30>
   140005f64:	b8 00 00 00 00       	mov    eax,0x0
   140005f69:	e9 3f 02 00 00       	jmp    1400061ad <__quorem_D2A+0x26f>
   140005f6e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f72:	48 83 c0 18          	add    rax,0x18
   140005f76:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005f7a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005f7e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005f81:	48 98                	cdqe
   140005f83:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005f8a:	00 
   140005f8b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005f8f:	48 01 d0             	add    rax,rdx
   140005f92:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005f96:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f9a:	48 83 c0 18          	add    rax,0x18
   140005f9e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005fa2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005fa5:	48 98                	cdqe
   140005fa7:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005fae:	00 
   140005faf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005fb3:	48 01 d0             	add    rax,rdx
   140005fb6:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140005fba:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005fbe:	8b 00                	mov    eax,DWORD PTR [rax]
   140005fc0:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140005fc4:	8b 12                	mov    edx,DWORD PTR [rdx]
   140005fc6:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140005fc9:	ba 00 00 00 00       	mov    edx,0x0
   140005fce:	f7 f1                	div    ecx
   140005fd0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140005fd3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140005fd7:	0f 84 c4 00 00 00    	je     1400060a1 <__quorem_D2A+0x163>
   140005fdd:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140005fe4:	00 
   140005fe5:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   140005fec:	00 
   140005fed:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005ff1:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140005ff5:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140005ff9:	8b 00                	mov    eax,DWORD PTR [rax]
   140005ffb:	89 c2                	mov    edx,eax
   140005ffd:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140006000:	48 0f af d0          	imul   rdx,rax
   140006004:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006008:	48 01 d0             	add    rax,rdx
   14000600b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000600f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006013:	48 c1 e8 20          	shr    rax,0x20
   140006017:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000601b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000601f:	8b 00                	mov    eax,DWORD PTR [rax]
   140006021:	89 c1                	mov    ecx,eax
   140006023:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006027:	89 c2                	mov    edx,eax
   140006029:	48 89 c8             	mov    rax,rcx
   14000602c:	48 29 d0             	sub    rax,rdx
   14000602f:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006033:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006037:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000603b:	48 c1 e8 20          	shr    rax,0x20
   14000603f:	83 e0 01             	and    eax,0x1
   140006042:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006046:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000604a:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000604e:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006052:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006056:	89 10                	mov    DWORD PTR [rax],edx
   140006058:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000605c:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006060:	73 8b                	jae    140005fed <__quorem_D2A+0xaf>
   140006062:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006066:	8b 00                	mov    eax,DWORD PTR [rax]
   140006068:	85 c0                	test   eax,eax
   14000606a:	75 35                	jne    1400060a1 <__quorem_D2A+0x163>
   14000606c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006070:	48 83 c0 18          	add    rax,0x18
   140006074:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006078:	eb 04                	jmp    14000607e <__quorem_D2A+0x140>
   14000607a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000607e:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   140006083:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006087:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   14000608b:	73 0a                	jae    140006097 <__quorem_D2A+0x159>
   14000608d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006091:	8b 00                	mov    eax,DWORD PTR [rax]
   140006093:	85 c0                	test   eax,eax
   140006095:	74 e3                	je     14000607a <__quorem_D2A+0x13c>
   140006097:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000609b:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000609e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400060a1:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400060a5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060a9:	48 89 c1             	mov    rcx,rax
   1400060ac:	e8 bc 24 00 00       	call   14000856d <__cmp_D2A>
   1400060b1:	85 c0                	test   eax,eax
   1400060b3:	0f 88 f1 00 00 00    	js     1400061aa <__quorem_D2A+0x26c>
   1400060b9:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   1400060bd:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400060c4:	00 
   1400060c5:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   1400060cc:	00 
   1400060cd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060d1:	48 83 c0 18          	add    rax,0x18
   1400060d5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400060d9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400060dd:	48 83 c0 18          	add    rax,0x18
   1400060e1:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400060e5:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400060e9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400060ed:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   1400060f1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060f3:	89 c2                	mov    edx,eax
   1400060f5:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400060f9:	48 01 d0             	add    rax,rdx
   1400060fc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140006100:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006104:	48 c1 e8 20          	shr    rax,0x20
   140006108:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000610c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006110:	8b 00                	mov    eax,DWORD PTR [rax]
   140006112:	89 c1                	mov    ecx,eax
   140006114:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006118:	89 c2                	mov    edx,eax
   14000611a:	48 89 c8             	mov    rax,rcx
   14000611d:	48 29 d0             	sub    rax,rdx
   140006120:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006124:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006128:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000612c:	48 c1 e8 20          	shr    rax,0x20
   140006130:	83 e0 01             	and    eax,0x1
   140006133:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006137:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000613b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000613f:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006143:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006147:	89 10                	mov    DWORD PTR [rax],edx
   140006149:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000614d:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006151:	73 92                	jae    1400060e5 <__quorem_D2A+0x1a7>
   140006153:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006157:	48 83 c0 18          	add    rax,0x18
   14000615b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000615f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006162:	48 98                	cdqe
   140006164:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000616b:	00 
   14000616c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006170:	48 01 d0             	add    rax,rdx
   140006173:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006177:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000617b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000617d:	85 c0                	test   eax,eax
   14000617f:	75 29                	jne    1400061aa <__quorem_D2A+0x26c>
   140006181:	eb 04                	jmp    140006187 <__quorem_D2A+0x249>
   140006183:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140006187:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   14000618c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006190:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   140006194:	73 0a                	jae    1400061a0 <__quorem_D2A+0x262>
   140006196:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000619a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000619c:	85 c0                	test   eax,eax
   14000619e:	74 e3                	je     140006183 <__quorem_D2A+0x245>
   1400061a0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400061a4:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400061a7:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400061aa:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400061ad:	48 83 c4 70          	add    rsp,0x70
   1400061b1:	5d                   	pop    rbp
   1400061b2:	c3                   	ret
   1400061b3:	90                   	nop
   1400061b4:	90                   	nop
   1400061b5:	90                   	nop
   1400061b6:	90                   	nop
   1400061b7:	90                   	nop
   1400061b8:	90                   	nop
   1400061b9:	90                   	nop
   1400061ba:	90                   	nop
   1400061bb:	90                   	nop
   1400061bc:	90                   	nop
   1400061bd:	90                   	nop
   1400061be:	90                   	nop
   1400061bf:	90                   	nop

00000001400061c0 <__hi0bits_D2A>:
   1400061c0:	55                   	push   rbp
   1400061c1:	48 89 e5             	mov    rbp,rsp
   1400061c4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400061c7:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   1400061cb:	83 f0 1f             	xor    eax,0x1f
   1400061ce:	5d                   	pop    rbp
   1400061cf:	c3                   	ret

00000001400061d0 <bitstob>:
   1400061d0:	55                   	push   rbp
   1400061d1:	53                   	push   rbx
   1400061d2:	48 83 ec 58          	sub    rsp,0x58
   1400061d6:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400061db:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400061df:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   1400061e2:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400061e6:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   1400061ed:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400061f4:	eb 07                	jmp    1400061fd <bitstob+0x2d>
   1400061f6:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   1400061f9:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   1400061fd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006200:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   140006203:	7c f1                	jl     1400061f6 <bitstob+0x26>
   140006205:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140006208:	89 c1                	mov    ecx,eax
   14000620a:	e8 ae 1a 00 00       	call   140007cbd <__Balloc_D2A>
   14000620f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006213:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140006216:	83 e8 01             	sub    eax,0x1
   140006219:	c1 f8 05             	sar    eax,0x5
   14000621c:	48 98                	cdqe
   14000621e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006225:	00 
   140006226:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000622a:	48 01 d0             	add    rax,rdx
   14000622d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140006231:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006235:	48 83 c0 18          	add    rax,0x18
   140006239:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000623d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006241:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006245:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006249:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000624d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006251:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140006255:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006257:	89 10                	mov    DWORD PTR [rax],edx
   140006259:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   14000625e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006262:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140006266:	73 dd                	jae    140006245 <bitstob+0x75>
   140006268:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000626c:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140006270:	48 c1 f8 02          	sar    rax,0x2
   140006274:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140006277:	eb 1d                	jmp    140006296 <bitstob+0xc6>
   140006279:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000627d:	75 17                	jne    140006296 <bitstob+0xc6>
   14000627f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006283:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   14000628a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000628e:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140006294:	eb 59                	jmp    1400062ef <bitstob+0x11f>
   140006296:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000629a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000629d:	48 98                	cdqe
   14000629f:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400062a6:	00 
   1400062a7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400062ab:	48 01 d0             	add    rax,rdx
   1400062ae:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062b0:	85 c0                	test   eax,eax
   1400062b2:	74 c5                	je     140006279 <bitstob+0xa9>
   1400062b4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062b7:	8d 50 01             	lea    edx,[rax+0x1]
   1400062ba:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062be:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400062c1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062c4:	83 c0 01             	add    eax,0x1
   1400062c7:	c1 e0 05             	shl    eax,0x5
   1400062ca:	89 c3                	mov    ebx,eax
   1400062cc:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062d0:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400062d3:	48 63 d2             	movsxd rdx,edx
   1400062d6:	48 83 c2 04          	add    rdx,0x4
   1400062da:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   1400062de:	89 c1                	mov    ecx,eax
   1400062e0:	e8 db fe ff ff       	call   1400061c0 <__hi0bits_D2A>
   1400062e5:	29 c3                	sub    ebx,eax
   1400062e7:	89 da                	mov    edx,ebx
   1400062e9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400062ed:	89 10                	mov    DWORD PTR [rax],edx
   1400062ef:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062f3:	48 83 c4 58          	add    rsp,0x58
   1400062f7:	5b                   	pop    rbx
   1400062f8:	5d                   	pop    rbp
   1400062f9:	c3                   	ret

00000001400062fa <__gdtoa>:
   1400062fa:	55                   	push   rbp
   1400062fb:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   140006302:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140006309:	00 
   14000630a:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   140006311:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   140006317:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   14000631e:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   140006325:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   14000632c:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006333:	8b 00                	mov    eax,DWORD PTR [rax]
   140006335:	83 e0 cf             	and    eax,0xffffffcf
   140006338:	89 c2                	mov    edx,eax
   14000633a:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006341:	89 10                	mov    DWORD PTR [rax],edx
   140006343:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   14000634a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000634c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000634f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006352:	83 e0 07             	and    eax,0x7
   140006355:	83 f8 04             	cmp    eax,0x4
   140006358:	0f 84 b0 00 00 00    	je     14000640e <__gdtoa+0x114>
   14000635e:	83 f8 04             	cmp    eax,0x4
   140006361:	0f 8f d5 00 00 00    	jg     14000643c <__gdtoa+0x142>
   140006367:	83 f8 03             	cmp    eax,0x3
   14000636a:	74 74                	je     1400063e0 <__gdtoa+0xe6>
   14000636c:	83 f8 03             	cmp    eax,0x3
   14000636f:	0f 8f c7 00 00 00    	jg     14000643c <__gdtoa+0x142>
   140006375:	85 c0                	test   eax,eax
   140006377:	0f 84 05 01 00 00    	je     140006482 <__gdtoa+0x188>
   14000637d:	85 c0                	test   eax,eax
   14000637f:	0f 88 b7 00 00 00    	js     14000643c <__gdtoa+0x142>
   140006385:	83 e8 01             	sub    eax,0x1
   140006388:	83 f8 01             	cmp    eax,0x1
   14000638b:	0f 87 ab 00 00 00    	ja     14000643c <__gdtoa+0x142>
   140006391:	90                   	nop
   140006392:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006399:	8b 00                	mov    eax,DWORD PTR [rax]
   14000639b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000639e:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   1400063a2:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400063a5:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400063ac:	49 89 c8             	mov    r8,rcx
   1400063af:	48 89 c1             	mov    rcx,rax
   1400063b2:	e8 19 fe ff ff       	call   1400061d0 <bitstob>
   1400063b7:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400063bb:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   1400063c1:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400063c4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063c8:	48 89 c1             	mov    rcx,rax
   1400063cb:	e8 31 16 00 00       	call   140007a01 <__trailz_D2A>
   1400063d0:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400063d3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400063d6:	85 c0                	test   eax,eax
   1400063d8:	0f 84 8b 00 00 00    	je     140006469 <__gdtoa+0x16f>
   1400063de:	eb 66                	jmp    140006446 <__gdtoa+0x14c>
   1400063e0:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400063e7:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   1400063ed:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400063f4:	48 8d 0d 55 4f 00 00 	lea    rcx,[rip+0x4f55]        # 14000b350 <.rdata>
   1400063fb:	41 b8 08 00 00 00    	mov    r8d,0x8
   140006401:	48 89 c2             	mov    rdx,rax
   140006404:	e8 79 fa ff ff       	call   140005e82 <__nrv_alloc_D2A>
   140006409:	e9 4d 14 00 00       	jmp    14000785b <__gdtoa+0x1561>
   14000640e:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006415:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000641b:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006422:	48 8d 0d 30 4f 00 00 	lea    rcx,[rip+0x4f30]        # 14000b359 <.rdata+0x9>
   140006429:	41 b8 03 00 00 00    	mov    r8d,0x3
   14000642f:	48 89 c2             	mov    rdx,rax
   140006432:	e8 4b fa ff ff       	call   140005e82 <__nrv_alloc_D2A>
   140006437:	e9 1f 14 00 00       	jmp    14000785b <__gdtoa+0x1561>
   14000643c:	b8 00 00 00 00       	mov    eax,0x0
   140006441:	e9 15 14 00 00       	jmp    14000785b <__gdtoa+0x1561>
   140006446:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006449:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000644d:	48 89 c1             	mov    rcx,rax
   140006450:	e8 50 14 00 00       	call   1400078a5 <__rshift_D2A>
   140006455:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006458:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   14000645e:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006461:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006464:	29 c2                	sub    edx,eax
   140006466:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   140006469:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000646d:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006470:	85 c0                	test   eax,eax
   140006472:	75 3d                	jne    1400064b1 <__gdtoa+0x1b7>
   140006474:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006478:	48 89 c1             	mov    rcx,rax
   14000647b:	e8 7e 19 00 00       	call   140007dfe <__Bfree_D2A>
   140006480:	eb 01                	jmp    140006483 <__gdtoa+0x189>
   140006482:	90                   	nop
   140006483:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   14000648a:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140006490:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006497:	48 8d 0d bf 4e 00 00 	lea    rcx,[rip+0x4ebf]        # 14000b35d <.rdata+0xd>
   14000649e:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400064a4:	48 89 c2             	mov    rdx,rax
   1400064a7:	e8 d6 f9 ff ff       	call   140005e82 <__nrv_alloc_D2A>
   1400064ac:	e9 aa 13 00 00       	jmp    14000785b <__gdtoa+0x1561>
   1400064b1:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   1400064b5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064b9:	48 89 c1             	mov    rcx,rax
   1400064bc:	e8 75 23 00 00       	call   140008836 <__b2d_D2A>
   1400064c1:	66 48 0f 7e c0       	movq   rax,xmm0
   1400064c6:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   1400064ca:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400064cd:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   1400064d3:	01 d0                	add    eax,edx
   1400064d5:	83 e8 01             	sub    eax,0x1
   1400064d8:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400064db:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   1400064de:	25 ff ff 0f 00       	and    eax,0xfffff
   1400064e3:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400064e6:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   1400064e9:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400064ee:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400064f1:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400064f6:	f2 0f 10 15 62 4e 00 	movsd  xmm2,QWORD PTR [rip+0x4e62]        # 14000b360 <.rdata+0x10>
   1400064fd:	00 
   1400064fe:	66 0f 28 c8          	movapd xmm1,xmm0
   140006502:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006506:	f2 0f 10 05 5a 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e5a]        # 14000b368 <.rdata+0x18>
   14000650d:	00 
   14000650e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006512:	f2 0f 10 05 56 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e56]        # 14000b370 <.rdata+0x20>
   140006519:	00 
   14000651a:	f2 0f 58 c8          	addsd  xmm1,xmm0
   14000651e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006521:	66 0f ef d2          	pxor   xmm2,xmm2
   140006525:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   140006529:	f2 0f 10 05 47 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e47]        # 14000b378 <.rdata+0x28>
   140006530:	00 
   140006531:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006535:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006539:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000653e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006541:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006544:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006548:	79 03                	jns    14000654d <__gdtoa+0x253>
   14000654a:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   14000654d:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   140006554:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006558:	7e 23                	jle    14000657d <__gdtoa+0x283>
   14000655a:	66 0f ef c9          	pxor   xmm1,xmm1
   14000655e:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   140006563:	f2 0f 10 05 15 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e15]        # 14000b380 <.rdata+0x30>
   14000656a:	00 
   14000656b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000656f:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006574:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006578:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000657d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006582:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006586:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006589:	66 0f ef c0          	pxor   xmm0,xmm0
   14000658d:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006592:	76 1b                	jbe    1400065af <__gdtoa+0x2b5>
   140006594:	66 0f ef c0          	pxor   xmm0,xmm0
   140006598:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   14000659d:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   1400065a2:	7a 07                	jp     1400065ab <__gdtoa+0x2b1>
   1400065a4:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   1400065a9:	74 04                	je     1400065af <__gdtoa+0x2b5>
   1400065ab:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400065af:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   1400065b6:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   1400065b9:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   1400065bc:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   1400065c2:	01 ca                	add    edx,ecx
   1400065c4:	83 ea 01             	sub    edx,0x1
   1400065c7:	c1 e2 14             	shl    edx,0x14
   1400065ca:	01 d0                	add    eax,edx
   1400065cc:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400065cf:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400065d3:	78 2e                	js     140006603 <__gdtoa+0x309>
   1400065d5:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   1400065d9:	7f 28                	jg     140006603 <__gdtoa+0x309>
   1400065db:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400065e0:	48 8b 05 99 50 00 00 	mov    rax,QWORD PTR [rip+0x5099]        # 14000b680 <.refptr.__tens_D2A>
   1400065e7:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   1400065ea:	48 63 d2             	movsxd rdx,edx
   1400065ed:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400065f2:	66 0f 2f c1          	comisd xmm0,xmm1
   1400065f6:	76 04                	jbe    1400065fc <__gdtoa+0x302>
   1400065f8:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400065fc:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   140006603:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006606:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006609:	29 c2                	sub    edx,eax
   14000660b:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000660e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006611:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006615:	78 0f                	js     140006626 <__gdtoa+0x32c>
   140006617:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   14000661e:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006621:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   140006624:	eb 0f                	jmp    140006635 <__gdtoa+0x33b>
   140006626:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006629:	f7 d8                	neg    eax
   14000662b:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   14000662e:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   140006635:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006639:	78 15                	js     140006650 <__gdtoa+0x356>
   14000663b:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   140006642:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006645:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   140006648:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000664b:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   14000664e:	eb 15                	jmp    140006665 <__gdtoa+0x36b>
   140006650:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006653:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006656:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006659:	f7 d8                	neg    eax
   14000665b:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   14000665e:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   140006665:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000666c:	78 09                	js     140006677 <__gdtoa+0x37d>
   14000666e:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   140006675:	7e 0a                	jle    140006681 <__gdtoa+0x387>
   140006677:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   14000667e:	00 00 00 
   140006681:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   140006688:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   14000668f:	7e 10                	jle    1400066a1 <__gdtoa+0x3a7>
   140006691:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   140006698:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000669f:	eb 1b                	jmp    1400066bc <__gdtoa+0x3c2>
   1400066a1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400066a4:	3d f9 03 00 00       	cmp    eax,0x3f9
   1400066a9:	7f 0a                	jg     1400066b5 <__gdtoa+0x3bb>
   1400066ab:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400066ae:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   1400066b3:	7d 07                	jge    1400066bc <__gdtoa+0x3c2>
   1400066b5:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   1400066bc:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   1400066c3:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   1400066ca:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400066cd:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400066d0:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400066d7:	0f 84 c5 00 00 00    	je     1400067a2 <__gdtoa+0x4a8>
   1400066dd:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400066e4:	0f 8f e6 00 00 00    	jg     1400067d0 <__gdtoa+0x4d6>
   1400066ea:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   1400066f1:	74 7e                	je     140006771 <__gdtoa+0x477>
   1400066f3:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   1400066fa:	0f 8f d0 00 00 00    	jg     1400067d0 <__gdtoa+0x4d6>
   140006700:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006707:	0f 84 8e 00 00 00    	je     14000679b <__gdtoa+0x4a1>
   14000670d:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006714:	0f 8f b6 00 00 00    	jg     1400067d0 <__gdtoa+0x4d6>
   14000671a:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006721:	7f 0e                	jg     140006731 <__gdtoa+0x437>
   140006723:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000672a:	79 13                	jns    14000673f <__gdtoa+0x445>
   14000672c:	e9 9f 00 00 00       	jmp    1400067d0 <__gdtoa+0x4d6>
   140006731:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140006738:	74 30                	je     14000676a <__gdtoa+0x470>
   14000673a:	e9 91 00 00 00       	jmp    1400067d0 <__gdtoa+0x4d6>
   14000673f:	66 0f ef c9          	pxor   xmm1,xmm1
   140006743:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   140006748:	f2 0f 10 05 38 4c 00 	movsd  xmm0,QWORD PTR [rip+0x4c38]        # 14000b388 <.rdata+0x38>
   14000674f:	00 
   140006750:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006754:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006758:	83 c0 03             	add    eax,0x3
   14000675b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000675e:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   140006765:	00 00 00 
   140006768:	eb 66                	jmp    1400067d0 <__gdtoa+0x4d6>
   14000676a:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006771:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006778:	7f 0a                	jg     140006784 <__gdtoa+0x48a>
   14000677a:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   140006781:	00 00 00 
   140006784:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   14000678a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000678d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006790:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006793:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006796:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006799:	eb 35                	jmp    1400067d0 <__gdtoa+0x4d6>
   14000679b:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   1400067a2:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   1400067a8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400067ab:	01 d0                	add    eax,edx
   1400067ad:	83 c0 01             	add    eax,0x1
   1400067b0:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067b3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067b6:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400067b9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067bc:	83 e8 01             	sub    eax,0x1
   1400067bf:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   1400067c2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067c5:	85 c0                	test   eax,eax
   1400067c7:	7f 07                	jg     1400067d0 <__gdtoa+0x4d6>
   1400067c9:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400067d0:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067d3:	89 c1                	mov    ecx,eax
   1400067d5:	e8 56 f6 ff ff       	call   140005e30 <__rv_alloc_D2A>
   1400067da:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400067de:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400067e2:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   1400067e6:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400067ed:	7f 09                	jg     1400067f8 <__gdtoa+0x4fe>
   1400067ef:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   1400067f6:	eb 38                	jmp    140006830 <__gdtoa+0x536>
   1400067f8:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400067ff:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140006802:	83 e8 01             	sub    eax,0x1
   140006805:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006808:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000680c:	74 22                	je     140006830 <__gdtoa+0x536>
   14000680e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006812:	79 07                	jns    14000681b <__gdtoa+0x521>
   140006814:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   14000681b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000681e:	83 e0 08             	and    eax,0x8
   140006821:	85 c0                	test   eax,eax
   140006823:	74 0b                	je     140006830 <__gdtoa+0x536>
   140006825:	b8 03 00 00 00       	mov    eax,0x3
   14000682a:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   14000682d:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006830:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006834:	0f 88 b9 04 00 00    	js     140006cf3 <__gdtoa+0x9f9>
   14000683a:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   14000683e:	0f 8f af 04 00 00    	jg     140006cf3 <__gdtoa+0x9f9>
   140006844:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   140006848:	0f 84 a5 04 00 00    	je     140006cf3 <__gdtoa+0x9f9>
   14000684e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006852:	0f 85 9b 04 00 00    	jne    140006cf3 <__gdtoa+0x9f9>
   140006858:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000685c:	0f 85 91 04 00 00    	jne    140006cf3 <__gdtoa+0x9f9>
   140006862:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006869:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   14000686e:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   140006873:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006876:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140006879:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   14000687c:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   14000687f:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   140006886:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000688a:	0f 8e 98 00 00 00    	jle    140006928 <__gdtoa+0x62e>
   140006890:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006893:	83 e0 0f             	and    eax,0xf
   140006896:	89 c2                	mov    edx,eax
   140006898:	48 8b 05 e1 4d 00 00 	mov    rax,QWORD PTR [rip+0x4de1]        # 14000b680 <.refptr.__tens_D2A>
   14000689f:	48 63 d2             	movsxd rdx,edx
   1400068a2:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400068a7:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068ac:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068af:	c1 f8 04             	sar    eax,0x4
   1400068b2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400068b5:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400068b8:	83 e0 10             	and    eax,0x10
   1400068bb:	85 c0                	test   eax,eax
   1400068bd:	74 5e                	je     14000691d <__gdtoa+0x623>
   1400068bf:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   1400068c3:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400068c8:	48 8b 05 e1 4c 00 00 	mov    rax,QWORD PTR [rip+0x4ce1]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400068cf:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   1400068d4:	f2 0f 5e c1          	divsd  xmm0,xmm1
   1400068d8:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400068dd:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400068e1:	eb 3a                	jmp    14000691d <__gdtoa+0x623>
   1400068e3:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400068e6:	83 e0 01             	and    eax,0x1
   1400068e9:	85 c0                	test   eax,eax
   1400068eb:	74 24                	je     140006911 <__gdtoa+0x617>
   1400068ed:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400068f1:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400068f4:	48 8b 05 b5 4c 00 00 	mov    rax,QWORD PTR [rip+0x4cb5]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400068fb:	48 63 d2             	movsxd rdx,edx
   1400068fe:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006903:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006908:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000690c:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006911:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006914:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006917:	83 c0 01             	add    eax,0x1
   14000691a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000691d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006921:	75 c0                	jne    1400068e3 <__gdtoa+0x5e9>
   140006923:	e9 8b 00 00 00       	jmp    1400069b3 <__gdtoa+0x6b9>
   140006928:	f2 0f 10 05 60 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a60]        # 14000b390 <.rdata+0x40>
   14000692f:	00 
   140006930:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006935:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006938:	f7 d8                	neg    eax
   14000693a:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   14000693d:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140006941:	74 70                	je     1400069b3 <__gdtoa+0x6b9>
   140006943:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006948:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   14000694b:	83 e0 0f             	and    eax,0xf
   14000694e:	89 c2                	mov    edx,eax
   140006950:	48 8b 05 29 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d29]        # 14000b680 <.refptr.__tens_D2A>
   140006957:	48 63 d2             	movsxd rdx,edx
   14000695a:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   14000695f:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006963:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006968:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   14000696b:	c1 f8 04             	sar    eax,0x4
   14000696e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006971:	eb 3a                	jmp    1400069ad <__gdtoa+0x6b3>
   140006973:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006976:	83 e0 01             	and    eax,0x1
   140006979:	85 c0                	test   eax,eax
   14000697b:	74 24                	je     1400069a1 <__gdtoa+0x6a7>
   14000697d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006981:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006986:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006989:	48 8b 05 20 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c20]        # 14000b5b0 <.refptr.__bigtens_D2A>
   140006990:	48 63 d2             	movsxd rdx,edx
   140006993:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006998:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000699c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069a1:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   1400069a4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400069a7:	83 c0 01             	add    eax,0x1
   1400069aa:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400069ad:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400069b1:	75 c0                	jne    140006973 <__gdtoa+0x679>
   1400069b3:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400069b7:	74 47                	je     140006a00 <__gdtoa+0x706>
   1400069b9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069be:	f2 0f 10 05 ca 49 00 	movsd  xmm0,QWORD PTR [rip+0x49ca]        # 14000b390 <.rdata+0x40>
   1400069c5:	00 
   1400069c6:	66 0f 2f c1          	comisd xmm0,xmm1
   1400069ca:	76 34                	jbe    140006a00 <__gdtoa+0x706>
   1400069cc:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400069d0:	7e 2e                	jle    140006a00 <__gdtoa+0x706>
   1400069d2:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   1400069d6:	0f 8e f5 02 00 00    	jle    140006cd1 <__gdtoa+0x9d7>
   1400069dc:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400069df:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400069e2:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400069e6:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069eb:	f2 0f 10 05 a5 49 00 	movsd  xmm0,QWORD PTR [rip+0x49a5]        # 14000b398 <.rdata+0x48>
   1400069f2:	00 
   1400069f3:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069f7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069fc:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006a00:	66 0f ef c9          	pxor   xmm1,xmm1
   140006a04:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006a09:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a0e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006a12:	f2 0f 10 05 86 49 00 	movsd  xmm0,QWORD PTR [rip+0x4986]        # 14000b3a0 <.rdata+0x50>
   140006a19:	00 
   140006a1a:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006a1e:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a23:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   140006a26:	2d 00 00 40 03       	sub    eax,0x3400000
   140006a2b:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   140006a2e:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a32:	75 5f                	jne    140006a93 <__gdtoa+0x799>
   140006a34:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006a3b:	00 
   140006a3c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006a40:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006a44:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a49:	f2 0f 10 0d 57 49 00 	movsd  xmm1,QWORD PTR [rip+0x4957]        # 14000b3a8 <.rdata+0x58>
   140006a50:	00 
   140006a51:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a55:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a5a:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a5f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006a64:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a68:	0f 87 ac 07 00 00    	ja     14000721a <__gdtoa+0xf20>
   140006a6e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a73:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006a78:	f3 0f 7e 15 30 49 00 	movq   xmm2,QWORD PTR [rip+0x4930]        # 14000b3b0 <.rdata+0x60>
   140006a7f:	00 
   140006a80:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006a84:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a88:	0f 87 6e 07 00 00    	ja     1400071fc <__gdtoa+0xf02>
   140006a8e:	e9 42 02 00 00       	jmp    140006cd5 <__gdtoa+0x9db>
   140006a93:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006a97:	0f 84 22 01 00 00    	je     140006bbf <__gdtoa+0x8c5>
   140006a9d:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006aa2:	f2 0f 10 05 16 49 00 	movsd  xmm0,QWORD PTR [rip+0x4916]        # 14000b3c0 <.rdata+0x70>
   140006aa9:	00 
   140006aaa:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006aae:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006ab1:	8d 50 ff             	lea    edx,[rax-0x1]
   140006ab4:	48 8b 05 c5 4b 00 00 	mov    rax,QWORD PTR [rip+0x4bc5]        # 14000b680 <.refptr.__tens_D2A>
   140006abb:	48 63 d2             	movsxd rdx,edx
   140006abe:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006ac3:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006ac7:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006acc:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006ad0:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006ad5:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006adc:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ae1:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006ae6:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006aea:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006aed:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006af2:	66 0f ef c9          	pxor   xmm1,xmm1
   140006af6:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006afb:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006b00:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b04:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b09:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006b0c:	8d 48 30             	lea    ecx,[rax+0x30]
   140006b0f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006b13:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006b17:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006b1b:	89 ca                	mov    edx,ecx
   140006b1d:	88 10                	mov    BYTE PTR [rax],dl
   140006b1f:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b24:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b29:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b2d:	76 29                	jbe    140006b58 <__gdtoa+0x85e>
   140006b2f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b34:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b38:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b3c:	7a 0e                	jp     140006b4c <__gdtoa+0x852>
   140006b3e:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b42:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b46:	0f 84 93 0c 00 00    	je     1400077df <__gdtoa+0x14e5>
   140006b4c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006b53:	e9 87 0c 00 00       	jmp    1400077df <__gdtoa+0x14e5>
   140006b58:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006b5d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006b62:	66 0f 28 c8          	movapd xmm1,xmm0
   140006b66:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006b6a:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b6f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b73:	0f 87 c3 02 00 00    	ja     140006e3c <__gdtoa+0xb42>
   140006b79:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006b7c:	83 c0 01             	add    eax,0x1
   140006b7f:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006b82:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006b85:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006b88:	0f 8e 46 01 00 00    	jle    140006cd4 <__gdtoa+0x9da>
   140006b8e:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b93:	f2 0f 10 05 fd 47 00 	movsd  xmm0,QWORD PTR [rip+0x47fd]        # 14000b398 <.rdata+0x48>
   140006b9a:	00 
   140006b9b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b9f:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006ba4:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ba9:	f2 0f 10 05 e7 47 00 	movsd  xmm0,QWORD PTR [rip+0x47e7]        # 14000b398 <.rdata+0x48>
   140006bb0:	00 
   140006bb1:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bb5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006bba:	e9 1d ff ff ff       	jmp    140006adc <__gdtoa+0x7e2>
   140006bbf:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006bc4:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006bc7:	8d 50 ff             	lea    edx,[rax-0x1]
   140006bca:	48 8b 05 af 4a 00 00 	mov    rax,QWORD PTR [rip+0x4aaf]        # 14000b680 <.refptr.__tens_D2A>
   140006bd1:	48 63 d2             	movsxd rdx,edx
   140006bd4:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006bd9:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bdd:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006be2:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006be9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006bee:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006bf3:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006bf7:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006bfa:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006bfe:	74 1c                	je     140006c1c <__gdtoa+0x922>
   140006c00:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c05:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c09:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006c0e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006c13:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006c17:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c1c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006c1f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006c22:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006c26:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006c2a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006c2e:	89 ca                	mov    edx,ecx
   140006c30:	88 10                	mov    BYTE PTR [rax],dl
   140006c32:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c35:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006c38:	75 73                	jne    140006cad <__gdtoa+0x9b3>
   140006c3a:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006c3f:	f2 0f 10 05 79 47 00 	movsd  xmm0,QWORD PTR [rip+0x4779]        # 14000b3c0 <.rdata+0x70>
   140006c46:	00 
   140006c47:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c4b:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006c50:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c55:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c5a:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006c5f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c63:	0f 87 d6 01 00 00    	ja     140006e3f <__gdtoa+0xb45>
   140006c69:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c6e:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006c73:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006c78:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006c7c:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c80:	77 02                	ja     140006c84 <__gdtoa+0x98a>
   140006c82:	eb 51                	jmp    140006cd5 <__gdtoa+0x9db>
   140006c84:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c89:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c8d:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c91:	7a 0e                	jp     140006ca1 <__gdtoa+0x9a7>
   140006c93:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c97:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c9b:	0f 84 41 0b 00 00    	je     1400077e2 <__gdtoa+0x14e8>
   140006ca1:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006ca8:	e9 35 0b 00 00       	jmp    1400077e2 <__gdtoa+0x14e8>
   140006cad:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006cb0:	83 c0 01             	add    eax,0x1
   140006cb3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006cb6:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006cbb:	f2 0f 10 05 d5 46 00 	movsd  xmm0,QWORD PTR [rip+0x46d5]        # 14000b398 <.rdata+0x48>
   140006cc2:	00 
   140006cc3:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006cc7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006ccc:	e9 18 ff ff ff       	jmp    140006be9 <__gdtoa+0x8ef>
   140006cd1:	90                   	nop
   140006cd2:	eb 01                	jmp    140006cd5 <__gdtoa+0x9db>
   140006cd4:	90                   	nop
   140006cd5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006cd9:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006cdd:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006ce2:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006ce7:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006cea:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006ced:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006cf0:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006cf3:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006cfa:	0f 88 bf 01 00 00    	js     140006ebf <__gdtoa+0xbc5>
   140006d00:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006d07:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006d0a:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006d0d:	0f 8f ac 01 00 00    	jg     140006ebf <__gdtoa+0xbc5>
   140006d13:	48 8b 05 66 49 00 00 	mov    rax,QWORD PTR [rip+0x4966]        # 14000b680 <.refptr.__tens_D2A>
   140006d1a:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006d1d:	48 63 d2             	movsxd rdx,edx
   140006d20:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006d25:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006d2a:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006d31:	79 45                	jns    140006d78 <__gdtoa+0xa7e>
   140006d33:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d37:	7f 3f                	jg     140006d78 <__gdtoa+0xa7e>
   140006d39:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006d40:	00 
   140006d41:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006d45:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006d49:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d4d:	0f 88 ac 04 00 00    	js     1400071ff <__gdtoa+0xf05>
   140006d53:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d58:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006d5d:	f2 0f 10 05 43 46 00 	movsd  xmm0,QWORD PTR [rip+0x4643]        # 14000b3a8 <.rdata+0x58>
   140006d64:	00 
   140006d65:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006d69:	66 0f 2f c1          	comisd xmm0,xmm1
   140006d6d:	0f 83 8c 04 00 00    	jae    1400071ff <__gdtoa+0xf05>
   140006d73:	e9 a6 04 00 00       	jmp    14000721e <__gdtoa+0xf24>
   140006d78:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006d7f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d84:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006d89:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006d8d:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006d90:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d95:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d99:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006d9e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006da3:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006da7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006dac:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006daf:	8d 48 30             	lea    ecx,[rax+0x30]
   140006db2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006db6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006dba:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006dbe:	89 ca                	mov    edx,ecx
   140006dc0:	88 10                	mov    BYTE PTR [rax],dl
   140006dc2:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006dc7:	66 0f ef c9          	pxor   xmm1,xmm1
   140006dcb:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006dcf:	7a 0e                	jp     140006ddf <__gdtoa+0xae5>
   140006dd1:	66 0f ef c9          	pxor   xmm1,xmm1
   140006dd5:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006dd9:	0f 84 da 00 00 00    	je     140006eb9 <__gdtoa+0xbbf>
   140006ddf:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006de2:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006de5:	0f 85 aa 00 00 00    	jne    140006e95 <__gdtoa+0xb9b>
   140006deb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006def:	74 12                	je     140006e03 <__gdtoa+0xb09>
   140006df1:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006df5:	74 4b                	je     140006e42 <__gdtoa+0xb48>
   140006df7:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006dfe:	e9 e3 09 00 00       	jmp    1400077e6 <__gdtoa+0x14ec>
   140006e03:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e08:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006e0c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e11:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e16:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006e1b:	77 28                	ja     140006e45 <__gdtoa+0xb4b>
   140006e1d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e22:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e27:	7a 63                	jp     140006e8c <__gdtoa+0xb92>
   140006e29:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e2e:	75 5c                	jne    140006e8c <__gdtoa+0xb92>
   140006e30:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006e33:	83 e0 01             	and    eax,0x1
   140006e36:	85 c0                	test   eax,eax
   140006e38:	74 52                	je     140006e8c <__gdtoa+0xb92>
   140006e3a:	eb 0a                	jmp    140006e46 <__gdtoa+0xb4c>
   140006e3c:	90                   	nop
   140006e3d:	eb 07                	jmp    140006e46 <__gdtoa+0xb4c>
   140006e3f:	90                   	nop
   140006e40:	eb 04                	jmp    140006e46 <__gdtoa+0xb4c>
   140006e42:	90                   	nop
   140006e43:	eb 01                	jmp    140006e46 <__gdtoa+0xb4c>
   140006e45:	90                   	nop
   140006e46:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006e4d:	eb 17                	jmp    140006e66 <__gdtoa+0xb6c>
   140006e4f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e53:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006e57:	75 0d                	jne    140006e66 <__gdtoa+0xb6c>
   140006e59:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006e5d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e61:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006e64:	eb 10                	jmp    140006e76 <__gdtoa+0xb7c>
   140006e66:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006e6b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e6f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006e72:	3c 39                	cmp    al,0x39
   140006e74:	74 d9                	je     140006e4f <__gdtoa+0xb55>
   140006e76:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e7a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006e7e:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006e82:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006e85:	83 c2 01             	add    edx,0x1
   140006e88:	88 10                	mov    BYTE PTR [rax],dl
   140006e8a:	eb 2e                	jmp    140006eba <__gdtoa+0xbc0>
   140006e8c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e93:	eb 25                	jmp    140006eba <__gdtoa+0xbc0>
   140006e95:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e98:	83 c0 01             	add    eax,0x1
   140006e9b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006e9e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ea3:	f2 0f 10 05 ed 44 00 	movsd  xmm0,QWORD PTR [rip+0x44ed]        # 14000b398 <.rdata+0x48>
   140006eaa:	00 
   140006eab:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006eaf:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006eb4:	e9 c6 fe ff ff       	jmp    140006d7f <__gdtoa+0xa85>
   140006eb9:	90                   	nop
   140006eba:	e9 27 09 00 00       	jmp    1400077e6 <__gdtoa+0x14ec>
   140006ebf:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006ec2:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006ec5:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006ec8:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006ecb:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006ed2:	00 
   140006ed3:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006ed7:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006edb:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006edf:	0f 84 e0 00 00 00    	je     140006fc5 <__gdtoa+0xccb>
   140006ee5:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006ee8:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006eeb:	29 c2                	sub    edx,eax
   140006eed:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006ef0:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ef3:	8d 50 01             	lea    edx,[rax+0x1]
   140006ef6:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006ef9:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006eff:	29 c2                	sub    edx,eax
   140006f01:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f08:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f0b:	39 c2                	cmp    edx,eax
   140006f0d:	7d 43                	jge    140006f52 <__gdtoa+0xc58>
   140006f0f:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006f16:	74 3a                	je     140006f52 <__gdtoa+0xc58>
   140006f18:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006f1f:	74 31                	je     140006f52 <__gdtoa+0xc58>
   140006f21:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f28:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f2b:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f31:	29 c2                	sub    edx,eax
   140006f33:	8d 42 01             	lea    eax,[rdx+0x1]
   140006f36:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f39:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f40:	7e 68                	jle    140006faa <__gdtoa+0xcb0>
   140006f42:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006f46:	7e 62                	jle    140006faa <__gdtoa+0xcb0>
   140006f48:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f4b:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006f4e:	7d 5a                	jge    140006faa <__gdtoa+0xcb0>
   140006f50:	eb 0a                	jmp    140006f5c <__gdtoa+0xc62>
   140006f52:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f59:	7e 50                	jle    140006fab <__gdtoa+0xcb1>
   140006f5b:	90                   	nop
   140006f5c:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f5f:	83 e8 01             	sub    eax,0x1
   140006f62:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006f65:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006f68:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006f6b:	7c 08                	jl     140006f75 <__gdtoa+0xc7b>
   140006f6d:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f70:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006f73:	eb 19                	jmp    140006f8e <__gdtoa+0xc94>
   140006f75:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006f78:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006f7b:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f7e:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006f81:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f84:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006f87:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006f8e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f91:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f94:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f97:	85 c0                	test   eax,eax
   140006f99:	79 10                	jns    140006fab <__gdtoa+0xcb1>
   140006f9b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f9e:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006fa1:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006fa8:	eb 01                	jmp    140006fab <__gdtoa+0xcb1>
   140006faa:	90                   	nop
   140006fab:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fae:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140006fb1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fb4:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140006fb7:	b9 01 00 00 00       	mov    ecx,0x1
   140006fbc:	e8 f6 0f 00 00       	call   140007fb7 <__i2b_D2A>
   140006fc1:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006fc5:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140006fc9:	7e 26                	jle    140006ff1 <__gdtoa+0xcf7>
   140006fcb:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   140006fcf:	7e 20                	jle    140006ff1 <__gdtoa+0xcf7>
   140006fd1:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140006fd4:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140006fd7:	39 c2                	cmp    edx,eax
   140006fd9:	0f 4e c2             	cmovle eax,edx
   140006fdc:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006fdf:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fe2:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006fe5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fe8:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006feb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fee:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140006ff1:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140006ff5:	7e 7e                	jle    140007075 <__gdtoa+0xd7b>
   140006ff7:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006ffb:	74 65                	je     140007062 <__gdtoa+0xd68>
   140006ffd:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140007001:	7e 3b                	jle    14000703e <__gdtoa+0xd44>
   140007003:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140007006:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000700a:	48 89 c1             	mov    rcx,rax
   14000700d:	e8 11 12 00 00       	call   140008223 <__pow5mult_D2A>
   140007012:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007016:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000701a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000701e:	48 89 c1             	mov    rcx,rax
   140007021:	e8 d7 0f 00 00       	call   140007ffd <__mult_D2A>
   140007026:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000702a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000702e:	48 89 c1             	mov    rcx,rax
   140007031:	e8 c8 0d 00 00       	call   140007dfe <__Bfree_D2A>
   140007036:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000703a:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000703e:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140007041:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   140007044:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007047:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000704b:	74 28                	je     140007075 <__gdtoa+0xd7b>
   14000704d:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   140007050:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007054:	48 89 c1             	mov    rcx,rax
   140007057:	e8 c7 11 00 00       	call   140008223 <__pow5mult_D2A>
   14000705c:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007060:	eb 13                	jmp    140007075 <__gdtoa+0xd7b>
   140007062:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   140007065:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007069:	48 89 c1             	mov    rcx,rax
   14000706c:	e8 b2 11 00 00       	call   140008223 <__pow5mult_D2A>
   140007071:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007075:	b9 01 00 00 00       	mov    ecx,0x1
   14000707a:	e8 38 0f 00 00       	call   140007fb7 <__i2b_D2A>
   14000707f:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007083:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007087:	7e 13                	jle    14000709c <__gdtoa+0xda2>
   140007089:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   14000708c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007090:	48 89 c1             	mov    rcx,rax
   140007093:	e8 8b 11 00 00       	call   140008223 <__pow5mult_D2A>
   140007098:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000709c:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   1400070a3:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400070aa:	7f 29                	jg     1400070d5 <__gdtoa+0xddb>
   1400070ac:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   1400070af:	83 f8 01             	cmp    eax,0x1
   1400070b2:	75 21                	jne    1400070d5 <__gdtoa+0xddb>
   1400070b4:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400070bb:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400070be:	83 c0 01             	add    eax,0x1
   1400070c1:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   1400070c4:	7e 0f                	jle    1400070d5 <__gdtoa+0xddb>
   1400070c6:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   1400070ca:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   1400070ce:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   1400070d5:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   1400070d9:	74 22                	je     1400070fd <__gdtoa+0xe03>
   1400070db:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070df:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400070e2:	8d 50 ff             	lea    edx,[rax-0x1]
   1400070e5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070e9:	48 63 d2             	movsxd rdx,edx
   1400070ec:	48 83 c2 04          	add    rdx,0x4
   1400070f0:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   1400070f4:	89 c1                	mov    ecx,eax
   1400070f6:	e8 c5 f0 ff ff       	call   1400061c0 <__hi0bits_D2A>
   1400070fb:	eb 05                	jmp    140007102 <__gdtoa+0xe08>
   1400070fd:	b8 1f 00 00 00       	mov    eax,0x1f
   140007102:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   140007105:	83 e8 04             	sub    eax,0x4
   140007108:	83 e0 1f             	and    eax,0x1f
   14000710b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000710e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007111:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   140007114:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007117:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   14000711a:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   14000711e:	7e 13                	jle    140007133 <__gdtoa+0xe39>
   140007120:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   140007123:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007127:	48 89 c1             	mov    rcx,rax
   14000712a:	e8 b1 12 00 00       	call   1400083e0 <__lshift_D2A>
   14000712f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007133:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007136:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140007139:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000713d:	7e 13                	jle    140007152 <__gdtoa+0xe58>
   14000713f:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007142:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007146:	48 89 c1             	mov    rcx,rax
   140007149:	e8 92 12 00 00       	call   1400083e0 <__lshift_D2A>
   14000714e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007152:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140007156:	74 5a                	je     1400071b2 <__gdtoa+0xeb8>
   140007158:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000715c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007160:	48 89 c1             	mov    rcx,rax
   140007163:	e8 05 14 00 00       	call   14000856d <__cmp_D2A>
   140007168:	85 c0                	test   eax,eax
   14000716a:	79 46                	jns    1400071b2 <__gdtoa+0xeb8>
   14000716c:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140007170:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007174:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000717a:	ba 0a 00 00 00       	mov    edx,0xa
   14000717f:	48 89 c1             	mov    rcx,rax
   140007182:	e8 02 0d 00 00       	call   140007e89 <__multadd_D2A>
   140007187:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000718b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000718f:	74 1b                	je     1400071ac <__gdtoa+0xeb2>
   140007191:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007195:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000719b:	ba 0a 00 00 00       	mov    edx,0xa
   1400071a0:	48 89 c1             	mov    rcx,rax
   1400071a3:	e8 e1 0c 00 00       	call   140007e89 <__multadd_D2A>
   1400071a8:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400071ac:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400071af:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400071b2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400071b6:	0f 8f 81 00 00 00    	jg     14000723d <__gdtoa+0xf43>
   1400071bc:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400071c3:	7e 78                	jle    14000723d <__gdtoa+0xf43>
   1400071c5:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400071c9:	78 37                	js     140007202 <__gdtoa+0xf08>
   1400071cb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400071cf:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071d5:	ba 05 00 00 00       	mov    edx,0x5
   1400071da:	48 89 c1             	mov    rcx,rax
   1400071dd:	e8 a7 0c 00 00       	call   140007e89 <__multadd_D2A>
   1400071e2:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400071e6:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400071ea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071ee:	48 89 c1             	mov    rcx,rax
   1400071f1:	e8 77 13 00 00       	call   14000856d <__cmp_D2A>
   1400071f6:	85 c0                	test   eax,eax
   1400071f8:	7f 23                	jg     14000721d <__gdtoa+0xf23>
   1400071fa:	eb 07                	jmp    140007203 <__gdtoa+0xf09>
   1400071fc:	90                   	nop
   1400071fd:	eb 04                	jmp    140007203 <__gdtoa+0xf09>
   1400071ff:	90                   	nop
   140007200:	eb 01                	jmp    140007203 <__gdtoa+0xf09>
   140007202:	90                   	nop
   140007203:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   140007209:	f7 d0                	not    eax
   14000720b:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   14000720e:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007215:	e9 87 05 00 00       	jmp    1400077a1 <__gdtoa+0x14a7>
   14000721a:	90                   	nop
   14000721b:	eb 01                	jmp    14000721e <__gdtoa+0xf24>
   14000721d:	90                   	nop
   14000721e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007225:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007229:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000722d:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007231:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007234:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007238:	e9 64 05 00 00       	jmp    1400077a1 <__gdtoa+0x14a7>
   14000723d:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140007241:	0f 84 14 04 00 00    	je     14000765b <__gdtoa+0x1361>
   140007247:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   14000724b:	7e 13                	jle    140007260 <__gdtoa+0xf66>
   14000724d:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   140007250:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007254:	48 89 c1             	mov    rcx,rax
   140007257:	e8 84 11 00 00       	call   1400083e0 <__lshift_D2A>
   14000725c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007260:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007264:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007268:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   14000726c:	74 57                	je     1400072c5 <__gdtoa+0xfcb>
   14000726e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007272:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007275:	89 c1                	mov    ecx,eax
   140007277:	e8 41 0a 00 00       	call   140007cbd <__Balloc_D2A>
   14000727c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007280:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007284:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007287:	48 98                	cdqe
   140007289:	48 83 c0 02          	add    rax,0x2
   14000728d:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007294:	00 
   140007295:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007299:	48 8d 50 10          	lea    rdx,[rax+0x10]
   14000729d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072a1:	48 83 c0 10          	add    rax,0x10
   1400072a5:	49 89 c8             	mov    r8,rcx
   1400072a8:	48 89 c1             	mov    rcx,rax
   1400072ab:	e8 b8 22 00 00       	call   140009568 <memcpy>
   1400072b0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072b4:	ba 01 00 00 00       	mov    edx,0x1
   1400072b9:	48 89 c1             	mov    rcx,rax
   1400072bc:	e8 1f 11 00 00       	call   1400083e0 <__lshift_D2A>
   1400072c1:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072c5:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400072cc:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400072d0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072d4:	48 89 c1             	mov    rcx,rax
   1400072d7:	e8 62 ec ff ff       	call   140005f3e <__quorem_D2A>
   1400072dc:	83 c0 30             	add    eax,0x30
   1400072df:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400072e2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400072e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072ea:	48 89 c1             	mov    rcx,rax
   1400072ed:	e8 7b 12 00 00       	call   14000856d <__cmp_D2A>
   1400072f2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400072f5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400072f9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400072fd:	48 89 c1             	mov    rcx,rax
   140007300:	e8 38 13 00 00       	call   14000863d <__diff_D2A>
   140007305:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140007309:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   14000730d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140007310:	85 c0                	test   eax,eax
   140007312:	75 15                	jne    140007329 <__gdtoa+0x102f>
   140007314:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140007318:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000731c:	48 89 c1             	mov    rcx,rax
   14000731f:	e8 49 12 00 00       	call   14000856d <__cmp_D2A>
   140007324:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007327:	eb 07                	jmp    140007330 <__gdtoa+0x1036>
   140007329:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   140007330:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140007334:	48 89 c1             	mov    rcx,rax
   140007337:	e8 c2 0a 00 00       	call   140007dfe <__Bfree_D2A>
   14000733c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007340:	75 70                	jne    1400073b2 <__gdtoa+0x10b8>
   140007342:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007349:	75 67                	jne    1400073b2 <__gdtoa+0x10b8>
   14000734b:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007352:	8b 00                	mov    eax,DWORD PTR [rax]
   140007354:	83 e0 01             	and    eax,0x1
   140007357:	85 c0                	test   eax,eax
   140007359:	75 57                	jne    1400073b2 <__gdtoa+0x10b8>
   14000735b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000735f:	75 51                	jne    1400073b2 <__gdtoa+0x10b8>
   140007361:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007365:	0f 84 01 02 00 00    	je     14000756c <__gdtoa+0x1272>
   14000736b:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000736f:	7f 20                	jg     140007391 <__gdtoa+0x1097>
   140007371:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007375:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007378:	83 f8 01             	cmp    eax,0x1
   14000737b:	7f 0b                	jg     140007388 <__gdtoa+0x108e>
   14000737d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007381:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007384:	85 c0                	test   eax,eax
   140007386:	74 14                	je     14000739c <__gdtoa+0x10a2>
   140007388:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000738f:	eb 0b                	jmp    14000739c <__gdtoa+0x10a2>
   140007391:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   140007395:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   14000739c:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400073a0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400073a4:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400073a8:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400073ab:	88 10                	mov    BYTE PTR [rax],dl
   1400073ad:	e9 ef 03 00 00       	jmp    1400077a1 <__gdtoa+0x14a7>
   1400073b2:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073b6:	78 2b                	js     1400073e3 <__gdtoa+0x10e9>
   1400073b8:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073bc:	0f 85 96 01 00 00    	jne    140007558 <__gdtoa+0x125e>
   1400073c2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400073c9:	0f 85 89 01 00 00    	jne    140007558 <__gdtoa+0x125e>
   1400073cf:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400073d6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400073d8:	83 e0 01             	and    eax,0x1
   1400073db:	85 c0                	test   eax,eax
   1400073dd:	0f 85 75 01 00 00    	jne    140007558 <__gdtoa+0x125e>
   1400073e3:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400073e7:	0f 84 db 00 00 00    	je     1400074c8 <__gdtoa+0x11ce>
   1400073ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073f1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400073f4:	83 f8 01             	cmp    eax,0x1
   1400073f7:	7f 0f                	jg     140007408 <__gdtoa+0x110e>
   1400073f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073fd:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007400:	85 c0                	test   eax,eax
   140007402:	0f 84 c0 00 00 00    	je     1400074c8 <__gdtoa+0x11ce>
   140007408:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   14000740c:	0f 85 83 00 00 00    	jne    140007495 <__gdtoa+0x119b>
   140007412:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007419:	e9 24 01 00 00       	jmp    140007542 <__gdtoa+0x1248>
   14000741e:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007422:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007426:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000742a:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000742d:	88 10                	mov    BYTE PTR [rax],dl
   14000742f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007433:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007439:	ba 0a 00 00 00       	mov    edx,0xa
   14000743e:	48 89 c1             	mov    rcx,rax
   140007441:	e8 43 0a 00 00       	call   140007e89 <__multadd_D2A>
   140007446:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000744a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000744e:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007452:	75 08                	jne    14000745c <__gdtoa+0x1162>
   140007454:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007458:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   14000745c:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007460:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007464:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007468:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000746e:	ba 0a 00 00 00       	mov    edx,0xa
   140007473:	48 89 c1             	mov    rcx,rax
   140007476:	e8 0e 0a 00 00       	call   140007e89 <__multadd_D2A>
   14000747b:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000747f:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007483:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007487:	48 89 c1             	mov    rcx,rax
   14000748a:	e8 af ea ff ff       	call   140005f3e <__quorem_D2A>
   14000748f:	83 c0 30             	add    eax,0x30
   140007492:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007495:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007499:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000749d:	48 89 c1             	mov    rcx,rax
   1400074a0:	e8 c8 10 00 00       	call   14000856d <__cmp_D2A>
   1400074a5:	85 c0                	test   eax,eax
   1400074a7:	0f 8f 71 ff ff ff    	jg     14000741e <__gdtoa+0x1124>
   1400074ad:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400074b0:	8d 50 01             	lea    edx,[rax+0x1]
   1400074b3:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   1400074b6:	83 f8 39             	cmp    eax,0x39
   1400074b9:	0f 84 b0 00 00 00    	je     14000756f <__gdtoa+0x1275>
   1400074bf:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400074c6:	eb 7a                	jmp    140007542 <__gdtoa+0x1248>
   1400074c8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074cc:	7e 53                	jle    140007521 <__gdtoa+0x1227>
   1400074ce:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074d2:	ba 01 00 00 00       	mov    edx,0x1
   1400074d7:	48 89 c1             	mov    rcx,rax
   1400074da:	e8 01 0f 00 00       	call   1400083e0 <__lshift_D2A>
   1400074df:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400074e3:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400074e7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074eb:	48 89 c1             	mov    rcx,rax
   1400074ee:	e8 7a 10 00 00       	call   14000856d <__cmp_D2A>
   1400074f3:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400074f6:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074fa:	7f 10                	jg     14000750c <__gdtoa+0x1212>
   1400074fc:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007500:	75 18                	jne    14000751a <__gdtoa+0x1220>
   140007502:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007505:	83 e0 01             	and    eax,0x1
   140007508:	85 c0                	test   eax,eax
   14000750a:	74 0e                	je     14000751a <__gdtoa+0x1220>
   14000750c:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000750f:	8d 50 01             	lea    edx,[rax+0x1]
   140007512:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007515:	83 f8 39             	cmp    eax,0x39
   140007518:	74 58                	je     140007572 <__gdtoa+0x1278>
   14000751a:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007521:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007525:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007528:	83 f8 01             	cmp    eax,0x1
   14000752b:	7f 0b                	jg     140007538 <__gdtoa+0x123e>
   14000752d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007531:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007534:	85 c0                	test   eax,eax
   140007536:	74 09                	je     140007541 <__gdtoa+0x1247>
   140007538:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000753f:	eb 01                	jmp    140007542 <__gdtoa+0x1248>
   140007541:	90                   	nop
   140007542:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007546:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000754a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000754e:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007551:	88 10                	mov    BYTE PTR [rax],dl
   140007553:	e9 49 02 00 00       	jmp    1400077a1 <__gdtoa+0x14a7>
   140007558:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000755c:	7e 52                	jle    1400075b0 <__gdtoa+0x12b6>
   14000755e:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007562:	74 4c                	je     1400075b0 <__gdtoa+0x12b6>
   140007564:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007568:	75 24                	jne    14000758e <__gdtoa+0x1294>
   14000756a:	eb 07                	jmp    140007573 <__gdtoa+0x1279>
   14000756c:	90                   	nop
   14000756d:	eb 04                	jmp    140007573 <__gdtoa+0x1279>
   14000756f:	90                   	nop
   140007570:	eb 01                	jmp    140007573 <__gdtoa+0x1279>
   140007572:	90                   	nop
   140007573:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007577:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000757b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000757f:	c6 00 39             	mov    BYTE PTR [rax],0x39
   140007582:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007589:	e9 9d 01 00 00       	jmp    14000772b <__gdtoa+0x1431>
   14000758e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007595:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007598:	8d 48 01             	lea    ecx,[rax+0x1]
   14000759b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000759f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075a3:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075a7:	89 ca                	mov    edx,ecx
   1400075a9:	88 10                	mov    BYTE PTR [rax],dl
   1400075ab:	e9 f1 01 00 00       	jmp    1400077a1 <__gdtoa+0x14a7>
   1400075b0:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075b4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075b8:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075bc:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400075bf:	88 10                	mov    BYTE PTR [rax],dl
   1400075c1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400075c4:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   1400075c7:	0f 84 ea 00 00 00    	je     1400076b7 <__gdtoa+0x13bd>
   1400075cd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075d1:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075d7:	ba 0a 00 00 00       	mov    edx,0xa
   1400075dc:	48 89 c1             	mov    rcx,rax
   1400075df:	e8 a5 08 00 00       	call   140007e89 <__multadd_D2A>
   1400075e4:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400075e8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400075ec:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400075f0:	75 25                	jne    140007617 <__gdtoa+0x131d>
   1400075f2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400075f6:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075fc:	ba 0a 00 00 00       	mov    edx,0xa
   140007601:	48 89 c1             	mov    rcx,rax
   140007604:	e8 80 08 00 00       	call   140007e89 <__multadd_D2A>
   140007609:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000760d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007611:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007615:	eb 36                	jmp    14000764d <__gdtoa+0x1353>
   140007617:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000761b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007621:	ba 0a 00 00 00       	mov    edx,0xa
   140007626:	48 89 c1             	mov    rcx,rax
   140007629:	e8 5b 08 00 00       	call   140007e89 <__multadd_D2A>
   14000762e:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007632:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007636:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000763c:	ba 0a 00 00 00       	mov    edx,0xa
   140007641:	48 89 c1             	mov    rcx,rax
   140007644:	e8 40 08 00 00       	call   140007e89 <__multadd_D2A>
   140007649:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000764d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007650:	83 c0 01             	add    eax,0x1
   140007653:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007656:	e9 71 fc ff ff       	jmp    1400072cc <__gdtoa+0xfd2>
   14000765b:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140007662:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007666:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000766a:	48 89 c1             	mov    rcx,rax
   14000766d:	e8 cc e8 ff ff       	call   140005f3e <__quorem_D2A>
   140007672:	83 c0 30             	add    eax,0x30
   140007675:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007678:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000767c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007680:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007684:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007687:	88 10                	mov    BYTE PTR [rax],dl
   140007689:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000768c:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   14000768f:	7e 29                	jle    1400076ba <__gdtoa+0x13c0>
   140007691:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007695:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000769b:	ba 0a 00 00 00       	mov    edx,0xa
   1400076a0:	48 89 c1             	mov    rcx,rax
   1400076a3:	e8 e1 07 00 00       	call   140007e89 <__multadd_D2A>
   1400076a8:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400076ac:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076af:	83 c0 01             	add    eax,0x1
   1400076b2:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400076b5:	eb ab                	jmp    140007662 <__gdtoa+0x1368>
   1400076b7:	90                   	nop
   1400076b8:	eb 01                	jmp    1400076bb <__gdtoa+0x13c1>
   1400076ba:	90                   	nop
   1400076bb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400076bf:	74 26                	je     1400076e7 <__gdtoa+0x13ed>
   1400076c1:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400076c5:	0f 84 ae 00 00 00    	je     140007779 <__gdtoa+0x147f>
   1400076cb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076cf:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400076d2:	83 f8 01             	cmp    eax,0x1
   1400076d5:	7f 50                	jg     140007727 <__gdtoa+0x142d>
   1400076d7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076db:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400076de:	85 c0                	test   eax,eax
   1400076e0:	75 45                	jne    140007727 <__gdtoa+0x142d>
   1400076e2:	e9 92 00 00 00       	jmp    140007779 <__gdtoa+0x147f>
   1400076e7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076eb:	ba 01 00 00 00       	mov    edx,0x1
   1400076f0:	48 89 c1             	mov    rcx,rax
   1400076f3:	e8 e8 0c 00 00       	call   1400083e0 <__lshift_D2A>
   1400076f8:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400076fc:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007700:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007704:	48 89 c1             	mov    rcx,rax
   140007707:	e8 61 0e 00 00       	call   14000856d <__cmp_D2A>
   14000770c:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   14000770f:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007713:	7f 15                	jg     14000772a <__gdtoa+0x1430>
   140007715:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007719:	75 61                	jne    14000777c <__gdtoa+0x1482>
   14000771b:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000771e:	83 e0 01             	and    eax,0x1
   140007721:	85 c0                	test   eax,eax
   140007723:	74 5a                	je     14000777f <__gdtoa+0x1485>
   140007725:	eb 04                	jmp    14000772b <__gdtoa+0x1431>
   140007727:	90                   	nop
   140007728:	eb 01                	jmp    14000772b <__gdtoa+0x1431>
   14000772a:	90                   	nop
   14000772b:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007732:	eb 1f                	jmp    140007753 <__gdtoa+0x1459>
   140007734:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007738:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000773c:	75 15                	jne    140007753 <__gdtoa+0x1459>
   14000773e:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007742:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007746:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000774a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000774e:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007751:	eb 4e                	jmp    1400077a1 <__gdtoa+0x14a7>
   140007753:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140007758:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000775c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000775f:	3c 39                	cmp    al,0x39
   140007761:	74 d1                	je     140007734 <__gdtoa+0x143a>
   140007763:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007767:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000776b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000776f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140007772:	83 c2 01             	add    edx,0x1
   140007775:	88 10                	mov    BYTE PTR [rax],dl
   140007777:	eb 28                	jmp    1400077a1 <__gdtoa+0x14a7>
   140007779:	90                   	nop
   14000777a:	eb 04                	jmp    140007780 <__gdtoa+0x1486>
   14000777c:	90                   	nop
   14000777d:	eb 01                	jmp    140007780 <__gdtoa+0x1486>
   14000777f:	90                   	nop
   140007780:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007784:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007787:	83 f8 01             	cmp    eax,0x1
   14000778a:	7f 0b                	jg     140007797 <__gdtoa+0x149d>
   14000778c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007790:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007793:	85 c0                	test   eax,eax
   140007795:	74 09                	je     1400077a0 <__gdtoa+0x14a6>
   140007797:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000779e:	eb 01                	jmp    1400077a1 <__gdtoa+0x14a7>
   1400077a0:	90                   	nop
   1400077a1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400077a5:	48 89 c1             	mov    rcx,rax
   1400077a8:	e8 51 06 00 00       	call   140007dfe <__Bfree_D2A>
   1400077ad:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   1400077b2:	74 31                	je     1400077e5 <__gdtoa+0x14eb>
   1400077b4:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400077b9:	74 16                	je     1400077d1 <__gdtoa+0x14d7>
   1400077bb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400077bf:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400077c3:	74 0c                	je     1400077d1 <__gdtoa+0x14d7>
   1400077c5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400077c9:	48 89 c1             	mov    rcx,rax
   1400077cc:	e8 2d 06 00 00       	call   140007dfe <__Bfree_D2A>
   1400077d1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400077d5:	48 89 c1             	mov    rcx,rax
   1400077d8:	e8 21 06 00 00       	call   140007dfe <__Bfree_D2A>
   1400077dd:	eb 0e                	jmp    1400077ed <__gdtoa+0x14f3>
   1400077df:	90                   	nop
   1400077e0:	eb 0b                	jmp    1400077ed <__gdtoa+0x14f3>
   1400077e2:	90                   	nop
   1400077e3:	eb 08                	jmp    1400077ed <__gdtoa+0x14f3>
   1400077e5:	90                   	nop
   1400077e6:	eb 05                	jmp    1400077ed <__gdtoa+0x14f3>
   1400077e8:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   1400077ed:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077f1:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   1400077f5:	73 0f                	jae    140007806 <__gdtoa+0x150c>
   1400077f7:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077fb:	48 83 e8 01          	sub    rax,0x1
   1400077ff:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140007802:	3c 30                	cmp    al,0x30
   140007804:	74 e2                	je     1400077e8 <__gdtoa+0x14ee>
   140007806:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000780a:	48 89 c1             	mov    rcx,rax
   14000780d:	e8 ec 05 00 00       	call   140007dfe <__Bfree_D2A>
   140007812:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007816:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140007819:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000781c:	8d 50 01             	lea    edx,[rax+0x1]
   14000781f:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140007826:	89 10                	mov    DWORD PTR [rax],edx
   140007828:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   14000782f:	00 
   140007830:	74 0e                	je     140007840 <__gdtoa+0x1546>
   140007832:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140007839:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   14000783d:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007840:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007847:	8b 00                	mov    eax,DWORD PTR [rax]
   140007849:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   14000784c:	89 c2                	mov    edx,eax
   14000784e:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007855:	89 10                	mov    DWORD PTR [rax],edx
   140007857:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000785b:	48 81 c4 00 01 00 00 	add    rsp,0x100
   140007862:	5d                   	pop    rbp
   140007863:	c3                   	ret
   140007864:	90                   	nop
   140007865:	90                   	nop
   140007866:	90                   	nop
   140007867:	90                   	nop
   140007868:	90                   	nop
   140007869:	90                   	nop
   14000786a:	90                   	nop
   14000786b:	90                   	nop
   14000786c:	90                   	nop
   14000786d:	90                   	nop
   14000786e:	90                   	nop
   14000786f:	90                   	nop

0000000140007870 <__lo0bits_D2A>:
   140007870:	55                   	push   rbp
   140007871:	48 89 e5             	mov    rbp,rsp
   140007874:	48 83 ec 10          	sub    rsp,0x10
   140007878:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000787c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007880:	8b 00                	mov    eax,DWORD PTR [rax]
   140007882:	f3 0f bc c0          	tzcnt  eax,eax
   140007886:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007889:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000788d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000788f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007892:	89 c1                	mov    ecx,eax
   140007894:	d3 ea                	shr    edx,cl
   140007896:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000789a:	89 10                	mov    DWORD PTR [rax],edx
   14000789c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000789f:	48 83 c4 10          	add    rsp,0x10
   1400078a3:	5d                   	pop    rbp
   1400078a4:	c3                   	ret

00000001400078a5 <__rshift_D2A>:
   1400078a5:	55                   	push   rbp
   1400078a6:	48 89 e5             	mov    rbp,rsp
   1400078a9:	48 83 ec 20          	sub    rsp,0x20
   1400078ad:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400078b1:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400078b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078b8:	48 83 c0 18          	add    rax,0x18
   1400078bc:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400078c0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400078c4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400078c8:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400078cb:	c1 f8 05             	sar    eax,0x5
   1400078ce:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400078d1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078d5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400078d8:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   1400078db:	0f 8d e4 00 00 00    	jge    1400079c5 <__rshift_D2A+0x120>
   1400078e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078e5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400078e8:	48 98                	cdqe
   1400078ea:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400078f1:	00 
   1400078f2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078f6:	48 01 d0             	add    rax,rdx
   1400078f9:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400078fd:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007900:	48 98                	cdqe
   140007902:	48 c1 e0 02          	shl    rax,0x2
   140007906:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   14000790a:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000790e:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140007912:	0f 84 a3 00 00 00    	je     1400079bb <__rshift_D2A+0x116>
   140007918:	b8 20 00 00 00       	mov    eax,0x20
   14000791d:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   140007920:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007923:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007927:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000792b:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000792f:	8b 10                	mov    edx,DWORD PTR [rax]
   140007931:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007934:	89 c1                	mov    ecx,eax
   140007936:	d3 ea                	shr    edx,cl
   140007938:	89 d0                	mov    eax,edx
   14000793a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000793d:	eb 3c                	jmp    14000797b <__rshift_D2A+0xd6>
   14000793f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007943:	8b 10                	mov    edx,DWORD PTR [rax]
   140007945:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007948:	89 c1                	mov    ecx,eax
   14000794a:	d3 e2                	shl    edx,cl
   14000794c:	89 d1                	mov    ecx,edx
   14000794e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007952:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007956:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000795a:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   14000795d:	89 ca                	mov    edx,ecx
   14000795f:	89 10                	mov    DWORD PTR [rax],edx
   140007961:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007965:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007969:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000796d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000796f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007972:	89 c1                	mov    ecx,eax
   140007974:	d3 ea                	shr    edx,cl
   140007976:	89 d0                	mov    eax,edx
   140007978:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000797b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000797f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007983:	72 ba                	jb     14000793f <__rshift_D2A+0x9a>
   140007985:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007989:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   14000798c:	89 10                	mov    DWORD PTR [rax],edx
   14000798e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007992:	8b 00                	mov    eax,DWORD PTR [rax]
   140007994:	85 c0                	test   eax,eax
   140007996:	74 2d                	je     1400079c5 <__rshift_D2A+0x120>
   140007998:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   14000799d:	eb 26                	jmp    1400079c5 <__rshift_D2A+0x120>
   14000799f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400079a3:	48 8d 42 04          	lea    rax,[rdx+0x4]
   1400079a7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400079ab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079af:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400079b3:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   1400079b7:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400079b9:	89 10                	mov    DWORD PTR [rax],edx
   1400079bb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079bf:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   1400079c3:	72 da                	jb     14000799f <__rshift_D2A+0xfa>
   1400079c5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079c9:	48 83 c0 18          	add    rax,0x18
   1400079cd:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400079d1:	48 29 c2             	sub    rdx,rax
   1400079d4:	48 89 d0             	mov    rax,rdx
   1400079d7:	48 c1 f8 02          	sar    rax,0x2
   1400079db:	89 c2                	mov    edx,eax
   1400079dd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079e1:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400079e4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079e8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400079eb:	85 c0                	test   eax,eax
   1400079ed:	75 0b                	jne    1400079fa <__rshift_D2A+0x155>
   1400079ef:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079f3:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   1400079fa:	90                   	nop
   1400079fb:	48 83 c4 20          	add    rsp,0x20
   1400079ff:	5d                   	pop    rbp
   140007a00:	c3                   	ret

0000000140007a01 <__trailz_D2A>:
   140007a01:	55                   	push   rbp
   140007a02:	48 89 e5             	mov    rbp,rsp
   140007a05:	48 83 ec 40          	sub    rsp,0x40
   140007a09:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007a0d:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a14:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a18:	48 83 c0 18          	add    rax,0x18
   140007a1c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a20:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a24:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a27:	48 98                	cdqe
   140007a29:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007a30:	00 
   140007a31:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a35:	48 01 d0             	add    rax,rdx
   140007a38:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007a3c:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a43:	eb 09                	jmp    140007a4e <__trailz_D2A+0x4d>
   140007a45:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   140007a49:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   140007a4e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a52:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a56:	73 0a                	jae    140007a62 <__trailz_D2A+0x61>
   140007a58:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a5c:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a5e:	85 c0                	test   eax,eax
   140007a60:	74 e3                	je     140007a45 <__trailz_D2A+0x44>
   140007a62:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a66:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a6a:	73 18                	jae    140007a84 <__trailz_D2A+0x83>
   140007a6c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a70:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a72:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007a75:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007a79:	48 89 c1             	mov    rcx,rax
   140007a7c:	e8 ef fd ff ff       	call   140007870 <__lo0bits_D2A>
   140007a81:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007a84:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007a87:	48 83 c4 40          	add    rsp,0x40
   140007a8b:	5d                   	pop    rbp
   140007a8c:	c3                   	ret
   140007a8d:	90                   	nop
   140007a8e:	90                   	nop
   140007a8f:	90                   	nop

0000000140007a90 <dtoa_lock_cleanup>:
   140007a90:	55                   	push   rbp
   140007a91:	48 89 e5             	mov    rbp,rsp
   140007a94:	48 83 ec 40          	sub    rsp,0x40
   140007a98:	48 8d 05 51 77 00 00 	lea    rax,[rip+0x7751]        # 14000f1f0 <dtoa_CS_init>
   140007a9f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007aa3:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007aaa:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007aad:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007ab1:	87 10                	xchg   DWORD PTR [rax],edx
   140007ab3:	89 d0                	mov    eax,edx
   140007ab5:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007ab8:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007abc:	75 3d                	jne    140007afb <dtoa_lock_cleanup+0x6b>
   140007abe:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007ac5:	eb 2e                	jmp    140007af5 <dtoa_lock_cleanup+0x65>
   140007ac7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007aca:	48 63 d0             	movsxd rdx,eax
   140007acd:	48 89 d0             	mov    rax,rdx
   140007ad0:	48 c1 e0 02          	shl    rax,0x2
   140007ad4:	48 01 d0             	add    rax,rdx
   140007ad7:	48 c1 e0 03          	shl    rax,0x3
   140007adb:	48 8d 15 be 76 00 00 	lea    rdx,[rip+0x76be]        # 14000f1a0 <dtoa_CritSec>
   140007ae2:	48 01 d0             	add    rax,rdx
   140007ae5:	48 89 c1             	mov    rcx,rax
   140007ae8:	48 8b 05 f1 86 00 00 	mov    rax,QWORD PTR [rip+0x86f1]        # 1400101e0 <__IAT_start__>
   140007aef:	ff d0                	call   rax
   140007af1:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007af5:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007af9:	7e cc                	jle    140007ac7 <dtoa_lock_cleanup+0x37>
   140007afb:	90                   	nop
   140007afc:	48 83 c4 40          	add    rsp,0x40
   140007b00:	5d                   	pop    rbp
   140007b01:	c3                   	ret

0000000140007b02 <dtoa_lock>:
   140007b02:	55                   	push   rbp
   140007b03:	48 89 e5             	mov    rbp,rsp
   140007b06:	48 83 ec 40          	sub    rsp,0x40
   140007b0a:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007b0d:	8b 05 dd 76 00 00    	mov    eax,DWORD PTR [rip+0x76dd]        # 14000f1f0 <dtoa_CS_init>
   140007b13:	83 f8 02             	cmp    eax,0x2
   140007b16:	75 2c                	jne    140007b44 <dtoa_lock+0x42>
   140007b18:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007b1b:	48 89 d0             	mov    rax,rdx
   140007b1e:	48 c1 e0 02          	shl    rax,0x2
   140007b22:	48 01 d0             	add    rax,rdx
   140007b25:	48 c1 e0 03          	shl    rax,0x3
   140007b29:	48 8d 15 70 76 00 00 	lea    rdx,[rip+0x7670]        # 14000f1a0 <dtoa_CritSec>
   140007b30:	48 01 d0             	add    rax,rdx
   140007b33:	48 89 c1             	mov    rcx,rax
   140007b36:	48 8b 05 ab 86 00 00 	mov    rax,QWORD PTR [rip+0x86ab]        # 1400101e8 <__imp_EnterCriticalSection>
   140007b3d:	ff d0                	call   rax
   140007b3f:	e9 ea 00 00 00       	jmp    140007c2e <dtoa_lock+0x12c>
   140007b44:	8b 05 a6 76 00 00    	mov    eax,DWORD PTR [rip+0x76a6]        # 14000f1f0 <dtoa_CS_init>
   140007b4a:	85 c0                	test   eax,eax
   140007b4c:	0f 85 9e 00 00 00    	jne    140007bf0 <dtoa_lock+0xee>
   140007b52:	48 8d 05 97 76 00 00 	lea    rax,[rip+0x7697]        # 14000f1f0 <dtoa_CS_init>
   140007b59:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007b5d:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007b64:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007b67:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007b6b:	87 10                	xchg   DWORD PTR [rax],edx
   140007b6d:	89 d0                	mov    eax,edx
   140007b6f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007b72:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007b76:	75 58                	jne    140007bd0 <dtoa_lock+0xce>
   140007b78:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007b7f:	eb 2e                	jmp    140007baf <dtoa_lock+0xad>
   140007b81:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007b84:	48 63 d0             	movsxd rdx,eax
   140007b87:	48 89 d0             	mov    rax,rdx
   140007b8a:	48 c1 e0 02          	shl    rax,0x2
   140007b8e:	48 01 d0             	add    rax,rdx
   140007b91:	48 c1 e0 03          	shl    rax,0x3
   140007b95:	48 8d 15 04 76 00 00 	lea    rdx,[rip+0x7604]        # 14000f1a0 <dtoa_CritSec>
   140007b9c:	48 01 d0             	add    rax,rdx
   140007b9f:	48 89 c1             	mov    rcx,rax
   140007ba2:	48 8b 05 6f 86 00 00 	mov    rax,QWORD PTR [rip+0x866f]        # 140010218 <__imp_InitializeCriticalSection>
   140007ba9:	ff d0                	call   rax
   140007bab:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007baf:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007bb3:	7e cc                	jle    140007b81 <dtoa_lock+0x7f>
   140007bb5:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007a90 <dtoa_lock_cleanup>
   140007bbc:	48 89 c1             	mov    rcx,rax
   140007bbf:	e8 6b 9a ff ff       	call   14000162f <atexit>
   140007bc4:	c7 05 22 76 00 00 02 	mov    DWORD PTR [rip+0x7622],0x2        # 14000f1f0 <dtoa_CS_init>
   140007bcb:	00 00 00 
   140007bce:	eb 20                	jmp    140007bf0 <dtoa_lock+0xee>
   140007bd0:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007bd4:	75 1a                	jne    140007bf0 <dtoa_lock+0xee>
   140007bd6:	c7 05 10 76 00 00 02 	mov    DWORD PTR [rip+0x7610],0x2        # 14000f1f0 <dtoa_CS_init>
   140007bdd:	00 00 00 
   140007be0:	eb 0e                	jmp    140007bf0 <dtoa_lock+0xee>
   140007be2:	b9 01 00 00 00       	mov    ecx,0x1
   140007be7:	48 8b 05 52 86 00 00 	mov    rax,QWORD PTR [rip+0x8652]        # 140010240 <__imp_Sleep>
   140007bee:	ff d0                	call   rax
   140007bf0:	8b 05 fa 75 00 00    	mov    eax,DWORD PTR [rip+0x75fa]        # 14000f1f0 <dtoa_CS_init>
   140007bf6:	83 f8 01             	cmp    eax,0x1
   140007bf9:	74 e7                	je     140007be2 <dtoa_lock+0xe0>
   140007bfb:	8b 05 ef 75 00 00    	mov    eax,DWORD PTR [rip+0x75ef]        # 14000f1f0 <dtoa_CS_init>
   140007c01:	83 f8 02             	cmp    eax,0x2
   140007c04:	75 28                	jne    140007c2e <dtoa_lock+0x12c>
   140007c06:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c09:	48 89 d0             	mov    rax,rdx
   140007c0c:	48 c1 e0 02          	shl    rax,0x2
   140007c10:	48 01 d0             	add    rax,rdx
   140007c13:	48 c1 e0 03          	shl    rax,0x3
   140007c17:	48 8d 15 82 75 00 00 	lea    rdx,[rip+0x7582]        # 14000f1a0 <dtoa_CritSec>
   140007c1e:	48 01 d0             	add    rax,rdx
   140007c21:	48 89 c1             	mov    rcx,rax
   140007c24:	48 8b 05 bd 85 00 00 	mov    rax,QWORD PTR [rip+0x85bd]        # 1400101e8 <__imp_EnterCriticalSection>
   140007c2b:	ff d0                	call   rax
   140007c2d:	90                   	nop
   140007c2e:	48 83 c4 40          	add    rsp,0x40
   140007c32:	5d                   	pop    rbp
   140007c33:	c3                   	ret

0000000140007c34 <dtoa_unlock>:
   140007c34:	55                   	push   rbp
   140007c35:	48 89 e5             	mov    rbp,rsp
   140007c38:	48 83 ec 20          	sub    rsp,0x20
   140007c3c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c3f:	8b 05 ab 75 00 00    	mov    eax,DWORD PTR [rip+0x75ab]        # 14000f1f0 <dtoa_CS_init>
   140007c45:	83 f8 02             	cmp    eax,0x2
   140007c48:	75 27                	jne    140007c71 <dtoa_unlock+0x3d>
   140007c4a:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c4d:	48 89 d0             	mov    rax,rdx
   140007c50:	48 c1 e0 02          	shl    rax,0x2
   140007c54:	48 01 d0             	add    rax,rdx
   140007c57:	48 c1 e0 03          	shl    rax,0x3
   140007c5b:	48 8d 15 3e 75 00 00 	lea    rdx,[rip+0x753e]        # 14000f1a0 <dtoa_CritSec>
   140007c62:	48 01 d0             	add    rax,rdx
   140007c65:	48 89 c1             	mov    rcx,rax
   140007c68:	48 8b 05 b1 85 00 00 	mov    rax,QWORD PTR [rip+0x85b1]        # 140010220 <__imp_LeaveCriticalSection>
   140007c6f:	ff d0                	call   rax
   140007c71:	90                   	nop
   140007c72:	48 83 c4 20          	add    rsp,0x20
   140007c76:	5d                   	pop    rbp
   140007c77:	c3                   	ret

0000000140007c78 <__lo0bits_D2A>:
   140007c78:	55                   	push   rbp
   140007c79:	48 89 e5             	mov    rbp,rsp
   140007c7c:	48 83 ec 10          	sub    rsp,0x10
   140007c80:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007c84:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c88:	8b 00                	mov    eax,DWORD PTR [rax]
   140007c8a:	f3 0f bc c0          	tzcnt  eax,eax
   140007c8e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007c91:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c95:	8b 10                	mov    edx,DWORD PTR [rax]
   140007c97:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c9a:	89 c1                	mov    ecx,eax
   140007c9c:	d3 ea                	shr    edx,cl
   140007c9e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ca2:	89 10                	mov    DWORD PTR [rax],edx
   140007ca4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007ca7:	48 83 c4 10          	add    rsp,0x10
   140007cab:	5d                   	pop    rbp
   140007cac:	c3                   	ret

0000000140007cad <__hi0bits_D2A>:
   140007cad:	55                   	push   rbp
   140007cae:	48 89 e5             	mov    rbp,rsp
   140007cb1:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007cb4:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007cb8:	83 f0 1f             	xor    eax,0x1f
   140007cbb:	5d                   	pop    rbp
   140007cbc:	c3                   	ret

0000000140007cbd <__Balloc_D2A>:
   140007cbd:	55                   	push   rbp
   140007cbe:	48 89 e5             	mov    rbp,rsp
   140007cc1:	48 83 ec 30          	sub    rsp,0x30
   140007cc5:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007cc8:	b9 00 00 00 00       	mov    ecx,0x0
   140007ccd:	e8 30 fe ff ff       	call   140007b02 <dtoa_lock>
   140007cd2:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007cd6:	7f 48                	jg     140007d20 <__Balloc_D2A+0x63>
   140007cd8:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007cdb:	48 98                	cdqe
   140007cdd:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007ce4:	00 
   140007ce5:	48 8d 05 14 75 00 00 	lea    rax,[rip+0x7514]        # 14000f200 <freelist>
   140007cec:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007cf0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007cf4:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007cf9:	74 25                	je     140007d20 <__Balloc_D2A+0x63>
   140007cfb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007cff:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007d02:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d05:	48 63 d2             	movsxd rdx,edx
   140007d08:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007d0f:	00 
   140007d10:	48 8d 15 e9 74 00 00 	lea    rdx,[rip+0x74e9]        # 14000f200 <freelist>
   140007d17:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007d1b:	e9 b1 00 00 00       	jmp    140007dd1 <__Balloc_D2A+0x114>
   140007d20:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d23:	ba 01 00 00 00       	mov    edx,0x1
   140007d28:	89 c1                	mov    ecx,eax
   140007d2a:	d3 e2                	shl    edx,cl
   140007d2c:	89 d0                	mov    eax,edx
   140007d2e:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007d31:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007d34:	83 e8 01             	sub    eax,0x1
   140007d37:	48 98                	cdqe
   140007d39:	48 c1 e0 02          	shl    rax,0x2
   140007d3d:	48 83 c0 27          	add    rax,0x27
   140007d41:	48 c1 e8 03          	shr    rax,0x3
   140007d45:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007d48:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d4c:	7f 4e                	jg     140007d9c <__Balloc_D2A+0xdf>
   140007d4e:	48 8b 15 3b 23 00 00 	mov    rdx,QWORD PTR [rip+0x233b]        # 14000a090 <pmem_next>
   140007d55:	48 8d 05 04 75 00 00 	lea    rax,[rip+0x7504]        # 14000f260 <private_mem>
   140007d5c:	48 29 c2             	sub    rdx,rax
   140007d5f:	48 89 d0             	mov    rax,rdx
   140007d62:	48 c1 f8 03          	sar    rax,0x3
   140007d66:	48 89 c2             	mov    rdx,rax
   140007d69:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d6c:	48 01 d0             	add    rax,rdx
   140007d6f:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007d75:	77 25                	ja     140007d9c <__Balloc_D2A+0xdf>
   140007d77:	48 8b 05 12 23 00 00 	mov    rax,QWORD PTR [rip+0x2312]        # 14000a090 <pmem_next>
   140007d7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d82:	48 8b 05 07 23 00 00 	mov    rax,QWORD PTR [rip+0x2307]        # 14000a090 <pmem_next>
   140007d89:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007d8c:	48 c1 e2 03          	shl    rdx,0x3
   140007d90:	48 01 d0             	add    rax,rdx
   140007d93:	48 89 05 f6 22 00 00 	mov    QWORD PTR [rip+0x22f6],rax        # 14000a090 <pmem_next>
   140007d9a:	eb 21                	jmp    140007dbd <__Balloc_D2A+0x100>
   140007d9c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d9f:	48 c1 e0 03          	shl    rax,0x3
   140007da3:	48 89 c1             	mov    rcx,rax
   140007da6:	e8 b5 17 00 00       	call   140009560 <malloc>
   140007dab:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007daf:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007db4:	75 07                	jne    140007dbd <__Balloc_D2A+0x100>
   140007db6:	b8 00 00 00 00       	mov    eax,0x0
   140007dbb:	eb 3b                	jmp    140007df8 <__Balloc_D2A+0x13b>
   140007dbd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007dc1:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007dc4:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007dc7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007dcb:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007dce:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007dd1:	b9 00 00 00 00       	mov    ecx,0x0
   140007dd6:	e8 59 fe ff ff       	call   140007c34 <dtoa_unlock>
   140007ddb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ddf:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007de6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007dea:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007ded:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007df1:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007df4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007df8:	48 83 c4 30          	add    rsp,0x30
   140007dfc:	5d                   	pop    rbp
   140007dfd:	c3                   	ret

0000000140007dfe <__Bfree_D2A>:
   140007dfe:	55                   	push   rbp
   140007dff:	48 89 e5             	mov    rbp,rsp
   140007e02:	48 83 ec 20          	sub    rsp,0x20
   140007e06:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e0a:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007e0f:	74 71                	je     140007e82 <__Bfree_D2A+0x84>
   140007e11:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e15:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e18:	83 f8 09             	cmp    eax,0x9
   140007e1b:	7e 0e                	jle    140007e2b <__Bfree_D2A+0x2d>
   140007e1d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e21:	48 89 c1             	mov    rcx,rax
   140007e24:	e8 27 17 00 00       	call   140009550 <free>
   140007e29:	eb 57                	jmp    140007e82 <__Bfree_D2A+0x84>
   140007e2b:	b9 00 00 00 00       	mov    ecx,0x0
   140007e30:	e8 cd fc ff ff       	call   140007b02 <dtoa_lock>
   140007e35:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e39:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e3c:	48 98                	cdqe
   140007e3e:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007e45:	00 
   140007e46:	48 8d 05 b3 73 00 00 	lea    rax,[rip+0x73b3]        # 14000f200 <freelist>
   140007e4d:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007e51:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e55:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007e58:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e5c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e5f:	48 98                	cdqe
   140007e61:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007e68:	00 
   140007e69:	48 8d 15 90 73 00 00 	lea    rdx,[rip+0x7390]        # 14000f200 <freelist>
   140007e70:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e74:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007e78:	b9 00 00 00 00       	mov    ecx,0x0
   140007e7d:	e8 b2 fd ff ff       	call   140007c34 <dtoa_unlock>
   140007e82:	90                   	nop
   140007e83:	48 83 c4 20          	add    rsp,0x20
   140007e87:	5d                   	pop    rbp
   140007e88:	c3                   	ret

0000000140007e89 <__multadd_D2A>:
   140007e89:	55                   	push   rbp
   140007e8a:	48 89 e5             	mov    rbp,rsp
   140007e8d:	48 83 ec 50          	sub    rsp,0x50
   140007e91:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e95:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007e98:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007e9c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ea0:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ea3:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007ea6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eaa:	48 83 c0 18          	add    rax,0x18
   140007eae:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007eb2:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007eb9:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007ebc:	48 98                	cdqe
   140007ebe:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007ec2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007ec6:	8b 00                	mov    eax,DWORD PTR [rax]
   140007ec8:	89 c2                	mov    edx,eax
   140007eca:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007ecd:	48 98                	cdqe
   140007ecf:	48 0f af d0          	imul   rdx,rax
   140007ed3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007ed7:	48 01 d0             	add    rax,rdx
   140007eda:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007ede:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007ee2:	48 c1 e8 20          	shr    rax,0x20
   140007ee6:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007eea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007eee:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007ef2:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007ef6:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007efa:	89 10                	mov    DWORD PTR [rax],edx
   140007efc:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007f00:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007f03:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007f06:	7c ba                	jl     140007ec2 <__multadd_D2A+0x39>
   140007f08:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007f0d:	0f 84 9a 00 00 00    	je     140007fad <__multadd_D2A+0x124>
   140007f13:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f17:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007f1a:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007f1d:	7c 67                	jl     140007f86 <__multadd_D2A+0xfd>
   140007f1f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f23:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007f26:	83 c0 01             	add    eax,0x1
   140007f29:	89 c1                	mov    ecx,eax
   140007f2b:	e8 8d fd ff ff       	call   140007cbd <__Balloc_D2A>
   140007f30:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007f34:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007f39:	75 07                	jne    140007f42 <__multadd_D2A+0xb9>
   140007f3b:	b8 00 00 00 00       	mov    eax,0x0
   140007f40:	eb 6f                	jmp    140007fb1 <__multadd_D2A+0x128>
   140007f42:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f46:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f49:	48 98                	cdqe
   140007f4b:	48 83 c0 02          	add    rax,0x2
   140007f4f:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007f56:	00 
   140007f57:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f5b:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007f5f:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007f63:	48 83 c0 10          	add    rax,0x10
   140007f67:	49 89 c8             	mov    r8,rcx
   140007f6a:	48 89 c1             	mov    rcx,rax
   140007f6d:	e8 f6 15 00 00       	call   140009568 <memcpy>
   140007f72:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f76:	48 89 c1             	mov    rcx,rax
   140007f79:	e8 80 fe ff ff       	call   140007dfe <__Bfree_D2A>
   140007f7e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007f82:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007f86:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007f89:	8d 50 01             	lea    edx,[rax+0x1]
   140007f8c:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007f8f:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140007f93:	89 d1                	mov    ecx,edx
   140007f95:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007f99:	48 98                	cdqe
   140007f9b:	48 83 c0 04          	add    rax,0x4
   140007f9f:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140007fa3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fa7:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140007faa:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007fad:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fb1:	48 83 c4 50          	add    rsp,0x50
   140007fb5:	5d                   	pop    rbp
   140007fb6:	c3                   	ret

0000000140007fb7 <__i2b_D2A>:
   140007fb7:	55                   	push   rbp
   140007fb8:	48 89 e5             	mov    rbp,rsp
   140007fbb:	48 83 ec 30          	sub    rsp,0x30
   140007fbf:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007fc2:	b9 01 00 00 00       	mov    ecx,0x1
   140007fc7:	e8 f1 fc ff ff       	call   140007cbd <__Balloc_D2A>
   140007fcc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007fd0:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007fd5:	75 07                	jne    140007fde <__i2b_D2A+0x27>
   140007fd7:	b8 00 00 00 00       	mov    eax,0x0
   140007fdc:	eb 19                	jmp    140007ff7 <__i2b_D2A+0x40>
   140007fde:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007fe1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007fe5:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140007fe8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007fec:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140007ff3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ff7:	48 83 c4 30          	add    rsp,0x30
   140007ffb:	5d                   	pop    rbp
   140007ffc:	c3                   	ret

0000000140007ffd <__mult_D2A>:
   140007ffd:	55                   	push   rbp
   140007ffe:	48 89 e5             	mov    rbp,rsp
   140008001:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140008008:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000800c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008010:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008014:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008017:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000801b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000801e:	39 c2                	cmp    edx,eax
   140008020:	7d 18                	jge    14000803a <__mult_D2A+0x3d>
   140008022:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008026:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000802a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000802e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008032:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008036:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000803a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000803e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008041:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008044:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008048:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000804b:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   14000804e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008052:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008055:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   140008058:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   14000805b:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   14000805e:	01 d0                	add    eax,edx
   140008060:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008063:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008067:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000806a:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   14000806d:	7e 04                	jle    140008073 <__mult_D2A+0x76>
   14000806f:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008073:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008076:	89 c1                	mov    ecx,eax
   140008078:	e8 40 fc ff ff       	call   140007cbd <__Balloc_D2A>
   14000807d:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008081:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   140008086:	75 0a                	jne    140008092 <__mult_D2A+0x95>
   140008088:	b8 00 00 00 00       	mov    eax,0x0
   14000808d:	e9 88 01 00 00       	jmp    14000821a <__mult_D2A+0x21d>
   140008092:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008096:	48 83 c0 18          	add    rax,0x18
   14000809a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000809e:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400080a1:	48 98                	cdqe
   1400080a3:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400080aa:	00 
   1400080ab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080af:	48 01 d0             	add    rax,rdx
   1400080b2:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400080b6:	eb 0f                	jmp    1400080c7 <__mult_D2A+0xca>
   1400080b8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080bc:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400080c2:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   1400080c7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080cb:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   1400080cf:	72 e7                	jb     1400080b8 <__mult_D2A+0xbb>
   1400080d1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080d5:	48 83 c0 18          	add    rax,0x18
   1400080d9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400080dd:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   1400080e0:	48 98                	cdqe
   1400080e2:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400080e9:	00 
   1400080ea:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400080ee:	48 01 d0             	add    rax,rdx
   1400080f1:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400080f5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080f9:	48 83 c0 18          	add    rax,0x18
   1400080fd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008101:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140008104:	48 98                	cdqe
   140008106:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000810d:	00 
   14000810e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008112:	48 01 d0             	add    rax,rdx
   140008115:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   140008119:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000811d:	48 83 c0 18          	add    rax,0x18
   140008121:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008125:	e9 95 00 00 00       	jmp    1400081bf <__mult_D2A+0x1c2>
   14000812a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000812e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008132:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008136:	8b 00                	mov    eax,DWORD PTR [rax]
   140008138:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   14000813b:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   14000813f:	74 79                	je     1400081ba <__mult_D2A+0x1bd>
   140008141:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140008145:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008149:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000814d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008151:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140008158:	00 
   140008159:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000815d:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008161:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008165:	8b 00                	mov    eax,DWORD PTR [rax]
   140008167:	89 c2                	mov    edx,eax
   140008169:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   14000816c:	48 0f af d0          	imul   rdx,rax
   140008170:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008174:	8b 00                	mov    eax,DWORD PTR [rax]
   140008176:	89 c0                	mov    eax,eax
   140008178:	48 01 c2             	add    rdx,rax
   14000817b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000817f:	48 01 d0             	add    rax,rdx
   140008182:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140008186:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   14000818a:	48 c1 e8 20          	shr    rax,0x20
   14000818e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008192:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008196:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000819a:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000819e:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400081a2:	89 10                	mov    DWORD PTR [rax],edx
   1400081a4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400081a8:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   1400081ac:	72 ab                	jb     140008159 <__mult_D2A+0x15c>
   1400081ae:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400081b2:	89 c2                	mov    edx,eax
   1400081b4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081b8:	89 10                	mov    DWORD PTR [rax],edx
   1400081ba:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   1400081bf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400081c3:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   1400081c7:	0f 82 5d ff ff ff    	jb     14000812a <__mult_D2A+0x12d>
   1400081cd:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081d1:	48 83 c0 18          	add    rax,0x18
   1400081d5:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400081d9:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400081dc:	48 98                	cdqe
   1400081de:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400081e5:	00 
   1400081e6:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400081ea:	48 01 d0             	add    rax,rdx
   1400081ed:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400081f1:	eb 04                	jmp    1400081f7 <__mult_D2A+0x1fa>
   1400081f3:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400081f7:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400081fb:	7e 0f                	jle    14000820c <__mult_D2A+0x20f>
   1400081fd:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008202:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008206:	8b 00                	mov    eax,DWORD PTR [rax]
   140008208:	85 c0                	test   eax,eax
   14000820a:	74 e7                	je     1400081f3 <__mult_D2A+0x1f6>
   14000820c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008210:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008213:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008216:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000821a:	48 81 c4 90 00 00 00 	add    rsp,0x90
   140008221:	5d                   	pop    rbp
   140008222:	c3                   	ret

0000000140008223 <__pow5mult_D2A>:
   140008223:	55                   	push   rbp
   140008224:	48 89 e5             	mov    rbp,rsp
   140008227:	48 83 ec 40          	sub    rsp,0x40
   14000822b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000822f:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140008232:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008235:	83 e0 03             	and    eax,0x3
   140008238:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000823b:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000823f:	74 41                	je     140008282 <__pow5mult_D2A+0x5f>
   140008241:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008244:	83 e8 01             	sub    eax,0x1
   140008247:	48 98                	cdqe
   140008249:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008250:	00 
   140008251:	48 8d 05 40 1e 00 00 	lea    rax,[rip+0x1e40]        # 14000a098 <p05.0>
   140008258:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   14000825b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000825f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140008265:	48 89 c1             	mov    rcx,rax
   140008268:	e8 1c fc ff ff       	call   140007e89 <__multadd_D2A>
   14000826d:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008271:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140008276:	75 0a                	jne    140008282 <__pow5mult_D2A+0x5f>
   140008278:	b8 00 00 00 00       	mov    eax,0x0
   14000827d:	e9 58 01 00 00       	jmp    1400083da <__pow5mult_D2A+0x1b7>
   140008282:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   140008286:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000828a:	75 09                	jne    140008295 <__pow5mult_D2A+0x72>
   14000828c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008290:	e9 45 01 00 00       	jmp    1400083da <__pow5mult_D2A+0x1b7>
   140008295:	48 8b 05 c4 78 00 00 	mov    rax,QWORD PTR [rip+0x78c4]        # 14000fb60 <p5s>
   14000829c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082a0:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400082a5:	75 5e                	jne    140008305 <__pow5mult_D2A+0xe2>
   1400082a7:	b9 01 00 00 00       	mov    ecx,0x1
   1400082ac:	e8 51 f8 ff ff       	call   140007b02 <dtoa_lock>
   1400082b1:	48 8b 05 a8 78 00 00 	mov    rax,QWORD PTR [rip+0x78a8]        # 14000fb60 <p5s>
   1400082b8:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082bc:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400082c1:	75 38                	jne    1400082fb <__pow5mult_D2A+0xd8>
   1400082c3:	b9 71 02 00 00       	mov    ecx,0x271
   1400082c8:	e8 ea fc ff ff       	call   140007fb7 <__i2b_D2A>
   1400082cd:	48 89 05 8c 78 00 00 	mov    QWORD PTR [rip+0x788c],rax        # 14000fb60 <p5s>
   1400082d4:	48 8b 05 85 78 00 00 	mov    rax,QWORD PTR [rip+0x7885]        # 14000fb60 <p5s>
   1400082db:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082df:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400082e4:	75 0a                	jne    1400082f0 <__pow5mult_D2A+0xcd>
   1400082e6:	b8 00 00 00 00       	mov    eax,0x0
   1400082eb:	e9 ea 00 00 00       	jmp    1400083da <__pow5mult_D2A+0x1b7>
   1400082f0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400082f4:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   1400082fb:	b9 01 00 00 00       	mov    ecx,0x1
   140008300:	e8 2f f9 ff ff       	call   140007c34 <dtoa_unlock>
   140008305:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008308:	83 e0 01             	and    eax,0x1
   14000830b:	85 c0                	test   eax,eax
   14000830d:	74 39                	je     140008348 <__pow5mult_D2A+0x125>
   14000830f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008313:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008317:	48 89 c1             	mov    rcx,rax
   14000831a:	e8 de fc ff ff       	call   140007ffd <__mult_D2A>
   14000831f:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008323:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   140008328:	75 0a                	jne    140008334 <__pow5mult_D2A+0x111>
   14000832a:	b8 00 00 00 00       	mov    eax,0x0
   14000832f:	e9 a6 00 00 00       	jmp    1400083da <__pow5mult_D2A+0x1b7>
   140008334:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008338:	48 89 c1             	mov    rcx,rax
   14000833b:	e8 be fa ff ff       	call   140007dfe <__Bfree_D2A>
   140008340:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008344:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008348:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   14000834b:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000834f:	0f 84 80 00 00 00    	je     1400083d5 <__pow5mult_D2A+0x1b2>
   140008355:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008359:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000835c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008360:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008365:	75 61                	jne    1400083c8 <__pow5mult_D2A+0x1a5>
   140008367:	b9 01 00 00 00       	mov    ecx,0x1
   14000836c:	e8 91 f7 ff ff       	call   140007b02 <dtoa_lock>
   140008371:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008375:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008378:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000837c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008381:	75 3b                	jne    1400083be <__pow5mult_D2A+0x19b>
   140008383:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008387:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000838b:	48 89 c1             	mov    rcx,rax
   14000838e:	e8 6a fc ff ff       	call   140007ffd <__mult_D2A>
   140008393:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008397:	48 89 02             	mov    QWORD PTR [rdx],rax
   14000839a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000839e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083a1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083a5:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083aa:	75 07                	jne    1400083b3 <__pow5mult_D2A+0x190>
   1400083ac:	b8 00 00 00 00       	mov    eax,0x0
   1400083b1:	eb 27                	jmp    1400083da <__pow5mult_D2A+0x1b7>
   1400083b3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400083b7:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   1400083be:	b9 01 00 00 00       	mov    ecx,0x1
   1400083c3:	e8 6c f8 ff ff       	call   140007c34 <dtoa_unlock>
   1400083c8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400083cc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400083d0:	e9 30 ff ff ff       	jmp    140008305 <__pow5mult_D2A+0xe2>
   1400083d5:	90                   	nop
   1400083d6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083da:	48 83 c4 40          	add    rsp,0x40
   1400083de:	5d                   	pop    rbp
   1400083df:	c3                   	ret

00000001400083e0 <__lshift_D2A>:
   1400083e0:	55                   	push   rbp
   1400083e1:	48 89 e5             	mov    rbp,rsp
   1400083e4:	48 83 ec 60          	sub    rsp,0x60
   1400083e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400083ec:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400083ef:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400083f2:	c1 f8 05             	sar    eax,0x5
   1400083f5:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   1400083f8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083fc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400083ff:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008402:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008406:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008409:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   14000840c:	01 d0                	add    eax,edx
   14000840e:	83 c0 01             	add    eax,0x1
   140008411:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008414:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008418:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000841b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000841e:	eb 07                	jmp    140008427 <__lshift_D2A+0x47>
   140008420:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140008424:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140008427:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000842a:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   14000842d:	7f f1                	jg     140008420 <__lshift_D2A+0x40>
   14000842f:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008432:	89 c1                	mov    ecx,eax
   140008434:	e8 84 f8 ff ff       	call   140007cbd <__Balloc_D2A>
   140008439:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000843d:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008442:	75 0a                	jne    14000844e <__lshift_D2A+0x6e>
   140008444:	b8 00 00 00 00       	mov    eax,0x0
   140008449:	e9 19 01 00 00       	jmp    140008567 <__lshift_D2A+0x187>
   14000844e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008452:	48 83 c0 18          	add    rax,0x18
   140008456:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000845a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008461:	eb 16                	jmp    140008479 <__lshift_D2A+0x99>
   140008463:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008467:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000846b:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000846f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008475:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008479:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000847c:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   14000847f:	7c e2                	jl     140008463 <__lshift_D2A+0x83>
   140008481:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008485:	48 83 c0 18          	add    rax,0x18
   140008489:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000848d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008491:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008494:	48 98                	cdqe
   140008496:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000849d:	00 
   14000849e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084a2:	48 01 d0             	add    rax,rdx
   1400084a5:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400084a9:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   1400084ad:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400084b1:	74 71                	je     140008524 <__lshift_D2A+0x144>
   1400084b3:	b8 20 00 00 00       	mov    eax,0x20
   1400084b8:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400084bb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400084be:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   1400084c5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084c9:	8b 10                	mov    edx,DWORD PTR [rax]
   1400084cb:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400084ce:	89 c1                	mov    ecx,eax
   1400084d0:	d3 e2                	shl    edx,cl
   1400084d2:	89 d1                	mov    ecx,edx
   1400084d4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084d8:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400084dc:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400084e0:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   1400084e3:	89 ca                	mov    edx,ecx
   1400084e5:	89 10                	mov    DWORD PTR [rax],edx
   1400084e7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084eb:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400084ef:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400084f3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400084f5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400084f8:	89 c1                	mov    ecx,eax
   1400084fa:	d3 ea                	shr    edx,cl
   1400084fc:	89 d0                	mov    eax,edx
   1400084fe:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008501:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008505:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008509:	72 ba                	jb     1400084c5 <__lshift_D2A+0xe5>
   14000850b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000850f:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   140008512:	89 10                	mov    DWORD PTR [rax],edx
   140008514:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008518:	8b 00                	mov    eax,DWORD PTR [rax]
   14000851a:	85 c0                	test   eax,eax
   14000851c:	74 2c                	je     14000854a <__lshift_D2A+0x16a>
   14000851e:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140008522:	eb 26                	jmp    14000854a <__lshift_D2A+0x16a>
   140008524:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008528:	48 8d 42 04          	lea    rax,[rdx+0x4]
   14000852c:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008530:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008534:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140008538:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   14000853c:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000853e:	89 10                	mov    DWORD PTR [rax],edx
   140008540:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008544:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008548:	72 da                	jb     140008524 <__lshift_D2A+0x144>
   14000854a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000854d:	8d 50 ff             	lea    edx,[rax-0x1]
   140008550:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008554:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008557:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000855b:	48 89 c1             	mov    rcx,rax
   14000855e:	e8 9b f8 ff ff       	call   140007dfe <__Bfree_D2A>
   140008563:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008567:	48 83 c4 60          	add    rsp,0x60
   14000856b:	5d                   	pop    rbp
   14000856c:	c3                   	ret

000000014000856d <__cmp_D2A>:
   14000856d:	55                   	push   rbp
   14000856e:	48 89 e5             	mov    rbp,rsp
   140008571:	48 83 ec 30          	sub    rsp,0x30
   140008575:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008579:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000857d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008581:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008584:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140008587:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000858b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000858e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140008591:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008594:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   140008597:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000859b:	74 08                	je     1400085a5 <__cmp_D2A+0x38>
   14000859d:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400085a0:	e9 92 00 00 00       	jmp    140008637 <__cmp_D2A+0xca>
   1400085a5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085a9:	48 83 c0 18          	add    rax,0x18
   1400085ad:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400085b1:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085b4:	48 98                	cdqe
   1400085b6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400085bd:	00 
   1400085be:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400085c2:	48 01 d0             	add    rax,rdx
   1400085c5:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400085c9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400085cd:	48 83 c0 18          	add    rax,0x18
   1400085d1:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400085d5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085d8:	48 98                	cdqe
   1400085da:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400085e1:	00 
   1400085e2:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400085e6:	48 01 d0             	add    rax,rdx
   1400085e9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400085ed:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400085f2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400085f6:	8b 10                	mov    edx,DWORD PTR [rax]
   1400085f8:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   1400085fd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008601:	8b 00                	mov    eax,DWORD PTR [rax]
   140008603:	39 c2                	cmp    edx,eax
   140008605:	74 1e                	je     140008625 <__cmp_D2A+0xb8>
   140008607:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000860b:	8b 10                	mov    edx,DWORD PTR [rax]
   14000860d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008611:	8b 00                	mov    eax,DWORD PTR [rax]
   140008613:	39 c2                	cmp    edx,eax
   140008615:	73 07                	jae    14000861e <__cmp_D2A+0xb1>
   140008617:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000861c:	eb 19                	jmp    140008637 <__cmp_D2A+0xca>
   14000861e:	b8 01 00 00 00       	mov    eax,0x1
   140008623:	eb 12                	jmp    140008637 <__cmp_D2A+0xca>
   140008625:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008629:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000862d:	73 02                	jae    140008631 <__cmp_D2A+0xc4>
   14000862f:	eb bc                	jmp    1400085ed <__cmp_D2A+0x80>
   140008631:	90                   	nop
   140008632:	b8 00 00 00 00       	mov    eax,0x0
   140008637:	48 83 c4 30          	add    rsp,0x30
   14000863b:	5d                   	pop    rbp
   14000863c:	c3                   	ret

000000014000863d <__diff_D2A>:
   14000863d:	55                   	push   rbp
   14000863e:	48 89 e5             	mov    rbp,rsp
   140008641:	48 83 ec 70          	sub    rsp,0x70
   140008645:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008649:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000864d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140008651:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008655:	48 89 c1             	mov    rcx,rax
   140008658:	e8 10 ff ff ff       	call   14000856d <__cmp_D2A>
   14000865d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008660:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008664:	75 3e                	jne    1400086a4 <__diff_D2A+0x67>
   140008666:	b9 00 00 00 00       	mov    ecx,0x0
   14000866b:	e8 4d f6 ff ff       	call   140007cbd <__Balloc_D2A>
   140008670:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008674:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008679:	75 0a                	jne    140008685 <__diff_D2A+0x48>
   14000867b:	b8 00 00 00 00       	mov    eax,0x0
   140008680:	e9 ab 01 00 00       	jmp    140008830 <__diff_D2A+0x1f3>
   140008685:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008689:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008690:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008694:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000869b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000869f:	e9 8c 01 00 00       	jmp    140008830 <__diff_D2A+0x1f3>
   1400086a4:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400086a8:	79 21                	jns    1400086cb <__diff_D2A+0x8e>
   1400086aa:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086ae:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400086b2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086b6:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400086ba:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086be:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400086c2:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400086c9:	eb 07                	jmp    1400086d2 <__diff_D2A+0x95>
   1400086cb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400086d2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086d6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400086d9:	89 c1                	mov    ecx,eax
   1400086db:	e8 dd f5 ff ff       	call   140007cbd <__Balloc_D2A>
   1400086e0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400086e4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400086e9:	75 0a                	jne    1400086f5 <__diff_D2A+0xb8>
   1400086eb:	b8 00 00 00 00       	mov    eax,0x0
   1400086f0:	e9 3b 01 00 00       	jmp    140008830 <__diff_D2A+0x1f3>
   1400086f5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086f9:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400086fc:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400086ff:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008703:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008706:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008709:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000870d:	48 83 c0 18          	add    rax,0x18
   140008711:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008715:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008718:	48 98                	cdqe
   14000871a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008721:	00 
   140008722:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008726:	48 01 d0             	add    rax,rdx
   140008729:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000872d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008731:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008734:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   140008737:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000873b:	48 83 c0 18          	add    rax,0x18
   14000873f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008743:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008746:	48 98                	cdqe
   140008748:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000874f:	00 
   140008750:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008754:	48 01 d0             	add    rax,rdx
   140008757:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000875b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000875f:	48 83 c0 18          	add    rax,0x18
   140008763:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008767:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   14000876e:	00 
   14000876f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008773:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008777:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000877b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000877d:	89 c1                	mov    ecx,eax
   14000877f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008783:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008787:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   14000878b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000878d:	89 c2                	mov    edx,eax
   14000878f:	48 89 c8             	mov    rax,rcx
   140008792:	48 29 d0             	sub    rax,rdx
   140008795:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140008799:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000879d:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400087a1:	48 c1 e8 20          	shr    rax,0x20
   1400087a5:	83 e0 01             	and    eax,0x1
   1400087a8:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400087ac:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087b0:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087b4:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400087b8:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400087bc:	89 10                	mov    DWORD PTR [rax],edx
   1400087be:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087c2:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   1400087c6:	72 a7                	jb     14000876f <__diff_D2A+0x132>
   1400087c8:	eb 39                	jmp    140008803 <__diff_D2A+0x1c6>
   1400087ca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087ce:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087d2:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400087d6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087d8:	89 c0                	mov    eax,eax
   1400087da:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400087de:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400087e2:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400087e6:	48 c1 e8 20          	shr    rax,0x20
   1400087ea:	83 e0 01             	and    eax,0x1
   1400087ed:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400087f1:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087f5:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087f9:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400087fd:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140008801:	89 10                	mov    DWORD PTR [rax],edx
   140008803:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008807:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   14000880b:	72 bd                	jb     1400087ca <__diff_D2A+0x18d>
   14000880d:	eb 04                	jmp    140008813 <__diff_D2A+0x1d6>
   14000880f:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008813:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008818:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000881c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000881e:	85 c0                	test   eax,eax
   140008820:	74 ed                	je     14000880f <__diff_D2A+0x1d2>
   140008822:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008826:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008829:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000882c:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008830:	48 83 c4 70          	add    rsp,0x70
   140008834:	5d                   	pop    rbp
   140008835:	c3                   	ret

0000000140008836 <__b2d_D2A>:
   140008836:	55                   	push   rbp
   140008837:	48 89 e5             	mov    rbp,rsp
   14000883a:	48 83 ec 50          	sub    rsp,0x50
   14000883e:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008842:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008846:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000884a:	48 83 c0 18          	add    rax,0x18
   14000884e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008852:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008856:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008859:	48 98                	cdqe
   14000885b:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008862:	00 
   140008863:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008867:	48 01 d0             	add    rax,rdx
   14000886a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000886e:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008873:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008877:	8b 00                	mov    eax,DWORD PTR [rax]
   140008879:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   14000887c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000887f:	89 c1                	mov    ecx,eax
   140008881:	e8 27 f4 ff ff       	call   140007cad <__hi0bits_D2A>
   140008886:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008889:	b8 20 00 00 00       	mov    eax,0x20
   14000888e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008891:	89 c2                	mov    edx,eax
   140008893:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008897:	89 10                	mov    DWORD PTR [rax],edx
   140008899:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   14000889d:	7f 66                	jg     140008905 <__b2d_D2A+0xcf>
   14000889f:	b8 0b 00 00 00       	mov    eax,0xb
   1400088a4:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088a7:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400088aa:	89 c1                	mov    ecx,eax
   1400088ac:	d3 ea                	shr    edx,cl
   1400088ae:	89 d0                	mov    eax,edx
   1400088b0:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400088b5:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400088b8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088bc:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400088c0:	73 10                	jae    1400088d2 <__b2d_D2A+0x9c>
   1400088c2:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088c7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088cb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088cd:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400088d0:	eb 07                	jmp    1400088d9 <__b2d_D2A+0xa3>
   1400088d2:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400088d9:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400088dc:	83 c0 15             	add    eax,0x15
   1400088df:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400088e2:	89 c1                	mov    ecx,eax
   1400088e4:	d3 e2                	shl    edx,cl
   1400088e6:	41 89 d0             	mov    r8d,edx
   1400088e9:	b8 0b 00 00 00       	mov    eax,0xb
   1400088ee:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088f1:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   1400088f4:	89 c1                	mov    ecx,eax
   1400088f6:	d3 ea                	shr    edx,cl
   1400088f8:	89 d0                	mov    eax,edx
   1400088fa:	44 09 c0             	or     eax,r8d
   1400088fd:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008900:	e9 ac 00 00 00       	jmp    1400089b1 <__b2d_D2A+0x17b>
   140008905:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008909:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000890d:	73 10                	jae    14000891f <__b2d_D2A+0xe9>
   14000890f:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008914:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008918:	8b 00                	mov    eax,DWORD PTR [rax]
   14000891a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000891d:	eb 07                	jmp    140008926 <__b2d_D2A+0xf0>
   14000891f:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   140008926:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   14000892a:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   14000892e:	74 70                	je     1400089a0 <__b2d_D2A+0x16a>
   140008930:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008933:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008936:	89 c1                	mov    ecx,eax
   140008938:	d3 e2                	shl    edx,cl
   14000893a:	41 89 d0             	mov    r8d,edx
   14000893d:	b8 20 00 00 00       	mov    eax,0x20
   140008942:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008945:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008948:	89 c1                	mov    ecx,eax
   14000894a:	d3 ea                	shr    edx,cl
   14000894c:	89 d0                	mov    eax,edx
   14000894e:	44 09 c0             	or     eax,r8d
   140008951:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008956:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008959:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000895d:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008961:	73 10                	jae    140008973 <__b2d_D2A+0x13d>
   140008963:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008968:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000896c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000896e:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140008971:	eb 07                	jmp    14000897a <__b2d_D2A+0x144>
   140008973:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   14000897a:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000897d:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008980:	89 c1                	mov    ecx,eax
   140008982:	d3 e2                	shl    edx,cl
   140008984:	41 89 d0             	mov    r8d,edx
   140008987:	b8 20 00 00 00       	mov    eax,0x20
   14000898c:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   14000898f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008992:	89 c1                	mov    ecx,eax
   140008994:	d3 ea                	shr    edx,cl
   140008996:	89 d0                	mov    eax,edx
   140008998:	44 09 c0             	or     eax,r8d
   14000899b:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000899e:	eb 11                	jmp    1400089b1 <__b2d_D2A+0x17b>
   1400089a0:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400089a3:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400089a8:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089ab:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400089ae:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089b1:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   1400089b6:	48 83 c4 50          	add    rsp,0x50
   1400089ba:	5d                   	pop    rbp
   1400089bb:	c3                   	ret

00000001400089bc <__d2b_D2A>:
   1400089bc:	55                   	push   rbp
   1400089bd:	53                   	push   rbx
   1400089be:	48 83 ec 58          	sub    rsp,0x58
   1400089c2:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400089c7:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   1400089cc:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400089d0:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400089d4:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400089d9:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   1400089de:	b9 01 00 00 00       	mov    ecx,0x1
   1400089e3:	e8 d5 f2 ff ff       	call   140007cbd <__Balloc_D2A>
   1400089e8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400089ec:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400089f1:	75 0a                	jne    1400089fd <__d2b_D2A+0x41>
   1400089f3:	b8 00 00 00 00       	mov    eax,0x0
   1400089f8:	e9 68 01 00 00       	jmp    140008b65 <__d2b_D2A+0x1a9>
   1400089fd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a01:	48 83 c0 18          	add    rax,0x18
   140008a05:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008a09:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a0c:	25 ff ff 0f 00       	and    eax,0xfffff
   140008a11:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a14:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a17:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008a1c:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008a1f:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a22:	c1 e8 14             	shr    eax,0x14
   140008a25:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140008a28:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008a2c:	74 0b                	je     140008a39 <__d2b_D2A+0x7d>
   140008a2e:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   140008a31:	0d 00 00 10 00       	or     eax,0x100000
   140008a36:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a39:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140008a3c:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008a3f:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008a42:	85 c0                	test   eax,eax
   140008a44:	74 7b                	je     140008ac1 <__d2b_D2A+0x105>
   140008a46:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   140008a4a:	48 89 c1             	mov    rcx,rax
   140008a4d:	e8 26 f2 ff ff       	call   140007c78 <__lo0bits_D2A>
   140008a52:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008a55:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008a59:	74 2b                	je     140008a86 <__d2b_D2A+0xca>
   140008a5b:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a5e:	b8 20 00 00 00       	mov    eax,0x20
   140008a63:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008a66:	89 c1                	mov    ecx,eax
   140008a68:	d3 e2                	shl    edx,cl
   140008a6a:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008a6d:	09 c2                	or     edx,eax
   140008a6f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a73:	89 10                	mov    DWORD PTR [rax],edx
   140008a75:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a78:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008a7b:	89 c1                	mov    ecx,eax
   140008a7d:	d3 ea                	shr    edx,cl
   140008a7f:	89 d0                	mov    eax,edx
   140008a81:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a84:	eb 09                	jmp    140008a8f <__d2b_D2A+0xd3>
   140008a86:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008a89:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a8d:	89 10                	mov    DWORD PTR [rax],edx
   140008a8f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a93:	48 83 c0 04          	add    rax,0x4
   140008a97:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a9a:	89 10                	mov    DWORD PTR [rax],edx
   140008a9c:	8b 00                	mov    eax,DWORD PTR [rax]
   140008a9e:	85 c0                	test   eax,eax
   140008aa0:	74 07                	je     140008aa9 <__d2b_D2A+0xed>
   140008aa2:	ba 02 00 00 00       	mov    edx,0x2
   140008aa7:	eb 05                	jmp    140008aae <__d2b_D2A+0xf2>
   140008aa9:	ba 01 00 00 00       	mov    edx,0x1
   140008aae:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ab2:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008ab5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ab9:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008abc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008abf:	eb 31                	jmp    140008af2 <__d2b_D2A+0x136>
   140008ac1:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008ac5:	48 89 c1             	mov    rcx,rax
   140008ac8:	e8 ab f1 ff ff       	call   140007c78 <__lo0bits_D2A>
   140008acd:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008ad0:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008ad3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008ad7:	89 10                	mov    DWORD PTR [rax],edx
   140008ad9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008add:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008ae4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ae8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008aeb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008aee:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008af2:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008af6:	74 26                	je     140008b1e <__d2b_D2A+0x162>
   140008af8:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008afb:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008b01:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b04:	01 c2                	add    edx,eax
   140008b06:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b0a:	89 10                	mov    DWORD PTR [rax],edx
   140008b0c:	b8 35 00 00 00       	mov    eax,0x35
   140008b11:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008b14:	89 c2                	mov    edx,eax
   140008b16:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b1a:	89 10                	mov    DWORD PTR [rax],edx
   140008b1c:	eb 43                	jmp    140008b61 <__d2b_D2A+0x1a5>
   140008b1e:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b21:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008b27:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b2a:	01 c2                	add    edx,eax
   140008b2c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b30:	89 10                	mov    DWORD PTR [rax],edx
   140008b32:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b35:	c1 e0 05             	shl    eax,0x5
   140008b38:	89 c3                	mov    ebx,eax
   140008b3a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b3d:	48 98                	cdqe
   140008b3f:	48 c1 e0 02          	shl    rax,0x2
   140008b43:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008b47:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b4b:	48 01 d0             	add    rax,rdx
   140008b4e:	8b 00                	mov    eax,DWORD PTR [rax]
   140008b50:	89 c1                	mov    ecx,eax
   140008b52:	e8 56 f1 ff ff       	call   140007cad <__hi0bits_D2A>
   140008b57:	29 c3                	sub    ebx,eax
   140008b59:	89 da                	mov    edx,ebx
   140008b5b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b5f:	89 10                	mov    DWORD PTR [rax],edx
   140008b61:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b65:	48 83 c4 58          	add    rsp,0x58
   140008b69:	5b                   	pop    rbx
   140008b6a:	5d                   	pop    rbp
   140008b6b:	c3                   	ret

0000000140008b6c <__strcp_D2A>:
   140008b6c:	55                   	push   rbp
   140008b6d:	48 89 e5             	mov    rbp,rsp
   140008b70:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008b74:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008b78:	eb 05                	jmp    140008b7f <__strcp_D2A+0x13>
   140008b7a:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008b7f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008b83:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008b87:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008b8b:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008b8e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b92:	88 10                	mov    BYTE PTR [rax],dl
   140008b94:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b98:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008b9b:	84 c0                	test   al,al
   140008b9d:	75 db                	jne    140008b7a <__strcp_D2A+0xe>
   140008b9f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ba3:	5d                   	pop    rbp
   140008ba4:	c3                   	ret
   140008ba5:	90                   	nop
   140008ba6:	90                   	nop
   140008ba7:	90                   	nop
   140008ba8:	90                   	nop
   140008ba9:	90                   	nop
   140008baa:	90                   	nop
   140008bab:	90                   	nop
   140008bac:	90                   	nop
   140008bad:	90                   	nop
   140008bae:	90                   	nop
   140008baf:	90                   	nop

0000000140008bb0 <__fpclassify>:
   140008bb0:	55                   	push   rbp
   140008bb1:	48 89 e5             	mov    rbp,rsp
   140008bb4:	48 83 ec 10          	sub    rsp,0x10
   140008bb8:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008bbd:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008bc2:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008bc7:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008bca:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008bcd:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008bd0:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008bd3:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008bd9:	09 d0                	or     eax,edx
   140008bdb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008bde:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008be5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008be8:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008beb:	85 c0                	test   eax,eax
   140008bed:	75 07                	jne    140008bf6 <__fpclassify+0x46>
   140008bef:	b8 00 40 00 00       	mov    eax,0x4000
   140008bf4:	eb 2f                	jmp    140008c25 <__fpclassify+0x75>
   140008bf6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008bfa:	75 07                	jne    140008c03 <__fpclassify+0x53>
   140008bfc:	b8 00 44 00 00       	mov    eax,0x4400
   140008c01:	eb 22                	jmp    140008c25 <__fpclassify+0x75>
   140008c03:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008c0a:	75 14                	jne    140008c20 <__fpclassify+0x70>
   140008c0c:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008c10:	74 07                	je     140008c19 <__fpclassify+0x69>
   140008c12:	b8 00 01 00 00       	mov    eax,0x100
   140008c17:	eb 0c                	jmp    140008c25 <__fpclassify+0x75>
   140008c19:	b8 00 05 00 00       	mov    eax,0x500
   140008c1e:	eb 05                	jmp    140008c25 <__fpclassify+0x75>
   140008c20:	b8 00 04 00 00       	mov    eax,0x400
   140008c25:	48 83 c4 10          	add    rsp,0x10
   140008c29:	5d                   	pop    rbp
   140008c2a:	c3                   	ret
   140008c2b:	90                   	nop
   140008c2c:	90                   	nop
   140008c2d:	90                   	nop
   140008c2e:	90                   	nop
   140008c2f:	90                   	nop

0000000140008c30 <__fpclassifyl>:
   140008c30:	55                   	push   rbp
   140008c31:	53                   	push   rbx
   140008c32:	48 83 ec 38          	sub    rsp,0x38
   140008c36:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008c3b:	48 89 cb             	mov    rbx,rcx
   140008c3e:	db 2b                	fld    TBYTE PTR [rbx]
   140008c40:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008c43:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008c46:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008c49:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008c4d:	98                   	cwde
   140008c4e:	25 ff 7f 00 00       	and    eax,0x7fff
   140008c53:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c56:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c5a:	75 25                	jne    140008c81 <__fpclassifyl+0x51>
   140008c5c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c5f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c62:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c65:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c68:	85 c0                	test   eax,eax
   140008c6a:	75 07                	jne    140008c73 <__fpclassifyl+0x43>
   140008c6c:	b8 00 40 00 00       	mov    eax,0x4000
   140008c71:	eb 3d                	jmp    140008cb0 <__fpclassifyl+0x80>
   140008c73:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c76:	85 c0                	test   eax,eax
   140008c78:	78 31                	js     140008cab <__fpclassifyl+0x7b>
   140008c7a:	b8 00 44 00 00       	mov    eax,0x4400
   140008c7f:	eb 2f                	jmp    140008cb0 <__fpclassifyl+0x80>
   140008c81:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008c88:	75 21                	jne    140008cab <__fpclassifyl+0x7b>
   140008c8a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c8d:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008c92:	89 c2                	mov    edx,eax
   140008c94:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c97:	09 d0                	or     eax,edx
   140008c99:	85 c0                	test   eax,eax
   140008c9b:	75 07                	jne    140008ca4 <__fpclassifyl+0x74>
   140008c9d:	b8 00 05 00 00       	mov    eax,0x500
   140008ca2:	eb 0c                	jmp    140008cb0 <__fpclassifyl+0x80>
   140008ca4:	b8 00 01 00 00       	mov    eax,0x100
   140008ca9:	eb 05                	jmp    140008cb0 <__fpclassifyl+0x80>
   140008cab:	b8 00 04 00 00       	mov    eax,0x400
   140008cb0:	48 83 c4 38          	add    rsp,0x38
   140008cb4:	5b                   	pop    rbx
   140008cb5:	5d                   	pop    rbp
   140008cb6:	c3                   	ret
   140008cb7:	90                   	nop
   140008cb8:	90                   	nop
   140008cb9:	90                   	nop
   140008cba:	90                   	nop
   140008cbb:	90                   	nop
   140008cbc:	90                   	nop
   140008cbd:	90                   	nop
   140008cbe:	90                   	nop
   140008cbf:	90                   	nop

0000000140008cc0 <__isnan>:
   140008cc0:	55                   	push   rbp
   140008cc1:	48 89 e5             	mov    rbp,rsp
   140008cc4:	48 83 ec 10          	sub    rsp,0x10
   140008cc8:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008ccd:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008cd2:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008cd7:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008cda:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cdd:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008ce0:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008ce5:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008ce8:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008ceb:	f7 d8                	neg    eax
   140008ced:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008cf0:	c1 e8 1f             	shr    eax,0x1f
   140008cf3:	89 c2                	mov    edx,eax
   140008cf5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008cf8:	09 d0                	or     eax,edx
   140008cfa:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008cfd:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008d02:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008d05:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d08:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d0b:	c1 f8 1f             	sar    eax,0x1f
   140008d0e:	48 83 c4 10          	add    rsp,0x10
   140008d12:	5d                   	pop    rbp
   140008d13:	c3                   	ret
   140008d14:	90                   	nop
   140008d15:	90                   	nop
   140008d16:	90                   	nop
   140008d17:	90                   	nop
   140008d18:	90                   	nop
   140008d19:	90                   	nop
   140008d1a:	90                   	nop
   140008d1b:	90                   	nop
   140008d1c:	90                   	nop
   140008d1d:	90                   	nop
   140008d1e:	90                   	nop
   140008d1f:	90                   	nop

0000000140008d20 <__isnanl>:
   140008d20:	55                   	push   rbp
   140008d21:	53                   	push   rbx
   140008d22:	48 83 ec 38          	sub    rsp,0x38
   140008d26:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008d2b:	48 89 cb             	mov    rbx,rcx
   140008d2e:	db 2b                	fld    TBYTE PTR [rbx]
   140008d30:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008d33:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008d36:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008d39:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008d3d:	98                   	cwde
   140008d3e:	01 c0                	add    eax,eax
   140008d40:	25 ff ff 00 00       	and    eax,0xffff
   140008d45:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d48:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008d4b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008d4e:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008d54:	09 d0                	or     eax,edx
   140008d56:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d59:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d5c:	f7 d8                	neg    eax
   140008d5e:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008d61:	c1 e8 1f             	shr    eax,0x1f
   140008d64:	89 c2                	mov    edx,eax
   140008d66:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d69:	09 d0                	or     eax,edx
   140008d6b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d6e:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008d73:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008d76:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d79:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d7c:	c1 f8 10             	sar    eax,0x10
   140008d7f:	48 83 c4 38          	add    rsp,0x38
   140008d83:	5b                   	pop    rbx
   140008d84:	5d                   	pop    rbp
   140008d85:	c3                   	ret
   140008d86:	90                   	nop
   140008d87:	90                   	nop
   140008d88:	90                   	nop
   140008d89:	90                   	nop
   140008d8a:	90                   	nop
   140008d8b:	90                   	nop
   140008d8c:	90                   	nop
   140008d8d:	90                   	nop
   140008d8e:	90                   	nop
   140008d8f:	90                   	nop

0000000140008d90 <wcsnlen>:
   140008d90:	55                   	push   rbp
   140008d91:	48 89 e5             	mov    rbp,rsp
   140008d94:	48 83 ec 10          	sub    rsp,0x10
   140008d98:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008d9c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008da0:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008da7:	00 
   140008da8:	eb 0a                	jmp    140008db4 <wcsnlen+0x24>
   140008daa:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008daf:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008db4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008db8:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008dbc:	73 0c                	jae    140008dca <wcsnlen+0x3a>
   140008dbe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008dc2:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008dc5:	66 85 c0             	test   ax,ax
   140008dc8:	75 e0                	jne    140008daa <wcsnlen+0x1a>
   140008dca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dce:	48 83 c4 10          	add    rsp,0x10
   140008dd2:	5d                   	pop    rbp
   140008dd3:	c3                   	ret
   140008dd4:	90                   	nop
   140008dd5:	90                   	nop
   140008dd6:	90                   	nop
   140008dd7:	90                   	nop
   140008dd8:	90                   	nop
   140008dd9:	90                   	nop
   140008dda:	90                   	nop
   140008ddb:	90                   	nop
   140008ddc:	90                   	nop
   140008ddd:	90                   	nop
   140008dde:	90                   	nop
   140008ddf:	90                   	nop

0000000140008de0 <strnlen>:
   140008de0:	55                   	push   rbp
   140008de1:	48 89 e5             	mov    rbp,rsp
   140008de4:	48 83 ec 10          	sub    rsp,0x10
   140008de8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008dec:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008df0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008df4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008df8:	eb 05                	jmp    140008dff <strnlen+0x1f>
   140008dfa:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008dff:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e03:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e07:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e0b:	73 0b                	jae    140008e18 <strnlen+0x38>
   140008e0d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e11:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008e14:	84 c0                	test   al,al
   140008e16:	75 e2                	jne    140008dfa <strnlen+0x1a>
   140008e18:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e1c:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e20:	48 83 c4 10          	add    rsp,0x10
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

0000000140008e30 <_initterm_e>:
   140008e30:	55                   	push   rbp
   140008e31:	48 89 e5             	mov    rbp,rsp
   140008e34:	48 83 ec 30          	sub    rsp,0x30
   140008e38:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e3c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e40:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e44:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e48:	eb 29                	jmp    140008e73 <_initterm_e+0x43>
   140008e4a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e4e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e51:	48 85 c0             	test   rax,rax
   140008e54:	74 17                	je     140008e6d <_initterm_e+0x3d>
   140008e56:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e5a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e5d:	ff d0                	call   rax
   140008e5f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008e62:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008e66:	74 06                	je     140008e6e <_initterm_e+0x3e>
   140008e68:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008e6b:	eb 15                	jmp    140008e82 <_initterm_e+0x52>
   140008e6d:	90                   	nop
   140008e6e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008e73:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e77:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e7b:	72 cd                	jb     140008e4a <_initterm_e+0x1a>
   140008e7d:	b8 00 00 00 00       	mov    eax,0x0
   140008e82:	48 83 c4 30          	add    rsp,0x30
   140008e86:	5d                   	pop    rbp
   140008e87:	c3                   	ret
   140008e88:	90                   	nop
   140008e89:	90                   	nop
   140008e8a:	90                   	nop
   140008e8b:	90                   	nop
   140008e8c:	90                   	nop
   140008e8d:	90                   	nop
   140008e8e:	90                   	nop
   140008e8f:	90                   	nop

0000000140008e90 <__p__fmode>:
   140008e90:	55                   	push   rbp
   140008e91:	48 89 e5             	mov    rbp,rsp
   140008e94:	48 8b 05 65 27 00 00 	mov    rax,QWORD PTR [rip+0x2765]        # 14000b600 <.refptr.__imp__fmode>
   140008e9b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e9e:	5d                   	pop    rbp
   140008e9f:	c3                   	ret

0000000140008ea0 <__p__commode>:
   140008ea0:	55                   	push   rbp
   140008ea1:	48 89 e5             	mov    rbp,rsp
   140008ea4:	48 8b 05 45 27 00 00 	mov    rax,QWORD PTR [rip+0x2745]        # 14000b5f0 <.refptr.__imp__commode>
   140008eab:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008eae:	5d                   	pop    rbp
   140008eaf:	c3                   	ret

0000000140008eb0 <__p___initenv>:
   140008eb0:	55                   	push   rbp
   140008eb1:	48 89 e5             	mov    rbp,rsp
   140008eb4:	48 8b 05 25 27 00 00 	mov    rax,QWORD PTR [rip+0x2725]        # 14000b5e0 <.refptr.__imp___initenv>
   140008ebb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ebe:	5d                   	pop    rbp
   140008ebf:	c3                   	ret

0000000140008ec0 <_set_invalid_parameter_handler>:
   140008ec0:	55                   	push   rbp
   140008ec1:	48 89 e5             	mov    rbp,rsp
   140008ec4:	48 83 ec 10          	sub    rsp,0x10
   140008ec8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008ecc:	48 8d 05 ad 6c 00 00 	lea    rax,[rip+0x6cad]        # 14000fb80 <handler>
   140008ed3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008ed7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008edb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008edf:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140008ee3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008ee7:	48 87 10             	xchg   QWORD PTR [rax],rdx
   140008eea:	48 89 d0             	mov    rax,rdx
   140008eed:	48 83 c4 10          	add    rsp,0x10
   140008ef1:	5d                   	pop    rbp
   140008ef2:	c3                   	ret

0000000140008ef3 <_get_invalid_parameter_handler>:
   140008ef3:	55                   	push   rbp
   140008ef4:	48 89 e5             	mov    rbp,rsp
   140008ef7:	48 8b 05 82 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c82]        # 14000fb80 <handler>
   140008efe:	5d                   	pop    rbp
   140008eff:	c3                   	ret

0000000140008f00 <_configthreadlocale>:
   140008f00:	55                   	push   rbp
   140008f01:	48 89 e5             	mov    rbp,rsp
   140008f04:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008f07:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   140008f0b:	75 07                	jne    140008f14 <_configthreadlocale+0x14>
   140008f0d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140008f12:	eb 05                	jmp    140008f19 <_configthreadlocale+0x19>
   140008f14:	b8 02 00 00 00       	mov    eax,0x2
   140008f19:	5d                   	pop    rbp
   140008f1a:	c3                   	ret
   140008f1b:	90                   	nop
   140008f1c:	90                   	nop
   140008f1d:	90                   	nop
   140008f1e:	90                   	nop
   140008f1f:	90                   	nop

0000000140008f20 <__acrt_iob_func>:
   140008f20:	55                   	push   rbp
   140008f21:	48 89 e5             	mov    rbp,rsp
   140008f24:	48 83 ec 20          	sub    rsp,0x20
   140008f28:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008f2b:	e8 b0 05 00 00       	call   1400094e0 <__iob_func>
   140008f30:	48 89 c1             	mov    rcx,rax
   140008f33:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008f36:	48 89 d0             	mov    rax,rdx
   140008f39:	48 01 c0             	add    rax,rax
   140008f3c:	48 01 d0             	add    rax,rdx
   140008f3f:	48 c1 e0 04          	shl    rax,0x4
   140008f43:	48 01 c8             	add    rax,rcx
   140008f46:	48 83 c4 20          	add    rsp,0x20
   140008f4a:	5d                   	pop    rbp
   140008f4b:	c3                   	ret
   140008f4c:	90                   	nop
   140008f4d:	90                   	nop
   140008f4e:	90                   	nop
   140008f4f:	90                   	nop

0000000140008f50 <wcrtomb>:
   140008f50:	55                   	push   rbp
   140008f51:	48 89 e5             	mov    rbp,rsp
   140008f54:	48 83 ec 40          	sub    rsp,0x40
   140008f58:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f5c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140008f60:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140008f64:	e8 5f 05 00 00       	call   1400094c8 <___lc_codepage_func>
   140008f69:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008f6c:	e8 5f 05 00 00       	call   1400094d0 <___mb_cur_max_func>
   140008f71:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008f74:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   140008f78:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140008f7c:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   140008f80:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f84:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140008f87:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   140008f8b:	48 89 c1             	mov    rcx,rax
   140008f8e:	e8 7d 00 00 00       	call   140009010 <__mingw_wcrtomb_cp>
   140008f93:	48 83 c4 40          	add    rsp,0x40
   140008f97:	5d                   	pop    rbp
   140008f98:	c3                   	ret
   140008f99:	90                   	nop
   140008f9a:	90                   	nop
   140008f9b:	90                   	nop
   140008f9c:	90                   	nop
   140008f9d:	90                   	nop
   140008f9e:	90                   	nop
   140008f9f:	90                   	nop

0000000140008fa0 <mbrtowc>:
   140008fa0:	55                   	push   rbp
   140008fa1:	48 89 e5             	mov    rbp,rsp
   140008fa4:	48 83 ec 40          	sub    rsp,0x40
   140008fa8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008fac:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008fb0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140008fb4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140008fb8:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   140008fbd:	75 0b                	jne    140008fca <mbrtowc+0x2a>
   140008fbf:	48 8d 05 ca 6b 00 00 	lea    rax,[rip+0x6bca]        # 14000fb90 <state_mbrtowc.0>
   140008fc6:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140008fca:	e8 f9 04 00 00       	call   1400094c8 <___lc_codepage_func>
   140008fcf:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008fd2:	e8 f9 04 00 00       	call   1400094d0 <___mb_cur_max_func>
   140008fd7:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008fda:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   140008fde:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140008fe2:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140008fe6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fea:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140008fed:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   140008ff1:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   140008ff4:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   140008ff8:	48 89 c1             	mov    rcx,rax
   140008ffb:	e8 70 01 00 00       	call   140009170 <__mingw_mbrtowc_cp>
   140009000:	48 83 c4 40          	add    rsp,0x40
   140009004:	5d                   	pop    rbp
   140009005:	c3                   	ret
   140009006:	90                   	nop
   140009007:	90                   	nop
   140009008:	90                   	nop
   140009009:	90                   	nop
   14000900a:	90                   	nop
   14000900b:	90                   	nop
   14000900c:	90                   	nop
   14000900d:	90                   	nop
   14000900e:	90                   	nop
   14000900f:	90                   	nop

0000000140009010 <__mingw_wcrtomb_cp>:
   140009010:	55                   	push   rbp
   140009011:	48 89 e5             	mov    rbp,rsp
   140009014:	48 83 ec 50          	sub    rsp,0x50
   140009018:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000901c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009020:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009024:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   140009028:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000902d:	75 1b                	jne    14000904a <__mingw_wcrtomb_cp+0x3a>
   14000902f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009034:	74 0a                	je     140009040 <__mingw_wcrtomb_cp+0x30>
   140009036:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000903a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009040:	b8 01 00 00 00       	mov    eax,0x1
   140009045:	e9 17 01 00 00       	jmp    140009161 <__mingw_wcrtomb_cp+0x151>
   14000904a:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   14000904f:	74 21                	je     140009072 <__mingw_wcrtomb_cp+0x62>
   140009051:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140009055:	8b 00                	mov    eax,DWORD PTR [rax]
   140009057:	85 c0                	test   eax,eax
   140009059:	74 17                	je     140009072 <__mingw_wcrtomb_cp+0x62>
   14000905b:	e8 a8 04 00 00       	call   140009508 <_errno>
   140009060:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009066:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000906d:	e9 ef 00 00 00       	jmp    140009161 <__mingw_wcrtomb_cp+0x151>
   140009072:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009076:	66 85 c0             	test   ax,ax
   140009079:	75 18                	jne    140009093 <__mingw_wcrtomb_cp+0x83>
   14000907b:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009080:	74 07                	je     140009089 <__mingw_wcrtomb_cp+0x79>
   140009082:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009086:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140009089:	b8 01 00 00 00       	mov    eax,0x1
   14000908e:	e9 ce 00 00 00       	jmp    140009161 <__mingw_wcrtomb_cp+0x151>
   140009093:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   140009097:	75 2b                	jne    1400090c4 <__mingw_wcrtomb_cp+0xb4>
   140009099:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   14000909d:	66 3d ff 00          	cmp    ax,0xff
   1400090a1:	0f 87 a4 00 00 00    	ja     14000914b <__mingw_wcrtomb_cp+0x13b>
   1400090a7:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400090ac:	74 0c                	je     1400090ba <__mingw_wcrtomb_cp+0xaa>
   1400090ae:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   1400090b2:	89 c2                	mov    edx,eax
   1400090b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400090b8:	88 10                	mov    BYTE PTR [rax],dl
   1400090ba:	b8 01 00 00 00       	mov    eax,0x1
   1400090bf:	e9 9d 00 00 00       	jmp    140009161 <__mingw_wcrtomb_cp+0x151>
   1400090c4:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400090cb:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   1400090d1:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   1400090d5:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   1400090d8:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   1400090dc:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   1400090e1:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   1400090e8:	00 00 
   1400090ea:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   1400090ed:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   1400090f1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400090f5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400090fa:	41 b9 01 00 00 00    	mov    r9d,0x1
   140009100:	49 89 c8             	mov    r8,rcx
   140009103:	ba 00 00 00 00       	mov    edx,0x0
   140009108:	89 c1                	mov    ecx,eax
   14000910a:	48 8b 05 4f 71 00 00 	mov    rax,QWORD PTR [rip+0x714f]        # 140010260 <__imp_WideCharToMultiByte>
   140009111:	ff d0                	call   rax
   140009113:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009116:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000911a:	74 32                	je     14000914e <__mingw_wcrtomb_cp+0x13e>
   14000911c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000911f:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   140009122:	7f 2a                	jg     14000914e <__mingw_wcrtomb_cp+0x13e>
   140009124:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009127:	85 c0                	test   eax,eax
   140009129:	75 23                	jne    14000914e <__mingw_wcrtomb_cp+0x13e>
   14000912b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000912e:	48 63 c8             	movsxd rcx,eax
   140009131:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009135:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009139:	49 89 c8             	mov    r8,rcx
   14000913c:	48 89 c1             	mov    rcx,rax
   14000913f:	e8 24 04 00 00       	call   140009568 <memcpy>
   140009144:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009147:	48 98                	cdqe
   140009149:	eb 16                	jmp    140009161 <__mingw_wcrtomb_cp+0x151>
   14000914b:	90                   	nop
   14000914c:	eb 01                	jmp    14000914f <__mingw_wcrtomb_cp+0x13f>
   14000914e:	90                   	nop
   14000914f:	e8 b4 03 00 00       	call   140009508 <_errno>
   140009154:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000915a:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009161:	48 83 c4 50          	add    rsp,0x50
   140009165:	5d                   	pop    rbp
   140009166:	c3                   	ret
   140009167:	90                   	nop
   140009168:	90                   	nop
   140009169:	90                   	nop
   14000916a:	90                   	nop
   14000916b:	90                   	nop
   14000916c:	90                   	nop
   14000916d:	90                   	nop
   14000916e:	90                   	nop
   14000916f:	90                   	nop

0000000140009170 <__mingw_mbrtowc_cp>:
   140009170:	55                   	push   rbp
   140009171:	48 89 e5             	mov    rbp,rsp
   140009174:	48 83 ec 50          	sub    rsp,0x50
   140009178:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000917c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009180:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009184:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009188:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   14000918d:	75 1b                	jne    1400091aa <__mingw_mbrtowc_cp+0x3a>
   14000918f:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   140009196:	00 
   140009197:	48 8d 05 82 23 00 00 	lea    rax,[rip+0x2382]        # 14000b520 <.rdata>
   14000919e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400091a2:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   1400091a9:	00 
   1400091aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400091ae:	8b 00                	mov    eax,DWORD PTR [rax]
   1400091b0:	3d ff 00 00 00       	cmp    eax,0xff
   1400091b5:	0f 87 b9 01 00 00    	ja     140009374 <__mingw_mbrtowc_cp+0x204>
   1400091bb:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400091c0:	75 0c                	jne    1400091ce <__mingw_mbrtowc_cp+0x5e>
   1400091c2:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   1400091c9:	e9 bc 01 00 00       	jmp    14000938a <__mingw_mbrtowc_cp+0x21a>
   1400091ce:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400091d2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400091d4:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400091d7:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   1400091db:	75 0c                	jne    1400091e9 <__mingw_mbrtowc_cp+0x79>
   1400091dd:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400091e1:	84 c0                	test   al,al
   1400091e3:	0f 85 8e 01 00 00    	jne    140009377 <__mingw_mbrtowc_cp+0x207>
   1400091e9:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   1400091ed:	75 2c                	jne    14000921b <__mingw_mbrtowc_cp+0xab>
   1400091ef:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091f4:	74 11                	je     140009207 <__mingw_mbrtowc_cp+0x97>
   1400091f6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400091fa:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400091fd:	0f b6 d0             	movzx  edx,al
   140009200:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009204:	66 89 10             	mov    WORD PTR [rax],dx
   140009207:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000920b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000920e:	84 c0                	test   al,al
   140009210:	0f 95 c0             	setne  al
   140009213:	0f b6 c0             	movzx  eax,al
   140009216:	e9 6f 01 00 00       	jmp    14000938a <__mingw_mbrtowc_cp+0x21a>
   14000921b:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140009222:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140009229:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   14000922d:	84 c0                	test   al,al
   14000922f:	74 1a                	je     14000924b <__mingw_mbrtowc_cp+0xdb>
   140009231:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009235:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009238:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000923b:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140009242:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140009249:	eb 73                	jmp    1400092be <__mingw_mbrtowc_cp+0x14e>
   14000924b:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   14000924f:	75 5c                	jne    1400092ad <__mingw_mbrtowc_cp+0x13d>
   140009251:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009255:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009258:	0f b6 c0             	movzx  eax,al
   14000925b:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000925e:	89 c1                	mov    ecx,eax
   140009260:	e8 ab 01 00 00       	call   140009410 <__mingw_isleadbyte_cp>
   140009265:	85 c0                	test   eax,eax
   140009267:	74 44                	je     1400092ad <__mingw_mbrtowc_cp+0x13d>
   140009269:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000926d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009270:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009273:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   140009278:	77 15                	ja     14000928f <__mingw_mbrtowc_cp+0x11f>
   14000927a:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000927d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009281:	89 10                	mov    DWORD PTR [rax],edx
   140009283:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   14000928a:	e9 fb 00 00 00       	jmp    14000938a <__mingw_mbrtowc_cp+0x21a>
   14000928f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009293:	48 83 c0 01          	add    rax,0x1
   140009297:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000929a:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000929d:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400092a4:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400092ab:	eb 11                	jmp    1400092be <__mingw_mbrtowc_cp+0x14e>
   1400092ad:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400092b1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400092b4:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   1400092b7:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400092be:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400092c2:	84 c0                	test   al,al
   1400092c4:	75 24                	jne    1400092ea <__mingw_mbrtowc_cp+0x17a>
   1400092c6:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400092cb:	74 09                	je     1400092d6 <__mingw_mbrtowc_cp+0x166>
   1400092cd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400092d1:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   1400092d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400092da:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400092e0:	b8 00 00 00 00       	mov    eax,0x0
   1400092e5:	e9 a0 00 00 00       	jmp    14000938a <__mingw_mbrtowc_cp+0x21a>
   1400092ea:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   1400092ee:	75 08                	jne    1400092f8 <__mingw_mbrtowc_cp+0x188>
   1400092f0:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   1400092f4:	84 c0                	test   al,al
   1400092f6:	74 64                	je     14000935c <__mingw_mbrtowc_cp+0x1ec>
   1400092f8:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   1400092fe:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   140009302:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   140009306:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   140009309:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   140009310:	00 
   140009311:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   140009315:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000931a:	45 89 c1             	mov    r9d,r8d
   14000931d:	49 89 c8             	mov    r8,rcx
   140009320:	ba 08 00 00 00       	mov    edx,0x8
   140009325:	89 c1                	mov    ecx,eax
   140009327:	48 8b 05 02 6f 00 00 	mov    rax,QWORD PTR [rip+0x6f02]        # 140010230 <__imp_MultiByteToWideChar>
   14000932e:	ff d0                	call   rax
   140009330:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140009333:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   140009337:	75 26                	jne    14000935f <__mingw_mbrtowc_cp+0x1ef>
   140009339:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000933e:	74 0b                	je     14000934b <__mingw_mbrtowc_cp+0x1db>
   140009340:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   140009344:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009348:	66 89 10             	mov    WORD PTR [rax],dx
   14000934b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000934f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009355:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009358:	48 98                	cdqe
   14000935a:	eb 2e                	jmp    14000938a <__mingw_mbrtowc_cp+0x21a>
   14000935c:	90                   	nop
   14000935d:	eb 01                	jmp    140009360 <__mingw_mbrtowc_cp+0x1f0>
   14000935f:	90                   	nop
   140009360:	e8 a3 01 00 00       	call   140009508 <_errno>
   140009365:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000936b:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009372:	eb 16                	jmp    14000938a <__mingw_mbrtowc_cp+0x21a>
   140009374:	90                   	nop
   140009375:	eb 01                	jmp    140009378 <__mingw_mbrtowc_cp+0x208>
   140009377:	90                   	nop
   140009378:	e8 8b 01 00 00       	call   140009508 <_errno>
   14000937d:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009383:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000938a:	48 83 c4 50          	add    rsp,0x50
   14000938e:	5d                   	pop    rbp
   14000938f:	c3                   	ret

0000000140009390 <fallback_IsDBCSLeadByteEx>:
   140009390:	55                   	push   rbp
   140009391:	48 89 e5             	mov    rbp,rsp
   140009394:	48 83 ec 40          	sub    rsp,0x40
   140009398:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000939b:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   14000939e:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   1400093a2:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400093a5:	89 c1                	mov    ecx,eax
   1400093a7:	48 8b 05 4a 6e 00 00 	mov    rax,QWORD PTR [rip+0x6e4a]        # 1400101f8 <__imp_GetCPInfo>
   1400093ae:	ff d0                	call   rax
   1400093b0:	85 c0                	test   eax,eax
   1400093b2:	74 51                	je     140009405 <fallback_IsDBCSLeadByteEx+0x75>
   1400093b4:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   1400093b7:	83 f8 02             	cmp    eax,0x2
   1400093ba:	75 49                	jne    140009405 <fallback_IsDBCSLeadByteEx+0x75>
   1400093bc:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400093c3:	eb 2c                	jmp    1400093f1 <fallback_IsDBCSLeadByteEx+0x61>
   1400093c5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400093c8:	48 98                	cdqe
   1400093ca:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400093cf:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   1400093d2:	72 19                	jb     1400093ed <fallback_IsDBCSLeadByteEx+0x5d>
   1400093d4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400093d7:	83 c0 01             	add    eax,0x1
   1400093da:	48 98                	cdqe
   1400093dc:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400093e1:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   1400093e4:	72 07                	jb     1400093ed <fallback_IsDBCSLeadByteEx+0x5d>
   1400093e6:	b8 01 00 00 00       	mov    eax,0x1
   1400093eb:	eb 1d                	jmp    14000940a <fallback_IsDBCSLeadByteEx+0x7a>
   1400093ed:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400093f1:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   1400093f5:	7f 0e                	jg     140009405 <fallback_IsDBCSLeadByteEx+0x75>
   1400093f7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400093fa:	48 98                	cdqe
   1400093fc:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009401:	84 c0                	test   al,al
   140009403:	75 c0                	jne    1400093c5 <fallback_IsDBCSLeadByteEx+0x35>
   140009405:	b8 00 00 00 00       	mov    eax,0x0
   14000940a:	48 83 c4 40          	add    rsp,0x40
   14000940e:	5d                   	pop    rbp
   14000940f:	c3                   	ret

0000000140009410 <__mingw_isleadbyte_cp>:
   140009410:	55                   	push   rbp
   140009411:	48 89 e5             	mov    rbp,rsp
   140009414:	48 83 ec 40          	sub    rsp,0x40
   140009418:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000941b:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000941e:	48 8b 05 7b 67 00 00 	mov    rax,QWORD PTR [rip+0x677b]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009425:	48 85 c0             	test   rax,rax
   140009428:	75 71                	jne    14000949b <__mingw_isleadbyte_cp+0x8b>
   14000942a:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140009431:	00 
   140009432:	48 8d 05 f7 20 00 00 	lea    rax,[rip+0x20f7]        # 14000b530 <.rdata>
   140009439:	48 89 c1             	mov    rcx,rax
   14000943c:	48 8b 05 c5 6d 00 00 	mov    rax,QWORD PTR [rip+0x6dc5]        # 140010208 <__imp_GetModuleHandleA>
   140009443:	ff d0                	call   rax
   140009445:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140009449:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000944e:	74 1b                	je     14000946b <__mingw_isleadbyte_cp+0x5b>
   140009450:	48 8d 15 e6 20 00 00 	lea    rdx,[rip+0x20e6]        # 14000b53d <.rdata+0xd>
   140009457:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000945b:	48 89 c1             	mov    rcx,rax
   14000945e:	48 8b 05 ab 6d 00 00 	mov    rax,QWORD PTR [rip+0x6dab]        # 140010210 <__imp_GetProcAddress>
   140009465:	ff d0                	call   rax
   140009467:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000946b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140009470:	75 0b                	jne    14000947d <__mingw_isleadbyte_cp+0x6d>
   140009472:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 140009390 <fallback_IsDBCSLeadByteEx>
   140009479:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000947d:	48 8d 05 1c 67 00 00 	lea    rax,[rip+0x671c]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009484:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140009488:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000948c:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140009490:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140009494:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140009498:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000949b:	4c 8b 05 fe 66 00 00 	mov    r8,QWORD PTR [rip+0x66fe]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400094a2:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400094a5:	0f b6 d0             	movzx  edx,al
   1400094a8:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400094ab:	89 c1                	mov    ecx,eax
   1400094ad:	41 ff d0             	call   r8
   1400094b0:	48 83 c4 40          	add    rsp,0x40
   1400094b4:	5d                   	pop    rbp
   1400094b5:	c3                   	ret
   1400094b6:	90                   	nop
   1400094b7:	90                   	nop
   1400094b8:	90                   	nop
   1400094b9:	90                   	nop
   1400094ba:	90                   	nop
   1400094bb:	90                   	nop
   1400094bc:	90                   	nop
   1400094bd:	90                   	nop
   1400094be:	90                   	nop
   1400094bf:	90                   	nop

00000001400094c0 <__C_specific_handler>:
   1400094c0:	ff 25 aa 6d 00 00    	jmp    QWORD PTR [rip+0x6daa]        # 140010270 <__imp___C_specific_handler>
   1400094c6:	90                   	nop
   1400094c7:	90                   	nop

00000001400094c8 <___lc_codepage_func>:
   1400094c8:	ff 25 aa 6d 00 00    	jmp    QWORD PTR [rip+0x6daa]        # 140010278 <__imp____lc_codepage_func>
   1400094ce:	90                   	nop
   1400094cf:	90                   	nop

00000001400094d0 <___mb_cur_max_func>:
   1400094d0:	ff 25 aa 6d 00 00    	jmp    QWORD PTR [rip+0x6daa]        # 140010280 <__imp____mb_cur_max_func>
   1400094d6:	90                   	nop
   1400094d7:	90                   	nop

00000001400094d8 <__getmainargs>:
   1400094d8:	ff 25 aa 6d 00 00    	jmp    QWORD PTR [rip+0x6daa]        # 140010288 <__imp___getmainargs>
   1400094de:	90                   	nop
   1400094df:	90                   	nop

00000001400094e0 <__iob_func>:
   1400094e0:	ff 25 b2 6d 00 00    	jmp    QWORD PTR [rip+0x6db2]        # 140010298 <__imp___iob_func>
   1400094e6:	90                   	nop
   1400094e7:	90                   	nop

00000001400094e8 <__set_app_type>:
   1400094e8:	ff 25 b2 6d 00 00    	jmp    QWORD PTR [rip+0x6db2]        # 1400102a0 <__imp___set_app_type>
   1400094ee:	90                   	nop
   1400094ef:	90                   	nop

00000001400094f0 <__setusermatherr>:
   1400094f0:	ff 25 b2 6d 00 00    	jmp    QWORD PTR [rip+0x6db2]        # 1400102a8 <__imp___setusermatherr>
   1400094f6:	90                   	nop
   1400094f7:	90                   	nop

00000001400094f8 <_amsg_exit>:
   1400094f8:	ff 25 b2 6d 00 00    	jmp    QWORD PTR [rip+0x6db2]        # 1400102b0 <__imp__amsg_exit>
   1400094fe:	90                   	nop
   1400094ff:	90                   	nop

0000000140009500 <_cexit>:
   140009500:	ff 25 b2 6d 00 00    	jmp    QWORD PTR [rip+0x6db2]        # 1400102b8 <__imp__cexit>
   140009506:	90                   	nop
   140009507:	90                   	nop

0000000140009508 <_errno>:
   140009508:	ff 25 ba 6d 00 00    	jmp    QWORD PTR [rip+0x6dba]        # 1400102c8 <__imp__errno>
   14000950e:	90                   	nop
   14000950f:	90                   	nop

0000000140009510 <_initterm>:
   140009510:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 1400102d8 <__imp__initterm>
   140009516:	90                   	nop
   140009517:	90                   	nop

0000000140009518 <_crt_atexit>:
   140009518:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 1400102e0 <__imp__crt_atexit>
   14000951e:	90                   	nop
   14000951f:	90                   	nop

0000000140009520 <abort>:
   140009520:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 1400102e8 <__imp_abort>
   140009526:	90                   	nop
   140009527:	90                   	nop

0000000140009528 <calloc>:
   140009528:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 1400102f0 <__imp_calloc>
   14000952e:	90                   	nop
   14000952f:	90                   	nop

0000000140009530 <exit>:
   140009530:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 1400102f8 <__imp_exit>
   140009536:	90                   	nop
   140009537:	90                   	nop

0000000140009538 <fflush>:
   140009538:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010300 <__imp_fflush>
   14000953e:	90                   	nop
   14000953f:	90                   	nop

0000000140009540 <fprintf>:
   140009540:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010308 <__imp_fprintf>
   140009546:	90                   	nop
   140009547:	90                   	nop

0000000140009548 <fputc>:
   140009548:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010310 <__imp_fputc>
   14000954e:	90                   	nop
   14000954f:	90                   	nop

0000000140009550 <free>:
   140009550:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010318 <__imp_free>
   140009556:	90                   	nop
   140009557:	90                   	nop

0000000140009558 <localeconv>:
   140009558:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010320 <__imp_localeconv>
   14000955e:	90                   	nop
   14000955f:	90                   	nop

0000000140009560 <malloc>:
   140009560:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010328 <__imp_malloc>
   140009566:	90                   	nop
   140009567:	90                   	nop

0000000140009568 <memcpy>:
   140009568:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010330 <__imp_memcpy>
   14000956e:	90                   	nop
   14000956f:	90                   	nop

0000000140009570 <puts>:
   140009570:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010338 <__imp_puts>
   140009576:	90                   	nop
   140009577:	90                   	nop

0000000140009578 <setvbuf>:
   140009578:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010340 <__imp_setvbuf>
   14000957e:	90                   	nop
   14000957f:	90                   	nop

0000000140009580 <signal>:
   140009580:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010348 <__imp_signal>
   140009586:	90                   	nop
   140009587:	90                   	nop

0000000140009588 <strerror>:
   140009588:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010350 <__imp_strerror>
   14000958e:	90                   	nop
   14000958f:	90                   	nop

0000000140009590 <strlen>:
   140009590:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010358 <__imp_strlen>
   140009596:	90                   	nop
   140009597:	90                   	nop

0000000140009598 <strncmp>:
   140009598:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010360 <__imp_strncmp>
   14000959e:	90                   	nop
   14000959f:	90                   	nop

00000001400095a0 <vfprintf>:
   1400095a0:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010368 <__imp_vfprintf>
   1400095a6:	90                   	nop
   1400095a7:	90                   	nop

00000001400095a8 <wcslen>:
   1400095a8:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 140010370 <__imp_wcslen>
   1400095ae:	90                   	nop
   1400095af:	90                   	nop

00000001400095b0 <WideCharToMultiByte>:
   1400095b0:	ff 25 aa 6c 00 00    	jmp    QWORD PTR [rip+0x6caa]        # 140010260 <__imp_WideCharToMultiByte>
   1400095b6:	90                   	nop
   1400095b7:	90                   	nop

00000001400095b8 <VirtualQuery>:
   1400095b8:	ff 25 9a 6c 00 00    	jmp    QWORD PTR [rip+0x6c9a]        # 140010258 <__imp_VirtualQuery>
   1400095be:	90                   	nop
   1400095bf:	90                   	nop

00000001400095c0 <VirtualProtect>:
   1400095c0:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010250 <__imp_VirtualProtect>
   1400095c6:	90                   	nop
   1400095c7:	90                   	nop

00000001400095c8 <TlsGetValue>:
   1400095c8:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010248 <__imp_TlsGetValue>
   1400095ce:	90                   	nop
   1400095cf:	90                   	nop

00000001400095d0 <Sleep>:
   1400095d0:	ff 25 6a 6c 00 00    	jmp    QWORD PTR [rip+0x6c6a]        # 140010240 <__imp_Sleep>
   1400095d6:	90                   	nop
   1400095d7:	90                   	nop

00000001400095d8 <SetUnhandledExceptionFilter>:
   1400095d8:	ff 25 5a 6c 00 00    	jmp    QWORD PTR [rip+0x6c5a]        # 140010238 <__imp_SetUnhandledExceptionFilter>
   1400095de:	90                   	nop
   1400095df:	90                   	nop

00000001400095e0 <MultiByteToWideChar>:
   1400095e0:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010230 <__imp_MultiByteToWideChar>
   1400095e6:	90                   	nop
   1400095e7:	90                   	nop

00000001400095e8 <LoadLibraryA>:
   1400095e8:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010228 <__imp_LoadLibraryA>
   1400095ee:	90                   	nop
   1400095ef:	90                   	nop

00000001400095f0 <LeaveCriticalSection>:
   1400095f0:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010220 <__imp_LeaveCriticalSection>
   1400095f6:	90                   	nop
   1400095f7:	90                   	nop

00000001400095f8 <InitializeCriticalSection>:
   1400095f8:	ff 25 1a 6c 00 00    	jmp    QWORD PTR [rip+0x6c1a]        # 140010218 <__imp_InitializeCriticalSection>
   1400095fe:	90                   	nop
   1400095ff:	90                   	nop

0000000140009600 <GetProcAddress>:
   140009600:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010210 <__imp_GetProcAddress>
   140009606:	90                   	nop
   140009607:	90                   	nop

0000000140009608 <GetModuleHandleA>:
   140009608:	ff 25 fa 6b 00 00    	jmp    QWORD PTR [rip+0x6bfa]        # 140010208 <__imp_GetModuleHandleA>
   14000960e:	90                   	nop
   14000960f:	90                   	nop

0000000140009610 <GetLastError>:
   140009610:	ff 25 ea 6b 00 00    	jmp    QWORD PTR [rip+0x6bea]        # 140010200 <__imp_GetLastError>
   140009616:	90                   	nop
   140009617:	90                   	nop

0000000140009618 <GetCPInfo>:
   140009618:	ff 25 da 6b 00 00    	jmp    QWORD PTR [rip+0x6bda]        # 1400101f8 <__imp_GetCPInfo>
   14000961e:	90                   	nop
   14000961f:	90                   	nop

0000000140009620 <FreeLibrary>:
   140009620:	ff 25 ca 6b 00 00    	jmp    QWORD PTR [rip+0x6bca]        # 1400101f0 <__imp_FreeLibrary>
   140009626:	90                   	nop
   140009627:	90                   	nop

0000000140009628 <EnterCriticalSection>:
   140009628:	ff 25 ba 6b 00 00    	jmp    QWORD PTR [rip+0x6bba]        # 1400101e8 <__imp_EnterCriticalSection>
   14000962e:	90                   	nop
   14000962f:	90                   	nop

0000000140009630 <DeleteCriticalSection>:
   140009630:	ff 25 aa 6b 00 00    	jmp    QWORD PTR [rip+0x6baa]        # 1400101e0 <__IAT_start__>
   140009636:	90                   	nop
   140009637:	90                   	nop
   140009638:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000963f:	00 

0000000140009640 <register_frame_ctor>:
   140009640:	e9 2b 80 ff ff       	jmp    140001670 <__gcc_register_frame>
   140009645:	90                   	nop
   140009646:	90                   	nop
   140009647:	90                   	nop
   140009648:	90                   	nop
   140009649:	90                   	nop
   14000964a:	90                   	nop
   14000964b:	90                   	nop
   14000964c:	90                   	nop
   14000964d:	90                   	nop
   14000964e:	90                   	nop
   14000964f:	90                   	nop
