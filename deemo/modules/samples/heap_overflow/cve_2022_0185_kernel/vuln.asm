
C:\Users\Administrator\Desktop\BinMind\round2\samples\heap_overflow\cve_2022_0185_kernel\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 b7 23 00 00       	call   1400033e0 <fflush>
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
   14000103f:	48 8b 05 9a 43 00 00 	mov    rax,QWORD PTR [rip+0x439a]        # 1400053e0 <.refptr.__mingw_app_type>
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
   14000106e:	48 8b 05 6b 43 00 00 	mov    rax,QWORD PTR [rip+0x436b]        # 1400053e0 <.refptr.__mingw_app_type>
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
   1400010e8:	48 8b 05 f1 90 00 00 	mov    rax,QWORD PTR [rip+0x90f1]        # 14000a1e0 <__imp_Sleep>
   1400010ef:	ff d0                	call   rax
   1400010f1:	48 8b 05 38 43 00 00 	mov    rax,QWORD PTR [rip+0x4338]        # 140005430 <.refptr.__native_startup_lock>
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
   140001128:	48 8b 05 11 43 00 00 	mov    rax,QWORD PTR [rip+0x4311]        # 140005440 <.refptr.__native_startup_state>
   14000112f:	8b 00                	mov    eax,DWORD PTR [rax]
   140001131:	83 f8 01             	cmp    eax,0x1
   140001134:	75 0a                	jne    140001140 <__tmainCRTStartup+0xb2>
   140001136:	b9 1f 00 00 00       	mov    ecx,0x1f
   14000113b:	e8 68 22 00 00       	call   1400033a8 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 e8 21 00 00       	call   140003350 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 8f 22 00 00       	call   140003410 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 2f 22 00 00       	call   1400033c8 <abort>
   140001199:	e8 b2 12 00 00       	call   140002450 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 29 90 00 00 	mov    rax,QWORD PTR [rip+0x9029]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 26 21 00 00       	call   1400032f0 <_set_invalid_parameter_handler>
   1400011ca:	e8 91 1b 00 00       	call   140002d60 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 a7 21 00 00       	call   140003398 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 9b 21 00 00       	call   140003398 <__set_app_type>
   1400011fd:	e8 be 20 00 00       	call   1400032c0 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 be 20 00 00       	call   1400032d0 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 0e 08 00 00       	call   140001a30 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 73 21 00 00       	call   1400033a8 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 18 13 00 00       	call   14000256a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 c6 20 00 00       	call   140003330 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 e0 1f 00 00       	call   140003260 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 1a 21 00 00       	call   1400033a8 <_amsg_exit>
   14000128e:	48 8b 05 4b 42 00 00 	mov    rax,QWORD PTR [rip+0x424b]        # 1400054e0 <.refptr._newmode>
   140001295:	8b 00                	mov    eax,DWORD PTR [rax]
   140001297:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000129a:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400054a0 <.refptr._dowildcard>
   1400012a1:	44 8b 00             	mov    r8d,DWORD PTR [rax]
   1400012a4:	4c 8d 15 65 7d 00 00 	lea    r10,[rip+0x7d65]        # 140009010 <envp>
   1400012ab:	48 8d 15 56 7d 00 00 	lea    rdx,[rip+0x7d56]        # 140009008 <argv>
   1400012b2:	48 8d 05 4b 7d 00 00 	lea    rax,[rip+0x7d4b]        # 140009004 <argc>
   1400012b9:	48 8d 4d ac          	lea    rcx,[rbp-0x54]
   1400012bd:	48 89 4c 24 20       	mov    QWORD PTR [rsp+0x20],rcx
   1400012c2:	45 89 c1             	mov    r9d,r8d
   1400012c5:	4d 89 d0             	mov    r8,r10
   1400012c8:	48 89 c1             	mov    rcx,rax
   1400012cb:	e8 b8 20 00 00       	call   140003388 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 c5 20 00 00       	call   1400033a8 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 9e 20 00 00       	call   1400033a8 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 98 20 00 00       	call   1400033b8 <_initterm>
   140001320:	e8 e2 06 00 00       	call   140001a07 <__main>
   140001325:	48 8b 05 14 41 00 00 	mov    rax,QWORD PTR [rip+0x4114]        # 140005440 <.refptr.__native_startup_state>
   14000132c:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   140001332:	eb 0a                	jmp    14000133e <__tmainCRTStartup+0x2b0>
   140001334:	c7 05 de 7c 00 00 01 	mov    DWORD PTR [rip+0x7cde],0x1        # 14000901c <has_cctor>
   14000133b:	00 00 00 
   14000133e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140001342:	75 1e                	jne    140001362 <__tmainCRTStartup+0x2d4>
   140001344:	48 8b 05 e5 40 00 00 	mov    rax,QWORD PTR [rip+0x40e5]        # 140005430 <.refptr.__native_startup_lock>
   14000134b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000134f:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
   140001356:	00 
   140001357:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000135b:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000135f:	48 87 10             	xchg   QWORD PTR [rax],rdx
   140001362:	48 8b 05 27 40 00 00 	mov    rax,QWORD PTR [rip+0x4027]        # 140005390 <.refptr.__dyn_tls_init_callback>
   140001369:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000136c:	48 85 c0             	test   rax,rax
   14000136f:	74 1c                	je     14000138d <__tmainCRTStartup+0x2ff>
   140001371:	48 8b 05 18 40 00 00 	mov    rax,QWORD PTR [rip+0x4018]        # 140005390 <.refptr.__dyn_tls_init_callback>
   140001378:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000137b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140001381:	ba 02 00 00 00       	mov    edx,0x2
   140001386:	b9 00 00 00 00       	mov    ecx,0x0
   14000138b:	ff d0                	call   rax
   14000138d:	e8 4e 1f 00 00       	call   1400032e0 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 8a 04 00 00       	call   140001844 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 07 20 00 00       	call   1400033d8 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 d0 1f 00 00       	call   1400033b0 <_cexit>
   1400013e0:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013e3:	48 81 c4 90 00 00 00 	add    rsp,0x90
   1400013ea:	5d                   	pop    rbp
   1400013eb:	c3                   	ret

00000001400013ec <check_managed_app>:
   1400013ec:	55                   	push   rbp
   1400013ed:	48 89 e5             	mov    rbp,rsp
   1400013f0:	48 83 ec 20          	sub    rsp,0x20
   1400013f4:	48 8b 05 f5 3f 00 00 	mov    rax,QWORD PTR [rip+0x3ff5]        # 1400053f0 <.refptr.__mingw_initltsdrot_force>
   1400013fb:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140001401:	48 8b 05 f8 3f 00 00 	mov    rax,QWORD PTR [rip+0x3ff8]        # 140005400 <.refptr.__mingw_initltsdyn_force>
   140001408:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000140e:	48 8b 05 fb 3f 00 00 	mov    rax,QWORD PTR [rip+0x3ffb]        # 140005410 <.refptr.__mingw_initltssuo_force>
   140001415:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000141b:	48 8b 05 3e 3f 00 00 	mov    rax,QWORD PTR [rip+0x3f3e]        # 140005360 <.refptr.__ImageBase>
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
   140001511:	e8 e2 1e 00 00       	call   1400033f8 <malloc>
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
   14000155c:	e8 bf 1e 00 00       	call   140003420 <strlen>
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
   140001585:	e8 6e 1e 00 00       	call   1400033f8 <malloc>
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
   1400015e8:	e8 13 1e 00 00       	call   140003400 <memcpy>
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
   140001642:	e8 79 1d 00 00       	call   1400033c0 <_crt_atexit>
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
   14000167b:	48 8d 0d 7e 39 00 00 	lea    rcx,[rip+0x397e]        # 140005000 <.rdata>
   140001682:	ff 15 28 8b 00 00    	call   QWORD PTR [rip+0x8b28]        # 14000a1b0 <__imp_GetModuleHandleA>
   140001688:	48 89 c3             	mov    rbx,rax
   14000168b:	48 85 c0             	test   rax,rax
   14000168e:	74 70                	je     140001700 <__gcc_register_frame+0x90>
   140001690:	48 8d 0d 69 39 00 00 	lea    rcx,[rip+0x3969]        # 140005000 <.rdata>
   140001697:	ff 15 33 8b 00 00    	call   QWORD PTR [rip+0x8b33]        # 14000a1d0 <__imp_LoadLibraryA>
   14000169d:	4c 8b 0d 14 8b 00 00 	mov    r9,QWORD PTR [rip+0x8b14]        # 14000a1b8 <__imp_GetProcAddress>
   1400016a4:	48 8d 15 68 39 00 00 	lea    rdx,[rip+0x3968]        # 140005013 <.rdata+0x13>
   1400016ab:	48 89 d9             	mov    rcx,rbx
   1400016ae:	48 89 05 6b 79 00 00 	mov    QWORD PTR [rip+0x796b],rax        # 140009020 <hmod_libgcc>
   1400016b5:	4c 89 4d f0          	mov    QWORD PTR [rbp-0x10],r9
   1400016b9:	41 ff d1             	call   r9
   1400016bc:	48 8d 15 66 39 00 00 	lea    rdx,[rip+0x3966]        # 140005029 <.rdata+0x29>
   1400016c3:	48 89 d9             	mov    rcx,rbx
   1400016c6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400016ca:	ff 55 f0             	call   QWORD PTR [rbp-0x10]
   1400016cd:	4c 8b 45 f8          	mov    r8,QWORD PTR [rbp-0x8]
   1400016d1:	48 89 05 28 29 00 00 	mov    QWORD PTR [rip+0x2928],rax        # 140004000 <__data_start__>
   1400016d8:	4d 85 c0             	test   r8,r8
   1400016db:	74 11                	je     1400016ee <__gcc_register_frame+0x7e>
   1400016dd:	48 8d 15 5c 79 00 00 	lea    rdx,[rip+0x795c]        # 140009040 <obj>
   1400016e4:	48 8d 0d 15 49 00 00 	lea    rcx,[rip+0x4915]        # 140006000 <__EH_FRAME_BEGIN__>
   1400016eb:	41 ff d0             	call   r8
   1400016ee:	48 8d 0d 2b 00 00 00 	lea    rcx,[rip+0x2b]        # 140001720 <__gcc_deregister_frame>
   1400016f5:	48 83 c4 38          	add    rsp,0x38
   1400016f9:	5b                   	pop    rbx
   1400016fa:	5d                   	pop    rbp
   1400016fb:	e9 2f ff ff ff       	jmp    14000162f <atexit>
   140001700:	48 8d 05 59 ff ff ff 	lea    rax,[rip+0xffffffffffffff59]        # 140001660 <.weak.__deregister_frame_info.hmod_libgcc>
   140001707:	4c 8d 05 42 ff ff ff 	lea    r8,[rip+0xffffffffffffff42]        # 140001650 <.weak.__register_frame_info.hmod_libgcc>
   14000170e:	48 89 05 eb 28 00 00 	mov    QWORD PTR [rip+0x28eb],rax        # 140004000 <__data_start__>
   140001715:	eb c6                	jmp    1400016dd <__gcc_register_frame+0x6d>
   140001717:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
   14000171e:	00 00 

0000000140001720 <__gcc_deregister_frame>:
   140001720:	55                   	push   rbp
   140001721:	48 89 e5             	mov    rbp,rsp
   140001724:	48 83 ec 20          	sub    rsp,0x20
   140001728:	48 8b 05 d1 28 00 00 	mov    rax,QWORD PTR [rip+0x28d1]        # 140004000 <__data_start__>
   14000172f:	48 85 c0             	test   rax,rax
   140001732:	74 09                	je     14000173d <__gcc_deregister_frame+0x1d>
   140001734:	48 8d 0d c5 48 00 00 	lea    rcx,[rip+0x48c5]        # 140006000 <__EH_FRAME_BEGIN__>
   14000173b:	ff d0                	call   rax
   14000173d:	48 8b 0d dc 78 00 00 	mov    rcx,QWORD PTR [rip+0x78dc]        # 140009020 <hmod_libgcc>
   140001744:	48 85 c9             	test   rcx,rcx
   140001747:	74 0f                	je     140001758 <__gcc_deregister_frame+0x38>
   140001749:	48 83 c4 20          	add    rsp,0x20
   14000174d:	5d                   	pop    rbp
   14000174e:	48 ff 25 4b 8a 00 00 	rex.W jmp QWORD PTR [rip+0x8a4b]        # 14000a1a0 <__imp_FreeLibrary>
   140001755:	0f 1f 00             	nop    DWORD PTR [rax]
   140001758:	48 83 c4 20          	add    rsp,0x20
   14000175c:	5d                   	pop    rbp
   14000175d:	c3                   	ret
   14000175e:	90                   	nop
   14000175f:	90                   	nop

0000000140001760 <parse_param>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 30          	sub    rsp,0x30
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001770:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001774:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001778:	48 89 c1             	mov    rcx,rax
   14000177b:	e8 a0 1c 00 00       	call   140003420 <strlen>
   140001780:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001784:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001788:	48 89 c1             	mov    rcx,rax
   14000178b:	e8 90 1c 00 00       	call   140003420 <strlen>
   140001790:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001794:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001798:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000179c:	48 01 d0             	add    rax,rdx
   14000179f:	48 3d fe 0f 00 00    	cmp    rax,0xffe
   1400017a5:	76 0a                	jbe    1400017b1 <parse_param+0x51>
   1400017a7:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400017ac:	e9 8d 00 00 00       	jmp    14000183e <parse_param+0xde>
   1400017b1:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400017b5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017b9:	8b 80 00 10 00 00    	mov    eax,DWORD PTR [rax+0x1000]
   1400017bf:	48 98                	cdqe
   1400017c1:	48 8d 0c 02          	lea    rcx,[rdx+rax*1]
   1400017c5:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400017c9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400017cd:	49 89 d0             	mov    r8,rdx
   1400017d0:	48 89 c2             	mov    rdx,rax
   1400017d3:	e8 28 1c 00 00       	call   140003400 <memcpy>
   1400017d8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017dc:	8b 80 00 10 00 00    	mov    eax,DWORD PTR [rax+0x1000]
   1400017e2:	89 c2                	mov    edx,eax
   1400017e4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017e8:	01 d0                	add    eax,edx
   1400017ea:	89 c2                	mov    edx,eax
   1400017ec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017f0:	89 90 00 10 00 00    	mov    DWORD PTR [rax+0x1000],edx
   1400017f6:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400017fa:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017fe:	8b 80 00 10 00 00    	mov    eax,DWORD PTR [rax+0x1000]
   140001804:	48 98                	cdqe
   140001806:	48 8d 0c 02          	lea    rcx,[rdx+rax*1]
   14000180a:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   14000180e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001812:	49 89 d0             	mov    r8,rdx
   140001815:	48 89 c2             	mov    rdx,rax
   140001818:	e8 e3 1b 00 00       	call   140003400 <memcpy>
   14000181d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001821:	8b 80 00 10 00 00    	mov    eax,DWORD PTR [rax+0x1000]
   140001827:	48 63 d0             	movsxd rdx,eax
   14000182a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000182e:	48 01 c2             	add    rdx,rax
   140001831:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001835:	c6 04 10 00          	mov    BYTE PTR [rax+rdx*1],0x0
   140001839:	b8 00 00 00 00       	mov    eax,0x0
   14000183e:	48 83 c4 30          	add    rsp,0x30
   140001842:	5d                   	pop    rbp
   140001843:	c3                   	ret

0000000140001844 <main>:
   140001844:	55                   	push   rbp
   140001845:	b8 50 10 00 00       	mov    eax,0x1050
   14000184a:	e8 d1 19 00 00       	call   140003220 <___chkstk_ms>
   14000184f:	48 29 c4             	sub    rsp,rax
   140001852:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140001859:	00 
   14000185a:	89 8d e0 0f 00 00    	mov    DWORD PTR [rbp+0xfe0],ecx
   140001860:	48 89 95 e8 0f 00 00 	mov    QWORD PTR [rbp+0xfe8],rdx
   140001867:	e8 9b 01 00 00       	call   140001a07 <__main>
   14000186c:	b9 00 10 00 00       	mov    ecx,0x1000
   140001871:	e8 82 1b 00 00       	call   1400033f8 <malloc>
   140001876:	48 89 85 c8 0f 00 00 	mov    QWORD PTR [rbp+0xfc8],rax
   14000187d:	48 83 bd c8 0f 00 00 	cmp    QWORD PTR [rbp+0xfc8],0x0
   140001884:	00 
   140001885:	75 0a                	jne    140001891 <main+0x4d>
   140001887:	b8 01 00 00 00       	mov    eax,0x1
   14000188c:	e9 b0 00 00 00       	jmp    140001941 <main+0xfd>
   140001891:	48 8b 85 c8 0f 00 00 	mov    rax,QWORD PTR [rbp+0xfc8]
   140001898:	c7 80 00 10 00 00 00 	mov    DWORD PTR [rax+0x1000],0x0
   14000189f:	00 00 00 
   1400018a2:	48 8d 45 20          	lea    rax,[rbp+0x20]
   1400018a6:	41 b8 9f 0f 00 00    	mov    r8d,0xf9f
   1400018ac:	ba 4b 00 00 00       	mov    edx,0x4b
   1400018b1:	48 89 c1             	mov    rcx,rax
   1400018b4:	e8 4f 1b 00 00       	call   140003408 <memset>
   1400018b9:	c6 85 bf 0f 00 00 00 	mov    BYTE PTR [rbp+0xfbf],0x0
   1400018c0:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400018c4:	41 b8 64 00 00 00    	mov    r8d,0x64
   1400018ca:	ba 56 00 00 00       	mov    edx,0x56
   1400018cf:	48 89 c1             	mov    rcx,rax
   1400018d2:	e8 31 1b 00 00       	call   140003408 <memset>
   1400018d7:	c6 45 04 00          	mov    BYTE PTR [rbp+0x4],0x0
   1400018db:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   1400018df:	48 8d 55 20          	lea    rdx,[rbp+0x20]
   1400018e3:	48 8b 85 c8 0f 00 00 	mov    rax,QWORD PTR [rbp+0xfc8]
   1400018ea:	49 89 c8             	mov    r8,rcx
   1400018ed:	48 89 c1             	mov    rcx,rax
   1400018f0:	e8 6b fe ff ff       	call   140001760 <parse_param>
   1400018f5:	48 8d 45 20          	lea    rax,[rbp+0x20]
   1400018f9:	41 b8 9a 0f 00 00    	mov    r8d,0xf9a
   1400018ff:	ba 4b 00 00 00       	mov    edx,0x4b
   140001904:	48 89 c1             	mov    rcx,rax
   140001907:	e8 fc 1a 00 00       	call   140003408 <memset>
   14000190c:	c6 85 ba 0f 00 00 00 	mov    BYTE PTR [rbp+0xfba],0x0
   140001913:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140001917:	48 8d 55 20          	lea    rdx,[rbp+0x20]
   14000191b:	48 8b 85 c8 0f 00 00 	mov    rax,QWORD PTR [rbp+0xfc8]
   140001922:	49 89 c8             	mov    r8,rcx
   140001925:	48 89 c1             	mov    rcx,rax
   140001928:	e8 33 fe ff ff       	call   140001760 <parse_param>
   14000192d:	48 8b 85 c8 0f 00 00 	mov    rax,QWORD PTR [rbp+0xfc8]
   140001934:	48 89 c1             	mov    rcx,rax
   140001937:	e8 b4 1a 00 00       	call   1400033f0 <free>
   14000193c:	b8 00 00 00 00       	mov    eax,0x0
   140001941:	48 81 c4 50 10 00 00 	add    rsp,0x1050
   140001948:	5d                   	pop    rbp
   140001949:	c3                   	ret
   14000194a:	90                   	nop
   14000194b:	90                   	nop
   14000194c:	90                   	nop
   14000194d:	90                   	nop
   14000194e:	90                   	nop
   14000194f:	90                   	nop

0000000140001950 <__do_global_dtors>:
   140001950:	55                   	push   rbp
   140001951:	48 89 e5             	mov    rbp,rsp
   140001954:	48 83 ec 20          	sub    rsp,0x20
   140001958:	eb 1e                	jmp    140001978 <__do_global_dtors+0x28>
   14000195a:	48 8b 05 af 26 00 00 	mov    rax,QWORD PTR [rip+0x26af]        # 140004010 <p.0>
   140001961:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001964:	ff d0                	call   rax
   140001966:	48 8b 05 a3 26 00 00 	mov    rax,QWORD PTR [rip+0x26a3]        # 140004010 <p.0>
   14000196d:	48 83 c0 08          	add    rax,0x8
   140001971:	48 89 05 98 26 00 00 	mov    QWORD PTR [rip+0x2698],rax        # 140004010 <p.0>
   140001978:	48 8b 05 91 26 00 00 	mov    rax,QWORD PTR [rip+0x2691]        # 140004010 <p.0>
   14000197f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001982:	48 85 c0             	test   rax,rax
   140001985:	75 d3                	jne    14000195a <__do_global_dtors+0xa>
   140001987:	90                   	nop
   140001988:	90                   	nop
   140001989:	48 83 c4 20          	add    rsp,0x20
   14000198d:	5d                   	pop    rbp
   14000198e:	c3                   	ret

000000014000198f <__do_global_ctors>:
   14000198f:	55                   	push   rbp
   140001990:	48 89 e5             	mov    rbp,rsp
   140001993:	48 83 ec 30          	sub    rsp,0x30
   140001997:	48 8b 05 b2 39 00 00 	mov    rax,QWORD PTR [rip+0x39b2]        # 140005350 <.refptr.__CTOR_LIST__>
   14000199e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019a1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400019a4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400019a8:	75 25                	jne    1400019cf <__do_global_ctors+0x40>
   1400019aa:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400019b1:	eb 04                	jmp    1400019b7 <__do_global_ctors+0x28>
   1400019b3:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400019b7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400019ba:	8d 50 01             	lea    edx,[rax+0x1]
   1400019bd:	48 8b 05 8c 39 00 00 	mov    rax,QWORD PTR [rip+0x398c]        # 140005350 <.refptr.__CTOR_LIST__>
   1400019c4:	89 d2                	mov    edx,edx
   1400019c6:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400019ca:	48 85 c0             	test   rax,rax
   1400019cd:	75 e4                	jne    1400019b3 <__do_global_ctors+0x24>
   1400019cf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400019d2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400019d5:	eb 14                	jmp    1400019eb <__do_global_ctors+0x5c>
   1400019d7:	48 8b 05 72 39 00 00 	mov    rax,QWORD PTR [rip+0x3972]        # 140005350 <.refptr.__CTOR_LIST__>
   1400019de:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400019e1:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400019e5:	ff d0                	call   rax
   1400019e7:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400019eb:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400019ef:	75 e6                	jne    1400019d7 <__do_global_ctors+0x48>
   1400019f1:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001950 <__do_global_dtors>
   1400019f8:	48 89 c1             	mov    rcx,rax
   1400019fb:	e8 2f fc ff ff       	call   14000162f <atexit>
   140001a00:	90                   	nop
   140001a01:	48 83 c4 30          	add    rsp,0x30
   140001a05:	5d                   	pop    rbp
   140001a06:	c3                   	ret

0000000140001a07 <__main>:
   140001a07:	55                   	push   rbp
   140001a08:	48 89 e5             	mov    rbp,rsp
   140001a0b:	48 83 ec 20          	sub    rsp,0x20
   140001a0f:	8b 05 6b 76 00 00    	mov    eax,DWORD PTR [rip+0x766b]        # 140009080 <initialized>
   140001a15:	85 c0                	test   eax,eax
   140001a17:	75 0f                	jne    140001a28 <__main+0x21>
   140001a19:	c7 05 5d 76 00 00 01 	mov    DWORD PTR [rip+0x765d],0x1        # 140009080 <initialized>
   140001a20:	00 00 00 
   140001a23:	e8 67 ff ff ff       	call   14000198f <__do_global_ctors>
   140001a28:	90                   	nop
   140001a29:	48 83 c4 20          	add    rsp,0x20
   140001a2d:	5d                   	pop    rbp
   140001a2e:	c3                   	ret
   140001a2f:	90                   	nop

0000000140001a30 <_setargv>:
   140001a30:	55                   	push   rbp
   140001a31:	48 89 e5             	mov    rbp,rsp
   140001a34:	b8 00 00 00 00       	mov    eax,0x0
   140001a39:	5d                   	pop    rbp
   140001a3a:	c3                   	ret
   140001a3b:	90                   	nop
   140001a3c:	90                   	nop
   140001a3d:	90                   	nop
   140001a3e:	90                   	nop
   140001a3f:	90                   	nop

0000000140001a40 <__dyn_tls_init>:
   140001a40:	55                   	push   rbp
   140001a41:	48 89 e5             	mov    rbp,rsp
   140001a44:	48 83 ec 30          	sub    rsp,0x30
   140001a48:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a4c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a4f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a53:	48 8b 05 d6 38 00 00 	mov    rax,QWORD PTR [rip+0x38d6]        # 140005330 <.refptr._CRT_MT>
   140001a5a:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a5c:	83 f8 02             	cmp    eax,0x2
   140001a5f:	74 0d                	je     140001a6e <__dyn_tls_init+0x2e>
   140001a61:	48 8b 05 c8 38 00 00 	mov    rax,QWORD PTR [rip+0x38c8]        # 140005330 <.refptr._CRT_MT>
   140001a68:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   140001a6e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001a72:	74 1e                	je     140001a92 <__dyn_tls_init+0x52>
   140001a74:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001a78:	75 5b                	jne    140001ad5 <__dyn_tls_init+0x95>
   140001a7a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a7e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a81:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a85:	49 89 c8             	mov    r8,rcx
   140001a88:	48 89 c1             	mov    rcx,rax
   140001a8b:	e8 d1 11 00 00       	call   140002c61 <__mingw_TLScallback>
   140001a90:	eb 43                	jmp    140001ad5 <__dyn_tls_init+0x95>
   140001a92:	48 8d 05 ff 3b 00 00 	lea    rax,[rip+0x3bff]        # 140005698 <___crt_xd_start__>
   140001a99:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a9d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001aa2:	eb 22                	jmp    140001ac6 <__dyn_tls_init+0x86>
   140001aa4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001aa8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001aac:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001ab0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001ab3:	48 85 c0             	test   rax,rax
   140001ab6:	74 09                	je     140001ac1 <__dyn_tls_init+0x81>
   140001ab8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001abc:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001abf:	ff d0                	call   rax
   140001ac1:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001ac6:	48 8d 05 d3 3b 00 00 	lea    rax,[rip+0x3bd3]        # 1400056a0 <__xd_z>
   140001acd:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001ad1:	75 d1                	jne    140001aa4 <__dyn_tls_init+0x64>
   140001ad3:	eb 01                	jmp    140001ad6 <__dyn_tls_init+0x96>
   140001ad5:	90                   	nop
   140001ad6:	48 83 c4 30          	add    rsp,0x30
   140001ada:	5d                   	pop    rbp
   140001adb:	c3                   	ret

0000000140001adc <__tlregdtor>:
   140001adc:	55                   	push   rbp
   140001add:	48 89 e5             	mov    rbp,rsp
   140001ae0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001ae4:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001ae9:	75 07                	jne    140001af2 <__tlregdtor+0x16>
   140001aeb:	b8 00 00 00 00       	mov    eax,0x0
   140001af0:	eb 05                	jmp    140001af7 <__tlregdtor+0x1b>
   140001af2:	b8 00 00 00 00       	mov    eax,0x0
   140001af7:	5d                   	pop    rbp
   140001af8:	c3                   	ret

0000000140001af9 <__dyn_tls_dtor>:
   140001af9:	55                   	push   rbp
   140001afa:	48 89 e5             	mov    rbp,rsp
   140001afd:	48 83 ec 20          	sub    rsp,0x20
   140001b01:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b05:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001b08:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001b0c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001b10:	74 06                	je     140001b18 <__dyn_tls_dtor+0x1f>
   140001b12:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001b16:	75 18                	jne    140001b30 <__dyn_tls_dtor+0x37>
   140001b18:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001b1c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001b1f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001b23:	49 89 c8             	mov    r8,rcx
   140001b26:	48 89 c1             	mov    rcx,rax
   140001b29:	e8 33 11 00 00       	call   140002c61 <__mingw_TLScallback>
   140001b2e:	eb 01                	jmp    140001b31 <__dyn_tls_dtor+0x38>
   140001b30:	90                   	nop
   140001b31:	48 83 c4 20          	add    rsp,0x20
   140001b35:	5d                   	pop    rbp
   140001b36:	c3                   	ret
   140001b37:	90                   	nop
   140001b38:	90                   	nop
   140001b39:	90                   	nop
   140001b3a:	90                   	nop
   140001b3b:	90                   	nop
   140001b3c:	90                   	nop
   140001b3d:	90                   	nop
   140001b3e:	90                   	nop
   140001b3f:	90                   	nop

0000000140001b40 <_matherr>:
   140001b40:	55                   	push   rbp
   140001b41:	53                   	push   rbx
   140001b42:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001b49:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001b4e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001b52:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001b56:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001b5b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001b5f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b63:	8b 00                	mov    eax,DWORD PTR [rax]
   140001b65:	83 f8 06             	cmp    eax,0x6
   140001b68:	74 56                	je     140001bc0 <_matherr+0x80>
   140001b6a:	83 f8 06             	cmp    eax,0x6
   140001b6d:	7f 78                	jg     140001be7 <_matherr+0xa7>
   140001b6f:	83 f8 05             	cmp    eax,0x5
   140001b72:	74 59                	je     140001bcd <_matherr+0x8d>
   140001b74:	83 f8 05             	cmp    eax,0x5
   140001b77:	7f 6e                	jg     140001be7 <_matherr+0xa7>
   140001b79:	83 f8 04             	cmp    eax,0x4
   140001b7c:	74 5c                	je     140001bda <_matherr+0x9a>
   140001b7e:	83 f8 04             	cmp    eax,0x4
   140001b81:	7f 64                	jg     140001be7 <_matherr+0xa7>
   140001b83:	83 f8 03             	cmp    eax,0x3
   140001b86:	74 2b                	je     140001bb3 <_matherr+0x73>
   140001b88:	83 f8 03             	cmp    eax,0x3
   140001b8b:	7f 5a                	jg     140001be7 <_matherr+0xa7>
   140001b8d:	83 f8 01             	cmp    eax,0x1
   140001b90:	74 07                	je     140001b99 <_matherr+0x59>
   140001b92:	83 f8 02             	cmp    eax,0x2
   140001b95:	74 0f                	je     140001ba6 <_matherr+0x66>
   140001b97:	eb 4e                	jmp    140001be7 <_matherr+0xa7>
   140001b99:	48 8d 05 00 35 00 00 	lea    rax,[rip+0x3500]        # 1400050a0 <.rdata>
   140001ba0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ba4:	eb 4d                	jmp    140001bf3 <_matherr+0xb3>
   140001ba6:	48 8d 05 12 35 00 00 	lea    rax,[rip+0x3512]        # 1400050bf <.rdata+0x1f>
   140001bad:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bb1:	eb 40                	jmp    140001bf3 <_matherr+0xb3>
   140001bb3:	48 8d 05 26 35 00 00 	lea    rax,[rip+0x3526]        # 1400050e0 <.rdata+0x40>
   140001bba:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bbe:	eb 33                	jmp    140001bf3 <_matherr+0xb3>
   140001bc0:	48 8d 05 39 35 00 00 	lea    rax,[rip+0x3539]        # 140005100 <.rdata+0x60>
   140001bc7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bcb:	eb 26                	jmp    140001bf3 <_matherr+0xb3>
   140001bcd:	48 8d 05 54 35 00 00 	lea    rax,[rip+0x3554]        # 140005128 <.rdata+0x88>
   140001bd4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bd8:	eb 19                	jmp    140001bf3 <_matherr+0xb3>
   140001bda:	48 8d 05 6f 35 00 00 	lea    rax,[rip+0x356f]        # 140005150 <.rdata+0xb0>
   140001be1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001be5:	eb 0c                	jmp    140001bf3 <_matherr+0xb3>
   140001be7:	48 8d 05 98 35 00 00 	lea    rax,[rip+0x3598]        # 140005186 <.rdata+0xe6>
   140001bee:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bf2:	90                   	nop
   140001bf3:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001bf7:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001bfd:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c01:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001c06:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c0a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001c0f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c13:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001c17:	b9 02 00 00 00       	mov    ecx,0x2
   140001c1c:	e8 2f 17 00 00       	call   140003350 <__acrt_iob_func>
   140001c21:	48 89 c1             	mov    rcx,rax
   140001c24:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001c28:	48 8d 05 69 35 00 00 	lea    rax,[rip+0x3569]        # 140005198 <.rdata+0xf8>
   140001c2f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001c36:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001c3c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001c42:	49 89 d9             	mov    r9,rbx
   140001c45:	49 89 d0             	mov    r8,rdx
   140001c48:	48 89 c2             	mov    rdx,rax
   140001c4b:	e8 98 17 00 00       	call   1400033e8 <fprintf>
   140001c50:	b8 00 00 00 00       	mov    eax,0x0
   140001c55:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001c59:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001c5d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001c62:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001c69:	5b                   	pop    rbx
   140001c6a:	5d                   	pop    rbp
   140001c6b:	c3                   	ret
   140001c6c:	90                   	nop
   140001c6d:	90                   	nop
   140001c6e:	90                   	nop
   140001c6f:	90                   	nop

0000000140001c70 <__report_error>:
   140001c70:	55                   	push   rbp
   140001c71:	53                   	push   rbx
   140001c72:	48 83 ec 38          	sub    rsp,0x38
   140001c76:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001c7b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001c7f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001c83:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001c87:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001c8b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001c8f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c93:	b9 02 00 00 00       	mov    ecx,0x2
   140001c98:	e8 b3 16 00 00       	call   140003350 <__acrt_iob_func>
   140001c9d:	48 89 c1             	mov    rcx,rax
   140001ca0:	48 8d 05 29 35 00 00 	lea    rax,[rip+0x3529]        # 1400051d0 <.rdata>
   140001ca7:	48 89 c2             	mov    rdx,rax
   140001caa:	e8 39 17 00 00       	call   1400033e8 <fprintf>
   140001caf:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001cb3:	b9 02 00 00 00       	mov    ecx,0x2
   140001cb8:	e8 93 16 00 00       	call   140003350 <__acrt_iob_func>
   140001cbd:	48 89 c1             	mov    rcx,rax
   140001cc0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001cc4:	49 89 d8             	mov    r8,rbx
   140001cc7:	48 89 c2             	mov    rdx,rax
   140001cca:	e8 61 17 00 00       	call   140003430 <vfprintf>
   140001ccf:	e8 f4 16 00 00       	call   1400033c8 <abort>
   140001cd4:	90                   	nop

0000000140001cd5 <mark_section_writable>:
   140001cd5:	55                   	push   rbp
   140001cd6:	48 89 e5             	mov    rbp,rsp
   140001cd9:	48 83 ec 60          	sub    rsp,0x60
   140001cdd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001ce1:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001ce8:	e9 82 00 00 00       	jmp    140001d6f <mark_section_writable+0x9a>
   140001ced:	48 8b 0d ec 73 00 00 	mov    rcx,QWORD PTR [rip+0x73ec]        # 1400090e0 <the_secs>
   140001cf4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cf7:	48 63 d0             	movsxd rdx,eax
   140001cfa:	48 89 d0             	mov    rax,rdx
   140001cfd:	48 c1 e0 02          	shl    rax,0x2
   140001d01:	48 01 d0             	add    rax,rdx
   140001d04:	48 c1 e0 03          	shl    rax,0x3
   140001d08:	48 01 c8             	add    rax,rcx
   140001d0b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d0f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001d13:	72 56                	jb     140001d6b <mark_section_writable+0x96>
   140001d15:	48 8b 0d c4 73 00 00 	mov    rcx,QWORD PTR [rip+0x73c4]        # 1400090e0 <the_secs>
   140001d1c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d1f:	48 63 d0             	movsxd rdx,eax
   140001d22:	48 89 d0             	mov    rax,rdx
   140001d25:	48 c1 e0 02          	shl    rax,0x2
   140001d29:	48 01 d0             	add    rax,rdx
   140001d2c:	48 c1 e0 03          	shl    rax,0x3
   140001d30:	48 01 c8             	add    rax,rcx
   140001d33:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001d37:	4c 8b 05 a2 73 00 00 	mov    r8,QWORD PTR [rip+0x73a2]        # 1400090e0 <the_secs>
   140001d3e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d41:	48 63 d0             	movsxd rdx,eax
   140001d44:	48 89 d0             	mov    rax,rdx
   140001d47:	48 c1 e0 02          	shl    rax,0x2
   140001d4b:	48 01 d0             	add    rax,rdx
   140001d4e:	48 c1 e0 03          	shl    rax,0x3
   140001d52:	4c 01 c0             	add    rax,r8
   140001d55:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001d59:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d5c:	89 c0                	mov    eax,eax
   140001d5e:	48 01 c8             	add    rax,rcx
   140001d61:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001d65:	0f 82 41 02 00 00    	jb     140001fac <mark_section_writable+0x2d7>
   140001d6b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001d6f:	8b 05 73 73 00 00    	mov    eax,DWORD PTR [rip+0x7373]        # 1400090e8 <maxSections>
   140001d75:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001d78:	0f 8c 6f ff ff ff    	jl     140001ced <mark_section_writable+0x18>
   140001d7e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001d82:	48 89 c1             	mov    rcx,rax
   140001d85:	e8 c1 11 00 00       	call   140002f4b <__mingw_GetSectionForAddress>
   140001d8a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001d8e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001d93:	75 13                	jne    140001da8 <mark_section_writable+0xd3>
   140001d95:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001d99:	48 8d 0d 50 34 00 00 	lea    rcx,[rip+0x3450]        # 1400051f0 <.rdata+0x20>
   140001da0:	48 89 c2             	mov    rdx,rax
   140001da3:	e8 c8 fe ff ff       	call   140001c70 <__report_error>
   140001da8:	48 8b 0d 31 73 00 00 	mov    rcx,QWORD PTR [rip+0x7331]        # 1400090e0 <the_secs>
   140001daf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001db2:	48 63 d0             	movsxd rdx,eax
   140001db5:	48 89 d0             	mov    rax,rdx
   140001db8:	48 c1 e0 02          	shl    rax,0x2
   140001dbc:	48 01 d0             	add    rax,rdx
   140001dbf:	48 c1 e0 03          	shl    rax,0x3
   140001dc3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001dc7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001dcb:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001dcf:	48 8b 0d 0a 73 00 00 	mov    rcx,QWORD PTR [rip+0x730a]        # 1400090e0 <the_secs>
   140001dd6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dd9:	48 63 d0             	movsxd rdx,eax
   140001ddc:	48 89 d0             	mov    rax,rdx
   140001ddf:	48 c1 e0 02          	shl    rax,0x2
   140001de3:	48 01 d0             	add    rax,rdx
   140001de6:	48 c1 e0 03          	shl    rax,0x3
   140001dea:	48 01 c8             	add    rax,rcx
   140001ded:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001df3:	e8 9f 12 00 00       	call   140003097 <_GetPEImageBase>
   140001df8:	48 89 c1             	mov    rcx,rax
   140001dfb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001dff:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001e02:	41 89 c1             	mov    r9d,eax
   140001e05:	4c 8b 05 d4 72 00 00 	mov    r8,QWORD PTR [rip+0x72d4]        # 1400090e0 <the_secs>
   140001e0c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e0f:	48 63 d0             	movsxd rdx,eax
   140001e12:	48 89 d0             	mov    rax,rdx
   140001e15:	48 c1 e0 02          	shl    rax,0x2
   140001e19:	48 01 d0             	add    rax,rdx
   140001e1c:	48 c1 e0 03          	shl    rax,0x3
   140001e20:	4c 01 c0             	add    rax,r8
   140001e23:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001e27:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001e2b:	48 8b 0d ae 72 00 00 	mov    rcx,QWORD PTR [rip+0x72ae]        # 1400090e0 <the_secs>
   140001e32:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e35:	48 63 d0             	movsxd rdx,eax
   140001e38:	48 89 d0             	mov    rax,rdx
   140001e3b:	48 c1 e0 02          	shl    rax,0x2
   140001e3f:	48 01 d0             	add    rax,rdx
   140001e42:	48 c1 e0 03          	shl    rax,0x3
   140001e46:	48 01 c8             	add    rax,rcx
   140001e49:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001e4d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001e51:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001e57:	48 89 c1             	mov    rcx,rax
   140001e5a:	48 8b 05 97 83 00 00 	mov    rax,QWORD PTR [rip+0x8397]        # 14000a1f8 <__imp_VirtualQuery>
   140001e61:	ff d0                	call   rax
   140001e63:	48 85 c0             	test   rax,rax
   140001e66:	75 3f                	jne    140001ea7 <mark_section_writable+0x1d2>
   140001e68:	48 8b 0d 71 72 00 00 	mov    rcx,QWORD PTR [rip+0x7271]        # 1400090e0 <the_secs>
   140001e6f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e72:	48 63 d0             	movsxd rdx,eax
   140001e75:	48 89 d0             	mov    rax,rdx
   140001e78:	48 c1 e0 02          	shl    rax,0x2
   140001e7c:	48 01 d0             	add    rax,rdx
   140001e7f:	48 c1 e0 03          	shl    rax,0x3
   140001e83:	48 01 c8             	add    rax,rcx
   140001e86:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001e8a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001e8e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001e91:	89 c1                	mov    ecx,eax
   140001e93:	48 8d 05 76 33 00 00 	lea    rax,[rip+0x3376]        # 140005210 <.rdata+0x40>
   140001e9a:	49 89 d0             	mov    r8,rdx
   140001e9d:	89 ca                	mov    edx,ecx
   140001e9f:	48 89 c1             	mov    rcx,rax
   140001ea2:	e8 c9 fd ff ff       	call   140001c70 <__report_error>
   140001ea7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001eaa:	83 f8 40             	cmp    eax,0x40
   140001ead:	0f 84 e8 00 00 00    	je     140001f9b <mark_section_writable+0x2c6>
   140001eb3:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001eb6:	83 f8 04             	cmp    eax,0x4
   140001eb9:	0f 84 dc 00 00 00    	je     140001f9b <mark_section_writable+0x2c6>
   140001ebf:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001ec2:	3d 80 00 00 00       	cmp    eax,0x80
   140001ec7:	0f 84 ce 00 00 00    	je     140001f9b <mark_section_writable+0x2c6>
   140001ecd:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001ed0:	83 f8 08             	cmp    eax,0x8
   140001ed3:	0f 84 c2 00 00 00    	je     140001f9b <mark_section_writable+0x2c6>
   140001ed9:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001edc:	83 f8 02             	cmp    eax,0x2
   140001edf:	75 09                	jne    140001eea <mark_section_writable+0x215>
   140001ee1:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001ee8:	eb 07                	jmp    140001ef1 <mark_section_writable+0x21c>
   140001eea:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001ef1:	48 8b 0d e8 71 00 00 	mov    rcx,QWORD PTR [rip+0x71e8]        # 1400090e0 <the_secs>
   140001ef8:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001efb:	48 63 d0             	movsxd rdx,eax
   140001efe:	48 89 d0             	mov    rax,rdx
   140001f01:	48 c1 e0 02          	shl    rax,0x2
   140001f05:	48 01 d0             	add    rax,rdx
   140001f08:	48 c1 e0 03          	shl    rax,0x3
   140001f0c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001f10:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001f14:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001f18:	48 8b 0d c1 71 00 00 	mov    rcx,QWORD PTR [rip+0x71c1]        # 1400090e0 <the_secs>
   140001f1f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f22:	48 63 d0             	movsxd rdx,eax
   140001f25:	48 89 d0             	mov    rax,rdx
   140001f28:	48 c1 e0 02          	shl    rax,0x2
   140001f2c:	48 01 d0             	add    rax,rdx
   140001f2f:	48 c1 e0 03          	shl    rax,0x3
   140001f33:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001f37:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001f3b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001f3f:	48 8b 0d 9a 71 00 00 	mov    rcx,QWORD PTR [rip+0x719a]        # 1400090e0 <the_secs>
   140001f46:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f49:	48 63 d0             	movsxd rdx,eax
   140001f4c:	48 89 d0             	mov    rax,rdx
   140001f4f:	48 c1 e0 02          	shl    rax,0x2
   140001f53:	48 01 d0             	add    rax,rdx
   140001f56:	48 c1 e0 03          	shl    rax,0x3
   140001f5a:	48 01 c8             	add    rax,rcx
   140001f5d:	49 89 c0             	mov    r8,rax
   140001f60:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001f64:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001f68:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001f6b:	4d 89 c1             	mov    r9,r8
   140001f6e:	41 89 c8             	mov    r8d,ecx
   140001f71:	48 89 c1             	mov    rcx,rax
   140001f74:	48 8b 05 75 82 00 00 	mov    rax,QWORD PTR [rip+0x8275]        # 14000a1f0 <__imp_VirtualProtect>
   140001f7b:	ff d0                	call   rax
   140001f7d:	85 c0                	test   eax,eax
   140001f7f:	75 1a                	jne    140001f9b <mark_section_writable+0x2c6>
   140001f81:	48 8b 05 20 82 00 00 	mov    rax,QWORD PTR [rip+0x8220]        # 14000a1a8 <__imp_GetLastError>
   140001f88:	ff d0                	call   rax
   140001f8a:	89 c2                	mov    edx,eax
   140001f8c:	48 8d 05 b5 32 00 00 	lea    rax,[rip+0x32b5]        # 140005248 <.rdata+0x78>
   140001f93:	48 89 c1             	mov    rcx,rax
   140001f96:	e8 d5 fc ff ff       	call   140001c70 <__report_error>
   140001f9b:	8b 05 47 71 00 00    	mov    eax,DWORD PTR [rip+0x7147]        # 1400090e8 <maxSections>
   140001fa1:	83 c0 01             	add    eax,0x1
   140001fa4:	89 05 3e 71 00 00    	mov    DWORD PTR [rip+0x713e],eax        # 1400090e8 <maxSections>
   140001faa:	eb 01                	jmp    140001fad <mark_section_writable+0x2d8>
   140001fac:	90                   	nop
   140001fad:	48 83 c4 60          	add    rsp,0x60
   140001fb1:	5d                   	pop    rbp
   140001fb2:	c3                   	ret

0000000140001fb3 <restore_modified_sections>:
   140001fb3:	55                   	push   rbp
   140001fb4:	48 89 e5             	mov    rbp,rsp
   140001fb7:	48 83 ec 30          	sub    rsp,0x30
   140001fbb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001fc2:	e9 ad 00 00 00       	jmp    140002074 <restore_modified_sections+0xc1>
   140001fc7:	48 8b 0d 12 71 00 00 	mov    rcx,QWORD PTR [rip+0x7112]        # 1400090e0 <the_secs>
   140001fce:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001fd1:	48 63 d0             	movsxd rdx,eax
   140001fd4:	48 89 d0             	mov    rax,rdx
   140001fd7:	48 c1 e0 02          	shl    rax,0x2
   140001fdb:	48 01 d0             	add    rax,rdx
   140001fde:	48 c1 e0 03          	shl    rax,0x3
   140001fe2:	48 01 c8             	add    rax,rcx
   140001fe5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fe7:	85 c0                	test   eax,eax
   140001fe9:	0f 84 80 00 00 00    	je     14000206f <restore_modified_sections+0xbc>
   140001fef:	48 8b 0d ea 70 00 00 	mov    rcx,QWORD PTR [rip+0x70ea]        # 1400090e0 <the_secs>
   140001ff6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ff9:	48 63 d0             	movsxd rdx,eax
   140001ffc:	48 89 d0             	mov    rax,rdx
   140001fff:	48 c1 e0 02          	shl    rax,0x2
   140002003:	48 01 d0             	add    rax,rdx
   140002006:	48 c1 e0 03          	shl    rax,0x3
   14000200a:	48 01 c8             	add    rax,rcx
   14000200d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140002010:	48 8b 0d c9 70 00 00 	mov    rcx,QWORD PTR [rip+0x70c9]        # 1400090e0 <the_secs>
   140002017:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000201a:	48 63 d0             	movsxd rdx,eax
   14000201d:	48 89 d0             	mov    rax,rdx
   140002020:	48 c1 e0 02          	shl    rax,0x2
   140002024:	48 01 d0             	add    rax,rdx
   140002027:	48 c1 e0 03          	shl    rax,0x3
   14000202b:	48 01 c8             	add    rax,rcx
   14000202e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140002032:	4c 8b 05 a7 70 00 00 	mov    r8,QWORD PTR [rip+0x70a7]        # 1400090e0 <the_secs>
   140002039:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000203c:	48 63 d0             	movsxd rdx,eax
   14000203f:	48 89 d0             	mov    rax,rdx
   140002042:	48 c1 e0 02          	shl    rax,0x2
   140002046:	48 01 d0             	add    rax,rdx
   140002049:	48 c1 e0 03          	shl    rax,0x3
   14000204d:	4c 01 c0             	add    rax,r8
   140002050:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140002054:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140002058:	49 89 d1             	mov    r9,rdx
   14000205b:	45 89 d0             	mov    r8d,r10d
   14000205e:	48 89 ca             	mov    rdx,rcx
   140002061:	48 89 c1             	mov    rcx,rax
   140002064:	48 8b 05 85 81 00 00 	mov    rax,QWORD PTR [rip+0x8185]        # 14000a1f0 <__imp_VirtualProtect>
   14000206b:	ff d0                	call   rax
   14000206d:	eb 01                	jmp    140002070 <restore_modified_sections+0xbd>
   14000206f:	90                   	nop
   140002070:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140002074:	8b 05 6e 70 00 00    	mov    eax,DWORD PTR [rip+0x706e]        # 1400090e8 <maxSections>
   14000207a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   14000207d:	0f 8c 44 ff ff ff    	jl     140001fc7 <restore_modified_sections+0x14>
   140002083:	90                   	nop
   140002084:	90                   	nop
   140002085:	48 83 c4 30          	add    rsp,0x30
   140002089:	5d                   	pop    rbp
   14000208a:	c3                   	ret

000000014000208b <__write_memory>:
   14000208b:	55                   	push   rbp
   14000208c:	48 89 e5             	mov    rbp,rsp
   14000208f:	48 83 ec 20          	sub    rsp,0x20
   140002093:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002097:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000209b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000209f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400020a4:	74 25                	je     1400020cb <__write_memory+0x40>
   1400020a6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400020aa:	48 89 c1             	mov    rcx,rax
   1400020ad:	e8 23 fc ff ff       	call   140001cd5 <mark_section_writable>
   1400020b2:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400020b6:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400020ba:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400020be:	49 89 c8             	mov    r8,rcx
   1400020c1:	48 89 c1             	mov    rcx,rax
   1400020c4:	e8 37 13 00 00       	call   140003400 <memcpy>
   1400020c9:	eb 01                	jmp    1400020cc <__write_memory+0x41>
   1400020cb:	90                   	nop
   1400020cc:	48 83 c4 20          	add    rsp,0x20
   1400020d0:	5d                   	pop    rbp
   1400020d1:	c3                   	ret

00000001400020d2 <do_pseudo_reloc>:
   1400020d2:	55                   	push   rbp
   1400020d3:	48 89 e5             	mov    rbp,rsp
   1400020d6:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   1400020da:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400020de:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400020e2:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400020e6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400020ea:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   1400020ee:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020f2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400020f6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400020fa:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   1400020ff:	0f 8e 44 03 00 00    	jle    140002449 <do_pseudo_reloc+0x377>
   140002105:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000210a:	7e 25                	jle    140002131 <do_pseudo_reloc+0x5f>
   14000210c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002110:	8b 00                	mov    eax,DWORD PTR [rax]
   140002112:	85 c0                	test   eax,eax
   140002114:	75 1b                	jne    140002131 <do_pseudo_reloc+0x5f>
   140002116:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000211a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000211d:	85 c0                	test   eax,eax
   14000211f:	75 10                	jne    140002131 <do_pseudo_reloc+0x5f>
   140002121:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002125:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002128:	85 c0                	test   eax,eax
   14000212a:	75 05                	jne    140002131 <do_pseudo_reloc+0x5f>
   14000212c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002131:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002135:	8b 00                	mov    eax,DWORD PTR [rax]
   140002137:	85 c0                	test   eax,eax
   140002139:	75 0b                	jne    140002146 <do_pseudo_reloc+0x74>
   14000213b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000213f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002142:	85 c0                	test   eax,eax
   140002144:	74 59                	je     14000219f <do_pseudo_reloc+0xcd>
   140002146:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000214a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000214e:	eb 40                	jmp    140002190 <do_pseudo_reloc+0xbe>
   140002150:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002154:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002157:	89 c2                	mov    edx,eax
   140002159:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000215d:	48 01 d0             	add    rax,rdx
   140002160:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002164:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002168:	8b 10                	mov    edx,DWORD PTR [rax]
   14000216a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000216e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002170:	01 d0                	add    eax,edx
   140002172:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002175:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002179:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000217d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002183:	48 89 c1             	mov    rcx,rax
   140002186:	e8 00 ff ff ff       	call   14000208b <__write_memory>
   14000218b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002190:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002194:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002198:	72 b6                	jb     140002150 <do_pseudo_reloc+0x7e>
   14000219a:	e9 ab 02 00 00       	jmp    14000244a <do_pseudo_reloc+0x378>
   14000219f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021a3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021a6:	83 f8 01             	cmp    eax,0x1
   1400021a9:	74 18                	je     1400021c3 <do_pseudo_reloc+0xf1>
   1400021ab:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021af:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021b2:	89 c2                	mov    edx,eax
   1400021b4:	48 8d 05 b5 30 00 00 	lea    rax,[rip+0x30b5]        # 140005270 <.rdata+0xa0>
   1400021bb:	48 89 c1             	mov    rcx,rax
   1400021be:	e8 ad fa ff ff       	call   140001c70 <__report_error>
   1400021c3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021c7:	48 83 c0 0c          	add    rax,0xc
   1400021cb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400021cf:	e9 65 02 00 00       	jmp    140002439 <do_pseudo_reloc+0x367>
   1400021d4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021d8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400021db:	89 c2                	mov    edx,eax
   1400021dd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400021e1:	48 01 d0             	add    rax,rdx
   1400021e4:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400021e8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021ec:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021ee:	89 c2                	mov    edx,eax
   1400021f0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400021f4:	48 01 d0             	add    rax,rdx
   1400021f7:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400021fb:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400021ff:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002202:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002206:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000220a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000220d:	0f b6 c0             	movzx  eax,al
   140002210:	83 f8 40             	cmp    eax,0x40
   140002213:	0f 84 b6 00 00 00    	je     1400022cf <do_pseudo_reloc+0x1fd>
   140002219:	83 f8 40             	cmp    eax,0x40
   14000221c:	0f 87 ba 00 00 00    	ja     1400022dc <do_pseudo_reloc+0x20a>
   140002222:	83 f8 20             	cmp    eax,0x20
   140002225:	74 77                	je     14000229e <do_pseudo_reloc+0x1cc>
   140002227:	83 f8 20             	cmp    eax,0x20
   14000222a:	0f 87 ac 00 00 00    	ja     1400022dc <do_pseudo_reloc+0x20a>
   140002230:	83 f8 08             	cmp    eax,0x8
   140002233:	74 0a                	je     14000223f <do_pseudo_reloc+0x16d>
   140002235:	83 f8 10             	cmp    eax,0x10
   140002238:	74 38                	je     140002272 <do_pseudo_reloc+0x1a0>
   14000223a:	e9 9d 00 00 00       	jmp    1400022dc <do_pseudo_reloc+0x20a>
   14000223f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002243:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002246:	0f b6 c0             	movzx  eax,al
   140002249:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000224d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002251:	25 80 00 00 00       	and    eax,0x80
   140002256:	48 85 c0             	test   rax,rax
   140002259:	0f 84 9d 00 00 00    	je     1400022fc <do_pseudo_reloc+0x22a>
   14000225f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002263:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002269:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000226d:	e9 8a 00 00 00       	jmp    1400022fc <do_pseudo_reloc+0x22a>
   140002272:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002276:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002279:	0f b7 c0             	movzx  eax,ax
   14000227c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002280:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002284:	25 00 80 00 00       	and    eax,0x8000
   140002289:	48 85 c0             	test   rax,rax
   14000228c:	74 71                	je     1400022ff <do_pseudo_reloc+0x22d>
   14000228e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002292:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002298:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000229c:	eb 61                	jmp    1400022ff <do_pseudo_reloc+0x22d>
   14000229e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022a2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400022a4:	89 c0                	mov    eax,eax
   1400022a6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022aa:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022ae:	25 00 00 00 80       	and    eax,0x80000000
   1400022b3:	48 85 c0             	test   rax,rax
   1400022b6:	74 4a                	je     140002302 <do_pseudo_reloc+0x230>
   1400022b8:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022bc:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   1400022c3:	ff ff ff 
   1400022c6:	48 09 d0             	or     rax,rdx
   1400022c9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022cd:	eb 33                	jmp    140002302 <do_pseudo_reloc+0x230>
   1400022cf:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022d3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400022d6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022da:	eb 27                	jmp    140002303 <do_pseudo_reloc+0x231>
   1400022dc:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   1400022e3:	00 
   1400022e4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022e8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022eb:	0f b6 c0             	movzx  eax,al
   1400022ee:	48 8d 0d b3 2f 00 00 	lea    rcx,[rip+0x2fb3]        # 1400052a8 <.rdata+0xd8>
   1400022f5:	89 c2                	mov    edx,eax
   1400022f7:	e8 74 f9 ff ff       	call   140001c70 <__report_error>
   1400022fc:	90                   	nop
   1400022fd:	eb 04                	jmp    140002303 <do_pseudo_reloc+0x231>
   1400022ff:	90                   	nop
   140002300:	eb 01                	jmp    140002303 <do_pseudo_reloc+0x231>
   140002302:	90                   	nop
   140002303:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002307:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000230b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000230d:	89 c2                	mov    edx,eax
   14000230f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002313:	48 01 c2             	add    rdx,rax
   140002316:	48 89 c8             	mov    rax,rcx
   140002319:	48 29 d0             	sub    rax,rdx
   14000231c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002320:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002324:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002328:	48 01 d0             	add    rax,rdx
   14000232b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000232f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002333:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002336:	25 ff 00 00 00       	and    eax,0xff
   14000233b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000233e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002342:	77 67                	ja     1400023ab <do_pseudo_reloc+0x2d9>
   140002344:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002347:	ba 01 00 00 00       	mov    edx,0x1
   14000234c:	89 c1                	mov    ecx,eax
   14000234e:	48 d3 e2             	shl    rdx,cl
   140002351:	48 89 d0             	mov    rax,rdx
   140002354:	48 83 e8 01          	sub    rax,0x1
   140002358:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000235c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000235f:	83 e8 01             	sub    eax,0x1
   140002362:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002369:	89 c1                	mov    ecx,eax
   14000236b:	48 d3 e2             	shl    rdx,cl
   14000236e:	48 89 d0             	mov    rax,rdx
   140002371:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002375:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002379:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000237d:	7c 0a                	jl     140002389 <do_pseudo_reloc+0x2b7>
   14000237f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002383:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002387:	7e 22                	jle    1400023ab <do_pseudo_reloc+0x2d9>
   140002389:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000238d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002391:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002395:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002398:	48 8d 0d 39 2f 00 00 	lea    rcx,[rip+0x2f39]        # 1400052d8 <.rdata+0x108>
   14000239f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400023a4:	89 c2                	mov    edx,eax
   1400023a6:	e8 c5 f8 ff ff       	call   140001c70 <__report_error>
   1400023ab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400023af:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400023b2:	0f b6 c0             	movzx  eax,al
   1400023b5:	83 f8 40             	cmp    eax,0x40
   1400023b8:	74 63                	je     14000241d <do_pseudo_reloc+0x34b>
   1400023ba:	83 f8 40             	cmp    eax,0x40
   1400023bd:	77 75                	ja     140002434 <do_pseudo_reloc+0x362>
   1400023bf:	83 f8 20             	cmp    eax,0x20
   1400023c2:	74 41                	je     140002405 <do_pseudo_reloc+0x333>
   1400023c4:	83 f8 20             	cmp    eax,0x20
   1400023c7:	77 6b                	ja     140002434 <do_pseudo_reloc+0x362>
   1400023c9:	83 f8 08             	cmp    eax,0x8
   1400023cc:	74 07                	je     1400023d5 <do_pseudo_reloc+0x303>
   1400023ce:	83 f8 10             	cmp    eax,0x10
   1400023d1:	74 1a                	je     1400023ed <do_pseudo_reloc+0x31b>
   1400023d3:	eb 5f                	jmp    140002434 <do_pseudo_reloc+0x362>
   1400023d5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400023d9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400023dd:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400023e3:	48 89 c1             	mov    rcx,rax
   1400023e6:	e8 a0 fc ff ff       	call   14000208b <__write_memory>
   1400023eb:	eb 47                	jmp    140002434 <do_pseudo_reloc+0x362>
   1400023ed:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400023f1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400023f5:	41 b8 02 00 00 00    	mov    r8d,0x2
   1400023fb:	48 89 c1             	mov    rcx,rax
   1400023fe:	e8 88 fc ff ff       	call   14000208b <__write_memory>
   140002403:	eb 2f                	jmp    140002434 <do_pseudo_reloc+0x362>
   140002405:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002409:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000240d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002413:	48 89 c1             	mov    rcx,rax
   140002416:	e8 70 fc ff ff       	call   14000208b <__write_memory>
   14000241b:	eb 17                	jmp    140002434 <do_pseudo_reloc+0x362>
   14000241d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002421:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002425:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000242b:	48 89 c1             	mov    rcx,rax
   14000242e:	e8 58 fc ff ff       	call   14000208b <__write_memory>
   140002433:	90                   	nop
   140002434:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002439:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000243d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002441:	0f 82 8d fd ff ff    	jb     1400021d4 <do_pseudo_reloc+0x102>
   140002447:	eb 01                	jmp    14000244a <do_pseudo_reloc+0x378>
   140002449:	90                   	nop
   14000244a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000244e:	5d                   	pop    rbp
   14000244f:	c3                   	ret

0000000140002450 <_pei386_runtime_relocator>:
   140002450:	55                   	push   rbp
   140002451:	48 89 e5             	mov    rbp,rsp
   140002454:	48 83 ec 30          	sub    rsp,0x30
   140002458:	8b 05 8e 6c 00 00    	mov    eax,DWORD PTR [rip+0x6c8e]        # 1400090ec <was_init.0>
   14000245e:	85 c0                	test   eax,eax
   140002460:	0f 85 88 00 00 00    	jne    1400024ee <_pei386_runtime_relocator+0x9e>
   140002466:	8b 05 80 6c 00 00    	mov    eax,DWORD PTR [rip+0x6c80]        # 1400090ec <was_init.0>
   14000246c:	83 c0 01             	add    eax,0x1
   14000246f:	89 05 77 6c 00 00    	mov    DWORD PTR [rip+0x6c77],eax        # 1400090ec <was_init.0>
   140002475:	e8 21 0b 00 00       	call   140002f9b <__mingw_GetSectionCount>
   14000247a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000247d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002480:	48 63 d0             	movsxd rdx,eax
   140002483:	48 89 d0             	mov    rax,rdx
   140002486:	48 c1 e0 02          	shl    rax,0x2
   14000248a:	48 01 d0             	add    rax,rdx
   14000248d:	48 c1 e0 03          	shl    rax,0x3
   140002491:	48 83 c0 0f          	add    rax,0xf
   140002495:	48 c1 e8 04          	shr    rax,0x4
   140002499:	48 c1 e0 04          	shl    rax,0x4
   14000249d:	e8 7e 0d 00 00       	call   140003220 <___chkstk_ms>
   1400024a2:	48 29 c4             	sub    rsp,rax
   1400024a5:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400024aa:	48 83 c0 0f          	add    rax,0xf
   1400024ae:	48 c1 e8 04          	shr    rax,0x4
   1400024b2:	48 c1 e0 04          	shl    rax,0x4
   1400024b6:	48 89 05 23 6c 00 00 	mov    QWORD PTR [rip+0x6c23],rax        # 1400090e0 <the_secs>
   1400024bd:	c7 05 21 6c 00 00 00 	mov    DWORD PTR [rip+0x6c21],0x0        # 1400090e8 <maxSections>
   1400024c4:	00 00 00 
   1400024c7:	48 8b 0d 92 2e 00 00 	mov    rcx,QWORD PTR [rip+0x2e92]        # 140005360 <.refptr.__ImageBase>
   1400024ce:	48 8b 15 9b 2e 00 00 	mov    rdx,QWORD PTR [rip+0x2e9b]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   1400024d5:	48 8b 05 a4 2e 00 00 	mov    rax,QWORD PTR [rip+0x2ea4]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   1400024dc:	49 89 c8             	mov    r8,rcx
   1400024df:	48 89 c1             	mov    rcx,rax
   1400024e2:	e8 eb fb ff ff       	call   1400020d2 <do_pseudo_reloc>
   1400024e7:	e8 c7 fa ff ff       	call   140001fb3 <restore_modified_sections>
   1400024ec:	eb 01                	jmp    1400024ef <_pei386_runtime_relocator+0x9f>
   1400024ee:	90                   	nop
   1400024ef:	48 89 ec             	mov    rsp,rbp
   1400024f2:	5d                   	pop    rbp
   1400024f3:	c3                   	ret
   1400024f4:	90                   	nop
   1400024f5:	90                   	nop
   1400024f6:	90                   	nop
   1400024f7:	90                   	nop
   1400024f8:	90                   	nop
   1400024f9:	90                   	nop
   1400024fa:	90                   	nop
   1400024fb:	90                   	nop
   1400024fc:	90                   	nop
   1400024fd:	90                   	nop
   1400024fe:	90                   	nop
   1400024ff:	90                   	nop

0000000140002500 <__mingw_raise_matherr>:
   140002500:	55                   	push   rbp
   140002501:	48 89 e5             	mov    rbp,rsp
   140002504:	48 83 ec 50          	sub    rsp,0x50
   140002508:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000250b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000250f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002514:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002519:	48 8b 05 d0 6b 00 00 	mov    rax,QWORD PTR [rip+0x6bd0]        # 1400090f0 <stUserMathErr>
   140002520:	48 85 c0             	test   rax,rax
   140002523:	74 3e                	je     140002563 <__mingw_raise_matherr+0x63>
   140002525:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002528:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000252b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000252f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002533:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002538:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000253d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002542:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002547:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000254c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002551:	48 8b 15 98 6b 00 00 	mov    rdx,QWORD PTR [rip+0x6b98]        # 1400090f0 <stUserMathErr>
   140002558:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000255c:	48 89 c1             	mov    rcx,rax
   14000255f:	ff d2                	call   rdx
   140002561:	eb 01                	jmp    140002564 <__mingw_raise_matherr+0x64>
   140002563:	90                   	nop
   140002564:	48 83 c4 50          	add    rsp,0x50
   140002568:	5d                   	pop    rbp
   140002569:	c3                   	ret

000000014000256a <__mingw_setusermatherr>:
   14000256a:	55                   	push   rbp
   14000256b:	48 89 e5             	mov    rbp,rsp
   14000256e:	48 83 ec 20          	sub    rsp,0x20
   140002572:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002576:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000257a:	48 89 05 6f 6b 00 00 	mov    QWORD PTR [rip+0x6b6f],rax        # 1400090f0 <stUserMathErr>
   140002581:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002585:	48 89 c1             	mov    rcx,rax
   140002588:	e8 13 0e 00 00       	call   1400033a0 <__setusermatherr>
   14000258d:	90                   	nop
   14000258e:	48 83 c4 20          	add    rsp,0x20
   140002592:	5d                   	pop    rbp
   140002593:	c3                   	ret
   140002594:	90                   	nop
   140002595:	90                   	nop
   140002596:	90                   	nop
   140002597:	90                   	nop
   140002598:	90                   	nop
   140002599:	90                   	nop
   14000259a:	90                   	nop
   14000259b:	90                   	nop
   14000259c:	90                   	nop
   14000259d:	90                   	nop
   14000259e:	90                   	nop
   14000259f:	90                   	nop

00000001400025a0 <__mingw_SEH_error_handler>:
   1400025a0:	55                   	push   rbp
   1400025a1:	48 89 e5             	mov    rbp,rsp
   1400025a4:	48 83 ec 30          	sub    rsp,0x30
   1400025a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400025ac:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400025b0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400025b4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400025b8:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400025bf:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400025c6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400025ca:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400025cd:	83 e0 02             	and    eax,0x2
   1400025d0:	85 c0                	test   eax,eax
   1400025d2:	74 0a                	je     1400025de <__mingw_SEH_error_handler+0x3e>
   1400025d4:	b8 01 00 00 00       	mov    eax,0x1
   1400025d9:	e9 16 02 00 00       	jmp    1400027f4 <__mingw_SEH_error_handler+0x254>
   1400025de:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400025e2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400025e4:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400025e9:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400025ee:	75 18                	jne    140002608 <__mingw_SEH_error_handler+0x68>
   1400025f0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400025f4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400025f7:	83 e0 01             	and    eax,0x1
   1400025fa:	85 c0                	test   eax,eax
   1400025fc:	75 0a                	jne    140002608 <__mingw_SEH_error_handler+0x68>
   1400025fe:	b8 00 00 00 00       	mov    eax,0x0
   140002603:	e9 ec 01 00 00       	jmp    1400027f4 <__mingw_SEH_error_handler+0x254>
   140002608:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000260c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000260e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002613:	0f 84 12 01 00 00    	je     14000272b <__mingw_SEH_error_handler+0x18b>
   140002619:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000261e:	0f 87 c3 01 00 00    	ja     1400027e7 <__mingw_SEH_error_handler+0x247>
   140002624:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002629:	0f 87 b8 01 00 00    	ja     1400027e7 <__mingw_SEH_error_handler+0x247>
   14000262f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002634:	0f 83 4c 01 00 00    	jae    140002786 <__mingw_SEH_error_handler+0x1e6>
   14000263a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000263f:	0f 84 3a 01 00 00    	je     14000277f <__mingw_SEH_error_handler+0x1df>
   140002645:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000264a:	0f 87 97 01 00 00    	ja     1400027e7 <__mingw_SEH_error_handler+0x247>
   140002650:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002655:	0f 84 83 01 00 00    	je     1400027de <__mingw_SEH_error_handler+0x23e>
   14000265b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002660:	0f 87 81 01 00 00    	ja     1400027e7 <__mingw_SEH_error_handler+0x247>
   140002666:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000266b:	0f 87 76 01 00 00    	ja     1400027e7 <__mingw_SEH_error_handler+0x247>
   140002671:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002676:	0f 83 03 01 00 00    	jae    14000277f <__mingw_SEH_error_handler+0x1df>
   14000267c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002681:	0f 84 57 01 00 00    	je     1400027de <__mingw_SEH_error_handler+0x23e>
   140002687:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000268c:	0f 87 55 01 00 00    	ja     1400027e7 <__mingw_SEH_error_handler+0x247>
   140002692:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002697:	0f 84 8e 00 00 00    	je     14000272b <__mingw_SEH_error_handler+0x18b>
   14000269d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400026a2:	0f 87 3f 01 00 00    	ja     1400027e7 <__mingw_SEH_error_handler+0x247>
   1400026a8:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400026ad:	0f 84 2b 01 00 00    	je     1400027de <__mingw_SEH_error_handler+0x23e>
   1400026b3:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400026b8:	0f 87 29 01 00 00    	ja     1400027e7 <__mingw_SEH_error_handler+0x247>
   1400026be:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400026c3:	0f 84 15 01 00 00    	je     1400027de <__mingw_SEH_error_handler+0x23e>
   1400026c9:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400026ce:	0f 85 13 01 00 00    	jne    1400027e7 <__mingw_SEH_error_handler+0x247>
   1400026d4:	ba 00 00 00 00       	mov    edx,0x0
   1400026d9:	b9 0b 00 00 00       	mov    ecx,0xb
   1400026de:	e8 35 0d 00 00       	call   140003418 <signal>
   1400026e3:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026e7:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026ec:	75 1b                	jne    140002709 <__mingw_SEH_error_handler+0x169>
   1400026ee:	ba 01 00 00 00       	mov    edx,0x1
   1400026f3:	b9 0b 00 00 00       	mov    ecx,0xb
   1400026f8:	e8 1b 0d 00 00       	call   140003418 <signal>
   1400026fd:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002704:	e9 e1 00 00 00       	jmp    1400027ea <__mingw_SEH_error_handler+0x24a>
   140002709:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000270e:	0f 84 d6 00 00 00    	je     1400027ea <__mingw_SEH_error_handler+0x24a>
   140002714:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002718:	b9 0b 00 00 00       	mov    ecx,0xb
   14000271d:	ff d0                	call   rax
   14000271f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002726:	e9 bf 00 00 00       	jmp    1400027ea <__mingw_SEH_error_handler+0x24a>
   14000272b:	ba 00 00 00 00       	mov    edx,0x0
   140002730:	b9 04 00 00 00       	mov    ecx,0x4
   140002735:	e8 de 0c 00 00       	call   140003418 <signal>
   14000273a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000273e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002743:	75 1b                	jne    140002760 <__mingw_SEH_error_handler+0x1c0>
   140002745:	ba 01 00 00 00       	mov    edx,0x1
   14000274a:	b9 04 00 00 00       	mov    ecx,0x4
   14000274f:	e8 c4 0c 00 00       	call   140003418 <signal>
   140002754:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000275b:	e9 8d 00 00 00       	jmp    1400027ed <__mingw_SEH_error_handler+0x24d>
   140002760:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002765:	0f 84 82 00 00 00    	je     1400027ed <__mingw_SEH_error_handler+0x24d>
   14000276b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000276f:	b9 04 00 00 00       	mov    ecx,0x4
   140002774:	ff d0                	call   rax
   140002776:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000277d:	eb 6e                	jmp    1400027ed <__mingw_SEH_error_handler+0x24d>
   14000277f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002786:	ba 00 00 00 00       	mov    edx,0x0
   14000278b:	b9 08 00 00 00       	mov    ecx,0x8
   140002790:	e8 83 0c 00 00       	call   140003418 <signal>
   140002795:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002799:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000279e:	75 23                	jne    1400027c3 <__mingw_SEH_error_handler+0x223>
   1400027a0:	ba 01 00 00 00       	mov    edx,0x1
   1400027a5:	b9 08 00 00 00       	mov    ecx,0x8
   1400027aa:	e8 69 0c 00 00       	call   140003418 <signal>
   1400027af:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400027b3:	74 05                	je     1400027ba <__mingw_SEH_error_handler+0x21a>
   1400027b5:	e8 a6 05 00 00       	call   140002d60 <_fpreset>
   1400027ba:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400027c1:	eb 2d                	jmp    1400027f0 <__mingw_SEH_error_handler+0x250>
   1400027c3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027c8:	74 26                	je     1400027f0 <__mingw_SEH_error_handler+0x250>
   1400027ca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027ce:	b9 08 00 00 00       	mov    ecx,0x8
   1400027d3:	ff d0                	call   rax
   1400027d5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400027dc:	eb 12                	jmp    1400027f0 <__mingw_SEH_error_handler+0x250>
   1400027de:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400027e5:	eb 0a                	jmp    1400027f1 <__mingw_SEH_error_handler+0x251>
   1400027e7:	90                   	nop
   1400027e8:	eb 07                	jmp    1400027f1 <__mingw_SEH_error_handler+0x251>
   1400027ea:	90                   	nop
   1400027eb:	eb 04                	jmp    1400027f1 <__mingw_SEH_error_handler+0x251>
   1400027ed:	90                   	nop
   1400027ee:	eb 01                	jmp    1400027f1 <__mingw_SEH_error_handler+0x251>
   1400027f0:	90                   	nop
   1400027f1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400027f4:	48 83 c4 30          	add    rsp,0x30
   1400027f8:	5d                   	pop    rbp
   1400027f9:	c3                   	ret

00000001400027fa <_gnu_exception_handler>:
   1400027fa:	55                   	push   rbp
   1400027fb:	48 89 e5             	mov    rbp,rsp
   1400027fe:	48 83 ec 30          	sub    rsp,0x30
   140002802:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002806:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000280d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002814:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002818:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000281b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000281d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002822:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002827:	75 1b                	jne    140002844 <_gnu_exception_handler+0x4a>
   140002829:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000282d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002830:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002833:	83 e0 01             	and    eax,0x1
   140002836:	85 c0                	test   eax,eax
   140002838:	75 0a                	jne    140002844 <_gnu_exception_handler+0x4a>
   14000283a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000283f:	e9 14 02 00 00       	jmp    140002a58 <_gnu_exception_handler+0x25e>
   140002844:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002848:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000284b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000284d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002852:	0f 84 12 01 00 00    	je     14000296a <_gnu_exception_handler+0x170>
   140002858:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000285d:	0f 87 c3 01 00 00    	ja     140002a26 <_gnu_exception_handler+0x22c>
   140002863:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002868:	0f 87 b8 01 00 00    	ja     140002a26 <_gnu_exception_handler+0x22c>
   14000286e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002873:	0f 83 4c 01 00 00    	jae    1400029c5 <_gnu_exception_handler+0x1cb>
   140002879:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000287e:	0f 84 3a 01 00 00    	je     1400029be <_gnu_exception_handler+0x1c4>
   140002884:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002889:	0f 87 97 01 00 00    	ja     140002a26 <_gnu_exception_handler+0x22c>
   14000288f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002894:	0f 84 83 01 00 00    	je     140002a1d <_gnu_exception_handler+0x223>
   14000289a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000289f:	0f 87 81 01 00 00    	ja     140002a26 <_gnu_exception_handler+0x22c>
   1400028a5:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400028aa:	0f 87 76 01 00 00    	ja     140002a26 <_gnu_exception_handler+0x22c>
   1400028b0:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400028b5:	0f 83 03 01 00 00    	jae    1400029be <_gnu_exception_handler+0x1c4>
   1400028bb:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400028c0:	0f 84 57 01 00 00    	je     140002a1d <_gnu_exception_handler+0x223>
   1400028c6:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400028cb:	0f 87 55 01 00 00    	ja     140002a26 <_gnu_exception_handler+0x22c>
   1400028d1:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400028d6:	0f 84 8e 00 00 00    	je     14000296a <_gnu_exception_handler+0x170>
   1400028dc:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400028e1:	0f 87 3f 01 00 00    	ja     140002a26 <_gnu_exception_handler+0x22c>
   1400028e7:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400028ec:	0f 84 2b 01 00 00    	je     140002a1d <_gnu_exception_handler+0x223>
   1400028f2:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400028f7:	0f 87 29 01 00 00    	ja     140002a26 <_gnu_exception_handler+0x22c>
   1400028fd:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002902:	0f 84 15 01 00 00    	je     140002a1d <_gnu_exception_handler+0x223>
   140002908:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000290d:	0f 85 13 01 00 00    	jne    140002a26 <_gnu_exception_handler+0x22c>
   140002913:	ba 00 00 00 00       	mov    edx,0x0
   140002918:	b9 0b 00 00 00       	mov    ecx,0xb
   14000291d:	e8 f6 0a 00 00       	call   140003418 <signal>
   140002922:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002926:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000292b:	75 1b                	jne    140002948 <_gnu_exception_handler+0x14e>
   14000292d:	ba 01 00 00 00       	mov    edx,0x1
   140002932:	b9 0b 00 00 00       	mov    ecx,0xb
   140002937:	e8 dc 0a 00 00       	call   140003418 <signal>
   14000293c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002943:	e9 e1 00 00 00       	jmp    140002a29 <_gnu_exception_handler+0x22f>
   140002948:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000294d:	0f 84 d6 00 00 00    	je     140002a29 <_gnu_exception_handler+0x22f>
   140002953:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002957:	b9 0b 00 00 00       	mov    ecx,0xb
   14000295c:	ff d0                	call   rax
   14000295e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002965:	e9 bf 00 00 00       	jmp    140002a29 <_gnu_exception_handler+0x22f>
   14000296a:	ba 00 00 00 00       	mov    edx,0x0
   14000296f:	b9 04 00 00 00       	mov    ecx,0x4
   140002974:	e8 9f 0a 00 00       	call   140003418 <signal>
   140002979:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000297d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002982:	75 1b                	jne    14000299f <_gnu_exception_handler+0x1a5>
   140002984:	ba 01 00 00 00       	mov    edx,0x1
   140002989:	b9 04 00 00 00       	mov    ecx,0x4
   14000298e:	e8 85 0a 00 00       	call   140003418 <signal>
   140002993:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000299a:	e9 8d 00 00 00       	jmp    140002a2c <_gnu_exception_handler+0x232>
   14000299f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400029a4:	0f 84 82 00 00 00    	je     140002a2c <_gnu_exception_handler+0x232>
   1400029aa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ae:	b9 04 00 00 00       	mov    ecx,0x4
   1400029b3:	ff d0                	call   rax
   1400029b5:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400029bc:	eb 6e                	jmp    140002a2c <_gnu_exception_handler+0x232>
   1400029be:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400029c5:	ba 00 00 00 00       	mov    edx,0x0
   1400029ca:	b9 08 00 00 00       	mov    ecx,0x8
   1400029cf:	e8 44 0a 00 00       	call   140003418 <signal>
   1400029d4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029d8:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400029dd:	75 23                	jne    140002a02 <_gnu_exception_handler+0x208>
   1400029df:	ba 01 00 00 00       	mov    edx,0x1
   1400029e4:	b9 08 00 00 00       	mov    ecx,0x8
   1400029e9:	e8 2a 0a 00 00       	call   140003418 <signal>
   1400029ee:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400029f2:	74 05                	je     1400029f9 <_gnu_exception_handler+0x1ff>
   1400029f4:	e8 67 03 00 00       	call   140002d60 <_fpreset>
   1400029f9:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a00:	eb 2d                	jmp    140002a2f <_gnu_exception_handler+0x235>
   140002a02:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a07:	74 26                	je     140002a2f <_gnu_exception_handler+0x235>
   140002a09:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a0d:	b9 08 00 00 00       	mov    ecx,0x8
   140002a12:	ff d0                	call   rax
   140002a14:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a1b:	eb 12                	jmp    140002a2f <_gnu_exception_handler+0x235>
   140002a1d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a24:	eb 0a                	jmp    140002a30 <_gnu_exception_handler+0x236>
   140002a26:	90                   	nop
   140002a27:	eb 07                	jmp    140002a30 <_gnu_exception_handler+0x236>
   140002a29:	90                   	nop
   140002a2a:	eb 04                	jmp    140002a30 <_gnu_exception_handler+0x236>
   140002a2c:	90                   	nop
   140002a2d:	eb 01                	jmp    140002a30 <_gnu_exception_handler+0x236>
   140002a2f:	90                   	nop
   140002a30:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002a34:	75 1f                	jne    140002a55 <_gnu_exception_handler+0x25b>
   140002a36:	48 8b 05 d3 66 00 00 	mov    rax,QWORD PTR [rip+0x66d3]        # 140009110 <__mingw_oldexcpt_handler>
   140002a3d:	48 85 c0             	test   rax,rax
   140002a40:	74 13                	je     140002a55 <_gnu_exception_handler+0x25b>
   140002a42:	48 8b 15 c7 66 00 00 	mov    rdx,QWORD PTR [rip+0x66c7]        # 140009110 <__mingw_oldexcpt_handler>
   140002a49:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002a4d:	48 89 c1             	mov    rcx,rax
   140002a50:	ff d2                	call   rdx
   140002a52:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002a55:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002a58:	48 83 c4 30          	add    rsp,0x30
   140002a5c:	5d                   	pop    rbp
   140002a5d:	c3                   	ret
   140002a5e:	90                   	nop
   140002a5f:	90                   	nop

0000000140002a60 <___w64_mingwthr_add_key_dtor>:
   140002a60:	55                   	push   rbp
   140002a61:	48 89 e5             	mov    rbp,rsp
   140002a64:	48 83 ec 30          	sub    rsp,0x30
   140002a68:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a6b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002a6f:	8b 05 d3 66 00 00    	mov    eax,DWORD PTR [rip+0x66d3]        # 140009148 <__mingwthr_cs_init>
   140002a75:	85 c0                	test   eax,eax
   140002a77:	75 07                	jne    140002a80 <___w64_mingwthr_add_key_dtor+0x20>
   140002a79:	b8 00 00 00 00       	mov    eax,0x0
   140002a7e:	eb 7b                	jmp    140002afb <___w64_mingwthr_add_key_dtor+0x9b>
   140002a80:	ba 18 00 00 00       	mov    edx,0x18
   140002a85:	b9 01 00 00 00       	mov    ecx,0x1
   140002a8a:	e8 41 09 00 00       	call   1400033d0 <calloc>
   140002a8f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a93:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a98:	75 07                	jne    140002aa1 <___w64_mingwthr_add_key_dtor+0x41>
   140002a9a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140002a9f:	eb 5a                	jmp    140002afb <___w64_mingwthr_add_key_dtor+0x9b>
   140002aa1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002aa5:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002aa8:	89 10                	mov    DWORD PTR [rax],edx
   140002aaa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002aae:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002ab2:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002ab6:	48 8d 05 63 66 00 00 	lea    rax,[rip+0x6663]        # 140009120 <__mingwthr_cs>
   140002abd:	48 89 c1             	mov    rcx,rax
   140002ac0:	48 8b 05 d1 76 00 00 	mov    rax,QWORD PTR [rip+0x76d1]        # 14000a198 <__imp_EnterCriticalSection>
   140002ac7:	ff d0                	call   rax
   140002ac9:	48 8b 15 80 66 00 00 	mov    rdx,QWORD PTR [rip+0x6680]        # 140009150 <key_dtor_list>
   140002ad0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ad4:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002ad8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002adc:	48 89 05 6d 66 00 00 	mov    QWORD PTR [rip+0x666d],rax        # 140009150 <key_dtor_list>
   140002ae3:	48 8d 05 36 66 00 00 	lea    rax,[rip+0x6636]        # 140009120 <__mingwthr_cs>
   140002aea:	48 89 c1             	mov    rcx,rax
   140002aed:	48 8b 05 d4 76 00 00 	mov    rax,QWORD PTR [rip+0x76d4]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002af4:	ff d0                	call   rax
   140002af6:	b8 00 00 00 00       	mov    eax,0x0
   140002afb:	48 83 c4 30          	add    rsp,0x30
   140002aff:	5d                   	pop    rbp
   140002b00:	c3                   	ret

0000000140002b01 <___w64_mingwthr_remove_key_dtor>:
   140002b01:	55                   	push   rbp
   140002b02:	48 89 e5             	mov    rbp,rsp
   140002b05:	48 83 ec 30          	sub    rsp,0x30
   140002b09:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002b0c:	8b 05 36 66 00 00    	mov    eax,DWORD PTR [rip+0x6636]        # 140009148 <__mingwthr_cs_init>
   140002b12:	85 c0                	test   eax,eax
   140002b14:	75 0a                	jne    140002b20 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002b16:	b8 00 00 00 00       	mov    eax,0x0
   140002b1b:	e9 9c 00 00 00       	jmp    140002bbc <___w64_mingwthr_remove_key_dtor+0xbb>
   140002b20:	48 8d 05 f9 65 00 00 	lea    rax,[rip+0x65f9]        # 140009120 <__mingwthr_cs>
   140002b27:	48 89 c1             	mov    rcx,rax
   140002b2a:	48 8b 05 67 76 00 00 	mov    rax,QWORD PTR [rip+0x7667]        # 14000a198 <__imp_EnterCriticalSection>
   140002b31:	ff d0                	call   rax
   140002b33:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002b3a:	00 
   140002b3b:	48 8b 05 0e 66 00 00 	mov    rax,QWORD PTR [rip+0x660e]        # 140009150 <key_dtor_list>
   140002b42:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b46:	eb 55                	jmp    140002b9d <___w64_mingwthr_remove_key_dtor+0x9c>
   140002b48:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b4c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b4e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002b51:	75 36                	jne    140002b89 <___w64_mingwthr_remove_key_dtor+0x88>
   140002b53:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b58:	75 11                	jne    140002b6b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002b5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b5e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b62:	48 89 05 e7 65 00 00 	mov    QWORD PTR [rip+0x65e7],rax        # 140009150 <key_dtor_list>
   140002b69:	eb 10                	jmp    140002b7b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002b6b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b6f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002b73:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b77:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002b7b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b7f:	48 89 c1             	mov    rcx,rax
   140002b82:	e8 69 08 00 00       	call   1400033f0 <free>
   140002b87:	eb 1b                	jmp    140002ba4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002b89:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b8d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b91:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b95:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b99:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b9d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002ba2:	75 a4                	jne    140002b48 <___w64_mingwthr_remove_key_dtor+0x47>
   140002ba4:	48 8d 05 75 65 00 00 	lea    rax,[rip+0x6575]        # 140009120 <__mingwthr_cs>
   140002bab:	48 89 c1             	mov    rcx,rax
   140002bae:	48 8b 05 13 76 00 00 	mov    rax,QWORD PTR [rip+0x7613]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002bb5:	ff d0                	call   rax
   140002bb7:	b8 00 00 00 00       	mov    eax,0x0
   140002bbc:	48 83 c4 30          	add    rsp,0x30
   140002bc0:	5d                   	pop    rbp
   140002bc1:	c3                   	ret

0000000140002bc2 <__mingwthr_run_key_dtors>:
   140002bc2:	55                   	push   rbp
   140002bc3:	48 89 e5             	mov    rbp,rsp
   140002bc6:	48 83 ec 30          	sub    rsp,0x30
   140002bca:	8b 05 78 65 00 00    	mov    eax,DWORD PTR [rip+0x6578]        # 140009148 <__mingwthr_cs_init>
   140002bd0:	85 c0                	test   eax,eax
   140002bd2:	0f 84 82 00 00 00    	je     140002c5a <__mingwthr_run_key_dtors+0x98>
   140002bd8:	48 8d 05 41 65 00 00 	lea    rax,[rip+0x6541]        # 140009120 <__mingwthr_cs>
   140002bdf:	48 89 c1             	mov    rcx,rax
   140002be2:	48 8b 05 af 75 00 00 	mov    rax,QWORD PTR [rip+0x75af]        # 14000a198 <__imp_EnterCriticalSection>
   140002be9:	ff d0                	call   rax
   140002beb:	48 8b 05 5e 65 00 00 	mov    rax,QWORD PTR [rip+0x655e]        # 140009150 <key_dtor_list>
   140002bf2:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bf6:	eb 46                	jmp    140002c3e <__mingwthr_run_key_dtors+0x7c>
   140002bf8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bfc:	8b 00                	mov    eax,DWORD PTR [rax]
   140002bfe:	89 c1                	mov    ecx,eax
   140002c00:	48 8b 05 e1 75 00 00 	mov    rax,QWORD PTR [rip+0x75e1]        # 14000a1e8 <__imp_TlsGetValue>
   140002c07:	ff d0                	call   rax
   140002c09:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c0d:	48 8b 05 94 75 00 00 	mov    rax,QWORD PTR [rip+0x7594]        # 14000a1a8 <__imp_GetLastError>
   140002c14:	ff d0                	call   rax
   140002c16:	85 c0                	test   eax,eax
   140002c18:	75 18                	jne    140002c32 <__mingwthr_run_key_dtors+0x70>
   140002c1a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002c1f:	74 11                	je     140002c32 <__mingwthr_run_key_dtors+0x70>
   140002c21:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c25:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002c29:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c2d:	48 89 c1             	mov    rcx,rax
   140002c30:	ff d2                	call   rdx
   140002c32:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c36:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c3a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c3e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c43:	75 b3                	jne    140002bf8 <__mingwthr_run_key_dtors+0x36>
   140002c45:	48 8d 05 d4 64 00 00 	lea    rax,[rip+0x64d4]        # 140009120 <__mingwthr_cs>
   140002c4c:	48 89 c1             	mov    rcx,rax
   140002c4f:	48 8b 05 72 75 00 00 	mov    rax,QWORD PTR [rip+0x7572]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002c56:	ff d0                	call   rax
   140002c58:	eb 01                	jmp    140002c5b <__mingwthr_run_key_dtors+0x99>
   140002c5a:	90                   	nop
   140002c5b:	48 83 c4 30          	add    rsp,0x30
   140002c5f:	5d                   	pop    rbp
   140002c60:	c3                   	ret

0000000140002c61 <__mingw_TLScallback>:
   140002c61:	55                   	push   rbp
   140002c62:	48 89 e5             	mov    rbp,rsp
   140002c65:	48 83 ec 30          	sub    rsp,0x30
   140002c69:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c6d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002c70:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002c74:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002c78:	0f 84 cc 00 00 00    	je     140002d4a <__mingw_TLScallback+0xe9>
   140002c7e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002c82:	0f 87 ca 00 00 00    	ja     140002d52 <__mingw_TLScallback+0xf1>
   140002c88:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002c8c:	0f 84 b1 00 00 00    	je     140002d43 <__mingw_TLScallback+0xe2>
   140002c92:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002c96:	0f 87 b6 00 00 00    	ja     140002d52 <__mingw_TLScallback+0xf1>
   140002c9c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002ca0:	74 33                	je     140002cd5 <__mingw_TLScallback+0x74>
   140002ca2:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002ca6:	0f 85 a6 00 00 00    	jne    140002d52 <__mingw_TLScallback+0xf1>
   140002cac:	8b 05 96 64 00 00    	mov    eax,DWORD PTR [rip+0x6496]        # 140009148 <__mingwthr_cs_init>
   140002cb2:	85 c0                	test   eax,eax
   140002cb4:	75 13                	jne    140002cc9 <__mingw_TLScallback+0x68>
   140002cb6:	48 8d 05 63 64 00 00 	lea    rax,[rip+0x6463]        # 140009120 <__mingwthr_cs>
   140002cbd:	48 89 c1             	mov    rcx,rax
   140002cc0:	48 8b 05 f9 74 00 00 	mov    rax,QWORD PTR [rip+0x74f9]        # 14000a1c0 <__imp_InitializeCriticalSection>
   140002cc7:	ff d0                	call   rax
   140002cc9:	c7 05 75 64 00 00 01 	mov    DWORD PTR [rip+0x6475],0x1        # 140009148 <__mingwthr_cs_init>
   140002cd0:	00 00 00 
   140002cd3:	eb 7d                	jmp    140002d52 <__mingw_TLScallback+0xf1>
   140002cd5:	e8 e8 fe ff ff       	call   140002bc2 <__mingwthr_run_key_dtors>
   140002cda:	8b 05 68 64 00 00    	mov    eax,DWORD PTR [rip+0x6468]        # 140009148 <__mingwthr_cs_init>
   140002ce0:	83 f8 01             	cmp    eax,0x1
   140002ce3:	75 6c                	jne    140002d51 <__mingw_TLScallback+0xf0>
   140002ce5:	48 8b 05 64 64 00 00 	mov    rax,QWORD PTR [rip+0x6464]        # 140009150 <key_dtor_list>
   140002cec:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cf0:	eb 20                	jmp    140002d12 <__mingw_TLScallback+0xb1>
   140002cf2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cf6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002cfa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002cfe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d02:	48 89 c1             	mov    rcx,rax
   140002d05:	e8 e6 06 00 00       	call   1400033f0 <free>
   140002d0a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d0e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d12:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002d17:	75 d9                	jne    140002cf2 <__mingw_TLScallback+0x91>
   140002d19:	48 c7 05 2c 64 00 00 	mov    QWORD PTR [rip+0x642c],0x0        # 140009150 <key_dtor_list>
   140002d20:	00 00 00 00 
   140002d24:	c7 05 1a 64 00 00 00 	mov    DWORD PTR [rip+0x641a],0x0        # 140009148 <__mingwthr_cs_init>
   140002d2b:	00 00 00 
   140002d2e:	48 8d 05 eb 63 00 00 	lea    rax,[rip+0x63eb]        # 140009120 <__mingwthr_cs>
   140002d35:	48 89 c1             	mov    rcx,rax
   140002d38:	48 8b 05 51 74 00 00 	mov    rax,QWORD PTR [rip+0x7451]        # 14000a190 <__IAT_start__>
   140002d3f:	ff d0                	call   rax
   140002d41:	eb 0e                	jmp    140002d51 <__mingw_TLScallback+0xf0>
   140002d43:	e8 18 00 00 00       	call   140002d60 <_fpreset>
   140002d48:	eb 08                	jmp    140002d52 <__mingw_TLScallback+0xf1>
   140002d4a:	e8 73 fe ff ff       	call   140002bc2 <__mingwthr_run_key_dtors>
   140002d4f:	eb 01                	jmp    140002d52 <__mingw_TLScallback+0xf1>
   140002d51:	90                   	nop
   140002d52:	b8 01 00 00 00       	mov    eax,0x1
   140002d57:	48 83 c4 30          	add    rsp,0x30
   140002d5b:	5d                   	pop    rbp
   140002d5c:	c3                   	ret
   140002d5d:	90                   	nop
   140002d5e:	90                   	nop
   140002d5f:	90                   	nop

0000000140002d60 <_fpreset>:
   140002d60:	55                   	push   rbp
   140002d61:	48 89 e5             	mov    rbp,rsp
   140002d64:	db e3                	fninit
   140002d66:	90                   	nop
   140002d67:	5d                   	pop    rbp
   140002d68:	c3                   	ret
   140002d69:	90                   	nop
   140002d6a:	90                   	nop
   140002d6b:	90                   	nop
   140002d6c:	90                   	nop
   140002d6d:	90                   	nop
   140002d6e:	90                   	nop
   140002d6f:	90                   	nop

0000000140002d70 <_ValidateImageBase>:
   140002d70:	55                   	push   rbp
   140002d71:	48 89 e5             	mov    rbp,rsp
   140002d74:	48 83 ec 20          	sub    rsp,0x20
   140002d78:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d7c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d80:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d84:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d88:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d8b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002d8f:	74 07                	je     140002d98 <_ValidateImageBase+0x28>
   140002d91:	b8 00 00 00 00       	mov    eax,0x0
   140002d96:	eb 4e                	jmp    140002de6 <_ValidateImageBase+0x76>
   140002d98:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d9c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d9f:	48 63 d0             	movsxd rdx,eax
   140002da2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002da6:	48 01 d0             	add    rax,rdx
   140002da9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002dad:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002db1:	8b 00                	mov    eax,DWORD PTR [rax]
   140002db3:	3d 50 45 00 00       	cmp    eax,0x4550
   140002db8:	74 07                	je     140002dc1 <_ValidateImageBase+0x51>
   140002dba:	b8 00 00 00 00       	mov    eax,0x0
   140002dbf:	eb 25                	jmp    140002de6 <_ValidateImageBase+0x76>
   140002dc1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002dc5:	48 83 c0 18          	add    rax,0x18
   140002dc9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002dcd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dd1:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002dd4:	66 3d 0b 02          	cmp    ax,0x20b
   140002dd8:	74 07                	je     140002de1 <_ValidateImageBase+0x71>
   140002dda:	b8 00 00 00 00       	mov    eax,0x0
   140002ddf:	eb 05                	jmp    140002de6 <_ValidateImageBase+0x76>
   140002de1:	b8 01 00 00 00       	mov    eax,0x1
   140002de6:	48 83 c4 20          	add    rsp,0x20
   140002dea:	5d                   	pop    rbp
   140002deb:	c3                   	ret

0000000140002dec <_FindPESection>:
   140002dec:	55                   	push   rbp
   140002ded:	48 89 e5             	mov    rbp,rsp
   140002df0:	48 83 ec 20          	sub    rsp,0x20
   140002df4:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002df8:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002dfc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e00:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e03:	48 63 d0             	movsxd rdx,eax
   140002e06:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e0a:	48 01 d0             	add    rax,rdx
   140002e0d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e11:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e18:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e1c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e20:	0f b7 d0             	movzx  edx,ax
   140002e23:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e27:	48 01 d0             	add    rax,rdx
   140002e2a:	48 83 c0 18          	add    rax,0x18
   140002e2e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e32:	eb 36                	jmp    140002e6a <_FindPESection+0x7e>
   140002e34:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e38:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002e3b:	89 c0                	mov    eax,eax
   140002e3d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002e41:	72 1e                	jb     140002e61 <_FindPESection+0x75>
   140002e43:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e47:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002e4a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e4e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002e51:	01 d0                	add    eax,edx
   140002e53:	89 c0                	mov    eax,eax
   140002e55:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002e59:	73 06                	jae    140002e61 <_FindPESection+0x75>
   140002e5b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e5f:	eb 1e                	jmp    140002e7f <_FindPESection+0x93>
   140002e61:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e65:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e6a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e6e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e72:	0f b7 c0             	movzx  eax,ax
   140002e75:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e78:	72 ba                	jb     140002e34 <_FindPESection+0x48>
   140002e7a:	b8 00 00 00 00       	mov    eax,0x0
   140002e7f:	48 83 c4 20          	add    rsp,0x20
   140002e83:	5d                   	pop    rbp
   140002e84:	c3                   	ret

0000000140002e85 <_FindPESectionByName>:
   140002e85:	55                   	push   rbp
   140002e86:	48 89 e5             	mov    rbp,rsp
   140002e89:	48 83 ec 40          	sub    rsp,0x40
   140002e8d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e91:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e95:	48 89 c1             	mov    rcx,rax
   140002e98:	e8 83 05 00 00       	call   140003420 <strlen>
   140002e9d:	48 83 f8 08          	cmp    rax,0x8
   140002ea1:	76 0a                	jbe    140002ead <_FindPESectionByName+0x28>
   140002ea3:	b8 00 00 00 00       	mov    eax,0x0
   140002ea8:	e9 98 00 00 00       	jmp    140002f45 <_FindPESectionByName+0xc0>
   140002ead:	48 8b 05 ac 24 00 00 	mov    rax,QWORD PTR [rip+0x24ac]        # 140005360 <.refptr.__ImageBase>
   140002eb4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002eb8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ebc:	48 89 c1             	mov    rcx,rax
   140002ebf:	e8 ac fe ff ff       	call   140002d70 <_ValidateImageBase>
   140002ec4:	85 c0                	test   eax,eax
   140002ec6:	75 07                	jne    140002ecf <_FindPESectionByName+0x4a>
   140002ec8:	b8 00 00 00 00       	mov    eax,0x0
   140002ecd:	eb 76                	jmp    140002f45 <_FindPESectionByName+0xc0>
   140002ecf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ed3:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ed6:	48 63 d0             	movsxd rdx,eax
   140002ed9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002edd:	48 01 d0             	add    rax,rdx
   140002ee0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002ee4:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002eeb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002eef:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002ef3:	0f b7 d0             	movzx  edx,ax
   140002ef6:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002efa:	48 01 d0             	add    rax,rdx
   140002efd:	48 83 c0 18          	add    rax,0x18
   140002f01:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f05:	eb 29                	jmp    140002f30 <_FindPESectionByName+0xab>
   140002f07:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f0b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002f0f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002f15:	48 89 c1             	mov    rcx,rax
   140002f18:	e8 0b 05 00 00       	call   140003428 <strncmp>
   140002f1d:	85 c0                	test   eax,eax
   140002f1f:	75 06                	jne    140002f27 <_FindPESectionByName+0xa2>
   140002f21:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f25:	eb 1e                	jmp    140002f45 <_FindPESectionByName+0xc0>
   140002f27:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f2b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f30:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f34:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f38:	0f b7 c0             	movzx  eax,ax
   140002f3b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f3e:	72 c7                	jb     140002f07 <_FindPESectionByName+0x82>
   140002f40:	b8 00 00 00 00       	mov    eax,0x0
   140002f45:	48 83 c4 40          	add    rsp,0x40
   140002f49:	5d                   	pop    rbp
   140002f4a:	c3                   	ret

0000000140002f4b <__mingw_GetSectionForAddress>:
   140002f4b:	55                   	push   rbp
   140002f4c:	48 89 e5             	mov    rbp,rsp
   140002f4f:	48 83 ec 30          	sub    rsp,0x30
   140002f53:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f57:	48 8b 05 02 24 00 00 	mov    rax,QWORD PTR [rip+0x2402]        # 140005360 <.refptr.__ImageBase>
   140002f5e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f62:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f66:	48 89 c1             	mov    rcx,rax
   140002f69:	e8 02 fe ff ff       	call   140002d70 <_ValidateImageBase>
   140002f6e:	85 c0                	test   eax,eax
   140002f70:	75 07                	jne    140002f79 <__mingw_GetSectionForAddress+0x2e>
   140002f72:	b8 00 00 00 00       	mov    eax,0x0
   140002f77:	eb 1c                	jmp    140002f95 <__mingw_GetSectionForAddress+0x4a>
   140002f79:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f7d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002f81:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f85:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002f89:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f8d:	48 89 c1             	mov    rcx,rax
   140002f90:	e8 57 fe ff ff       	call   140002dec <_FindPESection>
   140002f95:	48 83 c4 30          	add    rsp,0x30
   140002f99:	5d                   	pop    rbp
   140002f9a:	c3                   	ret

0000000140002f9b <__mingw_GetSectionCount>:
   140002f9b:	55                   	push   rbp
   140002f9c:	48 89 e5             	mov    rbp,rsp
   140002f9f:	48 83 ec 30          	sub    rsp,0x30
   140002fa3:	48 8b 05 b6 23 00 00 	mov    rax,QWORD PTR [rip+0x23b6]        # 140005360 <.refptr.__ImageBase>
   140002faa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fae:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fb2:	48 89 c1             	mov    rcx,rax
   140002fb5:	e8 b6 fd ff ff       	call   140002d70 <_ValidateImageBase>
   140002fba:	85 c0                	test   eax,eax
   140002fbc:	75 07                	jne    140002fc5 <__mingw_GetSectionCount+0x2a>
   140002fbe:	b8 00 00 00 00       	mov    eax,0x0
   140002fc3:	eb 20                	jmp    140002fe5 <__mingw_GetSectionCount+0x4a>
   140002fc5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fc9:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002fcc:	48 63 d0             	movsxd rdx,eax
   140002fcf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fd3:	48 01 d0             	add    rax,rdx
   140002fd6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fda:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fde:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002fe2:	0f b7 c0             	movzx  eax,ax
   140002fe5:	48 83 c4 30          	add    rsp,0x30
   140002fe9:	5d                   	pop    rbp
   140002fea:	c3                   	ret

0000000140002feb <_FindPESectionExec>:
   140002feb:	55                   	push   rbp
   140002fec:	48 89 e5             	mov    rbp,rsp
   140002fef:	48 83 ec 40          	sub    rsp,0x40
   140002ff3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ff7:	48 8b 05 62 23 00 00 	mov    rax,QWORD PTR [rip+0x2362]        # 140005360 <.refptr.__ImageBase>
   140002ffe:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003002:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003006:	48 89 c1             	mov    rcx,rax
   140003009:	e8 62 fd ff ff       	call   140002d70 <_ValidateImageBase>
   14000300e:	85 c0                	test   eax,eax
   140003010:	75 07                	jne    140003019 <_FindPESectionExec+0x2e>
   140003012:	b8 00 00 00 00       	mov    eax,0x0
   140003017:	eb 78                	jmp    140003091 <_FindPESectionExec+0xa6>
   140003019:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000301d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003020:	48 63 d0             	movsxd rdx,eax
   140003023:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003027:	48 01 d0             	add    rax,rdx
   14000302a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000302e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140003035:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003039:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   14000303d:	0f b7 d0             	movzx  edx,ax
   140003040:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003044:	48 01 d0             	add    rax,rdx
   140003047:	48 83 c0 18          	add    rax,0x18
   14000304b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000304f:	eb 2b                	jmp    14000307c <_FindPESectionExec+0x91>
   140003051:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003055:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003058:	25 00 00 00 20       	and    eax,0x20000000
   14000305d:	85 c0                	test   eax,eax
   14000305f:	74 12                	je     140003073 <_FindPESectionExec+0x88>
   140003061:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140003066:	75 06                	jne    14000306e <_FindPESectionExec+0x83>
   140003068:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000306c:	eb 23                	jmp    140003091 <_FindPESectionExec+0xa6>
   14000306e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140003073:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140003077:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   14000307c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003080:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140003084:	0f b7 c0             	movzx  eax,ax
   140003087:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   14000308a:	72 c5                	jb     140003051 <_FindPESectionExec+0x66>
   14000308c:	b8 00 00 00 00       	mov    eax,0x0
   140003091:	48 83 c4 40          	add    rsp,0x40
   140003095:	5d                   	pop    rbp
   140003096:	c3                   	ret

0000000140003097 <_GetPEImageBase>:
   140003097:	55                   	push   rbp
   140003098:	48 89 e5             	mov    rbp,rsp
   14000309b:	48 83 ec 30          	sub    rsp,0x30
   14000309f:	48 8b 05 ba 22 00 00 	mov    rax,QWORD PTR [rip+0x22ba]        # 140005360 <.refptr.__ImageBase>
   1400030a6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030aa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030ae:	48 89 c1             	mov    rcx,rax
   1400030b1:	e8 ba fc ff ff       	call   140002d70 <_ValidateImageBase>
   1400030b6:	85 c0                	test   eax,eax
   1400030b8:	75 07                	jne    1400030c1 <_GetPEImageBase+0x2a>
   1400030ba:	b8 00 00 00 00       	mov    eax,0x0
   1400030bf:	eb 04                	jmp    1400030c5 <_GetPEImageBase+0x2e>
   1400030c1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030c5:	48 83 c4 30          	add    rsp,0x30
   1400030c9:	5d                   	pop    rbp
   1400030ca:	c3                   	ret

00000001400030cb <_IsNonwritableInCurrentImage>:
   1400030cb:	55                   	push   rbp
   1400030cc:	48 89 e5             	mov    rbp,rsp
   1400030cf:	48 83 ec 40          	sub    rsp,0x40
   1400030d3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400030d7:	48 8b 05 82 22 00 00 	mov    rax,QWORD PTR [rip+0x2282]        # 140005360 <.refptr.__ImageBase>
   1400030de:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030e2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030e6:	48 89 c1             	mov    rcx,rax
   1400030e9:	e8 82 fc ff ff       	call   140002d70 <_ValidateImageBase>
   1400030ee:	85 c0                	test   eax,eax
   1400030f0:	75 07                	jne    1400030f9 <_IsNonwritableInCurrentImage+0x2e>
   1400030f2:	b8 00 00 00 00       	mov    eax,0x0
   1400030f7:	eb 3d                	jmp    140003136 <_IsNonwritableInCurrentImage+0x6b>
   1400030f9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400030fd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003101:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003105:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003109:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000310d:	48 89 c1             	mov    rcx,rax
   140003110:	e8 d7 fc ff ff       	call   140002dec <_FindPESection>
   140003115:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003119:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000311e:	75 07                	jne    140003127 <_IsNonwritableInCurrentImage+0x5c>
   140003120:	b8 00 00 00 00       	mov    eax,0x0
   140003125:	eb 0f                	jmp    140003136 <_IsNonwritableInCurrentImage+0x6b>
   140003127:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000312b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000312e:	f7 d0                	not    eax
   140003130:	c1 e8 1f             	shr    eax,0x1f
   140003133:	0f b6 c0             	movzx  eax,al
   140003136:	48 83 c4 40          	add    rsp,0x40
   14000313a:	5d                   	pop    rbp
   14000313b:	c3                   	ret

000000014000313c <__mingw_enum_import_library_names>:
   14000313c:	55                   	push   rbp
   14000313d:	48 89 e5             	mov    rbp,rsp
   140003140:	48 83 ec 50          	sub    rsp,0x50
   140003144:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003147:	48 8b 05 12 22 00 00 	mov    rax,QWORD PTR [rip+0x2212]        # 140005360 <.refptr.__ImageBase>
   14000314e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003152:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003156:	48 89 c1             	mov    rcx,rax
   140003159:	e8 12 fc ff ff       	call   140002d70 <_ValidateImageBase>
   14000315e:	85 c0                	test   eax,eax
   140003160:	75 0a                	jne    14000316c <__mingw_enum_import_library_names+0x30>
   140003162:	b8 00 00 00 00       	mov    eax,0x0
   140003167:	e9 ab 00 00 00       	jmp    140003217 <__mingw_enum_import_library_names+0xdb>
   14000316c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003170:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003173:	48 63 d0             	movsxd rdx,eax
   140003176:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000317a:	48 01 d0             	add    rax,rdx
   14000317d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003181:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003185:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000318b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000318e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003192:	75 07                	jne    14000319b <__mingw_enum_import_library_names+0x5f>
   140003194:	b8 00 00 00 00       	mov    eax,0x0
   140003199:	eb 7c                	jmp    140003217 <__mingw_enum_import_library_names+0xdb>
   14000319b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000319e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400031a2:	48 89 c1             	mov    rcx,rax
   1400031a5:	e8 42 fc ff ff       	call   140002dec <_FindPESection>
   1400031aa:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400031ae:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   1400031b3:	75 07                	jne    1400031bc <__mingw_enum_import_library_names+0x80>
   1400031b5:	b8 00 00 00 00       	mov    eax,0x0
   1400031ba:	eb 5b                	jmp    140003217 <__mingw_enum_import_library_names+0xdb>
   1400031bc:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400031bf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400031c3:	48 01 d0             	add    rax,rdx
   1400031c6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031ca:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400031cf:	75 07                	jne    1400031d8 <__mingw_enum_import_library_names+0x9c>
   1400031d1:	b8 00 00 00 00       	mov    eax,0x0
   1400031d6:	eb 3f                	jmp    140003217 <__mingw_enum_import_library_names+0xdb>
   1400031d8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031dc:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400031df:	85 c0                	test   eax,eax
   1400031e1:	75 0b                	jne    1400031ee <__mingw_enum_import_library_names+0xb2>
   1400031e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031e7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400031ea:	85 c0                	test   eax,eax
   1400031ec:	74 23                	je     140003211 <__mingw_enum_import_library_names+0xd5>
   1400031ee:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400031f2:	7f 12                	jg     140003206 <__mingw_enum_import_library_names+0xca>
   1400031f4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031f8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400031fb:	89 c2                	mov    edx,eax
   1400031fd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003201:	48 01 d0             	add    rax,rdx
   140003204:	eb 11                	jmp    140003217 <__mingw_enum_import_library_names+0xdb>
   140003206:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000320a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000320f:	eb c7                	jmp    1400031d8 <__mingw_enum_import_library_names+0x9c>
   140003211:	90                   	nop
   140003212:	b8 00 00 00 00       	mov    eax,0x0
   140003217:	48 83 c4 50          	add    rsp,0x50
   14000321b:	5d                   	pop    rbp
   14000321c:	c3                   	ret
   14000321d:	90                   	nop
   14000321e:	90                   	nop
   14000321f:	90                   	nop

0000000140003220 <___chkstk_ms>:
   140003220:	51                   	push   rcx
   140003221:	50                   	push   rax
   140003222:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003228:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000322d:	72 19                	jb     140003248 <___chkstk_ms+0x28>
   14000322f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003236:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000323a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003240:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003246:	77 e7                	ja     14000322f <___chkstk_ms+0xf>
   140003248:	48 29 c1             	sub    rcx,rax
   14000324b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000324f:	58                   	pop    rax
   140003250:	59                   	pop    rcx
   140003251:	c3                   	ret
   140003252:	90                   	nop
   140003253:	90                   	nop
   140003254:	90                   	nop
   140003255:	90                   	nop
   140003256:	90                   	nop
   140003257:	90                   	nop
   140003258:	90                   	nop
   140003259:	90                   	nop
   14000325a:	90                   	nop
   14000325b:	90                   	nop
   14000325c:	90                   	nop
   14000325d:	90                   	nop
   14000325e:	90                   	nop
   14000325f:	90                   	nop

0000000140003260 <_initterm_e>:
   140003260:	55                   	push   rbp
   140003261:	48 89 e5             	mov    rbp,rsp
   140003264:	48 83 ec 30          	sub    rsp,0x30
   140003268:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000326c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003270:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003274:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003278:	eb 29                	jmp    1400032a3 <_initterm_e+0x43>
   14000327a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000327e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140003281:	48 85 c0             	test   rax,rax
   140003284:	74 17                	je     14000329d <_initterm_e+0x3d>
   140003286:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000328a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000328d:	ff d0                	call   rax
   14000328f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003292:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003296:	74 06                	je     14000329e <_initterm_e+0x3e>
   140003298:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000329b:	eb 15                	jmp    1400032b2 <_initterm_e+0x52>
   14000329d:	90                   	nop
   14000329e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400032a3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400032a7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400032ab:	72 cd                	jb     14000327a <_initterm_e+0x1a>
   1400032ad:	b8 00 00 00 00       	mov    eax,0x0
   1400032b2:	48 83 c4 30          	add    rsp,0x30
   1400032b6:	5d                   	pop    rbp
   1400032b7:	c3                   	ret
   1400032b8:	90                   	nop
   1400032b9:	90                   	nop
   1400032ba:	90                   	nop
   1400032bb:	90                   	nop
   1400032bc:	90                   	nop
   1400032bd:	90                   	nop
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <__p__fmode>:
   1400032c0:	55                   	push   rbp
   1400032c1:	48 89 e5             	mov    rbp,rsp
   1400032c4:	48 8b 05 05 21 00 00 	mov    rax,QWORD PTR [rip+0x2105]        # 1400053d0 <.refptr.__imp__fmode>
   1400032cb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400032ce:	5d                   	pop    rbp
   1400032cf:	c3                   	ret

00000001400032d0 <__p__commode>:
   1400032d0:	55                   	push   rbp
   1400032d1:	48 89 e5             	mov    rbp,rsp
   1400032d4:	48 8b 05 e5 20 00 00 	mov    rax,QWORD PTR [rip+0x20e5]        # 1400053c0 <.refptr.__imp__commode>
   1400032db:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400032de:	5d                   	pop    rbp
   1400032df:	c3                   	ret

00000001400032e0 <__p___initenv>:
   1400032e0:	55                   	push   rbp
   1400032e1:	48 89 e5             	mov    rbp,rsp
   1400032e4:	48 8b 05 c5 20 00 00 	mov    rax,QWORD PTR [rip+0x20c5]        # 1400053b0 <.refptr.__imp___initenv>
   1400032eb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400032ee:	5d                   	pop    rbp
   1400032ef:	c3                   	ret

00000001400032f0 <_set_invalid_parameter_handler>:
   1400032f0:	55                   	push   rbp
   1400032f1:	48 89 e5             	mov    rbp,rsp
   1400032f4:	48 83 ec 10          	sub    rsp,0x10
   1400032f8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400032fc:	48 8d 05 8d 5e 00 00 	lea    rax,[rip+0x5e8d]        # 140009190 <handler>
   140003303:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003307:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000330b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000330f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003313:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003317:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000331a:	48 89 d0             	mov    rax,rdx
   14000331d:	48 83 c4 10          	add    rsp,0x10
   140003321:	5d                   	pop    rbp
   140003322:	c3                   	ret

0000000140003323 <_get_invalid_parameter_handler>:
   140003323:	55                   	push   rbp
   140003324:	48 89 e5             	mov    rbp,rsp
   140003327:	48 8b 05 62 5e 00 00 	mov    rax,QWORD PTR [rip+0x5e62]        # 140009190 <handler>
   14000332e:	5d                   	pop    rbp
   14000332f:	c3                   	ret

0000000140003330 <_configthreadlocale>:
   140003330:	55                   	push   rbp
   140003331:	48 89 e5             	mov    rbp,rsp
   140003334:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003337:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000333b:	75 07                	jne    140003344 <_configthreadlocale+0x14>
   14000333d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140003342:	eb 05                	jmp    140003349 <_configthreadlocale+0x19>
   140003344:	b8 02 00 00 00       	mov    eax,0x2
   140003349:	5d                   	pop    rbp
   14000334a:	c3                   	ret
   14000334b:	90                   	nop
   14000334c:	90                   	nop
   14000334d:	90                   	nop
   14000334e:	90                   	nop
   14000334f:	90                   	nop

0000000140003350 <__acrt_iob_func>:
   140003350:	55                   	push   rbp
   140003351:	48 89 e5             	mov    rbp,rsp
   140003354:	48 83 ec 20          	sub    rsp,0x20
   140003358:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000335b:	e8 30 00 00 00       	call   140003390 <__iob_func>
   140003360:	48 89 c1             	mov    rcx,rax
   140003363:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003366:	48 89 d0             	mov    rax,rdx
   140003369:	48 01 c0             	add    rax,rax
   14000336c:	48 01 d0             	add    rax,rdx
   14000336f:	48 c1 e0 04          	shl    rax,0x4
   140003373:	48 01 c8             	add    rax,rcx
   140003376:	48 83 c4 20          	add    rsp,0x20
   14000337a:	5d                   	pop    rbp
   14000337b:	c3                   	ret
   14000337c:	90                   	nop
   14000337d:	90                   	nop
   14000337e:	90                   	nop
   14000337f:	90                   	nop

0000000140003380 <__C_specific_handler>:
   140003380:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a208 <__imp___C_specific_handler>
   140003386:	90                   	nop
   140003387:	90                   	nop

0000000140003388 <__getmainargs>:
   140003388:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a210 <__imp___getmainargs>
   14000338e:	90                   	nop
   14000338f:	90                   	nop

0000000140003390 <__iob_func>:
   140003390:	ff 25 8a 6e 00 00    	jmp    QWORD PTR [rip+0x6e8a]        # 14000a220 <__imp___iob_func>
   140003396:	90                   	nop
   140003397:	90                   	nop

0000000140003398 <__set_app_type>:
   140003398:	ff 25 8a 6e 00 00    	jmp    QWORD PTR [rip+0x6e8a]        # 14000a228 <__imp___set_app_type>
   14000339e:	90                   	nop
   14000339f:	90                   	nop

00000001400033a0 <__setusermatherr>:
   1400033a0:	ff 25 8a 6e 00 00    	jmp    QWORD PTR [rip+0x6e8a]        # 14000a230 <__imp___setusermatherr>
   1400033a6:	90                   	nop
   1400033a7:	90                   	nop

00000001400033a8 <_amsg_exit>:
   1400033a8:	ff 25 8a 6e 00 00    	jmp    QWORD PTR [rip+0x6e8a]        # 14000a238 <__imp__amsg_exit>
   1400033ae:	90                   	nop
   1400033af:	90                   	nop

00000001400033b0 <_cexit>:
   1400033b0:	ff 25 8a 6e 00 00    	jmp    QWORD PTR [rip+0x6e8a]        # 14000a240 <__imp__cexit>
   1400033b6:	90                   	nop
   1400033b7:	90                   	nop

00000001400033b8 <_initterm>:
   1400033b8:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a258 <__imp__initterm>
   1400033be:	90                   	nop
   1400033bf:	90                   	nop

00000001400033c0 <_crt_atexit>:
   1400033c0:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a260 <__imp__crt_atexit>
   1400033c6:	90                   	nop
   1400033c7:	90                   	nop

00000001400033c8 <abort>:
   1400033c8:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a268 <__imp_abort>
   1400033ce:	90                   	nop
   1400033cf:	90                   	nop

00000001400033d0 <calloc>:
   1400033d0:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a270 <__imp_calloc>
   1400033d6:	90                   	nop
   1400033d7:	90                   	nop

00000001400033d8 <exit>:
   1400033d8:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a278 <__imp_exit>
   1400033de:	90                   	nop
   1400033df:	90                   	nop

00000001400033e0 <fflush>:
   1400033e0:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a280 <__imp_fflush>
   1400033e6:	90                   	nop
   1400033e7:	90                   	nop

00000001400033e8 <fprintf>:
   1400033e8:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a288 <__imp_fprintf>
   1400033ee:	90                   	nop
   1400033ef:	90                   	nop

00000001400033f0 <free>:
   1400033f0:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a290 <__imp_free>
   1400033f6:	90                   	nop
   1400033f7:	90                   	nop

00000001400033f8 <malloc>:
   1400033f8:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a298 <__imp_malloc>
   1400033fe:	90                   	nop
   1400033ff:	90                   	nop

0000000140003400 <memcpy>:
   140003400:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a2a0 <__imp_memcpy>
   140003406:	90                   	nop
   140003407:	90                   	nop

0000000140003408 <memset>:
   140003408:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a2a8 <__imp_memset>
   14000340e:	90                   	nop
   14000340f:	90                   	nop

0000000140003410 <setvbuf>:
   140003410:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a2b0 <__imp_setvbuf>
   140003416:	90                   	nop
   140003417:	90                   	nop

0000000140003418 <signal>:
   140003418:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a2b8 <__imp_signal>
   14000341e:	90                   	nop
   14000341f:	90                   	nop

0000000140003420 <strlen>:
   140003420:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a2c0 <__imp_strlen>
   140003426:	90                   	nop
   140003427:	90                   	nop

0000000140003428 <strncmp>:
   140003428:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a2c8 <__imp_strncmp>
   14000342e:	90                   	nop
   14000342f:	90                   	nop

0000000140003430 <vfprintf>:
   140003430:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a2d0 <__imp_vfprintf>
   140003436:	90                   	nop
   140003437:	90                   	nop
   140003438:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000343f:	00 

0000000140003440 <VirtualQuery>:
   140003440:	ff 25 b2 6d 00 00    	jmp    QWORD PTR [rip+0x6db2]        # 14000a1f8 <__imp_VirtualQuery>
   140003446:	90                   	nop
   140003447:	90                   	nop

0000000140003448 <VirtualProtect>:
   140003448:	ff 25 a2 6d 00 00    	jmp    QWORD PTR [rip+0x6da2]        # 14000a1f0 <__imp_VirtualProtect>
   14000344e:	90                   	nop
   14000344f:	90                   	nop

0000000140003450 <TlsGetValue>:
   140003450:	ff 25 92 6d 00 00    	jmp    QWORD PTR [rip+0x6d92]        # 14000a1e8 <__imp_TlsGetValue>
   140003456:	90                   	nop
   140003457:	90                   	nop

0000000140003458 <Sleep>:
   140003458:	ff 25 82 6d 00 00    	jmp    QWORD PTR [rip+0x6d82]        # 14000a1e0 <__imp_Sleep>
   14000345e:	90                   	nop
   14000345f:	90                   	nop

0000000140003460 <SetUnhandledExceptionFilter>:
   140003460:	ff 25 72 6d 00 00    	jmp    QWORD PTR [rip+0x6d72]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   140003466:	90                   	nop
   140003467:	90                   	nop

0000000140003468 <LoadLibraryA>:
   140003468:	ff 25 62 6d 00 00    	jmp    QWORD PTR [rip+0x6d62]        # 14000a1d0 <__imp_LoadLibraryA>
   14000346e:	90                   	nop
   14000346f:	90                   	nop

0000000140003470 <LeaveCriticalSection>:
   140003470:	ff 25 52 6d 00 00    	jmp    QWORD PTR [rip+0x6d52]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140003476:	90                   	nop
   140003477:	90                   	nop

0000000140003478 <InitializeCriticalSection>:
   140003478:	ff 25 42 6d 00 00    	jmp    QWORD PTR [rip+0x6d42]        # 14000a1c0 <__imp_InitializeCriticalSection>
   14000347e:	90                   	nop
   14000347f:	90                   	nop

0000000140003480 <GetProcAddress>:
   140003480:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 14000a1b8 <__imp_GetProcAddress>
   140003486:	90                   	nop
   140003487:	90                   	nop

0000000140003488 <GetModuleHandleA>:
   140003488:	ff 25 22 6d 00 00    	jmp    QWORD PTR [rip+0x6d22]        # 14000a1b0 <__imp_GetModuleHandleA>
   14000348e:	90                   	nop
   14000348f:	90                   	nop

0000000140003490 <GetLastError>:
   140003490:	ff 25 12 6d 00 00    	jmp    QWORD PTR [rip+0x6d12]        # 14000a1a8 <__imp_GetLastError>
   140003496:	90                   	nop
   140003497:	90                   	nop

0000000140003498 <FreeLibrary>:
   140003498:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 14000a1a0 <__imp_FreeLibrary>
   14000349e:	90                   	nop
   14000349f:	90                   	nop

00000001400034a0 <EnterCriticalSection>:
   1400034a0:	ff 25 f2 6c 00 00    	jmp    QWORD PTR [rip+0x6cf2]        # 14000a198 <__imp_EnterCriticalSection>
   1400034a6:	90                   	nop
   1400034a7:	90                   	nop

00000001400034a8 <DeleteCriticalSection>:
   1400034a8:	ff 25 e2 6c 00 00    	jmp    QWORD PTR [rip+0x6ce2]        # 14000a190 <__IAT_start__>
   1400034ae:	90                   	nop
   1400034af:	90                   	nop

00000001400034b0 <register_frame_ctor>:
   1400034b0:	e9 bb e1 ff ff       	jmp    140001670 <__gcc_register_frame>
   1400034b5:	90                   	nop
   1400034b6:	90                   	nop
   1400034b7:	90                   	nop
   1400034b8:	90                   	nop
   1400034b9:	90                   	nop
   1400034ba:	90                   	nop
   1400034bb:	90                   	nop
   1400034bc:	90                   	nop
   1400034bd:	90                   	nop
   1400034be:	90                   	nop
   1400034bf:	90                   	nop
