
C:\Users\Administrator\Desktop\BinMind\round2\samples\uaf\cve_2022_25636_nft\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 27 23 00 00       	call   140003350 <fflush>
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
   1400010e8:	48 8b 05 e9 90 00 00 	mov    rax,QWORD PTR [rip+0x90e9]        # 14000a1d8 <__imp_Sleep>
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
   14000113b:	e8 d8 21 00 00       	call   140003318 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 58 21 00 00       	call   1400032c0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 f7 21 00 00       	call   140003378 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 9f 21 00 00       	call   140003338 <abort>
   140001199:	e8 22 12 00 00       	call   1400023c0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 21 90 00 00 	mov    rax,QWORD PTR [rip+0x9021]        # 14000a1d0 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 96 20 00 00       	call   140003260 <_set_invalid_parameter_handler>
   1400011ca:	e8 01 1b 00 00       	call   140002cd0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 17 21 00 00       	call   140003308 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 0b 21 00 00       	call   140003308 <__set_app_type>
   1400011fd:	e8 2e 20 00 00       	call   140003230 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 2e 20 00 00       	call   140003240 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 7e 07 00 00       	call   1400019a0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 e3 20 00 00       	call   140003318 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 88 12 00 00       	call   1400024da <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 36 20 00 00       	call   1400032a0 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 50 1f 00 00       	call   1400031d0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 8a 20 00 00       	call   140003318 <_amsg_exit>
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
   1400012cb:	e8 28 20 00 00       	call   1400032f8 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 35 20 00 00       	call   140003318 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 0e 20 00 00       	call   140003318 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 08 20 00 00       	call   140003328 <_initterm>
   140001320:	e8 52 06 00 00       	call   140001977 <__main>
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
   14000138d:	e8 be 1e 00 00       	call   140003250 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 2d 04 00 00       	call   1400017e7 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 77 1f 00 00       	call   140003348 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 40 1f 00 00       	call   140003320 <_cexit>
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
   140001511:	e8 52 1e 00 00       	call   140003368 <malloc>
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
   14000155c:	e8 27 1e 00 00       	call   140003388 <strlen>
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
   140001585:	e8 de 1d 00 00       	call   140003368 <malloc>
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
   1400015e8:	e8 83 1d 00 00       	call   140003370 <memcpy>
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
   140001642:	e8 e9 1c 00 00       	call   140003330 <_crt_atexit>
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
   140001682:	ff 15 20 8b 00 00    	call   QWORD PTR [rip+0x8b20]        # 14000a1a8 <__imp_GetModuleHandleA>
   140001688:	48 89 c3             	mov    rbx,rax
   14000168b:	48 85 c0             	test   rax,rax
   14000168e:	74 70                	je     140001700 <__gcc_register_frame+0x90>
   140001690:	48 8d 0d 69 39 00 00 	lea    rcx,[rip+0x3969]        # 140005000 <.rdata>
   140001697:	ff 15 2b 8b 00 00    	call   QWORD PTR [rip+0x8b2b]        # 14000a1c8 <__imp_LoadLibraryA>
   14000169d:	4c 8b 0d 0c 8b 00 00 	mov    r9,QWORD PTR [rip+0x8b0c]        # 14000a1b0 <__imp_GetProcAddress>
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
   14000174e:	48 ff 25 43 8a 00 00 	rex.W jmp QWORD PTR [rip+0x8a43]        # 14000a198 <__imp_FreeLibrary>
   140001755:	0f 1f 00             	nop    DWORD PTR [rax]
   140001758:	48 83 c4 20          	add    rsp,0x20
   14000175c:	5d                   	pop    rbp
   14000175d:	c3                   	ret
   14000175e:	90                   	nop
   14000175f:	90                   	nop

0000000140001760 <nft_data_destroy>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 20          	sub    rsp,0x20
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001770:	48 89 c1             	mov    rcx,rax
   140001773:	e8 e8 1b 00 00       	call   140003360 <free>
   140001778:	90                   	nop
   140001779:	48 83 c4 20          	add    rsp,0x20
   14000177d:	5d                   	pop    rbp
   14000177e:	c3                   	ret

000000014000177f <nft_byteorder_eval>:
   14000177f:	55                   	push   rbp
   140001780:	48 89 e5             	mov    rbp,rsp
   140001783:	48 83 ec 10          	sub    rsp,0x10
   140001787:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000178b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001792:	eb 3c                	jmp    1400017d0 <nft_byteorder_eval+0x51>
   140001794:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001798:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   14000179c:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000179f:	48 63 d2             	movsxd rdx,edx
   1400017a2:	48 c1 e2 02          	shl    rdx,0x2
   1400017a6:	48 01 d0             	add    rax,rdx
   1400017a9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400017ab:	89 c0                	mov    eax,eax
   1400017ad:	48 0f c8             	bswap  rax
   1400017b0:	48 89 c1             	mov    rcx,rax
   1400017b3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017b7:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   1400017bb:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400017be:	48 63 d2             	movsxd rdx,edx
   1400017c1:	48 c1 e2 02          	shl    rdx,0x2
   1400017c5:	48 01 d0             	add    rax,rdx
   1400017c8:	89 ca                	mov    edx,ecx
   1400017ca:	89 10                	mov    DWORD PTR [rax],edx
   1400017cc:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400017d0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017d4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400017d7:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   1400017da:	7c b8                	jl     140001794 <nft_byteorder_eval+0x15>
   1400017dc:	b8 00 00 00 00       	mov    eax,0x0
   1400017e1:	48 83 c4 10          	add    rsp,0x10
   1400017e5:	5d                   	pop    rbp
   1400017e6:	c3                   	ret

00000001400017e7 <main>:
   1400017e7:	55                   	push   rbp
   1400017e8:	48 89 e5             	mov    rbp,rsp
   1400017eb:	48 83 ec 30          	sub    rsp,0x30
   1400017ef:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400017f2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400017f6:	e8 7c 01 00 00       	call   140001977 <__main>
   1400017fb:	b9 18 00 00 00       	mov    ecx,0x18
   140001800:	e8 63 1b 00 00       	call   140003368 <malloc>
   140001805:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001809:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000180d:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140001813:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001817:	c7 40 10 02 00 00 00 	mov    DWORD PTR [rax+0x10],0x2
   14000181e:	b9 08 00 00 00       	mov    ecx,0x8
   140001823:	e8 40 1b 00 00       	call   140003368 <malloc>
   140001828:	48 89 c2             	mov    rdx,rax
   14000182b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000182f:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140001833:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001837:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   14000183b:	c7 00 44 33 22 11    	mov    DWORD PTR [rax],0x11223344
   140001841:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001845:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001849:	48 83 c0 04          	add    rax,0x4
   14000184d:	c7 00 88 77 66 55    	mov    DWORD PTR [rax],0x55667788
   140001853:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001857:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   14000185b:	48 89 c1             	mov    rcx,rax
   14000185e:	e8 fd fe ff ff       	call   140001760 <nft_data_destroy>
   140001863:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001867:	48 c7 40 08 00 00 00 	mov    QWORD PTR [rax+0x8],0x0
   14000186e:	00 
   14000186f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001873:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   140001879:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000187d:	8b 00                	mov    eax,DWORD PTR [rax]
   14000187f:	83 f8 02             	cmp    eax,0x2
   140001882:	75 19                	jne    14000189d <main+0xb6>
   140001884:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001888:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   14000188c:	48 85 c0             	test   rax,rax
   14000188f:	74 0c                	je     14000189d <main+0xb6>
   140001891:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001895:	48 89 c1             	mov    rcx,rax
   140001898:	e8 e2 fe ff ff       	call   14000177f <nft_byteorder_eval>
   14000189d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400018a1:	48 89 c1             	mov    rcx,rax
   1400018a4:	e8 b7 1a 00 00       	call   140003360 <free>
   1400018a9:	b8 00 00 00 00       	mov    eax,0x0
   1400018ae:	48 83 c4 30          	add    rsp,0x30
   1400018b2:	5d                   	pop    rbp
   1400018b3:	c3                   	ret
   1400018b4:	90                   	nop
   1400018b5:	90                   	nop
   1400018b6:	90                   	nop
   1400018b7:	90                   	nop
   1400018b8:	90                   	nop
   1400018b9:	90                   	nop
   1400018ba:	90                   	nop
   1400018bb:	90                   	nop
   1400018bc:	90                   	nop
   1400018bd:	90                   	nop
   1400018be:	90                   	nop
   1400018bf:	90                   	nop

00000001400018c0 <__do_global_dtors>:
   1400018c0:	55                   	push   rbp
   1400018c1:	48 89 e5             	mov    rbp,rsp
   1400018c4:	48 83 ec 20          	sub    rsp,0x20
   1400018c8:	eb 1e                	jmp    1400018e8 <__do_global_dtors+0x28>
   1400018ca:	48 8b 05 3f 27 00 00 	mov    rax,QWORD PTR [rip+0x273f]        # 140004010 <p.0>
   1400018d1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018d4:	ff d0                	call   rax
   1400018d6:	48 8b 05 33 27 00 00 	mov    rax,QWORD PTR [rip+0x2733]        # 140004010 <p.0>
   1400018dd:	48 83 c0 08          	add    rax,0x8
   1400018e1:	48 89 05 28 27 00 00 	mov    QWORD PTR [rip+0x2728],rax        # 140004010 <p.0>
   1400018e8:	48 8b 05 21 27 00 00 	mov    rax,QWORD PTR [rip+0x2721]        # 140004010 <p.0>
   1400018ef:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018f2:	48 85 c0             	test   rax,rax
   1400018f5:	75 d3                	jne    1400018ca <__do_global_dtors+0xa>
   1400018f7:	90                   	nop
   1400018f8:	90                   	nop
   1400018f9:	48 83 c4 20          	add    rsp,0x20
   1400018fd:	5d                   	pop    rbp
   1400018fe:	c3                   	ret

00000001400018ff <__do_global_ctors>:
   1400018ff:	55                   	push   rbp
   140001900:	48 89 e5             	mov    rbp,rsp
   140001903:	48 83 ec 30          	sub    rsp,0x30
   140001907:	48 8b 05 42 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a42]        # 140005350 <.refptr.__CTOR_LIST__>
   14000190e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001911:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001914:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001918:	75 25                	jne    14000193f <__do_global_ctors+0x40>
   14000191a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001921:	eb 04                	jmp    140001927 <__do_global_ctors+0x28>
   140001923:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001927:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000192a:	8d 50 01             	lea    edx,[rax+0x1]
   14000192d:	48 8b 05 1c 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a1c]        # 140005350 <.refptr.__CTOR_LIST__>
   140001934:	89 d2                	mov    edx,edx
   140001936:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000193a:	48 85 c0             	test   rax,rax
   14000193d:	75 e4                	jne    140001923 <__do_global_ctors+0x24>
   14000193f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001942:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001945:	eb 14                	jmp    14000195b <__do_global_ctors+0x5c>
   140001947:	48 8b 05 02 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a02]        # 140005350 <.refptr.__CTOR_LIST__>
   14000194e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001951:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001955:	ff d0                	call   rax
   140001957:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000195b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000195f:	75 e6                	jne    140001947 <__do_global_ctors+0x48>
   140001961:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400018c0 <__do_global_dtors>
   140001968:	48 89 c1             	mov    rcx,rax
   14000196b:	e8 bf fc ff ff       	call   14000162f <atexit>
   140001970:	90                   	nop
   140001971:	48 83 c4 30          	add    rsp,0x30
   140001975:	5d                   	pop    rbp
   140001976:	c3                   	ret

0000000140001977 <__main>:
   140001977:	55                   	push   rbp
   140001978:	48 89 e5             	mov    rbp,rsp
   14000197b:	48 83 ec 20          	sub    rsp,0x20
   14000197f:	8b 05 fb 76 00 00    	mov    eax,DWORD PTR [rip+0x76fb]        # 140009080 <initialized>
   140001985:	85 c0                	test   eax,eax
   140001987:	75 0f                	jne    140001998 <__main+0x21>
   140001989:	c7 05 ed 76 00 00 01 	mov    DWORD PTR [rip+0x76ed],0x1        # 140009080 <initialized>
   140001990:	00 00 00 
   140001993:	e8 67 ff ff ff       	call   1400018ff <__do_global_ctors>
   140001998:	90                   	nop
   140001999:	48 83 c4 20          	add    rsp,0x20
   14000199d:	5d                   	pop    rbp
   14000199e:	c3                   	ret
   14000199f:	90                   	nop

00000001400019a0 <_setargv>:
   1400019a0:	55                   	push   rbp
   1400019a1:	48 89 e5             	mov    rbp,rsp
   1400019a4:	b8 00 00 00 00       	mov    eax,0x0
   1400019a9:	5d                   	pop    rbp
   1400019aa:	c3                   	ret
   1400019ab:	90                   	nop
   1400019ac:	90                   	nop
   1400019ad:	90                   	nop
   1400019ae:	90                   	nop
   1400019af:	90                   	nop

00000001400019b0 <__dyn_tls_init>:
   1400019b0:	55                   	push   rbp
   1400019b1:	48 89 e5             	mov    rbp,rsp
   1400019b4:	48 83 ec 30          	sub    rsp,0x30
   1400019b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019bc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019bf:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019c3:	48 8b 05 66 39 00 00 	mov    rax,QWORD PTR [rip+0x3966]        # 140005330 <.refptr._CRT_MT>
   1400019ca:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019cc:	83 f8 02             	cmp    eax,0x2
   1400019cf:	74 0d                	je     1400019de <__dyn_tls_init+0x2e>
   1400019d1:	48 8b 05 58 39 00 00 	mov    rax,QWORD PTR [rip+0x3958]        # 140005330 <.refptr._CRT_MT>
   1400019d8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400019de:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   1400019e2:	74 1e                	je     140001a02 <__dyn_tls_init+0x52>
   1400019e4:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   1400019e8:	75 5b                	jne    140001a45 <__dyn_tls_init+0x95>
   1400019ea:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019ee:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019f5:	49 89 c8             	mov    r8,rcx
   1400019f8:	48 89 c1             	mov    rcx,rax
   1400019fb:	e8 d1 11 00 00       	call   140002bd1 <__mingw_TLScallback>
   140001a00:	eb 43                	jmp    140001a45 <__dyn_tls_init+0x95>
   140001a02:	48 8d 05 8f 3c 00 00 	lea    rax,[rip+0x3c8f]        # 140005698 <___crt_xd_start__>
   140001a09:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a0d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001a12:	eb 22                	jmp    140001a36 <__dyn_tls_init+0x86>
   140001a14:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001a18:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001a1c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001a20:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a23:	48 85 c0             	test   rax,rax
   140001a26:	74 09                	je     140001a31 <__dyn_tls_init+0x81>
   140001a28:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001a2c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a2f:	ff d0                	call   rax
   140001a31:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001a36:	48 8d 05 63 3c 00 00 	lea    rax,[rip+0x3c63]        # 1400056a0 <__xd_z>
   140001a3d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001a41:	75 d1                	jne    140001a14 <__dyn_tls_init+0x64>
   140001a43:	eb 01                	jmp    140001a46 <__dyn_tls_init+0x96>
   140001a45:	90                   	nop
   140001a46:	48 83 c4 30          	add    rsp,0x30
   140001a4a:	5d                   	pop    rbp
   140001a4b:	c3                   	ret

0000000140001a4c <__tlregdtor>:
   140001a4c:	55                   	push   rbp
   140001a4d:	48 89 e5             	mov    rbp,rsp
   140001a50:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a54:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001a59:	75 07                	jne    140001a62 <__tlregdtor+0x16>
   140001a5b:	b8 00 00 00 00       	mov    eax,0x0
   140001a60:	eb 05                	jmp    140001a67 <__tlregdtor+0x1b>
   140001a62:	b8 00 00 00 00       	mov    eax,0x0
   140001a67:	5d                   	pop    rbp
   140001a68:	c3                   	ret

0000000140001a69 <__dyn_tls_dtor>:
   140001a69:	55                   	push   rbp
   140001a6a:	48 89 e5             	mov    rbp,rsp
   140001a6d:	48 83 ec 20          	sub    rsp,0x20
   140001a71:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a75:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a78:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a7c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a80:	74 06                	je     140001a88 <__dyn_tls_dtor+0x1f>
   140001a82:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a86:	75 18                	jne    140001aa0 <__dyn_tls_dtor+0x37>
   140001a88:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a8c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a8f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a93:	49 89 c8             	mov    r8,rcx
   140001a96:	48 89 c1             	mov    rcx,rax
   140001a99:	e8 33 11 00 00       	call   140002bd1 <__mingw_TLScallback>
   140001a9e:	eb 01                	jmp    140001aa1 <__dyn_tls_dtor+0x38>
   140001aa0:	90                   	nop
   140001aa1:	48 83 c4 20          	add    rsp,0x20
   140001aa5:	5d                   	pop    rbp
   140001aa6:	c3                   	ret
   140001aa7:	90                   	nop
   140001aa8:	90                   	nop
   140001aa9:	90                   	nop
   140001aaa:	90                   	nop
   140001aab:	90                   	nop
   140001aac:	90                   	nop
   140001aad:	90                   	nop
   140001aae:	90                   	nop
   140001aaf:	90                   	nop

0000000140001ab0 <_matherr>:
   140001ab0:	55                   	push   rbp
   140001ab1:	53                   	push   rbx
   140001ab2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001ab9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001abe:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001ac2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001ac6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001acb:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001acf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ad3:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ad5:	83 f8 06             	cmp    eax,0x6
   140001ad8:	74 56                	je     140001b30 <_matherr+0x80>
   140001ada:	83 f8 06             	cmp    eax,0x6
   140001add:	7f 78                	jg     140001b57 <_matherr+0xa7>
   140001adf:	83 f8 05             	cmp    eax,0x5
   140001ae2:	74 59                	je     140001b3d <_matherr+0x8d>
   140001ae4:	83 f8 05             	cmp    eax,0x5
   140001ae7:	7f 6e                	jg     140001b57 <_matherr+0xa7>
   140001ae9:	83 f8 04             	cmp    eax,0x4
   140001aec:	74 5c                	je     140001b4a <_matherr+0x9a>
   140001aee:	83 f8 04             	cmp    eax,0x4
   140001af1:	7f 64                	jg     140001b57 <_matherr+0xa7>
   140001af3:	83 f8 03             	cmp    eax,0x3
   140001af6:	74 2b                	je     140001b23 <_matherr+0x73>
   140001af8:	83 f8 03             	cmp    eax,0x3
   140001afb:	7f 5a                	jg     140001b57 <_matherr+0xa7>
   140001afd:	83 f8 01             	cmp    eax,0x1
   140001b00:	74 07                	je     140001b09 <_matherr+0x59>
   140001b02:	83 f8 02             	cmp    eax,0x2
   140001b05:	74 0f                	je     140001b16 <_matherr+0x66>
   140001b07:	eb 4e                	jmp    140001b57 <_matherr+0xa7>
   140001b09:	48 8d 05 90 35 00 00 	lea    rax,[rip+0x3590]        # 1400050a0 <.rdata>
   140001b10:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b14:	eb 4d                	jmp    140001b63 <_matherr+0xb3>
   140001b16:	48 8d 05 a2 35 00 00 	lea    rax,[rip+0x35a2]        # 1400050bf <.rdata+0x1f>
   140001b1d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b21:	eb 40                	jmp    140001b63 <_matherr+0xb3>
   140001b23:	48 8d 05 b6 35 00 00 	lea    rax,[rip+0x35b6]        # 1400050e0 <.rdata+0x40>
   140001b2a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b2e:	eb 33                	jmp    140001b63 <_matherr+0xb3>
   140001b30:	48 8d 05 c9 35 00 00 	lea    rax,[rip+0x35c9]        # 140005100 <.rdata+0x60>
   140001b37:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b3b:	eb 26                	jmp    140001b63 <_matherr+0xb3>
   140001b3d:	48 8d 05 e4 35 00 00 	lea    rax,[rip+0x35e4]        # 140005128 <.rdata+0x88>
   140001b44:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b48:	eb 19                	jmp    140001b63 <_matherr+0xb3>
   140001b4a:	48 8d 05 ff 35 00 00 	lea    rax,[rip+0x35ff]        # 140005150 <.rdata+0xb0>
   140001b51:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b55:	eb 0c                	jmp    140001b63 <_matherr+0xb3>
   140001b57:	48 8d 05 28 36 00 00 	lea    rax,[rip+0x3628]        # 140005186 <.rdata+0xe6>
   140001b5e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b62:	90                   	nop
   140001b63:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b67:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b6d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b71:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b76:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b7a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b7f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b83:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b87:	b9 02 00 00 00       	mov    ecx,0x2
   140001b8c:	e8 2f 17 00 00       	call   1400032c0 <__acrt_iob_func>
   140001b91:	48 89 c1             	mov    rcx,rax
   140001b94:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b98:	48 8d 05 f9 35 00 00 	lea    rax,[rip+0x35f9]        # 140005198 <.rdata+0xf8>
   140001b9f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001ba6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001bac:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001bb2:	49 89 d9             	mov    r9,rbx
   140001bb5:	49 89 d0             	mov    r8,rdx
   140001bb8:	48 89 c2             	mov    rdx,rax
   140001bbb:	e8 98 17 00 00       	call   140003358 <fprintf>
   140001bc0:	b8 00 00 00 00       	mov    eax,0x0
   140001bc5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001bc9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001bcd:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001bd2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001bd9:	5b                   	pop    rbx
   140001bda:	5d                   	pop    rbp
   140001bdb:	c3                   	ret
   140001bdc:	90                   	nop
   140001bdd:	90                   	nop
   140001bde:	90                   	nop
   140001bdf:	90                   	nop

0000000140001be0 <__report_error>:
   140001be0:	55                   	push   rbp
   140001be1:	53                   	push   rbx
   140001be2:	48 83 ec 38          	sub    rsp,0x38
   140001be6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001beb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001bef:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001bf3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001bf7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001bfb:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001bff:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c03:	b9 02 00 00 00       	mov    ecx,0x2
   140001c08:	e8 b3 16 00 00       	call   1400032c0 <__acrt_iob_func>
   140001c0d:	48 89 c1             	mov    rcx,rax
   140001c10:	48 8d 05 b9 35 00 00 	lea    rax,[rip+0x35b9]        # 1400051d0 <.rdata>
   140001c17:	48 89 c2             	mov    rdx,rax
   140001c1a:	e8 39 17 00 00       	call   140003358 <fprintf>
   140001c1f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001c23:	b9 02 00 00 00       	mov    ecx,0x2
   140001c28:	e8 93 16 00 00       	call   1400032c0 <__acrt_iob_func>
   140001c2d:	48 89 c1             	mov    rcx,rax
   140001c30:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001c34:	49 89 d8             	mov    r8,rbx
   140001c37:	48 89 c2             	mov    rdx,rax
   140001c3a:	e8 59 17 00 00       	call   140003398 <vfprintf>
   140001c3f:	e8 f4 16 00 00       	call   140003338 <abort>
   140001c44:	90                   	nop

0000000140001c45 <mark_section_writable>:
   140001c45:	55                   	push   rbp
   140001c46:	48 89 e5             	mov    rbp,rsp
   140001c49:	48 83 ec 60          	sub    rsp,0x60
   140001c4d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001c51:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001c58:	e9 82 00 00 00       	jmp    140001cdf <mark_section_writable+0x9a>
   140001c5d:	48 8b 0d 7c 74 00 00 	mov    rcx,QWORD PTR [rip+0x747c]        # 1400090e0 <the_secs>
   140001c64:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c67:	48 63 d0             	movsxd rdx,eax
   140001c6a:	48 89 d0             	mov    rax,rdx
   140001c6d:	48 c1 e0 02          	shl    rax,0x2
   140001c71:	48 01 d0             	add    rax,rdx
   140001c74:	48 c1 e0 03          	shl    rax,0x3
   140001c78:	48 01 c8             	add    rax,rcx
   140001c7b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c7f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c83:	72 56                	jb     140001cdb <mark_section_writable+0x96>
   140001c85:	48 8b 0d 54 74 00 00 	mov    rcx,QWORD PTR [rip+0x7454]        # 1400090e0 <the_secs>
   140001c8c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c8f:	48 63 d0             	movsxd rdx,eax
   140001c92:	48 89 d0             	mov    rax,rdx
   140001c95:	48 c1 e0 02          	shl    rax,0x2
   140001c99:	48 01 d0             	add    rax,rdx
   140001c9c:	48 c1 e0 03          	shl    rax,0x3
   140001ca0:	48 01 c8             	add    rax,rcx
   140001ca3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001ca7:	4c 8b 05 32 74 00 00 	mov    r8,QWORD PTR [rip+0x7432]        # 1400090e0 <the_secs>
   140001cae:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cb1:	48 63 d0             	movsxd rdx,eax
   140001cb4:	48 89 d0             	mov    rax,rdx
   140001cb7:	48 c1 e0 02          	shl    rax,0x2
   140001cbb:	48 01 d0             	add    rax,rdx
   140001cbe:	48 c1 e0 03          	shl    rax,0x3
   140001cc2:	4c 01 c0             	add    rax,r8
   140001cc5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001cc9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001ccc:	89 c0                	mov    eax,eax
   140001cce:	48 01 c8             	add    rax,rcx
   140001cd1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001cd5:	0f 82 41 02 00 00    	jb     140001f1c <mark_section_writable+0x2d7>
   140001cdb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001cdf:	8b 05 03 74 00 00    	mov    eax,DWORD PTR [rip+0x7403]        # 1400090e8 <maxSections>
   140001ce5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001ce8:	0f 8c 6f ff ff ff    	jl     140001c5d <mark_section_writable+0x18>
   140001cee:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001cf2:	48 89 c1             	mov    rcx,rax
   140001cf5:	e8 c1 11 00 00       	call   140002ebb <__mingw_GetSectionForAddress>
   140001cfa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001cfe:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001d03:	75 13                	jne    140001d18 <mark_section_writable+0xd3>
   140001d05:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001d09:	48 8d 0d e0 34 00 00 	lea    rcx,[rip+0x34e0]        # 1400051f0 <.rdata+0x20>
   140001d10:	48 89 c2             	mov    rdx,rax
   140001d13:	e8 c8 fe ff ff       	call   140001be0 <__report_error>
   140001d18:	48 8b 0d c1 73 00 00 	mov    rcx,QWORD PTR [rip+0x73c1]        # 1400090e0 <the_secs>
   140001d1f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d22:	48 63 d0             	movsxd rdx,eax
   140001d25:	48 89 d0             	mov    rax,rdx
   140001d28:	48 c1 e0 02          	shl    rax,0x2
   140001d2c:	48 01 d0             	add    rax,rdx
   140001d2f:	48 c1 e0 03          	shl    rax,0x3
   140001d33:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d37:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d3b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001d3f:	48 8b 0d 9a 73 00 00 	mov    rcx,QWORD PTR [rip+0x739a]        # 1400090e0 <the_secs>
   140001d46:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d49:	48 63 d0             	movsxd rdx,eax
   140001d4c:	48 89 d0             	mov    rax,rdx
   140001d4f:	48 c1 e0 02          	shl    rax,0x2
   140001d53:	48 01 d0             	add    rax,rdx
   140001d56:	48 c1 e0 03          	shl    rax,0x3
   140001d5a:	48 01 c8             	add    rax,rcx
   140001d5d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d63:	e8 9f 12 00 00       	call   140003007 <_GetPEImageBase>
   140001d68:	48 89 c1             	mov    rcx,rax
   140001d6b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d6f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d72:	41 89 c1             	mov    r9d,eax
   140001d75:	4c 8b 05 64 73 00 00 	mov    r8,QWORD PTR [rip+0x7364]        # 1400090e0 <the_secs>
   140001d7c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d7f:	48 63 d0             	movsxd rdx,eax
   140001d82:	48 89 d0             	mov    rax,rdx
   140001d85:	48 c1 e0 02          	shl    rax,0x2
   140001d89:	48 01 d0             	add    rax,rdx
   140001d8c:	48 c1 e0 03          	shl    rax,0x3
   140001d90:	4c 01 c0             	add    rax,r8
   140001d93:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d97:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d9b:	48 8b 0d 3e 73 00 00 	mov    rcx,QWORD PTR [rip+0x733e]        # 1400090e0 <the_secs>
   140001da2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001da5:	48 63 d0             	movsxd rdx,eax
   140001da8:	48 89 d0             	mov    rax,rdx
   140001dab:	48 c1 e0 02          	shl    rax,0x2
   140001daf:	48 01 d0             	add    rax,rdx
   140001db2:	48 c1 e0 03          	shl    rax,0x3
   140001db6:	48 01 c8             	add    rax,rcx
   140001db9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001dbd:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001dc1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001dc7:	48 89 c1             	mov    rcx,rax
   140001dca:	48 8b 05 1f 84 00 00 	mov    rax,QWORD PTR [rip+0x841f]        # 14000a1f0 <__imp_VirtualQuery>
   140001dd1:	ff d0                	call   rax
   140001dd3:	48 85 c0             	test   rax,rax
   140001dd6:	75 3f                	jne    140001e17 <mark_section_writable+0x1d2>
   140001dd8:	48 8b 0d 01 73 00 00 	mov    rcx,QWORD PTR [rip+0x7301]        # 1400090e0 <the_secs>
   140001ddf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001de2:	48 63 d0             	movsxd rdx,eax
   140001de5:	48 89 d0             	mov    rax,rdx
   140001de8:	48 c1 e0 02          	shl    rax,0x2
   140001dec:	48 01 d0             	add    rax,rdx
   140001def:	48 c1 e0 03          	shl    rax,0x3
   140001df3:	48 01 c8             	add    rax,rcx
   140001df6:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001dfa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001dfe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001e01:	89 c1                	mov    ecx,eax
   140001e03:	48 8d 05 06 34 00 00 	lea    rax,[rip+0x3406]        # 140005210 <.rdata+0x40>
   140001e0a:	49 89 d0             	mov    r8,rdx
   140001e0d:	89 ca                	mov    edx,ecx
   140001e0f:	48 89 c1             	mov    rcx,rax
   140001e12:	e8 c9 fd ff ff       	call   140001be0 <__report_error>
   140001e17:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e1a:	83 f8 40             	cmp    eax,0x40
   140001e1d:	0f 84 e8 00 00 00    	je     140001f0b <mark_section_writable+0x2c6>
   140001e23:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e26:	83 f8 04             	cmp    eax,0x4
   140001e29:	0f 84 dc 00 00 00    	je     140001f0b <mark_section_writable+0x2c6>
   140001e2f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e32:	3d 80 00 00 00       	cmp    eax,0x80
   140001e37:	0f 84 ce 00 00 00    	je     140001f0b <mark_section_writable+0x2c6>
   140001e3d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e40:	83 f8 08             	cmp    eax,0x8
   140001e43:	0f 84 c2 00 00 00    	je     140001f0b <mark_section_writable+0x2c6>
   140001e49:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e4c:	83 f8 02             	cmp    eax,0x2
   140001e4f:	75 09                	jne    140001e5a <mark_section_writable+0x215>
   140001e51:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001e58:	eb 07                	jmp    140001e61 <mark_section_writable+0x21c>
   140001e5a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e61:	48 8b 0d 78 72 00 00 	mov    rcx,QWORD PTR [rip+0x7278]        # 1400090e0 <the_secs>
   140001e68:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e6b:	48 63 d0             	movsxd rdx,eax
   140001e6e:	48 89 d0             	mov    rax,rdx
   140001e71:	48 c1 e0 02          	shl    rax,0x2
   140001e75:	48 01 d0             	add    rax,rdx
   140001e78:	48 c1 e0 03          	shl    rax,0x3
   140001e7c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e80:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e84:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e88:	48 8b 0d 51 72 00 00 	mov    rcx,QWORD PTR [rip+0x7251]        # 1400090e0 <the_secs>
   140001e8f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e92:	48 63 d0             	movsxd rdx,eax
   140001e95:	48 89 d0             	mov    rax,rdx
   140001e98:	48 c1 e0 02          	shl    rax,0x2
   140001e9c:	48 01 d0             	add    rax,rdx
   140001e9f:	48 c1 e0 03          	shl    rax,0x3
   140001ea3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001ea7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001eab:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001eaf:	48 8b 0d 2a 72 00 00 	mov    rcx,QWORD PTR [rip+0x722a]        # 1400090e0 <the_secs>
   140001eb6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eb9:	48 63 d0             	movsxd rdx,eax
   140001ebc:	48 89 d0             	mov    rax,rdx
   140001ebf:	48 c1 e0 02          	shl    rax,0x2
   140001ec3:	48 01 d0             	add    rax,rdx
   140001ec6:	48 c1 e0 03          	shl    rax,0x3
   140001eca:	48 01 c8             	add    rax,rcx
   140001ecd:	49 89 c0             	mov    r8,rax
   140001ed0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001ed4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001ed8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001edb:	4d 89 c1             	mov    r9,r8
   140001ede:	41 89 c8             	mov    r8d,ecx
   140001ee1:	48 89 c1             	mov    rcx,rax
   140001ee4:	48 8b 05 fd 82 00 00 	mov    rax,QWORD PTR [rip+0x82fd]        # 14000a1e8 <__imp_VirtualProtect>
   140001eeb:	ff d0                	call   rax
   140001eed:	85 c0                	test   eax,eax
   140001eef:	75 1a                	jne    140001f0b <mark_section_writable+0x2c6>
   140001ef1:	48 8b 05 a8 82 00 00 	mov    rax,QWORD PTR [rip+0x82a8]        # 14000a1a0 <__imp_GetLastError>
   140001ef8:	ff d0                	call   rax
   140001efa:	89 c2                	mov    edx,eax
   140001efc:	48 8d 05 45 33 00 00 	lea    rax,[rip+0x3345]        # 140005248 <.rdata+0x78>
   140001f03:	48 89 c1             	mov    rcx,rax
   140001f06:	e8 d5 fc ff ff       	call   140001be0 <__report_error>
   140001f0b:	8b 05 d7 71 00 00    	mov    eax,DWORD PTR [rip+0x71d7]        # 1400090e8 <maxSections>
   140001f11:	83 c0 01             	add    eax,0x1
   140001f14:	89 05 ce 71 00 00    	mov    DWORD PTR [rip+0x71ce],eax        # 1400090e8 <maxSections>
   140001f1a:	eb 01                	jmp    140001f1d <mark_section_writable+0x2d8>
   140001f1c:	90                   	nop
   140001f1d:	48 83 c4 60          	add    rsp,0x60
   140001f21:	5d                   	pop    rbp
   140001f22:	c3                   	ret

0000000140001f23 <restore_modified_sections>:
   140001f23:	55                   	push   rbp
   140001f24:	48 89 e5             	mov    rbp,rsp
   140001f27:	48 83 ec 30          	sub    rsp,0x30
   140001f2b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001f32:	e9 ad 00 00 00       	jmp    140001fe4 <restore_modified_sections+0xc1>
   140001f37:	48 8b 0d a2 71 00 00 	mov    rcx,QWORD PTR [rip+0x71a2]        # 1400090e0 <the_secs>
   140001f3e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f41:	48 63 d0             	movsxd rdx,eax
   140001f44:	48 89 d0             	mov    rax,rdx
   140001f47:	48 c1 e0 02          	shl    rax,0x2
   140001f4b:	48 01 d0             	add    rax,rdx
   140001f4e:	48 c1 e0 03          	shl    rax,0x3
   140001f52:	48 01 c8             	add    rax,rcx
   140001f55:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f57:	85 c0                	test   eax,eax
   140001f59:	0f 84 80 00 00 00    	je     140001fdf <restore_modified_sections+0xbc>
   140001f5f:	48 8b 0d 7a 71 00 00 	mov    rcx,QWORD PTR [rip+0x717a]        # 1400090e0 <the_secs>
   140001f66:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f69:	48 63 d0             	movsxd rdx,eax
   140001f6c:	48 89 d0             	mov    rax,rdx
   140001f6f:	48 c1 e0 02          	shl    rax,0x2
   140001f73:	48 01 d0             	add    rax,rdx
   140001f76:	48 c1 e0 03          	shl    rax,0x3
   140001f7a:	48 01 c8             	add    rax,rcx
   140001f7d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f80:	48 8b 0d 59 71 00 00 	mov    rcx,QWORD PTR [rip+0x7159]        # 1400090e0 <the_secs>
   140001f87:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f8a:	48 63 d0             	movsxd rdx,eax
   140001f8d:	48 89 d0             	mov    rax,rdx
   140001f90:	48 c1 e0 02          	shl    rax,0x2
   140001f94:	48 01 d0             	add    rax,rdx
   140001f97:	48 c1 e0 03          	shl    rax,0x3
   140001f9b:	48 01 c8             	add    rax,rcx
   140001f9e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001fa2:	4c 8b 05 37 71 00 00 	mov    r8,QWORD PTR [rip+0x7137]        # 1400090e0 <the_secs>
   140001fa9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001fac:	48 63 d0             	movsxd rdx,eax
   140001faf:	48 89 d0             	mov    rax,rdx
   140001fb2:	48 c1 e0 02          	shl    rax,0x2
   140001fb6:	48 01 d0             	add    rax,rdx
   140001fb9:	48 c1 e0 03          	shl    rax,0x3
   140001fbd:	4c 01 c0             	add    rax,r8
   140001fc0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001fc4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001fc8:	49 89 d1             	mov    r9,rdx
   140001fcb:	45 89 d0             	mov    r8d,r10d
   140001fce:	48 89 ca             	mov    rdx,rcx
   140001fd1:	48 89 c1             	mov    rcx,rax
   140001fd4:	48 8b 05 0d 82 00 00 	mov    rax,QWORD PTR [rip+0x820d]        # 14000a1e8 <__imp_VirtualProtect>
   140001fdb:	ff d0                	call   rax
   140001fdd:	eb 01                	jmp    140001fe0 <restore_modified_sections+0xbd>
   140001fdf:	90                   	nop
   140001fe0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001fe4:	8b 05 fe 70 00 00    	mov    eax,DWORD PTR [rip+0x70fe]        # 1400090e8 <maxSections>
   140001fea:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001fed:	0f 8c 44 ff ff ff    	jl     140001f37 <restore_modified_sections+0x14>
   140001ff3:	90                   	nop
   140001ff4:	90                   	nop
   140001ff5:	48 83 c4 30          	add    rsp,0x30
   140001ff9:	5d                   	pop    rbp
   140001ffa:	c3                   	ret

0000000140001ffb <__write_memory>:
   140001ffb:	55                   	push   rbp
   140001ffc:	48 89 e5             	mov    rbp,rsp
   140001fff:	48 83 ec 20          	sub    rsp,0x20
   140002003:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002007:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000200b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000200f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140002014:	74 25                	je     14000203b <__write_memory+0x40>
   140002016:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000201a:	48 89 c1             	mov    rcx,rax
   14000201d:	e8 23 fc ff ff       	call   140001c45 <mark_section_writable>
   140002022:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140002026:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000202a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000202e:	49 89 c8             	mov    r8,rcx
   140002031:	48 89 c1             	mov    rcx,rax
   140002034:	e8 37 13 00 00       	call   140003370 <memcpy>
   140002039:	eb 01                	jmp    14000203c <__write_memory+0x41>
   14000203b:	90                   	nop
   14000203c:	48 83 c4 20          	add    rsp,0x20
   140002040:	5d                   	pop    rbp
   140002041:	c3                   	ret

0000000140002042 <do_pseudo_reloc>:
   140002042:	55                   	push   rbp
   140002043:	48 89 e5             	mov    rbp,rsp
   140002046:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   14000204a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000204e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002052:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002056:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000205a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000205e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002062:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002066:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000206a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000206f:	0f 8e 44 03 00 00    	jle    1400023b9 <do_pseudo_reloc+0x377>
   140002075:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000207a:	7e 25                	jle    1400020a1 <do_pseudo_reloc+0x5f>
   14000207c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002080:	8b 00                	mov    eax,DWORD PTR [rax]
   140002082:	85 c0                	test   eax,eax
   140002084:	75 1b                	jne    1400020a1 <do_pseudo_reloc+0x5f>
   140002086:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000208a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000208d:	85 c0                	test   eax,eax
   14000208f:	75 10                	jne    1400020a1 <do_pseudo_reloc+0x5f>
   140002091:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002095:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002098:	85 c0                	test   eax,eax
   14000209a:	75 05                	jne    1400020a1 <do_pseudo_reloc+0x5f>
   14000209c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   1400020a1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020a5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020a7:	85 c0                	test   eax,eax
   1400020a9:	75 0b                	jne    1400020b6 <do_pseudo_reloc+0x74>
   1400020ab:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020af:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020b2:	85 c0                	test   eax,eax
   1400020b4:	74 59                	je     14000210f <do_pseudo_reloc+0xcd>
   1400020b6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020ba:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400020be:	eb 40                	jmp    140002100 <do_pseudo_reloc+0xbe>
   1400020c0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020c4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020c7:	89 c2                	mov    edx,eax
   1400020c9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020cd:	48 01 d0             	add    rax,rdx
   1400020d0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020d4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020d8:	8b 10                	mov    edx,DWORD PTR [rax]
   1400020da:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020de:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020e0:	01 d0                	add    eax,edx
   1400020e2:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   1400020e5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020e9:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   1400020ed:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400020f3:	48 89 c1             	mov    rcx,rax
   1400020f6:	e8 00 ff ff ff       	call   140001ffb <__write_memory>
   1400020fb:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002100:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002104:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002108:	72 b6                	jb     1400020c0 <do_pseudo_reloc+0x7e>
   14000210a:	e9 ab 02 00 00       	jmp    1400023ba <do_pseudo_reloc+0x378>
   14000210f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002113:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002116:	83 f8 01             	cmp    eax,0x1
   140002119:	74 18                	je     140002133 <do_pseudo_reloc+0xf1>
   14000211b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000211f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002122:	89 c2                	mov    edx,eax
   140002124:	48 8d 05 45 31 00 00 	lea    rax,[rip+0x3145]        # 140005270 <.rdata+0xa0>
   14000212b:	48 89 c1             	mov    rcx,rax
   14000212e:	e8 ad fa ff ff       	call   140001be0 <__report_error>
   140002133:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002137:	48 83 c0 0c          	add    rax,0xc
   14000213b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000213f:	e9 65 02 00 00       	jmp    1400023a9 <do_pseudo_reloc+0x367>
   140002144:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002148:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000214b:	89 c2                	mov    edx,eax
   14000214d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002151:	48 01 d0             	add    rax,rdx
   140002154:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002158:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000215c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000215e:	89 c2                	mov    edx,eax
   140002160:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002164:	48 01 d0             	add    rax,rdx
   140002167:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000216b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000216f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002172:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002176:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000217a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000217d:	0f b6 c0             	movzx  eax,al
   140002180:	83 f8 40             	cmp    eax,0x40
   140002183:	0f 84 b6 00 00 00    	je     14000223f <do_pseudo_reloc+0x1fd>
   140002189:	83 f8 40             	cmp    eax,0x40
   14000218c:	0f 87 ba 00 00 00    	ja     14000224c <do_pseudo_reloc+0x20a>
   140002192:	83 f8 20             	cmp    eax,0x20
   140002195:	74 77                	je     14000220e <do_pseudo_reloc+0x1cc>
   140002197:	83 f8 20             	cmp    eax,0x20
   14000219a:	0f 87 ac 00 00 00    	ja     14000224c <do_pseudo_reloc+0x20a>
   1400021a0:	83 f8 08             	cmp    eax,0x8
   1400021a3:	74 0a                	je     1400021af <do_pseudo_reloc+0x16d>
   1400021a5:	83 f8 10             	cmp    eax,0x10
   1400021a8:	74 38                	je     1400021e2 <do_pseudo_reloc+0x1a0>
   1400021aa:	e9 9d 00 00 00       	jmp    14000224c <do_pseudo_reloc+0x20a>
   1400021af:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021b3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400021b6:	0f b6 c0             	movzx  eax,al
   1400021b9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021bd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021c1:	25 80 00 00 00       	and    eax,0x80
   1400021c6:	48 85 c0             	test   rax,rax
   1400021c9:	0f 84 9d 00 00 00    	je     14000226c <do_pseudo_reloc+0x22a>
   1400021cf:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021d3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400021d9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021dd:	e9 8a 00 00 00       	jmp    14000226c <do_pseudo_reloc+0x22a>
   1400021e2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021e6:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400021e9:	0f b7 c0             	movzx  eax,ax
   1400021ec:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021f0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021f4:	25 00 80 00 00       	and    eax,0x8000
   1400021f9:	48 85 c0             	test   rax,rax
   1400021fc:	74 71                	je     14000226f <do_pseudo_reloc+0x22d>
   1400021fe:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002202:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002208:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000220c:	eb 61                	jmp    14000226f <do_pseudo_reloc+0x22d>
   14000220e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002212:	8b 00                	mov    eax,DWORD PTR [rax]
   140002214:	89 c0                	mov    eax,eax
   140002216:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000221a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000221e:	25 00 00 00 80       	and    eax,0x80000000
   140002223:	48 85 c0             	test   rax,rax
   140002226:	74 4a                	je     140002272 <do_pseudo_reloc+0x230>
   140002228:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000222c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002233:	ff ff ff 
   140002236:	48 09 d0             	or     rax,rdx
   140002239:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000223d:	eb 33                	jmp    140002272 <do_pseudo_reloc+0x230>
   14000223f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002243:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002246:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000224a:	eb 27                	jmp    140002273 <do_pseudo_reloc+0x231>
   14000224c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002253:	00 
   140002254:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002258:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000225b:	0f b6 c0             	movzx  eax,al
   14000225e:	48 8d 0d 43 30 00 00 	lea    rcx,[rip+0x3043]        # 1400052a8 <.rdata+0xd8>
   140002265:	89 c2                	mov    edx,eax
   140002267:	e8 74 f9 ff ff       	call   140001be0 <__report_error>
   14000226c:	90                   	nop
   14000226d:	eb 04                	jmp    140002273 <do_pseudo_reloc+0x231>
   14000226f:	90                   	nop
   140002270:	eb 01                	jmp    140002273 <do_pseudo_reloc+0x231>
   140002272:	90                   	nop
   140002273:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002277:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000227b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000227d:	89 c2                	mov    edx,eax
   14000227f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002283:	48 01 c2             	add    rdx,rax
   140002286:	48 89 c8             	mov    rax,rcx
   140002289:	48 29 d0             	sub    rax,rdx
   14000228c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002290:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002294:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002298:	48 01 d0             	add    rax,rdx
   14000229b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000229f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022a3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022a6:	25 ff 00 00 00       	and    eax,0xff
   1400022ab:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400022ae:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400022b2:	77 67                	ja     14000231b <do_pseudo_reloc+0x2d9>
   1400022b4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022b7:	ba 01 00 00 00       	mov    edx,0x1
   1400022bc:	89 c1                	mov    ecx,eax
   1400022be:	48 d3 e2             	shl    rdx,cl
   1400022c1:	48 89 d0             	mov    rax,rdx
   1400022c4:	48 83 e8 01          	sub    rax,0x1
   1400022c8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400022cc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022cf:	83 e8 01             	sub    eax,0x1
   1400022d2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400022d9:	89 c1                	mov    ecx,eax
   1400022db:	48 d3 e2             	shl    rdx,cl
   1400022de:	48 89 d0             	mov    rax,rdx
   1400022e1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400022e5:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022e9:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   1400022ed:	7c 0a                	jl     1400022f9 <do_pseudo_reloc+0x2b7>
   1400022ef:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022f3:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400022f7:	7e 22                	jle    14000231b <do_pseudo_reloc+0x2d9>
   1400022f9:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400022fd:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002301:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002305:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002308:	48 8d 0d c9 2f 00 00 	lea    rcx,[rip+0x2fc9]        # 1400052d8 <.rdata+0x108>
   14000230f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002314:	89 c2                	mov    edx,eax
   140002316:	e8 c5 f8 ff ff       	call   140001be0 <__report_error>
   14000231b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000231f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002322:	0f b6 c0             	movzx  eax,al
   140002325:	83 f8 40             	cmp    eax,0x40
   140002328:	74 63                	je     14000238d <do_pseudo_reloc+0x34b>
   14000232a:	83 f8 40             	cmp    eax,0x40
   14000232d:	77 75                	ja     1400023a4 <do_pseudo_reloc+0x362>
   14000232f:	83 f8 20             	cmp    eax,0x20
   140002332:	74 41                	je     140002375 <do_pseudo_reloc+0x333>
   140002334:	83 f8 20             	cmp    eax,0x20
   140002337:	77 6b                	ja     1400023a4 <do_pseudo_reloc+0x362>
   140002339:	83 f8 08             	cmp    eax,0x8
   14000233c:	74 07                	je     140002345 <do_pseudo_reloc+0x303>
   14000233e:	83 f8 10             	cmp    eax,0x10
   140002341:	74 1a                	je     14000235d <do_pseudo_reloc+0x31b>
   140002343:	eb 5f                	jmp    1400023a4 <do_pseudo_reloc+0x362>
   140002345:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002349:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000234d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002353:	48 89 c1             	mov    rcx,rax
   140002356:	e8 a0 fc ff ff       	call   140001ffb <__write_memory>
   14000235b:	eb 47                	jmp    1400023a4 <do_pseudo_reloc+0x362>
   14000235d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002361:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002365:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000236b:	48 89 c1             	mov    rcx,rax
   14000236e:	e8 88 fc ff ff       	call   140001ffb <__write_memory>
   140002373:	eb 2f                	jmp    1400023a4 <do_pseudo_reloc+0x362>
   140002375:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002379:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000237d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002383:	48 89 c1             	mov    rcx,rax
   140002386:	e8 70 fc ff ff       	call   140001ffb <__write_memory>
   14000238b:	eb 17                	jmp    1400023a4 <do_pseudo_reloc+0x362>
   14000238d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002391:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002395:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000239b:	48 89 c1             	mov    rcx,rax
   14000239e:	e8 58 fc ff ff       	call   140001ffb <__write_memory>
   1400023a3:	90                   	nop
   1400023a4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400023a9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400023ad:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400023b1:	0f 82 8d fd ff ff    	jb     140002144 <do_pseudo_reloc+0x102>
   1400023b7:	eb 01                	jmp    1400023ba <do_pseudo_reloc+0x378>
   1400023b9:	90                   	nop
   1400023ba:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400023be:	5d                   	pop    rbp
   1400023bf:	c3                   	ret

00000001400023c0 <_pei386_runtime_relocator>:
   1400023c0:	55                   	push   rbp
   1400023c1:	48 89 e5             	mov    rbp,rsp
   1400023c4:	48 83 ec 30          	sub    rsp,0x30
   1400023c8:	8b 05 1e 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d1e]        # 1400090ec <was_init.0>
   1400023ce:	85 c0                	test   eax,eax
   1400023d0:	0f 85 88 00 00 00    	jne    14000245e <_pei386_runtime_relocator+0x9e>
   1400023d6:	8b 05 10 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d10]        # 1400090ec <was_init.0>
   1400023dc:	83 c0 01             	add    eax,0x1
   1400023df:	89 05 07 6d 00 00    	mov    DWORD PTR [rip+0x6d07],eax        # 1400090ec <was_init.0>
   1400023e5:	e8 21 0b 00 00       	call   140002f0b <__mingw_GetSectionCount>
   1400023ea:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400023ed:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400023f0:	48 63 d0             	movsxd rdx,eax
   1400023f3:	48 89 d0             	mov    rax,rdx
   1400023f6:	48 c1 e0 02          	shl    rax,0x2
   1400023fa:	48 01 d0             	add    rax,rdx
   1400023fd:	48 c1 e0 03          	shl    rax,0x3
   140002401:	48 83 c0 0f          	add    rax,0xf
   140002405:	48 c1 e8 04          	shr    rax,0x4
   140002409:	48 c1 e0 04          	shl    rax,0x4
   14000240d:	e8 7e 0d 00 00       	call   140003190 <___chkstk_ms>
   140002412:	48 29 c4             	sub    rsp,rax
   140002415:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000241a:	48 83 c0 0f          	add    rax,0xf
   14000241e:	48 c1 e8 04          	shr    rax,0x4
   140002422:	48 c1 e0 04          	shl    rax,0x4
   140002426:	48 89 05 b3 6c 00 00 	mov    QWORD PTR [rip+0x6cb3],rax        # 1400090e0 <the_secs>
   14000242d:	c7 05 b1 6c 00 00 00 	mov    DWORD PTR [rip+0x6cb1],0x0        # 1400090e8 <maxSections>
   140002434:	00 00 00 
   140002437:	48 8b 0d 22 2f 00 00 	mov    rcx,QWORD PTR [rip+0x2f22]        # 140005360 <.refptr.__ImageBase>
   14000243e:	48 8b 15 2b 2f 00 00 	mov    rdx,QWORD PTR [rip+0x2f2b]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002445:	48 8b 05 34 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f34]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000244c:	49 89 c8             	mov    r8,rcx
   14000244f:	48 89 c1             	mov    rcx,rax
   140002452:	e8 eb fb ff ff       	call   140002042 <do_pseudo_reloc>
   140002457:	e8 c7 fa ff ff       	call   140001f23 <restore_modified_sections>
   14000245c:	eb 01                	jmp    14000245f <_pei386_runtime_relocator+0x9f>
   14000245e:	90                   	nop
   14000245f:	48 89 ec             	mov    rsp,rbp
   140002462:	5d                   	pop    rbp
   140002463:	c3                   	ret
   140002464:	90                   	nop
   140002465:	90                   	nop
   140002466:	90                   	nop
   140002467:	90                   	nop
   140002468:	90                   	nop
   140002469:	90                   	nop
   14000246a:	90                   	nop
   14000246b:	90                   	nop
   14000246c:	90                   	nop
   14000246d:	90                   	nop
   14000246e:	90                   	nop
   14000246f:	90                   	nop

0000000140002470 <__mingw_raise_matherr>:
   140002470:	55                   	push   rbp
   140002471:	48 89 e5             	mov    rbp,rsp
   140002474:	48 83 ec 50          	sub    rsp,0x50
   140002478:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000247b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000247f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002484:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002489:	48 8b 05 60 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c60]        # 1400090f0 <stUserMathErr>
   140002490:	48 85 c0             	test   rax,rax
   140002493:	74 3e                	je     1400024d3 <__mingw_raise_matherr+0x63>
   140002495:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002498:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000249b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000249f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400024a3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400024a8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400024ad:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400024b2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400024b7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400024bc:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400024c1:	48 8b 15 28 6c 00 00 	mov    rdx,QWORD PTR [rip+0x6c28]        # 1400090f0 <stUserMathErr>
   1400024c8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400024cc:	48 89 c1             	mov    rcx,rax
   1400024cf:	ff d2                	call   rdx
   1400024d1:	eb 01                	jmp    1400024d4 <__mingw_raise_matherr+0x64>
   1400024d3:	90                   	nop
   1400024d4:	48 83 c4 50          	add    rsp,0x50
   1400024d8:	5d                   	pop    rbp
   1400024d9:	c3                   	ret

00000001400024da <__mingw_setusermatherr>:
   1400024da:	55                   	push   rbp
   1400024db:	48 89 e5             	mov    rbp,rsp
   1400024de:	48 83 ec 20          	sub    rsp,0x20
   1400024e2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024e6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024ea:	48 89 05 ff 6b 00 00 	mov    QWORD PTR [rip+0x6bff],rax        # 1400090f0 <stUserMathErr>
   1400024f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024f5:	48 89 c1             	mov    rcx,rax
   1400024f8:	e8 13 0e 00 00       	call   140003310 <__setusermatherr>
   1400024fd:	90                   	nop
   1400024fe:	48 83 c4 20          	add    rsp,0x20
   140002502:	5d                   	pop    rbp
   140002503:	c3                   	ret
   140002504:	90                   	nop
   140002505:	90                   	nop
   140002506:	90                   	nop
   140002507:	90                   	nop
   140002508:	90                   	nop
   140002509:	90                   	nop
   14000250a:	90                   	nop
   14000250b:	90                   	nop
   14000250c:	90                   	nop
   14000250d:	90                   	nop
   14000250e:	90                   	nop
   14000250f:	90                   	nop

0000000140002510 <__mingw_SEH_error_handler>:
   140002510:	55                   	push   rbp
   140002511:	48 89 e5             	mov    rbp,rsp
   140002514:	48 83 ec 30          	sub    rsp,0x30
   140002518:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000251c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002520:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002524:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002528:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000252f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002536:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000253a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000253d:	83 e0 02             	and    eax,0x2
   140002540:	85 c0                	test   eax,eax
   140002542:	74 0a                	je     14000254e <__mingw_SEH_error_handler+0x3e>
   140002544:	b8 01 00 00 00       	mov    eax,0x1
   140002549:	e9 16 02 00 00       	jmp    140002764 <__mingw_SEH_error_handler+0x254>
   14000254e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002552:	8b 00                	mov    eax,DWORD PTR [rax]
   140002554:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002559:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000255e:	75 18                	jne    140002578 <__mingw_SEH_error_handler+0x68>
   140002560:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002564:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002567:	83 e0 01             	and    eax,0x1
   14000256a:	85 c0                	test   eax,eax
   14000256c:	75 0a                	jne    140002578 <__mingw_SEH_error_handler+0x68>
   14000256e:	b8 00 00 00 00       	mov    eax,0x0
   140002573:	e9 ec 01 00 00       	jmp    140002764 <__mingw_SEH_error_handler+0x254>
   140002578:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000257c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000257e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002583:	0f 84 12 01 00 00    	je     14000269b <__mingw_SEH_error_handler+0x18b>
   140002589:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000258e:	0f 87 c3 01 00 00    	ja     140002757 <__mingw_SEH_error_handler+0x247>
   140002594:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002599:	0f 87 b8 01 00 00    	ja     140002757 <__mingw_SEH_error_handler+0x247>
   14000259f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400025a4:	0f 83 4c 01 00 00    	jae    1400026f6 <__mingw_SEH_error_handler+0x1e6>
   1400025aa:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400025af:	0f 84 3a 01 00 00    	je     1400026ef <__mingw_SEH_error_handler+0x1df>
   1400025b5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400025ba:	0f 87 97 01 00 00    	ja     140002757 <__mingw_SEH_error_handler+0x247>
   1400025c0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025c5:	0f 84 83 01 00 00    	je     14000274e <__mingw_SEH_error_handler+0x23e>
   1400025cb:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025d0:	0f 87 81 01 00 00    	ja     140002757 <__mingw_SEH_error_handler+0x247>
   1400025d6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400025db:	0f 87 76 01 00 00    	ja     140002757 <__mingw_SEH_error_handler+0x247>
   1400025e1:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400025e6:	0f 83 03 01 00 00    	jae    1400026ef <__mingw_SEH_error_handler+0x1df>
   1400025ec:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025f1:	0f 84 57 01 00 00    	je     14000274e <__mingw_SEH_error_handler+0x23e>
   1400025f7:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025fc:	0f 87 55 01 00 00    	ja     140002757 <__mingw_SEH_error_handler+0x247>
   140002602:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002607:	0f 84 8e 00 00 00    	je     14000269b <__mingw_SEH_error_handler+0x18b>
   14000260d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002612:	0f 87 3f 01 00 00    	ja     140002757 <__mingw_SEH_error_handler+0x247>
   140002618:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000261d:	0f 84 2b 01 00 00    	je     14000274e <__mingw_SEH_error_handler+0x23e>
   140002623:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002628:	0f 87 29 01 00 00    	ja     140002757 <__mingw_SEH_error_handler+0x247>
   14000262e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002633:	0f 84 15 01 00 00    	je     14000274e <__mingw_SEH_error_handler+0x23e>
   140002639:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000263e:	0f 85 13 01 00 00    	jne    140002757 <__mingw_SEH_error_handler+0x247>
   140002644:	ba 00 00 00 00       	mov    edx,0x0
   140002649:	b9 0b 00 00 00       	mov    ecx,0xb
   14000264e:	e8 2d 0d 00 00       	call   140003380 <signal>
   140002653:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002657:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000265c:	75 1b                	jne    140002679 <__mingw_SEH_error_handler+0x169>
   14000265e:	ba 01 00 00 00       	mov    edx,0x1
   140002663:	b9 0b 00 00 00       	mov    ecx,0xb
   140002668:	e8 13 0d 00 00       	call   140003380 <signal>
   14000266d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002674:	e9 e1 00 00 00       	jmp    14000275a <__mingw_SEH_error_handler+0x24a>
   140002679:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000267e:	0f 84 d6 00 00 00    	je     14000275a <__mingw_SEH_error_handler+0x24a>
   140002684:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002688:	b9 0b 00 00 00       	mov    ecx,0xb
   14000268d:	ff d0                	call   rax
   14000268f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002696:	e9 bf 00 00 00       	jmp    14000275a <__mingw_SEH_error_handler+0x24a>
   14000269b:	ba 00 00 00 00       	mov    edx,0x0
   1400026a0:	b9 04 00 00 00       	mov    ecx,0x4
   1400026a5:	e8 d6 0c 00 00       	call   140003380 <signal>
   1400026aa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026ae:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026b3:	75 1b                	jne    1400026d0 <__mingw_SEH_error_handler+0x1c0>
   1400026b5:	ba 01 00 00 00       	mov    edx,0x1
   1400026ba:	b9 04 00 00 00       	mov    ecx,0x4
   1400026bf:	e8 bc 0c 00 00       	call   140003380 <signal>
   1400026c4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026cb:	e9 8d 00 00 00       	jmp    14000275d <__mingw_SEH_error_handler+0x24d>
   1400026d0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026d5:	0f 84 82 00 00 00    	je     14000275d <__mingw_SEH_error_handler+0x24d>
   1400026db:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026df:	b9 04 00 00 00       	mov    ecx,0x4
   1400026e4:	ff d0                	call   rax
   1400026e6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026ed:	eb 6e                	jmp    14000275d <__mingw_SEH_error_handler+0x24d>
   1400026ef:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400026f6:	ba 00 00 00 00       	mov    edx,0x0
   1400026fb:	b9 08 00 00 00       	mov    ecx,0x8
   140002700:	e8 7b 0c 00 00       	call   140003380 <signal>
   140002705:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002709:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000270e:	75 23                	jne    140002733 <__mingw_SEH_error_handler+0x223>
   140002710:	ba 01 00 00 00       	mov    edx,0x1
   140002715:	b9 08 00 00 00       	mov    ecx,0x8
   14000271a:	e8 61 0c 00 00       	call   140003380 <signal>
   14000271f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002723:	74 05                	je     14000272a <__mingw_SEH_error_handler+0x21a>
   140002725:	e8 a6 05 00 00       	call   140002cd0 <_fpreset>
   14000272a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002731:	eb 2d                	jmp    140002760 <__mingw_SEH_error_handler+0x250>
   140002733:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002738:	74 26                	je     140002760 <__mingw_SEH_error_handler+0x250>
   14000273a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000273e:	b9 08 00 00 00       	mov    ecx,0x8
   140002743:	ff d0                	call   rax
   140002745:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000274c:	eb 12                	jmp    140002760 <__mingw_SEH_error_handler+0x250>
   14000274e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002755:	eb 0a                	jmp    140002761 <__mingw_SEH_error_handler+0x251>
   140002757:	90                   	nop
   140002758:	eb 07                	jmp    140002761 <__mingw_SEH_error_handler+0x251>
   14000275a:	90                   	nop
   14000275b:	eb 04                	jmp    140002761 <__mingw_SEH_error_handler+0x251>
   14000275d:	90                   	nop
   14000275e:	eb 01                	jmp    140002761 <__mingw_SEH_error_handler+0x251>
   140002760:	90                   	nop
   140002761:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002764:	48 83 c4 30          	add    rsp,0x30
   140002768:	5d                   	pop    rbp
   140002769:	c3                   	ret

000000014000276a <_gnu_exception_handler>:
   14000276a:	55                   	push   rbp
   14000276b:	48 89 e5             	mov    rbp,rsp
   14000276e:	48 83 ec 30          	sub    rsp,0x30
   140002772:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002776:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000277d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002784:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002788:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000278b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000278d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002792:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002797:	75 1b                	jne    1400027b4 <_gnu_exception_handler+0x4a>
   140002799:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000279d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400027a0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400027a3:	83 e0 01             	and    eax,0x1
   1400027a6:	85 c0                	test   eax,eax
   1400027a8:	75 0a                	jne    1400027b4 <_gnu_exception_handler+0x4a>
   1400027aa:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400027af:	e9 14 02 00 00       	jmp    1400029c8 <_gnu_exception_handler+0x25e>
   1400027b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400027b8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400027bb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400027bd:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400027c2:	0f 84 12 01 00 00    	je     1400028da <_gnu_exception_handler+0x170>
   1400027c8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400027cd:	0f 87 c3 01 00 00    	ja     140002996 <_gnu_exception_handler+0x22c>
   1400027d3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400027d8:	0f 87 b8 01 00 00    	ja     140002996 <_gnu_exception_handler+0x22c>
   1400027de:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400027e3:	0f 83 4c 01 00 00    	jae    140002935 <_gnu_exception_handler+0x1cb>
   1400027e9:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027ee:	0f 84 3a 01 00 00    	je     14000292e <_gnu_exception_handler+0x1c4>
   1400027f4:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027f9:	0f 87 97 01 00 00    	ja     140002996 <_gnu_exception_handler+0x22c>
   1400027ff:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002804:	0f 84 83 01 00 00    	je     14000298d <_gnu_exception_handler+0x223>
   14000280a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000280f:	0f 87 81 01 00 00    	ja     140002996 <_gnu_exception_handler+0x22c>
   140002815:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000281a:	0f 87 76 01 00 00    	ja     140002996 <_gnu_exception_handler+0x22c>
   140002820:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002825:	0f 83 03 01 00 00    	jae    14000292e <_gnu_exception_handler+0x1c4>
   14000282b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002830:	0f 84 57 01 00 00    	je     14000298d <_gnu_exception_handler+0x223>
   140002836:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000283b:	0f 87 55 01 00 00    	ja     140002996 <_gnu_exception_handler+0x22c>
   140002841:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002846:	0f 84 8e 00 00 00    	je     1400028da <_gnu_exception_handler+0x170>
   14000284c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002851:	0f 87 3f 01 00 00    	ja     140002996 <_gnu_exception_handler+0x22c>
   140002857:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000285c:	0f 84 2b 01 00 00    	je     14000298d <_gnu_exception_handler+0x223>
   140002862:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002867:	0f 87 29 01 00 00    	ja     140002996 <_gnu_exception_handler+0x22c>
   14000286d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002872:	0f 84 15 01 00 00    	je     14000298d <_gnu_exception_handler+0x223>
   140002878:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000287d:	0f 85 13 01 00 00    	jne    140002996 <_gnu_exception_handler+0x22c>
   140002883:	ba 00 00 00 00       	mov    edx,0x0
   140002888:	b9 0b 00 00 00       	mov    ecx,0xb
   14000288d:	e8 ee 0a 00 00       	call   140003380 <signal>
   140002892:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002896:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000289b:	75 1b                	jne    1400028b8 <_gnu_exception_handler+0x14e>
   14000289d:	ba 01 00 00 00       	mov    edx,0x1
   1400028a2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400028a7:	e8 d4 0a 00 00       	call   140003380 <signal>
   1400028ac:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028b3:	e9 e1 00 00 00       	jmp    140002999 <_gnu_exception_handler+0x22f>
   1400028b8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028bd:	0f 84 d6 00 00 00    	je     140002999 <_gnu_exception_handler+0x22f>
   1400028c3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028c7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400028cc:	ff d0                	call   rax
   1400028ce:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028d5:	e9 bf 00 00 00       	jmp    140002999 <_gnu_exception_handler+0x22f>
   1400028da:	ba 00 00 00 00       	mov    edx,0x0
   1400028df:	b9 04 00 00 00       	mov    ecx,0x4
   1400028e4:	e8 97 0a 00 00       	call   140003380 <signal>
   1400028e9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028ed:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028f2:	75 1b                	jne    14000290f <_gnu_exception_handler+0x1a5>
   1400028f4:	ba 01 00 00 00       	mov    edx,0x1
   1400028f9:	b9 04 00 00 00       	mov    ecx,0x4
   1400028fe:	e8 7d 0a 00 00       	call   140003380 <signal>
   140002903:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000290a:	e9 8d 00 00 00       	jmp    14000299c <_gnu_exception_handler+0x232>
   14000290f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002914:	0f 84 82 00 00 00    	je     14000299c <_gnu_exception_handler+0x232>
   14000291a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000291e:	b9 04 00 00 00       	mov    ecx,0x4
   140002923:	ff d0                	call   rax
   140002925:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000292c:	eb 6e                	jmp    14000299c <_gnu_exception_handler+0x232>
   14000292e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002935:	ba 00 00 00 00       	mov    edx,0x0
   14000293a:	b9 08 00 00 00       	mov    ecx,0x8
   14000293f:	e8 3c 0a 00 00       	call   140003380 <signal>
   140002944:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002948:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000294d:	75 23                	jne    140002972 <_gnu_exception_handler+0x208>
   14000294f:	ba 01 00 00 00       	mov    edx,0x1
   140002954:	b9 08 00 00 00       	mov    ecx,0x8
   140002959:	e8 22 0a 00 00       	call   140003380 <signal>
   14000295e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002962:	74 05                	je     140002969 <_gnu_exception_handler+0x1ff>
   140002964:	e8 67 03 00 00       	call   140002cd0 <_fpreset>
   140002969:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002970:	eb 2d                	jmp    14000299f <_gnu_exception_handler+0x235>
   140002972:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002977:	74 26                	je     14000299f <_gnu_exception_handler+0x235>
   140002979:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000297d:	b9 08 00 00 00       	mov    ecx,0x8
   140002982:	ff d0                	call   rax
   140002984:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000298b:	eb 12                	jmp    14000299f <_gnu_exception_handler+0x235>
   14000298d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002994:	eb 0a                	jmp    1400029a0 <_gnu_exception_handler+0x236>
   140002996:	90                   	nop
   140002997:	eb 07                	jmp    1400029a0 <_gnu_exception_handler+0x236>
   140002999:	90                   	nop
   14000299a:	eb 04                	jmp    1400029a0 <_gnu_exception_handler+0x236>
   14000299c:	90                   	nop
   14000299d:	eb 01                	jmp    1400029a0 <_gnu_exception_handler+0x236>
   14000299f:	90                   	nop
   1400029a0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400029a4:	75 1f                	jne    1400029c5 <_gnu_exception_handler+0x25b>
   1400029a6:	48 8b 05 63 67 00 00 	mov    rax,QWORD PTR [rip+0x6763]        # 140009110 <__mingw_oldexcpt_handler>
   1400029ad:	48 85 c0             	test   rax,rax
   1400029b0:	74 13                	je     1400029c5 <_gnu_exception_handler+0x25b>
   1400029b2:	48 8b 15 57 67 00 00 	mov    rdx,QWORD PTR [rip+0x6757]        # 140009110 <__mingw_oldexcpt_handler>
   1400029b9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400029bd:	48 89 c1             	mov    rcx,rax
   1400029c0:	ff d2                	call   rdx
   1400029c2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400029c5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400029c8:	48 83 c4 30          	add    rsp,0x30
   1400029cc:	5d                   	pop    rbp
   1400029cd:	c3                   	ret
   1400029ce:	90                   	nop
   1400029cf:	90                   	nop

00000001400029d0 <___w64_mingwthr_add_key_dtor>:
   1400029d0:	55                   	push   rbp
   1400029d1:	48 89 e5             	mov    rbp,rsp
   1400029d4:	48 83 ec 30          	sub    rsp,0x30
   1400029d8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029db:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400029df:	8b 05 63 67 00 00    	mov    eax,DWORD PTR [rip+0x6763]        # 140009148 <__mingwthr_cs_init>
   1400029e5:	85 c0                	test   eax,eax
   1400029e7:	75 07                	jne    1400029f0 <___w64_mingwthr_add_key_dtor+0x20>
   1400029e9:	b8 00 00 00 00       	mov    eax,0x0
   1400029ee:	eb 7b                	jmp    140002a6b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029f0:	ba 18 00 00 00       	mov    edx,0x18
   1400029f5:	b9 01 00 00 00       	mov    ecx,0x1
   1400029fa:	e8 41 09 00 00       	call   140003340 <calloc>
   1400029ff:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a03:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a08:	75 07                	jne    140002a11 <___w64_mingwthr_add_key_dtor+0x41>
   140002a0a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140002a0f:	eb 5a                	jmp    140002a6b <___w64_mingwthr_add_key_dtor+0x9b>
   140002a11:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a15:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002a18:	89 10                	mov    DWORD PTR [rax],edx
   140002a1a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a1e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002a22:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002a26:	48 8d 05 f3 66 00 00 	lea    rax,[rip+0x66f3]        # 140009120 <__mingwthr_cs>
   140002a2d:	48 89 c1             	mov    rcx,rax
   140002a30:	48 8b 05 59 77 00 00 	mov    rax,QWORD PTR [rip+0x7759]        # 14000a190 <__imp_EnterCriticalSection>
   140002a37:	ff d0                	call   rax
   140002a39:	48 8b 15 10 67 00 00 	mov    rdx,QWORD PTR [rip+0x6710]        # 140009150 <key_dtor_list>
   140002a40:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a44:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a48:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a4c:	48 89 05 fd 66 00 00 	mov    QWORD PTR [rip+0x66fd],rax        # 140009150 <key_dtor_list>
   140002a53:	48 8d 05 c6 66 00 00 	lea    rax,[rip+0x66c6]        # 140009120 <__mingwthr_cs>
   140002a5a:	48 89 c1             	mov    rcx,rax
   140002a5d:	48 8b 05 5c 77 00 00 	mov    rax,QWORD PTR [rip+0x775c]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002a64:	ff d0                	call   rax
   140002a66:	b8 00 00 00 00       	mov    eax,0x0
   140002a6b:	48 83 c4 30          	add    rsp,0x30
   140002a6f:	5d                   	pop    rbp
   140002a70:	c3                   	ret

0000000140002a71 <___w64_mingwthr_remove_key_dtor>:
   140002a71:	55                   	push   rbp
   140002a72:	48 89 e5             	mov    rbp,rsp
   140002a75:	48 83 ec 30          	sub    rsp,0x30
   140002a79:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a7c:	8b 05 c6 66 00 00    	mov    eax,DWORD PTR [rip+0x66c6]        # 140009148 <__mingwthr_cs_init>
   140002a82:	85 c0                	test   eax,eax
   140002a84:	75 0a                	jne    140002a90 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a86:	b8 00 00 00 00       	mov    eax,0x0
   140002a8b:	e9 9c 00 00 00       	jmp    140002b2c <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a90:	48 8d 05 89 66 00 00 	lea    rax,[rip+0x6689]        # 140009120 <__mingwthr_cs>
   140002a97:	48 89 c1             	mov    rcx,rax
   140002a9a:	48 8b 05 ef 76 00 00 	mov    rax,QWORD PTR [rip+0x76ef]        # 14000a190 <__imp_EnterCriticalSection>
   140002aa1:	ff d0                	call   rax
   140002aa3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002aaa:	00 
   140002aab:	48 8b 05 9e 66 00 00 	mov    rax,QWORD PTR [rip+0x669e]        # 140009150 <key_dtor_list>
   140002ab2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ab6:	eb 55                	jmp    140002b0d <___w64_mingwthr_remove_key_dtor+0x9c>
   140002ab8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002abc:	8b 00                	mov    eax,DWORD PTR [rax]
   140002abe:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002ac1:	75 36                	jne    140002af9 <___w64_mingwthr_remove_key_dtor+0x88>
   140002ac3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ac8:	75 11                	jne    140002adb <___w64_mingwthr_remove_key_dtor+0x6a>
   140002aca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ace:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ad2:	48 89 05 77 66 00 00 	mov    QWORD PTR [rip+0x6677],rax        # 140009150 <key_dtor_list>
   140002ad9:	eb 10                	jmp    140002aeb <___w64_mingwthr_remove_key_dtor+0x7a>
   140002adb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002adf:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002ae3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ae7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002aeb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aef:	48 89 c1             	mov    rcx,rax
   140002af2:	e8 69 08 00 00       	call   140003360 <free>
   140002af7:	eb 1b                	jmp    140002b14 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002af9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002afd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b01:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b05:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b09:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b0d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b12:	75 a4                	jne    140002ab8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002b14:	48 8d 05 05 66 00 00 	lea    rax,[rip+0x6605]        # 140009120 <__mingwthr_cs>
   140002b1b:	48 89 c1             	mov    rcx,rax
   140002b1e:	48 8b 05 9b 76 00 00 	mov    rax,QWORD PTR [rip+0x769b]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002b25:	ff d0                	call   rax
   140002b27:	b8 00 00 00 00       	mov    eax,0x0
   140002b2c:	48 83 c4 30          	add    rsp,0x30
   140002b30:	5d                   	pop    rbp
   140002b31:	c3                   	ret

0000000140002b32 <__mingwthr_run_key_dtors>:
   140002b32:	55                   	push   rbp
   140002b33:	48 89 e5             	mov    rbp,rsp
   140002b36:	48 83 ec 30          	sub    rsp,0x30
   140002b3a:	8b 05 08 66 00 00    	mov    eax,DWORD PTR [rip+0x6608]        # 140009148 <__mingwthr_cs_init>
   140002b40:	85 c0                	test   eax,eax
   140002b42:	0f 84 82 00 00 00    	je     140002bca <__mingwthr_run_key_dtors+0x98>
   140002b48:	48 8d 05 d1 65 00 00 	lea    rax,[rip+0x65d1]        # 140009120 <__mingwthr_cs>
   140002b4f:	48 89 c1             	mov    rcx,rax
   140002b52:	48 8b 05 37 76 00 00 	mov    rax,QWORD PTR [rip+0x7637]        # 14000a190 <__imp_EnterCriticalSection>
   140002b59:	ff d0                	call   rax
   140002b5b:	48 8b 05 ee 65 00 00 	mov    rax,QWORD PTR [rip+0x65ee]        # 140009150 <key_dtor_list>
   140002b62:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b66:	eb 46                	jmp    140002bae <__mingwthr_run_key_dtors+0x7c>
   140002b68:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b6c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b6e:	89 c1                	mov    ecx,eax
   140002b70:	48 8b 05 69 76 00 00 	mov    rax,QWORD PTR [rip+0x7669]        # 14000a1e0 <__imp_TlsGetValue>
   140002b77:	ff d0                	call   rax
   140002b79:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b7d:	48 8b 05 1c 76 00 00 	mov    rax,QWORD PTR [rip+0x761c]        # 14000a1a0 <__imp_GetLastError>
   140002b84:	ff d0                	call   rax
   140002b86:	85 c0                	test   eax,eax
   140002b88:	75 18                	jne    140002ba2 <__mingwthr_run_key_dtors+0x70>
   140002b8a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b8f:	74 11                	je     140002ba2 <__mingwthr_run_key_dtors+0x70>
   140002b91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b95:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002b99:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b9d:	48 89 c1             	mov    rcx,rax
   140002ba0:	ff d2                	call   rdx
   140002ba2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ba6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002baa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bae:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002bb3:	75 b3                	jne    140002b68 <__mingwthr_run_key_dtors+0x36>
   140002bb5:	48 8d 05 64 65 00 00 	lea    rax,[rip+0x6564]        # 140009120 <__mingwthr_cs>
   140002bbc:	48 89 c1             	mov    rcx,rax
   140002bbf:	48 8b 05 fa 75 00 00 	mov    rax,QWORD PTR [rip+0x75fa]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002bc6:	ff d0                	call   rax
   140002bc8:	eb 01                	jmp    140002bcb <__mingwthr_run_key_dtors+0x99>
   140002bca:	90                   	nop
   140002bcb:	48 83 c4 30          	add    rsp,0x30
   140002bcf:	5d                   	pop    rbp
   140002bd0:	c3                   	ret

0000000140002bd1 <__mingw_TLScallback>:
   140002bd1:	55                   	push   rbp
   140002bd2:	48 89 e5             	mov    rbp,rsp
   140002bd5:	48 83 ec 30          	sub    rsp,0x30
   140002bd9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002bdd:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002be0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002be4:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002be8:	0f 84 cc 00 00 00    	je     140002cba <__mingw_TLScallback+0xe9>
   140002bee:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002bf2:	0f 87 ca 00 00 00    	ja     140002cc2 <__mingw_TLScallback+0xf1>
   140002bf8:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bfc:	0f 84 b1 00 00 00    	je     140002cb3 <__mingw_TLScallback+0xe2>
   140002c02:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002c06:	0f 87 b6 00 00 00    	ja     140002cc2 <__mingw_TLScallback+0xf1>
   140002c0c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002c10:	74 33                	je     140002c45 <__mingw_TLScallback+0x74>
   140002c12:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002c16:	0f 85 a6 00 00 00    	jne    140002cc2 <__mingw_TLScallback+0xf1>
   140002c1c:	8b 05 26 65 00 00    	mov    eax,DWORD PTR [rip+0x6526]        # 140009148 <__mingwthr_cs_init>
   140002c22:	85 c0                	test   eax,eax
   140002c24:	75 13                	jne    140002c39 <__mingw_TLScallback+0x68>
   140002c26:	48 8d 05 f3 64 00 00 	lea    rax,[rip+0x64f3]        # 140009120 <__mingwthr_cs>
   140002c2d:	48 89 c1             	mov    rcx,rax
   140002c30:	48 8b 05 81 75 00 00 	mov    rax,QWORD PTR [rip+0x7581]        # 14000a1b8 <__imp_InitializeCriticalSection>
   140002c37:	ff d0                	call   rax
   140002c39:	c7 05 05 65 00 00 01 	mov    DWORD PTR [rip+0x6505],0x1        # 140009148 <__mingwthr_cs_init>
   140002c40:	00 00 00 
   140002c43:	eb 7d                	jmp    140002cc2 <__mingw_TLScallback+0xf1>
   140002c45:	e8 e8 fe ff ff       	call   140002b32 <__mingwthr_run_key_dtors>
   140002c4a:	8b 05 f8 64 00 00    	mov    eax,DWORD PTR [rip+0x64f8]        # 140009148 <__mingwthr_cs_init>
   140002c50:	83 f8 01             	cmp    eax,0x1
   140002c53:	75 6c                	jne    140002cc1 <__mingw_TLScallback+0xf0>
   140002c55:	48 8b 05 f4 64 00 00 	mov    rax,QWORD PTR [rip+0x64f4]        # 140009150 <key_dtor_list>
   140002c5c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c60:	eb 20                	jmp    140002c82 <__mingw_TLScallback+0xb1>
   140002c62:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c66:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c6a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c6e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c72:	48 89 c1             	mov    rcx,rax
   140002c75:	e8 e6 06 00 00       	call   140003360 <free>
   140002c7a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c82:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c87:	75 d9                	jne    140002c62 <__mingw_TLScallback+0x91>
   140002c89:	48 c7 05 bc 64 00 00 	mov    QWORD PTR [rip+0x64bc],0x0        # 140009150 <key_dtor_list>
   140002c90:	00 00 00 00 
   140002c94:	c7 05 aa 64 00 00 00 	mov    DWORD PTR [rip+0x64aa],0x0        # 140009148 <__mingwthr_cs_init>
   140002c9b:	00 00 00 
   140002c9e:	48 8d 05 7b 64 00 00 	lea    rax,[rip+0x647b]        # 140009120 <__mingwthr_cs>
   140002ca5:	48 89 c1             	mov    rcx,rax
   140002ca8:	48 8b 05 d9 74 00 00 	mov    rax,QWORD PTR [rip+0x74d9]        # 14000a188 <__IAT_start__>
   140002caf:	ff d0                	call   rax
   140002cb1:	eb 0e                	jmp    140002cc1 <__mingw_TLScallback+0xf0>
   140002cb3:	e8 18 00 00 00       	call   140002cd0 <_fpreset>
   140002cb8:	eb 08                	jmp    140002cc2 <__mingw_TLScallback+0xf1>
   140002cba:	e8 73 fe ff ff       	call   140002b32 <__mingwthr_run_key_dtors>
   140002cbf:	eb 01                	jmp    140002cc2 <__mingw_TLScallback+0xf1>
   140002cc1:	90                   	nop
   140002cc2:	b8 01 00 00 00       	mov    eax,0x1
   140002cc7:	48 83 c4 30          	add    rsp,0x30
   140002ccb:	5d                   	pop    rbp
   140002ccc:	c3                   	ret
   140002ccd:	90                   	nop
   140002cce:	90                   	nop
   140002ccf:	90                   	nop

0000000140002cd0 <_fpreset>:
   140002cd0:	55                   	push   rbp
   140002cd1:	48 89 e5             	mov    rbp,rsp
   140002cd4:	db e3                	fninit
   140002cd6:	90                   	nop
   140002cd7:	5d                   	pop    rbp
   140002cd8:	c3                   	ret
   140002cd9:	90                   	nop
   140002cda:	90                   	nop
   140002cdb:	90                   	nop
   140002cdc:	90                   	nop
   140002cdd:	90                   	nop
   140002cde:	90                   	nop
   140002cdf:	90                   	nop

0000000140002ce0 <_ValidateImageBase>:
   140002ce0:	55                   	push   rbp
   140002ce1:	48 89 e5             	mov    rbp,rsp
   140002ce4:	48 83 ec 20          	sub    rsp,0x20
   140002ce8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002cec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cf0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cf4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cf8:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002cfb:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002cff:	74 07                	je     140002d08 <_ValidateImageBase+0x28>
   140002d01:	b8 00 00 00 00       	mov    eax,0x0
   140002d06:	eb 4e                	jmp    140002d56 <_ValidateImageBase+0x76>
   140002d08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d0c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d0f:	48 63 d0             	movsxd rdx,eax
   140002d12:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d16:	48 01 d0             	add    rax,rdx
   140002d19:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002d1d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d21:	8b 00                	mov    eax,DWORD PTR [rax]
   140002d23:	3d 50 45 00 00       	cmp    eax,0x4550
   140002d28:	74 07                	je     140002d31 <_ValidateImageBase+0x51>
   140002d2a:	b8 00 00 00 00       	mov    eax,0x0
   140002d2f:	eb 25                	jmp    140002d56 <_ValidateImageBase+0x76>
   140002d31:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d35:	48 83 c0 18          	add    rax,0x18
   140002d39:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d3d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d41:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d44:	66 3d 0b 02          	cmp    ax,0x20b
   140002d48:	74 07                	je     140002d51 <_ValidateImageBase+0x71>
   140002d4a:	b8 00 00 00 00       	mov    eax,0x0
   140002d4f:	eb 05                	jmp    140002d56 <_ValidateImageBase+0x76>
   140002d51:	b8 01 00 00 00       	mov    eax,0x1
   140002d56:	48 83 c4 20          	add    rsp,0x20
   140002d5a:	5d                   	pop    rbp
   140002d5b:	c3                   	ret

0000000140002d5c <_FindPESection>:
   140002d5c:	55                   	push   rbp
   140002d5d:	48 89 e5             	mov    rbp,rsp
   140002d60:	48 83 ec 20          	sub    rsp,0x20
   140002d64:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d68:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d6c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d70:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d73:	48 63 d0             	movsxd rdx,eax
   140002d76:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d7a:	48 01 d0             	add    rax,rdx
   140002d7d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d81:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d88:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d8c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d90:	0f b7 d0             	movzx  edx,ax
   140002d93:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d97:	48 01 d0             	add    rax,rdx
   140002d9a:	48 83 c0 18          	add    rax,0x18
   140002d9e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002da2:	eb 36                	jmp    140002dda <_FindPESection+0x7e>
   140002da4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002da8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002dab:	89 c0                	mov    eax,eax
   140002dad:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002db1:	72 1e                	jb     140002dd1 <_FindPESection+0x75>
   140002db3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002db7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002dba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dbe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002dc1:	01 d0                	add    eax,edx
   140002dc3:	89 c0                	mov    eax,eax
   140002dc5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002dc9:	73 06                	jae    140002dd1 <_FindPESection+0x75>
   140002dcb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dcf:	eb 1e                	jmp    140002def <_FindPESection+0x93>
   140002dd1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002dd5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002dda:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dde:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002de2:	0f b7 c0             	movzx  eax,ax
   140002de5:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002de8:	72 ba                	jb     140002da4 <_FindPESection+0x48>
   140002dea:	b8 00 00 00 00       	mov    eax,0x0
   140002def:	48 83 c4 20          	add    rsp,0x20
   140002df3:	5d                   	pop    rbp
   140002df4:	c3                   	ret

0000000140002df5 <_FindPESectionByName>:
   140002df5:	55                   	push   rbp
   140002df6:	48 89 e5             	mov    rbp,rsp
   140002df9:	48 83 ec 40          	sub    rsp,0x40
   140002dfd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e01:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e05:	48 89 c1             	mov    rcx,rax
   140002e08:	e8 7b 05 00 00       	call   140003388 <strlen>
   140002e0d:	48 83 f8 08          	cmp    rax,0x8
   140002e11:	76 0a                	jbe    140002e1d <_FindPESectionByName+0x28>
   140002e13:	b8 00 00 00 00       	mov    eax,0x0
   140002e18:	e9 98 00 00 00       	jmp    140002eb5 <_FindPESectionByName+0xc0>
   140002e1d:	48 8b 05 3c 25 00 00 	mov    rax,QWORD PTR [rip+0x253c]        # 140005360 <.refptr.__ImageBase>
   140002e24:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e28:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e2c:	48 89 c1             	mov    rcx,rax
   140002e2f:	e8 ac fe ff ff       	call   140002ce0 <_ValidateImageBase>
   140002e34:	85 c0                	test   eax,eax
   140002e36:	75 07                	jne    140002e3f <_FindPESectionByName+0x4a>
   140002e38:	b8 00 00 00 00       	mov    eax,0x0
   140002e3d:	eb 76                	jmp    140002eb5 <_FindPESectionByName+0xc0>
   140002e3f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e43:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e46:	48 63 d0             	movsxd rdx,eax
   140002e49:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e4d:	48 01 d0             	add    rax,rdx
   140002e50:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e54:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e5b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e5f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e63:	0f b7 d0             	movzx  edx,ax
   140002e66:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e6a:	48 01 d0             	add    rax,rdx
   140002e6d:	48 83 c0 18          	add    rax,0x18
   140002e71:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e75:	eb 29                	jmp    140002ea0 <_FindPESectionByName+0xab>
   140002e77:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e7b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e7f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e85:	48 89 c1             	mov    rcx,rax
   140002e88:	e8 03 05 00 00       	call   140003390 <strncmp>
   140002e8d:	85 c0                	test   eax,eax
   140002e8f:	75 06                	jne    140002e97 <_FindPESectionByName+0xa2>
   140002e91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e95:	eb 1e                	jmp    140002eb5 <_FindPESectionByName+0xc0>
   140002e97:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e9b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002ea0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ea4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ea8:	0f b7 c0             	movzx  eax,ax
   140002eab:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002eae:	72 c7                	jb     140002e77 <_FindPESectionByName+0x82>
   140002eb0:	b8 00 00 00 00       	mov    eax,0x0
   140002eb5:	48 83 c4 40          	add    rsp,0x40
   140002eb9:	5d                   	pop    rbp
   140002eba:	c3                   	ret

0000000140002ebb <__mingw_GetSectionForAddress>:
   140002ebb:	55                   	push   rbp
   140002ebc:	48 89 e5             	mov    rbp,rsp
   140002ebf:	48 83 ec 30          	sub    rsp,0x30
   140002ec3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ec7:	48 8b 05 92 24 00 00 	mov    rax,QWORD PTR [rip+0x2492]        # 140005360 <.refptr.__ImageBase>
   140002ece:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ed2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ed6:	48 89 c1             	mov    rcx,rax
   140002ed9:	e8 02 fe ff ff       	call   140002ce0 <_ValidateImageBase>
   140002ede:	85 c0                	test   eax,eax
   140002ee0:	75 07                	jne    140002ee9 <__mingw_GetSectionForAddress+0x2e>
   140002ee2:	b8 00 00 00 00       	mov    eax,0x0
   140002ee7:	eb 1c                	jmp    140002f05 <__mingw_GetSectionForAddress+0x4a>
   140002ee9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002eed:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002ef1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ef5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002ef9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002efd:	48 89 c1             	mov    rcx,rax
   140002f00:	e8 57 fe ff ff       	call   140002d5c <_FindPESection>
   140002f05:	48 83 c4 30          	add    rsp,0x30
   140002f09:	5d                   	pop    rbp
   140002f0a:	c3                   	ret

0000000140002f0b <__mingw_GetSectionCount>:
   140002f0b:	55                   	push   rbp
   140002f0c:	48 89 e5             	mov    rbp,rsp
   140002f0f:	48 83 ec 30          	sub    rsp,0x30
   140002f13:	48 8b 05 46 24 00 00 	mov    rax,QWORD PTR [rip+0x2446]        # 140005360 <.refptr.__ImageBase>
   140002f1a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f1e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f22:	48 89 c1             	mov    rcx,rax
   140002f25:	e8 b6 fd ff ff       	call   140002ce0 <_ValidateImageBase>
   140002f2a:	85 c0                	test   eax,eax
   140002f2c:	75 07                	jne    140002f35 <__mingw_GetSectionCount+0x2a>
   140002f2e:	b8 00 00 00 00       	mov    eax,0x0
   140002f33:	eb 20                	jmp    140002f55 <__mingw_GetSectionCount+0x4a>
   140002f35:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f39:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f3c:	48 63 d0             	movsxd rdx,eax
   140002f3f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f43:	48 01 d0             	add    rax,rdx
   140002f46:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f4a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002f4e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f52:	0f b7 c0             	movzx  eax,ax
   140002f55:	48 83 c4 30          	add    rsp,0x30
   140002f59:	5d                   	pop    rbp
   140002f5a:	c3                   	ret

0000000140002f5b <_FindPESectionExec>:
   140002f5b:	55                   	push   rbp
   140002f5c:	48 89 e5             	mov    rbp,rsp
   140002f5f:	48 83 ec 40          	sub    rsp,0x40
   140002f63:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f67:	48 8b 05 f2 23 00 00 	mov    rax,QWORD PTR [rip+0x23f2]        # 140005360 <.refptr.__ImageBase>
   140002f6e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f72:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f76:	48 89 c1             	mov    rcx,rax
   140002f79:	e8 62 fd ff ff       	call   140002ce0 <_ValidateImageBase>
   140002f7e:	85 c0                	test   eax,eax
   140002f80:	75 07                	jne    140002f89 <_FindPESectionExec+0x2e>
   140002f82:	b8 00 00 00 00       	mov    eax,0x0
   140002f87:	eb 78                	jmp    140003001 <_FindPESectionExec+0xa6>
   140002f89:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f8d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f90:	48 63 d0             	movsxd rdx,eax
   140002f93:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f97:	48 01 d0             	add    rax,rdx
   140002f9a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f9e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002fa5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fa9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002fad:	0f b7 d0             	movzx  edx,ax
   140002fb0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fb4:	48 01 d0             	add    rax,rdx
   140002fb7:	48 83 c0 18          	add    rax,0x18
   140002fbb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fbf:	eb 2b                	jmp    140002fec <_FindPESectionExec+0x91>
   140002fc1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fc5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fc8:	25 00 00 00 20       	and    eax,0x20000000
   140002fcd:	85 c0                	test   eax,eax
   140002fcf:	74 12                	je     140002fe3 <_FindPESectionExec+0x88>
   140002fd1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002fd6:	75 06                	jne    140002fde <_FindPESectionExec+0x83>
   140002fd8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fdc:	eb 23                	jmp    140003001 <_FindPESectionExec+0xa6>
   140002fde:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002fe3:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002fe7:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002fec:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ff0:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ff4:	0f b7 c0             	movzx  eax,ax
   140002ff7:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002ffa:	72 c5                	jb     140002fc1 <_FindPESectionExec+0x66>
   140002ffc:	b8 00 00 00 00       	mov    eax,0x0
   140003001:	48 83 c4 40          	add    rsp,0x40
   140003005:	5d                   	pop    rbp
   140003006:	c3                   	ret

0000000140003007 <_GetPEImageBase>:
   140003007:	55                   	push   rbp
   140003008:	48 89 e5             	mov    rbp,rsp
   14000300b:	48 83 ec 30          	sub    rsp,0x30
   14000300f:	48 8b 05 4a 23 00 00 	mov    rax,QWORD PTR [rip+0x234a]        # 140005360 <.refptr.__ImageBase>
   140003016:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000301a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000301e:	48 89 c1             	mov    rcx,rax
   140003021:	e8 ba fc ff ff       	call   140002ce0 <_ValidateImageBase>
   140003026:	85 c0                	test   eax,eax
   140003028:	75 07                	jne    140003031 <_GetPEImageBase+0x2a>
   14000302a:	b8 00 00 00 00       	mov    eax,0x0
   14000302f:	eb 04                	jmp    140003035 <_GetPEImageBase+0x2e>
   140003031:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003035:	48 83 c4 30          	add    rsp,0x30
   140003039:	5d                   	pop    rbp
   14000303a:	c3                   	ret

000000014000303b <_IsNonwritableInCurrentImage>:
   14000303b:	55                   	push   rbp
   14000303c:	48 89 e5             	mov    rbp,rsp
   14000303f:	48 83 ec 40          	sub    rsp,0x40
   140003043:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003047:	48 8b 05 12 23 00 00 	mov    rax,QWORD PTR [rip+0x2312]        # 140005360 <.refptr.__ImageBase>
   14000304e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003052:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003056:	48 89 c1             	mov    rcx,rax
   140003059:	e8 82 fc ff ff       	call   140002ce0 <_ValidateImageBase>
   14000305e:	85 c0                	test   eax,eax
   140003060:	75 07                	jne    140003069 <_IsNonwritableInCurrentImage+0x2e>
   140003062:	b8 00 00 00 00       	mov    eax,0x0
   140003067:	eb 3d                	jmp    1400030a6 <_IsNonwritableInCurrentImage+0x6b>
   140003069:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000306d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003071:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003075:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003079:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000307d:	48 89 c1             	mov    rcx,rax
   140003080:	e8 d7 fc ff ff       	call   140002d5c <_FindPESection>
   140003085:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003089:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000308e:	75 07                	jne    140003097 <_IsNonwritableInCurrentImage+0x5c>
   140003090:	b8 00 00 00 00       	mov    eax,0x0
   140003095:	eb 0f                	jmp    1400030a6 <_IsNonwritableInCurrentImage+0x6b>
   140003097:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000309b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000309e:	f7 d0                	not    eax
   1400030a0:	c1 e8 1f             	shr    eax,0x1f
   1400030a3:	0f b6 c0             	movzx  eax,al
   1400030a6:	48 83 c4 40          	add    rsp,0x40
   1400030aa:	5d                   	pop    rbp
   1400030ab:	c3                   	ret

00000001400030ac <__mingw_enum_import_library_names>:
   1400030ac:	55                   	push   rbp
   1400030ad:	48 89 e5             	mov    rbp,rsp
   1400030b0:	48 83 ec 50          	sub    rsp,0x50
   1400030b4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400030b7:	48 8b 05 a2 22 00 00 	mov    rax,QWORD PTR [rip+0x22a2]        # 140005360 <.refptr.__ImageBase>
   1400030be:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400030c2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030c6:	48 89 c1             	mov    rcx,rax
   1400030c9:	e8 12 fc ff ff       	call   140002ce0 <_ValidateImageBase>
   1400030ce:	85 c0                	test   eax,eax
   1400030d0:	75 0a                	jne    1400030dc <__mingw_enum_import_library_names+0x30>
   1400030d2:	b8 00 00 00 00       	mov    eax,0x0
   1400030d7:	e9 ab 00 00 00       	jmp    140003187 <__mingw_enum_import_library_names+0xdb>
   1400030dc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030e0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   1400030e3:	48 63 d0             	movsxd rdx,eax
   1400030e6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030ea:	48 01 d0             	add    rax,rdx
   1400030ed:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400030f1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030f5:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   1400030fb:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400030fe:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003102:	75 07                	jne    14000310b <__mingw_enum_import_library_names+0x5f>
   140003104:	b8 00 00 00 00       	mov    eax,0x0
   140003109:	eb 7c                	jmp    140003187 <__mingw_enum_import_library_names+0xdb>
   14000310b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000310e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003112:	48 89 c1             	mov    rcx,rax
   140003115:	e8 42 fc ff ff       	call   140002d5c <_FindPESection>
   14000311a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000311e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003123:	75 07                	jne    14000312c <__mingw_enum_import_library_names+0x80>
   140003125:	b8 00 00 00 00       	mov    eax,0x0
   14000312a:	eb 5b                	jmp    140003187 <__mingw_enum_import_library_names+0xdb>
   14000312c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000312f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003133:	48 01 d0             	add    rax,rdx
   140003136:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000313a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000313f:	75 07                	jne    140003148 <__mingw_enum_import_library_names+0x9c>
   140003141:	b8 00 00 00 00       	mov    eax,0x0
   140003146:	eb 3f                	jmp    140003187 <__mingw_enum_import_library_names+0xdb>
   140003148:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000314c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000314f:	85 c0                	test   eax,eax
   140003151:	75 0b                	jne    14000315e <__mingw_enum_import_library_names+0xb2>
   140003153:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003157:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000315a:	85 c0                	test   eax,eax
   14000315c:	74 23                	je     140003181 <__mingw_enum_import_library_names+0xd5>
   14000315e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003162:	7f 12                	jg     140003176 <__mingw_enum_import_library_names+0xca>
   140003164:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003168:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000316b:	89 c2                	mov    edx,eax
   14000316d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003171:	48 01 d0             	add    rax,rdx
   140003174:	eb 11                	jmp    140003187 <__mingw_enum_import_library_names+0xdb>
   140003176:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000317a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000317f:	eb c7                	jmp    140003148 <__mingw_enum_import_library_names+0x9c>
   140003181:	90                   	nop
   140003182:	b8 00 00 00 00       	mov    eax,0x0
   140003187:	48 83 c4 50          	add    rsp,0x50
   14000318b:	5d                   	pop    rbp
   14000318c:	c3                   	ret
   14000318d:	90                   	nop
   14000318e:	90                   	nop
   14000318f:	90                   	nop

0000000140003190 <___chkstk_ms>:
   140003190:	51                   	push   rcx
   140003191:	50                   	push   rax
   140003192:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003198:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000319d:	72 19                	jb     1400031b8 <___chkstk_ms+0x28>
   14000319f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400031a6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400031aa:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400031b0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400031b6:	77 e7                	ja     14000319f <___chkstk_ms+0xf>
   1400031b8:	48 29 c1             	sub    rcx,rax
   1400031bb:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400031bf:	58                   	pop    rax
   1400031c0:	59                   	pop    rcx
   1400031c1:	c3                   	ret
   1400031c2:	90                   	nop
   1400031c3:	90                   	nop
   1400031c4:	90                   	nop
   1400031c5:	90                   	nop
   1400031c6:	90                   	nop
   1400031c7:	90                   	nop
   1400031c8:	90                   	nop
   1400031c9:	90                   	nop
   1400031ca:	90                   	nop
   1400031cb:	90                   	nop
   1400031cc:	90                   	nop
   1400031cd:	90                   	nop
   1400031ce:	90                   	nop
   1400031cf:	90                   	nop

00000001400031d0 <_initterm_e>:
   1400031d0:	55                   	push   rbp
   1400031d1:	48 89 e5             	mov    rbp,rsp
   1400031d4:	48 83 ec 30          	sub    rsp,0x30
   1400031d8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400031dc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400031e0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400031e4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031e8:	eb 29                	jmp    140003213 <_initterm_e+0x43>
   1400031ea:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031ee:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031f1:	48 85 c0             	test   rax,rax
   1400031f4:	74 17                	je     14000320d <_initterm_e+0x3d>
   1400031f6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031fa:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031fd:	ff d0                	call   rax
   1400031ff:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003202:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003206:	74 06                	je     14000320e <_initterm_e+0x3e>
   140003208:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000320b:	eb 15                	jmp    140003222 <_initterm_e+0x52>
   14000320d:	90                   	nop
   14000320e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140003213:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003217:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   14000321b:	72 cd                	jb     1400031ea <_initterm_e+0x1a>
   14000321d:	b8 00 00 00 00       	mov    eax,0x0
   140003222:	48 83 c4 30          	add    rsp,0x30
   140003226:	5d                   	pop    rbp
   140003227:	c3                   	ret
   140003228:	90                   	nop
   140003229:	90                   	nop
   14000322a:	90                   	nop
   14000322b:	90                   	nop
   14000322c:	90                   	nop
   14000322d:	90                   	nop
   14000322e:	90                   	nop
   14000322f:	90                   	nop

0000000140003230 <__p__fmode>:
   140003230:	55                   	push   rbp
   140003231:	48 89 e5             	mov    rbp,rsp
   140003234:	48 8b 05 95 21 00 00 	mov    rax,QWORD PTR [rip+0x2195]        # 1400053d0 <.refptr.__imp__fmode>
   14000323b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000323e:	5d                   	pop    rbp
   14000323f:	c3                   	ret

0000000140003240 <__p__commode>:
   140003240:	55                   	push   rbp
   140003241:	48 89 e5             	mov    rbp,rsp
   140003244:	48 8b 05 75 21 00 00 	mov    rax,QWORD PTR [rip+0x2175]        # 1400053c0 <.refptr.__imp__commode>
   14000324b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000324e:	5d                   	pop    rbp
   14000324f:	c3                   	ret

0000000140003250 <__p___initenv>:
   140003250:	55                   	push   rbp
   140003251:	48 89 e5             	mov    rbp,rsp
   140003254:	48 8b 05 55 21 00 00 	mov    rax,QWORD PTR [rip+0x2155]        # 1400053b0 <.refptr.__imp___initenv>
   14000325b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000325e:	5d                   	pop    rbp
   14000325f:	c3                   	ret

0000000140003260 <_set_invalid_parameter_handler>:
   140003260:	55                   	push   rbp
   140003261:	48 89 e5             	mov    rbp,rsp
   140003264:	48 83 ec 10          	sub    rsp,0x10
   140003268:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000326c:	48 8d 05 1d 5f 00 00 	lea    rax,[rip+0x5f1d]        # 140009190 <handler>
   140003273:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003277:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000327b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000327f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003283:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003287:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000328a:	48 89 d0             	mov    rax,rdx
   14000328d:	48 83 c4 10          	add    rsp,0x10
   140003291:	5d                   	pop    rbp
   140003292:	c3                   	ret

0000000140003293 <_get_invalid_parameter_handler>:
   140003293:	55                   	push   rbp
   140003294:	48 89 e5             	mov    rbp,rsp
   140003297:	48 8b 05 f2 5e 00 00 	mov    rax,QWORD PTR [rip+0x5ef2]        # 140009190 <handler>
   14000329e:	5d                   	pop    rbp
   14000329f:	c3                   	ret

00000001400032a0 <_configthreadlocale>:
   1400032a0:	55                   	push   rbp
   1400032a1:	48 89 e5             	mov    rbp,rsp
   1400032a4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400032a7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   1400032ab:	75 07                	jne    1400032b4 <_configthreadlocale+0x14>
   1400032ad:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400032b2:	eb 05                	jmp    1400032b9 <_configthreadlocale+0x19>
   1400032b4:	b8 02 00 00 00       	mov    eax,0x2
   1400032b9:	5d                   	pop    rbp
   1400032ba:	c3                   	ret
   1400032bb:	90                   	nop
   1400032bc:	90                   	nop
   1400032bd:	90                   	nop
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <__acrt_iob_func>:
   1400032c0:	55                   	push   rbp
   1400032c1:	48 89 e5             	mov    rbp,rsp
   1400032c4:	48 83 ec 20          	sub    rsp,0x20
   1400032c8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400032cb:	e8 30 00 00 00       	call   140003300 <__iob_func>
   1400032d0:	48 89 c1             	mov    rcx,rax
   1400032d3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400032d6:	48 89 d0             	mov    rax,rdx
   1400032d9:	48 01 c0             	add    rax,rax
   1400032dc:	48 01 d0             	add    rax,rdx
   1400032df:	48 c1 e0 04          	shl    rax,0x4
   1400032e3:	48 01 c8             	add    rax,rcx
   1400032e6:	48 83 c4 20          	add    rsp,0x20
   1400032ea:	5d                   	pop    rbp
   1400032eb:	c3                   	ret
   1400032ec:	90                   	nop
   1400032ed:	90                   	nop
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <__C_specific_handler>:
   1400032f0:	ff 25 0a 6f 00 00    	jmp    QWORD PTR [rip+0x6f0a]        # 14000a200 <__imp___C_specific_handler>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <__getmainargs>:
   1400032f8:	ff 25 0a 6f 00 00    	jmp    QWORD PTR [rip+0x6f0a]        # 14000a208 <__imp___getmainargs>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <__iob_func>:
   140003300:	ff 25 12 6f 00 00    	jmp    QWORD PTR [rip+0x6f12]        # 14000a218 <__imp___iob_func>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <__set_app_type>:
   140003308:	ff 25 12 6f 00 00    	jmp    QWORD PTR [rip+0x6f12]        # 14000a220 <__imp___set_app_type>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <__setusermatherr>:
   140003310:	ff 25 12 6f 00 00    	jmp    QWORD PTR [rip+0x6f12]        # 14000a228 <__imp___setusermatherr>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <_amsg_exit>:
   140003318:	ff 25 12 6f 00 00    	jmp    QWORD PTR [rip+0x6f12]        # 14000a230 <__imp__amsg_exit>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <_cexit>:
   140003320:	ff 25 12 6f 00 00    	jmp    QWORD PTR [rip+0x6f12]        # 14000a238 <__imp__cexit>
   140003326:	90                   	nop
   140003327:	90                   	nop

0000000140003328 <_initterm>:
   140003328:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a250 <__imp__initterm>
   14000332e:	90                   	nop
   14000332f:	90                   	nop

0000000140003330 <_crt_atexit>:
   140003330:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a258 <__imp__crt_atexit>
   140003336:	90                   	nop
   140003337:	90                   	nop

0000000140003338 <abort>:
   140003338:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a260 <__imp_abort>
   14000333e:	90                   	nop
   14000333f:	90                   	nop

0000000140003340 <calloc>:
   140003340:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a268 <__imp_calloc>
   140003346:	90                   	nop
   140003347:	90                   	nop

0000000140003348 <exit>:
   140003348:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a270 <__imp_exit>
   14000334e:	90                   	nop
   14000334f:	90                   	nop

0000000140003350 <fflush>:
   140003350:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a278 <__imp_fflush>
   140003356:	90                   	nop
   140003357:	90                   	nop

0000000140003358 <fprintf>:
   140003358:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a280 <__imp_fprintf>
   14000335e:	90                   	nop
   14000335f:	90                   	nop

0000000140003360 <free>:
   140003360:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a288 <__imp_free>
   140003366:	90                   	nop
   140003367:	90                   	nop

0000000140003368 <malloc>:
   140003368:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a290 <__imp_malloc>
   14000336e:	90                   	nop
   14000336f:	90                   	nop

0000000140003370 <memcpy>:
   140003370:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a298 <__imp_memcpy>
   140003376:	90                   	nop
   140003377:	90                   	nop

0000000140003378 <setvbuf>:
   140003378:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a2a0 <__imp_setvbuf>
   14000337e:	90                   	nop
   14000337f:	90                   	nop

0000000140003380 <signal>:
   140003380:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a2a8 <__imp_signal>
   140003386:	90                   	nop
   140003387:	90                   	nop

0000000140003388 <strlen>:
   140003388:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a2b0 <__imp_strlen>
   14000338e:	90                   	nop
   14000338f:	90                   	nop

0000000140003390 <strncmp>:
   140003390:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a2b8 <__imp_strncmp>
   140003396:	90                   	nop
   140003397:	90                   	nop

0000000140003398 <vfprintf>:
   140003398:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a2c0 <__imp_vfprintf>
   14000339e:	90                   	nop
   14000339f:	90                   	nop

00000001400033a0 <VirtualQuery>:
   1400033a0:	ff 25 4a 6e 00 00    	jmp    QWORD PTR [rip+0x6e4a]        # 14000a1f0 <__imp_VirtualQuery>
   1400033a6:	90                   	nop
   1400033a7:	90                   	nop

00000001400033a8 <VirtualProtect>:
   1400033a8:	ff 25 3a 6e 00 00    	jmp    QWORD PTR [rip+0x6e3a]        # 14000a1e8 <__imp_VirtualProtect>
   1400033ae:	90                   	nop
   1400033af:	90                   	nop

00000001400033b0 <TlsGetValue>:
   1400033b0:	ff 25 2a 6e 00 00    	jmp    QWORD PTR [rip+0x6e2a]        # 14000a1e0 <__imp_TlsGetValue>
   1400033b6:	90                   	nop
   1400033b7:	90                   	nop

00000001400033b8 <Sleep>:
   1400033b8:	ff 25 1a 6e 00 00    	jmp    QWORD PTR [rip+0x6e1a]        # 14000a1d8 <__imp_Sleep>
   1400033be:	90                   	nop
   1400033bf:	90                   	nop

00000001400033c0 <SetUnhandledExceptionFilter>:
   1400033c0:	ff 25 0a 6e 00 00    	jmp    QWORD PTR [rip+0x6e0a]        # 14000a1d0 <__imp_SetUnhandledExceptionFilter>
   1400033c6:	90                   	nop
   1400033c7:	90                   	nop

00000001400033c8 <LoadLibraryA>:
   1400033c8:	ff 25 fa 6d 00 00    	jmp    QWORD PTR [rip+0x6dfa]        # 14000a1c8 <__imp_LoadLibraryA>
   1400033ce:	90                   	nop
   1400033cf:	90                   	nop

00000001400033d0 <LeaveCriticalSection>:
   1400033d0:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a1c0 <__imp_LeaveCriticalSection>
   1400033d6:	90                   	nop
   1400033d7:	90                   	nop

00000001400033d8 <InitializeCriticalSection>:
   1400033d8:	ff 25 da 6d 00 00    	jmp    QWORD PTR [rip+0x6dda]        # 14000a1b8 <__imp_InitializeCriticalSection>
   1400033de:	90                   	nop
   1400033df:	90                   	nop

00000001400033e0 <GetProcAddress>:
   1400033e0:	ff 25 ca 6d 00 00    	jmp    QWORD PTR [rip+0x6dca]        # 14000a1b0 <__imp_GetProcAddress>
   1400033e6:	90                   	nop
   1400033e7:	90                   	nop

00000001400033e8 <GetModuleHandleA>:
   1400033e8:	ff 25 ba 6d 00 00    	jmp    QWORD PTR [rip+0x6dba]        # 14000a1a8 <__imp_GetModuleHandleA>
   1400033ee:	90                   	nop
   1400033ef:	90                   	nop

00000001400033f0 <GetLastError>:
   1400033f0:	ff 25 aa 6d 00 00    	jmp    QWORD PTR [rip+0x6daa]        # 14000a1a0 <__imp_GetLastError>
   1400033f6:	90                   	nop
   1400033f7:	90                   	nop

00000001400033f8 <FreeLibrary>:
   1400033f8:	ff 25 9a 6d 00 00    	jmp    QWORD PTR [rip+0x6d9a]        # 14000a198 <__imp_FreeLibrary>
   1400033fe:	90                   	nop
   1400033ff:	90                   	nop

0000000140003400 <EnterCriticalSection>:
   140003400:	ff 25 8a 6d 00 00    	jmp    QWORD PTR [rip+0x6d8a]        # 14000a190 <__imp_EnterCriticalSection>
   140003406:	90                   	nop
   140003407:	90                   	nop

0000000140003408 <DeleteCriticalSection>:
   140003408:	ff 25 7a 6d 00 00    	jmp    QWORD PTR [rip+0x6d7a]        # 14000a188 <__IAT_start__>
   14000340e:	90                   	nop
   14000340f:	90                   	nop

0000000140003410 <register_frame_ctor>:
   140003410:	e9 5b e2 ff ff       	jmp    140001670 <__gcc_register_frame>
   140003415:	90                   	nop
   140003416:	90                   	nop
   140003417:	90                   	nop
   140003418:	90                   	nop
   140003419:	90                   	nop
   14000341a:	90                   	nop
   14000341b:	90                   	nop
   14000341c:	90                   	nop
   14000341d:	90                   	nop
   14000341e:	90                   	nop
   14000341f:	90                   	nop
