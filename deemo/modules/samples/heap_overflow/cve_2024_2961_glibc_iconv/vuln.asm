
C:\Users\Administrator\Desktop\BinMind\round2\samples\heap_overflow\cve_2024_2961_glibc_iconv\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 d7 23 00 00       	call   140003400 <fflush>
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
   14000113b:	e8 88 22 00 00       	call   1400033c8 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 08 22 00 00       	call   140003370 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 af 22 00 00       	call   140003430 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 4f 22 00 00       	call   1400033e8 <abort>
   140001199:	e8 d2 12 00 00       	call   140002470 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 29 90 00 00 	mov    rax,QWORD PTR [rip+0x9029]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 46 21 00 00       	call   140003310 <_set_invalid_parameter_handler>
   1400011ca:	e8 b1 1b 00 00       	call   140002d80 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 c7 21 00 00       	call   1400033b8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 bb 21 00 00       	call   1400033b8 <__set_app_type>
   1400011fd:	e8 de 20 00 00       	call   1400032e0 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 de 20 00 00       	call   1400032f0 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 2e 08 00 00       	call   140001a50 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 93 21 00 00       	call   1400033c8 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 38 13 00 00       	call   14000258a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 e6 20 00 00       	call   140003350 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 00 20 00 00       	call   140003280 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 3a 21 00 00       	call   1400033c8 <_amsg_exit>
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
   1400012cb:	e8 d8 20 00 00       	call   1400033a8 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 e5 20 00 00       	call   1400033c8 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 be 20 00 00       	call   1400033c8 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 b8 20 00 00       	call   1400033d8 <_initterm>
   140001320:	e8 02 07 00 00       	call   140001a27 <__main>
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
   14000138d:	e8 6e 1f 00 00       	call   140003300 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 4b 05 00 00       	call   140001905 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 27 20 00 00       	call   1400033f8 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 f0 1f 00 00       	call   1400033d0 <_cexit>
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
   140001511:	e8 02 1f 00 00       	call   140003418 <malloc>
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
   14000155c:	e8 df 1e 00 00       	call   140003440 <strlen>
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
   140001585:	e8 8e 1e 00 00       	call   140003418 <malloc>
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
   1400015e8:	e8 33 1e 00 00       	call   140003420 <memcpy>
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
   140001642:	e8 99 1d 00 00       	call   1400033e0 <_crt_atexit>
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

0000000140001760 <my_iconv>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 10          	sub    rsp,0x10
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001770:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001774:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140001778:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   14000177f:	00 
   140001780:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140001787:	00 
   140001788:	e9 ef 00 00 00       	jmp    14000187c <my_iconv+0x11c>
   14000178d:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140001791:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001795:	48 01 d0             	add    rax,rdx
   140001798:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000179b:	3c 1b                	cmp    al,0x1b
   14000179d:	75 79                	jne    140001818 <my_iconv+0xb8>
   14000179f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017a3:	48 83 c0 04          	add    rax,0x4
   1400017a7:	48 39 45 28          	cmp    QWORD PTR [rbp+0x28],rax
   1400017ab:	73 0c                	jae    1400017b9 <my_iconv+0x59>
   1400017ad:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400017b4:	e9 d5 00 00 00       	jmp    14000188e <my_iconv+0x12e>
   1400017b9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017bd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400017c1:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400017c5:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400017c9:	48 01 d0             	add    rax,rdx
   1400017cc:	c6 00 1b             	mov    BYTE PTR [rax],0x1b
   1400017cf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017d3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400017d7:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400017db:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400017df:	48 01 d0             	add    rax,rdx
   1400017e2:	c6 00 24             	mov    BYTE PTR [rax],0x24
   1400017e5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017e9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400017ed:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400017f1:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400017f5:	48 01 d0             	add    rax,rdx
   1400017f8:	c6 00 29             	mov    BYTE PTR [rax],0x29
   1400017fb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017ff:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140001803:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140001807:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000180b:	48 01 d0             	add    rax,rdx
   14000180e:	c6 00 41             	mov    BYTE PTR [rax],0x41
   140001811:	48 83 45 f0 03       	add    QWORD PTR [rbp-0x10],0x3
   140001816:	eb 64                	jmp    14000187c <my_iconv+0x11c>
   140001818:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000181c:	48 83 c0 02          	add    rax,0x2
   140001820:	48 39 45 28          	cmp    QWORD PTR [rbp+0x28],rax
   140001824:	73 09                	jae    14000182f <my_iconv+0xcf>
   140001826:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000182d:	eb 5f                	jmp    14000188e <my_iconv+0x12e>
   14000182f:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140001833:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001837:	48 8d 0c 02          	lea    rcx,[rdx+rax*1]
   14000183b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000183f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140001843:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140001847:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000184b:	48 01 c2             	add    rdx,rax
   14000184e:	0f b6 01             	movzx  eax,BYTE PTR [rcx]
   140001851:	88 02                	mov    BYTE PTR [rdx],al
   140001853:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140001857:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000185b:	48 8d 0c 02          	lea    rcx,[rdx+rax*1]
   14000185f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001863:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140001867:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000186b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000186f:	48 01 c2             	add    rdx,rax
   140001872:	0f b6 01             	movzx  eax,BYTE PTR [rcx]
   140001875:	88 02                	mov    BYTE PTR [rdx],al
   140001877:	48 83 45 f0 01       	add    QWORD PTR [rbp-0x10],0x1
   14000187c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001880:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140001884:	0f 82 03 ff ff ff    	jb     14000178d <my_iconv+0x2d>
   14000188a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000188e:	48 83 c4 10          	add    rsp,0x10
   140001892:	5d                   	pop    rbp
   140001893:	c3                   	ret

0000000140001894 <convert>:
   140001894:	55                   	push   rbp
   140001895:	48 89 e5             	mov    rbp,rsp
   140001898:	48 83 ec 30          	sub    rsp,0x30
   14000189c:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400018a0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400018a4:	b9 10 00 00 00       	mov    ecx,0x10
   1400018a9:	e8 6a 1b 00 00       	call   140003418 <malloc>
   1400018ae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400018b2:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400018b7:	75 07                	jne    1400018c0 <convert+0x2c>
   1400018b9:	b8 00 00 00 00       	mov    eax,0x0
   1400018be:	eb 3f                	jmp    1400018ff <convert+0x6b>
   1400018c0:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
   1400018c4:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400018c8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400018cc:	41 b9 10 00 00 00    	mov    r9d,0x10
   1400018d2:	49 89 c8             	mov    r8,rcx
   1400018d5:	48 89 c1             	mov    rcx,rax
   1400018d8:	e8 83 fe ff ff       	call   140001760 <my_iconv>
   1400018dd:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400018e1:	48 83 7d f0 ff       	cmp    QWORD PTR [rbp-0x10],0xffffffffffffffff
   1400018e6:	75 13                	jne    1400018fb <convert+0x67>
   1400018e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400018ec:	48 89 c1             	mov    rcx,rax
   1400018ef:	e8 1c 1b 00 00       	call   140003410 <free>
   1400018f4:	b8 00 00 00 00       	mov    eax,0x0
   1400018f9:	eb 04                	jmp    1400018ff <convert+0x6b>
   1400018fb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400018ff:	48 83 c4 30          	add    rsp,0x30
   140001903:	5d                   	pop    rbp
   140001904:	c3                   	ret

0000000140001905 <main>:
   140001905:	55                   	push   rbp
   140001906:	48 89 e5             	mov    rbp,rsp
   140001909:	48 83 ec 40          	sub    rsp,0x40
   14000190d:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140001910:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001914:	e8 0e 01 00 00       	call   140001a27 <__main>
   140001919:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   14000191d:	41 b8 0c 00 00 00    	mov    r8d,0xc
   140001923:	ba 58 00 00 00       	mov    edx,0x58
   140001928:	48 89 c1             	mov    rcx,rax
   14000192b:	e8 f8 1a 00 00       	call   140003428 <memset>
   140001930:	c6 45 ec 00          	mov    BYTE PTR [rbp-0x14],0x0
   140001934:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140001938:	ba 0c 00 00 00       	mov    edx,0xc
   14000193d:	48 89 c1             	mov    rcx,rax
   140001940:	e8 4f ff ff ff       	call   140001894 <convert>
   140001945:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001949:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000194e:	74 0c                	je     14000195c <main+0x57>
   140001950:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001954:	48 89 c1             	mov    rcx,rax
   140001957:	e8 b4 1a 00 00       	call   140003410 <free>
   14000195c:	b8 00 00 00 00       	mov    eax,0x0
   140001961:	48 83 c4 40          	add    rsp,0x40
   140001965:	5d                   	pop    rbp
   140001966:	c3                   	ret
   140001967:	90                   	nop
   140001968:	90                   	nop
   140001969:	90                   	nop
   14000196a:	90                   	nop
   14000196b:	90                   	nop
   14000196c:	90                   	nop
   14000196d:	90                   	nop
   14000196e:	90                   	nop
   14000196f:	90                   	nop

0000000140001970 <__do_global_dtors>:
   140001970:	55                   	push   rbp
   140001971:	48 89 e5             	mov    rbp,rsp
   140001974:	48 83 ec 20          	sub    rsp,0x20
   140001978:	eb 1e                	jmp    140001998 <__do_global_dtors+0x28>
   14000197a:	48 8b 05 8f 26 00 00 	mov    rax,QWORD PTR [rip+0x268f]        # 140004010 <p.0>
   140001981:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001984:	ff d0                	call   rax
   140001986:	48 8b 05 83 26 00 00 	mov    rax,QWORD PTR [rip+0x2683]        # 140004010 <p.0>
   14000198d:	48 83 c0 08          	add    rax,0x8
   140001991:	48 89 05 78 26 00 00 	mov    QWORD PTR [rip+0x2678],rax        # 140004010 <p.0>
   140001998:	48 8b 05 71 26 00 00 	mov    rax,QWORD PTR [rip+0x2671]        # 140004010 <p.0>
   14000199f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019a2:	48 85 c0             	test   rax,rax
   1400019a5:	75 d3                	jne    14000197a <__do_global_dtors+0xa>
   1400019a7:	90                   	nop
   1400019a8:	90                   	nop
   1400019a9:	48 83 c4 20          	add    rsp,0x20
   1400019ad:	5d                   	pop    rbp
   1400019ae:	c3                   	ret

00000001400019af <__do_global_ctors>:
   1400019af:	55                   	push   rbp
   1400019b0:	48 89 e5             	mov    rbp,rsp
   1400019b3:	48 83 ec 30          	sub    rsp,0x30
   1400019b7:	48 8b 05 92 39 00 00 	mov    rax,QWORD PTR [rip+0x3992]        # 140005350 <.refptr.__CTOR_LIST__>
   1400019be:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019c1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400019c4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400019c8:	75 25                	jne    1400019ef <__do_global_ctors+0x40>
   1400019ca:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400019d1:	eb 04                	jmp    1400019d7 <__do_global_ctors+0x28>
   1400019d3:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400019d7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400019da:	8d 50 01             	lea    edx,[rax+0x1]
   1400019dd:	48 8b 05 6c 39 00 00 	mov    rax,QWORD PTR [rip+0x396c]        # 140005350 <.refptr.__CTOR_LIST__>
   1400019e4:	89 d2                	mov    edx,edx
   1400019e6:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400019ea:	48 85 c0             	test   rax,rax
   1400019ed:	75 e4                	jne    1400019d3 <__do_global_ctors+0x24>
   1400019ef:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400019f2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400019f5:	eb 14                	jmp    140001a0b <__do_global_ctors+0x5c>
   1400019f7:	48 8b 05 52 39 00 00 	mov    rax,QWORD PTR [rip+0x3952]        # 140005350 <.refptr.__CTOR_LIST__>
   1400019fe:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001a01:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001a05:	ff d0                	call   rax
   140001a07:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140001a0b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140001a0f:	75 e6                	jne    1400019f7 <__do_global_ctors+0x48>
   140001a11:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001970 <__do_global_dtors>
   140001a18:	48 89 c1             	mov    rcx,rax
   140001a1b:	e8 0f fc ff ff       	call   14000162f <atexit>
   140001a20:	90                   	nop
   140001a21:	48 83 c4 30          	add    rsp,0x30
   140001a25:	5d                   	pop    rbp
   140001a26:	c3                   	ret

0000000140001a27 <__main>:
   140001a27:	55                   	push   rbp
   140001a28:	48 89 e5             	mov    rbp,rsp
   140001a2b:	48 83 ec 20          	sub    rsp,0x20
   140001a2f:	8b 05 4b 76 00 00    	mov    eax,DWORD PTR [rip+0x764b]        # 140009080 <initialized>
   140001a35:	85 c0                	test   eax,eax
   140001a37:	75 0f                	jne    140001a48 <__main+0x21>
   140001a39:	c7 05 3d 76 00 00 01 	mov    DWORD PTR [rip+0x763d],0x1        # 140009080 <initialized>
   140001a40:	00 00 00 
   140001a43:	e8 67 ff ff ff       	call   1400019af <__do_global_ctors>
   140001a48:	90                   	nop
   140001a49:	48 83 c4 20          	add    rsp,0x20
   140001a4d:	5d                   	pop    rbp
   140001a4e:	c3                   	ret
   140001a4f:	90                   	nop

0000000140001a50 <_setargv>:
   140001a50:	55                   	push   rbp
   140001a51:	48 89 e5             	mov    rbp,rsp
   140001a54:	b8 00 00 00 00       	mov    eax,0x0
   140001a59:	5d                   	pop    rbp
   140001a5a:	c3                   	ret
   140001a5b:	90                   	nop
   140001a5c:	90                   	nop
   140001a5d:	90                   	nop
   140001a5e:	90                   	nop
   140001a5f:	90                   	nop

0000000140001a60 <__dyn_tls_init>:
   140001a60:	55                   	push   rbp
   140001a61:	48 89 e5             	mov    rbp,rsp
   140001a64:	48 83 ec 30          	sub    rsp,0x30
   140001a68:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a6c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a6f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a73:	48 8b 05 b6 38 00 00 	mov    rax,QWORD PTR [rip+0x38b6]        # 140005330 <.refptr._CRT_MT>
   140001a7a:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a7c:	83 f8 02             	cmp    eax,0x2
   140001a7f:	74 0d                	je     140001a8e <__dyn_tls_init+0x2e>
   140001a81:	48 8b 05 a8 38 00 00 	mov    rax,QWORD PTR [rip+0x38a8]        # 140005330 <.refptr._CRT_MT>
   140001a88:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   140001a8e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001a92:	74 1e                	je     140001ab2 <__dyn_tls_init+0x52>
   140001a94:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001a98:	75 5b                	jne    140001af5 <__dyn_tls_init+0x95>
   140001a9a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a9e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001aa1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001aa5:	49 89 c8             	mov    r8,rcx
   140001aa8:	48 89 c1             	mov    rcx,rax
   140001aab:	e8 d1 11 00 00       	call   140002c81 <__mingw_TLScallback>
   140001ab0:	eb 43                	jmp    140001af5 <__dyn_tls_init+0x95>
   140001ab2:	48 8d 05 df 3b 00 00 	lea    rax,[rip+0x3bdf]        # 140005698 <___crt_xd_start__>
   140001ab9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001abd:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001ac2:	eb 22                	jmp    140001ae6 <__dyn_tls_init+0x86>
   140001ac4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001ac8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001acc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001ad0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001ad3:	48 85 c0             	test   rax,rax
   140001ad6:	74 09                	je     140001ae1 <__dyn_tls_init+0x81>
   140001ad8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001adc:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001adf:	ff d0                	call   rax
   140001ae1:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001ae6:	48 8d 05 b3 3b 00 00 	lea    rax,[rip+0x3bb3]        # 1400056a0 <__xd_z>
   140001aed:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001af1:	75 d1                	jne    140001ac4 <__dyn_tls_init+0x64>
   140001af3:	eb 01                	jmp    140001af6 <__dyn_tls_init+0x96>
   140001af5:	90                   	nop
   140001af6:	48 83 c4 30          	add    rsp,0x30
   140001afa:	5d                   	pop    rbp
   140001afb:	c3                   	ret

0000000140001afc <__tlregdtor>:
   140001afc:	55                   	push   rbp
   140001afd:	48 89 e5             	mov    rbp,rsp
   140001b00:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b04:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001b09:	75 07                	jne    140001b12 <__tlregdtor+0x16>
   140001b0b:	b8 00 00 00 00       	mov    eax,0x0
   140001b10:	eb 05                	jmp    140001b17 <__tlregdtor+0x1b>
   140001b12:	b8 00 00 00 00       	mov    eax,0x0
   140001b17:	5d                   	pop    rbp
   140001b18:	c3                   	ret

0000000140001b19 <__dyn_tls_dtor>:
   140001b19:	55                   	push   rbp
   140001b1a:	48 89 e5             	mov    rbp,rsp
   140001b1d:	48 83 ec 20          	sub    rsp,0x20
   140001b21:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b25:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001b28:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001b2c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001b30:	74 06                	je     140001b38 <__dyn_tls_dtor+0x1f>
   140001b32:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001b36:	75 18                	jne    140001b50 <__dyn_tls_dtor+0x37>
   140001b38:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001b3c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001b3f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001b43:	49 89 c8             	mov    r8,rcx
   140001b46:	48 89 c1             	mov    rcx,rax
   140001b49:	e8 33 11 00 00       	call   140002c81 <__mingw_TLScallback>
   140001b4e:	eb 01                	jmp    140001b51 <__dyn_tls_dtor+0x38>
   140001b50:	90                   	nop
   140001b51:	48 83 c4 20          	add    rsp,0x20
   140001b55:	5d                   	pop    rbp
   140001b56:	c3                   	ret
   140001b57:	90                   	nop
   140001b58:	90                   	nop
   140001b59:	90                   	nop
   140001b5a:	90                   	nop
   140001b5b:	90                   	nop
   140001b5c:	90                   	nop
   140001b5d:	90                   	nop
   140001b5e:	90                   	nop
   140001b5f:	90                   	nop

0000000140001b60 <_matherr>:
   140001b60:	55                   	push   rbp
   140001b61:	53                   	push   rbx
   140001b62:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001b69:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001b6e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001b72:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001b76:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001b7b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001b7f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b83:	8b 00                	mov    eax,DWORD PTR [rax]
   140001b85:	83 f8 06             	cmp    eax,0x6
   140001b88:	74 56                	je     140001be0 <_matherr+0x80>
   140001b8a:	83 f8 06             	cmp    eax,0x6
   140001b8d:	7f 78                	jg     140001c07 <_matherr+0xa7>
   140001b8f:	83 f8 05             	cmp    eax,0x5
   140001b92:	74 59                	je     140001bed <_matherr+0x8d>
   140001b94:	83 f8 05             	cmp    eax,0x5
   140001b97:	7f 6e                	jg     140001c07 <_matherr+0xa7>
   140001b99:	83 f8 04             	cmp    eax,0x4
   140001b9c:	74 5c                	je     140001bfa <_matherr+0x9a>
   140001b9e:	83 f8 04             	cmp    eax,0x4
   140001ba1:	7f 64                	jg     140001c07 <_matherr+0xa7>
   140001ba3:	83 f8 03             	cmp    eax,0x3
   140001ba6:	74 2b                	je     140001bd3 <_matherr+0x73>
   140001ba8:	83 f8 03             	cmp    eax,0x3
   140001bab:	7f 5a                	jg     140001c07 <_matherr+0xa7>
   140001bad:	83 f8 01             	cmp    eax,0x1
   140001bb0:	74 07                	je     140001bb9 <_matherr+0x59>
   140001bb2:	83 f8 02             	cmp    eax,0x2
   140001bb5:	74 0f                	je     140001bc6 <_matherr+0x66>
   140001bb7:	eb 4e                	jmp    140001c07 <_matherr+0xa7>
   140001bb9:	48 8d 05 e0 34 00 00 	lea    rax,[rip+0x34e0]        # 1400050a0 <.rdata>
   140001bc0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bc4:	eb 4d                	jmp    140001c13 <_matherr+0xb3>
   140001bc6:	48 8d 05 f2 34 00 00 	lea    rax,[rip+0x34f2]        # 1400050bf <.rdata+0x1f>
   140001bcd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bd1:	eb 40                	jmp    140001c13 <_matherr+0xb3>
   140001bd3:	48 8d 05 06 35 00 00 	lea    rax,[rip+0x3506]        # 1400050e0 <.rdata+0x40>
   140001bda:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bde:	eb 33                	jmp    140001c13 <_matherr+0xb3>
   140001be0:	48 8d 05 19 35 00 00 	lea    rax,[rip+0x3519]        # 140005100 <.rdata+0x60>
   140001be7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001beb:	eb 26                	jmp    140001c13 <_matherr+0xb3>
   140001bed:	48 8d 05 34 35 00 00 	lea    rax,[rip+0x3534]        # 140005128 <.rdata+0x88>
   140001bf4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bf8:	eb 19                	jmp    140001c13 <_matherr+0xb3>
   140001bfa:	48 8d 05 4f 35 00 00 	lea    rax,[rip+0x354f]        # 140005150 <.rdata+0xb0>
   140001c01:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c05:	eb 0c                	jmp    140001c13 <_matherr+0xb3>
   140001c07:	48 8d 05 78 35 00 00 	lea    rax,[rip+0x3578]        # 140005186 <.rdata+0xe6>
   140001c0e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c12:	90                   	nop
   140001c13:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c17:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001c1d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c21:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001c26:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c2a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001c2f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c33:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001c37:	b9 02 00 00 00       	mov    ecx,0x2
   140001c3c:	e8 2f 17 00 00       	call   140003370 <__acrt_iob_func>
   140001c41:	48 89 c1             	mov    rcx,rax
   140001c44:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001c48:	48 8d 05 49 35 00 00 	lea    rax,[rip+0x3549]        # 140005198 <.rdata+0xf8>
   140001c4f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001c56:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001c5c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001c62:	49 89 d9             	mov    r9,rbx
   140001c65:	49 89 d0             	mov    r8,rdx
   140001c68:	48 89 c2             	mov    rdx,rax
   140001c6b:	e8 98 17 00 00       	call   140003408 <fprintf>
   140001c70:	b8 00 00 00 00       	mov    eax,0x0
   140001c75:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001c79:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001c7d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001c82:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001c89:	5b                   	pop    rbx
   140001c8a:	5d                   	pop    rbp
   140001c8b:	c3                   	ret
   140001c8c:	90                   	nop
   140001c8d:	90                   	nop
   140001c8e:	90                   	nop
   140001c8f:	90                   	nop

0000000140001c90 <__report_error>:
   140001c90:	55                   	push   rbp
   140001c91:	53                   	push   rbx
   140001c92:	48 83 ec 38          	sub    rsp,0x38
   140001c96:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001c9b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001c9f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001ca3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001ca7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001cab:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001caf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001cb3:	b9 02 00 00 00       	mov    ecx,0x2
   140001cb8:	e8 b3 16 00 00       	call   140003370 <__acrt_iob_func>
   140001cbd:	48 89 c1             	mov    rcx,rax
   140001cc0:	48 8d 05 09 35 00 00 	lea    rax,[rip+0x3509]        # 1400051d0 <.rdata>
   140001cc7:	48 89 c2             	mov    rdx,rax
   140001cca:	e8 39 17 00 00       	call   140003408 <fprintf>
   140001ccf:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001cd3:	b9 02 00 00 00       	mov    ecx,0x2
   140001cd8:	e8 93 16 00 00       	call   140003370 <__acrt_iob_func>
   140001cdd:	48 89 c1             	mov    rcx,rax
   140001ce0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001ce4:	49 89 d8             	mov    r8,rbx
   140001ce7:	48 89 c2             	mov    rdx,rax
   140001cea:	e8 61 17 00 00       	call   140003450 <vfprintf>
   140001cef:	e8 f4 16 00 00       	call   1400033e8 <abort>
   140001cf4:	90                   	nop

0000000140001cf5 <mark_section_writable>:
   140001cf5:	55                   	push   rbp
   140001cf6:	48 89 e5             	mov    rbp,rsp
   140001cf9:	48 83 ec 60          	sub    rsp,0x60
   140001cfd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001d01:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001d08:	e9 82 00 00 00       	jmp    140001d8f <mark_section_writable+0x9a>
   140001d0d:	48 8b 0d cc 73 00 00 	mov    rcx,QWORD PTR [rip+0x73cc]        # 1400090e0 <the_secs>
   140001d14:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d17:	48 63 d0             	movsxd rdx,eax
   140001d1a:	48 89 d0             	mov    rax,rdx
   140001d1d:	48 c1 e0 02          	shl    rax,0x2
   140001d21:	48 01 d0             	add    rax,rdx
   140001d24:	48 c1 e0 03          	shl    rax,0x3
   140001d28:	48 01 c8             	add    rax,rcx
   140001d2b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d2f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001d33:	72 56                	jb     140001d8b <mark_section_writable+0x96>
   140001d35:	48 8b 0d a4 73 00 00 	mov    rcx,QWORD PTR [rip+0x73a4]        # 1400090e0 <the_secs>
   140001d3c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d3f:	48 63 d0             	movsxd rdx,eax
   140001d42:	48 89 d0             	mov    rax,rdx
   140001d45:	48 c1 e0 02          	shl    rax,0x2
   140001d49:	48 01 d0             	add    rax,rdx
   140001d4c:	48 c1 e0 03          	shl    rax,0x3
   140001d50:	48 01 c8             	add    rax,rcx
   140001d53:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001d57:	4c 8b 05 82 73 00 00 	mov    r8,QWORD PTR [rip+0x7382]        # 1400090e0 <the_secs>
   140001d5e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d61:	48 63 d0             	movsxd rdx,eax
   140001d64:	48 89 d0             	mov    rax,rdx
   140001d67:	48 c1 e0 02          	shl    rax,0x2
   140001d6b:	48 01 d0             	add    rax,rdx
   140001d6e:	48 c1 e0 03          	shl    rax,0x3
   140001d72:	4c 01 c0             	add    rax,r8
   140001d75:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001d79:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d7c:	89 c0                	mov    eax,eax
   140001d7e:	48 01 c8             	add    rax,rcx
   140001d81:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001d85:	0f 82 41 02 00 00    	jb     140001fcc <mark_section_writable+0x2d7>
   140001d8b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001d8f:	8b 05 53 73 00 00    	mov    eax,DWORD PTR [rip+0x7353]        # 1400090e8 <maxSections>
   140001d95:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001d98:	0f 8c 6f ff ff ff    	jl     140001d0d <mark_section_writable+0x18>
   140001d9e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001da2:	48 89 c1             	mov    rcx,rax
   140001da5:	e8 c1 11 00 00       	call   140002f6b <__mingw_GetSectionForAddress>
   140001daa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001dae:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001db3:	75 13                	jne    140001dc8 <mark_section_writable+0xd3>
   140001db5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001db9:	48 8d 0d 30 34 00 00 	lea    rcx,[rip+0x3430]        # 1400051f0 <.rdata+0x20>
   140001dc0:	48 89 c2             	mov    rdx,rax
   140001dc3:	e8 c8 fe ff ff       	call   140001c90 <__report_error>
   140001dc8:	48 8b 0d 11 73 00 00 	mov    rcx,QWORD PTR [rip+0x7311]        # 1400090e0 <the_secs>
   140001dcf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dd2:	48 63 d0             	movsxd rdx,eax
   140001dd5:	48 89 d0             	mov    rax,rdx
   140001dd8:	48 c1 e0 02          	shl    rax,0x2
   140001ddc:	48 01 d0             	add    rax,rdx
   140001ddf:	48 c1 e0 03          	shl    rax,0x3
   140001de3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001de7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001deb:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001def:	48 8b 0d ea 72 00 00 	mov    rcx,QWORD PTR [rip+0x72ea]        # 1400090e0 <the_secs>
   140001df6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001df9:	48 63 d0             	movsxd rdx,eax
   140001dfc:	48 89 d0             	mov    rax,rdx
   140001dff:	48 c1 e0 02          	shl    rax,0x2
   140001e03:	48 01 d0             	add    rax,rdx
   140001e06:	48 c1 e0 03          	shl    rax,0x3
   140001e0a:	48 01 c8             	add    rax,rcx
   140001e0d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001e13:	e8 9f 12 00 00       	call   1400030b7 <_GetPEImageBase>
   140001e18:	48 89 c1             	mov    rcx,rax
   140001e1b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001e1f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001e22:	41 89 c1             	mov    r9d,eax
   140001e25:	4c 8b 05 b4 72 00 00 	mov    r8,QWORD PTR [rip+0x72b4]        # 1400090e0 <the_secs>
   140001e2c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e2f:	48 63 d0             	movsxd rdx,eax
   140001e32:	48 89 d0             	mov    rax,rdx
   140001e35:	48 c1 e0 02          	shl    rax,0x2
   140001e39:	48 01 d0             	add    rax,rdx
   140001e3c:	48 c1 e0 03          	shl    rax,0x3
   140001e40:	4c 01 c0             	add    rax,r8
   140001e43:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001e47:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001e4b:	48 8b 0d 8e 72 00 00 	mov    rcx,QWORD PTR [rip+0x728e]        # 1400090e0 <the_secs>
   140001e52:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e55:	48 63 d0             	movsxd rdx,eax
   140001e58:	48 89 d0             	mov    rax,rdx
   140001e5b:	48 c1 e0 02          	shl    rax,0x2
   140001e5f:	48 01 d0             	add    rax,rdx
   140001e62:	48 c1 e0 03          	shl    rax,0x3
   140001e66:	48 01 c8             	add    rax,rcx
   140001e69:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001e6d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001e71:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001e77:	48 89 c1             	mov    rcx,rax
   140001e7a:	48 8b 05 77 83 00 00 	mov    rax,QWORD PTR [rip+0x8377]        # 14000a1f8 <__imp_VirtualQuery>
   140001e81:	ff d0                	call   rax
   140001e83:	48 85 c0             	test   rax,rax
   140001e86:	75 3f                	jne    140001ec7 <mark_section_writable+0x1d2>
   140001e88:	48 8b 0d 51 72 00 00 	mov    rcx,QWORD PTR [rip+0x7251]        # 1400090e0 <the_secs>
   140001e8f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e92:	48 63 d0             	movsxd rdx,eax
   140001e95:	48 89 d0             	mov    rax,rdx
   140001e98:	48 c1 e0 02          	shl    rax,0x2
   140001e9c:	48 01 d0             	add    rax,rdx
   140001e9f:	48 c1 e0 03          	shl    rax,0x3
   140001ea3:	48 01 c8             	add    rax,rcx
   140001ea6:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001eaa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001eae:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001eb1:	89 c1                	mov    ecx,eax
   140001eb3:	48 8d 05 56 33 00 00 	lea    rax,[rip+0x3356]        # 140005210 <.rdata+0x40>
   140001eba:	49 89 d0             	mov    r8,rdx
   140001ebd:	89 ca                	mov    edx,ecx
   140001ebf:	48 89 c1             	mov    rcx,rax
   140001ec2:	e8 c9 fd ff ff       	call   140001c90 <__report_error>
   140001ec7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001eca:	83 f8 40             	cmp    eax,0x40
   140001ecd:	0f 84 e8 00 00 00    	je     140001fbb <mark_section_writable+0x2c6>
   140001ed3:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001ed6:	83 f8 04             	cmp    eax,0x4
   140001ed9:	0f 84 dc 00 00 00    	je     140001fbb <mark_section_writable+0x2c6>
   140001edf:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001ee2:	3d 80 00 00 00       	cmp    eax,0x80
   140001ee7:	0f 84 ce 00 00 00    	je     140001fbb <mark_section_writable+0x2c6>
   140001eed:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001ef0:	83 f8 08             	cmp    eax,0x8
   140001ef3:	0f 84 c2 00 00 00    	je     140001fbb <mark_section_writable+0x2c6>
   140001ef9:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001efc:	83 f8 02             	cmp    eax,0x2
   140001eff:	75 09                	jne    140001f0a <mark_section_writable+0x215>
   140001f01:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001f08:	eb 07                	jmp    140001f11 <mark_section_writable+0x21c>
   140001f0a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001f11:	48 8b 0d c8 71 00 00 	mov    rcx,QWORD PTR [rip+0x71c8]        # 1400090e0 <the_secs>
   140001f18:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f1b:	48 63 d0             	movsxd rdx,eax
   140001f1e:	48 89 d0             	mov    rax,rdx
   140001f21:	48 c1 e0 02          	shl    rax,0x2
   140001f25:	48 01 d0             	add    rax,rdx
   140001f28:	48 c1 e0 03          	shl    rax,0x3
   140001f2c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001f30:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001f34:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001f38:	48 8b 0d a1 71 00 00 	mov    rcx,QWORD PTR [rip+0x71a1]        # 1400090e0 <the_secs>
   140001f3f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f42:	48 63 d0             	movsxd rdx,eax
   140001f45:	48 89 d0             	mov    rax,rdx
   140001f48:	48 c1 e0 02          	shl    rax,0x2
   140001f4c:	48 01 d0             	add    rax,rdx
   140001f4f:	48 c1 e0 03          	shl    rax,0x3
   140001f53:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001f57:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001f5b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001f5f:	48 8b 0d 7a 71 00 00 	mov    rcx,QWORD PTR [rip+0x717a]        # 1400090e0 <the_secs>
   140001f66:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f69:	48 63 d0             	movsxd rdx,eax
   140001f6c:	48 89 d0             	mov    rax,rdx
   140001f6f:	48 c1 e0 02          	shl    rax,0x2
   140001f73:	48 01 d0             	add    rax,rdx
   140001f76:	48 c1 e0 03          	shl    rax,0x3
   140001f7a:	48 01 c8             	add    rax,rcx
   140001f7d:	49 89 c0             	mov    r8,rax
   140001f80:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001f84:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001f88:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001f8b:	4d 89 c1             	mov    r9,r8
   140001f8e:	41 89 c8             	mov    r8d,ecx
   140001f91:	48 89 c1             	mov    rcx,rax
   140001f94:	48 8b 05 55 82 00 00 	mov    rax,QWORD PTR [rip+0x8255]        # 14000a1f0 <__imp_VirtualProtect>
   140001f9b:	ff d0                	call   rax
   140001f9d:	85 c0                	test   eax,eax
   140001f9f:	75 1a                	jne    140001fbb <mark_section_writable+0x2c6>
   140001fa1:	48 8b 05 00 82 00 00 	mov    rax,QWORD PTR [rip+0x8200]        # 14000a1a8 <__imp_GetLastError>
   140001fa8:	ff d0                	call   rax
   140001faa:	89 c2                	mov    edx,eax
   140001fac:	48 8d 05 95 32 00 00 	lea    rax,[rip+0x3295]        # 140005248 <.rdata+0x78>
   140001fb3:	48 89 c1             	mov    rcx,rax
   140001fb6:	e8 d5 fc ff ff       	call   140001c90 <__report_error>
   140001fbb:	8b 05 27 71 00 00    	mov    eax,DWORD PTR [rip+0x7127]        # 1400090e8 <maxSections>
   140001fc1:	83 c0 01             	add    eax,0x1
   140001fc4:	89 05 1e 71 00 00    	mov    DWORD PTR [rip+0x711e],eax        # 1400090e8 <maxSections>
   140001fca:	eb 01                	jmp    140001fcd <mark_section_writable+0x2d8>
   140001fcc:	90                   	nop
   140001fcd:	48 83 c4 60          	add    rsp,0x60
   140001fd1:	5d                   	pop    rbp
   140001fd2:	c3                   	ret

0000000140001fd3 <restore_modified_sections>:
   140001fd3:	55                   	push   rbp
   140001fd4:	48 89 e5             	mov    rbp,rsp
   140001fd7:	48 83 ec 30          	sub    rsp,0x30
   140001fdb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001fe2:	e9 ad 00 00 00       	jmp    140002094 <restore_modified_sections+0xc1>
   140001fe7:	48 8b 0d f2 70 00 00 	mov    rcx,QWORD PTR [rip+0x70f2]        # 1400090e0 <the_secs>
   140001fee:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ff1:	48 63 d0             	movsxd rdx,eax
   140001ff4:	48 89 d0             	mov    rax,rdx
   140001ff7:	48 c1 e0 02          	shl    rax,0x2
   140001ffb:	48 01 d0             	add    rax,rdx
   140001ffe:	48 c1 e0 03          	shl    rax,0x3
   140002002:	48 01 c8             	add    rax,rcx
   140002005:	8b 00                	mov    eax,DWORD PTR [rax]
   140002007:	85 c0                	test   eax,eax
   140002009:	0f 84 80 00 00 00    	je     14000208f <restore_modified_sections+0xbc>
   14000200f:	48 8b 0d ca 70 00 00 	mov    rcx,QWORD PTR [rip+0x70ca]        # 1400090e0 <the_secs>
   140002016:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002019:	48 63 d0             	movsxd rdx,eax
   14000201c:	48 89 d0             	mov    rax,rdx
   14000201f:	48 c1 e0 02          	shl    rax,0x2
   140002023:	48 01 d0             	add    rax,rdx
   140002026:	48 c1 e0 03          	shl    rax,0x3
   14000202a:	48 01 c8             	add    rax,rcx
   14000202d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140002030:	48 8b 0d a9 70 00 00 	mov    rcx,QWORD PTR [rip+0x70a9]        # 1400090e0 <the_secs>
   140002037:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000203a:	48 63 d0             	movsxd rdx,eax
   14000203d:	48 89 d0             	mov    rax,rdx
   140002040:	48 c1 e0 02          	shl    rax,0x2
   140002044:	48 01 d0             	add    rax,rdx
   140002047:	48 c1 e0 03          	shl    rax,0x3
   14000204b:	48 01 c8             	add    rax,rcx
   14000204e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140002052:	4c 8b 05 87 70 00 00 	mov    r8,QWORD PTR [rip+0x7087]        # 1400090e0 <the_secs>
   140002059:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000205c:	48 63 d0             	movsxd rdx,eax
   14000205f:	48 89 d0             	mov    rax,rdx
   140002062:	48 c1 e0 02          	shl    rax,0x2
   140002066:	48 01 d0             	add    rax,rdx
   140002069:	48 c1 e0 03          	shl    rax,0x3
   14000206d:	4c 01 c0             	add    rax,r8
   140002070:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140002074:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140002078:	49 89 d1             	mov    r9,rdx
   14000207b:	45 89 d0             	mov    r8d,r10d
   14000207e:	48 89 ca             	mov    rdx,rcx
   140002081:	48 89 c1             	mov    rcx,rax
   140002084:	48 8b 05 65 81 00 00 	mov    rax,QWORD PTR [rip+0x8165]        # 14000a1f0 <__imp_VirtualProtect>
   14000208b:	ff d0                	call   rax
   14000208d:	eb 01                	jmp    140002090 <restore_modified_sections+0xbd>
   14000208f:	90                   	nop
   140002090:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140002094:	8b 05 4e 70 00 00    	mov    eax,DWORD PTR [rip+0x704e]        # 1400090e8 <maxSections>
   14000209a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   14000209d:	0f 8c 44 ff ff ff    	jl     140001fe7 <restore_modified_sections+0x14>
   1400020a3:	90                   	nop
   1400020a4:	90                   	nop
   1400020a5:	48 83 c4 30          	add    rsp,0x30
   1400020a9:	5d                   	pop    rbp
   1400020aa:	c3                   	ret

00000001400020ab <__write_memory>:
   1400020ab:	55                   	push   rbp
   1400020ac:	48 89 e5             	mov    rbp,rsp
   1400020af:	48 83 ec 20          	sub    rsp,0x20
   1400020b3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400020b7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400020bb:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400020bf:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400020c4:	74 25                	je     1400020eb <__write_memory+0x40>
   1400020c6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400020ca:	48 89 c1             	mov    rcx,rax
   1400020cd:	e8 23 fc ff ff       	call   140001cf5 <mark_section_writable>
   1400020d2:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400020d6:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400020da:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400020de:	49 89 c8             	mov    r8,rcx
   1400020e1:	48 89 c1             	mov    rcx,rax
   1400020e4:	e8 37 13 00 00       	call   140003420 <memcpy>
   1400020e9:	eb 01                	jmp    1400020ec <__write_memory+0x41>
   1400020eb:	90                   	nop
   1400020ec:	48 83 c4 20          	add    rsp,0x20
   1400020f0:	5d                   	pop    rbp
   1400020f1:	c3                   	ret

00000001400020f2 <do_pseudo_reloc>:
   1400020f2:	55                   	push   rbp
   1400020f3:	48 89 e5             	mov    rbp,rsp
   1400020f6:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   1400020fa:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400020fe:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002102:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002106:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000210a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000210e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002112:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002116:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000211a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000211f:	0f 8e 44 03 00 00    	jle    140002469 <do_pseudo_reloc+0x377>
   140002125:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000212a:	7e 25                	jle    140002151 <do_pseudo_reloc+0x5f>
   14000212c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002130:	8b 00                	mov    eax,DWORD PTR [rax]
   140002132:	85 c0                	test   eax,eax
   140002134:	75 1b                	jne    140002151 <do_pseudo_reloc+0x5f>
   140002136:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000213a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000213d:	85 c0                	test   eax,eax
   14000213f:	75 10                	jne    140002151 <do_pseudo_reloc+0x5f>
   140002141:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002145:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002148:	85 c0                	test   eax,eax
   14000214a:	75 05                	jne    140002151 <do_pseudo_reloc+0x5f>
   14000214c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002151:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002155:	8b 00                	mov    eax,DWORD PTR [rax]
   140002157:	85 c0                	test   eax,eax
   140002159:	75 0b                	jne    140002166 <do_pseudo_reloc+0x74>
   14000215b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000215f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002162:	85 c0                	test   eax,eax
   140002164:	74 59                	je     1400021bf <do_pseudo_reloc+0xcd>
   140002166:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000216a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000216e:	eb 40                	jmp    1400021b0 <do_pseudo_reloc+0xbe>
   140002170:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002174:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002177:	89 c2                	mov    edx,eax
   140002179:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000217d:	48 01 d0             	add    rax,rdx
   140002180:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002184:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002188:	8b 10                	mov    edx,DWORD PTR [rax]
   14000218a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000218e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002190:	01 d0                	add    eax,edx
   140002192:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002195:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002199:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000219d:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400021a3:	48 89 c1             	mov    rcx,rax
   1400021a6:	e8 00 ff ff ff       	call   1400020ab <__write_memory>
   1400021ab:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   1400021b0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400021b4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400021b8:	72 b6                	jb     140002170 <do_pseudo_reloc+0x7e>
   1400021ba:	e9 ab 02 00 00       	jmp    14000246a <do_pseudo_reloc+0x378>
   1400021bf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021c3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021c6:	83 f8 01             	cmp    eax,0x1
   1400021c9:	74 18                	je     1400021e3 <do_pseudo_reloc+0xf1>
   1400021cb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021cf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021d2:	89 c2                	mov    edx,eax
   1400021d4:	48 8d 05 95 30 00 00 	lea    rax,[rip+0x3095]        # 140005270 <.rdata+0xa0>
   1400021db:	48 89 c1             	mov    rcx,rax
   1400021de:	e8 ad fa ff ff       	call   140001c90 <__report_error>
   1400021e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021e7:	48 83 c0 0c          	add    rax,0xc
   1400021eb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400021ef:	e9 65 02 00 00       	jmp    140002459 <do_pseudo_reloc+0x367>
   1400021f4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021f8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400021fb:	89 c2                	mov    edx,eax
   1400021fd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002201:	48 01 d0             	add    rax,rdx
   140002204:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002208:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000220c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000220e:	89 c2                	mov    edx,eax
   140002210:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002214:	48 01 d0             	add    rax,rdx
   140002217:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000221b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000221f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002222:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002226:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000222a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000222d:	0f b6 c0             	movzx  eax,al
   140002230:	83 f8 40             	cmp    eax,0x40
   140002233:	0f 84 b6 00 00 00    	je     1400022ef <do_pseudo_reloc+0x1fd>
   140002239:	83 f8 40             	cmp    eax,0x40
   14000223c:	0f 87 ba 00 00 00    	ja     1400022fc <do_pseudo_reloc+0x20a>
   140002242:	83 f8 20             	cmp    eax,0x20
   140002245:	74 77                	je     1400022be <do_pseudo_reloc+0x1cc>
   140002247:	83 f8 20             	cmp    eax,0x20
   14000224a:	0f 87 ac 00 00 00    	ja     1400022fc <do_pseudo_reloc+0x20a>
   140002250:	83 f8 08             	cmp    eax,0x8
   140002253:	74 0a                	je     14000225f <do_pseudo_reloc+0x16d>
   140002255:	83 f8 10             	cmp    eax,0x10
   140002258:	74 38                	je     140002292 <do_pseudo_reloc+0x1a0>
   14000225a:	e9 9d 00 00 00       	jmp    1400022fc <do_pseudo_reloc+0x20a>
   14000225f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002263:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002266:	0f b6 c0             	movzx  eax,al
   140002269:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000226d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002271:	25 80 00 00 00       	and    eax,0x80
   140002276:	48 85 c0             	test   rax,rax
   140002279:	0f 84 9d 00 00 00    	je     14000231c <do_pseudo_reloc+0x22a>
   14000227f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002283:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002289:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000228d:	e9 8a 00 00 00       	jmp    14000231c <do_pseudo_reloc+0x22a>
   140002292:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002296:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002299:	0f b7 c0             	movzx  eax,ax
   14000229c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022a0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022a4:	25 00 80 00 00       	and    eax,0x8000
   1400022a9:	48 85 c0             	test   rax,rax
   1400022ac:	74 71                	je     14000231f <do_pseudo_reloc+0x22d>
   1400022ae:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022b2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400022b8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022bc:	eb 61                	jmp    14000231f <do_pseudo_reloc+0x22d>
   1400022be:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022c2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400022c4:	89 c0                	mov    eax,eax
   1400022c6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022ca:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022ce:	25 00 00 00 80       	and    eax,0x80000000
   1400022d3:	48 85 c0             	test   rax,rax
   1400022d6:	74 4a                	je     140002322 <do_pseudo_reloc+0x230>
   1400022d8:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022dc:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   1400022e3:	ff ff ff 
   1400022e6:	48 09 d0             	or     rax,rdx
   1400022e9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022ed:	eb 33                	jmp    140002322 <do_pseudo_reloc+0x230>
   1400022ef:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022f3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400022f6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022fa:	eb 27                	jmp    140002323 <do_pseudo_reloc+0x231>
   1400022fc:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002303:	00 
   140002304:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002308:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000230b:	0f b6 c0             	movzx  eax,al
   14000230e:	48 8d 0d 93 2f 00 00 	lea    rcx,[rip+0x2f93]        # 1400052a8 <.rdata+0xd8>
   140002315:	89 c2                	mov    edx,eax
   140002317:	e8 74 f9 ff ff       	call   140001c90 <__report_error>
   14000231c:	90                   	nop
   14000231d:	eb 04                	jmp    140002323 <do_pseudo_reloc+0x231>
   14000231f:	90                   	nop
   140002320:	eb 01                	jmp    140002323 <do_pseudo_reloc+0x231>
   140002322:	90                   	nop
   140002323:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002327:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000232b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000232d:	89 c2                	mov    edx,eax
   14000232f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002333:	48 01 c2             	add    rdx,rax
   140002336:	48 89 c8             	mov    rax,rcx
   140002339:	48 29 d0             	sub    rax,rdx
   14000233c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002340:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002344:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002348:	48 01 d0             	add    rax,rdx
   14000234b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000234f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002353:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002356:	25 ff 00 00 00       	and    eax,0xff
   14000235b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000235e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002362:	77 67                	ja     1400023cb <do_pseudo_reloc+0x2d9>
   140002364:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002367:	ba 01 00 00 00       	mov    edx,0x1
   14000236c:	89 c1                	mov    ecx,eax
   14000236e:	48 d3 e2             	shl    rdx,cl
   140002371:	48 89 d0             	mov    rax,rdx
   140002374:	48 83 e8 01          	sub    rax,0x1
   140002378:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000237c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000237f:	83 e8 01             	sub    eax,0x1
   140002382:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002389:	89 c1                	mov    ecx,eax
   14000238b:	48 d3 e2             	shl    rdx,cl
   14000238e:	48 89 d0             	mov    rax,rdx
   140002391:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002395:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002399:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000239d:	7c 0a                	jl     1400023a9 <do_pseudo_reloc+0x2b7>
   14000239f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400023a3:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400023a7:	7e 22                	jle    1400023cb <do_pseudo_reloc+0x2d9>
   1400023a9:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400023ad:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400023b1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400023b5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400023b8:	48 8d 0d 19 2f 00 00 	lea    rcx,[rip+0x2f19]        # 1400052d8 <.rdata+0x108>
   1400023bf:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400023c4:	89 c2                	mov    edx,eax
   1400023c6:	e8 c5 f8 ff ff       	call   140001c90 <__report_error>
   1400023cb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400023cf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400023d2:	0f b6 c0             	movzx  eax,al
   1400023d5:	83 f8 40             	cmp    eax,0x40
   1400023d8:	74 63                	je     14000243d <do_pseudo_reloc+0x34b>
   1400023da:	83 f8 40             	cmp    eax,0x40
   1400023dd:	77 75                	ja     140002454 <do_pseudo_reloc+0x362>
   1400023df:	83 f8 20             	cmp    eax,0x20
   1400023e2:	74 41                	je     140002425 <do_pseudo_reloc+0x333>
   1400023e4:	83 f8 20             	cmp    eax,0x20
   1400023e7:	77 6b                	ja     140002454 <do_pseudo_reloc+0x362>
   1400023e9:	83 f8 08             	cmp    eax,0x8
   1400023ec:	74 07                	je     1400023f5 <do_pseudo_reloc+0x303>
   1400023ee:	83 f8 10             	cmp    eax,0x10
   1400023f1:	74 1a                	je     14000240d <do_pseudo_reloc+0x31b>
   1400023f3:	eb 5f                	jmp    140002454 <do_pseudo_reloc+0x362>
   1400023f5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400023f9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400023fd:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002403:	48 89 c1             	mov    rcx,rax
   140002406:	e8 a0 fc ff ff       	call   1400020ab <__write_memory>
   14000240b:	eb 47                	jmp    140002454 <do_pseudo_reloc+0x362>
   14000240d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002411:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002415:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000241b:	48 89 c1             	mov    rcx,rax
   14000241e:	e8 88 fc ff ff       	call   1400020ab <__write_memory>
   140002423:	eb 2f                	jmp    140002454 <do_pseudo_reloc+0x362>
   140002425:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002429:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000242d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002433:	48 89 c1             	mov    rcx,rax
   140002436:	e8 70 fc ff ff       	call   1400020ab <__write_memory>
   14000243b:	eb 17                	jmp    140002454 <do_pseudo_reloc+0x362>
   14000243d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002441:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002445:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000244b:	48 89 c1             	mov    rcx,rax
   14000244e:	e8 58 fc ff ff       	call   1400020ab <__write_memory>
   140002453:	90                   	nop
   140002454:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002459:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000245d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002461:	0f 82 8d fd ff ff    	jb     1400021f4 <do_pseudo_reloc+0x102>
   140002467:	eb 01                	jmp    14000246a <do_pseudo_reloc+0x378>
   140002469:	90                   	nop
   14000246a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000246e:	5d                   	pop    rbp
   14000246f:	c3                   	ret

0000000140002470 <_pei386_runtime_relocator>:
   140002470:	55                   	push   rbp
   140002471:	48 89 e5             	mov    rbp,rsp
   140002474:	48 83 ec 30          	sub    rsp,0x30
   140002478:	8b 05 6e 6c 00 00    	mov    eax,DWORD PTR [rip+0x6c6e]        # 1400090ec <was_init.0>
   14000247e:	85 c0                	test   eax,eax
   140002480:	0f 85 88 00 00 00    	jne    14000250e <_pei386_runtime_relocator+0x9e>
   140002486:	8b 05 60 6c 00 00    	mov    eax,DWORD PTR [rip+0x6c60]        # 1400090ec <was_init.0>
   14000248c:	83 c0 01             	add    eax,0x1
   14000248f:	89 05 57 6c 00 00    	mov    DWORD PTR [rip+0x6c57],eax        # 1400090ec <was_init.0>
   140002495:	e8 21 0b 00 00       	call   140002fbb <__mingw_GetSectionCount>
   14000249a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000249d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400024a0:	48 63 d0             	movsxd rdx,eax
   1400024a3:	48 89 d0             	mov    rax,rdx
   1400024a6:	48 c1 e0 02          	shl    rax,0x2
   1400024aa:	48 01 d0             	add    rax,rdx
   1400024ad:	48 c1 e0 03          	shl    rax,0x3
   1400024b1:	48 83 c0 0f          	add    rax,0xf
   1400024b5:	48 c1 e8 04          	shr    rax,0x4
   1400024b9:	48 c1 e0 04          	shl    rax,0x4
   1400024bd:	e8 7e 0d 00 00       	call   140003240 <___chkstk_ms>
   1400024c2:	48 29 c4             	sub    rsp,rax
   1400024c5:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400024ca:	48 83 c0 0f          	add    rax,0xf
   1400024ce:	48 c1 e8 04          	shr    rax,0x4
   1400024d2:	48 c1 e0 04          	shl    rax,0x4
   1400024d6:	48 89 05 03 6c 00 00 	mov    QWORD PTR [rip+0x6c03],rax        # 1400090e0 <the_secs>
   1400024dd:	c7 05 01 6c 00 00 00 	mov    DWORD PTR [rip+0x6c01],0x0        # 1400090e8 <maxSections>
   1400024e4:	00 00 00 
   1400024e7:	48 8b 0d 72 2e 00 00 	mov    rcx,QWORD PTR [rip+0x2e72]        # 140005360 <.refptr.__ImageBase>
   1400024ee:	48 8b 15 7b 2e 00 00 	mov    rdx,QWORD PTR [rip+0x2e7b]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   1400024f5:	48 8b 05 84 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e84]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   1400024fc:	49 89 c8             	mov    r8,rcx
   1400024ff:	48 89 c1             	mov    rcx,rax
   140002502:	e8 eb fb ff ff       	call   1400020f2 <do_pseudo_reloc>
   140002507:	e8 c7 fa ff ff       	call   140001fd3 <restore_modified_sections>
   14000250c:	eb 01                	jmp    14000250f <_pei386_runtime_relocator+0x9f>
   14000250e:	90                   	nop
   14000250f:	48 89 ec             	mov    rsp,rbp
   140002512:	5d                   	pop    rbp
   140002513:	c3                   	ret
   140002514:	90                   	nop
   140002515:	90                   	nop
   140002516:	90                   	nop
   140002517:	90                   	nop
   140002518:	90                   	nop
   140002519:	90                   	nop
   14000251a:	90                   	nop
   14000251b:	90                   	nop
   14000251c:	90                   	nop
   14000251d:	90                   	nop
   14000251e:	90                   	nop
   14000251f:	90                   	nop

0000000140002520 <__mingw_raise_matherr>:
   140002520:	55                   	push   rbp
   140002521:	48 89 e5             	mov    rbp,rsp
   140002524:	48 83 ec 50          	sub    rsp,0x50
   140002528:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000252b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000252f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002534:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002539:	48 8b 05 b0 6b 00 00 	mov    rax,QWORD PTR [rip+0x6bb0]        # 1400090f0 <stUserMathErr>
   140002540:	48 85 c0             	test   rax,rax
   140002543:	74 3e                	je     140002583 <__mingw_raise_matherr+0x63>
   140002545:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002548:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000254b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000254f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002553:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002558:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000255d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002562:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002567:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000256c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002571:	48 8b 15 78 6b 00 00 	mov    rdx,QWORD PTR [rip+0x6b78]        # 1400090f0 <stUserMathErr>
   140002578:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000257c:	48 89 c1             	mov    rcx,rax
   14000257f:	ff d2                	call   rdx
   140002581:	eb 01                	jmp    140002584 <__mingw_raise_matherr+0x64>
   140002583:	90                   	nop
   140002584:	48 83 c4 50          	add    rsp,0x50
   140002588:	5d                   	pop    rbp
   140002589:	c3                   	ret

000000014000258a <__mingw_setusermatherr>:
   14000258a:	55                   	push   rbp
   14000258b:	48 89 e5             	mov    rbp,rsp
   14000258e:	48 83 ec 20          	sub    rsp,0x20
   140002592:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002596:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000259a:	48 89 05 4f 6b 00 00 	mov    QWORD PTR [rip+0x6b4f],rax        # 1400090f0 <stUserMathErr>
   1400025a1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400025a5:	48 89 c1             	mov    rcx,rax
   1400025a8:	e8 13 0e 00 00       	call   1400033c0 <__setusermatherr>
   1400025ad:	90                   	nop
   1400025ae:	48 83 c4 20          	add    rsp,0x20
   1400025b2:	5d                   	pop    rbp
   1400025b3:	c3                   	ret
   1400025b4:	90                   	nop
   1400025b5:	90                   	nop
   1400025b6:	90                   	nop
   1400025b7:	90                   	nop
   1400025b8:	90                   	nop
   1400025b9:	90                   	nop
   1400025ba:	90                   	nop
   1400025bb:	90                   	nop
   1400025bc:	90                   	nop
   1400025bd:	90                   	nop
   1400025be:	90                   	nop
   1400025bf:	90                   	nop

00000001400025c0 <__mingw_SEH_error_handler>:
   1400025c0:	55                   	push   rbp
   1400025c1:	48 89 e5             	mov    rbp,rsp
   1400025c4:	48 83 ec 30          	sub    rsp,0x30
   1400025c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400025cc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400025d0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400025d4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400025d8:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400025df:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400025e6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400025ea:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400025ed:	83 e0 02             	and    eax,0x2
   1400025f0:	85 c0                	test   eax,eax
   1400025f2:	74 0a                	je     1400025fe <__mingw_SEH_error_handler+0x3e>
   1400025f4:	b8 01 00 00 00       	mov    eax,0x1
   1400025f9:	e9 16 02 00 00       	jmp    140002814 <__mingw_SEH_error_handler+0x254>
   1400025fe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002602:	8b 00                	mov    eax,DWORD PTR [rax]
   140002604:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002609:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000260e:	75 18                	jne    140002628 <__mingw_SEH_error_handler+0x68>
   140002610:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002614:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002617:	83 e0 01             	and    eax,0x1
   14000261a:	85 c0                	test   eax,eax
   14000261c:	75 0a                	jne    140002628 <__mingw_SEH_error_handler+0x68>
   14000261e:	b8 00 00 00 00       	mov    eax,0x0
   140002623:	e9 ec 01 00 00       	jmp    140002814 <__mingw_SEH_error_handler+0x254>
   140002628:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000262c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000262e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002633:	0f 84 12 01 00 00    	je     14000274b <__mingw_SEH_error_handler+0x18b>
   140002639:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000263e:	0f 87 c3 01 00 00    	ja     140002807 <__mingw_SEH_error_handler+0x247>
   140002644:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002649:	0f 87 b8 01 00 00    	ja     140002807 <__mingw_SEH_error_handler+0x247>
   14000264f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002654:	0f 83 4c 01 00 00    	jae    1400027a6 <__mingw_SEH_error_handler+0x1e6>
   14000265a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000265f:	0f 84 3a 01 00 00    	je     14000279f <__mingw_SEH_error_handler+0x1df>
   140002665:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000266a:	0f 87 97 01 00 00    	ja     140002807 <__mingw_SEH_error_handler+0x247>
   140002670:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002675:	0f 84 83 01 00 00    	je     1400027fe <__mingw_SEH_error_handler+0x23e>
   14000267b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002680:	0f 87 81 01 00 00    	ja     140002807 <__mingw_SEH_error_handler+0x247>
   140002686:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000268b:	0f 87 76 01 00 00    	ja     140002807 <__mingw_SEH_error_handler+0x247>
   140002691:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002696:	0f 83 03 01 00 00    	jae    14000279f <__mingw_SEH_error_handler+0x1df>
   14000269c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400026a1:	0f 84 57 01 00 00    	je     1400027fe <__mingw_SEH_error_handler+0x23e>
   1400026a7:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400026ac:	0f 87 55 01 00 00    	ja     140002807 <__mingw_SEH_error_handler+0x247>
   1400026b2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400026b7:	0f 84 8e 00 00 00    	je     14000274b <__mingw_SEH_error_handler+0x18b>
   1400026bd:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400026c2:	0f 87 3f 01 00 00    	ja     140002807 <__mingw_SEH_error_handler+0x247>
   1400026c8:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400026cd:	0f 84 2b 01 00 00    	je     1400027fe <__mingw_SEH_error_handler+0x23e>
   1400026d3:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400026d8:	0f 87 29 01 00 00    	ja     140002807 <__mingw_SEH_error_handler+0x247>
   1400026de:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400026e3:	0f 84 15 01 00 00    	je     1400027fe <__mingw_SEH_error_handler+0x23e>
   1400026e9:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400026ee:	0f 85 13 01 00 00    	jne    140002807 <__mingw_SEH_error_handler+0x247>
   1400026f4:	ba 00 00 00 00       	mov    edx,0x0
   1400026f9:	b9 0b 00 00 00       	mov    ecx,0xb
   1400026fe:	e8 35 0d 00 00       	call   140003438 <signal>
   140002703:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002707:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000270c:	75 1b                	jne    140002729 <__mingw_SEH_error_handler+0x169>
   14000270e:	ba 01 00 00 00       	mov    edx,0x1
   140002713:	b9 0b 00 00 00       	mov    ecx,0xb
   140002718:	e8 1b 0d 00 00       	call   140003438 <signal>
   14000271d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002724:	e9 e1 00 00 00       	jmp    14000280a <__mingw_SEH_error_handler+0x24a>
   140002729:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000272e:	0f 84 d6 00 00 00    	je     14000280a <__mingw_SEH_error_handler+0x24a>
   140002734:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002738:	b9 0b 00 00 00       	mov    ecx,0xb
   14000273d:	ff d0                	call   rax
   14000273f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002746:	e9 bf 00 00 00       	jmp    14000280a <__mingw_SEH_error_handler+0x24a>
   14000274b:	ba 00 00 00 00       	mov    edx,0x0
   140002750:	b9 04 00 00 00       	mov    ecx,0x4
   140002755:	e8 de 0c 00 00       	call   140003438 <signal>
   14000275a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000275e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002763:	75 1b                	jne    140002780 <__mingw_SEH_error_handler+0x1c0>
   140002765:	ba 01 00 00 00       	mov    edx,0x1
   14000276a:	b9 04 00 00 00       	mov    ecx,0x4
   14000276f:	e8 c4 0c 00 00       	call   140003438 <signal>
   140002774:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000277b:	e9 8d 00 00 00       	jmp    14000280d <__mingw_SEH_error_handler+0x24d>
   140002780:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002785:	0f 84 82 00 00 00    	je     14000280d <__mingw_SEH_error_handler+0x24d>
   14000278b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000278f:	b9 04 00 00 00       	mov    ecx,0x4
   140002794:	ff d0                	call   rax
   140002796:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000279d:	eb 6e                	jmp    14000280d <__mingw_SEH_error_handler+0x24d>
   14000279f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400027a6:	ba 00 00 00 00       	mov    edx,0x0
   1400027ab:	b9 08 00 00 00       	mov    ecx,0x8
   1400027b0:	e8 83 0c 00 00       	call   140003438 <signal>
   1400027b5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027b9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027be:	75 23                	jne    1400027e3 <__mingw_SEH_error_handler+0x223>
   1400027c0:	ba 01 00 00 00       	mov    edx,0x1
   1400027c5:	b9 08 00 00 00       	mov    ecx,0x8
   1400027ca:	e8 69 0c 00 00       	call   140003438 <signal>
   1400027cf:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400027d3:	74 05                	je     1400027da <__mingw_SEH_error_handler+0x21a>
   1400027d5:	e8 a6 05 00 00       	call   140002d80 <_fpreset>
   1400027da:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400027e1:	eb 2d                	jmp    140002810 <__mingw_SEH_error_handler+0x250>
   1400027e3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027e8:	74 26                	je     140002810 <__mingw_SEH_error_handler+0x250>
   1400027ea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027ee:	b9 08 00 00 00       	mov    ecx,0x8
   1400027f3:	ff d0                	call   rax
   1400027f5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400027fc:	eb 12                	jmp    140002810 <__mingw_SEH_error_handler+0x250>
   1400027fe:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002805:	eb 0a                	jmp    140002811 <__mingw_SEH_error_handler+0x251>
   140002807:	90                   	nop
   140002808:	eb 07                	jmp    140002811 <__mingw_SEH_error_handler+0x251>
   14000280a:	90                   	nop
   14000280b:	eb 04                	jmp    140002811 <__mingw_SEH_error_handler+0x251>
   14000280d:	90                   	nop
   14000280e:	eb 01                	jmp    140002811 <__mingw_SEH_error_handler+0x251>
   140002810:	90                   	nop
   140002811:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002814:	48 83 c4 30          	add    rsp,0x30
   140002818:	5d                   	pop    rbp
   140002819:	c3                   	ret

000000014000281a <_gnu_exception_handler>:
   14000281a:	55                   	push   rbp
   14000281b:	48 89 e5             	mov    rbp,rsp
   14000281e:	48 83 ec 30          	sub    rsp,0x30
   140002822:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002826:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000282d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002834:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002838:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000283b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000283d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002842:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002847:	75 1b                	jne    140002864 <_gnu_exception_handler+0x4a>
   140002849:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000284d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002850:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002853:	83 e0 01             	and    eax,0x1
   140002856:	85 c0                	test   eax,eax
   140002858:	75 0a                	jne    140002864 <_gnu_exception_handler+0x4a>
   14000285a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000285f:	e9 14 02 00 00       	jmp    140002a78 <_gnu_exception_handler+0x25e>
   140002864:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002868:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000286b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000286d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002872:	0f 84 12 01 00 00    	je     14000298a <_gnu_exception_handler+0x170>
   140002878:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000287d:	0f 87 c3 01 00 00    	ja     140002a46 <_gnu_exception_handler+0x22c>
   140002883:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002888:	0f 87 b8 01 00 00    	ja     140002a46 <_gnu_exception_handler+0x22c>
   14000288e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002893:	0f 83 4c 01 00 00    	jae    1400029e5 <_gnu_exception_handler+0x1cb>
   140002899:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000289e:	0f 84 3a 01 00 00    	je     1400029de <_gnu_exception_handler+0x1c4>
   1400028a4:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400028a9:	0f 87 97 01 00 00    	ja     140002a46 <_gnu_exception_handler+0x22c>
   1400028af:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400028b4:	0f 84 83 01 00 00    	je     140002a3d <_gnu_exception_handler+0x223>
   1400028ba:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400028bf:	0f 87 81 01 00 00    	ja     140002a46 <_gnu_exception_handler+0x22c>
   1400028c5:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400028ca:	0f 87 76 01 00 00    	ja     140002a46 <_gnu_exception_handler+0x22c>
   1400028d0:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400028d5:	0f 83 03 01 00 00    	jae    1400029de <_gnu_exception_handler+0x1c4>
   1400028db:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400028e0:	0f 84 57 01 00 00    	je     140002a3d <_gnu_exception_handler+0x223>
   1400028e6:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400028eb:	0f 87 55 01 00 00    	ja     140002a46 <_gnu_exception_handler+0x22c>
   1400028f1:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400028f6:	0f 84 8e 00 00 00    	je     14000298a <_gnu_exception_handler+0x170>
   1400028fc:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002901:	0f 87 3f 01 00 00    	ja     140002a46 <_gnu_exception_handler+0x22c>
   140002907:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000290c:	0f 84 2b 01 00 00    	je     140002a3d <_gnu_exception_handler+0x223>
   140002912:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002917:	0f 87 29 01 00 00    	ja     140002a46 <_gnu_exception_handler+0x22c>
   14000291d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002922:	0f 84 15 01 00 00    	je     140002a3d <_gnu_exception_handler+0x223>
   140002928:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000292d:	0f 85 13 01 00 00    	jne    140002a46 <_gnu_exception_handler+0x22c>
   140002933:	ba 00 00 00 00       	mov    edx,0x0
   140002938:	b9 0b 00 00 00       	mov    ecx,0xb
   14000293d:	e8 f6 0a 00 00       	call   140003438 <signal>
   140002942:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002946:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000294b:	75 1b                	jne    140002968 <_gnu_exception_handler+0x14e>
   14000294d:	ba 01 00 00 00       	mov    edx,0x1
   140002952:	b9 0b 00 00 00       	mov    ecx,0xb
   140002957:	e8 dc 0a 00 00       	call   140003438 <signal>
   14000295c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002963:	e9 e1 00 00 00       	jmp    140002a49 <_gnu_exception_handler+0x22f>
   140002968:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000296d:	0f 84 d6 00 00 00    	je     140002a49 <_gnu_exception_handler+0x22f>
   140002973:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002977:	b9 0b 00 00 00       	mov    ecx,0xb
   14000297c:	ff d0                	call   rax
   14000297e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002985:	e9 bf 00 00 00       	jmp    140002a49 <_gnu_exception_handler+0x22f>
   14000298a:	ba 00 00 00 00       	mov    edx,0x0
   14000298f:	b9 04 00 00 00       	mov    ecx,0x4
   140002994:	e8 9f 0a 00 00       	call   140003438 <signal>
   140002999:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000299d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400029a2:	75 1b                	jne    1400029bf <_gnu_exception_handler+0x1a5>
   1400029a4:	ba 01 00 00 00       	mov    edx,0x1
   1400029a9:	b9 04 00 00 00       	mov    ecx,0x4
   1400029ae:	e8 85 0a 00 00       	call   140003438 <signal>
   1400029b3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400029ba:	e9 8d 00 00 00       	jmp    140002a4c <_gnu_exception_handler+0x232>
   1400029bf:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400029c4:	0f 84 82 00 00 00    	je     140002a4c <_gnu_exception_handler+0x232>
   1400029ca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ce:	b9 04 00 00 00       	mov    ecx,0x4
   1400029d3:	ff d0                	call   rax
   1400029d5:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400029dc:	eb 6e                	jmp    140002a4c <_gnu_exception_handler+0x232>
   1400029de:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400029e5:	ba 00 00 00 00       	mov    edx,0x0
   1400029ea:	b9 08 00 00 00       	mov    ecx,0x8
   1400029ef:	e8 44 0a 00 00       	call   140003438 <signal>
   1400029f4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029f8:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400029fd:	75 23                	jne    140002a22 <_gnu_exception_handler+0x208>
   1400029ff:	ba 01 00 00 00       	mov    edx,0x1
   140002a04:	b9 08 00 00 00       	mov    ecx,0x8
   140002a09:	e8 2a 0a 00 00       	call   140003438 <signal>
   140002a0e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002a12:	74 05                	je     140002a19 <_gnu_exception_handler+0x1ff>
   140002a14:	e8 67 03 00 00       	call   140002d80 <_fpreset>
   140002a19:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a20:	eb 2d                	jmp    140002a4f <_gnu_exception_handler+0x235>
   140002a22:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a27:	74 26                	je     140002a4f <_gnu_exception_handler+0x235>
   140002a29:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a2d:	b9 08 00 00 00       	mov    ecx,0x8
   140002a32:	ff d0                	call   rax
   140002a34:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a3b:	eb 12                	jmp    140002a4f <_gnu_exception_handler+0x235>
   140002a3d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a44:	eb 0a                	jmp    140002a50 <_gnu_exception_handler+0x236>
   140002a46:	90                   	nop
   140002a47:	eb 07                	jmp    140002a50 <_gnu_exception_handler+0x236>
   140002a49:	90                   	nop
   140002a4a:	eb 04                	jmp    140002a50 <_gnu_exception_handler+0x236>
   140002a4c:	90                   	nop
   140002a4d:	eb 01                	jmp    140002a50 <_gnu_exception_handler+0x236>
   140002a4f:	90                   	nop
   140002a50:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002a54:	75 1f                	jne    140002a75 <_gnu_exception_handler+0x25b>
   140002a56:	48 8b 05 b3 66 00 00 	mov    rax,QWORD PTR [rip+0x66b3]        # 140009110 <__mingw_oldexcpt_handler>
   140002a5d:	48 85 c0             	test   rax,rax
   140002a60:	74 13                	je     140002a75 <_gnu_exception_handler+0x25b>
   140002a62:	48 8b 15 a7 66 00 00 	mov    rdx,QWORD PTR [rip+0x66a7]        # 140009110 <__mingw_oldexcpt_handler>
   140002a69:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002a6d:	48 89 c1             	mov    rcx,rax
   140002a70:	ff d2                	call   rdx
   140002a72:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002a75:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002a78:	48 83 c4 30          	add    rsp,0x30
   140002a7c:	5d                   	pop    rbp
   140002a7d:	c3                   	ret
   140002a7e:	90                   	nop
   140002a7f:	90                   	nop

0000000140002a80 <___w64_mingwthr_add_key_dtor>:
   140002a80:	55                   	push   rbp
   140002a81:	48 89 e5             	mov    rbp,rsp
   140002a84:	48 83 ec 30          	sub    rsp,0x30
   140002a88:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a8b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002a8f:	8b 05 b3 66 00 00    	mov    eax,DWORD PTR [rip+0x66b3]        # 140009148 <__mingwthr_cs_init>
   140002a95:	85 c0                	test   eax,eax
   140002a97:	75 07                	jne    140002aa0 <___w64_mingwthr_add_key_dtor+0x20>
   140002a99:	b8 00 00 00 00       	mov    eax,0x0
   140002a9e:	eb 7b                	jmp    140002b1b <___w64_mingwthr_add_key_dtor+0x9b>
   140002aa0:	ba 18 00 00 00       	mov    edx,0x18
   140002aa5:	b9 01 00 00 00       	mov    ecx,0x1
   140002aaa:	e8 41 09 00 00       	call   1400033f0 <calloc>
   140002aaf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ab3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ab8:	75 07                	jne    140002ac1 <___w64_mingwthr_add_key_dtor+0x41>
   140002aba:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140002abf:	eb 5a                	jmp    140002b1b <___w64_mingwthr_add_key_dtor+0x9b>
   140002ac1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ac5:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002ac8:	89 10                	mov    DWORD PTR [rax],edx
   140002aca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ace:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002ad2:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002ad6:	48 8d 05 43 66 00 00 	lea    rax,[rip+0x6643]        # 140009120 <__mingwthr_cs>
   140002add:	48 89 c1             	mov    rcx,rax
   140002ae0:	48 8b 05 b1 76 00 00 	mov    rax,QWORD PTR [rip+0x76b1]        # 14000a198 <__imp_EnterCriticalSection>
   140002ae7:	ff d0                	call   rax
   140002ae9:	48 8b 15 60 66 00 00 	mov    rdx,QWORD PTR [rip+0x6660]        # 140009150 <key_dtor_list>
   140002af0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002af4:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002af8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002afc:	48 89 05 4d 66 00 00 	mov    QWORD PTR [rip+0x664d],rax        # 140009150 <key_dtor_list>
   140002b03:	48 8d 05 16 66 00 00 	lea    rax,[rip+0x6616]        # 140009120 <__mingwthr_cs>
   140002b0a:	48 89 c1             	mov    rcx,rax
   140002b0d:	48 8b 05 b4 76 00 00 	mov    rax,QWORD PTR [rip+0x76b4]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002b14:	ff d0                	call   rax
   140002b16:	b8 00 00 00 00       	mov    eax,0x0
   140002b1b:	48 83 c4 30          	add    rsp,0x30
   140002b1f:	5d                   	pop    rbp
   140002b20:	c3                   	ret

0000000140002b21 <___w64_mingwthr_remove_key_dtor>:
   140002b21:	55                   	push   rbp
   140002b22:	48 89 e5             	mov    rbp,rsp
   140002b25:	48 83 ec 30          	sub    rsp,0x30
   140002b29:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002b2c:	8b 05 16 66 00 00    	mov    eax,DWORD PTR [rip+0x6616]        # 140009148 <__mingwthr_cs_init>
   140002b32:	85 c0                	test   eax,eax
   140002b34:	75 0a                	jne    140002b40 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002b36:	b8 00 00 00 00       	mov    eax,0x0
   140002b3b:	e9 9c 00 00 00       	jmp    140002bdc <___w64_mingwthr_remove_key_dtor+0xbb>
   140002b40:	48 8d 05 d9 65 00 00 	lea    rax,[rip+0x65d9]        # 140009120 <__mingwthr_cs>
   140002b47:	48 89 c1             	mov    rcx,rax
   140002b4a:	48 8b 05 47 76 00 00 	mov    rax,QWORD PTR [rip+0x7647]        # 14000a198 <__imp_EnterCriticalSection>
   140002b51:	ff d0                	call   rax
   140002b53:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002b5a:	00 
   140002b5b:	48 8b 05 ee 65 00 00 	mov    rax,QWORD PTR [rip+0x65ee]        # 140009150 <key_dtor_list>
   140002b62:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b66:	eb 55                	jmp    140002bbd <___w64_mingwthr_remove_key_dtor+0x9c>
   140002b68:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b6c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b6e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002b71:	75 36                	jne    140002ba9 <___w64_mingwthr_remove_key_dtor+0x88>
   140002b73:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b78:	75 11                	jne    140002b8b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002b7a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b7e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b82:	48 89 05 c7 65 00 00 	mov    QWORD PTR [rip+0x65c7],rax        # 140009150 <key_dtor_list>
   140002b89:	eb 10                	jmp    140002b9b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002b8b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b8f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002b93:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b97:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002b9b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b9f:	48 89 c1             	mov    rcx,rax
   140002ba2:	e8 69 08 00 00       	call   140003410 <free>
   140002ba7:	eb 1b                	jmp    140002bc4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002ba9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bad:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bb1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bb5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002bb9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002bbd:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002bc2:	75 a4                	jne    140002b68 <___w64_mingwthr_remove_key_dtor+0x47>
   140002bc4:	48 8d 05 55 65 00 00 	lea    rax,[rip+0x6555]        # 140009120 <__mingwthr_cs>
   140002bcb:	48 89 c1             	mov    rcx,rax
   140002bce:	48 8b 05 f3 75 00 00 	mov    rax,QWORD PTR [rip+0x75f3]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002bd5:	ff d0                	call   rax
   140002bd7:	b8 00 00 00 00       	mov    eax,0x0
   140002bdc:	48 83 c4 30          	add    rsp,0x30
   140002be0:	5d                   	pop    rbp
   140002be1:	c3                   	ret

0000000140002be2 <__mingwthr_run_key_dtors>:
   140002be2:	55                   	push   rbp
   140002be3:	48 89 e5             	mov    rbp,rsp
   140002be6:	48 83 ec 30          	sub    rsp,0x30
   140002bea:	8b 05 58 65 00 00    	mov    eax,DWORD PTR [rip+0x6558]        # 140009148 <__mingwthr_cs_init>
   140002bf0:	85 c0                	test   eax,eax
   140002bf2:	0f 84 82 00 00 00    	je     140002c7a <__mingwthr_run_key_dtors+0x98>
   140002bf8:	48 8d 05 21 65 00 00 	lea    rax,[rip+0x6521]        # 140009120 <__mingwthr_cs>
   140002bff:	48 89 c1             	mov    rcx,rax
   140002c02:	48 8b 05 8f 75 00 00 	mov    rax,QWORD PTR [rip+0x758f]        # 14000a198 <__imp_EnterCriticalSection>
   140002c09:	ff d0                	call   rax
   140002c0b:	48 8b 05 3e 65 00 00 	mov    rax,QWORD PTR [rip+0x653e]        # 140009150 <key_dtor_list>
   140002c12:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c16:	eb 46                	jmp    140002c5e <__mingwthr_run_key_dtors+0x7c>
   140002c18:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c1c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c1e:	89 c1                	mov    ecx,eax
   140002c20:	48 8b 05 c1 75 00 00 	mov    rax,QWORD PTR [rip+0x75c1]        # 14000a1e8 <__imp_TlsGetValue>
   140002c27:	ff d0                	call   rax
   140002c29:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c2d:	48 8b 05 74 75 00 00 	mov    rax,QWORD PTR [rip+0x7574]        # 14000a1a8 <__imp_GetLastError>
   140002c34:	ff d0                	call   rax
   140002c36:	85 c0                	test   eax,eax
   140002c38:	75 18                	jne    140002c52 <__mingwthr_run_key_dtors+0x70>
   140002c3a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002c3f:	74 11                	je     140002c52 <__mingwthr_run_key_dtors+0x70>
   140002c41:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c45:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002c49:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c4d:	48 89 c1             	mov    rcx,rax
   140002c50:	ff d2                	call   rdx
   140002c52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c56:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c5a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c5e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c63:	75 b3                	jne    140002c18 <__mingwthr_run_key_dtors+0x36>
   140002c65:	48 8d 05 b4 64 00 00 	lea    rax,[rip+0x64b4]        # 140009120 <__mingwthr_cs>
   140002c6c:	48 89 c1             	mov    rcx,rax
   140002c6f:	48 8b 05 52 75 00 00 	mov    rax,QWORD PTR [rip+0x7552]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002c76:	ff d0                	call   rax
   140002c78:	eb 01                	jmp    140002c7b <__mingwthr_run_key_dtors+0x99>
   140002c7a:	90                   	nop
   140002c7b:	48 83 c4 30          	add    rsp,0x30
   140002c7f:	5d                   	pop    rbp
   140002c80:	c3                   	ret

0000000140002c81 <__mingw_TLScallback>:
   140002c81:	55                   	push   rbp
   140002c82:	48 89 e5             	mov    rbp,rsp
   140002c85:	48 83 ec 30          	sub    rsp,0x30
   140002c89:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c8d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002c90:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002c94:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002c98:	0f 84 cc 00 00 00    	je     140002d6a <__mingw_TLScallback+0xe9>
   140002c9e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002ca2:	0f 87 ca 00 00 00    	ja     140002d72 <__mingw_TLScallback+0xf1>
   140002ca8:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002cac:	0f 84 b1 00 00 00    	je     140002d63 <__mingw_TLScallback+0xe2>
   140002cb2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002cb6:	0f 87 b6 00 00 00    	ja     140002d72 <__mingw_TLScallback+0xf1>
   140002cbc:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002cc0:	74 33                	je     140002cf5 <__mingw_TLScallback+0x74>
   140002cc2:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002cc6:	0f 85 a6 00 00 00    	jne    140002d72 <__mingw_TLScallback+0xf1>
   140002ccc:	8b 05 76 64 00 00    	mov    eax,DWORD PTR [rip+0x6476]        # 140009148 <__mingwthr_cs_init>
   140002cd2:	85 c0                	test   eax,eax
   140002cd4:	75 13                	jne    140002ce9 <__mingw_TLScallback+0x68>
   140002cd6:	48 8d 05 43 64 00 00 	lea    rax,[rip+0x6443]        # 140009120 <__mingwthr_cs>
   140002cdd:	48 89 c1             	mov    rcx,rax
   140002ce0:	48 8b 05 d9 74 00 00 	mov    rax,QWORD PTR [rip+0x74d9]        # 14000a1c0 <__imp_InitializeCriticalSection>
   140002ce7:	ff d0                	call   rax
   140002ce9:	c7 05 55 64 00 00 01 	mov    DWORD PTR [rip+0x6455],0x1        # 140009148 <__mingwthr_cs_init>
   140002cf0:	00 00 00 
   140002cf3:	eb 7d                	jmp    140002d72 <__mingw_TLScallback+0xf1>
   140002cf5:	e8 e8 fe ff ff       	call   140002be2 <__mingwthr_run_key_dtors>
   140002cfa:	8b 05 48 64 00 00    	mov    eax,DWORD PTR [rip+0x6448]        # 140009148 <__mingwthr_cs_init>
   140002d00:	83 f8 01             	cmp    eax,0x1
   140002d03:	75 6c                	jne    140002d71 <__mingw_TLScallback+0xf0>
   140002d05:	48 8b 05 44 64 00 00 	mov    rax,QWORD PTR [rip+0x6444]        # 140009150 <key_dtor_list>
   140002d0c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d10:	eb 20                	jmp    140002d32 <__mingw_TLScallback+0xb1>
   140002d12:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d16:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002d1a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002d1e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d22:	48 89 c1             	mov    rcx,rax
   140002d25:	e8 e6 06 00 00       	call   140003410 <free>
   140002d2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d2e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d32:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002d37:	75 d9                	jne    140002d12 <__mingw_TLScallback+0x91>
   140002d39:	48 c7 05 0c 64 00 00 	mov    QWORD PTR [rip+0x640c],0x0        # 140009150 <key_dtor_list>
   140002d40:	00 00 00 00 
   140002d44:	c7 05 fa 63 00 00 00 	mov    DWORD PTR [rip+0x63fa],0x0        # 140009148 <__mingwthr_cs_init>
   140002d4b:	00 00 00 
   140002d4e:	48 8d 05 cb 63 00 00 	lea    rax,[rip+0x63cb]        # 140009120 <__mingwthr_cs>
   140002d55:	48 89 c1             	mov    rcx,rax
   140002d58:	48 8b 05 31 74 00 00 	mov    rax,QWORD PTR [rip+0x7431]        # 14000a190 <__IAT_start__>
   140002d5f:	ff d0                	call   rax
   140002d61:	eb 0e                	jmp    140002d71 <__mingw_TLScallback+0xf0>
   140002d63:	e8 18 00 00 00       	call   140002d80 <_fpreset>
   140002d68:	eb 08                	jmp    140002d72 <__mingw_TLScallback+0xf1>
   140002d6a:	e8 73 fe ff ff       	call   140002be2 <__mingwthr_run_key_dtors>
   140002d6f:	eb 01                	jmp    140002d72 <__mingw_TLScallback+0xf1>
   140002d71:	90                   	nop
   140002d72:	b8 01 00 00 00       	mov    eax,0x1
   140002d77:	48 83 c4 30          	add    rsp,0x30
   140002d7b:	5d                   	pop    rbp
   140002d7c:	c3                   	ret
   140002d7d:	90                   	nop
   140002d7e:	90                   	nop
   140002d7f:	90                   	nop

0000000140002d80 <_fpreset>:
   140002d80:	55                   	push   rbp
   140002d81:	48 89 e5             	mov    rbp,rsp
   140002d84:	db e3                	fninit
   140002d86:	90                   	nop
   140002d87:	5d                   	pop    rbp
   140002d88:	c3                   	ret
   140002d89:	90                   	nop
   140002d8a:	90                   	nop
   140002d8b:	90                   	nop
   140002d8c:	90                   	nop
   140002d8d:	90                   	nop
   140002d8e:	90                   	nop
   140002d8f:	90                   	nop

0000000140002d90 <_ValidateImageBase>:
   140002d90:	55                   	push   rbp
   140002d91:	48 89 e5             	mov    rbp,rsp
   140002d94:	48 83 ec 20          	sub    rsp,0x20
   140002d98:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d9c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002da0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002da4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002da8:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002dab:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002daf:	74 07                	je     140002db8 <_ValidateImageBase+0x28>
   140002db1:	b8 00 00 00 00       	mov    eax,0x0
   140002db6:	eb 4e                	jmp    140002e06 <_ValidateImageBase+0x76>
   140002db8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dbc:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002dbf:	48 63 d0             	movsxd rdx,eax
   140002dc2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dc6:	48 01 d0             	add    rax,rdx
   140002dc9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002dcd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002dd1:	8b 00                	mov    eax,DWORD PTR [rax]
   140002dd3:	3d 50 45 00 00       	cmp    eax,0x4550
   140002dd8:	74 07                	je     140002de1 <_ValidateImageBase+0x51>
   140002dda:	b8 00 00 00 00       	mov    eax,0x0
   140002ddf:	eb 25                	jmp    140002e06 <_ValidateImageBase+0x76>
   140002de1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002de5:	48 83 c0 18          	add    rax,0x18
   140002de9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ded:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002df1:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002df4:	66 3d 0b 02          	cmp    ax,0x20b
   140002df8:	74 07                	je     140002e01 <_ValidateImageBase+0x71>
   140002dfa:	b8 00 00 00 00       	mov    eax,0x0
   140002dff:	eb 05                	jmp    140002e06 <_ValidateImageBase+0x76>
   140002e01:	b8 01 00 00 00       	mov    eax,0x1
   140002e06:	48 83 c4 20          	add    rsp,0x20
   140002e0a:	5d                   	pop    rbp
   140002e0b:	c3                   	ret

0000000140002e0c <_FindPESection>:
   140002e0c:	55                   	push   rbp
   140002e0d:	48 89 e5             	mov    rbp,rsp
   140002e10:	48 83 ec 20          	sub    rsp,0x20
   140002e14:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e18:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002e1c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e20:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e23:	48 63 d0             	movsxd rdx,eax
   140002e26:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e2a:	48 01 d0             	add    rax,rdx
   140002e2d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e31:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e38:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e3c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e40:	0f b7 d0             	movzx  edx,ax
   140002e43:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e47:	48 01 d0             	add    rax,rdx
   140002e4a:	48 83 c0 18          	add    rax,0x18
   140002e4e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e52:	eb 36                	jmp    140002e8a <_FindPESection+0x7e>
   140002e54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e58:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002e5b:	89 c0                	mov    eax,eax
   140002e5d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002e61:	72 1e                	jb     140002e81 <_FindPESection+0x75>
   140002e63:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e67:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002e6a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e6e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002e71:	01 d0                	add    eax,edx
   140002e73:	89 c0                	mov    eax,eax
   140002e75:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002e79:	73 06                	jae    140002e81 <_FindPESection+0x75>
   140002e7b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e7f:	eb 1e                	jmp    140002e9f <_FindPESection+0x93>
   140002e81:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e85:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e8a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e8e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e92:	0f b7 c0             	movzx  eax,ax
   140002e95:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e98:	72 ba                	jb     140002e54 <_FindPESection+0x48>
   140002e9a:	b8 00 00 00 00       	mov    eax,0x0
   140002e9f:	48 83 c4 20          	add    rsp,0x20
   140002ea3:	5d                   	pop    rbp
   140002ea4:	c3                   	ret

0000000140002ea5 <_FindPESectionByName>:
   140002ea5:	55                   	push   rbp
   140002ea6:	48 89 e5             	mov    rbp,rsp
   140002ea9:	48 83 ec 40          	sub    rsp,0x40
   140002ead:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002eb1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002eb5:	48 89 c1             	mov    rcx,rax
   140002eb8:	e8 83 05 00 00       	call   140003440 <strlen>
   140002ebd:	48 83 f8 08          	cmp    rax,0x8
   140002ec1:	76 0a                	jbe    140002ecd <_FindPESectionByName+0x28>
   140002ec3:	b8 00 00 00 00       	mov    eax,0x0
   140002ec8:	e9 98 00 00 00       	jmp    140002f65 <_FindPESectionByName+0xc0>
   140002ecd:	48 8b 05 8c 24 00 00 	mov    rax,QWORD PTR [rip+0x248c]        # 140005360 <.refptr.__ImageBase>
   140002ed4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ed8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002edc:	48 89 c1             	mov    rcx,rax
   140002edf:	e8 ac fe ff ff       	call   140002d90 <_ValidateImageBase>
   140002ee4:	85 c0                	test   eax,eax
   140002ee6:	75 07                	jne    140002eef <_FindPESectionByName+0x4a>
   140002ee8:	b8 00 00 00 00       	mov    eax,0x0
   140002eed:	eb 76                	jmp    140002f65 <_FindPESectionByName+0xc0>
   140002eef:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ef3:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ef6:	48 63 d0             	movsxd rdx,eax
   140002ef9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002efd:	48 01 d0             	add    rax,rdx
   140002f00:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f04:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f0b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f0f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f13:	0f b7 d0             	movzx  edx,ax
   140002f16:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f1a:	48 01 d0             	add    rax,rdx
   140002f1d:	48 83 c0 18          	add    rax,0x18
   140002f21:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f25:	eb 29                	jmp    140002f50 <_FindPESectionByName+0xab>
   140002f27:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f2b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002f2f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002f35:	48 89 c1             	mov    rcx,rax
   140002f38:	e8 0b 05 00 00       	call   140003448 <strncmp>
   140002f3d:	85 c0                	test   eax,eax
   140002f3f:	75 06                	jne    140002f47 <_FindPESectionByName+0xa2>
   140002f41:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f45:	eb 1e                	jmp    140002f65 <_FindPESectionByName+0xc0>
   140002f47:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f4b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f50:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f54:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f58:	0f b7 c0             	movzx  eax,ax
   140002f5b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f5e:	72 c7                	jb     140002f27 <_FindPESectionByName+0x82>
   140002f60:	b8 00 00 00 00       	mov    eax,0x0
   140002f65:	48 83 c4 40          	add    rsp,0x40
   140002f69:	5d                   	pop    rbp
   140002f6a:	c3                   	ret

0000000140002f6b <__mingw_GetSectionForAddress>:
   140002f6b:	55                   	push   rbp
   140002f6c:	48 89 e5             	mov    rbp,rsp
   140002f6f:	48 83 ec 30          	sub    rsp,0x30
   140002f73:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f77:	48 8b 05 e2 23 00 00 	mov    rax,QWORD PTR [rip+0x23e2]        # 140005360 <.refptr.__ImageBase>
   140002f7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f82:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f86:	48 89 c1             	mov    rcx,rax
   140002f89:	e8 02 fe ff ff       	call   140002d90 <_ValidateImageBase>
   140002f8e:	85 c0                	test   eax,eax
   140002f90:	75 07                	jne    140002f99 <__mingw_GetSectionForAddress+0x2e>
   140002f92:	b8 00 00 00 00       	mov    eax,0x0
   140002f97:	eb 1c                	jmp    140002fb5 <__mingw_GetSectionForAddress+0x4a>
   140002f99:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f9d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002fa1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fa5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002fa9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fad:	48 89 c1             	mov    rcx,rax
   140002fb0:	e8 57 fe ff ff       	call   140002e0c <_FindPESection>
   140002fb5:	48 83 c4 30          	add    rsp,0x30
   140002fb9:	5d                   	pop    rbp
   140002fba:	c3                   	ret

0000000140002fbb <__mingw_GetSectionCount>:
   140002fbb:	55                   	push   rbp
   140002fbc:	48 89 e5             	mov    rbp,rsp
   140002fbf:	48 83 ec 30          	sub    rsp,0x30
   140002fc3:	48 8b 05 96 23 00 00 	mov    rax,QWORD PTR [rip+0x2396]        # 140005360 <.refptr.__ImageBase>
   140002fca:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fce:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fd2:	48 89 c1             	mov    rcx,rax
   140002fd5:	e8 b6 fd ff ff       	call   140002d90 <_ValidateImageBase>
   140002fda:	85 c0                	test   eax,eax
   140002fdc:	75 07                	jne    140002fe5 <__mingw_GetSectionCount+0x2a>
   140002fde:	b8 00 00 00 00       	mov    eax,0x0
   140002fe3:	eb 20                	jmp    140003005 <__mingw_GetSectionCount+0x4a>
   140002fe5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fe9:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002fec:	48 63 d0             	movsxd rdx,eax
   140002fef:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ff3:	48 01 d0             	add    rax,rdx
   140002ff6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ffa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ffe:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140003002:	0f b7 c0             	movzx  eax,ax
   140003005:	48 83 c4 30          	add    rsp,0x30
   140003009:	5d                   	pop    rbp
   14000300a:	c3                   	ret

000000014000300b <_FindPESectionExec>:
   14000300b:	55                   	push   rbp
   14000300c:	48 89 e5             	mov    rbp,rsp
   14000300f:	48 83 ec 40          	sub    rsp,0x40
   140003013:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003017:	48 8b 05 42 23 00 00 	mov    rax,QWORD PTR [rip+0x2342]        # 140005360 <.refptr.__ImageBase>
   14000301e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003022:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003026:	48 89 c1             	mov    rcx,rax
   140003029:	e8 62 fd ff ff       	call   140002d90 <_ValidateImageBase>
   14000302e:	85 c0                	test   eax,eax
   140003030:	75 07                	jne    140003039 <_FindPESectionExec+0x2e>
   140003032:	b8 00 00 00 00       	mov    eax,0x0
   140003037:	eb 78                	jmp    1400030b1 <_FindPESectionExec+0xa6>
   140003039:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000303d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003040:	48 63 d0             	movsxd rdx,eax
   140003043:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003047:	48 01 d0             	add    rax,rdx
   14000304a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000304e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140003055:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003059:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   14000305d:	0f b7 d0             	movzx  edx,ax
   140003060:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003064:	48 01 d0             	add    rax,rdx
   140003067:	48 83 c0 18          	add    rax,0x18
   14000306b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000306f:	eb 2b                	jmp    14000309c <_FindPESectionExec+0x91>
   140003071:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003075:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003078:	25 00 00 00 20       	and    eax,0x20000000
   14000307d:	85 c0                	test   eax,eax
   14000307f:	74 12                	je     140003093 <_FindPESectionExec+0x88>
   140003081:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140003086:	75 06                	jne    14000308e <_FindPESectionExec+0x83>
   140003088:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000308c:	eb 23                	jmp    1400030b1 <_FindPESectionExec+0xa6>
   14000308e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140003093:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140003097:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   14000309c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400030a0:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   1400030a4:	0f b7 c0             	movzx  eax,ax
   1400030a7:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   1400030aa:	72 c5                	jb     140003071 <_FindPESectionExec+0x66>
   1400030ac:	b8 00 00 00 00       	mov    eax,0x0
   1400030b1:	48 83 c4 40          	add    rsp,0x40
   1400030b5:	5d                   	pop    rbp
   1400030b6:	c3                   	ret

00000001400030b7 <_GetPEImageBase>:
   1400030b7:	55                   	push   rbp
   1400030b8:	48 89 e5             	mov    rbp,rsp
   1400030bb:	48 83 ec 30          	sub    rsp,0x30
   1400030bf:	48 8b 05 9a 22 00 00 	mov    rax,QWORD PTR [rip+0x229a]        # 140005360 <.refptr.__ImageBase>
   1400030c6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030ca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030ce:	48 89 c1             	mov    rcx,rax
   1400030d1:	e8 ba fc ff ff       	call   140002d90 <_ValidateImageBase>
   1400030d6:	85 c0                	test   eax,eax
   1400030d8:	75 07                	jne    1400030e1 <_GetPEImageBase+0x2a>
   1400030da:	b8 00 00 00 00       	mov    eax,0x0
   1400030df:	eb 04                	jmp    1400030e5 <_GetPEImageBase+0x2e>
   1400030e1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030e5:	48 83 c4 30          	add    rsp,0x30
   1400030e9:	5d                   	pop    rbp
   1400030ea:	c3                   	ret

00000001400030eb <_IsNonwritableInCurrentImage>:
   1400030eb:	55                   	push   rbp
   1400030ec:	48 89 e5             	mov    rbp,rsp
   1400030ef:	48 83 ec 40          	sub    rsp,0x40
   1400030f3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400030f7:	48 8b 05 62 22 00 00 	mov    rax,QWORD PTR [rip+0x2262]        # 140005360 <.refptr.__ImageBase>
   1400030fe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003102:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003106:	48 89 c1             	mov    rcx,rax
   140003109:	e8 82 fc ff ff       	call   140002d90 <_ValidateImageBase>
   14000310e:	85 c0                	test   eax,eax
   140003110:	75 07                	jne    140003119 <_IsNonwritableInCurrentImage+0x2e>
   140003112:	b8 00 00 00 00       	mov    eax,0x0
   140003117:	eb 3d                	jmp    140003156 <_IsNonwritableInCurrentImage+0x6b>
   140003119:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000311d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003121:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003125:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003129:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000312d:	48 89 c1             	mov    rcx,rax
   140003130:	e8 d7 fc ff ff       	call   140002e0c <_FindPESection>
   140003135:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003139:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000313e:	75 07                	jne    140003147 <_IsNonwritableInCurrentImage+0x5c>
   140003140:	b8 00 00 00 00       	mov    eax,0x0
   140003145:	eb 0f                	jmp    140003156 <_IsNonwritableInCurrentImage+0x6b>
   140003147:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000314b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000314e:	f7 d0                	not    eax
   140003150:	c1 e8 1f             	shr    eax,0x1f
   140003153:	0f b6 c0             	movzx  eax,al
   140003156:	48 83 c4 40          	add    rsp,0x40
   14000315a:	5d                   	pop    rbp
   14000315b:	c3                   	ret

000000014000315c <__mingw_enum_import_library_names>:
   14000315c:	55                   	push   rbp
   14000315d:	48 89 e5             	mov    rbp,rsp
   140003160:	48 83 ec 50          	sub    rsp,0x50
   140003164:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003167:	48 8b 05 f2 21 00 00 	mov    rax,QWORD PTR [rip+0x21f2]        # 140005360 <.refptr.__ImageBase>
   14000316e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003172:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003176:	48 89 c1             	mov    rcx,rax
   140003179:	e8 12 fc ff ff       	call   140002d90 <_ValidateImageBase>
   14000317e:	85 c0                	test   eax,eax
   140003180:	75 0a                	jne    14000318c <__mingw_enum_import_library_names+0x30>
   140003182:	b8 00 00 00 00       	mov    eax,0x0
   140003187:	e9 ab 00 00 00       	jmp    140003237 <__mingw_enum_import_library_names+0xdb>
   14000318c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003190:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003193:	48 63 d0             	movsxd rdx,eax
   140003196:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000319a:	48 01 d0             	add    rax,rdx
   14000319d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400031a1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400031a5:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   1400031ab:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400031ae:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400031b2:	75 07                	jne    1400031bb <__mingw_enum_import_library_names+0x5f>
   1400031b4:	b8 00 00 00 00       	mov    eax,0x0
   1400031b9:	eb 7c                	jmp    140003237 <__mingw_enum_import_library_names+0xdb>
   1400031bb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400031be:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400031c2:	48 89 c1             	mov    rcx,rax
   1400031c5:	e8 42 fc ff ff       	call   140002e0c <_FindPESection>
   1400031ca:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400031ce:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   1400031d3:	75 07                	jne    1400031dc <__mingw_enum_import_library_names+0x80>
   1400031d5:	b8 00 00 00 00       	mov    eax,0x0
   1400031da:	eb 5b                	jmp    140003237 <__mingw_enum_import_library_names+0xdb>
   1400031dc:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400031df:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400031e3:	48 01 d0             	add    rax,rdx
   1400031e6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031ea:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400031ef:	75 07                	jne    1400031f8 <__mingw_enum_import_library_names+0x9c>
   1400031f1:	b8 00 00 00 00       	mov    eax,0x0
   1400031f6:	eb 3f                	jmp    140003237 <__mingw_enum_import_library_names+0xdb>
   1400031f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031fc:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400031ff:	85 c0                	test   eax,eax
   140003201:	75 0b                	jne    14000320e <__mingw_enum_import_library_names+0xb2>
   140003203:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003207:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000320a:	85 c0                	test   eax,eax
   14000320c:	74 23                	je     140003231 <__mingw_enum_import_library_names+0xd5>
   14000320e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003212:	7f 12                	jg     140003226 <__mingw_enum_import_library_names+0xca>
   140003214:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003218:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000321b:	89 c2                	mov    edx,eax
   14000321d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003221:	48 01 d0             	add    rax,rdx
   140003224:	eb 11                	jmp    140003237 <__mingw_enum_import_library_names+0xdb>
   140003226:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000322a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000322f:	eb c7                	jmp    1400031f8 <__mingw_enum_import_library_names+0x9c>
   140003231:	90                   	nop
   140003232:	b8 00 00 00 00       	mov    eax,0x0
   140003237:	48 83 c4 50          	add    rsp,0x50
   14000323b:	5d                   	pop    rbp
   14000323c:	c3                   	ret
   14000323d:	90                   	nop
   14000323e:	90                   	nop
   14000323f:	90                   	nop

0000000140003240 <___chkstk_ms>:
   140003240:	51                   	push   rcx
   140003241:	50                   	push   rax
   140003242:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003248:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000324d:	72 19                	jb     140003268 <___chkstk_ms+0x28>
   14000324f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003256:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000325a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003260:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003266:	77 e7                	ja     14000324f <___chkstk_ms+0xf>
   140003268:	48 29 c1             	sub    rcx,rax
   14000326b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000326f:	58                   	pop    rax
   140003270:	59                   	pop    rcx
   140003271:	c3                   	ret
   140003272:	90                   	nop
   140003273:	90                   	nop
   140003274:	90                   	nop
   140003275:	90                   	nop
   140003276:	90                   	nop
   140003277:	90                   	nop
   140003278:	90                   	nop
   140003279:	90                   	nop
   14000327a:	90                   	nop
   14000327b:	90                   	nop
   14000327c:	90                   	nop
   14000327d:	90                   	nop
   14000327e:	90                   	nop
   14000327f:	90                   	nop

0000000140003280 <_initterm_e>:
   140003280:	55                   	push   rbp
   140003281:	48 89 e5             	mov    rbp,rsp
   140003284:	48 83 ec 30          	sub    rsp,0x30
   140003288:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000328c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003290:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003294:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003298:	eb 29                	jmp    1400032c3 <_initterm_e+0x43>
   14000329a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000329e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400032a1:	48 85 c0             	test   rax,rax
   1400032a4:	74 17                	je     1400032bd <_initterm_e+0x3d>
   1400032a6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400032aa:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400032ad:	ff d0                	call   rax
   1400032af:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400032b2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   1400032b6:	74 06                	je     1400032be <_initterm_e+0x3e>
   1400032b8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400032bb:	eb 15                	jmp    1400032d2 <_initterm_e+0x52>
   1400032bd:	90                   	nop
   1400032be:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400032c3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400032c7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400032cb:	72 cd                	jb     14000329a <_initterm_e+0x1a>
   1400032cd:	b8 00 00 00 00       	mov    eax,0x0
   1400032d2:	48 83 c4 30          	add    rsp,0x30
   1400032d6:	5d                   	pop    rbp
   1400032d7:	c3                   	ret
   1400032d8:	90                   	nop
   1400032d9:	90                   	nop
   1400032da:	90                   	nop
   1400032db:	90                   	nop
   1400032dc:	90                   	nop
   1400032dd:	90                   	nop
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <__p__fmode>:
   1400032e0:	55                   	push   rbp
   1400032e1:	48 89 e5             	mov    rbp,rsp
   1400032e4:	48 8b 05 e5 20 00 00 	mov    rax,QWORD PTR [rip+0x20e5]        # 1400053d0 <.refptr.__imp__fmode>
   1400032eb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400032ee:	5d                   	pop    rbp
   1400032ef:	c3                   	ret

00000001400032f0 <__p__commode>:
   1400032f0:	55                   	push   rbp
   1400032f1:	48 89 e5             	mov    rbp,rsp
   1400032f4:	48 8b 05 c5 20 00 00 	mov    rax,QWORD PTR [rip+0x20c5]        # 1400053c0 <.refptr.__imp__commode>
   1400032fb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400032fe:	5d                   	pop    rbp
   1400032ff:	c3                   	ret

0000000140003300 <__p___initenv>:
   140003300:	55                   	push   rbp
   140003301:	48 89 e5             	mov    rbp,rsp
   140003304:	48 8b 05 a5 20 00 00 	mov    rax,QWORD PTR [rip+0x20a5]        # 1400053b0 <.refptr.__imp___initenv>
   14000330b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000330e:	5d                   	pop    rbp
   14000330f:	c3                   	ret

0000000140003310 <_set_invalid_parameter_handler>:
   140003310:	55                   	push   rbp
   140003311:	48 89 e5             	mov    rbp,rsp
   140003314:	48 83 ec 10          	sub    rsp,0x10
   140003318:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000331c:	48 8d 05 6d 5e 00 00 	lea    rax,[rip+0x5e6d]        # 140009190 <handler>
   140003323:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003327:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000332b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000332f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003333:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003337:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000333a:	48 89 d0             	mov    rax,rdx
   14000333d:	48 83 c4 10          	add    rsp,0x10
   140003341:	5d                   	pop    rbp
   140003342:	c3                   	ret

0000000140003343 <_get_invalid_parameter_handler>:
   140003343:	55                   	push   rbp
   140003344:	48 89 e5             	mov    rbp,rsp
   140003347:	48 8b 05 42 5e 00 00 	mov    rax,QWORD PTR [rip+0x5e42]        # 140009190 <handler>
   14000334e:	5d                   	pop    rbp
   14000334f:	c3                   	ret

0000000140003350 <_configthreadlocale>:
   140003350:	55                   	push   rbp
   140003351:	48 89 e5             	mov    rbp,rsp
   140003354:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003357:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000335b:	75 07                	jne    140003364 <_configthreadlocale+0x14>
   14000335d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140003362:	eb 05                	jmp    140003369 <_configthreadlocale+0x19>
   140003364:	b8 02 00 00 00       	mov    eax,0x2
   140003369:	5d                   	pop    rbp
   14000336a:	c3                   	ret
   14000336b:	90                   	nop
   14000336c:	90                   	nop
   14000336d:	90                   	nop
   14000336e:	90                   	nop
   14000336f:	90                   	nop

0000000140003370 <__acrt_iob_func>:
   140003370:	55                   	push   rbp
   140003371:	48 89 e5             	mov    rbp,rsp
   140003374:	48 83 ec 20          	sub    rsp,0x20
   140003378:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000337b:	e8 30 00 00 00       	call   1400033b0 <__iob_func>
   140003380:	48 89 c1             	mov    rcx,rax
   140003383:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003386:	48 89 d0             	mov    rax,rdx
   140003389:	48 01 c0             	add    rax,rax
   14000338c:	48 01 d0             	add    rax,rdx
   14000338f:	48 c1 e0 04          	shl    rax,0x4
   140003393:	48 01 c8             	add    rax,rcx
   140003396:	48 83 c4 20          	add    rsp,0x20
   14000339a:	5d                   	pop    rbp
   14000339b:	c3                   	ret
   14000339c:	90                   	nop
   14000339d:	90                   	nop
   14000339e:	90                   	nop
   14000339f:	90                   	nop

00000001400033a0 <__C_specific_handler>:
   1400033a0:	ff 25 62 6e 00 00    	jmp    QWORD PTR [rip+0x6e62]        # 14000a208 <__imp___C_specific_handler>
   1400033a6:	90                   	nop
   1400033a7:	90                   	nop

00000001400033a8 <__getmainargs>:
   1400033a8:	ff 25 62 6e 00 00    	jmp    QWORD PTR [rip+0x6e62]        # 14000a210 <__imp___getmainargs>
   1400033ae:	90                   	nop
   1400033af:	90                   	nop

00000001400033b0 <__iob_func>:
   1400033b0:	ff 25 6a 6e 00 00    	jmp    QWORD PTR [rip+0x6e6a]        # 14000a220 <__imp___iob_func>
   1400033b6:	90                   	nop
   1400033b7:	90                   	nop

00000001400033b8 <__set_app_type>:
   1400033b8:	ff 25 6a 6e 00 00    	jmp    QWORD PTR [rip+0x6e6a]        # 14000a228 <__imp___set_app_type>
   1400033be:	90                   	nop
   1400033bf:	90                   	nop

00000001400033c0 <__setusermatherr>:
   1400033c0:	ff 25 6a 6e 00 00    	jmp    QWORD PTR [rip+0x6e6a]        # 14000a230 <__imp___setusermatherr>
   1400033c6:	90                   	nop
   1400033c7:	90                   	nop

00000001400033c8 <_amsg_exit>:
   1400033c8:	ff 25 6a 6e 00 00    	jmp    QWORD PTR [rip+0x6e6a]        # 14000a238 <__imp__amsg_exit>
   1400033ce:	90                   	nop
   1400033cf:	90                   	nop

00000001400033d0 <_cexit>:
   1400033d0:	ff 25 6a 6e 00 00    	jmp    QWORD PTR [rip+0x6e6a]        # 14000a240 <__imp__cexit>
   1400033d6:	90                   	nop
   1400033d7:	90                   	nop

00000001400033d8 <_initterm>:
   1400033d8:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a258 <__imp__initterm>
   1400033de:	90                   	nop
   1400033df:	90                   	nop

00000001400033e0 <_crt_atexit>:
   1400033e0:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a260 <__imp__crt_atexit>
   1400033e6:	90                   	nop
   1400033e7:	90                   	nop

00000001400033e8 <abort>:
   1400033e8:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a268 <__imp_abort>
   1400033ee:	90                   	nop
   1400033ef:	90                   	nop

00000001400033f0 <calloc>:
   1400033f0:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a270 <__imp_calloc>
   1400033f6:	90                   	nop
   1400033f7:	90                   	nop

00000001400033f8 <exit>:
   1400033f8:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a278 <__imp_exit>
   1400033fe:	90                   	nop
   1400033ff:	90                   	nop

0000000140003400 <fflush>:
   140003400:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a280 <__imp_fflush>
   140003406:	90                   	nop
   140003407:	90                   	nop

0000000140003408 <fprintf>:
   140003408:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a288 <__imp_fprintf>
   14000340e:	90                   	nop
   14000340f:	90                   	nop

0000000140003410 <free>:
   140003410:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a290 <__imp_free>
   140003416:	90                   	nop
   140003417:	90                   	nop

0000000140003418 <malloc>:
   140003418:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a298 <__imp_malloc>
   14000341e:	90                   	nop
   14000341f:	90                   	nop

0000000140003420 <memcpy>:
   140003420:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a2a0 <__imp_memcpy>
   140003426:	90                   	nop
   140003427:	90                   	nop

0000000140003428 <memset>:
   140003428:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a2a8 <__imp_memset>
   14000342e:	90                   	nop
   14000342f:	90                   	nop

0000000140003430 <setvbuf>:
   140003430:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a2b0 <__imp_setvbuf>
   140003436:	90                   	nop
   140003437:	90                   	nop

0000000140003438 <signal>:
   140003438:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a2b8 <__imp_signal>
   14000343e:	90                   	nop
   14000343f:	90                   	nop

0000000140003440 <strlen>:
   140003440:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a2c0 <__imp_strlen>
   140003446:	90                   	nop
   140003447:	90                   	nop

0000000140003448 <strncmp>:
   140003448:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a2c8 <__imp_strncmp>
   14000344e:	90                   	nop
   14000344f:	90                   	nop

0000000140003450 <vfprintf>:
   140003450:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a2d0 <__imp_vfprintf>
   140003456:	90                   	nop
   140003457:	90                   	nop
   140003458:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000345f:	00 

0000000140003460 <VirtualQuery>:
   140003460:	ff 25 92 6d 00 00    	jmp    QWORD PTR [rip+0x6d92]        # 14000a1f8 <__imp_VirtualQuery>
   140003466:	90                   	nop
   140003467:	90                   	nop

0000000140003468 <VirtualProtect>:
   140003468:	ff 25 82 6d 00 00    	jmp    QWORD PTR [rip+0x6d82]        # 14000a1f0 <__imp_VirtualProtect>
   14000346e:	90                   	nop
   14000346f:	90                   	nop

0000000140003470 <TlsGetValue>:
   140003470:	ff 25 72 6d 00 00    	jmp    QWORD PTR [rip+0x6d72]        # 14000a1e8 <__imp_TlsGetValue>
   140003476:	90                   	nop
   140003477:	90                   	nop

0000000140003478 <Sleep>:
   140003478:	ff 25 62 6d 00 00    	jmp    QWORD PTR [rip+0x6d62]        # 14000a1e0 <__imp_Sleep>
   14000347e:	90                   	nop
   14000347f:	90                   	nop

0000000140003480 <SetUnhandledExceptionFilter>:
   140003480:	ff 25 52 6d 00 00    	jmp    QWORD PTR [rip+0x6d52]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   140003486:	90                   	nop
   140003487:	90                   	nop

0000000140003488 <LoadLibraryA>:
   140003488:	ff 25 42 6d 00 00    	jmp    QWORD PTR [rip+0x6d42]        # 14000a1d0 <__imp_LoadLibraryA>
   14000348e:	90                   	nop
   14000348f:	90                   	nop

0000000140003490 <LeaveCriticalSection>:
   140003490:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140003496:	90                   	nop
   140003497:	90                   	nop

0000000140003498 <InitializeCriticalSection>:
   140003498:	ff 25 22 6d 00 00    	jmp    QWORD PTR [rip+0x6d22]        # 14000a1c0 <__imp_InitializeCriticalSection>
   14000349e:	90                   	nop
   14000349f:	90                   	nop

00000001400034a0 <GetProcAddress>:
   1400034a0:	ff 25 12 6d 00 00    	jmp    QWORD PTR [rip+0x6d12]        # 14000a1b8 <__imp_GetProcAddress>
   1400034a6:	90                   	nop
   1400034a7:	90                   	nop

00000001400034a8 <GetModuleHandleA>:
   1400034a8:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 14000a1b0 <__imp_GetModuleHandleA>
   1400034ae:	90                   	nop
   1400034af:	90                   	nop

00000001400034b0 <GetLastError>:
   1400034b0:	ff 25 f2 6c 00 00    	jmp    QWORD PTR [rip+0x6cf2]        # 14000a1a8 <__imp_GetLastError>
   1400034b6:	90                   	nop
   1400034b7:	90                   	nop

00000001400034b8 <FreeLibrary>:
   1400034b8:	ff 25 e2 6c 00 00    	jmp    QWORD PTR [rip+0x6ce2]        # 14000a1a0 <__imp_FreeLibrary>
   1400034be:	90                   	nop
   1400034bf:	90                   	nop

00000001400034c0 <EnterCriticalSection>:
   1400034c0:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 14000a198 <__imp_EnterCriticalSection>
   1400034c6:	90                   	nop
   1400034c7:	90                   	nop

00000001400034c8 <DeleteCriticalSection>:
   1400034c8:	ff 25 c2 6c 00 00    	jmp    QWORD PTR [rip+0x6cc2]        # 14000a190 <__IAT_start__>
   1400034ce:	90                   	nop
   1400034cf:	90                   	nop

00000001400034d0 <register_frame_ctor>:
   1400034d0:	e9 9b e1 ff ff       	jmp    140001670 <__gcc_register_frame>
   1400034d5:	90                   	nop
   1400034d6:	90                   	nop
   1400034d7:	90                   	nop
   1400034d8:	90                   	nop
   1400034d9:	90                   	nop
   1400034da:	90                   	nop
   1400034db:	90                   	nop
   1400034dc:	90                   	nop
   1400034dd:	90                   	nop
   1400034de:	90                   	nop
   1400034df:	90                   	nop
