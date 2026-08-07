
C:\Users\Administrator\Desktop\BinMind\round2\samples\heap_overflow\cve_2016_10190_ffmpeg\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 d7 22 00 00       	call   140003300 <fflush>
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
   14000113b:	e8 88 21 00 00       	call   1400032c8 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 08 21 00 00       	call   140003270 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 af 21 00 00       	call   140003330 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 4f 21 00 00       	call   1400032e8 <abort>
   140001199:	e8 d2 11 00 00       	call   140002370 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 29 90 00 00 	mov    rax,QWORD PTR [rip+0x9029]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 46 20 00 00       	call   140003210 <_set_invalid_parameter_handler>
   1400011ca:	e8 b1 1a 00 00       	call   140002c80 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 c7 20 00 00       	call   1400032b8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 bb 20 00 00       	call   1400032b8 <__set_app_type>
   1400011fd:	e8 de 1f 00 00       	call   1400031e0 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 de 1f 00 00       	call   1400031f0 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 2e 07 00 00       	call   140001950 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 93 20 00 00       	call   1400032c8 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 38 12 00 00       	call   14000248a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 e6 1f 00 00       	call   140003250 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 00 1f 00 00       	call   140003180 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 3a 20 00 00       	call   1400032c8 <_amsg_exit>
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
   1400012cb:	e8 d8 1f 00 00       	call   1400032a8 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 e5 1f 00 00       	call   1400032c8 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 be 1f 00 00       	call   1400032c8 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 b8 1f 00 00       	call   1400032d8 <_initterm>
   140001320:	e8 02 06 00 00       	call   140001927 <__main>
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
   14000138d:	e8 6e 1e 00 00       	call   140003200 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 31 04 00 00       	call   1400017eb <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 27 1f 00 00       	call   1400032f8 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 f0 1e 00 00       	call   1400032d0 <_cexit>
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
   140001511:	e8 02 1e 00 00       	call   140003318 <malloc>
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
   14000155c:	e8 df 1d 00 00       	call   140003340 <strlen>
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
   140001585:	e8 8e 1d 00 00       	call   140003318 <malloc>
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
   1400015e8:	e8 33 1d 00 00       	call   140003320 <memcpy>
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
   140001642:	e8 99 1c 00 00       	call   1400032e0 <_crt_atexit>
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

0000000140001760 <read_segment>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 20          	sub    rsp,0x20
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001770:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001774:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140001777:	0f b6 c0             	movzx  eax,al
   14000177a:	c1 e0 18             	shl    eax,0x18
   14000177d:	89 c2                	mov    edx,eax
   14000177f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001783:	48 83 c0 01          	add    rax,0x1
   140001787:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000178a:	0f b6 c0             	movzx  eax,al
   14000178d:	c1 e0 10             	shl    eax,0x10
   140001790:	09 c2                	or     edx,eax
   140001792:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001796:	48 83 c0 02          	add    rax,0x2
   14000179a:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000179d:	0f b6 c0             	movzx  eax,al
   1400017a0:	c1 e0 08             	shl    eax,0x8
   1400017a3:	09 c2                	or     edx,eax
   1400017a5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400017a9:	48 83 c0 03          	add    rax,0x3
   1400017ad:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400017b0:	0f b6 c0             	movzx  eax,al
   1400017b3:	09 d0                	or     eax,edx
   1400017b5:	89 c2                	mov    edx,eax
   1400017b7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017bb:	89 10                	mov    DWORD PTR [rax],edx
   1400017bd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017c1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400017c3:	89 c1                	mov    ecx,eax
   1400017c5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400017c9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400017cd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017d1:	48 83 c0 04          	add    rax,0x4
   1400017d5:	49 89 c8             	mov    r8,rcx
   1400017d8:	48 89 c1             	mov    rcx,rax
   1400017db:	e8 40 1b 00 00       	call   140003320 <memcpy>
   1400017e0:	b8 00 00 00 00       	mov    eax,0x0
   1400017e5:	48 83 c4 20          	add    rsp,0x20
   1400017e9:	5d                   	pop    rbp
   1400017ea:	c3                   	ret

00000001400017eb <main>:
   1400017eb:	55                   	push   rbp
   1400017ec:	48 89 e5             	mov    rbp,rsp
   1400017ef:	48 83 ec 70          	sub    rsp,0x70
   1400017f3:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400017f6:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400017fa:	e8 28 01 00 00       	call   140001927 <__main>
   1400017ff:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140001803:	41 b8 40 00 00 00    	mov    r8d,0x40
   140001809:	ba 00 00 00 00       	mov    edx,0x0
   14000180e:	48 89 c1             	mov    rcx,rax
   140001811:	e8 12 1b 00 00       	call   140003328 <memset>
   140001816:	c6 45 b0 00          	mov    BYTE PTR [rbp-0x50],0x0
   14000181a:	c6 45 b1 00          	mov    BYTE PTR [rbp-0x4f],0x0
   14000181e:	c6 45 b2 00          	mov    BYTE PTR [rbp-0x4e],0x0
   140001822:	c6 45 b3 80          	mov    BYTE PTR [rbp-0x4d],0x80
   140001826:	b9 24 00 00 00       	mov    ecx,0x24
   14000182b:	e8 e8 1a 00 00       	call   140003318 <malloc>
   140001830:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001834:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140001839:	75 07                	jne    140001842 <main+0x57>
   14000183b:	b8 01 00 00 00       	mov    eax,0x1
   140001840:	eb 21                	jmp    140001863 <main+0x78>
   140001842:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   140001846:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000184a:	48 89 c1             	mov    rcx,rax
   14000184d:	e8 0e ff ff ff       	call   140001760 <read_segment>
   140001852:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001856:	48 89 c1             	mov    rcx,rax
   140001859:	e8 b2 1a 00 00       	call   140003310 <free>
   14000185e:	b8 00 00 00 00       	mov    eax,0x0
   140001863:	48 83 c4 70          	add    rsp,0x70
   140001867:	5d                   	pop    rbp
   140001868:	c3                   	ret
   140001869:	90                   	nop
   14000186a:	90                   	nop
   14000186b:	90                   	nop
   14000186c:	90                   	nop
   14000186d:	90                   	nop
   14000186e:	90                   	nop
   14000186f:	90                   	nop

0000000140001870 <__do_global_dtors>:
   140001870:	55                   	push   rbp
   140001871:	48 89 e5             	mov    rbp,rsp
   140001874:	48 83 ec 20          	sub    rsp,0x20
   140001878:	eb 1e                	jmp    140001898 <__do_global_dtors+0x28>
   14000187a:	48 8b 05 8f 27 00 00 	mov    rax,QWORD PTR [rip+0x278f]        # 140004010 <p.0>
   140001881:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001884:	ff d0                	call   rax
   140001886:	48 8b 05 83 27 00 00 	mov    rax,QWORD PTR [rip+0x2783]        # 140004010 <p.0>
   14000188d:	48 83 c0 08          	add    rax,0x8
   140001891:	48 89 05 78 27 00 00 	mov    QWORD PTR [rip+0x2778],rax        # 140004010 <p.0>
   140001898:	48 8b 05 71 27 00 00 	mov    rax,QWORD PTR [rip+0x2771]        # 140004010 <p.0>
   14000189f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018a2:	48 85 c0             	test   rax,rax
   1400018a5:	75 d3                	jne    14000187a <__do_global_dtors+0xa>
   1400018a7:	90                   	nop
   1400018a8:	90                   	nop
   1400018a9:	48 83 c4 20          	add    rsp,0x20
   1400018ad:	5d                   	pop    rbp
   1400018ae:	c3                   	ret

00000001400018af <__do_global_ctors>:
   1400018af:	55                   	push   rbp
   1400018b0:	48 89 e5             	mov    rbp,rsp
   1400018b3:	48 83 ec 30          	sub    rsp,0x30
   1400018b7:	48 8b 05 92 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a92]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018be:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018c1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400018c4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400018c8:	75 25                	jne    1400018ef <__do_global_ctors+0x40>
   1400018ca:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400018d1:	eb 04                	jmp    1400018d7 <__do_global_ctors+0x28>
   1400018d3:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400018d7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018da:	8d 50 01             	lea    edx,[rax+0x1]
   1400018dd:	48 8b 05 6c 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a6c]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018e4:	89 d2                	mov    edx,edx
   1400018e6:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018ea:	48 85 c0             	test   rax,rax
   1400018ed:	75 e4                	jne    1400018d3 <__do_global_ctors+0x24>
   1400018ef:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018f2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400018f5:	eb 14                	jmp    14000190b <__do_global_ctors+0x5c>
   1400018f7:	48 8b 05 52 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a52]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018fe:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001901:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001905:	ff d0                	call   rax
   140001907:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000190b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000190f:	75 e6                	jne    1400018f7 <__do_global_ctors+0x48>
   140001911:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001870 <__do_global_dtors>
   140001918:	48 89 c1             	mov    rcx,rax
   14000191b:	e8 0f fd ff ff       	call   14000162f <atexit>
   140001920:	90                   	nop
   140001921:	48 83 c4 30          	add    rsp,0x30
   140001925:	5d                   	pop    rbp
   140001926:	c3                   	ret

0000000140001927 <__main>:
   140001927:	55                   	push   rbp
   140001928:	48 89 e5             	mov    rbp,rsp
   14000192b:	48 83 ec 20          	sub    rsp,0x20
   14000192f:	8b 05 4b 77 00 00    	mov    eax,DWORD PTR [rip+0x774b]        # 140009080 <initialized>
   140001935:	85 c0                	test   eax,eax
   140001937:	75 0f                	jne    140001948 <__main+0x21>
   140001939:	c7 05 3d 77 00 00 01 	mov    DWORD PTR [rip+0x773d],0x1        # 140009080 <initialized>
   140001940:	00 00 00 
   140001943:	e8 67 ff ff ff       	call   1400018af <__do_global_ctors>
   140001948:	90                   	nop
   140001949:	48 83 c4 20          	add    rsp,0x20
   14000194d:	5d                   	pop    rbp
   14000194e:	c3                   	ret
   14000194f:	90                   	nop

0000000140001950 <_setargv>:
   140001950:	55                   	push   rbp
   140001951:	48 89 e5             	mov    rbp,rsp
   140001954:	b8 00 00 00 00       	mov    eax,0x0
   140001959:	5d                   	pop    rbp
   14000195a:	c3                   	ret
   14000195b:	90                   	nop
   14000195c:	90                   	nop
   14000195d:	90                   	nop
   14000195e:	90                   	nop
   14000195f:	90                   	nop

0000000140001960 <__dyn_tls_init>:
   140001960:	55                   	push   rbp
   140001961:	48 89 e5             	mov    rbp,rsp
   140001964:	48 83 ec 30          	sub    rsp,0x30
   140001968:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000196c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000196f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001973:	48 8b 05 b6 39 00 00 	mov    rax,QWORD PTR [rip+0x39b6]        # 140005330 <.refptr._CRT_MT>
   14000197a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000197c:	83 f8 02             	cmp    eax,0x2
   14000197f:	74 0d                	je     14000198e <__dyn_tls_init+0x2e>
   140001981:	48 8b 05 a8 39 00 00 	mov    rax,QWORD PTR [rip+0x39a8]        # 140005330 <.refptr._CRT_MT>
   140001988:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000198e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001992:	74 1e                	je     1400019b2 <__dyn_tls_init+0x52>
   140001994:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001998:	75 5b                	jne    1400019f5 <__dyn_tls_init+0x95>
   14000199a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000199e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019a1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019a5:	49 89 c8             	mov    r8,rcx
   1400019a8:	48 89 c1             	mov    rcx,rax
   1400019ab:	e8 d1 11 00 00       	call   140002b81 <__mingw_TLScallback>
   1400019b0:	eb 43                	jmp    1400019f5 <__dyn_tls_init+0x95>
   1400019b2:	48 8d 05 df 3c 00 00 	lea    rax,[rip+0x3cdf]        # 140005698 <___crt_xd_start__>
   1400019b9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400019bd:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019c2:	eb 22                	jmp    1400019e6 <__dyn_tls_init+0x86>
   1400019c4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400019c8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400019cc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019d0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019d3:	48 85 c0             	test   rax,rax
   1400019d6:	74 09                	je     1400019e1 <__dyn_tls_init+0x81>
   1400019d8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019dc:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019df:	ff d0                	call   rax
   1400019e1:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019e6:	48 8d 05 b3 3c 00 00 	lea    rax,[rip+0x3cb3]        # 1400056a0 <__xd_z>
   1400019ed:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   1400019f1:	75 d1                	jne    1400019c4 <__dyn_tls_init+0x64>
   1400019f3:	eb 01                	jmp    1400019f6 <__dyn_tls_init+0x96>
   1400019f5:	90                   	nop
   1400019f6:	48 83 c4 30          	add    rsp,0x30
   1400019fa:	5d                   	pop    rbp
   1400019fb:	c3                   	ret

00000001400019fc <__tlregdtor>:
   1400019fc:	55                   	push   rbp
   1400019fd:	48 89 e5             	mov    rbp,rsp
   140001a00:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a04:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001a09:	75 07                	jne    140001a12 <__tlregdtor+0x16>
   140001a0b:	b8 00 00 00 00       	mov    eax,0x0
   140001a10:	eb 05                	jmp    140001a17 <__tlregdtor+0x1b>
   140001a12:	b8 00 00 00 00       	mov    eax,0x0
   140001a17:	5d                   	pop    rbp
   140001a18:	c3                   	ret

0000000140001a19 <__dyn_tls_dtor>:
   140001a19:	55                   	push   rbp
   140001a1a:	48 89 e5             	mov    rbp,rsp
   140001a1d:	48 83 ec 20          	sub    rsp,0x20
   140001a21:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a25:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a28:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a2c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a30:	74 06                	je     140001a38 <__dyn_tls_dtor+0x1f>
   140001a32:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a36:	75 18                	jne    140001a50 <__dyn_tls_dtor+0x37>
   140001a38:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a3c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a3f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a43:	49 89 c8             	mov    r8,rcx
   140001a46:	48 89 c1             	mov    rcx,rax
   140001a49:	e8 33 11 00 00       	call   140002b81 <__mingw_TLScallback>
   140001a4e:	eb 01                	jmp    140001a51 <__dyn_tls_dtor+0x38>
   140001a50:	90                   	nop
   140001a51:	48 83 c4 20          	add    rsp,0x20
   140001a55:	5d                   	pop    rbp
   140001a56:	c3                   	ret
   140001a57:	90                   	nop
   140001a58:	90                   	nop
   140001a59:	90                   	nop
   140001a5a:	90                   	nop
   140001a5b:	90                   	nop
   140001a5c:	90                   	nop
   140001a5d:	90                   	nop
   140001a5e:	90                   	nop
   140001a5f:	90                   	nop

0000000140001a60 <_matherr>:
   140001a60:	55                   	push   rbp
   140001a61:	53                   	push   rbx
   140001a62:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a69:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a6e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a72:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a76:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a7b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a7f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a83:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a85:	83 f8 06             	cmp    eax,0x6
   140001a88:	74 56                	je     140001ae0 <_matherr+0x80>
   140001a8a:	83 f8 06             	cmp    eax,0x6
   140001a8d:	7f 78                	jg     140001b07 <_matherr+0xa7>
   140001a8f:	83 f8 05             	cmp    eax,0x5
   140001a92:	74 59                	je     140001aed <_matherr+0x8d>
   140001a94:	83 f8 05             	cmp    eax,0x5
   140001a97:	7f 6e                	jg     140001b07 <_matherr+0xa7>
   140001a99:	83 f8 04             	cmp    eax,0x4
   140001a9c:	74 5c                	je     140001afa <_matherr+0x9a>
   140001a9e:	83 f8 04             	cmp    eax,0x4
   140001aa1:	7f 64                	jg     140001b07 <_matherr+0xa7>
   140001aa3:	83 f8 03             	cmp    eax,0x3
   140001aa6:	74 2b                	je     140001ad3 <_matherr+0x73>
   140001aa8:	83 f8 03             	cmp    eax,0x3
   140001aab:	7f 5a                	jg     140001b07 <_matherr+0xa7>
   140001aad:	83 f8 01             	cmp    eax,0x1
   140001ab0:	74 07                	je     140001ab9 <_matherr+0x59>
   140001ab2:	83 f8 02             	cmp    eax,0x2
   140001ab5:	74 0f                	je     140001ac6 <_matherr+0x66>
   140001ab7:	eb 4e                	jmp    140001b07 <_matherr+0xa7>
   140001ab9:	48 8d 05 e0 35 00 00 	lea    rax,[rip+0x35e0]        # 1400050a0 <.rdata>
   140001ac0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ac4:	eb 4d                	jmp    140001b13 <_matherr+0xb3>
   140001ac6:	48 8d 05 f2 35 00 00 	lea    rax,[rip+0x35f2]        # 1400050bf <.rdata+0x1f>
   140001acd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ad1:	eb 40                	jmp    140001b13 <_matherr+0xb3>
   140001ad3:	48 8d 05 06 36 00 00 	lea    rax,[rip+0x3606]        # 1400050e0 <.rdata+0x40>
   140001ada:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ade:	eb 33                	jmp    140001b13 <_matherr+0xb3>
   140001ae0:	48 8d 05 19 36 00 00 	lea    rax,[rip+0x3619]        # 140005100 <.rdata+0x60>
   140001ae7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001aeb:	eb 26                	jmp    140001b13 <_matherr+0xb3>
   140001aed:	48 8d 05 34 36 00 00 	lea    rax,[rip+0x3634]        # 140005128 <.rdata+0x88>
   140001af4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001af8:	eb 19                	jmp    140001b13 <_matherr+0xb3>
   140001afa:	48 8d 05 4f 36 00 00 	lea    rax,[rip+0x364f]        # 140005150 <.rdata+0xb0>
   140001b01:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b05:	eb 0c                	jmp    140001b13 <_matherr+0xb3>
   140001b07:	48 8d 05 78 36 00 00 	lea    rax,[rip+0x3678]        # 140005186 <.rdata+0xe6>
   140001b0e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b12:	90                   	nop
   140001b13:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b17:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b1d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b21:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b26:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b2a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b2f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b33:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b37:	b9 02 00 00 00       	mov    ecx,0x2
   140001b3c:	e8 2f 17 00 00       	call   140003270 <__acrt_iob_func>
   140001b41:	48 89 c1             	mov    rcx,rax
   140001b44:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b48:	48 8d 05 49 36 00 00 	lea    rax,[rip+0x3649]        # 140005198 <.rdata+0xf8>
   140001b4f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b56:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b5c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b62:	49 89 d9             	mov    r9,rbx
   140001b65:	49 89 d0             	mov    r8,rdx
   140001b68:	48 89 c2             	mov    rdx,rax
   140001b6b:	e8 98 17 00 00       	call   140003308 <fprintf>
   140001b70:	b8 00 00 00 00       	mov    eax,0x0
   140001b75:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b79:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b7d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b82:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b89:	5b                   	pop    rbx
   140001b8a:	5d                   	pop    rbp
   140001b8b:	c3                   	ret
   140001b8c:	90                   	nop
   140001b8d:	90                   	nop
   140001b8e:	90                   	nop
   140001b8f:	90                   	nop

0000000140001b90 <__report_error>:
   140001b90:	55                   	push   rbp
   140001b91:	53                   	push   rbx
   140001b92:	48 83 ec 38          	sub    rsp,0x38
   140001b96:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b9b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b9f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001ba3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001ba7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001bab:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001baf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bb3:	b9 02 00 00 00       	mov    ecx,0x2
   140001bb8:	e8 b3 16 00 00       	call   140003270 <__acrt_iob_func>
   140001bbd:	48 89 c1             	mov    rcx,rax
   140001bc0:	48 8d 05 09 36 00 00 	lea    rax,[rip+0x3609]        # 1400051d0 <.rdata>
   140001bc7:	48 89 c2             	mov    rdx,rax
   140001bca:	e8 39 17 00 00       	call   140003308 <fprintf>
   140001bcf:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001bd3:	b9 02 00 00 00       	mov    ecx,0x2
   140001bd8:	e8 93 16 00 00       	call   140003270 <__acrt_iob_func>
   140001bdd:	48 89 c1             	mov    rcx,rax
   140001be0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001be4:	49 89 d8             	mov    r8,rbx
   140001be7:	48 89 c2             	mov    rdx,rax
   140001bea:	e8 61 17 00 00       	call   140003350 <vfprintf>
   140001bef:	e8 f4 16 00 00       	call   1400032e8 <abort>
   140001bf4:	90                   	nop

0000000140001bf5 <mark_section_writable>:
   140001bf5:	55                   	push   rbp
   140001bf6:	48 89 e5             	mov    rbp,rsp
   140001bf9:	48 83 ec 60          	sub    rsp,0x60
   140001bfd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001c01:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001c08:	e9 82 00 00 00       	jmp    140001c8f <mark_section_writable+0x9a>
   140001c0d:	48 8b 0d cc 74 00 00 	mov    rcx,QWORD PTR [rip+0x74cc]        # 1400090e0 <the_secs>
   140001c14:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c17:	48 63 d0             	movsxd rdx,eax
   140001c1a:	48 89 d0             	mov    rax,rdx
   140001c1d:	48 c1 e0 02          	shl    rax,0x2
   140001c21:	48 01 d0             	add    rax,rdx
   140001c24:	48 c1 e0 03          	shl    rax,0x3
   140001c28:	48 01 c8             	add    rax,rcx
   140001c2b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c2f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c33:	72 56                	jb     140001c8b <mark_section_writable+0x96>
   140001c35:	48 8b 0d a4 74 00 00 	mov    rcx,QWORD PTR [rip+0x74a4]        # 1400090e0 <the_secs>
   140001c3c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c3f:	48 63 d0             	movsxd rdx,eax
   140001c42:	48 89 d0             	mov    rax,rdx
   140001c45:	48 c1 e0 02          	shl    rax,0x2
   140001c49:	48 01 d0             	add    rax,rdx
   140001c4c:	48 c1 e0 03          	shl    rax,0x3
   140001c50:	48 01 c8             	add    rax,rcx
   140001c53:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c57:	4c 8b 05 82 74 00 00 	mov    r8,QWORD PTR [rip+0x7482]        # 1400090e0 <the_secs>
   140001c5e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c61:	48 63 d0             	movsxd rdx,eax
   140001c64:	48 89 d0             	mov    rax,rdx
   140001c67:	48 c1 e0 02          	shl    rax,0x2
   140001c6b:	48 01 d0             	add    rax,rdx
   140001c6e:	48 c1 e0 03          	shl    rax,0x3
   140001c72:	4c 01 c0             	add    rax,r8
   140001c75:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c79:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c7c:	89 c0                	mov    eax,eax
   140001c7e:	48 01 c8             	add    rax,rcx
   140001c81:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c85:	0f 82 41 02 00 00    	jb     140001ecc <mark_section_writable+0x2d7>
   140001c8b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c8f:	8b 05 53 74 00 00    	mov    eax,DWORD PTR [rip+0x7453]        # 1400090e8 <maxSections>
   140001c95:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c98:	0f 8c 6f ff ff ff    	jl     140001c0d <mark_section_writable+0x18>
   140001c9e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001ca2:	48 89 c1             	mov    rcx,rax
   140001ca5:	e8 c1 11 00 00       	call   140002e6b <__mingw_GetSectionForAddress>
   140001caa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001cae:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001cb3:	75 13                	jne    140001cc8 <mark_section_writable+0xd3>
   140001cb5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001cb9:	48 8d 0d 30 35 00 00 	lea    rcx,[rip+0x3530]        # 1400051f0 <.rdata+0x20>
   140001cc0:	48 89 c2             	mov    rdx,rax
   140001cc3:	e8 c8 fe ff ff       	call   140001b90 <__report_error>
   140001cc8:	48 8b 0d 11 74 00 00 	mov    rcx,QWORD PTR [rip+0x7411]        # 1400090e0 <the_secs>
   140001ccf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cd2:	48 63 d0             	movsxd rdx,eax
   140001cd5:	48 89 d0             	mov    rax,rdx
   140001cd8:	48 c1 e0 02          	shl    rax,0x2
   140001cdc:	48 01 d0             	add    rax,rdx
   140001cdf:	48 c1 e0 03          	shl    rax,0x3
   140001ce3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001ce7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001ceb:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001cef:	48 8b 0d ea 73 00 00 	mov    rcx,QWORD PTR [rip+0x73ea]        # 1400090e0 <the_secs>
   140001cf6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cf9:	48 63 d0             	movsxd rdx,eax
   140001cfc:	48 89 d0             	mov    rax,rdx
   140001cff:	48 c1 e0 02          	shl    rax,0x2
   140001d03:	48 01 d0             	add    rax,rdx
   140001d06:	48 c1 e0 03          	shl    rax,0x3
   140001d0a:	48 01 c8             	add    rax,rcx
   140001d0d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d13:	e8 9f 12 00 00       	call   140002fb7 <_GetPEImageBase>
   140001d18:	48 89 c1             	mov    rcx,rax
   140001d1b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d1f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d22:	41 89 c1             	mov    r9d,eax
   140001d25:	4c 8b 05 b4 73 00 00 	mov    r8,QWORD PTR [rip+0x73b4]        # 1400090e0 <the_secs>
   140001d2c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d2f:	48 63 d0             	movsxd rdx,eax
   140001d32:	48 89 d0             	mov    rax,rdx
   140001d35:	48 c1 e0 02          	shl    rax,0x2
   140001d39:	48 01 d0             	add    rax,rdx
   140001d3c:	48 c1 e0 03          	shl    rax,0x3
   140001d40:	4c 01 c0             	add    rax,r8
   140001d43:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d47:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d4b:	48 8b 0d 8e 73 00 00 	mov    rcx,QWORD PTR [rip+0x738e]        # 1400090e0 <the_secs>
   140001d52:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d55:	48 63 d0             	movsxd rdx,eax
   140001d58:	48 89 d0             	mov    rax,rdx
   140001d5b:	48 c1 e0 02          	shl    rax,0x2
   140001d5f:	48 01 d0             	add    rax,rdx
   140001d62:	48 c1 e0 03          	shl    rax,0x3
   140001d66:	48 01 c8             	add    rax,rcx
   140001d69:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d6d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d71:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d77:	48 89 c1             	mov    rcx,rax
   140001d7a:	48 8b 05 77 84 00 00 	mov    rax,QWORD PTR [rip+0x8477]        # 14000a1f8 <__imp_VirtualQuery>
   140001d81:	ff d0                	call   rax
   140001d83:	48 85 c0             	test   rax,rax
   140001d86:	75 3f                	jne    140001dc7 <mark_section_writable+0x1d2>
   140001d88:	48 8b 0d 51 73 00 00 	mov    rcx,QWORD PTR [rip+0x7351]        # 1400090e0 <the_secs>
   140001d8f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d92:	48 63 d0             	movsxd rdx,eax
   140001d95:	48 89 d0             	mov    rax,rdx
   140001d98:	48 c1 e0 02          	shl    rax,0x2
   140001d9c:	48 01 d0             	add    rax,rdx
   140001d9f:	48 c1 e0 03          	shl    rax,0x3
   140001da3:	48 01 c8             	add    rax,rcx
   140001da6:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001daa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001dae:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001db1:	89 c1                	mov    ecx,eax
   140001db3:	48 8d 05 56 34 00 00 	lea    rax,[rip+0x3456]        # 140005210 <.rdata+0x40>
   140001dba:	49 89 d0             	mov    r8,rdx
   140001dbd:	89 ca                	mov    edx,ecx
   140001dbf:	48 89 c1             	mov    rcx,rax
   140001dc2:	e8 c9 fd ff ff       	call   140001b90 <__report_error>
   140001dc7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dca:	83 f8 40             	cmp    eax,0x40
   140001dcd:	0f 84 e8 00 00 00    	je     140001ebb <mark_section_writable+0x2c6>
   140001dd3:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dd6:	83 f8 04             	cmp    eax,0x4
   140001dd9:	0f 84 dc 00 00 00    	je     140001ebb <mark_section_writable+0x2c6>
   140001ddf:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001de2:	3d 80 00 00 00       	cmp    eax,0x80
   140001de7:	0f 84 ce 00 00 00    	je     140001ebb <mark_section_writable+0x2c6>
   140001ded:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001df0:	83 f8 08             	cmp    eax,0x8
   140001df3:	0f 84 c2 00 00 00    	je     140001ebb <mark_section_writable+0x2c6>
   140001df9:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dfc:	83 f8 02             	cmp    eax,0x2
   140001dff:	75 09                	jne    140001e0a <mark_section_writable+0x215>
   140001e01:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001e08:	eb 07                	jmp    140001e11 <mark_section_writable+0x21c>
   140001e0a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e11:	48 8b 0d c8 72 00 00 	mov    rcx,QWORD PTR [rip+0x72c8]        # 1400090e0 <the_secs>
   140001e18:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e1b:	48 63 d0             	movsxd rdx,eax
   140001e1e:	48 89 d0             	mov    rax,rdx
   140001e21:	48 c1 e0 02          	shl    rax,0x2
   140001e25:	48 01 d0             	add    rax,rdx
   140001e28:	48 c1 e0 03          	shl    rax,0x3
   140001e2c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e30:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e34:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e38:	48 8b 0d a1 72 00 00 	mov    rcx,QWORD PTR [rip+0x72a1]        # 1400090e0 <the_secs>
   140001e3f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e42:	48 63 d0             	movsxd rdx,eax
   140001e45:	48 89 d0             	mov    rax,rdx
   140001e48:	48 c1 e0 02          	shl    rax,0x2
   140001e4c:	48 01 d0             	add    rax,rdx
   140001e4f:	48 c1 e0 03          	shl    rax,0x3
   140001e53:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e57:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e5b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e5f:	48 8b 0d 7a 72 00 00 	mov    rcx,QWORD PTR [rip+0x727a]        # 1400090e0 <the_secs>
   140001e66:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e69:	48 63 d0             	movsxd rdx,eax
   140001e6c:	48 89 d0             	mov    rax,rdx
   140001e6f:	48 c1 e0 02          	shl    rax,0x2
   140001e73:	48 01 d0             	add    rax,rdx
   140001e76:	48 c1 e0 03          	shl    rax,0x3
   140001e7a:	48 01 c8             	add    rax,rcx
   140001e7d:	49 89 c0             	mov    r8,rax
   140001e80:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e84:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e88:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e8b:	4d 89 c1             	mov    r9,r8
   140001e8e:	41 89 c8             	mov    r8d,ecx
   140001e91:	48 89 c1             	mov    rcx,rax
   140001e94:	48 8b 05 55 83 00 00 	mov    rax,QWORD PTR [rip+0x8355]        # 14000a1f0 <__imp_VirtualProtect>
   140001e9b:	ff d0                	call   rax
   140001e9d:	85 c0                	test   eax,eax
   140001e9f:	75 1a                	jne    140001ebb <mark_section_writable+0x2c6>
   140001ea1:	48 8b 05 00 83 00 00 	mov    rax,QWORD PTR [rip+0x8300]        # 14000a1a8 <__imp_GetLastError>
   140001ea8:	ff d0                	call   rax
   140001eaa:	89 c2                	mov    edx,eax
   140001eac:	48 8d 05 95 33 00 00 	lea    rax,[rip+0x3395]        # 140005248 <.rdata+0x78>
   140001eb3:	48 89 c1             	mov    rcx,rax
   140001eb6:	e8 d5 fc ff ff       	call   140001b90 <__report_error>
   140001ebb:	8b 05 27 72 00 00    	mov    eax,DWORD PTR [rip+0x7227]        # 1400090e8 <maxSections>
   140001ec1:	83 c0 01             	add    eax,0x1
   140001ec4:	89 05 1e 72 00 00    	mov    DWORD PTR [rip+0x721e],eax        # 1400090e8 <maxSections>
   140001eca:	eb 01                	jmp    140001ecd <mark_section_writable+0x2d8>
   140001ecc:	90                   	nop
   140001ecd:	48 83 c4 60          	add    rsp,0x60
   140001ed1:	5d                   	pop    rbp
   140001ed2:	c3                   	ret

0000000140001ed3 <restore_modified_sections>:
   140001ed3:	55                   	push   rbp
   140001ed4:	48 89 e5             	mov    rbp,rsp
   140001ed7:	48 83 ec 30          	sub    rsp,0x30
   140001edb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001ee2:	e9 ad 00 00 00       	jmp    140001f94 <restore_modified_sections+0xc1>
   140001ee7:	48 8b 0d f2 71 00 00 	mov    rcx,QWORD PTR [rip+0x71f2]        # 1400090e0 <the_secs>
   140001eee:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ef1:	48 63 d0             	movsxd rdx,eax
   140001ef4:	48 89 d0             	mov    rax,rdx
   140001ef7:	48 c1 e0 02          	shl    rax,0x2
   140001efb:	48 01 d0             	add    rax,rdx
   140001efe:	48 c1 e0 03          	shl    rax,0x3
   140001f02:	48 01 c8             	add    rax,rcx
   140001f05:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f07:	85 c0                	test   eax,eax
   140001f09:	0f 84 80 00 00 00    	je     140001f8f <restore_modified_sections+0xbc>
   140001f0f:	48 8b 0d ca 71 00 00 	mov    rcx,QWORD PTR [rip+0x71ca]        # 1400090e0 <the_secs>
   140001f16:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f19:	48 63 d0             	movsxd rdx,eax
   140001f1c:	48 89 d0             	mov    rax,rdx
   140001f1f:	48 c1 e0 02          	shl    rax,0x2
   140001f23:	48 01 d0             	add    rax,rdx
   140001f26:	48 c1 e0 03          	shl    rax,0x3
   140001f2a:	48 01 c8             	add    rax,rcx
   140001f2d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f30:	48 8b 0d a9 71 00 00 	mov    rcx,QWORD PTR [rip+0x71a9]        # 1400090e0 <the_secs>
   140001f37:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f3a:	48 63 d0             	movsxd rdx,eax
   140001f3d:	48 89 d0             	mov    rax,rdx
   140001f40:	48 c1 e0 02          	shl    rax,0x2
   140001f44:	48 01 d0             	add    rax,rdx
   140001f47:	48 c1 e0 03          	shl    rax,0x3
   140001f4b:	48 01 c8             	add    rax,rcx
   140001f4e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f52:	4c 8b 05 87 71 00 00 	mov    r8,QWORD PTR [rip+0x7187]        # 1400090e0 <the_secs>
   140001f59:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f5c:	48 63 d0             	movsxd rdx,eax
   140001f5f:	48 89 d0             	mov    rax,rdx
   140001f62:	48 c1 e0 02          	shl    rax,0x2
   140001f66:	48 01 d0             	add    rax,rdx
   140001f69:	48 c1 e0 03          	shl    rax,0x3
   140001f6d:	4c 01 c0             	add    rax,r8
   140001f70:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f74:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f78:	49 89 d1             	mov    r9,rdx
   140001f7b:	45 89 d0             	mov    r8d,r10d
   140001f7e:	48 89 ca             	mov    rdx,rcx
   140001f81:	48 89 c1             	mov    rcx,rax
   140001f84:	48 8b 05 65 82 00 00 	mov    rax,QWORD PTR [rip+0x8265]        # 14000a1f0 <__imp_VirtualProtect>
   140001f8b:	ff d0                	call   rax
   140001f8d:	eb 01                	jmp    140001f90 <restore_modified_sections+0xbd>
   140001f8f:	90                   	nop
   140001f90:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f94:	8b 05 4e 71 00 00    	mov    eax,DWORD PTR [rip+0x714e]        # 1400090e8 <maxSections>
   140001f9a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f9d:	0f 8c 44 ff ff ff    	jl     140001ee7 <restore_modified_sections+0x14>
   140001fa3:	90                   	nop
   140001fa4:	90                   	nop
   140001fa5:	48 83 c4 30          	add    rsp,0x30
   140001fa9:	5d                   	pop    rbp
   140001faa:	c3                   	ret

0000000140001fab <__write_memory>:
   140001fab:	55                   	push   rbp
   140001fac:	48 89 e5             	mov    rbp,rsp
   140001faf:	48 83 ec 20          	sub    rsp,0x20
   140001fb3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fb7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001fbb:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001fbf:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001fc4:	74 25                	je     140001feb <__write_memory+0x40>
   140001fc6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fca:	48 89 c1             	mov    rcx,rax
   140001fcd:	e8 23 fc ff ff       	call   140001bf5 <mark_section_writable>
   140001fd2:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001fd6:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001fda:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fde:	49 89 c8             	mov    r8,rcx
   140001fe1:	48 89 c1             	mov    rcx,rax
   140001fe4:	e8 37 13 00 00       	call   140003320 <memcpy>
   140001fe9:	eb 01                	jmp    140001fec <__write_memory+0x41>
   140001feb:	90                   	nop
   140001fec:	48 83 c4 20          	add    rsp,0x20
   140001ff0:	5d                   	pop    rbp
   140001ff1:	c3                   	ret

0000000140001ff2 <do_pseudo_reloc>:
   140001ff2:	55                   	push   rbp
   140001ff3:	48 89 e5             	mov    rbp,rsp
   140001ff6:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001ffa:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001ffe:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002002:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002006:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000200a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000200e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002012:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002016:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000201a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000201f:	0f 8e 44 03 00 00    	jle    140002369 <do_pseudo_reloc+0x377>
   140002025:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000202a:	7e 25                	jle    140002051 <do_pseudo_reloc+0x5f>
   14000202c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002030:	8b 00                	mov    eax,DWORD PTR [rax]
   140002032:	85 c0                	test   eax,eax
   140002034:	75 1b                	jne    140002051 <do_pseudo_reloc+0x5f>
   140002036:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000203a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000203d:	85 c0                	test   eax,eax
   14000203f:	75 10                	jne    140002051 <do_pseudo_reloc+0x5f>
   140002041:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002045:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002048:	85 c0                	test   eax,eax
   14000204a:	75 05                	jne    140002051 <do_pseudo_reloc+0x5f>
   14000204c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002051:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002055:	8b 00                	mov    eax,DWORD PTR [rax]
   140002057:	85 c0                	test   eax,eax
   140002059:	75 0b                	jne    140002066 <do_pseudo_reloc+0x74>
   14000205b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000205f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002062:	85 c0                	test   eax,eax
   140002064:	74 59                	je     1400020bf <do_pseudo_reloc+0xcd>
   140002066:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000206a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000206e:	eb 40                	jmp    1400020b0 <do_pseudo_reloc+0xbe>
   140002070:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002074:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002077:	89 c2                	mov    edx,eax
   140002079:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000207d:	48 01 d0             	add    rax,rdx
   140002080:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002084:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002088:	8b 10                	mov    edx,DWORD PTR [rax]
   14000208a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000208e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002090:	01 d0                	add    eax,edx
   140002092:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002095:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002099:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000209d:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400020a3:	48 89 c1             	mov    rcx,rax
   1400020a6:	e8 00 ff ff ff       	call   140001fab <__write_memory>
   1400020ab:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   1400020b0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020b4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400020b8:	72 b6                	jb     140002070 <do_pseudo_reloc+0x7e>
   1400020ba:	e9 ab 02 00 00       	jmp    14000236a <do_pseudo_reloc+0x378>
   1400020bf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020c3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020c6:	83 f8 01             	cmp    eax,0x1
   1400020c9:	74 18                	je     1400020e3 <do_pseudo_reloc+0xf1>
   1400020cb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020cf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020d2:	89 c2                	mov    edx,eax
   1400020d4:	48 8d 05 95 31 00 00 	lea    rax,[rip+0x3195]        # 140005270 <.rdata+0xa0>
   1400020db:	48 89 c1             	mov    rcx,rax
   1400020de:	e8 ad fa ff ff       	call   140001b90 <__report_error>
   1400020e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020e7:	48 83 c0 0c          	add    rax,0xc
   1400020eb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400020ef:	e9 65 02 00 00       	jmp    140002359 <do_pseudo_reloc+0x367>
   1400020f4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020f8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020fb:	89 c2                	mov    edx,eax
   1400020fd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002101:	48 01 d0             	add    rax,rdx
   140002104:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002108:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000210c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000210e:	89 c2                	mov    edx,eax
   140002110:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002114:	48 01 d0             	add    rax,rdx
   140002117:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000211b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000211f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002122:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002126:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000212a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000212d:	0f b6 c0             	movzx  eax,al
   140002130:	83 f8 40             	cmp    eax,0x40
   140002133:	0f 84 b6 00 00 00    	je     1400021ef <do_pseudo_reloc+0x1fd>
   140002139:	83 f8 40             	cmp    eax,0x40
   14000213c:	0f 87 ba 00 00 00    	ja     1400021fc <do_pseudo_reloc+0x20a>
   140002142:	83 f8 20             	cmp    eax,0x20
   140002145:	74 77                	je     1400021be <do_pseudo_reloc+0x1cc>
   140002147:	83 f8 20             	cmp    eax,0x20
   14000214a:	0f 87 ac 00 00 00    	ja     1400021fc <do_pseudo_reloc+0x20a>
   140002150:	83 f8 08             	cmp    eax,0x8
   140002153:	74 0a                	je     14000215f <do_pseudo_reloc+0x16d>
   140002155:	83 f8 10             	cmp    eax,0x10
   140002158:	74 38                	je     140002192 <do_pseudo_reloc+0x1a0>
   14000215a:	e9 9d 00 00 00       	jmp    1400021fc <do_pseudo_reloc+0x20a>
   14000215f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002163:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002166:	0f b6 c0             	movzx  eax,al
   140002169:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000216d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002171:	25 80 00 00 00       	and    eax,0x80
   140002176:	48 85 c0             	test   rax,rax
   140002179:	0f 84 9d 00 00 00    	je     14000221c <do_pseudo_reloc+0x22a>
   14000217f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002183:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002189:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000218d:	e9 8a 00 00 00       	jmp    14000221c <do_pseudo_reloc+0x22a>
   140002192:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002196:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002199:	0f b7 c0             	movzx  eax,ax
   14000219c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021a0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021a4:	25 00 80 00 00       	and    eax,0x8000
   1400021a9:	48 85 c0             	test   rax,rax
   1400021ac:	74 71                	je     14000221f <do_pseudo_reloc+0x22d>
   1400021ae:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021b2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400021b8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021bc:	eb 61                	jmp    14000221f <do_pseudo_reloc+0x22d>
   1400021be:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021c2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021c4:	89 c0                	mov    eax,eax
   1400021c6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ca:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021ce:	25 00 00 00 80       	and    eax,0x80000000
   1400021d3:	48 85 c0             	test   rax,rax
   1400021d6:	74 4a                	je     140002222 <do_pseudo_reloc+0x230>
   1400021d8:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021dc:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   1400021e3:	ff ff ff 
   1400021e6:	48 09 d0             	or     rax,rdx
   1400021e9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ed:	eb 33                	jmp    140002222 <do_pseudo_reloc+0x230>
   1400021ef:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021f3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400021f6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021fa:	eb 27                	jmp    140002223 <do_pseudo_reloc+0x231>
   1400021fc:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002203:	00 
   140002204:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002208:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000220b:	0f b6 c0             	movzx  eax,al
   14000220e:	48 8d 0d 93 30 00 00 	lea    rcx,[rip+0x3093]        # 1400052a8 <.rdata+0xd8>
   140002215:	89 c2                	mov    edx,eax
   140002217:	e8 74 f9 ff ff       	call   140001b90 <__report_error>
   14000221c:	90                   	nop
   14000221d:	eb 04                	jmp    140002223 <do_pseudo_reloc+0x231>
   14000221f:	90                   	nop
   140002220:	eb 01                	jmp    140002223 <do_pseudo_reloc+0x231>
   140002222:	90                   	nop
   140002223:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002227:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000222b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000222d:	89 c2                	mov    edx,eax
   14000222f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002233:	48 01 c2             	add    rdx,rax
   140002236:	48 89 c8             	mov    rax,rcx
   140002239:	48 29 d0             	sub    rax,rdx
   14000223c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002240:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002244:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002248:	48 01 d0             	add    rax,rdx
   14000224b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000224f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002253:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002256:	25 ff 00 00 00       	and    eax,0xff
   14000225b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000225e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002262:	77 67                	ja     1400022cb <do_pseudo_reloc+0x2d9>
   140002264:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002267:	ba 01 00 00 00       	mov    edx,0x1
   14000226c:	89 c1                	mov    ecx,eax
   14000226e:	48 d3 e2             	shl    rdx,cl
   140002271:	48 89 d0             	mov    rax,rdx
   140002274:	48 83 e8 01          	sub    rax,0x1
   140002278:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000227c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000227f:	83 e8 01             	sub    eax,0x1
   140002282:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002289:	89 c1                	mov    ecx,eax
   14000228b:	48 d3 e2             	shl    rdx,cl
   14000228e:	48 89 d0             	mov    rax,rdx
   140002291:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002295:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002299:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000229d:	7c 0a                	jl     1400022a9 <do_pseudo_reloc+0x2b7>
   14000229f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022a3:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400022a7:	7e 22                	jle    1400022cb <do_pseudo_reloc+0x2d9>
   1400022a9:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400022ad:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400022b1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400022b5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022b8:	48 8d 0d 19 30 00 00 	lea    rcx,[rip+0x3019]        # 1400052d8 <.rdata+0x108>
   1400022bf:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400022c4:	89 c2                	mov    edx,eax
   1400022c6:	e8 c5 f8 ff ff       	call   140001b90 <__report_error>
   1400022cb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022cf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022d2:	0f b6 c0             	movzx  eax,al
   1400022d5:	83 f8 40             	cmp    eax,0x40
   1400022d8:	74 63                	je     14000233d <do_pseudo_reloc+0x34b>
   1400022da:	83 f8 40             	cmp    eax,0x40
   1400022dd:	77 75                	ja     140002354 <do_pseudo_reloc+0x362>
   1400022df:	83 f8 20             	cmp    eax,0x20
   1400022e2:	74 41                	je     140002325 <do_pseudo_reloc+0x333>
   1400022e4:	83 f8 20             	cmp    eax,0x20
   1400022e7:	77 6b                	ja     140002354 <do_pseudo_reloc+0x362>
   1400022e9:	83 f8 08             	cmp    eax,0x8
   1400022ec:	74 07                	je     1400022f5 <do_pseudo_reloc+0x303>
   1400022ee:	83 f8 10             	cmp    eax,0x10
   1400022f1:	74 1a                	je     14000230d <do_pseudo_reloc+0x31b>
   1400022f3:	eb 5f                	jmp    140002354 <do_pseudo_reloc+0x362>
   1400022f5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022f9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022fd:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002303:	48 89 c1             	mov    rcx,rax
   140002306:	e8 a0 fc ff ff       	call   140001fab <__write_memory>
   14000230b:	eb 47                	jmp    140002354 <do_pseudo_reloc+0x362>
   14000230d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002311:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002315:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000231b:	48 89 c1             	mov    rcx,rax
   14000231e:	e8 88 fc ff ff       	call   140001fab <__write_memory>
   140002323:	eb 2f                	jmp    140002354 <do_pseudo_reloc+0x362>
   140002325:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002329:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000232d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002333:	48 89 c1             	mov    rcx,rax
   140002336:	e8 70 fc ff ff       	call   140001fab <__write_memory>
   14000233b:	eb 17                	jmp    140002354 <do_pseudo_reloc+0x362>
   14000233d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002341:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002345:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000234b:	48 89 c1             	mov    rcx,rax
   14000234e:	e8 58 fc ff ff       	call   140001fab <__write_memory>
   140002353:	90                   	nop
   140002354:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002359:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000235d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002361:	0f 82 8d fd ff ff    	jb     1400020f4 <do_pseudo_reloc+0x102>
   140002367:	eb 01                	jmp    14000236a <do_pseudo_reloc+0x378>
   140002369:	90                   	nop
   14000236a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000236e:	5d                   	pop    rbp
   14000236f:	c3                   	ret

0000000140002370 <_pei386_runtime_relocator>:
   140002370:	55                   	push   rbp
   140002371:	48 89 e5             	mov    rbp,rsp
   140002374:	48 83 ec 30          	sub    rsp,0x30
   140002378:	8b 05 6e 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d6e]        # 1400090ec <was_init.0>
   14000237e:	85 c0                	test   eax,eax
   140002380:	0f 85 88 00 00 00    	jne    14000240e <_pei386_runtime_relocator+0x9e>
   140002386:	8b 05 60 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d60]        # 1400090ec <was_init.0>
   14000238c:	83 c0 01             	add    eax,0x1
   14000238f:	89 05 57 6d 00 00    	mov    DWORD PTR [rip+0x6d57],eax        # 1400090ec <was_init.0>
   140002395:	e8 21 0b 00 00       	call   140002ebb <__mingw_GetSectionCount>
   14000239a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000239d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400023a0:	48 63 d0             	movsxd rdx,eax
   1400023a3:	48 89 d0             	mov    rax,rdx
   1400023a6:	48 c1 e0 02          	shl    rax,0x2
   1400023aa:	48 01 d0             	add    rax,rdx
   1400023ad:	48 c1 e0 03          	shl    rax,0x3
   1400023b1:	48 83 c0 0f          	add    rax,0xf
   1400023b5:	48 c1 e8 04          	shr    rax,0x4
   1400023b9:	48 c1 e0 04          	shl    rax,0x4
   1400023bd:	e8 7e 0d 00 00       	call   140003140 <___chkstk_ms>
   1400023c2:	48 29 c4             	sub    rsp,rax
   1400023c5:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400023ca:	48 83 c0 0f          	add    rax,0xf
   1400023ce:	48 c1 e8 04          	shr    rax,0x4
   1400023d2:	48 c1 e0 04          	shl    rax,0x4
   1400023d6:	48 89 05 03 6d 00 00 	mov    QWORD PTR [rip+0x6d03],rax        # 1400090e0 <the_secs>
   1400023dd:	c7 05 01 6d 00 00 00 	mov    DWORD PTR [rip+0x6d01],0x0        # 1400090e8 <maxSections>
   1400023e4:	00 00 00 
   1400023e7:	48 8b 0d 72 2f 00 00 	mov    rcx,QWORD PTR [rip+0x2f72]        # 140005360 <.refptr.__ImageBase>
   1400023ee:	48 8b 15 7b 2f 00 00 	mov    rdx,QWORD PTR [rip+0x2f7b]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   1400023f5:	48 8b 05 84 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f84]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   1400023fc:	49 89 c8             	mov    r8,rcx
   1400023ff:	48 89 c1             	mov    rcx,rax
   140002402:	e8 eb fb ff ff       	call   140001ff2 <do_pseudo_reloc>
   140002407:	e8 c7 fa ff ff       	call   140001ed3 <restore_modified_sections>
   14000240c:	eb 01                	jmp    14000240f <_pei386_runtime_relocator+0x9f>
   14000240e:	90                   	nop
   14000240f:	48 89 ec             	mov    rsp,rbp
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

0000000140002420 <__mingw_raise_matherr>:
   140002420:	55                   	push   rbp
   140002421:	48 89 e5             	mov    rbp,rsp
   140002424:	48 83 ec 50          	sub    rsp,0x50
   140002428:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000242b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000242f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002434:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002439:	48 8b 05 b0 6c 00 00 	mov    rax,QWORD PTR [rip+0x6cb0]        # 1400090f0 <stUserMathErr>
   140002440:	48 85 c0             	test   rax,rax
   140002443:	74 3e                	je     140002483 <__mingw_raise_matherr+0x63>
   140002445:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002448:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000244b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000244f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002453:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002458:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000245d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002462:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002467:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000246c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002471:	48 8b 15 78 6c 00 00 	mov    rdx,QWORD PTR [rip+0x6c78]        # 1400090f0 <stUserMathErr>
   140002478:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000247c:	48 89 c1             	mov    rcx,rax
   14000247f:	ff d2                	call   rdx
   140002481:	eb 01                	jmp    140002484 <__mingw_raise_matherr+0x64>
   140002483:	90                   	nop
   140002484:	48 83 c4 50          	add    rsp,0x50
   140002488:	5d                   	pop    rbp
   140002489:	c3                   	ret

000000014000248a <__mingw_setusermatherr>:
   14000248a:	55                   	push   rbp
   14000248b:	48 89 e5             	mov    rbp,rsp
   14000248e:	48 83 ec 20          	sub    rsp,0x20
   140002492:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002496:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000249a:	48 89 05 4f 6c 00 00 	mov    QWORD PTR [rip+0x6c4f],rax        # 1400090f0 <stUserMathErr>
   1400024a1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024a5:	48 89 c1             	mov    rcx,rax
   1400024a8:	e8 13 0e 00 00       	call   1400032c0 <__setusermatherr>
   1400024ad:	90                   	nop
   1400024ae:	48 83 c4 20          	add    rsp,0x20
   1400024b2:	5d                   	pop    rbp
   1400024b3:	c3                   	ret
   1400024b4:	90                   	nop
   1400024b5:	90                   	nop
   1400024b6:	90                   	nop
   1400024b7:	90                   	nop
   1400024b8:	90                   	nop
   1400024b9:	90                   	nop
   1400024ba:	90                   	nop
   1400024bb:	90                   	nop
   1400024bc:	90                   	nop
   1400024bd:	90                   	nop
   1400024be:	90                   	nop
   1400024bf:	90                   	nop

00000001400024c0 <__mingw_SEH_error_handler>:
   1400024c0:	55                   	push   rbp
   1400024c1:	48 89 e5             	mov    rbp,rsp
   1400024c4:	48 83 ec 30          	sub    rsp,0x30
   1400024c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024cc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400024d0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400024d4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400024d8:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400024df:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400024e6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024ea:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024ed:	83 e0 02             	and    eax,0x2
   1400024f0:	85 c0                	test   eax,eax
   1400024f2:	74 0a                	je     1400024fe <__mingw_SEH_error_handler+0x3e>
   1400024f4:	b8 01 00 00 00       	mov    eax,0x1
   1400024f9:	e9 16 02 00 00       	jmp    140002714 <__mingw_SEH_error_handler+0x254>
   1400024fe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002502:	8b 00                	mov    eax,DWORD PTR [rax]
   140002504:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002509:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000250e:	75 18                	jne    140002528 <__mingw_SEH_error_handler+0x68>
   140002510:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002514:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002517:	83 e0 01             	and    eax,0x1
   14000251a:	85 c0                	test   eax,eax
   14000251c:	75 0a                	jne    140002528 <__mingw_SEH_error_handler+0x68>
   14000251e:	b8 00 00 00 00       	mov    eax,0x0
   140002523:	e9 ec 01 00 00       	jmp    140002714 <__mingw_SEH_error_handler+0x254>
   140002528:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000252c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000252e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002533:	0f 84 12 01 00 00    	je     14000264b <__mingw_SEH_error_handler+0x18b>
   140002539:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000253e:	0f 87 c3 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   140002544:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002549:	0f 87 b8 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   14000254f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002554:	0f 83 4c 01 00 00    	jae    1400026a6 <__mingw_SEH_error_handler+0x1e6>
   14000255a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000255f:	0f 84 3a 01 00 00    	je     14000269f <__mingw_SEH_error_handler+0x1df>
   140002565:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000256a:	0f 87 97 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   140002570:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002575:	0f 84 83 01 00 00    	je     1400026fe <__mingw_SEH_error_handler+0x23e>
   14000257b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002580:	0f 87 81 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   140002586:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000258b:	0f 87 76 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   140002591:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002596:	0f 83 03 01 00 00    	jae    14000269f <__mingw_SEH_error_handler+0x1df>
   14000259c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025a1:	0f 84 57 01 00 00    	je     1400026fe <__mingw_SEH_error_handler+0x23e>
   1400025a7:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025ac:	0f 87 55 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   1400025b2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025b7:	0f 84 8e 00 00 00    	je     14000264b <__mingw_SEH_error_handler+0x18b>
   1400025bd:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025c2:	0f 87 3f 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   1400025c8:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025cd:	0f 84 2b 01 00 00    	je     1400026fe <__mingw_SEH_error_handler+0x23e>
   1400025d3:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025d8:	0f 87 29 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   1400025de:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400025e3:	0f 84 15 01 00 00    	je     1400026fe <__mingw_SEH_error_handler+0x23e>
   1400025e9:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400025ee:	0f 85 13 01 00 00    	jne    140002707 <__mingw_SEH_error_handler+0x247>
   1400025f4:	ba 00 00 00 00       	mov    edx,0x0
   1400025f9:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025fe:	e8 35 0d 00 00       	call   140003338 <signal>
   140002603:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002607:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000260c:	75 1b                	jne    140002629 <__mingw_SEH_error_handler+0x169>
   14000260e:	ba 01 00 00 00       	mov    edx,0x1
   140002613:	b9 0b 00 00 00       	mov    ecx,0xb
   140002618:	e8 1b 0d 00 00       	call   140003338 <signal>
   14000261d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002624:	e9 e1 00 00 00       	jmp    14000270a <__mingw_SEH_error_handler+0x24a>
   140002629:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000262e:	0f 84 d6 00 00 00    	je     14000270a <__mingw_SEH_error_handler+0x24a>
   140002634:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002638:	b9 0b 00 00 00       	mov    ecx,0xb
   14000263d:	ff d0                	call   rax
   14000263f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002646:	e9 bf 00 00 00       	jmp    14000270a <__mingw_SEH_error_handler+0x24a>
   14000264b:	ba 00 00 00 00       	mov    edx,0x0
   140002650:	b9 04 00 00 00       	mov    ecx,0x4
   140002655:	e8 de 0c 00 00       	call   140003338 <signal>
   14000265a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000265e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002663:	75 1b                	jne    140002680 <__mingw_SEH_error_handler+0x1c0>
   140002665:	ba 01 00 00 00       	mov    edx,0x1
   14000266a:	b9 04 00 00 00       	mov    ecx,0x4
   14000266f:	e8 c4 0c 00 00       	call   140003338 <signal>
   140002674:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000267b:	e9 8d 00 00 00       	jmp    14000270d <__mingw_SEH_error_handler+0x24d>
   140002680:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002685:	0f 84 82 00 00 00    	je     14000270d <__mingw_SEH_error_handler+0x24d>
   14000268b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000268f:	b9 04 00 00 00       	mov    ecx,0x4
   140002694:	ff d0                	call   rax
   140002696:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000269d:	eb 6e                	jmp    14000270d <__mingw_SEH_error_handler+0x24d>
   14000269f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400026a6:	ba 00 00 00 00       	mov    edx,0x0
   1400026ab:	b9 08 00 00 00       	mov    ecx,0x8
   1400026b0:	e8 83 0c 00 00       	call   140003338 <signal>
   1400026b5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026b9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026be:	75 23                	jne    1400026e3 <__mingw_SEH_error_handler+0x223>
   1400026c0:	ba 01 00 00 00       	mov    edx,0x1
   1400026c5:	b9 08 00 00 00       	mov    ecx,0x8
   1400026ca:	e8 69 0c 00 00       	call   140003338 <signal>
   1400026cf:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400026d3:	74 05                	je     1400026da <__mingw_SEH_error_handler+0x21a>
   1400026d5:	e8 a6 05 00 00       	call   140002c80 <_fpreset>
   1400026da:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026e1:	eb 2d                	jmp    140002710 <__mingw_SEH_error_handler+0x250>
   1400026e3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026e8:	74 26                	je     140002710 <__mingw_SEH_error_handler+0x250>
   1400026ea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026ee:	b9 08 00 00 00       	mov    ecx,0x8
   1400026f3:	ff d0                	call   rax
   1400026f5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026fc:	eb 12                	jmp    140002710 <__mingw_SEH_error_handler+0x250>
   1400026fe:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002705:	eb 0a                	jmp    140002711 <__mingw_SEH_error_handler+0x251>
   140002707:	90                   	nop
   140002708:	eb 07                	jmp    140002711 <__mingw_SEH_error_handler+0x251>
   14000270a:	90                   	nop
   14000270b:	eb 04                	jmp    140002711 <__mingw_SEH_error_handler+0x251>
   14000270d:	90                   	nop
   14000270e:	eb 01                	jmp    140002711 <__mingw_SEH_error_handler+0x251>
   140002710:	90                   	nop
   140002711:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002714:	48 83 c4 30          	add    rsp,0x30
   140002718:	5d                   	pop    rbp
   140002719:	c3                   	ret

000000014000271a <_gnu_exception_handler>:
   14000271a:	55                   	push   rbp
   14000271b:	48 89 e5             	mov    rbp,rsp
   14000271e:	48 83 ec 30          	sub    rsp,0x30
   140002722:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002726:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000272d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002734:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002738:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000273b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000273d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002742:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002747:	75 1b                	jne    140002764 <_gnu_exception_handler+0x4a>
   140002749:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000274d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002750:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002753:	83 e0 01             	and    eax,0x1
   140002756:	85 c0                	test   eax,eax
   140002758:	75 0a                	jne    140002764 <_gnu_exception_handler+0x4a>
   14000275a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000275f:	e9 14 02 00 00       	jmp    140002978 <_gnu_exception_handler+0x25e>
   140002764:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002768:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000276b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000276d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002772:	0f 84 12 01 00 00    	je     14000288a <_gnu_exception_handler+0x170>
   140002778:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000277d:	0f 87 c3 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   140002783:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002788:	0f 87 b8 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   14000278e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002793:	0f 83 4c 01 00 00    	jae    1400028e5 <_gnu_exception_handler+0x1cb>
   140002799:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000279e:	0f 84 3a 01 00 00    	je     1400028de <_gnu_exception_handler+0x1c4>
   1400027a4:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027a9:	0f 87 97 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   1400027af:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027b4:	0f 84 83 01 00 00    	je     14000293d <_gnu_exception_handler+0x223>
   1400027ba:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027bf:	0f 87 81 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   1400027c5:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400027ca:	0f 87 76 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   1400027d0:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400027d5:	0f 83 03 01 00 00    	jae    1400028de <_gnu_exception_handler+0x1c4>
   1400027db:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027e0:	0f 84 57 01 00 00    	je     14000293d <_gnu_exception_handler+0x223>
   1400027e6:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027eb:	0f 87 55 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   1400027f1:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027f6:	0f 84 8e 00 00 00    	je     14000288a <_gnu_exception_handler+0x170>
   1400027fc:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002801:	0f 87 3f 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   140002807:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000280c:	0f 84 2b 01 00 00    	je     14000293d <_gnu_exception_handler+0x223>
   140002812:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002817:	0f 87 29 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   14000281d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002822:	0f 84 15 01 00 00    	je     14000293d <_gnu_exception_handler+0x223>
   140002828:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000282d:	0f 85 13 01 00 00    	jne    140002946 <_gnu_exception_handler+0x22c>
   140002833:	ba 00 00 00 00       	mov    edx,0x0
   140002838:	b9 0b 00 00 00       	mov    ecx,0xb
   14000283d:	e8 f6 0a 00 00       	call   140003338 <signal>
   140002842:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002846:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000284b:	75 1b                	jne    140002868 <_gnu_exception_handler+0x14e>
   14000284d:	ba 01 00 00 00       	mov    edx,0x1
   140002852:	b9 0b 00 00 00       	mov    ecx,0xb
   140002857:	e8 dc 0a 00 00       	call   140003338 <signal>
   14000285c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002863:	e9 e1 00 00 00       	jmp    140002949 <_gnu_exception_handler+0x22f>
   140002868:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000286d:	0f 84 d6 00 00 00    	je     140002949 <_gnu_exception_handler+0x22f>
   140002873:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002877:	b9 0b 00 00 00       	mov    ecx,0xb
   14000287c:	ff d0                	call   rax
   14000287e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002885:	e9 bf 00 00 00       	jmp    140002949 <_gnu_exception_handler+0x22f>
   14000288a:	ba 00 00 00 00       	mov    edx,0x0
   14000288f:	b9 04 00 00 00       	mov    ecx,0x4
   140002894:	e8 9f 0a 00 00       	call   140003338 <signal>
   140002899:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000289d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028a2:	75 1b                	jne    1400028bf <_gnu_exception_handler+0x1a5>
   1400028a4:	ba 01 00 00 00       	mov    edx,0x1
   1400028a9:	b9 04 00 00 00       	mov    ecx,0x4
   1400028ae:	e8 85 0a 00 00       	call   140003338 <signal>
   1400028b3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028ba:	e9 8d 00 00 00       	jmp    14000294c <_gnu_exception_handler+0x232>
   1400028bf:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028c4:	0f 84 82 00 00 00    	je     14000294c <_gnu_exception_handler+0x232>
   1400028ca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028ce:	b9 04 00 00 00       	mov    ecx,0x4
   1400028d3:	ff d0                	call   rax
   1400028d5:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028dc:	eb 6e                	jmp    14000294c <_gnu_exception_handler+0x232>
   1400028de:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400028e5:	ba 00 00 00 00       	mov    edx,0x0
   1400028ea:	b9 08 00 00 00       	mov    ecx,0x8
   1400028ef:	e8 44 0a 00 00       	call   140003338 <signal>
   1400028f4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028f8:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028fd:	75 23                	jne    140002922 <_gnu_exception_handler+0x208>
   1400028ff:	ba 01 00 00 00       	mov    edx,0x1
   140002904:	b9 08 00 00 00       	mov    ecx,0x8
   140002909:	e8 2a 0a 00 00       	call   140003338 <signal>
   14000290e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002912:	74 05                	je     140002919 <_gnu_exception_handler+0x1ff>
   140002914:	e8 67 03 00 00       	call   140002c80 <_fpreset>
   140002919:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002920:	eb 2d                	jmp    14000294f <_gnu_exception_handler+0x235>
   140002922:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002927:	74 26                	je     14000294f <_gnu_exception_handler+0x235>
   140002929:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000292d:	b9 08 00 00 00       	mov    ecx,0x8
   140002932:	ff d0                	call   rax
   140002934:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000293b:	eb 12                	jmp    14000294f <_gnu_exception_handler+0x235>
   14000293d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002944:	eb 0a                	jmp    140002950 <_gnu_exception_handler+0x236>
   140002946:	90                   	nop
   140002947:	eb 07                	jmp    140002950 <_gnu_exception_handler+0x236>
   140002949:	90                   	nop
   14000294a:	eb 04                	jmp    140002950 <_gnu_exception_handler+0x236>
   14000294c:	90                   	nop
   14000294d:	eb 01                	jmp    140002950 <_gnu_exception_handler+0x236>
   14000294f:	90                   	nop
   140002950:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002954:	75 1f                	jne    140002975 <_gnu_exception_handler+0x25b>
   140002956:	48 8b 05 b3 67 00 00 	mov    rax,QWORD PTR [rip+0x67b3]        # 140009110 <__mingw_oldexcpt_handler>
   14000295d:	48 85 c0             	test   rax,rax
   140002960:	74 13                	je     140002975 <_gnu_exception_handler+0x25b>
   140002962:	48 8b 15 a7 67 00 00 	mov    rdx,QWORD PTR [rip+0x67a7]        # 140009110 <__mingw_oldexcpt_handler>
   140002969:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000296d:	48 89 c1             	mov    rcx,rax
   140002970:	ff d2                	call   rdx
   140002972:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002975:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002978:	48 83 c4 30          	add    rsp,0x30
   14000297c:	5d                   	pop    rbp
   14000297d:	c3                   	ret
   14000297e:	90                   	nop
   14000297f:	90                   	nop

0000000140002980 <___w64_mingwthr_add_key_dtor>:
   140002980:	55                   	push   rbp
   140002981:	48 89 e5             	mov    rbp,rsp
   140002984:	48 83 ec 30          	sub    rsp,0x30
   140002988:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000298b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000298f:	8b 05 b3 67 00 00    	mov    eax,DWORD PTR [rip+0x67b3]        # 140009148 <__mingwthr_cs_init>
   140002995:	85 c0                	test   eax,eax
   140002997:	75 07                	jne    1400029a0 <___w64_mingwthr_add_key_dtor+0x20>
   140002999:	b8 00 00 00 00       	mov    eax,0x0
   14000299e:	eb 7b                	jmp    140002a1b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029a0:	ba 18 00 00 00       	mov    edx,0x18
   1400029a5:	b9 01 00 00 00       	mov    ecx,0x1
   1400029aa:	e8 41 09 00 00       	call   1400032f0 <calloc>
   1400029af:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400029b3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029b8:	75 07                	jne    1400029c1 <___w64_mingwthr_add_key_dtor+0x41>
   1400029ba:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400029bf:	eb 5a                	jmp    140002a1b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029c1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029c5:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400029c8:	89 10                	mov    DWORD PTR [rax],edx
   1400029ca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029ce:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400029d2:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   1400029d6:	48 8d 05 43 67 00 00 	lea    rax,[rip+0x6743]        # 140009120 <__mingwthr_cs>
   1400029dd:	48 89 c1             	mov    rcx,rax
   1400029e0:	48 8b 05 b1 77 00 00 	mov    rax,QWORD PTR [rip+0x77b1]        # 14000a198 <__imp_EnterCriticalSection>
   1400029e7:	ff d0                	call   rax
   1400029e9:	48 8b 15 60 67 00 00 	mov    rdx,QWORD PTR [rip+0x6760]        # 140009150 <key_dtor_list>
   1400029f0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029f4:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029fc:	48 89 05 4d 67 00 00 	mov    QWORD PTR [rip+0x674d],rax        # 140009150 <key_dtor_list>
   140002a03:	48 8d 05 16 67 00 00 	lea    rax,[rip+0x6716]        # 140009120 <__mingwthr_cs>
   140002a0a:	48 89 c1             	mov    rcx,rax
   140002a0d:	48 8b 05 b4 77 00 00 	mov    rax,QWORD PTR [rip+0x77b4]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002a14:	ff d0                	call   rax
   140002a16:	b8 00 00 00 00       	mov    eax,0x0
   140002a1b:	48 83 c4 30          	add    rsp,0x30
   140002a1f:	5d                   	pop    rbp
   140002a20:	c3                   	ret

0000000140002a21 <___w64_mingwthr_remove_key_dtor>:
   140002a21:	55                   	push   rbp
   140002a22:	48 89 e5             	mov    rbp,rsp
   140002a25:	48 83 ec 30          	sub    rsp,0x30
   140002a29:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a2c:	8b 05 16 67 00 00    	mov    eax,DWORD PTR [rip+0x6716]        # 140009148 <__mingwthr_cs_init>
   140002a32:	85 c0                	test   eax,eax
   140002a34:	75 0a                	jne    140002a40 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a36:	b8 00 00 00 00       	mov    eax,0x0
   140002a3b:	e9 9c 00 00 00       	jmp    140002adc <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a40:	48 8d 05 d9 66 00 00 	lea    rax,[rip+0x66d9]        # 140009120 <__mingwthr_cs>
   140002a47:	48 89 c1             	mov    rcx,rax
   140002a4a:	48 8b 05 47 77 00 00 	mov    rax,QWORD PTR [rip+0x7747]        # 14000a198 <__imp_EnterCriticalSection>
   140002a51:	ff d0                	call   rax
   140002a53:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a5a:	00 
   140002a5b:	48 8b 05 ee 66 00 00 	mov    rax,QWORD PTR [rip+0x66ee]        # 140009150 <key_dtor_list>
   140002a62:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a66:	eb 55                	jmp    140002abd <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a68:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a6c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a6e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a71:	75 36                	jne    140002aa9 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a73:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a78:	75 11                	jne    140002a8b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a7a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a7e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a82:	48 89 05 c7 66 00 00 	mov    QWORD PTR [rip+0x66c7],rax        # 140009150 <key_dtor_list>
   140002a89:	eb 10                	jmp    140002a9b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a8b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a8f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a93:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a97:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a9b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a9f:	48 89 c1             	mov    rcx,rax
   140002aa2:	e8 69 08 00 00       	call   140003310 <free>
   140002aa7:	eb 1b                	jmp    140002ac4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002aa9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aad:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ab1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ab5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ab9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002abd:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002ac2:	75 a4                	jne    140002a68 <___w64_mingwthr_remove_key_dtor+0x47>
   140002ac4:	48 8d 05 55 66 00 00 	lea    rax,[rip+0x6655]        # 140009120 <__mingwthr_cs>
   140002acb:	48 89 c1             	mov    rcx,rax
   140002ace:	48 8b 05 f3 76 00 00 	mov    rax,QWORD PTR [rip+0x76f3]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002ad5:	ff d0                	call   rax
   140002ad7:	b8 00 00 00 00       	mov    eax,0x0
   140002adc:	48 83 c4 30          	add    rsp,0x30
   140002ae0:	5d                   	pop    rbp
   140002ae1:	c3                   	ret

0000000140002ae2 <__mingwthr_run_key_dtors>:
   140002ae2:	55                   	push   rbp
   140002ae3:	48 89 e5             	mov    rbp,rsp
   140002ae6:	48 83 ec 30          	sub    rsp,0x30
   140002aea:	8b 05 58 66 00 00    	mov    eax,DWORD PTR [rip+0x6658]        # 140009148 <__mingwthr_cs_init>
   140002af0:	85 c0                	test   eax,eax
   140002af2:	0f 84 82 00 00 00    	je     140002b7a <__mingwthr_run_key_dtors+0x98>
   140002af8:	48 8d 05 21 66 00 00 	lea    rax,[rip+0x6621]        # 140009120 <__mingwthr_cs>
   140002aff:	48 89 c1             	mov    rcx,rax
   140002b02:	48 8b 05 8f 76 00 00 	mov    rax,QWORD PTR [rip+0x768f]        # 14000a198 <__imp_EnterCriticalSection>
   140002b09:	ff d0                	call   rax
   140002b0b:	48 8b 05 3e 66 00 00 	mov    rax,QWORD PTR [rip+0x663e]        # 140009150 <key_dtor_list>
   140002b12:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b16:	eb 46                	jmp    140002b5e <__mingwthr_run_key_dtors+0x7c>
   140002b18:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b1c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b1e:	89 c1                	mov    ecx,eax
   140002b20:	48 8b 05 c1 76 00 00 	mov    rax,QWORD PTR [rip+0x76c1]        # 14000a1e8 <__imp_TlsGetValue>
   140002b27:	ff d0                	call   rax
   140002b29:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b2d:	48 8b 05 74 76 00 00 	mov    rax,QWORD PTR [rip+0x7674]        # 14000a1a8 <__imp_GetLastError>
   140002b34:	ff d0                	call   rax
   140002b36:	85 c0                	test   eax,eax
   140002b38:	75 18                	jne    140002b52 <__mingwthr_run_key_dtors+0x70>
   140002b3a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b3f:	74 11                	je     140002b52 <__mingwthr_run_key_dtors+0x70>
   140002b41:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b45:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002b49:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b4d:	48 89 c1             	mov    rcx,rax
   140002b50:	ff d2                	call   rdx
   140002b52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b56:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b5a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b5e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b63:	75 b3                	jne    140002b18 <__mingwthr_run_key_dtors+0x36>
   140002b65:	48 8d 05 b4 65 00 00 	lea    rax,[rip+0x65b4]        # 140009120 <__mingwthr_cs>
   140002b6c:	48 89 c1             	mov    rcx,rax
   140002b6f:	48 8b 05 52 76 00 00 	mov    rax,QWORD PTR [rip+0x7652]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002b76:	ff d0                	call   rax
   140002b78:	eb 01                	jmp    140002b7b <__mingwthr_run_key_dtors+0x99>
   140002b7a:	90                   	nop
   140002b7b:	48 83 c4 30          	add    rsp,0x30
   140002b7f:	5d                   	pop    rbp
   140002b80:	c3                   	ret

0000000140002b81 <__mingw_TLScallback>:
   140002b81:	55                   	push   rbp
   140002b82:	48 89 e5             	mov    rbp,rsp
   140002b85:	48 83 ec 30          	sub    rsp,0x30
   140002b89:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b8d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b90:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b94:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b98:	0f 84 cc 00 00 00    	je     140002c6a <__mingw_TLScallback+0xe9>
   140002b9e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002ba2:	0f 87 ca 00 00 00    	ja     140002c72 <__mingw_TLScallback+0xf1>
   140002ba8:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bac:	0f 84 b1 00 00 00    	je     140002c63 <__mingw_TLScallback+0xe2>
   140002bb2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bb6:	0f 87 b6 00 00 00    	ja     140002c72 <__mingw_TLScallback+0xf1>
   140002bbc:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002bc0:	74 33                	je     140002bf5 <__mingw_TLScallback+0x74>
   140002bc2:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002bc6:	0f 85 a6 00 00 00    	jne    140002c72 <__mingw_TLScallback+0xf1>
   140002bcc:	8b 05 76 65 00 00    	mov    eax,DWORD PTR [rip+0x6576]        # 140009148 <__mingwthr_cs_init>
   140002bd2:	85 c0                	test   eax,eax
   140002bd4:	75 13                	jne    140002be9 <__mingw_TLScallback+0x68>
   140002bd6:	48 8d 05 43 65 00 00 	lea    rax,[rip+0x6543]        # 140009120 <__mingwthr_cs>
   140002bdd:	48 89 c1             	mov    rcx,rax
   140002be0:	48 8b 05 d9 75 00 00 	mov    rax,QWORD PTR [rip+0x75d9]        # 14000a1c0 <__imp_InitializeCriticalSection>
   140002be7:	ff d0                	call   rax
   140002be9:	c7 05 55 65 00 00 01 	mov    DWORD PTR [rip+0x6555],0x1        # 140009148 <__mingwthr_cs_init>
   140002bf0:	00 00 00 
   140002bf3:	eb 7d                	jmp    140002c72 <__mingw_TLScallback+0xf1>
   140002bf5:	e8 e8 fe ff ff       	call   140002ae2 <__mingwthr_run_key_dtors>
   140002bfa:	8b 05 48 65 00 00    	mov    eax,DWORD PTR [rip+0x6548]        # 140009148 <__mingwthr_cs_init>
   140002c00:	83 f8 01             	cmp    eax,0x1
   140002c03:	75 6c                	jne    140002c71 <__mingw_TLScallback+0xf0>
   140002c05:	48 8b 05 44 65 00 00 	mov    rax,QWORD PTR [rip+0x6544]        # 140009150 <key_dtor_list>
   140002c0c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c10:	eb 20                	jmp    140002c32 <__mingw_TLScallback+0xb1>
   140002c12:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c16:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c1a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c1e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c22:	48 89 c1             	mov    rcx,rax
   140002c25:	e8 e6 06 00 00       	call   140003310 <free>
   140002c2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c2e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c32:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c37:	75 d9                	jne    140002c12 <__mingw_TLScallback+0x91>
   140002c39:	48 c7 05 0c 65 00 00 	mov    QWORD PTR [rip+0x650c],0x0        # 140009150 <key_dtor_list>
   140002c40:	00 00 00 00 
   140002c44:	c7 05 fa 64 00 00 00 	mov    DWORD PTR [rip+0x64fa],0x0        # 140009148 <__mingwthr_cs_init>
   140002c4b:	00 00 00 
   140002c4e:	48 8d 05 cb 64 00 00 	lea    rax,[rip+0x64cb]        # 140009120 <__mingwthr_cs>
   140002c55:	48 89 c1             	mov    rcx,rax
   140002c58:	48 8b 05 31 75 00 00 	mov    rax,QWORD PTR [rip+0x7531]        # 14000a190 <__IAT_start__>
   140002c5f:	ff d0                	call   rax
   140002c61:	eb 0e                	jmp    140002c71 <__mingw_TLScallback+0xf0>
   140002c63:	e8 18 00 00 00       	call   140002c80 <_fpreset>
   140002c68:	eb 08                	jmp    140002c72 <__mingw_TLScallback+0xf1>
   140002c6a:	e8 73 fe ff ff       	call   140002ae2 <__mingwthr_run_key_dtors>
   140002c6f:	eb 01                	jmp    140002c72 <__mingw_TLScallback+0xf1>
   140002c71:	90                   	nop
   140002c72:	b8 01 00 00 00       	mov    eax,0x1
   140002c77:	48 83 c4 30          	add    rsp,0x30
   140002c7b:	5d                   	pop    rbp
   140002c7c:	c3                   	ret
   140002c7d:	90                   	nop
   140002c7e:	90                   	nop
   140002c7f:	90                   	nop

0000000140002c80 <_fpreset>:
   140002c80:	55                   	push   rbp
   140002c81:	48 89 e5             	mov    rbp,rsp
   140002c84:	db e3                	fninit
   140002c86:	90                   	nop
   140002c87:	5d                   	pop    rbp
   140002c88:	c3                   	ret
   140002c89:	90                   	nop
   140002c8a:	90                   	nop
   140002c8b:	90                   	nop
   140002c8c:	90                   	nop
   140002c8d:	90                   	nop
   140002c8e:	90                   	nop
   140002c8f:	90                   	nop

0000000140002c90 <_ValidateImageBase>:
   140002c90:	55                   	push   rbp
   140002c91:	48 89 e5             	mov    rbp,rsp
   140002c94:	48 83 ec 20          	sub    rsp,0x20
   140002c98:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c9c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ca0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ca4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ca8:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002cab:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002caf:	74 07                	je     140002cb8 <_ValidateImageBase+0x28>
   140002cb1:	b8 00 00 00 00       	mov    eax,0x0
   140002cb6:	eb 4e                	jmp    140002d06 <_ValidateImageBase+0x76>
   140002cb8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cbc:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002cbf:	48 63 d0             	movsxd rdx,eax
   140002cc2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cc6:	48 01 d0             	add    rax,rdx
   140002cc9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ccd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002cd1:	8b 00                	mov    eax,DWORD PTR [rax]
   140002cd3:	3d 50 45 00 00       	cmp    eax,0x4550
   140002cd8:	74 07                	je     140002ce1 <_ValidateImageBase+0x51>
   140002cda:	b8 00 00 00 00       	mov    eax,0x0
   140002cdf:	eb 25                	jmp    140002d06 <_ValidateImageBase+0x76>
   140002ce1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ce5:	48 83 c0 18          	add    rax,0x18
   140002ce9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ced:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cf1:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002cf4:	66 3d 0b 02          	cmp    ax,0x20b
   140002cf8:	74 07                	je     140002d01 <_ValidateImageBase+0x71>
   140002cfa:	b8 00 00 00 00       	mov    eax,0x0
   140002cff:	eb 05                	jmp    140002d06 <_ValidateImageBase+0x76>
   140002d01:	b8 01 00 00 00       	mov    eax,0x1
   140002d06:	48 83 c4 20          	add    rsp,0x20
   140002d0a:	5d                   	pop    rbp
   140002d0b:	c3                   	ret

0000000140002d0c <_FindPESection>:
   140002d0c:	55                   	push   rbp
   140002d0d:	48 89 e5             	mov    rbp,rsp
   140002d10:	48 83 ec 20          	sub    rsp,0x20
   140002d14:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d18:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d1c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d20:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d23:	48 63 d0             	movsxd rdx,eax
   140002d26:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d2a:	48 01 d0             	add    rax,rdx
   140002d2d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d31:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d38:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d3c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d40:	0f b7 d0             	movzx  edx,ax
   140002d43:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d47:	48 01 d0             	add    rax,rdx
   140002d4a:	48 83 c0 18          	add    rax,0x18
   140002d4e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d52:	eb 36                	jmp    140002d8a <_FindPESection+0x7e>
   140002d54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d58:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d5b:	89 c0                	mov    eax,eax
   140002d5d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d61:	72 1e                	jb     140002d81 <_FindPESection+0x75>
   140002d63:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d67:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d6a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d6e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d71:	01 d0                	add    eax,edx
   140002d73:	89 c0                	mov    eax,eax
   140002d75:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d79:	73 06                	jae    140002d81 <_FindPESection+0x75>
   140002d7b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d7f:	eb 1e                	jmp    140002d9f <_FindPESection+0x93>
   140002d81:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d85:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d8a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d8e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d92:	0f b7 c0             	movzx  eax,ax
   140002d95:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d98:	72 ba                	jb     140002d54 <_FindPESection+0x48>
   140002d9a:	b8 00 00 00 00       	mov    eax,0x0
   140002d9f:	48 83 c4 20          	add    rsp,0x20
   140002da3:	5d                   	pop    rbp
   140002da4:	c3                   	ret

0000000140002da5 <_FindPESectionByName>:
   140002da5:	55                   	push   rbp
   140002da6:	48 89 e5             	mov    rbp,rsp
   140002da9:	48 83 ec 40          	sub    rsp,0x40
   140002dad:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002db1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002db5:	48 89 c1             	mov    rcx,rax
   140002db8:	e8 83 05 00 00       	call   140003340 <strlen>
   140002dbd:	48 83 f8 08          	cmp    rax,0x8
   140002dc1:	76 0a                	jbe    140002dcd <_FindPESectionByName+0x28>
   140002dc3:	b8 00 00 00 00       	mov    eax,0x0
   140002dc8:	e9 98 00 00 00       	jmp    140002e65 <_FindPESectionByName+0xc0>
   140002dcd:	48 8b 05 8c 25 00 00 	mov    rax,QWORD PTR [rip+0x258c]        # 140005360 <.refptr.__ImageBase>
   140002dd4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002dd8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ddc:	48 89 c1             	mov    rcx,rax
   140002ddf:	e8 ac fe ff ff       	call   140002c90 <_ValidateImageBase>
   140002de4:	85 c0                	test   eax,eax
   140002de6:	75 07                	jne    140002def <_FindPESectionByName+0x4a>
   140002de8:	b8 00 00 00 00       	mov    eax,0x0
   140002ded:	eb 76                	jmp    140002e65 <_FindPESectionByName+0xc0>
   140002def:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002df3:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002df6:	48 63 d0             	movsxd rdx,eax
   140002df9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dfd:	48 01 d0             	add    rax,rdx
   140002e00:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e04:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e0b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e0f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e13:	0f b7 d0             	movzx  edx,ax
   140002e16:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e1a:	48 01 d0             	add    rax,rdx
   140002e1d:	48 83 c0 18          	add    rax,0x18
   140002e21:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e25:	eb 29                	jmp    140002e50 <_FindPESectionByName+0xab>
   140002e27:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e2b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e2f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e35:	48 89 c1             	mov    rcx,rax
   140002e38:	e8 0b 05 00 00       	call   140003348 <strncmp>
   140002e3d:	85 c0                	test   eax,eax
   140002e3f:	75 06                	jne    140002e47 <_FindPESectionByName+0xa2>
   140002e41:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e45:	eb 1e                	jmp    140002e65 <_FindPESectionByName+0xc0>
   140002e47:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e4b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e50:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e54:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e58:	0f b7 c0             	movzx  eax,ax
   140002e5b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e5e:	72 c7                	jb     140002e27 <_FindPESectionByName+0x82>
   140002e60:	b8 00 00 00 00       	mov    eax,0x0
   140002e65:	48 83 c4 40          	add    rsp,0x40
   140002e69:	5d                   	pop    rbp
   140002e6a:	c3                   	ret

0000000140002e6b <__mingw_GetSectionForAddress>:
   140002e6b:	55                   	push   rbp
   140002e6c:	48 89 e5             	mov    rbp,rsp
   140002e6f:	48 83 ec 30          	sub    rsp,0x30
   140002e73:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e77:	48 8b 05 e2 24 00 00 	mov    rax,QWORD PTR [rip+0x24e2]        # 140005360 <.refptr.__ImageBase>
   140002e7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e82:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e86:	48 89 c1             	mov    rcx,rax
   140002e89:	e8 02 fe ff ff       	call   140002c90 <_ValidateImageBase>
   140002e8e:	85 c0                	test   eax,eax
   140002e90:	75 07                	jne    140002e99 <__mingw_GetSectionForAddress+0x2e>
   140002e92:	b8 00 00 00 00       	mov    eax,0x0
   140002e97:	eb 1c                	jmp    140002eb5 <__mingw_GetSectionForAddress+0x4a>
   140002e99:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e9d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002ea1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ea5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002ea9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ead:	48 89 c1             	mov    rcx,rax
   140002eb0:	e8 57 fe ff ff       	call   140002d0c <_FindPESection>
   140002eb5:	48 83 c4 30          	add    rsp,0x30
   140002eb9:	5d                   	pop    rbp
   140002eba:	c3                   	ret

0000000140002ebb <__mingw_GetSectionCount>:
   140002ebb:	55                   	push   rbp
   140002ebc:	48 89 e5             	mov    rbp,rsp
   140002ebf:	48 83 ec 30          	sub    rsp,0x30
   140002ec3:	48 8b 05 96 24 00 00 	mov    rax,QWORD PTR [rip+0x2496]        # 140005360 <.refptr.__ImageBase>
   140002eca:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ece:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ed2:	48 89 c1             	mov    rcx,rax
   140002ed5:	e8 b6 fd ff ff       	call   140002c90 <_ValidateImageBase>
   140002eda:	85 c0                	test   eax,eax
   140002edc:	75 07                	jne    140002ee5 <__mingw_GetSectionCount+0x2a>
   140002ede:	b8 00 00 00 00       	mov    eax,0x0
   140002ee3:	eb 20                	jmp    140002f05 <__mingw_GetSectionCount+0x4a>
   140002ee5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ee9:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002eec:	48 63 d0             	movsxd rdx,eax
   140002eef:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ef3:	48 01 d0             	add    rax,rdx
   140002ef6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002efa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002efe:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f02:	0f b7 c0             	movzx  eax,ax
   140002f05:	48 83 c4 30          	add    rsp,0x30
   140002f09:	5d                   	pop    rbp
   140002f0a:	c3                   	ret

0000000140002f0b <_FindPESectionExec>:
   140002f0b:	55                   	push   rbp
   140002f0c:	48 89 e5             	mov    rbp,rsp
   140002f0f:	48 83 ec 40          	sub    rsp,0x40
   140002f13:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f17:	48 8b 05 42 24 00 00 	mov    rax,QWORD PTR [rip+0x2442]        # 140005360 <.refptr.__ImageBase>
   140002f1e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f22:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f26:	48 89 c1             	mov    rcx,rax
   140002f29:	e8 62 fd ff ff       	call   140002c90 <_ValidateImageBase>
   140002f2e:	85 c0                	test   eax,eax
   140002f30:	75 07                	jne    140002f39 <_FindPESectionExec+0x2e>
   140002f32:	b8 00 00 00 00       	mov    eax,0x0
   140002f37:	eb 78                	jmp    140002fb1 <_FindPESectionExec+0xa6>
   140002f39:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f3d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f40:	48 63 d0             	movsxd rdx,eax
   140002f43:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f47:	48 01 d0             	add    rax,rdx
   140002f4a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f4e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f55:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f59:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f5d:	0f b7 d0             	movzx  edx,ax
   140002f60:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f64:	48 01 d0             	add    rax,rdx
   140002f67:	48 83 c0 18          	add    rax,0x18
   140002f6b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f6f:	eb 2b                	jmp    140002f9c <_FindPESectionExec+0x91>
   140002f71:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f75:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f78:	25 00 00 00 20       	and    eax,0x20000000
   140002f7d:	85 c0                	test   eax,eax
   140002f7f:	74 12                	je     140002f93 <_FindPESectionExec+0x88>
   140002f81:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f86:	75 06                	jne    140002f8e <_FindPESectionExec+0x83>
   140002f88:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f8c:	eb 23                	jmp    140002fb1 <_FindPESectionExec+0xa6>
   140002f8e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f93:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f97:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f9c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fa0:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002fa4:	0f b7 c0             	movzx  eax,ax
   140002fa7:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002faa:	72 c5                	jb     140002f71 <_FindPESectionExec+0x66>
   140002fac:	b8 00 00 00 00       	mov    eax,0x0
   140002fb1:	48 83 c4 40          	add    rsp,0x40
   140002fb5:	5d                   	pop    rbp
   140002fb6:	c3                   	ret

0000000140002fb7 <_GetPEImageBase>:
   140002fb7:	55                   	push   rbp
   140002fb8:	48 89 e5             	mov    rbp,rsp
   140002fbb:	48 83 ec 30          	sub    rsp,0x30
   140002fbf:	48 8b 05 9a 23 00 00 	mov    rax,QWORD PTR [rip+0x239a]        # 140005360 <.refptr.__ImageBase>
   140002fc6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fce:	48 89 c1             	mov    rcx,rax
   140002fd1:	e8 ba fc ff ff       	call   140002c90 <_ValidateImageBase>
   140002fd6:	85 c0                	test   eax,eax
   140002fd8:	75 07                	jne    140002fe1 <_GetPEImageBase+0x2a>
   140002fda:	b8 00 00 00 00       	mov    eax,0x0
   140002fdf:	eb 04                	jmp    140002fe5 <_GetPEImageBase+0x2e>
   140002fe1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fe5:	48 83 c4 30          	add    rsp,0x30
   140002fe9:	5d                   	pop    rbp
   140002fea:	c3                   	ret

0000000140002feb <_IsNonwritableInCurrentImage>:
   140002feb:	55                   	push   rbp
   140002fec:	48 89 e5             	mov    rbp,rsp
   140002fef:	48 83 ec 40          	sub    rsp,0x40
   140002ff3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ff7:	48 8b 05 62 23 00 00 	mov    rax,QWORD PTR [rip+0x2362]        # 140005360 <.refptr.__ImageBase>
   140002ffe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003002:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003006:	48 89 c1             	mov    rcx,rax
   140003009:	e8 82 fc ff ff       	call   140002c90 <_ValidateImageBase>
   14000300e:	85 c0                	test   eax,eax
   140003010:	75 07                	jne    140003019 <_IsNonwritableInCurrentImage+0x2e>
   140003012:	b8 00 00 00 00       	mov    eax,0x0
   140003017:	eb 3d                	jmp    140003056 <_IsNonwritableInCurrentImage+0x6b>
   140003019:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000301d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003021:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003025:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003029:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000302d:	48 89 c1             	mov    rcx,rax
   140003030:	e8 d7 fc ff ff       	call   140002d0c <_FindPESection>
   140003035:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003039:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000303e:	75 07                	jne    140003047 <_IsNonwritableInCurrentImage+0x5c>
   140003040:	b8 00 00 00 00       	mov    eax,0x0
   140003045:	eb 0f                	jmp    140003056 <_IsNonwritableInCurrentImage+0x6b>
   140003047:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000304b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000304e:	f7 d0                	not    eax
   140003050:	c1 e8 1f             	shr    eax,0x1f
   140003053:	0f b6 c0             	movzx  eax,al
   140003056:	48 83 c4 40          	add    rsp,0x40
   14000305a:	5d                   	pop    rbp
   14000305b:	c3                   	ret

000000014000305c <__mingw_enum_import_library_names>:
   14000305c:	55                   	push   rbp
   14000305d:	48 89 e5             	mov    rbp,rsp
   140003060:	48 83 ec 50          	sub    rsp,0x50
   140003064:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003067:	48 8b 05 f2 22 00 00 	mov    rax,QWORD PTR [rip+0x22f2]        # 140005360 <.refptr.__ImageBase>
   14000306e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003072:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003076:	48 89 c1             	mov    rcx,rax
   140003079:	e8 12 fc ff ff       	call   140002c90 <_ValidateImageBase>
   14000307e:	85 c0                	test   eax,eax
   140003080:	75 0a                	jne    14000308c <__mingw_enum_import_library_names+0x30>
   140003082:	b8 00 00 00 00       	mov    eax,0x0
   140003087:	e9 ab 00 00 00       	jmp    140003137 <__mingw_enum_import_library_names+0xdb>
   14000308c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003090:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003093:	48 63 d0             	movsxd rdx,eax
   140003096:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000309a:	48 01 d0             	add    rax,rdx
   14000309d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400030a1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030a5:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   1400030ab:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400030ae:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400030b2:	75 07                	jne    1400030bb <__mingw_enum_import_library_names+0x5f>
   1400030b4:	b8 00 00 00 00       	mov    eax,0x0
   1400030b9:	eb 7c                	jmp    140003137 <__mingw_enum_import_library_names+0xdb>
   1400030bb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030be:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030c2:	48 89 c1             	mov    rcx,rax
   1400030c5:	e8 42 fc ff ff       	call   140002d0c <_FindPESection>
   1400030ca:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400030ce:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   1400030d3:	75 07                	jne    1400030dc <__mingw_enum_import_library_names+0x80>
   1400030d5:	b8 00 00 00 00       	mov    eax,0x0
   1400030da:	eb 5b                	jmp    140003137 <__mingw_enum_import_library_names+0xdb>
   1400030dc:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030df:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030e3:	48 01 d0             	add    rax,rdx
   1400030e6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030ea:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400030ef:	75 07                	jne    1400030f8 <__mingw_enum_import_library_names+0x9c>
   1400030f1:	b8 00 00 00 00       	mov    eax,0x0
   1400030f6:	eb 3f                	jmp    140003137 <__mingw_enum_import_library_names+0xdb>
   1400030f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030fc:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400030ff:	85 c0                	test   eax,eax
   140003101:	75 0b                	jne    14000310e <__mingw_enum_import_library_names+0xb2>
   140003103:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003107:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000310a:	85 c0                	test   eax,eax
   14000310c:	74 23                	je     140003131 <__mingw_enum_import_library_names+0xd5>
   14000310e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003112:	7f 12                	jg     140003126 <__mingw_enum_import_library_names+0xca>
   140003114:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003118:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000311b:	89 c2                	mov    edx,eax
   14000311d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003121:	48 01 d0             	add    rax,rdx
   140003124:	eb 11                	jmp    140003137 <__mingw_enum_import_library_names+0xdb>
   140003126:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000312a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000312f:	eb c7                	jmp    1400030f8 <__mingw_enum_import_library_names+0x9c>
   140003131:	90                   	nop
   140003132:	b8 00 00 00 00       	mov    eax,0x0
   140003137:	48 83 c4 50          	add    rsp,0x50
   14000313b:	5d                   	pop    rbp
   14000313c:	c3                   	ret
   14000313d:	90                   	nop
   14000313e:	90                   	nop
   14000313f:	90                   	nop

0000000140003140 <___chkstk_ms>:
   140003140:	51                   	push   rcx
   140003141:	50                   	push   rax
   140003142:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003148:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000314d:	72 19                	jb     140003168 <___chkstk_ms+0x28>
   14000314f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003156:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000315a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003160:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003166:	77 e7                	ja     14000314f <___chkstk_ms+0xf>
   140003168:	48 29 c1             	sub    rcx,rax
   14000316b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000316f:	58                   	pop    rax
   140003170:	59                   	pop    rcx
   140003171:	c3                   	ret
   140003172:	90                   	nop
   140003173:	90                   	nop
   140003174:	90                   	nop
   140003175:	90                   	nop
   140003176:	90                   	nop
   140003177:	90                   	nop
   140003178:	90                   	nop
   140003179:	90                   	nop
   14000317a:	90                   	nop
   14000317b:	90                   	nop
   14000317c:	90                   	nop
   14000317d:	90                   	nop
   14000317e:	90                   	nop
   14000317f:	90                   	nop

0000000140003180 <_initterm_e>:
   140003180:	55                   	push   rbp
   140003181:	48 89 e5             	mov    rbp,rsp
   140003184:	48 83 ec 30          	sub    rsp,0x30
   140003188:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000318c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003190:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003194:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003198:	eb 29                	jmp    1400031c3 <_initterm_e+0x43>
   14000319a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000319e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031a1:	48 85 c0             	test   rax,rax
   1400031a4:	74 17                	je     1400031bd <_initterm_e+0x3d>
   1400031a6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031aa:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031ad:	ff d0                	call   rax
   1400031af:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400031b2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   1400031b6:	74 06                	je     1400031be <_initterm_e+0x3e>
   1400031b8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400031bb:	eb 15                	jmp    1400031d2 <_initterm_e+0x52>
   1400031bd:	90                   	nop
   1400031be:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400031c3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031c7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400031cb:	72 cd                	jb     14000319a <_initterm_e+0x1a>
   1400031cd:	b8 00 00 00 00       	mov    eax,0x0
   1400031d2:	48 83 c4 30          	add    rsp,0x30
   1400031d6:	5d                   	pop    rbp
   1400031d7:	c3                   	ret
   1400031d8:	90                   	nop
   1400031d9:	90                   	nop
   1400031da:	90                   	nop
   1400031db:	90                   	nop
   1400031dc:	90                   	nop
   1400031dd:	90                   	nop
   1400031de:	90                   	nop
   1400031df:	90                   	nop

00000001400031e0 <__p__fmode>:
   1400031e0:	55                   	push   rbp
   1400031e1:	48 89 e5             	mov    rbp,rsp
   1400031e4:	48 8b 05 e5 21 00 00 	mov    rax,QWORD PTR [rip+0x21e5]        # 1400053d0 <.refptr.__imp__fmode>
   1400031eb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031ee:	5d                   	pop    rbp
   1400031ef:	c3                   	ret

00000001400031f0 <__p__commode>:
   1400031f0:	55                   	push   rbp
   1400031f1:	48 89 e5             	mov    rbp,rsp
   1400031f4:	48 8b 05 c5 21 00 00 	mov    rax,QWORD PTR [rip+0x21c5]        # 1400053c0 <.refptr.__imp__commode>
   1400031fb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031fe:	5d                   	pop    rbp
   1400031ff:	c3                   	ret

0000000140003200 <__p___initenv>:
   140003200:	55                   	push   rbp
   140003201:	48 89 e5             	mov    rbp,rsp
   140003204:	48 8b 05 a5 21 00 00 	mov    rax,QWORD PTR [rip+0x21a5]        # 1400053b0 <.refptr.__imp___initenv>
   14000320b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000320e:	5d                   	pop    rbp
   14000320f:	c3                   	ret

0000000140003210 <_set_invalid_parameter_handler>:
   140003210:	55                   	push   rbp
   140003211:	48 89 e5             	mov    rbp,rsp
   140003214:	48 83 ec 10          	sub    rsp,0x10
   140003218:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000321c:	48 8d 05 6d 5f 00 00 	lea    rax,[rip+0x5f6d]        # 140009190 <handler>
   140003223:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003227:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000322b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000322f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003233:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003237:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000323a:	48 89 d0             	mov    rax,rdx
   14000323d:	48 83 c4 10          	add    rsp,0x10
   140003241:	5d                   	pop    rbp
   140003242:	c3                   	ret

0000000140003243 <_get_invalid_parameter_handler>:
   140003243:	55                   	push   rbp
   140003244:	48 89 e5             	mov    rbp,rsp
   140003247:	48 8b 05 42 5f 00 00 	mov    rax,QWORD PTR [rip+0x5f42]        # 140009190 <handler>
   14000324e:	5d                   	pop    rbp
   14000324f:	c3                   	ret

0000000140003250 <_configthreadlocale>:
   140003250:	55                   	push   rbp
   140003251:	48 89 e5             	mov    rbp,rsp
   140003254:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003257:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000325b:	75 07                	jne    140003264 <_configthreadlocale+0x14>
   14000325d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140003262:	eb 05                	jmp    140003269 <_configthreadlocale+0x19>
   140003264:	b8 02 00 00 00       	mov    eax,0x2
   140003269:	5d                   	pop    rbp
   14000326a:	c3                   	ret
   14000326b:	90                   	nop
   14000326c:	90                   	nop
   14000326d:	90                   	nop
   14000326e:	90                   	nop
   14000326f:	90                   	nop

0000000140003270 <__acrt_iob_func>:
   140003270:	55                   	push   rbp
   140003271:	48 89 e5             	mov    rbp,rsp
   140003274:	48 83 ec 20          	sub    rsp,0x20
   140003278:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000327b:	e8 30 00 00 00       	call   1400032b0 <__iob_func>
   140003280:	48 89 c1             	mov    rcx,rax
   140003283:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003286:	48 89 d0             	mov    rax,rdx
   140003289:	48 01 c0             	add    rax,rax
   14000328c:	48 01 d0             	add    rax,rdx
   14000328f:	48 c1 e0 04          	shl    rax,0x4
   140003293:	48 01 c8             	add    rax,rcx
   140003296:	48 83 c4 20          	add    rsp,0x20
   14000329a:	5d                   	pop    rbp
   14000329b:	c3                   	ret
   14000329c:	90                   	nop
   14000329d:	90                   	nop
   14000329e:	90                   	nop
   14000329f:	90                   	nop

00000001400032a0 <__C_specific_handler>:
   1400032a0:	ff 25 62 6f 00 00    	jmp    QWORD PTR [rip+0x6f62]        # 14000a208 <__imp___C_specific_handler>
   1400032a6:	90                   	nop
   1400032a7:	90                   	nop

00000001400032a8 <__getmainargs>:
   1400032a8:	ff 25 62 6f 00 00    	jmp    QWORD PTR [rip+0x6f62]        # 14000a210 <__imp___getmainargs>
   1400032ae:	90                   	nop
   1400032af:	90                   	nop

00000001400032b0 <__iob_func>:
   1400032b0:	ff 25 6a 6f 00 00    	jmp    QWORD PTR [rip+0x6f6a]        # 14000a220 <__imp___iob_func>
   1400032b6:	90                   	nop
   1400032b7:	90                   	nop

00000001400032b8 <__set_app_type>:
   1400032b8:	ff 25 6a 6f 00 00    	jmp    QWORD PTR [rip+0x6f6a]        # 14000a228 <__imp___set_app_type>
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <__setusermatherr>:
   1400032c0:	ff 25 6a 6f 00 00    	jmp    QWORD PTR [rip+0x6f6a]        # 14000a230 <__imp___setusermatherr>
   1400032c6:	90                   	nop
   1400032c7:	90                   	nop

00000001400032c8 <_amsg_exit>:
   1400032c8:	ff 25 6a 6f 00 00    	jmp    QWORD PTR [rip+0x6f6a]        # 14000a238 <__imp__amsg_exit>
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <_cexit>:
   1400032d0:	ff 25 6a 6f 00 00    	jmp    QWORD PTR [rip+0x6f6a]        # 14000a240 <__imp__cexit>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop

00000001400032d8 <_initterm>:
   1400032d8:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a258 <__imp__initterm>
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <_crt_atexit>:
   1400032e0:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a260 <__imp__crt_atexit>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <abort>:
   1400032e8:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a268 <__imp_abort>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <calloc>:
   1400032f0:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a270 <__imp_calloc>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <exit>:
   1400032f8:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a278 <__imp_exit>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <fflush>:
   140003300:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a280 <__imp_fflush>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <fprintf>:
   140003308:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a288 <__imp_fprintf>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <free>:
   140003310:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a290 <__imp_free>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <malloc>:
   140003318:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a298 <__imp_malloc>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <memcpy>:
   140003320:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a2a0 <__imp_memcpy>
   140003326:	90                   	nop
   140003327:	90                   	nop

0000000140003328 <memset>:
   140003328:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a2a8 <__imp_memset>
   14000332e:	90                   	nop
   14000332f:	90                   	nop

0000000140003330 <setvbuf>:
   140003330:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a2b0 <__imp_setvbuf>
   140003336:	90                   	nop
   140003337:	90                   	nop

0000000140003338 <signal>:
   140003338:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a2b8 <__imp_signal>
   14000333e:	90                   	nop
   14000333f:	90                   	nop

0000000140003340 <strlen>:
   140003340:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a2c0 <__imp_strlen>
   140003346:	90                   	nop
   140003347:	90                   	nop

0000000140003348 <strncmp>:
   140003348:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a2c8 <__imp_strncmp>
   14000334e:	90                   	nop
   14000334f:	90                   	nop

0000000140003350 <vfprintf>:
   140003350:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a2d0 <__imp_vfprintf>
   140003356:	90                   	nop
   140003357:	90                   	nop
   140003358:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000335f:	00 

0000000140003360 <VirtualQuery>:
   140003360:	ff 25 92 6e 00 00    	jmp    QWORD PTR [rip+0x6e92]        # 14000a1f8 <__imp_VirtualQuery>
   140003366:	90                   	nop
   140003367:	90                   	nop

0000000140003368 <VirtualProtect>:
   140003368:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a1f0 <__imp_VirtualProtect>
   14000336e:	90                   	nop
   14000336f:	90                   	nop

0000000140003370 <TlsGetValue>:
   140003370:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a1e8 <__imp_TlsGetValue>
   140003376:	90                   	nop
   140003377:	90                   	nop

0000000140003378 <Sleep>:
   140003378:	ff 25 62 6e 00 00    	jmp    QWORD PTR [rip+0x6e62]        # 14000a1e0 <__imp_Sleep>
   14000337e:	90                   	nop
   14000337f:	90                   	nop

0000000140003380 <SetUnhandledExceptionFilter>:
   140003380:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   140003386:	90                   	nop
   140003387:	90                   	nop

0000000140003388 <LoadLibraryA>:
   140003388:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 14000a1d0 <__imp_LoadLibraryA>
   14000338e:	90                   	nop
   14000338f:	90                   	nop

0000000140003390 <LeaveCriticalSection>:
   140003390:	ff 25 32 6e 00 00    	jmp    QWORD PTR [rip+0x6e32]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140003396:	90                   	nop
   140003397:	90                   	nop

0000000140003398 <InitializeCriticalSection>:
   140003398:	ff 25 22 6e 00 00    	jmp    QWORD PTR [rip+0x6e22]        # 14000a1c0 <__imp_InitializeCriticalSection>
   14000339e:	90                   	nop
   14000339f:	90                   	nop

00000001400033a0 <GetProcAddress>:
   1400033a0:	ff 25 12 6e 00 00    	jmp    QWORD PTR [rip+0x6e12]        # 14000a1b8 <__imp_GetProcAddress>
   1400033a6:	90                   	nop
   1400033a7:	90                   	nop

00000001400033a8 <GetModuleHandleA>:
   1400033a8:	ff 25 02 6e 00 00    	jmp    QWORD PTR [rip+0x6e02]        # 14000a1b0 <__imp_GetModuleHandleA>
   1400033ae:	90                   	nop
   1400033af:	90                   	nop

00000001400033b0 <GetLastError>:
   1400033b0:	ff 25 f2 6d 00 00    	jmp    QWORD PTR [rip+0x6df2]        # 14000a1a8 <__imp_GetLastError>
   1400033b6:	90                   	nop
   1400033b7:	90                   	nop

00000001400033b8 <FreeLibrary>:
   1400033b8:	ff 25 e2 6d 00 00    	jmp    QWORD PTR [rip+0x6de2]        # 14000a1a0 <__imp_FreeLibrary>
   1400033be:	90                   	nop
   1400033bf:	90                   	nop

00000001400033c0 <EnterCriticalSection>:
   1400033c0:	ff 25 d2 6d 00 00    	jmp    QWORD PTR [rip+0x6dd2]        # 14000a198 <__imp_EnterCriticalSection>
   1400033c6:	90                   	nop
   1400033c7:	90                   	nop

00000001400033c8 <DeleteCriticalSection>:
   1400033c8:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 14000a190 <__IAT_start__>
   1400033ce:	90                   	nop
   1400033cf:	90                   	nop

00000001400033d0 <register_frame_ctor>:
   1400033d0:	e9 9b e2 ff ff       	jmp    140001670 <__gcc_register_frame>
   1400033d5:	90                   	nop
   1400033d6:	90                   	nop
   1400033d7:	90                   	nop
   1400033d8:	90                   	nop
   1400033d9:	90                   	nop
   1400033da:	90                   	nop
   1400033db:	90                   	nop
   1400033dc:	90                   	nop
   1400033dd:	90                   	nop
   1400033de:	90                   	nop
   1400033df:	90                   	nop
