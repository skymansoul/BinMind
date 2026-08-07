
C:\Users\Administrator\Desktop\BinMind\round2\samples\heap_overflow\cve_2023_38545_curl\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 c7 22 00 00       	call   1400032f0 <fflush>
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
   14000113b:	e8 78 21 00 00       	call   1400032b8 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 f8 20 00 00       	call   140003260 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 9f 21 00 00       	call   140003320 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 3f 21 00 00       	call   1400032d8 <abort>
   140001199:	e8 c2 11 00 00       	call   140002360 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 29 90 00 00 	mov    rax,QWORD PTR [rip+0x9029]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 36 20 00 00       	call   140003200 <_set_invalid_parameter_handler>
   1400011ca:	e8 a1 1a 00 00       	call   140002c70 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 b7 20 00 00       	call   1400032a8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 ab 20 00 00       	call   1400032a8 <__set_app_type>
   1400011fd:	e8 ce 1f 00 00       	call   1400031d0 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 ce 1f 00 00       	call   1400031e0 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 1e 07 00 00       	call   140001940 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 83 20 00 00       	call   1400032b8 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 28 12 00 00       	call   14000247a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 d6 1f 00 00       	call   140003240 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 f0 1e 00 00       	call   140003170 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 2a 20 00 00       	call   1400032b8 <_amsg_exit>
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
   1400012cb:	e8 c8 1f 00 00       	call   140003298 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 d5 1f 00 00       	call   1400032b8 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 ae 1f 00 00       	call   1400032b8 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 a8 1f 00 00       	call   1400032c8 <_initterm>
   140001320:	e8 f2 05 00 00       	call   140001917 <__main>
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
   14000138d:	e8 5e 1e 00 00       	call   1400031f0 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 27 04 00 00       	call   1400017e1 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 17 1f 00 00       	call   1400032e8 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 e0 1e 00 00       	call   1400032c0 <_cexit>
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
   140001511:	e8 f2 1d 00 00       	call   140003308 <malloc>
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
   14000155c:	e8 cf 1d 00 00       	call   140003330 <strlen>
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
   140001585:	e8 7e 1d 00 00       	call   140003308 <malloc>
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
   1400015e8:	e8 23 1d 00 00       	call   140003310 <memcpy>
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
   140001642:	e8 89 1c 00 00       	call   1400032d0 <_crt_atexit>
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

0000000140001760 <build_socks5>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 30          	sub    rsp,0x30
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001770:	48 89 c1             	mov    rcx,rax
   140001773:	e8 b8 1b 00 00       	call   140003330 <strlen>
   140001778:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000177c:	b9 06 01 00 00       	mov    ecx,0x106
   140001781:	e8 82 1b 00 00       	call   140003308 <malloc>
   140001786:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000178a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000178f:	75 07                	jne    140001798 <build_socks5+0x38>
   140001791:	b8 00 00 00 00       	mov    eax,0x0
   140001796:	eb 43                	jmp    1400017db <build_socks5+0x7b>
   140001798:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000179c:	c6 00 05             	mov    BYTE PTR [rax],0x5
   14000179f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017a3:	c6 40 01 01          	mov    BYTE PTR [rax+0x1],0x1
   1400017a7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017ab:	c6 40 02 00          	mov    BYTE PTR [rax+0x2],0x0
   1400017af:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017b3:	89 c2                	mov    edx,eax
   1400017b5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017b9:	88 50 06             	mov    BYTE PTR [rax+0x6],dl
   1400017bc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017c0:	48 8d 48 07          	lea    rcx,[rax+0x7]
   1400017c4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400017c8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017cc:	49 89 d0             	mov    r8,rdx
   1400017cf:	48 89 c2             	mov    rdx,rax
   1400017d2:	e8 39 1b 00 00       	call   140003310 <memcpy>
   1400017d7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017db:	48 83 c4 30          	add    rsp,0x30
   1400017df:	5d                   	pop    rbp
   1400017e0:	c3                   	ret

00000001400017e1 <main>:
   1400017e1:	55                   	push   rbp
   1400017e2:	48 81 ec 30 02 00 00 	sub    rsp,0x230
   1400017e9:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   1400017f0:	00 
   1400017f1:	89 8d c0 01 00 00    	mov    DWORD PTR [rbp+0x1c0],ecx
   1400017f7:	48 89 95 c8 01 00 00 	mov    QWORD PTR [rbp+0x1c8],rdx
   1400017fe:	e8 14 01 00 00       	call   140001917 <__main>
   140001803:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140001807:	41 b8 2c 01 00 00    	mov    r8d,0x12c
   14000180d:	ba 48 00 00 00       	mov    edx,0x48
   140001812:	48 89 c1             	mov    rcx,rax
   140001815:	e8 fe 1a 00 00       	call   140003318 <memset>
   14000181a:	c6 85 cc 00 00 00 00 	mov    BYTE PTR [rbp+0xcc],0x0
   140001821:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140001825:	48 89 c1             	mov    rcx,rax
   140001828:	e8 33 ff ff ff       	call   140001760 <build_socks5>
   14000182d:	48 89 85 a8 01 00 00 	mov    QWORD PTR [rbp+0x1a8],rax
   140001834:	48 83 bd a8 01 00 00 	cmp    QWORD PTR [rbp+0x1a8],0x0
   14000183b:	00 
   14000183c:	74 0f                	je     14000184d <main+0x6c>
   14000183e:	48 8b 85 a8 01 00 00 	mov    rax,QWORD PTR [rbp+0x1a8]
   140001845:	48 89 c1             	mov    rcx,rax
   140001848:	e8 b3 1a 00 00       	call   140003300 <free>
   14000184d:	b8 00 00 00 00       	mov    eax,0x0
   140001852:	48 81 c4 30 02 00 00 	add    rsp,0x230
   140001859:	5d                   	pop    rbp
   14000185a:	c3                   	ret
   14000185b:	90                   	nop
   14000185c:	90                   	nop
   14000185d:	90                   	nop
   14000185e:	90                   	nop
   14000185f:	90                   	nop

0000000140001860 <__do_global_dtors>:
   140001860:	55                   	push   rbp
   140001861:	48 89 e5             	mov    rbp,rsp
   140001864:	48 83 ec 20          	sub    rsp,0x20
   140001868:	eb 1e                	jmp    140001888 <__do_global_dtors+0x28>
   14000186a:	48 8b 05 9f 27 00 00 	mov    rax,QWORD PTR [rip+0x279f]        # 140004010 <p.0>
   140001871:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001874:	ff d0                	call   rax
   140001876:	48 8b 05 93 27 00 00 	mov    rax,QWORD PTR [rip+0x2793]        # 140004010 <p.0>
   14000187d:	48 83 c0 08          	add    rax,0x8
   140001881:	48 89 05 88 27 00 00 	mov    QWORD PTR [rip+0x2788],rax        # 140004010 <p.0>
   140001888:	48 8b 05 81 27 00 00 	mov    rax,QWORD PTR [rip+0x2781]        # 140004010 <p.0>
   14000188f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001892:	48 85 c0             	test   rax,rax
   140001895:	75 d3                	jne    14000186a <__do_global_dtors+0xa>
   140001897:	90                   	nop
   140001898:	90                   	nop
   140001899:	48 83 c4 20          	add    rsp,0x20
   14000189d:	5d                   	pop    rbp
   14000189e:	c3                   	ret

000000014000189f <__do_global_ctors>:
   14000189f:	55                   	push   rbp
   1400018a0:	48 89 e5             	mov    rbp,rsp
   1400018a3:	48 83 ec 30          	sub    rsp,0x30
   1400018a7:	48 8b 05 a2 3a 00 00 	mov    rax,QWORD PTR [rip+0x3aa2]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018ae:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018b1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400018b4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400018b8:	75 25                	jne    1400018df <__do_global_ctors+0x40>
   1400018ba:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400018c1:	eb 04                	jmp    1400018c7 <__do_global_ctors+0x28>
   1400018c3:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400018c7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018ca:	8d 50 01             	lea    edx,[rax+0x1]
   1400018cd:	48 8b 05 7c 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a7c]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018d4:	89 d2                	mov    edx,edx
   1400018d6:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018da:	48 85 c0             	test   rax,rax
   1400018dd:	75 e4                	jne    1400018c3 <__do_global_ctors+0x24>
   1400018df:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018e2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400018e5:	eb 14                	jmp    1400018fb <__do_global_ctors+0x5c>
   1400018e7:	48 8b 05 62 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a62]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018ee:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400018f1:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018f5:	ff d0                	call   rax
   1400018f7:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400018fb:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400018ff:	75 e6                	jne    1400018e7 <__do_global_ctors+0x48>
   140001901:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001860 <__do_global_dtors>
   140001908:	48 89 c1             	mov    rcx,rax
   14000190b:	e8 1f fd ff ff       	call   14000162f <atexit>
   140001910:	90                   	nop
   140001911:	48 83 c4 30          	add    rsp,0x30
   140001915:	5d                   	pop    rbp
   140001916:	c3                   	ret

0000000140001917 <__main>:
   140001917:	55                   	push   rbp
   140001918:	48 89 e5             	mov    rbp,rsp
   14000191b:	48 83 ec 20          	sub    rsp,0x20
   14000191f:	8b 05 5b 77 00 00    	mov    eax,DWORD PTR [rip+0x775b]        # 140009080 <initialized>
   140001925:	85 c0                	test   eax,eax
   140001927:	75 0f                	jne    140001938 <__main+0x21>
   140001929:	c7 05 4d 77 00 00 01 	mov    DWORD PTR [rip+0x774d],0x1        # 140009080 <initialized>
   140001930:	00 00 00 
   140001933:	e8 67 ff ff ff       	call   14000189f <__do_global_ctors>
   140001938:	90                   	nop
   140001939:	48 83 c4 20          	add    rsp,0x20
   14000193d:	5d                   	pop    rbp
   14000193e:	c3                   	ret
   14000193f:	90                   	nop

0000000140001940 <_setargv>:
   140001940:	55                   	push   rbp
   140001941:	48 89 e5             	mov    rbp,rsp
   140001944:	b8 00 00 00 00       	mov    eax,0x0
   140001949:	5d                   	pop    rbp
   14000194a:	c3                   	ret
   14000194b:	90                   	nop
   14000194c:	90                   	nop
   14000194d:	90                   	nop
   14000194e:	90                   	nop
   14000194f:	90                   	nop

0000000140001950 <__dyn_tls_init>:
   140001950:	55                   	push   rbp
   140001951:	48 89 e5             	mov    rbp,rsp
   140001954:	48 83 ec 30          	sub    rsp,0x30
   140001958:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000195c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000195f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001963:	48 8b 05 c6 39 00 00 	mov    rax,QWORD PTR [rip+0x39c6]        # 140005330 <.refptr._CRT_MT>
   14000196a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000196c:	83 f8 02             	cmp    eax,0x2
   14000196f:	74 0d                	je     14000197e <__dyn_tls_init+0x2e>
   140001971:	48 8b 05 b8 39 00 00 	mov    rax,QWORD PTR [rip+0x39b8]        # 140005330 <.refptr._CRT_MT>
   140001978:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000197e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001982:	74 1e                	je     1400019a2 <__dyn_tls_init+0x52>
   140001984:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001988:	75 5b                	jne    1400019e5 <__dyn_tls_init+0x95>
   14000198a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000198e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001991:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001995:	49 89 c8             	mov    r8,rcx
   140001998:	48 89 c1             	mov    rcx,rax
   14000199b:	e8 d1 11 00 00       	call   140002b71 <__mingw_TLScallback>
   1400019a0:	eb 43                	jmp    1400019e5 <__dyn_tls_init+0x95>
   1400019a2:	48 8d 05 ef 3c 00 00 	lea    rax,[rip+0x3cef]        # 140005698 <___crt_xd_start__>
   1400019a9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400019ad:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019b2:	eb 22                	jmp    1400019d6 <__dyn_tls_init+0x86>
   1400019b4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400019b8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400019bc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019c0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019c3:	48 85 c0             	test   rax,rax
   1400019c6:	74 09                	je     1400019d1 <__dyn_tls_init+0x81>
   1400019c8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019cc:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019cf:	ff d0                	call   rax
   1400019d1:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019d6:	48 8d 05 c3 3c 00 00 	lea    rax,[rip+0x3cc3]        # 1400056a0 <__xd_z>
   1400019dd:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   1400019e1:	75 d1                	jne    1400019b4 <__dyn_tls_init+0x64>
   1400019e3:	eb 01                	jmp    1400019e6 <__dyn_tls_init+0x96>
   1400019e5:	90                   	nop
   1400019e6:	48 83 c4 30          	add    rsp,0x30
   1400019ea:	5d                   	pop    rbp
   1400019eb:	c3                   	ret

00000001400019ec <__tlregdtor>:
   1400019ec:	55                   	push   rbp
   1400019ed:	48 89 e5             	mov    rbp,rsp
   1400019f0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019f4:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400019f9:	75 07                	jne    140001a02 <__tlregdtor+0x16>
   1400019fb:	b8 00 00 00 00       	mov    eax,0x0
   140001a00:	eb 05                	jmp    140001a07 <__tlregdtor+0x1b>
   140001a02:	b8 00 00 00 00       	mov    eax,0x0
   140001a07:	5d                   	pop    rbp
   140001a08:	c3                   	ret

0000000140001a09 <__dyn_tls_dtor>:
   140001a09:	55                   	push   rbp
   140001a0a:	48 89 e5             	mov    rbp,rsp
   140001a0d:	48 83 ec 20          	sub    rsp,0x20
   140001a11:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a15:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a18:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a1c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a20:	74 06                	je     140001a28 <__dyn_tls_dtor+0x1f>
   140001a22:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a26:	75 18                	jne    140001a40 <__dyn_tls_dtor+0x37>
   140001a28:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a2c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a2f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a33:	49 89 c8             	mov    r8,rcx
   140001a36:	48 89 c1             	mov    rcx,rax
   140001a39:	e8 33 11 00 00       	call   140002b71 <__mingw_TLScallback>
   140001a3e:	eb 01                	jmp    140001a41 <__dyn_tls_dtor+0x38>
   140001a40:	90                   	nop
   140001a41:	48 83 c4 20          	add    rsp,0x20
   140001a45:	5d                   	pop    rbp
   140001a46:	c3                   	ret
   140001a47:	90                   	nop
   140001a48:	90                   	nop
   140001a49:	90                   	nop
   140001a4a:	90                   	nop
   140001a4b:	90                   	nop
   140001a4c:	90                   	nop
   140001a4d:	90                   	nop
   140001a4e:	90                   	nop
   140001a4f:	90                   	nop

0000000140001a50 <_matherr>:
   140001a50:	55                   	push   rbp
   140001a51:	53                   	push   rbx
   140001a52:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a59:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a5e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a62:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a66:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a6b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a6f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a73:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a75:	83 f8 06             	cmp    eax,0x6
   140001a78:	74 56                	je     140001ad0 <_matherr+0x80>
   140001a7a:	83 f8 06             	cmp    eax,0x6
   140001a7d:	7f 78                	jg     140001af7 <_matherr+0xa7>
   140001a7f:	83 f8 05             	cmp    eax,0x5
   140001a82:	74 59                	je     140001add <_matherr+0x8d>
   140001a84:	83 f8 05             	cmp    eax,0x5
   140001a87:	7f 6e                	jg     140001af7 <_matherr+0xa7>
   140001a89:	83 f8 04             	cmp    eax,0x4
   140001a8c:	74 5c                	je     140001aea <_matherr+0x9a>
   140001a8e:	83 f8 04             	cmp    eax,0x4
   140001a91:	7f 64                	jg     140001af7 <_matherr+0xa7>
   140001a93:	83 f8 03             	cmp    eax,0x3
   140001a96:	74 2b                	je     140001ac3 <_matherr+0x73>
   140001a98:	83 f8 03             	cmp    eax,0x3
   140001a9b:	7f 5a                	jg     140001af7 <_matherr+0xa7>
   140001a9d:	83 f8 01             	cmp    eax,0x1
   140001aa0:	74 07                	je     140001aa9 <_matherr+0x59>
   140001aa2:	83 f8 02             	cmp    eax,0x2
   140001aa5:	74 0f                	je     140001ab6 <_matherr+0x66>
   140001aa7:	eb 4e                	jmp    140001af7 <_matherr+0xa7>
   140001aa9:	48 8d 05 f0 35 00 00 	lea    rax,[rip+0x35f0]        # 1400050a0 <.rdata>
   140001ab0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ab4:	eb 4d                	jmp    140001b03 <_matherr+0xb3>
   140001ab6:	48 8d 05 02 36 00 00 	lea    rax,[rip+0x3602]        # 1400050bf <.rdata+0x1f>
   140001abd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ac1:	eb 40                	jmp    140001b03 <_matherr+0xb3>
   140001ac3:	48 8d 05 16 36 00 00 	lea    rax,[rip+0x3616]        # 1400050e0 <.rdata+0x40>
   140001aca:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ace:	eb 33                	jmp    140001b03 <_matherr+0xb3>
   140001ad0:	48 8d 05 29 36 00 00 	lea    rax,[rip+0x3629]        # 140005100 <.rdata+0x60>
   140001ad7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001adb:	eb 26                	jmp    140001b03 <_matherr+0xb3>
   140001add:	48 8d 05 44 36 00 00 	lea    rax,[rip+0x3644]        # 140005128 <.rdata+0x88>
   140001ae4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ae8:	eb 19                	jmp    140001b03 <_matherr+0xb3>
   140001aea:	48 8d 05 5f 36 00 00 	lea    rax,[rip+0x365f]        # 140005150 <.rdata+0xb0>
   140001af1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001af5:	eb 0c                	jmp    140001b03 <_matherr+0xb3>
   140001af7:	48 8d 05 88 36 00 00 	lea    rax,[rip+0x3688]        # 140005186 <.rdata+0xe6>
   140001afe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b02:	90                   	nop
   140001b03:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b07:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b0d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b11:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b16:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b1a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b1f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b23:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b27:	b9 02 00 00 00       	mov    ecx,0x2
   140001b2c:	e8 2f 17 00 00       	call   140003260 <__acrt_iob_func>
   140001b31:	48 89 c1             	mov    rcx,rax
   140001b34:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b38:	48 8d 05 59 36 00 00 	lea    rax,[rip+0x3659]        # 140005198 <.rdata+0xf8>
   140001b3f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b46:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b4c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b52:	49 89 d9             	mov    r9,rbx
   140001b55:	49 89 d0             	mov    r8,rdx
   140001b58:	48 89 c2             	mov    rdx,rax
   140001b5b:	e8 98 17 00 00       	call   1400032f8 <fprintf>
   140001b60:	b8 00 00 00 00       	mov    eax,0x0
   140001b65:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b69:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b6d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b72:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b79:	5b                   	pop    rbx
   140001b7a:	5d                   	pop    rbp
   140001b7b:	c3                   	ret
   140001b7c:	90                   	nop
   140001b7d:	90                   	nop
   140001b7e:	90                   	nop
   140001b7f:	90                   	nop

0000000140001b80 <__report_error>:
   140001b80:	55                   	push   rbp
   140001b81:	53                   	push   rbx
   140001b82:	48 83 ec 38          	sub    rsp,0x38
   140001b86:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b8b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b8f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b93:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b97:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b9b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b9f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ba3:	b9 02 00 00 00       	mov    ecx,0x2
   140001ba8:	e8 b3 16 00 00       	call   140003260 <__acrt_iob_func>
   140001bad:	48 89 c1             	mov    rcx,rax
   140001bb0:	48 8d 05 19 36 00 00 	lea    rax,[rip+0x3619]        # 1400051d0 <.rdata>
   140001bb7:	48 89 c2             	mov    rdx,rax
   140001bba:	e8 39 17 00 00       	call   1400032f8 <fprintf>
   140001bbf:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001bc3:	b9 02 00 00 00       	mov    ecx,0x2
   140001bc8:	e8 93 16 00 00       	call   140003260 <__acrt_iob_func>
   140001bcd:	48 89 c1             	mov    rcx,rax
   140001bd0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001bd4:	49 89 d8             	mov    r8,rbx
   140001bd7:	48 89 c2             	mov    rdx,rax
   140001bda:	e8 61 17 00 00       	call   140003340 <vfprintf>
   140001bdf:	e8 f4 16 00 00       	call   1400032d8 <abort>
   140001be4:	90                   	nop

0000000140001be5 <mark_section_writable>:
   140001be5:	55                   	push   rbp
   140001be6:	48 89 e5             	mov    rbp,rsp
   140001be9:	48 83 ec 60          	sub    rsp,0x60
   140001bed:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001bf1:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001bf8:	e9 82 00 00 00       	jmp    140001c7f <mark_section_writable+0x9a>
   140001bfd:	48 8b 0d dc 74 00 00 	mov    rcx,QWORD PTR [rip+0x74dc]        # 1400090e0 <the_secs>
   140001c04:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c07:	48 63 d0             	movsxd rdx,eax
   140001c0a:	48 89 d0             	mov    rax,rdx
   140001c0d:	48 c1 e0 02          	shl    rax,0x2
   140001c11:	48 01 d0             	add    rax,rdx
   140001c14:	48 c1 e0 03          	shl    rax,0x3
   140001c18:	48 01 c8             	add    rax,rcx
   140001c1b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c1f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c23:	72 56                	jb     140001c7b <mark_section_writable+0x96>
   140001c25:	48 8b 0d b4 74 00 00 	mov    rcx,QWORD PTR [rip+0x74b4]        # 1400090e0 <the_secs>
   140001c2c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c2f:	48 63 d0             	movsxd rdx,eax
   140001c32:	48 89 d0             	mov    rax,rdx
   140001c35:	48 c1 e0 02          	shl    rax,0x2
   140001c39:	48 01 d0             	add    rax,rdx
   140001c3c:	48 c1 e0 03          	shl    rax,0x3
   140001c40:	48 01 c8             	add    rax,rcx
   140001c43:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c47:	4c 8b 05 92 74 00 00 	mov    r8,QWORD PTR [rip+0x7492]        # 1400090e0 <the_secs>
   140001c4e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c51:	48 63 d0             	movsxd rdx,eax
   140001c54:	48 89 d0             	mov    rax,rdx
   140001c57:	48 c1 e0 02          	shl    rax,0x2
   140001c5b:	48 01 d0             	add    rax,rdx
   140001c5e:	48 c1 e0 03          	shl    rax,0x3
   140001c62:	4c 01 c0             	add    rax,r8
   140001c65:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c69:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c6c:	89 c0                	mov    eax,eax
   140001c6e:	48 01 c8             	add    rax,rcx
   140001c71:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c75:	0f 82 41 02 00 00    	jb     140001ebc <mark_section_writable+0x2d7>
   140001c7b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c7f:	8b 05 63 74 00 00    	mov    eax,DWORD PTR [rip+0x7463]        # 1400090e8 <maxSections>
   140001c85:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c88:	0f 8c 6f ff ff ff    	jl     140001bfd <mark_section_writable+0x18>
   140001c8e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c92:	48 89 c1             	mov    rcx,rax
   140001c95:	e8 c1 11 00 00       	call   140002e5b <__mingw_GetSectionForAddress>
   140001c9a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c9e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001ca3:	75 13                	jne    140001cb8 <mark_section_writable+0xd3>
   140001ca5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001ca9:	48 8d 0d 40 35 00 00 	lea    rcx,[rip+0x3540]        # 1400051f0 <.rdata+0x20>
   140001cb0:	48 89 c2             	mov    rdx,rax
   140001cb3:	e8 c8 fe ff ff       	call   140001b80 <__report_error>
   140001cb8:	48 8b 0d 21 74 00 00 	mov    rcx,QWORD PTR [rip+0x7421]        # 1400090e0 <the_secs>
   140001cbf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cc2:	48 63 d0             	movsxd rdx,eax
   140001cc5:	48 89 d0             	mov    rax,rdx
   140001cc8:	48 c1 e0 02          	shl    rax,0x2
   140001ccc:	48 01 d0             	add    rax,rdx
   140001ccf:	48 c1 e0 03          	shl    rax,0x3
   140001cd3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001cd7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001cdb:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001cdf:	48 8b 0d fa 73 00 00 	mov    rcx,QWORD PTR [rip+0x73fa]        # 1400090e0 <the_secs>
   140001ce6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ce9:	48 63 d0             	movsxd rdx,eax
   140001cec:	48 89 d0             	mov    rax,rdx
   140001cef:	48 c1 e0 02          	shl    rax,0x2
   140001cf3:	48 01 d0             	add    rax,rdx
   140001cf6:	48 c1 e0 03          	shl    rax,0x3
   140001cfa:	48 01 c8             	add    rax,rcx
   140001cfd:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d03:	e8 9f 12 00 00       	call   140002fa7 <_GetPEImageBase>
   140001d08:	48 89 c1             	mov    rcx,rax
   140001d0b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d0f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d12:	41 89 c1             	mov    r9d,eax
   140001d15:	4c 8b 05 c4 73 00 00 	mov    r8,QWORD PTR [rip+0x73c4]        # 1400090e0 <the_secs>
   140001d1c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d1f:	48 63 d0             	movsxd rdx,eax
   140001d22:	48 89 d0             	mov    rax,rdx
   140001d25:	48 c1 e0 02          	shl    rax,0x2
   140001d29:	48 01 d0             	add    rax,rdx
   140001d2c:	48 c1 e0 03          	shl    rax,0x3
   140001d30:	4c 01 c0             	add    rax,r8
   140001d33:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d37:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d3b:	48 8b 0d 9e 73 00 00 	mov    rcx,QWORD PTR [rip+0x739e]        # 1400090e0 <the_secs>
   140001d42:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d45:	48 63 d0             	movsxd rdx,eax
   140001d48:	48 89 d0             	mov    rax,rdx
   140001d4b:	48 c1 e0 02          	shl    rax,0x2
   140001d4f:	48 01 d0             	add    rax,rdx
   140001d52:	48 c1 e0 03          	shl    rax,0x3
   140001d56:	48 01 c8             	add    rax,rcx
   140001d59:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d5d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d61:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d67:	48 89 c1             	mov    rcx,rax
   140001d6a:	48 8b 05 87 84 00 00 	mov    rax,QWORD PTR [rip+0x8487]        # 14000a1f8 <__imp_VirtualQuery>
   140001d71:	ff d0                	call   rax
   140001d73:	48 85 c0             	test   rax,rax
   140001d76:	75 3f                	jne    140001db7 <mark_section_writable+0x1d2>
   140001d78:	48 8b 0d 61 73 00 00 	mov    rcx,QWORD PTR [rip+0x7361]        # 1400090e0 <the_secs>
   140001d7f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d82:	48 63 d0             	movsxd rdx,eax
   140001d85:	48 89 d0             	mov    rax,rdx
   140001d88:	48 c1 e0 02          	shl    rax,0x2
   140001d8c:	48 01 d0             	add    rax,rdx
   140001d8f:	48 c1 e0 03          	shl    rax,0x3
   140001d93:	48 01 c8             	add    rax,rcx
   140001d96:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d9a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d9e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001da1:	89 c1                	mov    ecx,eax
   140001da3:	48 8d 05 66 34 00 00 	lea    rax,[rip+0x3466]        # 140005210 <.rdata+0x40>
   140001daa:	49 89 d0             	mov    r8,rdx
   140001dad:	89 ca                	mov    edx,ecx
   140001daf:	48 89 c1             	mov    rcx,rax
   140001db2:	e8 c9 fd ff ff       	call   140001b80 <__report_error>
   140001db7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dba:	83 f8 40             	cmp    eax,0x40
   140001dbd:	0f 84 e8 00 00 00    	je     140001eab <mark_section_writable+0x2c6>
   140001dc3:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dc6:	83 f8 04             	cmp    eax,0x4
   140001dc9:	0f 84 dc 00 00 00    	je     140001eab <mark_section_writable+0x2c6>
   140001dcf:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dd2:	3d 80 00 00 00       	cmp    eax,0x80
   140001dd7:	0f 84 ce 00 00 00    	je     140001eab <mark_section_writable+0x2c6>
   140001ddd:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001de0:	83 f8 08             	cmp    eax,0x8
   140001de3:	0f 84 c2 00 00 00    	je     140001eab <mark_section_writable+0x2c6>
   140001de9:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dec:	83 f8 02             	cmp    eax,0x2
   140001def:	75 09                	jne    140001dfa <mark_section_writable+0x215>
   140001df1:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001df8:	eb 07                	jmp    140001e01 <mark_section_writable+0x21c>
   140001dfa:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e01:	48 8b 0d d8 72 00 00 	mov    rcx,QWORD PTR [rip+0x72d8]        # 1400090e0 <the_secs>
   140001e08:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e0b:	48 63 d0             	movsxd rdx,eax
   140001e0e:	48 89 d0             	mov    rax,rdx
   140001e11:	48 c1 e0 02          	shl    rax,0x2
   140001e15:	48 01 d0             	add    rax,rdx
   140001e18:	48 c1 e0 03          	shl    rax,0x3
   140001e1c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e20:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e24:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e28:	48 8b 0d b1 72 00 00 	mov    rcx,QWORD PTR [rip+0x72b1]        # 1400090e0 <the_secs>
   140001e2f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e32:	48 63 d0             	movsxd rdx,eax
   140001e35:	48 89 d0             	mov    rax,rdx
   140001e38:	48 c1 e0 02          	shl    rax,0x2
   140001e3c:	48 01 d0             	add    rax,rdx
   140001e3f:	48 c1 e0 03          	shl    rax,0x3
   140001e43:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e47:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e4b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e4f:	48 8b 0d 8a 72 00 00 	mov    rcx,QWORD PTR [rip+0x728a]        # 1400090e0 <the_secs>
   140001e56:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e59:	48 63 d0             	movsxd rdx,eax
   140001e5c:	48 89 d0             	mov    rax,rdx
   140001e5f:	48 c1 e0 02          	shl    rax,0x2
   140001e63:	48 01 d0             	add    rax,rdx
   140001e66:	48 c1 e0 03          	shl    rax,0x3
   140001e6a:	48 01 c8             	add    rax,rcx
   140001e6d:	49 89 c0             	mov    r8,rax
   140001e70:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e74:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e78:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e7b:	4d 89 c1             	mov    r9,r8
   140001e7e:	41 89 c8             	mov    r8d,ecx
   140001e81:	48 89 c1             	mov    rcx,rax
   140001e84:	48 8b 05 65 83 00 00 	mov    rax,QWORD PTR [rip+0x8365]        # 14000a1f0 <__imp_VirtualProtect>
   140001e8b:	ff d0                	call   rax
   140001e8d:	85 c0                	test   eax,eax
   140001e8f:	75 1a                	jne    140001eab <mark_section_writable+0x2c6>
   140001e91:	48 8b 05 10 83 00 00 	mov    rax,QWORD PTR [rip+0x8310]        # 14000a1a8 <__imp_GetLastError>
   140001e98:	ff d0                	call   rax
   140001e9a:	89 c2                	mov    edx,eax
   140001e9c:	48 8d 05 a5 33 00 00 	lea    rax,[rip+0x33a5]        # 140005248 <.rdata+0x78>
   140001ea3:	48 89 c1             	mov    rcx,rax
   140001ea6:	e8 d5 fc ff ff       	call   140001b80 <__report_error>
   140001eab:	8b 05 37 72 00 00    	mov    eax,DWORD PTR [rip+0x7237]        # 1400090e8 <maxSections>
   140001eb1:	83 c0 01             	add    eax,0x1
   140001eb4:	89 05 2e 72 00 00    	mov    DWORD PTR [rip+0x722e],eax        # 1400090e8 <maxSections>
   140001eba:	eb 01                	jmp    140001ebd <mark_section_writable+0x2d8>
   140001ebc:	90                   	nop
   140001ebd:	48 83 c4 60          	add    rsp,0x60
   140001ec1:	5d                   	pop    rbp
   140001ec2:	c3                   	ret

0000000140001ec3 <restore_modified_sections>:
   140001ec3:	55                   	push   rbp
   140001ec4:	48 89 e5             	mov    rbp,rsp
   140001ec7:	48 83 ec 30          	sub    rsp,0x30
   140001ecb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001ed2:	e9 ad 00 00 00       	jmp    140001f84 <restore_modified_sections+0xc1>
   140001ed7:	48 8b 0d 02 72 00 00 	mov    rcx,QWORD PTR [rip+0x7202]        # 1400090e0 <the_secs>
   140001ede:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ee1:	48 63 d0             	movsxd rdx,eax
   140001ee4:	48 89 d0             	mov    rax,rdx
   140001ee7:	48 c1 e0 02          	shl    rax,0x2
   140001eeb:	48 01 d0             	add    rax,rdx
   140001eee:	48 c1 e0 03          	shl    rax,0x3
   140001ef2:	48 01 c8             	add    rax,rcx
   140001ef5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ef7:	85 c0                	test   eax,eax
   140001ef9:	0f 84 80 00 00 00    	je     140001f7f <restore_modified_sections+0xbc>
   140001eff:	48 8b 0d da 71 00 00 	mov    rcx,QWORD PTR [rip+0x71da]        # 1400090e0 <the_secs>
   140001f06:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f09:	48 63 d0             	movsxd rdx,eax
   140001f0c:	48 89 d0             	mov    rax,rdx
   140001f0f:	48 c1 e0 02          	shl    rax,0x2
   140001f13:	48 01 d0             	add    rax,rdx
   140001f16:	48 c1 e0 03          	shl    rax,0x3
   140001f1a:	48 01 c8             	add    rax,rcx
   140001f1d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f20:	48 8b 0d b9 71 00 00 	mov    rcx,QWORD PTR [rip+0x71b9]        # 1400090e0 <the_secs>
   140001f27:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f2a:	48 63 d0             	movsxd rdx,eax
   140001f2d:	48 89 d0             	mov    rax,rdx
   140001f30:	48 c1 e0 02          	shl    rax,0x2
   140001f34:	48 01 d0             	add    rax,rdx
   140001f37:	48 c1 e0 03          	shl    rax,0x3
   140001f3b:	48 01 c8             	add    rax,rcx
   140001f3e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f42:	4c 8b 05 97 71 00 00 	mov    r8,QWORD PTR [rip+0x7197]        # 1400090e0 <the_secs>
   140001f49:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f4c:	48 63 d0             	movsxd rdx,eax
   140001f4f:	48 89 d0             	mov    rax,rdx
   140001f52:	48 c1 e0 02          	shl    rax,0x2
   140001f56:	48 01 d0             	add    rax,rdx
   140001f59:	48 c1 e0 03          	shl    rax,0x3
   140001f5d:	4c 01 c0             	add    rax,r8
   140001f60:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f64:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f68:	49 89 d1             	mov    r9,rdx
   140001f6b:	45 89 d0             	mov    r8d,r10d
   140001f6e:	48 89 ca             	mov    rdx,rcx
   140001f71:	48 89 c1             	mov    rcx,rax
   140001f74:	48 8b 05 75 82 00 00 	mov    rax,QWORD PTR [rip+0x8275]        # 14000a1f0 <__imp_VirtualProtect>
   140001f7b:	ff d0                	call   rax
   140001f7d:	eb 01                	jmp    140001f80 <restore_modified_sections+0xbd>
   140001f7f:	90                   	nop
   140001f80:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f84:	8b 05 5e 71 00 00    	mov    eax,DWORD PTR [rip+0x715e]        # 1400090e8 <maxSections>
   140001f8a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f8d:	0f 8c 44 ff ff ff    	jl     140001ed7 <restore_modified_sections+0x14>
   140001f93:	90                   	nop
   140001f94:	90                   	nop
   140001f95:	48 83 c4 30          	add    rsp,0x30
   140001f99:	5d                   	pop    rbp
   140001f9a:	c3                   	ret

0000000140001f9b <__write_memory>:
   140001f9b:	55                   	push   rbp
   140001f9c:	48 89 e5             	mov    rbp,rsp
   140001f9f:	48 83 ec 20          	sub    rsp,0x20
   140001fa3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fa7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001fab:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001faf:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001fb4:	74 25                	je     140001fdb <__write_memory+0x40>
   140001fb6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fba:	48 89 c1             	mov    rcx,rax
   140001fbd:	e8 23 fc ff ff       	call   140001be5 <mark_section_writable>
   140001fc2:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001fc6:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001fca:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fce:	49 89 c8             	mov    r8,rcx
   140001fd1:	48 89 c1             	mov    rcx,rax
   140001fd4:	e8 37 13 00 00       	call   140003310 <memcpy>
   140001fd9:	eb 01                	jmp    140001fdc <__write_memory+0x41>
   140001fdb:	90                   	nop
   140001fdc:	48 83 c4 20          	add    rsp,0x20
   140001fe0:	5d                   	pop    rbp
   140001fe1:	c3                   	ret

0000000140001fe2 <do_pseudo_reloc>:
   140001fe2:	55                   	push   rbp
   140001fe3:	48 89 e5             	mov    rbp,rsp
   140001fe6:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001fea:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fee:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001ff2:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001ff6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001ffa:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001ffe:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002002:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002006:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000200a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000200f:	0f 8e 44 03 00 00    	jle    140002359 <do_pseudo_reloc+0x377>
   140002015:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000201a:	7e 25                	jle    140002041 <do_pseudo_reloc+0x5f>
   14000201c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002020:	8b 00                	mov    eax,DWORD PTR [rax]
   140002022:	85 c0                	test   eax,eax
   140002024:	75 1b                	jne    140002041 <do_pseudo_reloc+0x5f>
   140002026:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000202a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000202d:	85 c0                	test   eax,eax
   14000202f:	75 10                	jne    140002041 <do_pseudo_reloc+0x5f>
   140002031:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002035:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002038:	85 c0                	test   eax,eax
   14000203a:	75 05                	jne    140002041 <do_pseudo_reloc+0x5f>
   14000203c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002041:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002045:	8b 00                	mov    eax,DWORD PTR [rax]
   140002047:	85 c0                	test   eax,eax
   140002049:	75 0b                	jne    140002056 <do_pseudo_reloc+0x74>
   14000204b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000204f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002052:	85 c0                	test   eax,eax
   140002054:	74 59                	je     1400020af <do_pseudo_reloc+0xcd>
   140002056:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000205a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000205e:	eb 40                	jmp    1400020a0 <do_pseudo_reloc+0xbe>
   140002060:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002064:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002067:	89 c2                	mov    edx,eax
   140002069:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000206d:	48 01 d0             	add    rax,rdx
   140002070:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002074:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002078:	8b 10                	mov    edx,DWORD PTR [rax]
   14000207a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000207e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002080:	01 d0                	add    eax,edx
   140002082:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002085:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002089:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000208d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002093:	48 89 c1             	mov    rcx,rax
   140002096:	e8 00 ff ff ff       	call   140001f9b <__write_memory>
   14000209b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   1400020a0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020a4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400020a8:	72 b6                	jb     140002060 <do_pseudo_reloc+0x7e>
   1400020aa:	e9 ab 02 00 00       	jmp    14000235a <do_pseudo_reloc+0x378>
   1400020af:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020b3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020b6:	83 f8 01             	cmp    eax,0x1
   1400020b9:	74 18                	je     1400020d3 <do_pseudo_reloc+0xf1>
   1400020bb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020bf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020c2:	89 c2                	mov    edx,eax
   1400020c4:	48 8d 05 a5 31 00 00 	lea    rax,[rip+0x31a5]        # 140005270 <.rdata+0xa0>
   1400020cb:	48 89 c1             	mov    rcx,rax
   1400020ce:	e8 ad fa ff ff       	call   140001b80 <__report_error>
   1400020d3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020d7:	48 83 c0 0c          	add    rax,0xc
   1400020db:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400020df:	e9 65 02 00 00       	jmp    140002349 <do_pseudo_reloc+0x367>
   1400020e4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020e8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020eb:	89 c2                	mov    edx,eax
   1400020ed:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020f1:	48 01 d0             	add    rax,rdx
   1400020f4:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020fc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020fe:	89 c2                	mov    edx,eax
   140002100:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002104:	48 01 d0             	add    rax,rdx
   140002107:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000210b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000210f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002112:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002116:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000211a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000211d:	0f b6 c0             	movzx  eax,al
   140002120:	83 f8 40             	cmp    eax,0x40
   140002123:	0f 84 b6 00 00 00    	je     1400021df <do_pseudo_reloc+0x1fd>
   140002129:	83 f8 40             	cmp    eax,0x40
   14000212c:	0f 87 ba 00 00 00    	ja     1400021ec <do_pseudo_reloc+0x20a>
   140002132:	83 f8 20             	cmp    eax,0x20
   140002135:	74 77                	je     1400021ae <do_pseudo_reloc+0x1cc>
   140002137:	83 f8 20             	cmp    eax,0x20
   14000213a:	0f 87 ac 00 00 00    	ja     1400021ec <do_pseudo_reloc+0x20a>
   140002140:	83 f8 08             	cmp    eax,0x8
   140002143:	74 0a                	je     14000214f <do_pseudo_reloc+0x16d>
   140002145:	83 f8 10             	cmp    eax,0x10
   140002148:	74 38                	je     140002182 <do_pseudo_reloc+0x1a0>
   14000214a:	e9 9d 00 00 00       	jmp    1400021ec <do_pseudo_reloc+0x20a>
   14000214f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002153:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002156:	0f b6 c0             	movzx  eax,al
   140002159:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000215d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002161:	25 80 00 00 00       	and    eax,0x80
   140002166:	48 85 c0             	test   rax,rax
   140002169:	0f 84 9d 00 00 00    	je     14000220c <do_pseudo_reloc+0x22a>
   14000216f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002173:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002179:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000217d:	e9 8a 00 00 00       	jmp    14000220c <do_pseudo_reloc+0x22a>
   140002182:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002186:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002189:	0f b7 c0             	movzx  eax,ax
   14000218c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002190:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002194:	25 00 80 00 00       	and    eax,0x8000
   140002199:	48 85 c0             	test   rax,rax
   14000219c:	74 71                	je     14000220f <do_pseudo_reloc+0x22d>
   14000219e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021a2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400021a8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ac:	eb 61                	jmp    14000220f <do_pseudo_reloc+0x22d>
   1400021ae:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021b2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021b4:	89 c0                	mov    eax,eax
   1400021b6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ba:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021be:	25 00 00 00 80       	and    eax,0x80000000
   1400021c3:	48 85 c0             	test   rax,rax
   1400021c6:	74 4a                	je     140002212 <do_pseudo_reloc+0x230>
   1400021c8:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021cc:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   1400021d3:	ff ff ff 
   1400021d6:	48 09 d0             	or     rax,rdx
   1400021d9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021dd:	eb 33                	jmp    140002212 <do_pseudo_reloc+0x230>
   1400021df:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021e3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400021e6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ea:	eb 27                	jmp    140002213 <do_pseudo_reloc+0x231>
   1400021ec:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   1400021f3:	00 
   1400021f4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021f8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021fb:	0f b6 c0             	movzx  eax,al
   1400021fe:	48 8d 0d a3 30 00 00 	lea    rcx,[rip+0x30a3]        # 1400052a8 <.rdata+0xd8>
   140002205:	89 c2                	mov    edx,eax
   140002207:	e8 74 f9 ff ff       	call   140001b80 <__report_error>
   14000220c:	90                   	nop
   14000220d:	eb 04                	jmp    140002213 <do_pseudo_reloc+0x231>
   14000220f:	90                   	nop
   140002210:	eb 01                	jmp    140002213 <do_pseudo_reloc+0x231>
   140002212:	90                   	nop
   140002213:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002217:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000221b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000221d:	89 c2                	mov    edx,eax
   14000221f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002223:	48 01 c2             	add    rdx,rax
   140002226:	48 89 c8             	mov    rax,rcx
   140002229:	48 29 d0             	sub    rax,rdx
   14000222c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002230:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002234:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002238:	48 01 d0             	add    rax,rdx
   14000223b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000223f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002243:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002246:	25 ff 00 00 00       	and    eax,0xff
   14000224b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000224e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002252:	77 67                	ja     1400022bb <do_pseudo_reloc+0x2d9>
   140002254:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002257:	ba 01 00 00 00       	mov    edx,0x1
   14000225c:	89 c1                	mov    ecx,eax
   14000225e:	48 d3 e2             	shl    rdx,cl
   140002261:	48 89 d0             	mov    rax,rdx
   140002264:	48 83 e8 01          	sub    rax,0x1
   140002268:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000226c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000226f:	83 e8 01             	sub    eax,0x1
   140002272:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002279:	89 c1                	mov    ecx,eax
   14000227b:	48 d3 e2             	shl    rdx,cl
   14000227e:	48 89 d0             	mov    rax,rdx
   140002281:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002285:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002289:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000228d:	7c 0a                	jl     140002299 <do_pseudo_reloc+0x2b7>
   14000228f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002293:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002297:	7e 22                	jle    1400022bb <do_pseudo_reloc+0x2d9>
   140002299:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000229d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400022a1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400022a5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022a8:	48 8d 0d 29 30 00 00 	lea    rcx,[rip+0x3029]        # 1400052d8 <.rdata+0x108>
   1400022af:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400022b4:	89 c2                	mov    edx,eax
   1400022b6:	e8 c5 f8 ff ff       	call   140001b80 <__report_error>
   1400022bb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022bf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022c2:	0f b6 c0             	movzx  eax,al
   1400022c5:	83 f8 40             	cmp    eax,0x40
   1400022c8:	74 63                	je     14000232d <do_pseudo_reloc+0x34b>
   1400022ca:	83 f8 40             	cmp    eax,0x40
   1400022cd:	77 75                	ja     140002344 <do_pseudo_reloc+0x362>
   1400022cf:	83 f8 20             	cmp    eax,0x20
   1400022d2:	74 41                	je     140002315 <do_pseudo_reloc+0x333>
   1400022d4:	83 f8 20             	cmp    eax,0x20
   1400022d7:	77 6b                	ja     140002344 <do_pseudo_reloc+0x362>
   1400022d9:	83 f8 08             	cmp    eax,0x8
   1400022dc:	74 07                	je     1400022e5 <do_pseudo_reloc+0x303>
   1400022de:	83 f8 10             	cmp    eax,0x10
   1400022e1:	74 1a                	je     1400022fd <do_pseudo_reloc+0x31b>
   1400022e3:	eb 5f                	jmp    140002344 <do_pseudo_reloc+0x362>
   1400022e5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022e9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022ed:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400022f3:	48 89 c1             	mov    rcx,rax
   1400022f6:	e8 a0 fc ff ff       	call   140001f9b <__write_memory>
   1400022fb:	eb 47                	jmp    140002344 <do_pseudo_reloc+0x362>
   1400022fd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002301:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002305:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000230b:	48 89 c1             	mov    rcx,rax
   14000230e:	e8 88 fc ff ff       	call   140001f9b <__write_memory>
   140002313:	eb 2f                	jmp    140002344 <do_pseudo_reloc+0x362>
   140002315:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002319:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000231d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002323:	48 89 c1             	mov    rcx,rax
   140002326:	e8 70 fc ff ff       	call   140001f9b <__write_memory>
   14000232b:	eb 17                	jmp    140002344 <do_pseudo_reloc+0x362>
   14000232d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002331:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002335:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000233b:	48 89 c1             	mov    rcx,rax
   14000233e:	e8 58 fc ff ff       	call   140001f9b <__write_memory>
   140002343:	90                   	nop
   140002344:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002349:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000234d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002351:	0f 82 8d fd ff ff    	jb     1400020e4 <do_pseudo_reloc+0x102>
   140002357:	eb 01                	jmp    14000235a <do_pseudo_reloc+0x378>
   140002359:	90                   	nop
   14000235a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000235e:	5d                   	pop    rbp
   14000235f:	c3                   	ret

0000000140002360 <_pei386_runtime_relocator>:
   140002360:	55                   	push   rbp
   140002361:	48 89 e5             	mov    rbp,rsp
   140002364:	48 83 ec 30          	sub    rsp,0x30
   140002368:	8b 05 7e 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d7e]        # 1400090ec <was_init.0>
   14000236e:	85 c0                	test   eax,eax
   140002370:	0f 85 88 00 00 00    	jne    1400023fe <_pei386_runtime_relocator+0x9e>
   140002376:	8b 05 70 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d70]        # 1400090ec <was_init.0>
   14000237c:	83 c0 01             	add    eax,0x1
   14000237f:	89 05 67 6d 00 00    	mov    DWORD PTR [rip+0x6d67],eax        # 1400090ec <was_init.0>
   140002385:	e8 21 0b 00 00       	call   140002eab <__mingw_GetSectionCount>
   14000238a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000238d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002390:	48 63 d0             	movsxd rdx,eax
   140002393:	48 89 d0             	mov    rax,rdx
   140002396:	48 c1 e0 02          	shl    rax,0x2
   14000239a:	48 01 d0             	add    rax,rdx
   14000239d:	48 c1 e0 03          	shl    rax,0x3
   1400023a1:	48 83 c0 0f          	add    rax,0xf
   1400023a5:	48 c1 e8 04          	shr    rax,0x4
   1400023a9:	48 c1 e0 04          	shl    rax,0x4
   1400023ad:	e8 7e 0d 00 00       	call   140003130 <___chkstk_ms>
   1400023b2:	48 29 c4             	sub    rsp,rax
   1400023b5:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400023ba:	48 83 c0 0f          	add    rax,0xf
   1400023be:	48 c1 e8 04          	shr    rax,0x4
   1400023c2:	48 c1 e0 04          	shl    rax,0x4
   1400023c6:	48 89 05 13 6d 00 00 	mov    QWORD PTR [rip+0x6d13],rax        # 1400090e0 <the_secs>
   1400023cd:	c7 05 11 6d 00 00 00 	mov    DWORD PTR [rip+0x6d11],0x0        # 1400090e8 <maxSections>
   1400023d4:	00 00 00 
   1400023d7:	48 8b 0d 82 2f 00 00 	mov    rcx,QWORD PTR [rip+0x2f82]        # 140005360 <.refptr.__ImageBase>
   1400023de:	48 8b 15 8b 2f 00 00 	mov    rdx,QWORD PTR [rip+0x2f8b]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   1400023e5:	48 8b 05 94 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f94]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   1400023ec:	49 89 c8             	mov    r8,rcx
   1400023ef:	48 89 c1             	mov    rcx,rax
   1400023f2:	e8 eb fb ff ff       	call   140001fe2 <do_pseudo_reloc>
   1400023f7:	e8 c7 fa ff ff       	call   140001ec3 <restore_modified_sections>
   1400023fc:	eb 01                	jmp    1400023ff <_pei386_runtime_relocator+0x9f>
   1400023fe:	90                   	nop
   1400023ff:	48 89 ec             	mov    rsp,rbp
   140002402:	5d                   	pop    rbp
   140002403:	c3                   	ret
   140002404:	90                   	nop
   140002405:	90                   	nop
   140002406:	90                   	nop
   140002407:	90                   	nop
   140002408:	90                   	nop
   140002409:	90                   	nop
   14000240a:	90                   	nop
   14000240b:	90                   	nop
   14000240c:	90                   	nop
   14000240d:	90                   	nop
   14000240e:	90                   	nop
   14000240f:	90                   	nop

0000000140002410 <__mingw_raise_matherr>:
   140002410:	55                   	push   rbp
   140002411:	48 89 e5             	mov    rbp,rsp
   140002414:	48 83 ec 50          	sub    rsp,0x50
   140002418:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000241b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000241f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002424:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002429:	48 8b 05 c0 6c 00 00 	mov    rax,QWORD PTR [rip+0x6cc0]        # 1400090f0 <stUserMathErr>
   140002430:	48 85 c0             	test   rax,rax
   140002433:	74 3e                	je     140002473 <__mingw_raise_matherr+0x63>
   140002435:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002438:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000243b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000243f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002443:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002448:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000244d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002452:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002457:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000245c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002461:	48 8b 15 88 6c 00 00 	mov    rdx,QWORD PTR [rip+0x6c88]        # 1400090f0 <stUserMathErr>
   140002468:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000246c:	48 89 c1             	mov    rcx,rax
   14000246f:	ff d2                	call   rdx
   140002471:	eb 01                	jmp    140002474 <__mingw_raise_matherr+0x64>
   140002473:	90                   	nop
   140002474:	48 83 c4 50          	add    rsp,0x50
   140002478:	5d                   	pop    rbp
   140002479:	c3                   	ret

000000014000247a <__mingw_setusermatherr>:
   14000247a:	55                   	push   rbp
   14000247b:	48 89 e5             	mov    rbp,rsp
   14000247e:	48 83 ec 20          	sub    rsp,0x20
   140002482:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002486:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000248a:	48 89 05 5f 6c 00 00 	mov    QWORD PTR [rip+0x6c5f],rax        # 1400090f0 <stUserMathErr>
   140002491:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002495:	48 89 c1             	mov    rcx,rax
   140002498:	e8 13 0e 00 00       	call   1400032b0 <__setusermatherr>
   14000249d:	90                   	nop
   14000249e:	48 83 c4 20          	add    rsp,0x20
   1400024a2:	5d                   	pop    rbp
   1400024a3:	c3                   	ret
   1400024a4:	90                   	nop
   1400024a5:	90                   	nop
   1400024a6:	90                   	nop
   1400024a7:	90                   	nop
   1400024a8:	90                   	nop
   1400024a9:	90                   	nop
   1400024aa:	90                   	nop
   1400024ab:	90                   	nop
   1400024ac:	90                   	nop
   1400024ad:	90                   	nop
   1400024ae:	90                   	nop
   1400024af:	90                   	nop

00000001400024b0 <__mingw_SEH_error_handler>:
   1400024b0:	55                   	push   rbp
   1400024b1:	48 89 e5             	mov    rbp,rsp
   1400024b4:	48 83 ec 30          	sub    rsp,0x30
   1400024b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024bc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400024c0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400024c4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400024c8:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400024cf:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400024d6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024da:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024dd:	83 e0 02             	and    eax,0x2
   1400024e0:	85 c0                	test   eax,eax
   1400024e2:	74 0a                	je     1400024ee <__mingw_SEH_error_handler+0x3e>
   1400024e4:	b8 01 00 00 00       	mov    eax,0x1
   1400024e9:	e9 16 02 00 00       	jmp    140002704 <__mingw_SEH_error_handler+0x254>
   1400024ee:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024f2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024f4:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400024f9:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400024fe:	75 18                	jne    140002518 <__mingw_SEH_error_handler+0x68>
   140002500:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002504:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002507:	83 e0 01             	and    eax,0x1
   14000250a:	85 c0                	test   eax,eax
   14000250c:	75 0a                	jne    140002518 <__mingw_SEH_error_handler+0x68>
   14000250e:	b8 00 00 00 00       	mov    eax,0x0
   140002513:	e9 ec 01 00 00       	jmp    140002704 <__mingw_SEH_error_handler+0x254>
   140002518:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000251c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000251e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002523:	0f 84 12 01 00 00    	je     14000263b <__mingw_SEH_error_handler+0x18b>
   140002529:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000252e:	0f 87 c3 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   140002534:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002539:	0f 87 b8 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   14000253f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002544:	0f 83 4c 01 00 00    	jae    140002696 <__mingw_SEH_error_handler+0x1e6>
   14000254a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000254f:	0f 84 3a 01 00 00    	je     14000268f <__mingw_SEH_error_handler+0x1df>
   140002555:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000255a:	0f 87 97 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   140002560:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002565:	0f 84 83 01 00 00    	je     1400026ee <__mingw_SEH_error_handler+0x23e>
   14000256b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002570:	0f 87 81 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   140002576:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000257b:	0f 87 76 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   140002581:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002586:	0f 83 03 01 00 00    	jae    14000268f <__mingw_SEH_error_handler+0x1df>
   14000258c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002591:	0f 84 57 01 00 00    	je     1400026ee <__mingw_SEH_error_handler+0x23e>
   140002597:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000259c:	0f 87 55 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   1400025a2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025a7:	0f 84 8e 00 00 00    	je     14000263b <__mingw_SEH_error_handler+0x18b>
   1400025ad:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025b2:	0f 87 3f 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   1400025b8:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025bd:	0f 84 2b 01 00 00    	je     1400026ee <__mingw_SEH_error_handler+0x23e>
   1400025c3:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025c8:	0f 87 29 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   1400025ce:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400025d3:	0f 84 15 01 00 00    	je     1400026ee <__mingw_SEH_error_handler+0x23e>
   1400025d9:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400025de:	0f 85 13 01 00 00    	jne    1400026f7 <__mingw_SEH_error_handler+0x247>
   1400025e4:	ba 00 00 00 00       	mov    edx,0x0
   1400025e9:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025ee:	e8 35 0d 00 00       	call   140003328 <signal>
   1400025f3:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025f7:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025fc:	75 1b                	jne    140002619 <__mingw_SEH_error_handler+0x169>
   1400025fe:	ba 01 00 00 00       	mov    edx,0x1
   140002603:	b9 0b 00 00 00       	mov    ecx,0xb
   140002608:	e8 1b 0d 00 00       	call   140003328 <signal>
   14000260d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002614:	e9 e1 00 00 00       	jmp    1400026fa <__mingw_SEH_error_handler+0x24a>
   140002619:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000261e:	0f 84 d6 00 00 00    	je     1400026fa <__mingw_SEH_error_handler+0x24a>
   140002624:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002628:	b9 0b 00 00 00       	mov    ecx,0xb
   14000262d:	ff d0                	call   rax
   14000262f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002636:	e9 bf 00 00 00       	jmp    1400026fa <__mingw_SEH_error_handler+0x24a>
   14000263b:	ba 00 00 00 00       	mov    edx,0x0
   140002640:	b9 04 00 00 00       	mov    ecx,0x4
   140002645:	e8 de 0c 00 00       	call   140003328 <signal>
   14000264a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000264e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002653:	75 1b                	jne    140002670 <__mingw_SEH_error_handler+0x1c0>
   140002655:	ba 01 00 00 00       	mov    edx,0x1
   14000265a:	b9 04 00 00 00       	mov    ecx,0x4
   14000265f:	e8 c4 0c 00 00       	call   140003328 <signal>
   140002664:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000266b:	e9 8d 00 00 00       	jmp    1400026fd <__mingw_SEH_error_handler+0x24d>
   140002670:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002675:	0f 84 82 00 00 00    	je     1400026fd <__mingw_SEH_error_handler+0x24d>
   14000267b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000267f:	b9 04 00 00 00       	mov    ecx,0x4
   140002684:	ff d0                	call   rax
   140002686:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000268d:	eb 6e                	jmp    1400026fd <__mingw_SEH_error_handler+0x24d>
   14000268f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002696:	ba 00 00 00 00       	mov    edx,0x0
   14000269b:	b9 08 00 00 00       	mov    ecx,0x8
   1400026a0:	e8 83 0c 00 00       	call   140003328 <signal>
   1400026a5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026a9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026ae:	75 23                	jne    1400026d3 <__mingw_SEH_error_handler+0x223>
   1400026b0:	ba 01 00 00 00       	mov    edx,0x1
   1400026b5:	b9 08 00 00 00       	mov    ecx,0x8
   1400026ba:	e8 69 0c 00 00       	call   140003328 <signal>
   1400026bf:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400026c3:	74 05                	je     1400026ca <__mingw_SEH_error_handler+0x21a>
   1400026c5:	e8 a6 05 00 00       	call   140002c70 <_fpreset>
   1400026ca:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026d1:	eb 2d                	jmp    140002700 <__mingw_SEH_error_handler+0x250>
   1400026d3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026d8:	74 26                	je     140002700 <__mingw_SEH_error_handler+0x250>
   1400026da:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026de:	b9 08 00 00 00       	mov    ecx,0x8
   1400026e3:	ff d0                	call   rax
   1400026e5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026ec:	eb 12                	jmp    140002700 <__mingw_SEH_error_handler+0x250>
   1400026ee:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026f5:	eb 0a                	jmp    140002701 <__mingw_SEH_error_handler+0x251>
   1400026f7:	90                   	nop
   1400026f8:	eb 07                	jmp    140002701 <__mingw_SEH_error_handler+0x251>
   1400026fa:	90                   	nop
   1400026fb:	eb 04                	jmp    140002701 <__mingw_SEH_error_handler+0x251>
   1400026fd:	90                   	nop
   1400026fe:	eb 01                	jmp    140002701 <__mingw_SEH_error_handler+0x251>
   140002700:	90                   	nop
   140002701:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002704:	48 83 c4 30          	add    rsp,0x30
   140002708:	5d                   	pop    rbp
   140002709:	c3                   	ret

000000014000270a <_gnu_exception_handler>:
   14000270a:	55                   	push   rbp
   14000270b:	48 89 e5             	mov    rbp,rsp
   14000270e:	48 83 ec 30          	sub    rsp,0x30
   140002712:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002716:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000271d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002724:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002728:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000272b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000272d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002732:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002737:	75 1b                	jne    140002754 <_gnu_exception_handler+0x4a>
   140002739:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000273d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002740:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002743:	83 e0 01             	and    eax,0x1
   140002746:	85 c0                	test   eax,eax
   140002748:	75 0a                	jne    140002754 <_gnu_exception_handler+0x4a>
   14000274a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000274f:	e9 14 02 00 00       	jmp    140002968 <_gnu_exception_handler+0x25e>
   140002754:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002758:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000275b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000275d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002762:	0f 84 12 01 00 00    	je     14000287a <_gnu_exception_handler+0x170>
   140002768:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000276d:	0f 87 c3 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   140002773:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002778:	0f 87 b8 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   14000277e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002783:	0f 83 4c 01 00 00    	jae    1400028d5 <_gnu_exception_handler+0x1cb>
   140002789:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000278e:	0f 84 3a 01 00 00    	je     1400028ce <_gnu_exception_handler+0x1c4>
   140002794:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002799:	0f 87 97 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   14000279f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027a4:	0f 84 83 01 00 00    	je     14000292d <_gnu_exception_handler+0x223>
   1400027aa:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027af:	0f 87 81 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   1400027b5:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400027ba:	0f 87 76 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   1400027c0:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400027c5:	0f 83 03 01 00 00    	jae    1400028ce <_gnu_exception_handler+0x1c4>
   1400027cb:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027d0:	0f 84 57 01 00 00    	je     14000292d <_gnu_exception_handler+0x223>
   1400027d6:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027db:	0f 87 55 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   1400027e1:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027e6:	0f 84 8e 00 00 00    	je     14000287a <_gnu_exception_handler+0x170>
   1400027ec:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027f1:	0f 87 3f 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   1400027f7:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027fc:	0f 84 2b 01 00 00    	je     14000292d <_gnu_exception_handler+0x223>
   140002802:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002807:	0f 87 29 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   14000280d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002812:	0f 84 15 01 00 00    	je     14000292d <_gnu_exception_handler+0x223>
   140002818:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000281d:	0f 85 13 01 00 00    	jne    140002936 <_gnu_exception_handler+0x22c>
   140002823:	ba 00 00 00 00       	mov    edx,0x0
   140002828:	b9 0b 00 00 00       	mov    ecx,0xb
   14000282d:	e8 f6 0a 00 00       	call   140003328 <signal>
   140002832:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002836:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000283b:	75 1b                	jne    140002858 <_gnu_exception_handler+0x14e>
   14000283d:	ba 01 00 00 00       	mov    edx,0x1
   140002842:	b9 0b 00 00 00       	mov    ecx,0xb
   140002847:	e8 dc 0a 00 00       	call   140003328 <signal>
   14000284c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002853:	e9 e1 00 00 00       	jmp    140002939 <_gnu_exception_handler+0x22f>
   140002858:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000285d:	0f 84 d6 00 00 00    	je     140002939 <_gnu_exception_handler+0x22f>
   140002863:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002867:	b9 0b 00 00 00       	mov    ecx,0xb
   14000286c:	ff d0                	call   rax
   14000286e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002875:	e9 bf 00 00 00       	jmp    140002939 <_gnu_exception_handler+0x22f>
   14000287a:	ba 00 00 00 00       	mov    edx,0x0
   14000287f:	b9 04 00 00 00       	mov    ecx,0x4
   140002884:	e8 9f 0a 00 00       	call   140003328 <signal>
   140002889:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000288d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002892:	75 1b                	jne    1400028af <_gnu_exception_handler+0x1a5>
   140002894:	ba 01 00 00 00       	mov    edx,0x1
   140002899:	b9 04 00 00 00       	mov    ecx,0x4
   14000289e:	e8 85 0a 00 00       	call   140003328 <signal>
   1400028a3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028aa:	e9 8d 00 00 00       	jmp    14000293c <_gnu_exception_handler+0x232>
   1400028af:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028b4:	0f 84 82 00 00 00    	je     14000293c <_gnu_exception_handler+0x232>
   1400028ba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028be:	b9 04 00 00 00       	mov    ecx,0x4
   1400028c3:	ff d0                	call   rax
   1400028c5:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028cc:	eb 6e                	jmp    14000293c <_gnu_exception_handler+0x232>
   1400028ce:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400028d5:	ba 00 00 00 00       	mov    edx,0x0
   1400028da:	b9 08 00 00 00       	mov    ecx,0x8
   1400028df:	e8 44 0a 00 00       	call   140003328 <signal>
   1400028e4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028e8:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028ed:	75 23                	jne    140002912 <_gnu_exception_handler+0x208>
   1400028ef:	ba 01 00 00 00       	mov    edx,0x1
   1400028f4:	b9 08 00 00 00       	mov    ecx,0x8
   1400028f9:	e8 2a 0a 00 00       	call   140003328 <signal>
   1400028fe:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002902:	74 05                	je     140002909 <_gnu_exception_handler+0x1ff>
   140002904:	e8 67 03 00 00       	call   140002c70 <_fpreset>
   140002909:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002910:	eb 2d                	jmp    14000293f <_gnu_exception_handler+0x235>
   140002912:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002917:	74 26                	je     14000293f <_gnu_exception_handler+0x235>
   140002919:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000291d:	b9 08 00 00 00       	mov    ecx,0x8
   140002922:	ff d0                	call   rax
   140002924:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000292b:	eb 12                	jmp    14000293f <_gnu_exception_handler+0x235>
   14000292d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002934:	eb 0a                	jmp    140002940 <_gnu_exception_handler+0x236>
   140002936:	90                   	nop
   140002937:	eb 07                	jmp    140002940 <_gnu_exception_handler+0x236>
   140002939:	90                   	nop
   14000293a:	eb 04                	jmp    140002940 <_gnu_exception_handler+0x236>
   14000293c:	90                   	nop
   14000293d:	eb 01                	jmp    140002940 <_gnu_exception_handler+0x236>
   14000293f:	90                   	nop
   140002940:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002944:	75 1f                	jne    140002965 <_gnu_exception_handler+0x25b>
   140002946:	48 8b 05 c3 67 00 00 	mov    rax,QWORD PTR [rip+0x67c3]        # 140009110 <__mingw_oldexcpt_handler>
   14000294d:	48 85 c0             	test   rax,rax
   140002950:	74 13                	je     140002965 <_gnu_exception_handler+0x25b>
   140002952:	48 8b 15 b7 67 00 00 	mov    rdx,QWORD PTR [rip+0x67b7]        # 140009110 <__mingw_oldexcpt_handler>
   140002959:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000295d:	48 89 c1             	mov    rcx,rax
   140002960:	ff d2                	call   rdx
   140002962:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002965:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002968:	48 83 c4 30          	add    rsp,0x30
   14000296c:	5d                   	pop    rbp
   14000296d:	c3                   	ret
   14000296e:	90                   	nop
   14000296f:	90                   	nop

0000000140002970 <___w64_mingwthr_add_key_dtor>:
   140002970:	55                   	push   rbp
   140002971:	48 89 e5             	mov    rbp,rsp
   140002974:	48 83 ec 30          	sub    rsp,0x30
   140002978:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000297b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000297f:	8b 05 c3 67 00 00    	mov    eax,DWORD PTR [rip+0x67c3]        # 140009148 <__mingwthr_cs_init>
   140002985:	85 c0                	test   eax,eax
   140002987:	75 07                	jne    140002990 <___w64_mingwthr_add_key_dtor+0x20>
   140002989:	b8 00 00 00 00       	mov    eax,0x0
   14000298e:	eb 7b                	jmp    140002a0b <___w64_mingwthr_add_key_dtor+0x9b>
   140002990:	ba 18 00 00 00       	mov    edx,0x18
   140002995:	b9 01 00 00 00       	mov    ecx,0x1
   14000299a:	e8 41 09 00 00       	call   1400032e0 <calloc>
   14000299f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400029a3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029a8:	75 07                	jne    1400029b1 <___w64_mingwthr_add_key_dtor+0x41>
   1400029aa:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400029af:	eb 5a                	jmp    140002a0b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029b1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029b5:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400029b8:	89 10                	mov    DWORD PTR [rax],edx
   1400029ba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029be:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400029c2:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   1400029c6:	48 8d 05 53 67 00 00 	lea    rax,[rip+0x6753]        # 140009120 <__mingwthr_cs>
   1400029cd:	48 89 c1             	mov    rcx,rax
   1400029d0:	48 8b 05 c1 77 00 00 	mov    rax,QWORD PTR [rip+0x77c1]        # 14000a198 <__imp_EnterCriticalSection>
   1400029d7:	ff d0                	call   rax
   1400029d9:	48 8b 15 70 67 00 00 	mov    rdx,QWORD PTR [rip+0x6770]        # 140009150 <key_dtor_list>
   1400029e0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029e4:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029ec:	48 89 05 5d 67 00 00 	mov    QWORD PTR [rip+0x675d],rax        # 140009150 <key_dtor_list>
   1400029f3:	48 8d 05 26 67 00 00 	lea    rax,[rip+0x6726]        # 140009120 <__mingwthr_cs>
   1400029fa:	48 89 c1             	mov    rcx,rax
   1400029fd:	48 8b 05 c4 77 00 00 	mov    rax,QWORD PTR [rip+0x77c4]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002a04:	ff d0                	call   rax
   140002a06:	b8 00 00 00 00       	mov    eax,0x0
   140002a0b:	48 83 c4 30          	add    rsp,0x30
   140002a0f:	5d                   	pop    rbp
   140002a10:	c3                   	ret

0000000140002a11 <___w64_mingwthr_remove_key_dtor>:
   140002a11:	55                   	push   rbp
   140002a12:	48 89 e5             	mov    rbp,rsp
   140002a15:	48 83 ec 30          	sub    rsp,0x30
   140002a19:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a1c:	8b 05 26 67 00 00    	mov    eax,DWORD PTR [rip+0x6726]        # 140009148 <__mingwthr_cs_init>
   140002a22:	85 c0                	test   eax,eax
   140002a24:	75 0a                	jne    140002a30 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a26:	b8 00 00 00 00       	mov    eax,0x0
   140002a2b:	e9 9c 00 00 00       	jmp    140002acc <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a30:	48 8d 05 e9 66 00 00 	lea    rax,[rip+0x66e9]        # 140009120 <__mingwthr_cs>
   140002a37:	48 89 c1             	mov    rcx,rax
   140002a3a:	48 8b 05 57 77 00 00 	mov    rax,QWORD PTR [rip+0x7757]        # 14000a198 <__imp_EnterCriticalSection>
   140002a41:	ff d0                	call   rax
   140002a43:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a4a:	00 
   140002a4b:	48 8b 05 fe 66 00 00 	mov    rax,QWORD PTR [rip+0x66fe]        # 140009150 <key_dtor_list>
   140002a52:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a56:	eb 55                	jmp    140002aad <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a58:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a5c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a5e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a61:	75 36                	jne    140002a99 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a63:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a68:	75 11                	jne    140002a7b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a6a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a6e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a72:	48 89 05 d7 66 00 00 	mov    QWORD PTR [rip+0x66d7],rax        # 140009150 <key_dtor_list>
   140002a79:	eb 10                	jmp    140002a8b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a7b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a7f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a83:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a87:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a8b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a8f:	48 89 c1             	mov    rcx,rax
   140002a92:	e8 69 08 00 00       	call   140003300 <free>
   140002a97:	eb 1b                	jmp    140002ab4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a99:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a9d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002aa1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aa5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002aa9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002aad:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002ab2:	75 a4                	jne    140002a58 <___w64_mingwthr_remove_key_dtor+0x47>
   140002ab4:	48 8d 05 65 66 00 00 	lea    rax,[rip+0x6665]        # 140009120 <__mingwthr_cs>
   140002abb:	48 89 c1             	mov    rcx,rax
   140002abe:	48 8b 05 03 77 00 00 	mov    rax,QWORD PTR [rip+0x7703]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002ac5:	ff d0                	call   rax
   140002ac7:	b8 00 00 00 00       	mov    eax,0x0
   140002acc:	48 83 c4 30          	add    rsp,0x30
   140002ad0:	5d                   	pop    rbp
   140002ad1:	c3                   	ret

0000000140002ad2 <__mingwthr_run_key_dtors>:
   140002ad2:	55                   	push   rbp
   140002ad3:	48 89 e5             	mov    rbp,rsp
   140002ad6:	48 83 ec 30          	sub    rsp,0x30
   140002ada:	8b 05 68 66 00 00    	mov    eax,DWORD PTR [rip+0x6668]        # 140009148 <__mingwthr_cs_init>
   140002ae0:	85 c0                	test   eax,eax
   140002ae2:	0f 84 82 00 00 00    	je     140002b6a <__mingwthr_run_key_dtors+0x98>
   140002ae8:	48 8d 05 31 66 00 00 	lea    rax,[rip+0x6631]        # 140009120 <__mingwthr_cs>
   140002aef:	48 89 c1             	mov    rcx,rax
   140002af2:	48 8b 05 9f 76 00 00 	mov    rax,QWORD PTR [rip+0x769f]        # 14000a198 <__imp_EnterCriticalSection>
   140002af9:	ff d0                	call   rax
   140002afb:	48 8b 05 4e 66 00 00 	mov    rax,QWORD PTR [rip+0x664e]        # 140009150 <key_dtor_list>
   140002b02:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b06:	eb 46                	jmp    140002b4e <__mingwthr_run_key_dtors+0x7c>
   140002b08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b0c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b0e:	89 c1                	mov    ecx,eax
   140002b10:	48 8b 05 d1 76 00 00 	mov    rax,QWORD PTR [rip+0x76d1]        # 14000a1e8 <__imp_TlsGetValue>
   140002b17:	ff d0                	call   rax
   140002b19:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b1d:	48 8b 05 84 76 00 00 	mov    rax,QWORD PTR [rip+0x7684]        # 14000a1a8 <__imp_GetLastError>
   140002b24:	ff d0                	call   rax
   140002b26:	85 c0                	test   eax,eax
   140002b28:	75 18                	jne    140002b42 <__mingwthr_run_key_dtors+0x70>
   140002b2a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b2f:	74 11                	je     140002b42 <__mingwthr_run_key_dtors+0x70>
   140002b31:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b35:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002b39:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b3d:	48 89 c1             	mov    rcx,rax
   140002b40:	ff d2                	call   rdx
   140002b42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b46:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b4a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b4e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b53:	75 b3                	jne    140002b08 <__mingwthr_run_key_dtors+0x36>
   140002b55:	48 8d 05 c4 65 00 00 	lea    rax,[rip+0x65c4]        # 140009120 <__mingwthr_cs>
   140002b5c:	48 89 c1             	mov    rcx,rax
   140002b5f:	48 8b 05 62 76 00 00 	mov    rax,QWORD PTR [rip+0x7662]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002b66:	ff d0                	call   rax
   140002b68:	eb 01                	jmp    140002b6b <__mingwthr_run_key_dtors+0x99>
   140002b6a:	90                   	nop
   140002b6b:	48 83 c4 30          	add    rsp,0x30
   140002b6f:	5d                   	pop    rbp
   140002b70:	c3                   	ret

0000000140002b71 <__mingw_TLScallback>:
   140002b71:	55                   	push   rbp
   140002b72:	48 89 e5             	mov    rbp,rsp
   140002b75:	48 83 ec 30          	sub    rsp,0x30
   140002b79:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b7d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b80:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b84:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b88:	0f 84 cc 00 00 00    	je     140002c5a <__mingw_TLScallback+0xe9>
   140002b8e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b92:	0f 87 ca 00 00 00    	ja     140002c62 <__mingw_TLScallback+0xf1>
   140002b98:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b9c:	0f 84 b1 00 00 00    	je     140002c53 <__mingw_TLScallback+0xe2>
   140002ba2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002ba6:	0f 87 b6 00 00 00    	ja     140002c62 <__mingw_TLScallback+0xf1>
   140002bac:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002bb0:	74 33                	je     140002be5 <__mingw_TLScallback+0x74>
   140002bb2:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002bb6:	0f 85 a6 00 00 00    	jne    140002c62 <__mingw_TLScallback+0xf1>
   140002bbc:	8b 05 86 65 00 00    	mov    eax,DWORD PTR [rip+0x6586]        # 140009148 <__mingwthr_cs_init>
   140002bc2:	85 c0                	test   eax,eax
   140002bc4:	75 13                	jne    140002bd9 <__mingw_TLScallback+0x68>
   140002bc6:	48 8d 05 53 65 00 00 	lea    rax,[rip+0x6553]        # 140009120 <__mingwthr_cs>
   140002bcd:	48 89 c1             	mov    rcx,rax
   140002bd0:	48 8b 05 e9 75 00 00 	mov    rax,QWORD PTR [rip+0x75e9]        # 14000a1c0 <__imp_InitializeCriticalSection>
   140002bd7:	ff d0                	call   rax
   140002bd9:	c7 05 65 65 00 00 01 	mov    DWORD PTR [rip+0x6565],0x1        # 140009148 <__mingwthr_cs_init>
   140002be0:	00 00 00 
   140002be3:	eb 7d                	jmp    140002c62 <__mingw_TLScallback+0xf1>
   140002be5:	e8 e8 fe ff ff       	call   140002ad2 <__mingwthr_run_key_dtors>
   140002bea:	8b 05 58 65 00 00    	mov    eax,DWORD PTR [rip+0x6558]        # 140009148 <__mingwthr_cs_init>
   140002bf0:	83 f8 01             	cmp    eax,0x1
   140002bf3:	75 6c                	jne    140002c61 <__mingw_TLScallback+0xf0>
   140002bf5:	48 8b 05 54 65 00 00 	mov    rax,QWORD PTR [rip+0x6554]        # 140009150 <key_dtor_list>
   140002bfc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c00:	eb 20                	jmp    140002c22 <__mingw_TLScallback+0xb1>
   140002c02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c06:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c0a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c0e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c12:	48 89 c1             	mov    rcx,rax
   140002c15:	e8 e6 06 00 00       	call   140003300 <free>
   140002c1a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c1e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c22:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c27:	75 d9                	jne    140002c02 <__mingw_TLScallback+0x91>
   140002c29:	48 c7 05 1c 65 00 00 	mov    QWORD PTR [rip+0x651c],0x0        # 140009150 <key_dtor_list>
   140002c30:	00 00 00 00 
   140002c34:	c7 05 0a 65 00 00 00 	mov    DWORD PTR [rip+0x650a],0x0        # 140009148 <__mingwthr_cs_init>
   140002c3b:	00 00 00 
   140002c3e:	48 8d 05 db 64 00 00 	lea    rax,[rip+0x64db]        # 140009120 <__mingwthr_cs>
   140002c45:	48 89 c1             	mov    rcx,rax
   140002c48:	48 8b 05 41 75 00 00 	mov    rax,QWORD PTR [rip+0x7541]        # 14000a190 <__IAT_start__>
   140002c4f:	ff d0                	call   rax
   140002c51:	eb 0e                	jmp    140002c61 <__mingw_TLScallback+0xf0>
   140002c53:	e8 18 00 00 00       	call   140002c70 <_fpreset>
   140002c58:	eb 08                	jmp    140002c62 <__mingw_TLScallback+0xf1>
   140002c5a:	e8 73 fe ff ff       	call   140002ad2 <__mingwthr_run_key_dtors>
   140002c5f:	eb 01                	jmp    140002c62 <__mingw_TLScallback+0xf1>
   140002c61:	90                   	nop
   140002c62:	b8 01 00 00 00       	mov    eax,0x1
   140002c67:	48 83 c4 30          	add    rsp,0x30
   140002c6b:	5d                   	pop    rbp
   140002c6c:	c3                   	ret
   140002c6d:	90                   	nop
   140002c6e:	90                   	nop
   140002c6f:	90                   	nop

0000000140002c70 <_fpreset>:
   140002c70:	55                   	push   rbp
   140002c71:	48 89 e5             	mov    rbp,rsp
   140002c74:	db e3                	fninit
   140002c76:	90                   	nop
   140002c77:	5d                   	pop    rbp
   140002c78:	c3                   	ret
   140002c79:	90                   	nop
   140002c7a:	90                   	nop
   140002c7b:	90                   	nop
   140002c7c:	90                   	nop
   140002c7d:	90                   	nop
   140002c7e:	90                   	nop
   140002c7f:	90                   	nop

0000000140002c80 <_ValidateImageBase>:
   140002c80:	55                   	push   rbp
   140002c81:	48 89 e5             	mov    rbp,rsp
   140002c84:	48 83 ec 20          	sub    rsp,0x20
   140002c88:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c8c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c90:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c98:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c9b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c9f:	74 07                	je     140002ca8 <_ValidateImageBase+0x28>
   140002ca1:	b8 00 00 00 00       	mov    eax,0x0
   140002ca6:	eb 4e                	jmp    140002cf6 <_ValidateImageBase+0x76>
   140002ca8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cac:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002caf:	48 63 d0             	movsxd rdx,eax
   140002cb2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cb6:	48 01 d0             	add    rax,rdx
   140002cb9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002cbd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002cc1:	8b 00                	mov    eax,DWORD PTR [rax]
   140002cc3:	3d 50 45 00 00       	cmp    eax,0x4550
   140002cc8:	74 07                	je     140002cd1 <_ValidateImageBase+0x51>
   140002cca:	b8 00 00 00 00       	mov    eax,0x0
   140002ccf:	eb 25                	jmp    140002cf6 <_ValidateImageBase+0x76>
   140002cd1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002cd5:	48 83 c0 18          	add    rax,0x18
   140002cd9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002cdd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ce1:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002ce4:	66 3d 0b 02          	cmp    ax,0x20b
   140002ce8:	74 07                	je     140002cf1 <_ValidateImageBase+0x71>
   140002cea:	b8 00 00 00 00       	mov    eax,0x0
   140002cef:	eb 05                	jmp    140002cf6 <_ValidateImageBase+0x76>
   140002cf1:	b8 01 00 00 00       	mov    eax,0x1
   140002cf6:	48 83 c4 20          	add    rsp,0x20
   140002cfa:	5d                   	pop    rbp
   140002cfb:	c3                   	ret

0000000140002cfc <_FindPESection>:
   140002cfc:	55                   	push   rbp
   140002cfd:	48 89 e5             	mov    rbp,rsp
   140002d00:	48 83 ec 20          	sub    rsp,0x20
   140002d04:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d08:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d0c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d10:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d13:	48 63 d0             	movsxd rdx,eax
   140002d16:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d1a:	48 01 d0             	add    rax,rdx
   140002d1d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d21:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d28:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d2c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d30:	0f b7 d0             	movzx  edx,ax
   140002d33:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d37:	48 01 d0             	add    rax,rdx
   140002d3a:	48 83 c0 18          	add    rax,0x18
   140002d3e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d42:	eb 36                	jmp    140002d7a <_FindPESection+0x7e>
   140002d44:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d48:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d4b:	89 c0                	mov    eax,eax
   140002d4d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d51:	72 1e                	jb     140002d71 <_FindPESection+0x75>
   140002d53:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d57:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d5a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d5e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d61:	01 d0                	add    eax,edx
   140002d63:	89 c0                	mov    eax,eax
   140002d65:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d69:	73 06                	jae    140002d71 <_FindPESection+0x75>
   140002d6b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d6f:	eb 1e                	jmp    140002d8f <_FindPESection+0x93>
   140002d71:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d75:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d7a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d7e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d82:	0f b7 c0             	movzx  eax,ax
   140002d85:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d88:	72 ba                	jb     140002d44 <_FindPESection+0x48>
   140002d8a:	b8 00 00 00 00       	mov    eax,0x0
   140002d8f:	48 83 c4 20          	add    rsp,0x20
   140002d93:	5d                   	pop    rbp
   140002d94:	c3                   	ret

0000000140002d95 <_FindPESectionByName>:
   140002d95:	55                   	push   rbp
   140002d96:	48 89 e5             	mov    rbp,rsp
   140002d99:	48 83 ec 40          	sub    rsp,0x40
   140002d9d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002da1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002da5:	48 89 c1             	mov    rcx,rax
   140002da8:	e8 83 05 00 00       	call   140003330 <strlen>
   140002dad:	48 83 f8 08          	cmp    rax,0x8
   140002db1:	76 0a                	jbe    140002dbd <_FindPESectionByName+0x28>
   140002db3:	b8 00 00 00 00       	mov    eax,0x0
   140002db8:	e9 98 00 00 00       	jmp    140002e55 <_FindPESectionByName+0xc0>
   140002dbd:	48 8b 05 9c 25 00 00 	mov    rax,QWORD PTR [rip+0x259c]        # 140005360 <.refptr.__ImageBase>
   140002dc4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002dc8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dcc:	48 89 c1             	mov    rcx,rax
   140002dcf:	e8 ac fe ff ff       	call   140002c80 <_ValidateImageBase>
   140002dd4:	85 c0                	test   eax,eax
   140002dd6:	75 07                	jne    140002ddf <_FindPESectionByName+0x4a>
   140002dd8:	b8 00 00 00 00       	mov    eax,0x0
   140002ddd:	eb 76                	jmp    140002e55 <_FindPESectionByName+0xc0>
   140002ddf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002de3:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002de6:	48 63 d0             	movsxd rdx,eax
   140002de9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ded:	48 01 d0             	add    rax,rdx
   140002df0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002df4:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002dfb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dff:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e03:	0f b7 d0             	movzx  edx,ax
   140002e06:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e0a:	48 01 d0             	add    rax,rdx
   140002e0d:	48 83 c0 18          	add    rax,0x18
   140002e11:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e15:	eb 29                	jmp    140002e40 <_FindPESectionByName+0xab>
   140002e17:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e1b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e1f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e25:	48 89 c1             	mov    rcx,rax
   140002e28:	e8 0b 05 00 00       	call   140003338 <strncmp>
   140002e2d:	85 c0                	test   eax,eax
   140002e2f:	75 06                	jne    140002e37 <_FindPESectionByName+0xa2>
   140002e31:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e35:	eb 1e                	jmp    140002e55 <_FindPESectionByName+0xc0>
   140002e37:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e3b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e40:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e44:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e48:	0f b7 c0             	movzx  eax,ax
   140002e4b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e4e:	72 c7                	jb     140002e17 <_FindPESectionByName+0x82>
   140002e50:	b8 00 00 00 00       	mov    eax,0x0
   140002e55:	48 83 c4 40          	add    rsp,0x40
   140002e59:	5d                   	pop    rbp
   140002e5a:	c3                   	ret

0000000140002e5b <__mingw_GetSectionForAddress>:
   140002e5b:	55                   	push   rbp
   140002e5c:	48 89 e5             	mov    rbp,rsp
   140002e5f:	48 83 ec 30          	sub    rsp,0x30
   140002e63:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e67:	48 8b 05 f2 24 00 00 	mov    rax,QWORD PTR [rip+0x24f2]        # 140005360 <.refptr.__ImageBase>
   140002e6e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e76:	48 89 c1             	mov    rcx,rax
   140002e79:	e8 02 fe ff ff       	call   140002c80 <_ValidateImageBase>
   140002e7e:	85 c0                	test   eax,eax
   140002e80:	75 07                	jne    140002e89 <__mingw_GetSectionForAddress+0x2e>
   140002e82:	b8 00 00 00 00       	mov    eax,0x0
   140002e87:	eb 1c                	jmp    140002ea5 <__mingw_GetSectionForAddress+0x4a>
   140002e89:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e8d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e91:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e95:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e99:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e9d:	48 89 c1             	mov    rcx,rax
   140002ea0:	e8 57 fe ff ff       	call   140002cfc <_FindPESection>
   140002ea5:	48 83 c4 30          	add    rsp,0x30
   140002ea9:	5d                   	pop    rbp
   140002eaa:	c3                   	ret

0000000140002eab <__mingw_GetSectionCount>:
   140002eab:	55                   	push   rbp
   140002eac:	48 89 e5             	mov    rbp,rsp
   140002eaf:	48 83 ec 30          	sub    rsp,0x30
   140002eb3:	48 8b 05 a6 24 00 00 	mov    rax,QWORD PTR [rip+0x24a6]        # 140005360 <.refptr.__ImageBase>
   140002eba:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ebe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ec2:	48 89 c1             	mov    rcx,rax
   140002ec5:	e8 b6 fd ff ff       	call   140002c80 <_ValidateImageBase>
   140002eca:	85 c0                	test   eax,eax
   140002ecc:	75 07                	jne    140002ed5 <__mingw_GetSectionCount+0x2a>
   140002ece:	b8 00 00 00 00       	mov    eax,0x0
   140002ed3:	eb 20                	jmp    140002ef5 <__mingw_GetSectionCount+0x4a>
   140002ed5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ed9:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002edc:	48 63 d0             	movsxd rdx,eax
   140002edf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ee3:	48 01 d0             	add    rax,rdx
   140002ee6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002eea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002eee:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ef2:	0f b7 c0             	movzx  eax,ax
   140002ef5:	48 83 c4 30          	add    rsp,0x30
   140002ef9:	5d                   	pop    rbp
   140002efa:	c3                   	ret

0000000140002efb <_FindPESectionExec>:
   140002efb:	55                   	push   rbp
   140002efc:	48 89 e5             	mov    rbp,rsp
   140002eff:	48 83 ec 40          	sub    rsp,0x40
   140002f03:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f07:	48 8b 05 52 24 00 00 	mov    rax,QWORD PTR [rip+0x2452]        # 140005360 <.refptr.__ImageBase>
   140002f0e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f12:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f16:	48 89 c1             	mov    rcx,rax
   140002f19:	e8 62 fd ff ff       	call   140002c80 <_ValidateImageBase>
   140002f1e:	85 c0                	test   eax,eax
   140002f20:	75 07                	jne    140002f29 <_FindPESectionExec+0x2e>
   140002f22:	b8 00 00 00 00       	mov    eax,0x0
   140002f27:	eb 78                	jmp    140002fa1 <_FindPESectionExec+0xa6>
   140002f29:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f2d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f30:	48 63 d0             	movsxd rdx,eax
   140002f33:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f37:	48 01 d0             	add    rax,rdx
   140002f3a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f3e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f45:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f49:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f4d:	0f b7 d0             	movzx  edx,ax
   140002f50:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f54:	48 01 d0             	add    rax,rdx
   140002f57:	48 83 c0 18          	add    rax,0x18
   140002f5b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f5f:	eb 2b                	jmp    140002f8c <_FindPESectionExec+0x91>
   140002f61:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f65:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f68:	25 00 00 00 20       	and    eax,0x20000000
   140002f6d:	85 c0                	test   eax,eax
   140002f6f:	74 12                	je     140002f83 <_FindPESectionExec+0x88>
   140002f71:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f76:	75 06                	jne    140002f7e <_FindPESectionExec+0x83>
   140002f78:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f7c:	eb 23                	jmp    140002fa1 <_FindPESectionExec+0xa6>
   140002f7e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f83:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f87:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f8c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f90:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f94:	0f b7 c0             	movzx  eax,ax
   140002f97:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f9a:	72 c5                	jb     140002f61 <_FindPESectionExec+0x66>
   140002f9c:	b8 00 00 00 00       	mov    eax,0x0
   140002fa1:	48 83 c4 40          	add    rsp,0x40
   140002fa5:	5d                   	pop    rbp
   140002fa6:	c3                   	ret

0000000140002fa7 <_GetPEImageBase>:
   140002fa7:	55                   	push   rbp
   140002fa8:	48 89 e5             	mov    rbp,rsp
   140002fab:	48 83 ec 30          	sub    rsp,0x30
   140002faf:	48 8b 05 aa 23 00 00 	mov    rax,QWORD PTR [rip+0x23aa]        # 140005360 <.refptr.__ImageBase>
   140002fb6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fbe:	48 89 c1             	mov    rcx,rax
   140002fc1:	e8 ba fc ff ff       	call   140002c80 <_ValidateImageBase>
   140002fc6:	85 c0                	test   eax,eax
   140002fc8:	75 07                	jne    140002fd1 <_GetPEImageBase+0x2a>
   140002fca:	b8 00 00 00 00       	mov    eax,0x0
   140002fcf:	eb 04                	jmp    140002fd5 <_GetPEImageBase+0x2e>
   140002fd1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fd5:	48 83 c4 30          	add    rsp,0x30
   140002fd9:	5d                   	pop    rbp
   140002fda:	c3                   	ret

0000000140002fdb <_IsNonwritableInCurrentImage>:
   140002fdb:	55                   	push   rbp
   140002fdc:	48 89 e5             	mov    rbp,rsp
   140002fdf:	48 83 ec 40          	sub    rsp,0x40
   140002fe3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002fe7:	48 8b 05 72 23 00 00 	mov    rax,QWORD PTR [rip+0x2372]        # 140005360 <.refptr.__ImageBase>
   140002fee:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ff2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ff6:	48 89 c1             	mov    rcx,rax
   140002ff9:	e8 82 fc ff ff       	call   140002c80 <_ValidateImageBase>
   140002ffe:	85 c0                	test   eax,eax
   140003000:	75 07                	jne    140003009 <_IsNonwritableInCurrentImage+0x2e>
   140003002:	b8 00 00 00 00       	mov    eax,0x0
   140003007:	eb 3d                	jmp    140003046 <_IsNonwritableInCurrentImage+0x6b>
   140003009:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000300d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003011:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003015:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003019:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000301d:	48 89 c1             	mov    rcx,rax
   140003020:	e8 d7 fc ff ff       	call   140002cfc <_FindPESection>
   140003025:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003029:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000302e:	75 07                	jne    140003037 <_IsNonwritableInCurrentImage+0x5c>
   140003030:	b8 00 00 00 00       	mov    eax,0x0
   140003035:	eb 0f                	jmp    140003046 <_IsNonwritableInCurrentImage+0x6b>
   140003037:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000303b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000303e:	f7 d0                	not    eax
   140003040:	c1 e8 1f             	shr    eax,0x1f
   140003043:	0f b6 c0             	movzx  eax,al
   140003046:	48 83 c4 40          	add    rsp,0x40
   14000304a:	5d                   	pop    rbp
   14000304b:	c3                   	ret

000000014000304c <__mingw_enum_import_library_names>:
   14000304c:	55                   	push   rbp
   14000304d:	48 89 e5             	mov    rbp,rsp
   140003050:	48 83 ec 50          	sub    rsp,0x50
   140003054:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003057:	48 8b 05 02 23 00 00 	mov    rax,QWORD PTR [rip+0x2302]        # 140005360 <.refptr.__ImageBase>
   14000305e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003062:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003066:	48 89 c1             	mov    rcx,rax
   140003069:	e8 12 fc ff ff       	call   140002c80 <_ValidateImageBase>
   14000306e:	85 c0                	test   eax,eax
   140003070:	75 0a                	jne    14000307c <__mingw_enum_import_library_names+0x30>
   140003072:	b8 00 00 00 00       	mov    eax,0x0
   140003077:	e9 ab 00 00 00       	jmp    140003127 <__mingw_enum_import_library_names+0xdb>
   14000307c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003080:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003083:	48 63 d0             	movsxd rdx,eax
   140003086:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000308a:	48 01 d0             	add    rax,rdx
   14000308d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003091:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003095:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000309b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000309e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400030a2:	75 07                	jne    1400030ab <__mingw_enum_import_library_names+0x5f>
   1400030a4:	b8 00 00 00 00       	mov    eax,0x0
   1400030a9:	eb 7c                	jmp    140003127 <__mingw_enum_import_library_names+0xdb>
   1400030ab:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030ae:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030b2:	48 89 c1             	mov    rcx,rax
   1400030b5:	e8 42 fc ff ff       	call   140002cfc <_FindPESection>
   1400030ba:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400030be:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   1400030c3:	75 07                	jne    1400030cc <__mingw_enum_import_library_names+0x80>
   1400030c5:	b8 00 00 00 00       	mov    eax,0x0
   1400030ca:	eb 5b                	jmp    140003127 <__mingw_enum_import_library_names+0xdb>
   1400030cc:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030cf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030d3:	48 01 d0             	add    rax,rdx
   1400030d6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030da:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400030df:	75 07                	jne    1400030e8 <__mingw_enum_import_library_names+0x9c>
   1400030e1:	b8 00 00 00 00       	mov    eax,0x0
   1400030e6:	eb 3f                	jmp    140003127 <__mingw_enum_import_library_names+0xdb>
   1400030e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030ec:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400030ef:	85 c0                	test   eax,eax
   1400030f1:	75 0b                	jne    1400030fe <__mingw_enum_import_library_names+0xb2>
   1400030f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030f7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030fa:	85 c0                	test   eax,eax
   1400030fc:	74 23                	je     140003121 <__mingw_enum_import_library_names+0xd5>
   1400030fe:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003102:	7f 12                	jg     140003116 <__mingw_enum_import_library_names+0xca>
   140003104:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003108:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000310b:	89 c2                	mov    edx,eax
   14000310d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003111:	48 01 d0             	add    rax,rdx
   140003114:	eb 11                	jmp    140003127 <__mingw_enum_import_library_names+0xdb>
   140003116:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000311a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000311f:	eb c7                	jmp    1400030e8 <__mingw_enum_import_library_names+0x9c>
   140003121:	90                   	nop
   140003122:	b8 00 00 00 00       	mov    eax,0x0
   140003127:	48 83 c4 50          	add    rsp,0x50
   14000312b:	5d                   	pop    rbp
   14000312c:	c3                   	ret
   14000312d:	90                   	nop
   14000312e:	90                   	nop
   14000312f:	90                   	nop

0000000140003130 <___chkstk_ms>:
   140003130:	51                   	push   rcx
   140003131:	50                   	push   rax
   140003132:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003138:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000313d:	72 19                	jb     140003158 <___chkstk_ms+0x28>
   14000313f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003146:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000314a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003150:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003156:	77 e7                	ja     14000313f <___chkstk_ms+0xf>
   140003158:	48 29 c1             	sub    rcx,rax
   14000315b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000315f:	58                   	pop    rax
   140003160:	59                   	pop    rcx
   140003161:	c3                   	ret
   140003162:	90                   	nop
   140003163:	90                   	nop
   140003164:	90                   	nop
   140003165:	90                   	nop
   140003166:	90                   	nop
   140003167:	90                   	nop
   140003168:	90                   	nop
   140003169:	90                   	nop
   14000316a:	90                   	nop
   14000316b:	90                   	nop
   14000316c:	90                   	nop
   14000316d:	90                   	nop
   14000316e:	90                   	nop
   14000316f:	90                   	nop

0000000140003170 <_initterm_e>:
   140003170:	55                   	push   rbp
   140003171:	48 89 e5             	mov    rbp,rsp
   140003174:	48 83 ec 30          	sub    rsp,0x30
   140003178:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000317c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003180:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003184:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003188:	eb 29                	jmp    1400031b3 <_initterm_e+0x43>
   14000318a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000318e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140003191:	48 85 c0             	test   rax,rax
   140003194:	74 17                	je     1400031ad <_initterm_e+0x3d>
   140003196:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000319a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000319d:	ff d0                	call   rax
   14000319f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400031a2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   1400031a6:	74 06                	je     1400031ae <_initterm_e+0x3e>
   1400031a8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400031ab:	eb 15                	jmp    1400031c2 <_initterm_e+0x52>
   1400031ad:	90                   	nop
   1400031ae:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400031b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031b7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400031bb:	72 cd                	jb     14000318a <_initterm_e+0x1a>
   1400031bd:	b8 00 00 00 00       	mov    eax,0x0
   1400031c2:	48 83 c4 30          	add    rsp,0x30
   1400031c6:	5d                   	pop    rbp
   1400031c7:	c3                   	ret
   1400031c8:	90                   	nop
   1400031c9:	90                   	nop
   1400031ca:	90                   	nop
   1400031cb:	90                   	nop
   1400031cc:	90                   	nop
   1400031cd:	90                   	nop
   1400031ce:	90                   	nop
   1400031cf:	90                   	nop

00000001400031d0 <__p__fmode>:
   1400031d0:	55                   	push   rbp
   1400031d1:	48 89 e5             	mov    rbp,rsp
   1400031d4:	48 8b 05 f5 21 00 00 	mov    rax,QWORD PTR [rip+0x21f5]        # 1400053d0 <.refptr.__imp__fmode>
   1400031db:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031de:	5d                   	pop    rbp
   1400031df:	c3                   	ret

00000001400031e0 <__p__commode>:
   1400031e0:	55                   	push   rbp
   1400031e1:	48 89 e5             	mov    rbp,rsp
   1400031e4:	48 8b 05 d5 21 00 00 	mov    rax,QWORD PTR [rip+0x21d5]        # 1400053c0 <.refptr.__imp__commode>
   1400031eb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031ee:	5d                   	pop    rbp
   1400031ef:	c3                   	ret

00000001400031f0 <__p___initenv>:
   1400031f0:	55                   	push   rbp
   1400031f1:	48 89 e5             	mov    rbp,rsp
   1400031f4:	48 8b 05 b5 21 00 00 	mov    rax,QWORD PTR [rip+0x21b5]        # 1400053b0 <.refptr.__imp___initenv>
   1400031fb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031fe:	5d                   	pop    rbp
   1400031ff:	c3                   	ret

0000000140003200 <_set_invalid_parameter_handler>:
   140003200:	55                   	push   rbp
   140003201:	48 89 e5             	mov    rbp,rsp
   140003204:	48 83 ec 10          	sub    rsp,0x10
   140003208:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000320c:	48 8d 05 7d 5f 00 00 	lea    rax,[rip+0x5f7d]        # 140009190 <handler>
   140003213:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003217:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000321b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000321f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003223:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003227:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000322a:	48 89 d0             	mov    rax,rdx
   14000322d:	48 83 c4 10          	add    rsp,0x10
   140003231:	5d                   	pop    rbp
   140003232:	c3                   	ret

0000000140003233 <_get_invalid_parameter_handler>:
   140003233:	55                   	push   rbp
   140003234:	48 89 e5             	mov    rbp,rsp
   140003237:	48 8b 05 52 5f 00 00 	mov    rax,QWORD PTR [rip+0x5f52]        # 140009190 <handler>
   14000323e:	5d                   	pop    rbp
   14000323f:	c3                   	ret

0000000140003240 <_configthreadlocale>:
   140003240:	55                   	push   rbp
   140003241:	48 89 e5             	mov    rbp,rsp
   140003244:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003247:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000324b:	75 07                	jne    140003254 <_configthreadlocale+0x14>
   14000324d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140003252:	eb 05                	jmp    140003259 <_configthreadlocale+0x19>
   140003254:	b8 02 00 00 00       	mov    eax,0x2
   140003259:	5d                   	pop    rbp
   14000325a:	c3                   	ret
   14000325b:	90                   	nop
   14000325c:	90                   	nop
   14000325d:	90                   	nop
   14000325e:	90                   	nop
   14000325f:	90                   	nop

0000000140003260 <__acrt_iob_func>:
   140003260:	55                   	push   rbp
   140003261:	48 89 e5             	mov    rbp,rsp
   140003264:	48 83 ec 20          	sub    rsp,0x20
   140003268:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000326b:	e8 30 00 00 00       	call   1400032a0 <__iob_func>
   140003270:	48 89 c1             	mov    rcx,rax
   140003273:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003276:	48 89 d0             	mov    rax,rdx
   140003279:	48 01 c0             	add    rax,rax
   14000327c:	48 01 d0             	add    rax,rdx
   14000327f:	48 c1 e0 04          	shl    rax,0x4
   140003283:	48 01 c8             	add    rax,rcx
   140003286:	48 83 c4 20          	add    rsp,0x20
   14000328a:	5d                   	pop    rbp
   14000328b:	c3                   	ret
   14000328c:	90                   	nop
   14000328d:	90                   	nop
   14000328e:	90                   	nop
   14000328f:	90                   	nop

0000000140003290 <__C_specific_handler>:
   140003290:	ff 25 72 6f 00 00    	jmp    QWORD PTR [rip+0x6f72]        # 14000a208 <__imp___C_specific_handler>
   140003296:	90                   	nop
   140003297:	90                   	nop

0000000140003298 <__getmainargs>:
   140003298:	ff 25 72 6f 00 00    	jmp    QWORD PTR [rip+0x6f72]        # 14000a210 <__imp___getmainargs>
   14000329e:	90                   	nop
   14000329f:	90                   	nop

00000001400032a0 <__iob_func>:
   1400032a0:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a220 <__imp___iob_func>
   1400032a6:	90                   	nop
   1400032a7:	90                   	nop

00000001400032a8 <__set_app_type>:
   1400032a8:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a228 <__imp___set_app_type>
   1400032ae:	90                   	nop
   1400032af:	90                   	nop

00000001400032b0 <__setusermatherr>:
   1400032b0:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a230 <__imp___setusermatherr>
   1400032b6:	90                   	nop
   1400032b7:	90                   	nop

00000001400032b8 <_amsg_exit>:
   1400032b8:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a238 <__imp__amsg_exit>
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <_cexit>:
   1400032c0:	ff 25 7a 6f 00 00    	jmp    QWORD PTR [rip+0x6f7a]        # 14000a240 <__imp__cexit>
   1400032c6:	90                   	nop
   1400032c7:	90                   	nop

00000001400032c8 <_initterm>:
   1400032c8:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a258 <__imp__initterm>
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <_crt_atexit>:
   1400032d0:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a260 <__imp__crt_atexit>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop

00000001400032d8 <abort>:
   1400032d8:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a268 <__imp_abort>
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <calloc>:
   1400032e0:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a270 <__imp_calloc>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <exit>:
   1400032e8:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a278 <__imp_exit>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <fflush>:
   1400032f0:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a280 <__imp_fflush>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <fprintf>:
   1400032f8:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a288 <__imp_fprintf>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <free>:
   140003300:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a290 <__imp_free>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <malloc>:
   140003308:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a298 <__imp_malloc>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <memcpy>:
   140003310:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a2a0 <__imp_memcpy>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <memset>:
   140003318:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a2a8 <__imp_memset>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <setvbuf>:
   140003320:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a2b0 <__imp_setvbuf>
   140003326:	90                   	nop
   140003327:	90                   	nop

0000000140003328 <signal>:
   140003328:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a2b8 <__imp_signal>
   14000332e:	90                   	nop
   14000332f:	90                   	nop

0000000140003330 <strlen>:
   140003330:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a2c0 <__imp_strlen>
   140003336:	90                   	nop
   140003337:	90                   	nop

0000000140003338 <strncmp>:
   140003338:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a2c8 <__imp_strncmp>
   14000333e:	90                   	nop
   14000333f:	90                   	nop

0000000140003340 <vfprintf>:
   140003340:	ff 25 8a 6f 00 00    	jmp    QWORD PTR [rip+0x6f8a]        # 14000a2d0 <__imp_vfprintf>
   140003346:	90                   	nop
   140003347:	90                   	nop
   140003348:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000334f:	00 

0000000140003350 <VirtualQuery>:
   140003350:	ff 25 a2 6e 00 00    	jmp    QWORD PTR [rip+0x6ea2]        # 14000a1f8 <__imp_VirtualQuery>
   140003356:	90                   	nop
   140003357:	90                   	nop

0000000140003358 <VirtualProtect>:
   140003358:	ff 25 92 6e 00 00    	jmp    QWORD PTR [rip+0x6e92]        # 14000a1f0 <__imp_VirtualProtect>
   14000335e:	90                   	nop
   14000335f:	90                   	nop

0000000140003360 <TlsGetValue>:
   140003360:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a1e8 <__imp_TlsGetValue>
   140003366:	90                   	nop
   140003367:	90                   	nop

0000000140003368 <Sleep>:
   140003368:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a1e0 <__imp_Sleep>
   14000336e:	90                   	nop
   14000336f:	90                   	nop

0000000140003370 <SetUnhandledExceptionFilter>:
   140003370:	ff 25 62 6e 00 00    	jmp    QWORD PTR [rip+0x6e62]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   140003376:	90                   	nop
   140003377:	90                   	nop

0000000140003378 <LoadLibraryA>:
   140003378:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 14000a1d0 <__imp_LoadLibraryA>
   14000337e:	90                   	nop
   14000337f:	90                   	nop

0000000140003380 <LeaveCriticalSection>:
   140003380:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140003386:	90                   	nop
   140003387:	90                   	nop

0000000140003388 <InitializeCriticalSection>:
   140003388:	ff 25 32 6e 00 00    	jmp    QWORD PTR [rip+0x6e32]        # 14000a1c0 <__imp_InitializeCriticalSection>
   14000338e:	90                   	nop
   14000338f:	90                   	nop

0000000140003390 <GetProcAddress>:
   140003390:	ff 25 22 6e 00 00    	jmp    QWORD PTR [rip+0x6e22]        # 14000a1b8 <__imp_GetProcAddress>
   140003396:	90                   	nop
   140003397:	90                   	nop

0000000140003398 <GetModuleHandleA>:
   140003398:	ff 25 12 6e 00 00    	jmp    QWORD PTR [rip+0x6e12]        # 14000a1b0 <__imp_GetModuleHandleA>
   14000339e:	90                   	nop
   14000339f:	90                   	nop

00000001400033a0 <GetLastError>:
   1400033a0:	ff 25 02 6e 00 00    	jmp    QWORD PTR [rip+0x6e02]        # 14000a1a8 <__imp_GetLastError>
   1400033a6:	90                   	nop
   1400033a7:	90                   	nop

00000001400033a8 <FreeLibrary>:
   1400033a8:	ff 25 f2 6d 00 00    	jmp    QWORD PTR [rip+0x6df2]        # 14000a1a0 <__imp_FreeLibrary>
   1400033ae:	90                   	nop
   1400033af:	90                   	nop

00000001400033b0 <EnterCriticalSection>:
   1400033b0:	ff 25 e2 6d 00 00    	jmp    QWORD PTR [rip+0x6de2]        # 14000a198 <__imp_EnterCriticalSection>
   1400033b6:	90                   	nop
   1400033b7:	90                   	nop

00000001400033b8 <DeleteCriticalSection>:
   1400033b8:	ff 25 d2 6d 00 00    	jmp    QWORD PTR [rip+0x6dd2]        # 14000a190 <__IAT_start__>
   1400033be:	90                   	nop
   1400033bf:	90                   	nop

00000001400033c0 <register_frame_ctor>:
   1400033c0:	e9 ab e2 ff ff       	jmp    140001670 <__gcc_register_frame>
   1400033c5:	90                   	nop
   1400033c6:	90                   	nop
   1400033c7:	90                   	nop
   1400033c8:	90                   	nop
   1400033c9:	90                   	nop
   1400033ca:	90                   	nop
   1400033cb:	90                   	nop
   1400033cc:	90                   	nop
   1400033cd:	90                   	nop
   1400033ce:	90                   	nop
   1400033cf:	90                   	nop
