
C:\Users\Administrator\Desktop\BinMind\round2\samples\uaf\cve_2016_5195_dirtycow\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 f7 22 00 00       	call   140003320 <fflush>
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
   14000113b:	e8 a8 21 00 00       	call   1400032e8 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 28 21 00 00       	call   140003290 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 cf 21 00 00       	call   140003350 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 6f 21 00 00       	call   140003308 <abort>
   140001199:	e8 f2 11 00 00       	call   140002390 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 29 90 00 00 	mov    rax,QWORD PTR [rip+0x9029]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 66 20 00 00       	call   140003230 <_set_invalid_parameter_handler>
   1400011ca:	e8 d1 1a 00 00       	call   140002ca0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 e7 20 00 00       	call   1400032d8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 db 20 00 00       	call   1400032d8 <__set_app_type>
   1400011fd:	e8 fe 1f 00 00       	call   140003200 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 fe 1f 00 00       	call   140003210 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 4e 07 00 00       	call   140001970 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 b3 20 00 00       	call   1400032e8 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 58 12 00 00       	call   1400024aa <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 06 20 00 00       	call   140003270 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 20 1f 00 00       	call   1400031a0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 5a 20 00 00       	call   1400032e8 <_amsg_exit>
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
   1400012cb:	e8 f8 1f 00 00       	call   1400032c8 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 05 20 00 00       	call   1400032e8 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 de 1f 00 00       	call   1400032e8 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 d8 1f 00 00       	call   1400032f8 <_initterm>
   140001320:	e8 22 06 00 00       	call   140001947 <__main>
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
   14000138d:	e8 8e 1e 00 00       	call   140003220 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 45 04 00 00       	call   1400017ff <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 47 1f 00 00       	call   140003318 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 10 1f 00 00       	call   1400032f0 <_cexit>
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
   140001511:	e8 22 1e 00 00       	call   140003338 <malloc>
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
   14000155c:	e8 ff 1d 00 00       	call   140003360 <strlen>
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
   140001585:	e8 ae 1d 00 00       	call   140003338 <malloc>
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
   1400015e8:	e8 53 1d 00 00       	call   140003340 <memcpy>
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
   140001642:	e8 b9 1c 00 00       	call   140003300 <_crt_atexit>
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

0000000140001760 <cow_page_free>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 20          	sub    rsp,0x20
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001770:	8b 00                	mov    eax,DWORD PTR [rax]
   140001772:	8d 50 ff             	lea    edx,[rax-0x1]
   140001775:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001779:	89 10                	mov    DWORD PTR [rax],edx
   14000177b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000177f:	8b 00                	mov    eax,DWORD PTR [rax]
   140001781:	85 c0                	test   eax,eax
   140001783:	75 0c                	jne    140001791 <cow_page_free+0x31>
   140001785:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001789:	48 89 c1             	mov    rcx,rax
   14000178c:	e8 9f 1b 00 00       	call   140003330 <free>
   140001791:	90                   	nop
   140001792:	48 83 c4 20          	add    rsp,0x20
   140001796:	5d                   	pop    rbp
   140001797:	c3                   	ret

0000000140001798 <handle_mm_fault>:
   140001798:	55                   	push   rbp
   140001799:	48 89 e5             	mov    rbp,rsp
   14000179c:	48 83 ec 30          	sub    rsp,0x30
   1400017a0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400017a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017a8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017ab:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400017af:	b9 48 00 00 00       	mov    ecx,0x48
   1400017b4:	e8 7f 1b 00 00       	call   140003338 <malloc>
   1400017b9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400017bd:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400017c1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017c5:	41 b8 48 00 00 00    	mov    r8d,0x48
   1400017cb:	48 89 c1             	mov    rcx,rax
   1400017ce:	e8 6d 1b 00 00       	call   140003340 <memcpy>
   1400017d3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017d7:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   1400017dd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017e1:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400017e5:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400017e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017ec:	48 89 c1             	mov    rcx,rax
   1400017ef:	e8 6c ff ff ff       	call   140001760 <cow_page_free>
   1400017f4:	b8 00 00 00 00       	mov    eax,0x0
   1400017f9:	48 83 c4 30          	add    rsp,0x30
   1400017fd:	5d                   	pop    rbp
   1400017fe:	c3                   	ret

00000001400017ff <main>:
   1400017ff:	55                   	push   rbp
   140001800:	48 89 e5             	mov    rbp,rsp
   140001803:	48 83 ec 30          	sub    rsp,0x30
   140001807:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000180a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000180e:	e8 34 01 00 00       	call   140001947 <__main>
   140001813:	b9 10 00 00 00       	mov    ecx,0x10
   140001818:	e8 1b 1b 00 00       	call   140003338 <malloc>
   14000181d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001821:	b9 48 00 00 00       	mov    ecx,0x48
   140001826:	e8 0d 1b 00 00       	call   140003338 <malloc>
   14000182b:	48 89 c2             	mov    rdx,rax
   14000182e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001832:	48 89 10             	mov    QWORD PTR [rax],rdx
   140001835:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001839:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000183c:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   140001842:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001846:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001849:	48 83 c0 04          	add    rax,0x4
   14000184d:	41 b8 40 00 00 00    	mov    r8d,0x40
   140001853:	ba 43 00 00 00       	mov    edx,0x43
   140001858:	48 89 c1             	mov    rcx,rax
   14000185b:	e8 e8 1a 00 00       	call   140003348 <memset>
   140001860:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001864:	48 89 c1             	mov    rcx,rax
   140001867:	e8 2c ff ff ff       	call   140001798 <handle_mm_fault>
   14000186c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001870:	48 89 c1             	mov    rcx,rax
   140001873:	e8 20 ff ff ff       	call   140001798 <handle_mm_fault>
   140001878:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000187c:	48 89 c1             	mov    rcx,rax
   14000187f:	e8 ac 1a 00 00       	call   140003330 <free>
   140001884:	b8 00 00 00 00       	mov    eax,0x0
   140001889:	48 83 c4 30          	add    rsp,0x30
   14000188d:	5d                   	pop    rbp
   14000188e:	c3                   	ret
   14000188f:	90                   	nop

0000000140001890 <__do_global_dtors>:
   140001890:	55                   	push   rbp
   140001891:	48 89 e5             	mov    rbp,rsp
   140001894:	48 83 ec 20          	sub    rsp,0x20
   140001898:	eb 1e                	jmp    1400018b8 <__do_global_dtors+0x28>
   14000189a:	48 8b 05 6f 27 00 00 	mov    rax,QWORD PTR [rip+0x276f]        # 140004010 <p.0>
   1400018a1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018a4:	ff d0                	call   rax
   1400018a6:	48 8b 05 63 27 00 00 	mov    rax,QWORD PTR [rip+0x2763]        # 140004010 <p.0>
   1400018ad:	48 83 c0 08          	add    rax,0x8
   1400018b1:	48 89 05 58 27 00 00 	mov    QWORD PTR [rip+0x2758],rax        # 140004010 <p.0>
   1400018b8:	48 8b 05 51 27 00 00 	mov    rax,QWORD PTR [rip+0x2751]        # 140004010 <p.0>
   1400018bf:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018c2:	48 85 c0             	test   rax,rax
   1400018c5:	75 d3                	jne    14000189a <__do_global_dtors+0xa>
   1400018c7:	90                   	nop
   1400018c8:	90                   	nop
   1400018c9:	48 83 c4 20          	add    rsp,0x20
   1400018cd:	5d                   	pop    rbp
   1400018ce:	c3                   	ret

00000001400018cf <__do_global_ctors>:
   1400018cf:	55                   	push   rbp
   1400018d0:	48 89 e5             	mov    rbp,rsp
   1400018d3:	48 83 ec 30          	sub    rsp,0x30
   1400018d7:	48 8b 05 72 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a72]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018de:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018e1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400018e4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400018e8:	75 25                	jne    14000190f <__do_global_ctors+0x40>
   1400018ea:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400018f1:	eb 04                	jmp    1400018f7 <__do_global_ctors+0x28>
   1400018f3:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400018f7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018fa:	8d 50 01             	lea    edx,[rax+0x1]
   1400018fd:	48 8b 05 4c 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a4c]        # 140005350 <.refptr.__CTOR_LIST__>
   140001904:	89 d2                	mov    edx,edx
   140001906:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000190a:	48 85 c0             	test   rax,rax
   14000190d:	75 e4                	jne    1400018f3 <__do_global_ctors+0x24>
   14000190f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001912:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001915:	eb 14                	jmp    14000192b <__do_global_ctors+0x5c>
   140001917:	48 8b 05 32 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a32]        # 140005350 <.refptr.__CTOR_LIST__>
   14000191e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001921:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001925:	ff d0                	call   rax
   140001927:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000192b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000192f:	75 e6                	jne    140001917 <__do_global_ctors+0x48>
   140001931:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001890 <__do_global_dtors>
   140001938:	48 89 c1             	mov    rcx,rax
   14000193b:	e8 ef fc ff ff       	call   14000162f <atexit>
   140001940:	90                   	nop
   140001941:	48 83 c4 30          	add    rsp,0x30
   140001945:	5d                   	pop    rbp
   140001946:	c3                   	ret

0000000140001947 <__main>:
   140001947:	55                   	push   rbp
   140001948:	48 89 e5             	mov    rbp,rsp
   14000194b:	48 83 ec 20          	sub    rsp,0x20
   14000194f:	8b 05 2b 77 00 00    	mov    eax,DWORD PTR [rip+0x772b]        # 140009080 <initialized>
   140001955:	85 c0                	test   eax,eax
   140001957:	75 0f                	jne    140001968 <__main+0x21>
   140001959:	c7 05 1d 77 00 00 01 	mov    DWORD PTR [rip+0x771d],0x1        # 140009080 <initialized>
   140001960:	00 00 00 
   140001963:	e8 67 ff ff ff       	call   1400018cf <__do_global_ctors>
   140001968:	90                   	nop
   140001969:	48 83 c4 20          	add    rsp,0x20
   14000196d:	5d                   	pop    rbp
   14000196e:	c3                   	ret
   14000196f:	90                   	nop

0000000140001970 <_setargv>:
   140001970:	55                   	push   rbp
   140001971:	48 89 e5             	mov    rbp,rsp
   140001974:	b8 00 00 00 00       	mov    eax,0x0
   140001979:	5d                   	pop    rbp
   14000197a:	c3                   	ret
   14000197b:	90                   	nop
   14000197c:	90                   	nop
   14000197d:	90                   	nop
   14000197e:	90                   	nop
   14000197f:	90                   	nop

0000000140001980 <__dyn_tls_init>:
   140001980:	55                   	push   rbp
   140001981:	48 89 e5             	mov    rbp,rsp
   140001984:	48 83 ec 30          	sub    rsp,0x30
   140001988:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000198c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000198f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001993:	48 8b 05 96 39 00 00 	mov    rax,QWORD PTR [rip+0x3996]        # 140005330 <.refptr._CRT_MT>
   14000199a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000199c:	83 f8 02             	cmp    eax,0x2
   14000199f:	74 0d                	je     1400019ae <__dyn_tls_init+0x2e>
   1400019a1:	48 8b 05 88 39 00 00 	mov    rax,QWORD PTR [rip+0x3988]        # 140005330 <.refptr._CRT_MT>
   1400019a8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400019ae:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   1400019b2:	74 1e                	je     1400019d2 <__dyn_tls_init+0x52>
   1400019b4:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   1400019b8:	75 5b                	jne    140001a15 <__dyn_tls_init+0x95>
   1400019ba:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019be:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019c1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019c5:	49 89 c8             	mov    r8,rcx
   1400019c8:	48 89 c1             	mov    rcx,rax
   1400019cb:	e8 d1 11 00 00       	call   140002ba1 <__mingw_TLScallback>
   1400019d0:	eb 43                	jmp    140001a15 <__dyn_tls_init+0x95>
   1400019d2:	48 8d 05 bf 3c 00 00 	lea    rax,[rip+0x3cbf]        # 140005698 <___crt_xd_start__>
   1400019d9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400019dd:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019e2:	eb 22                	jmp    140001a06 <__dyn_tls_init+0x86>
   1400019e4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400019e8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400019ec:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019f0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019f3:	48 85 c0             	test   rax,rax
   1400019f6:	74 09                	je     140001a01 <__dyn_tls_init+0x81>
   1400019f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019fc:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019ff:	ff d0                	call   rax
   140001a01:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001a06:	48 8d 05 93 3c 00 00 	lea    rax,[rip+0x3c93]        # 1400056a0 <__xd_z>
   140001a0d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001a11:	75 d1                	jne    1400019e4 <__dyn_tls_init+0x64>
   140001a13:	eb 01                	jmp    140001a16 <__dyn_tls_init+0x96>
   140001a15:	90                   	nop
   140001a16:	48 83 c4 30          	add    rsp,0x30
   140001a1a:	5d                   	pop    rbp
   140001a1b:	c3                   	ret

0000000140001a1c <__tlregdtor>:
   140001a1c:	55                   	push   rbp
   140001a1d:	48 89 e5             	mov    rbp,rsp
   140001a20:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a24:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001a29:	75 07                	jne    140001a32 <__tlregdtor+0x16>
   140001a2b:	b8 00 00 00 00       	mov    eax,0x0
   140001a30:	eb 05                	jmp    140001a37 <__tlregdtor+0x1b>
   140001a32:	b8 00 00 00 00       	mov    eax,0x0
   140001a37:	5d                   	pop    rbp
   140001a38:	c3                   	ret

0000000140001a39 <__dyn_tls_dtor>:
   140001a39:	55                   	push   rbp
   140001a3a:	48 89 e5             	mov    rbp,rsp
   140001a3d:	48 83 ec 20          	sub    rsp,0x20
   140001a41:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a45:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a48:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a4c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a50:	74 06                	je     140001a58 <__dyn_tls_dtor+0x1f>
   140001a52:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a56:	75 18                	jne    140001a70 <__dyn_tls_dtor+0x37>
   140001a58:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a5c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a5f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a63:	49 89 c8             	mov    r8,rcx
   140001a66:	48 89 c1             	mov    rcx,rax
   140001a69:	e8 33 11 00 00       	call   140002ba1 <__mingw_TLScallback>
   140001a6e:	eb 01                	jmp    140001a71 <__dyn_tls_dtor+0x38>
   140001a70:	90                   	nop
   140001a71:	48 83 c4 20          	add    rsp,0x20
   140001a75:	5d                   	pop    rbp
   140001a76:	c3                   	ret
   140001a77:	90                   	nop
   140001a78:	90                   	nop
   140001a79:	90                   	nop
   140001a7a:	90                   	nop
   140001a7b:	90                   	nop
   140001a7c:	90                   	nop
   140001a7d:	90                   	nop
   140001a7e:	90                   	nop
   140001a7f:	90                   	nop

0000000140001a80 <_matherr>:
   140001a80:	55                   	push   rbp
   140001a81:	53                   	push   rbx
   140001a82:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a89:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a8e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a92:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a96:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a9b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a9f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001aa3:	8b 00                	mov    eax,DWORD PTR [rax]
   140001aa5:	83 f8 06             	cmp    eax,0x6
   140001aa8:	74 56                	je     140001b00 <_matherr+0x80>
   140001aaa:	83 f8 06             	cmp    eax,0x6
   140001aad:	7f 78                	jg     140001b27 <_matherr+0xa7>
   140001aaf:	83 f8 05             	cmp    eax,0x5
   140001ab2:	74 59                	je     140001b0d <_matherr+0x8d>
   140001ab4:	83 f8 05             	cmp    eax,0x5
   140001ab7:	7f 6e                	jg     140001b27 <_matherr+0xa7>
   140001ab9:	83 f8 04             	cmp    eax,0x4
   140001abc:	74 5c                	je     140001b1a <_matherr+0x9a>
   140001abe:	83 f8 04             	cmp    eax,0x4
   140001ac1:	7f 64                	jg     140001b27 <_matherr+0xa7>
   140001ac3:	83 f8 03             	cmp    eax,0x3
   140001ac6:	74 2b                	je     140001af3 <_matherr+0x73>
   140001ac8:	83 f8 03             	cmp    eax,0x3
   140001acb:	7f 5a                	jg     140001b27 <_matherr+0xa7>
   140001acd:	83 f8 01             	cmp    eax,0x1
   140001ad0:	74 07                	je     140001ad9 <_matherr+0x59>
   140001ad2:	83 f8 02             	cmp    eax,0x2
   140001ad5:	74 0f                	je     140001ae6 <_matherr+0x66>
   140001ad7:	eb 4e                	jmp    140001b27 <_matherr+0xa7>
   140001ad9:	48 8d 05 c0 35 00 00 	lea    rax,[rip+0x35c0]        # 1400050a0 <.rdata>
   140001ae0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ae4:	eb 4d                	jmp    140001b33 <_matherr+0xb3>
   140001ae6:	48 8d 05 d2 35 00 00 	lea    rax,[rip+0x35d2]        # 1400050bf <.rdata+0x1f>
   140001aed:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001af1:	eb 40                	jmp    140001b33 <_matherr+0xb3>
   140001af3:	48 8d 05 e6 35 00 00 	lea    rax,[rip+0x35e6]        # 1400050e0 <.rdata+0x40>
   140001afa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001afe:	eb 33                	jmp    140001b33 <_matherr+0xb3>
   140001b00:	48 8d 05 f9 35 00 00 	lea    rax,[rip+0x35f9]        # 140005100 <.rdata+0x60>
   140001b07:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b0b:	eb 26                	jmp    140001b33 <_matherr+0xb3>
   140001b0d:	48 8d 05 14 36 00 00 	lea    rax,[rip+0x3614]        # 140005128 <.rdata+0x88>
   140001b14:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b18:	eb 19                	jmp    140001b33 <_matherr+0xb3>
   140001b1a:	48 8d 05 2f 36 00 00 	lea    rax,[rip+0x362f]        # 140005150 <.rdata+0xb0>
   140001b21:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b25:	eb 0c                	jmp    140001b33 <_matherr+0xb3>
   140001b27:	48 8d 05 58 36 00 00 	lea    rax,[rip+0x3658]        # 140005186 <.rdata+0xe6>
   140001b2e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b32:	90                   	nop
   140001b33:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b37:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b3d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b41:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b46:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b4a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b4f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b53:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b57:	b9 02 00 00 00       	mov    ecx,0x2
   140001b5c:	e8 2f 17 00 00       	call   140003290 <__acrt_iob_func>
   140001b61:	48 89 c1             	mov    rcx,rax
   140001b64:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b68:	48 8d 05 29 36 00 00 	lea    rax,[rip+0x3629]        # 140005198 <.rdata+0xf8>
   140001b6f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b76:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b7c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b82:	49 89 d9             	mov    r9,rbx
   140001b85:	49 89 d0             	mov    r8,rdx
   140001b88:	48 89 c2             	mov    rdx,rax
   140001b8b:	e8 98 17 00 00       	call   140003328 <fprintf>
   140001b90:	b8 00 00 00 00       	mov    eax,0x0
   140001b95:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b99:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b9d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001ba2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001ba9:	5b                   	pop    rbx
   140001baa:	5d                   	pop    rbp
   140001bab:	c3                   	ret
   140001bac:	90                   	nop
   140001bad:	90                   	nop
   140001bae:	90                   	nop
   140001baf:	90                   	nop

0000000140001bb0 <__report_error>:
   140001bb0:	55                   	push   rbp
   140001bb1:	53                   	push   rbx
   140001bb2:	48 83 ec 38          	sub    rsp,0x38
   140001bb6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001bbb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001bbf:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001bc3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001bc7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001bcb:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001bcf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bd3:	b9 02 00 00 00       	mov    ecx,0x2
   140001bd8:	e8 b3 16 00 00       	call   140003290 <__acrt_iob_func>
   140001bdd:	48 89 c1             	mov    rcx,rax
   140001be0:	48 8d 05 e9 35 00 00 	lea    rax,[rip+0x35e9]        # 1400051d0 <.rdata>
   140001be7:	48 89 c2             	mov    rdx,rax
   140001bea:	e8 39 17 00 00       	call   140003328 <fprintf>
   140001bef:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001bf3:	b9 02 00 00 00       	mov    ecx,0x2
   140001bf8:	e8 93 16 00 00       	call   140003290 <__acrt_iob_func>
   140001bfd:	48 89 c1             	mov    rcx,rax
   140001c00:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001c04:	49 89 d8             	mov    r8,rbx
   140001c07:	48 89 c2             	mov    rdx,rax
   140001c0a:	e8 61 17 00 00       	call   140003370 <vfprintf>
   140001c0f:	e8 f4 16 00 00       	call   140003308 <abort>
   140001c14:	90                   	nop

0000000140001c15 <mark_section_writable>:
   140001c15:	55                   	push   rbp
   140001c16:	48 89 e5             	mov    rbp,rsp
   140001c19:	48 83 ec 60          	sub    rsp,0x60
   140001c1d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001c21:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001c28:	e9 82 00 00 00       	jmp    140001caf <mark_section_writable+0x9a>
   140001c2d:	48 8b 0d ac 74 00 00 	mov    rcx,QWORD PTR [rip+0x74ac]        # 1400090e0 <the_secs>
   140001c34:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c37:	48 63 d0             	movsxd rdx,eax
   140001c3a:	48 89 d0             	mov    rax,rdx
   140001c3d:	48 c1 e0 02          	shl    rax,0x2
   140001c41:	48 01 d0             	add    rax,rdx
   140001c44:	48 c1 e0 03          	shl    rax,0x3
   140001c48:	48 01 c8             	add    rax,rcx
   140001c4b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c4f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c53:	72 56                	jb     140001cab <mark_section_writable+0x96>
   140001c55:	48 8b 0d 84 74 00 00 	mov    rcx,QWORD PTR [rip+0x7484]        # 1400090e0 <the_secs>
   140001c5c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c5f:	48 63 d0             	movsxd rdx,eax
   140001c62:	48 89 d0             	mov    rax,rdx
   140001c65:	48 c1 e0 02          	shl    rax,0x2
   140001c69:	48 01 d0             	add    rax,rdx
   140001c6c:	48 c1 e0 03          	shl    rax,0x3
   140001c70:	48 01 c8             	add    rax,rcx
   140001c73:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c77:	4c 8b 05 62 74 00 00 	mov    r8,QWORD PTR [rip+0x7462]        # 1400090e0 <the_secs>
   140001c7e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c81:	48 63 d0             	movsxd rdx,eax
   140001c84:	48 89 d0             	mov    rax,rdx
   140001c87:	48 c1 e0 02          	shl    rax,0x2
   140001c8b:	48 01 d0             	add    rax,rdx
   140001c8e:	48 c1 e0 03          	shl    rax,0x3
   140001c92:	4c 01 c0             	add    rax,r8
   140001c95:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c99:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c9c:	89 c0                	mov    eax,eax
   140001c9e:	48 01 c8             	add    rax,rcx
   140001ca1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001ca5:	0f 82 41 02 00 00    	jb     140001eec <mark_section_writable+0x2d7>
   140001cab:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001caf:	8b 05 33 74 00 00    	mov    eax,DWORD PTR [rip+0x7433]        # 1400090e8 <maxSections>
   140001cb5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001cb8:	0f 8c 6f ff ff ff    	jl     140001c2d <mark_section_writable+0x18>
   140001cbe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001cc2:	48 89 c1             	mov    rcx,rax
   140001cc5:	e8 c1 11 00 00       	call   140002e8b <__mingw_GetSectionForAddress>
   140001cca:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001cce:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001cd3:	75 13                	jne    140001ce8 <mark_section_writable+0xd3>
   140001cd5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001cd9:	48 8d 0d 10 35 00 00 	lea    rcx,[rip+0x3510]        # 1400051f0 <.rdata+0x20>
   140001ce0:	48 89 c2             	mov    rdx,rax
   140001ce3:	e8 c8 fe ff ff       	call   140001bb0 <__report_error>
   140001ce8:	48 8b 0d f1 73 00 00 	mov    rcx,QWORD PTR [rip+0x73f1]        # 1400090e0 <the_secs>
   140001cef:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cf2:	48 63 d0             	movsxd rdx,eax
   140001cf5:	48 89 d0             	mov    rax,rdx
   140001cf8:	48 c1 e0 02          	shl    rax,0x2
   140001cfc:	48 01 d0             	add    rax,rdx
   140001cff:	48 c1 e0 03          	shl    rax,0x3
   140001d03:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d07:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d0b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001d0f:	48 8b 0d ca 73 00 00 	mov    rcx,QWORD PTR [rip+0x73ca]        # 1400090e0 <the_secs>
   140001d16:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d19:	48 63 d0             	movsxd rdx,eax
   140001d1c:	48 89 d0             	mov    rax,rdx
   140001d1f:	48 c1 e0 02          	shl    rax,0x2
   140001d23:	48 01 d0             	add    rax,rdx
   140001d26:	48 c1 e0 03          	shl    rax,0x3
   140001d2a:	48 01 c8             	add    rax,rcx
   140001d2d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d33:	e8 9f 12 00 00       	call   140002fd7 <_GetPEImageBase>
   140001d38:	48 89 c1             	mov    rcx,rax
   140001d3b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d3f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d42:	41 89 c1             	mov    r9d,eax
   140001d45:	4c 8b 05 94 73 00 00 	mov    r8,QWORD PTR [rip+0x7394]        # 1400090e0 <the_secs>
   140001d4c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d4f:	48 63 d0             	movsxd rdx,eax
   140001d52:	48 89 d0             	mov    rax,rdx
   140001d55:	48 c1 e0 02          	shl    rax,0x2
   140001d59:	48 01 d0             	add    rax,rdx
   140001d5c:	48 c1 e0 03          	shl    rax,0x3
   140001d60:	4c 01 c0             	add    rax,r8
   140001d63:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d67:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d6b:	48 8b 0d 6e 73 00 00 	mov    rcx,QWORD PTR [rip+0x736e]        # 1400090e0 <the_secs>
   140001d72:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d75:	48 63 d0             	movsxd rdx,eax
   140001d78:	48 89 d0             	mov    rax,rdx
   140001d7b:	48 c1 e0 02          	shl    rax,0x2
   140001d7f:	48 01 d0             	add    rax,rdx
   140001d82:	48 c1 e0 03          	shl    rax,0x3
   140001d86:	48 01 c8             	add    rax,rcx
   140001d89:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d8d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d91:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d97:	48 89 c1             	mov    rcx,rax
   140001d9a:	48 8b 05 57 84 00 00 	mov    rax,QWORD PTR [rip+0x8457]        # 14000a1f8 <__imp_VirtualQuery>
   140001da1:	ff d0                	call   rax
   140001da3:	48 85 c0             	test   rax,rax
   140001da6:	75 3f                	jne    140001de7 <mark_section_writable+0x1d2>
   140001da8:	48 8b 0d 31 73 00 00 	mov    rcx,QWORD PTR [rip+0x7331]        # 1400090e0 <the_secs>
   140001daf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001db2:	48 63 d0             	movsxd rdx,eax
   140001db5:	48 89 d0             	mov    rax,rdx
   140001db8:	48 c1 e0 02          	shl    rax,0x2
   140001dbc:	48 01 d0             	add    rax,rdx
   140001dbf:	48 c1 e0 03          	shl    rax,0x3
   140001dc3:	48 01 c8             	add    rax,rcx
   140001dc6:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001dca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001dce:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001dd1:	89 c1                	mov    ecx,eax
   140001dd3:	48 8d 05 36 34 00 00 	lea    rax,[rip+0x3436]        # 140005210 <.rdata+0x40>
   140001dda:	49 89 d0             	mov    r8,rdx
   140001ddd:	89 ca                	mov    edx,ecx
   140001ddf:	48 89 c1             	mov    rcx,rax
   140001de2:	e8 c9 fd ff ff       	call   140001bb0 <__report_error>
   140001de7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dea:	83 f8 40             	cmp    eax,0x40
   140001ded:	0f 84 e8 00 00 00    	je     140001edb <mark_section_writable+0x2c6>
   140001df3:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001df6:	83 f8 04             	cmp    eax,0x4
   140001df9:	0f 84 dc 00 00 00    	je     140001edb <mark_section_writable+0x2c6>
   140001dff:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e02:	3d 80 00 00 00       	cmp    eax,0x80
   140001e07:	0f 84 ce 00 00 00    	je     140001edb <mark_section_writable+0x2c6>
   140001e0d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e10:	83 f8 08             	cmp    eax,0x8
   140001e13:	0f 84 c2 00 00 00    	je     140001edb <mark_section_writable+0x2c6>
   140001e19:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e1c:	83 f8 02             	cmp    eax,0x2
   140001e1f:	75 09                	jne    140001e2a <mark_section_writable+0x215>
   140001e21:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001e28:	eb 07                	jmp    140001e31 <mark_section_writable+0x21c>
   140001e2a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e31:	48 8b 0d a8 72 00 00 	mov    rcx,QWORD PTR [rip+0x72a8]        # 1400090e0 <the_secs>
   140001e38:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e3b:	48 63 d0             	movsxd rdx,eax
   140001e3e:	48 89 d0             	mov    rax,rdx
   140001e41:	48 c1 e0 02          	shl    rax,0x2
   140001e45:	48 01 d0             	add    rax,rdx
   140001e48:	48 c1 e0 03          	shl    rax,0x3
   140001e4c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e50:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e54:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e58:	48 8b 0d 81 72 00 00 	mov    rcx,QWORD PTR [rip+0x7281]        # 1400090e0 <the_secs>
   140001e5f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e62:	48 63 d0             	movsxd rdx,eax
   140001e65:	48 89 d0             	mov    rax,rdx
   140001e68:	48 c1 e0 02          	shl    rax,0x2
   140001e6c:	48 01 d0             	add    rax,rdx
   140001e6f:	48 c1 e0 03          	shl    rax,0x3
   140001e73:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e77:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e7b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e7f:	48 8b 0d 5a 72 00 00 	mov    rcx,QWORD PTR [rip+0x725a]        # 1400090e0 <the_secs>
   140001e86:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e89:	48 63 d0             	movsxd rdx,eax
   140001e8c:	48 89 d0             	mov    rax,rdx
   140001e8f:	48 c1 e0 02          	shl    rax,0x2
   140001e93:	48 01 d0             	add    rax,rdx
   140001e96:	48 c1 e0 03          	shl    rax,0x3
   140001e9a:	48 01 c8             	add    rax,rcx
   140001e9d:	49 89 c0             	mov    r8,rax
   140001ea0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001ea4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001ea8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001eab:	4d 89 c1             	mov    r9,r8
   140001eae:	41 89 c8             	mov    r8d,ecx
   140001eb1:	48 89 c1             	mov    rcx,rax
   140001eb4:	48 8b 05 35 83 00 00 	mov    rax,QWORD PTR [rip+0x8335]        # 14000a1f0 <__imp_VirtualProtect>
   140001ebb:	ff d0                	call   rax
   140001ebd:	85 c0                	test   eax,eax
   140001ebf:	75 1a                	jne    140001edb <mark_section_writable+0x2c6>
   140001ec1:	48 8b 05 e0 82 00 00 	mov    rax,QWORD PTR [rip+0x82e0]        # 14000a1a8 <__imp_GetLastError>
   140001ec8:	ff d0                	call   rax
   140001eca:	89 c2                	mov    edx,eax
   140001ecc:	48 8d 05 75 33 00 00 	lea    rax,[rip+0x3375]        # 140005248 <.rdata+0x78>
   140001ed3:	48 89 c1             	mov    rcx,rax
   140001ed6:	e8 d5 fc ff ff       	call   140001bb0 <__report_error>
   140001edb:	8b 05 07 72 00 00    	mov    eax,DWORD PTR [rip+0x7207]        # 1400090e8 <maxSections>
   140001ee1:	83 c0 01             	add    eax,0x1
   140001ee4:	89 05 fe 71 00 00    	mov    DWORD PTR [rip+0x71fe],eax        # 1400090e8 <maxSections>
   140001eea:	eb 01                	jmp    140001eed <mark_section_writable+0x2d8>
   140001eec:	90                   	nop
   140001eed:	48 83 c4 60          	add    rsp,0x60
   140001ef1:	5d                   	pop    rbp
   140001ef2:	c3                   	ret

0000000140001ef3 <restore_modified_sections>:
   140001ef3:	55                   	push   rbp
   140001ef4:	48 89 e5             	mov    rbp,rsp
   140001ef7:	48 83 ec 30          	sub    rsp,0x30
   140001efb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001f02:	e9 ad 00 00 00       	jmp    140001fb4 <restore_modified_sections+0xc1>
   140001f07:	48 8b 0d d2 71 00 00 	mov    rcx,QWORD PTR [rip+0x71d2]        # 1400090e0 <the_secs>
   140001f0e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f11:	48 63 d0             	movsxd rdx,eax
   140001f14:	48 89 d0             	mov    rax,rdx
   140001f17:	48 c1 e0 02          	shl    rax,0x2
   140001f1b:	48 01 d0             	add    rax,rdx
   140001f1e:	48 c1 e0 03          	shl    rax,0x3
   140001f22:	48 01 c8             	add    rax,rcx
   140001f25:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f27:	85 c0                	test   eax,eax
   140001f29:	0f 84 80 00 00 00    	je     140001faf <restore_modified_sections+0xbc>
   140001f2f:	48 8b 0d aa 71 00 00 	mov    rcx,QWORD PTR [rip+0x71aa]        # 1400090e0 <the_secs>
   140001f36:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f39:	48 63 d0             	movsxd rdx,eax
   140001f3c:	48 89 d0             	mov    rax,rdx
   140001f3f:	48 c1 e0 02          	shl    rax,0x2
   140001f43:	48 01 d0             	add    rax,rdx
   140001f46:	48 c1 e0 03          	shl    rax,0x3
   140001f4a:	48 01 c8             	add    rax,rcx
   140001f4d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f50:	48 8b 0d 89 71 00 00 	mov    rcx,QWORD PTR [rip+0x7189]        # 1400090e0 <the_secs>
   140001f57:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f5a:	48 63 d0             	movsxd rdx,eax
   140001f5d:	48 89 d0             	mov    rax,rdx
   140001f60:	48 c1 e0 02          	shl    rax,0x2
   140001f64:	48 01 d0             	add    rax,rdx
   140001f67:	48 c1 e0 03          	shl    rax,0x3
   140001f6b:	48 01 c8             	add    rax,rcx
   140001f6e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f72:	4c 8b 05 67 71 00 00 	mov    r8,QWORD PTR [rip+0x7167]        # 1400090e0 <the_secs>
   140001f79:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f7c:	48 63 d0             	movsxd rdx,eax
   140001f7f:	48 89 d0             	mov    rax,rdx
   140001f82:	48 c1 e0 02          	shl    rax,0x2
   140001f86:	48 01 d0             	add    rax,rdx
   140001f89:	48 c1 e0 03          	shl    rax,0x3
   140001f8d:	4c 01 c0             	add    rax,r8
   140001f90:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f94:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f98:	49 89 d1             	mov    r9,rdx
   140001f9b:	45 89 d0             	mov    r8d,r10d
   140001f9e:	48 89 ca             	mov    rdx,rcx
   140001fa1:	48 89 c1             	mov    rcx,rax
   140001fa4:	48 8b 05 45 82 00 00 	mov    rax,QWORD PTR [rip+0x8245]        # 14000a1f0 <__imp_VirtualProtect>
   140001fab:	ff d0                	call   rax
   140001fad:	eb 01                	jmp    140001fb0 <restore_modified_sections+0xbd>
   140001faf:	90                   	nop
   140001fb0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001fb4:	8b 05 2e 71 00 00    	mov    eax,DWORD PTR [rip+0x712e]        # 1400090e8 <maxSections>
   140001fba:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001fbd:	0f 8c 44 ff ff ff    	jl     140001f07 <restore_modified_sections+0x14>
   140001fc3:	90                   	nop
   140001fc4:	90                   	nop
   140001fc5:	48 83 c4 30          	add    rsp,0x30
   140001fc9:	5d                   	pop    rbp
   140001fca:	c3                   	ret

0000000140001fcb <__write_memory>:
   140001fcb:	55                   	push   rbp
   140001fcc:	48 89 e5             	mov    rbp,rsp
   140001fcf:	48 83 ec 20          	sub    rsp,0x20
   140001fd3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fd7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001fdb:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001fdf:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001fe4:	74 25                	je     14000200b <__write_memory+0x40>
   140001fe6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fea:	48 89 c1             	mov    rcx,rax
   140001fed:	e8 23 fc ff ff       	call   140001c15 <mark_section_writable>
   140001ff2:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001ff6:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001ffa:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001ffe:	49 89 c8             	mov    r8,rcx
   140002001:	48 89 c1             	mov    rcx,rax
   140002004:	e8 37 13 00 00       	call   140003340 <memcpy>
   140002009:	eb 01                	jmp    14000200c <__write_memory+0x41>
   14000200b:	90                   	nop
   14000200c:	48 83 c4 20          	add    rsp,0x20
   140002010:	5d                   	pop    rbp
   140002011:	c3                   	ret

0000000140002012 <do_pseudo_reloc>:
   140002012:	55                   	push   rbp
   140002013:	48 89 e5             	mov    rbp,rsp
   140002016:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   14000201a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000201e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002022:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002026:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000202a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000202e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002032:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002036:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000203a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000203f:	0f 8e 44 03 00 00    	jle    140002389 <do_pseudo_reloc+0x377>
   140002045:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000204a:	7e 25                	jle    140002071 <do_pseudo_reloc+0x5f>
   14000204c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002050:	8b 00                	mov    eax,DWORD PTR [rax]
   140002052:	85 c0                	test   eax,eax
   140002054:	75 1b                	jne    140002071 <do_pseudo_reloc+0x5f>
   140002056:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000205a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000205d:	85 c0                	test   eax,eax
   14000205f:	75 10                	jne    140002071 <do_pseudo_reloc+0x5f>
   140002061:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002065:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002068:	85 c0                	test   eax,eax
   14000206a:	75 05                	jne    140002071 <do_pseudo_reloc+0x5f>
   14000206c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002071:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002075:	8b 00                	mov    eax,DWORD PTR [rax]
   140002077:	85 c0                	test   eax,eax
   140002079:	75 0b                	jne    140002086 <do_pseudo_reloc+0x74>
   14000207b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000207f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002082:	85 c0                	test   eax,eax
   140002084:	74 59                	je     1400020df <do_pseudo_reloc+0xcd>
   140002086:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000208a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000208e:	eb 40                	jmp    1400020d0 <do_pseudo_reloc+0xbe>
   140002090:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002094:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002097:	89 c2                	mov    edx,eax
   140002099:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000209d:	48 01 d0             	add    rax,rdx
   1400020a0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020a4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020a8:	8b 10                	mov    edx,DWORD PTR [rax]
   1400020aa:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020ae:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020b0:	01 d0                	add    eax,edx
   1400020b2:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   1400020b5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020b9:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   1400020bd:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400020c3:	48 89 c1             	mov    rcx,rax
   1400020c6:	e8 00 ff ff ff       	call   140001fcb <__write_memory>
   1400020cb:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   1400020d0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020d4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400020d8:	72 b6                	jb     140002090 <do_pseudo_reloc+0x7e>
   1400020da:	e9 ab 02 00 00       	jmp    14000238a <do_pseudo_reloc+0x378>
   1400020df:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020e3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020e6:	83 f8 01             	cmp    eax,0x1
   1400020e9:	74 18                	je     140002103 <do_pseudo_reloc+0xf1>
   1400020eb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020ef:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020f2:	89 c2                	mov    edx,eax
   1400020f4:	48 8d 05 75 31 00 00 	lea    rax,[rip+0x3175]        # 140005270 <.rdata+0xa0>
   1400020fb:	48 89 c1             	mov    rcx,rax
   1400020fe:	e8 ad fa ff ff       	call   140001bb0 <__report_error>
   140002103:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002107:	48 83 c0 0c          	add    rax,0xc
   14000210b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000210f:	e9 65 02 00 00       	jmp    140002379 <do_pseudo_reloc+0x367>
   140002114:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002118:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000211b:	89 c2                	mov    edx,eax
   14000211d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002121:	48 01 d0             	add    rax,rdx
   140002124:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002128:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000212c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000212e:	89 c2                	mov    edx,eax
   140002130:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002134:	48 01 d0             	add    rax,rdx
   140002137:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000213b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000213f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002142:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002146:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000214a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000214d:	0f b6 c0             	movzx  eax,al
   140002150:	83 f8 40             	cmp    eax,0x40
   140002153:	0f 84 b6 00 00 00    	je     14000220f <do_pseudo_reloc+0x1fd>
   140002159:	83 f8 40             	cmp    eax,0x40
   14000215c:	0f 87 ba 00 00 00    	ja     14000221c <do_pseudo_reloc+0x20a>
   140002162:	83 f8 20             	cmp    eax,0x20
   140002165:	74 77                	je     1400021de <do_pseudo_reloc+0x1cc>
   140002167:	83 f8 20             	cmp    eax,0x20
   14000216a:	0f 87 ac 00 00 00    	ja     14000221c <do_pseudo_reloc+0x20a>
   140002170:	83 f8 08             	cmp    eax,0x8
   140002173:	74 0a                	je     14000217f <do_pseudo_reloc+0x16d>
   140002175:	83 f8 10             	cmp    eax,0x10
   140002178:	74 38                	je     1400021b2 <do_pseudo_reloc+0x1a0>
   14000217a:	e9 9d 00 00 00       	jmp    14000221c <do_pseudo_reloc+0x20a>
   14000217f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002183:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002186:	0f b6 c0             	movzx  eax,al
   140002189:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000218d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002191:	25 80 00 00 00       	and    eax,0x80
   140002196:	48 85 c0             	test   rax,rax
   140002199:	0f 84 9d 00 00 00    	je     14000223c <do_pseudo_reloc+0x22a>
   14000219f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021a3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400021a9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ad:	e9 8a 00 00 00       	jmp    14000223c <do_pseudo_reloc+0x22a>
   1400021b2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021b6:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400021b9:	0f b7 c0             	movzx  eax,ax
   1400021bc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021c0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021c4:	25 00 80 00 00       	and    eax,0x8000
   1400021c9:	48 85 c0             	test   rax,rax
   1400021cc:	74 71                	je     14000223f <do_pseudo_reloc+0x22d>
   1400021ce:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021d2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400021d8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021dc:	eb 61                	jmp    14000223f <do_pseudo_reloc+0x22d>
   1400021de:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021e2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021e4:	89 c0                	mov    eax,eax
   1400021e6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ea:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021ee:	25 00 00 00 80       	and    eax,0x80000000
   1400021f3:	48 85 c0             	test   rax,rax
   1400021f6:	74 4a                	je     140002242 <do_pseudo_reloc+0x230>
   1400021f8:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021fc:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002203:	ff ff ff 
   140002206:	48 09 d0             	or     rax,rdx
   140002209:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000220d:	eb 33                	jmp    140002242 <do_pseudo_reloc+0x230>
   14000220f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002213:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002216:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000221a:	eb 27                	jmp    140002243 <do_pseudo_reloc+0x231>
   14000221c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002223:	00 
   140002224:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002228:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000222b:	0f b6 c0             	movzx  eax,al
   14000222e:	48 8d 0d 73 30 00 00 	lea    rcx,[rip+0x3073]        # 1400052a8 <.rdata+0xd8>
   140002235:	89 c2                	mov    edx,eax
   140002237:	e8 74 f9 ff ff       	call   140001bb0 <__report_error>
   14000223c:	90                   	nop
   14000223d:	eb 04                	jmp    140002243 <do_pseudo_reloc+0x231>
   14000223f:	90                   	nop
   140002240:	eb 01                	jmp    140002243 <do_pseudo_reloc+0x231>
   140002242:	90                   	nop
   140002243:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002247:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000224b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000224d:	89 c2                	mov    edx,eax
   14000224f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002253:	48 01 c2             	add    rdx,rax
   140002256:	48 89 c8             	mov    rax,rcx
   140002259:	48 29 d0             	sub    rax,rdx
   14000225c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002260:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002264:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002268:	48 01 d0             	add    rax,rdx
   14000226b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000226f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002273:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002276:	25 ff 00 00 00       	and    eax,0xff
   14000227b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000227e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002282:	77 67                	ja     1400022eb <do_pseudo_reloc+0x2d9>
   140002284:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002287:	ba 01 00 00 00       	mov    edx,0x1
   14000228c:	89 c1                	mov    ecx,eax
   14000228e:	48 d3 e2             	shl    rdx,cl
   140002291:	48 89 d0             	mov    rax,rdx
   140002294:	48 83 e8 01          	sub    rax,0x1
   140002298:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000229c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000229f:	83 e8 01             	sub    eax,0x1
   1400022a2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400022a9:	89 c1                	mov    ecx,eax
   1400022ab:	48 d3 e2             	shl    rdx,cl
   1400022ae:	48 89 d0             	mov    rax,rdx
   1400022b1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400022b5:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022b9:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   1400022bd:	7c 0a                	jl     1400022c9 <do_pseudo_reloc+0x2b7>
   1400022bf:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022c3:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400022c7:	7e 22                	jle    1400022eb <do_pseudo_reloc+0x2d9>
   1400022c9:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400022cd:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400022d1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400022d5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022d8:	48 8d 0d f9 2f 00 00 	lea    rcx,[rip+0x2ff9]        # 1400052d8 <.rdata+0x108>
   1400022df:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400022e4:	89 c2                	mov    edx,eax
   1400022e6:	e8 c5 f8 ff ff       	call   140001bb0 <__report_error>
   1400022eb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022ef:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022f2:	0f b6 c0             	movzx  eax,al
   1400022f5:	83 f8 40             	cmp    eax,0x40
   1400022f8:	74 63                	je     14000235d <do_pseudo_reloc+0x34b>
   1400022fa:	83 f8 40             	cmp    eax,0x40
   1400022fd:	77 75                	ja     140002374 <do_pseudo_reloc+0x362>
   1400022ff:	83 f8 20             	cmp    eax,0x20
   140002302:	74 41                	je     140002345 <do_pseudo_reloc+0x333>
   140002304:	83 f8 20             	cmp    eax,0x20
   140002307:	77 6b                	ja     140002374 <do_pseudo_reloc+0x362>
   140002309:	83 f8 08             	cmp    eax,0x8
   14000230c:	74 07                	je     140002315 <do_pseudo_reloc+0x303>
   14000230e:	83 f8 10             	cmp    eax,0x10
   140002311:	74 1a                	je     14000232d <do_pseudo_reloc+0x31b>
   140002313:	eb 5f                	jmp    140002374 <do_pseudo_reloc+0x362>
   140002315:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002319:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000231d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002323:	48 89 c1             	mov    rcx,rax
   140002326:	e8 a0 fc ff ff       	call   140001fcb <__write_memory>
   14000232b:	eb 47                	jmp    140002374 <do_pseudo_reloc+0x362>
   14000232d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002331:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002335:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000233b:	48 89 c1             	mov    rcx,rax
   14000233e:	e8 88 fc ff ff       	call   140001fcb <__write_memory>
   140002343:	eb 2f                	jmp    140002374 <do_pseudo_reloc+0x362>
   140002345:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002349:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000234d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002353:	48 89 c1             	mov    rcx,rax
   140002356:	e8 70 fc ff ff       	call   140001fcb <__write_memory>
   14000235b:	eb 17                	jmp    140002374 <do_pseudo_reloc+0x362>
   14000235d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002361:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002365:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000236b:	48 89 c1             	mov    rcx,rax
   14000236e:	e8 58 fc ff ff       	call   140001fcb <__write_memory>
   140002373:	90                   	nop
   140002374:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002379:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000237d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002381:	0f 82 8d fd ff ff    	jb     140002114 <do_pseudo_reloc+0x102>
   140002387:	eb 01                	jmp    14000238a <do_pseudo_reloc+0x378>
   140002389:	90                   	nop
   14000238a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000238e:	5d                   	pop    rbp
   14000238f:	c3                   	ret

0000000140002390 <_pei386_runtime_relocator>:
   140002390:	55                   	push   rbp
   140002391:	48 89 e5             	mov    rbp,rsp
   140002394:	48 83 ec 30          	sub    rsp,0x30
   140002398:	8b 05 4e 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d4e]        # 1400090ec <was_init.0>
   14000239e:	85 c0                	test   eax,eax
   1400023a0:	0f 85 88 00 00 00    	jne    14000242e <_pei386_runtime_relocator+0x9e>
   1400023a6:	8b 05 40 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d40]        # 1400090ec <was_init.0>
   1400023ac:	83 c0 01             	add    eax,0x1
   1400023af:	89 05 37 6d 00 00    	mov    DWORD PTR [rip+0x6d37],eax        # 1400090ec <was_init.0>
   1400023b5:	e8 21 0b 00 00       	call   140002edb <__mingw_GetSectionCount>
   1400023ba:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400023bd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400023c0:	48 63 d0             	movsxd rdx,eax
   1400023c3:	48 89 d0             	mov    rax,rdx
   1400023c6:	48 c1 e0 02          	shl    rax,0x2
   1400023ca:	48 01 d0             	add    rax,rdx
   1400023cd:	48 c1 e0 03          	shl    rax,0x3
   1400023d1:	48 83 c0 0f          	add    rax,0xf
   1400023d5:	48 c1 e8 04          	shr    rax,0x4
   1400023d9:	48 c1 e0 04          	shl    rax,0x4
   1400023dd:	e8 7e 0d 00 00       	call   140003160 <___chkstk_ms>
   1400023e2:	48 29 c4             	sub    rsp,rax
   1400023e5:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400023ea:	48 83 c0 0f          	add    rax,0xf
   1400023ee:	48 c1 e8 04          	shr    rax,0x4
   1400023f2:	48 c1 e0 04          	shl    rax,0x4
   1400023f6:	48 89 05 e3 6c 00 00 	mov    QWORD PTR [rip+0x6ce3],rax        # 1400090e0 <the_secs>
   1400023fd:	c7 05 e1 6c 00 00 00 	mov    DWORD PTR [rip+0x6ce1],0x0        # 1400090e8 <maxSections>
   140002404:	00 00 00 
   140002407:	48 8b 0d 52 2f 00 00 	mov    rcx,QWORD PTR [rip+0x2f52]        # 140005360 <.refptr.__ImageBase>
   14000240e:	48 8b 15 5b 2f 00 00 	mov    rdx,QWORD PTR [rip+0x2f5b]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002415:	48 8b 05 64 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f64]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000241c:	49 89 c8             	mov    r8,rcx
   14000241f:	48 89 c1             	mov    rcx,rax
   140002422:	e8 eb fb ff ff       	call   140002012 <do_pseudo_reloc>
   140002427:	e8 c7 fa ff ff       	call   140001ef3 <restore_modified_sections>
   14000242c:	eb 01                	jmp    14000242f <_pei386_runtime_relocator+0x9f>
   14000242e:	90                   	nop
   14000242f:	48 89 ec             	mov    rsp,rbp
   140002432:	5d                   	pop    rbp
   140002433:	c3                   	ret
   140002434:	90                   	nop
   140002435:	90                   	nop
   140002436:	90                   	nop
   140002437:	90                   	nop
   140002438:	90                   	nop
   140002439:	90                   	nop
   14000243a:	90                   	nop
   14000243b:	90                   	nop
   14000243c:	90                   	nop
   14000243d:	90                   	nop
   14000243e:	90                   	nop
   14000243f:	90                   	nop

0000000140002440 <__mingw_raise_matherr>:
   140002440:	55                   	push   rbp
   140002441:	48 89 e5             	mov    rbp,rsp
   140002444:	48 83 ec 50          	sub    rsp,0x50
   140002448:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000244b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000244f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002454:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002459:	48 8b 05 90 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c90]        # 1400090f0 <stUserMathErr>
   140002460:	48 85 c0             	test   rax,rax
   140002463:	74 3e                	je     1400024a3 <__mingw_raise_matherr+0x63>
   140002465:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002468:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000246b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000246f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002473:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002478:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000247d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002482:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002487:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000248c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002491:	48 8b 15 58 6c 00 00 	mov    rdx,QWORD PTR [rip+0x6c58]        # 1400090f0 <stUserMathErr>
   140002498:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000249c:	48 89 c1             	mov    rcx,rax
   14000249f:	ff d2                	call   rdx
   1400024a1:	eb 01                	jmp    1400024a4 <__mingw_raise_matherr+0x64>
   1400024a3:	90                   	nop
   1400024a4:	48 83 c4 50          	add    rsp,0x50
   1400024a8:	5d                   	pop    rbp
   1400024a9:	c3                   	ret

00000001400024aa <__mingw_setusermatherr>:
   1400024aa:	55                   	push   rbp
   1400024ab:	48 89 e5             	mov    rbp,rsp
   1400024ae:	48 83 ec 20          	sub    rsp,0x20
   1400024b2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024b6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024ba:	48 89 05 2f 6c 00 00 	mov    QWORD PTR [rip+0x6c2f],rax        # 1400090f0 <stUserMathErr>
   1400024c1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024c5:	48 89 c1             	mov    rcx,rax
   1400024c8:	e8 13 0e 00 00       	call   1400032e0 <__setusermatherr>
   1400024cd:	90                   	nop
   1400024ce:	48 83 c4 20          	add    rsp,0x20
   1400024d2:	5d                   	pop    rbp
   1400024d3:	c3                   	ret
   1400024d4:	90                   	nop
   1400024d5:	90                   	nop
   1400024d6:	90                   	nop
   1400024d7:	90                   	nop
   1400024d8:	90                   	nop
   1400024d9:	90                   	nop
   1400024da:	90                   	nop
   1400024db:	90                   	nop
   1400024dc:	90                   	nop
   1400024dd:	90                   	nop
   1400024de:	90                   	nop
   1400024df:	90                   	nop

00000001400024e0 <__mingw_SEH_error_handler>:
   1400024e0:	55                   	push   rbp
   1400024e1:	48 89 e5             	mov    rbp,rsp
   1400024e4:	48 83 ec 30          	sub    rsp,0x30
   1400024e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024ec:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400024f0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400024f4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400024f8:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400024ff:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002506:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000250a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000250d:	83 e0 02             	and    eax,0x2
   140002510:	85 c0                	test   eax,eax
   140002512:	74 0a                	je     14000251e <__mingw_SEH_error_handler+0x3e>
   140002514:	b8 01 00 00 00       	mov    eax,0x1
   140002519:	e9 16 02 00 00       	jmp    140002734 <__mingw_SEH_error_handler+0x254>
   14000251e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002522:	8b 00                	mov    eax,DWORD PTR [rax]
   140002524:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002529:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000252e:	75 18                	jne    140002548 <__mingw_SEH_error_handler+0x68>
   140002530:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002534:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002537:	83 e0 01             	and    eax,0x1
   14000253a:	85 c0                	test   eax,eax
   14000253c:	75 0a                	jne    140002548 <__mingw_SEH_error_handler+0x68>
   14000253e:	b8 00 00 00 00       	mov    eax,0x0
   140002543:	e9 ec 01 00 00       	jmp    140002734 <__mingw_SEH_error_handler+0x254>
   140002548:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000254c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000254e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002553:	0f 84 12 01 00 00    	je     14000266b <__mingw_SEH_error_handler+0x18b>
   140002559:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000255e:	0f 87 c3 01 00 00    	ja     140002727 <__mingw_SEH_error_handler+0x247>
   140002564:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002569:	0f 87 b8 01 00 00    	ja     140002727 <__mingw_SEH_error_handler+0x247>
   14000256f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002574:	0f 83 4c 01 00 00    	jae    1400026c6 <__mingw_SEH_error_handler+0x1e6>
   14000257a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000257f:	0f 84 3a 01 00 00    	je     1400026bf <__mingw_SEH_error_handler+0x1df>
   140002585:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000258a:	0f 87 97 01 00 00    	ja     140002727 <__mingw_SEH_error_handler+0x247>
   140002590:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002595:	0f 84 83 01 00 00    	je     14000271e <__mingw_SEH_error_handler+0x23e>
   14000259b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025a0:	0f 87 81 01 00 00    	ja     140002727 <__mingw_SEH_error_handler+0x247>
   1400025a6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400025ab:	0f 87 76 01 00 00    	ja     140002727 <__mingw_SEH_error_handler+0x247>
   1400025b1:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400025b6:	0f 83 03 01 00 00    	jae    1400026bf <__mingw_SEH_error_handler+0x1df>
   1400025bc:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025c1:	0f 84 57 01 00 00    	je     14000271e <__mingw_SEH_error_handler+0x23e>
   1400025c7:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025cc:	0f 87 55 01 00 00    	ja     140002727 <__mingw_SEH_error_handler+0x247>
   1400025d2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025d7:	0f 84 8e 00 00 00    	je     14000266b <__mingw_SEH_error_handler+0x18b>
   1400025dd:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025e2:	0f 87 3f 01 00 00    	ja     140002727 <__mingw_SEH_error_handler+0x247>
   1400025e8:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025ed:	0f 84 2b 01 00 00    	je     14000271e <__mingw_SEH_error_handler+0x23e>
   1400025f3:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025f8:	0f 87 29 01 00 00    	ja     140002727 <__mingw_SEH_error_handler+0x247>
   1400025fe:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002603:	0f 84 15 01 00 00    	je     14000271e <__mingw_SEH_error_handler+0x23e>
   140002609:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000260e:	0f 85 13 01 00 00    	jne    140002727 <__mingw_SEH_error_handler+0x247>
   140002614:	ba 00 00 00 00       	mov    edx,0x0
   140002619:	b9 0b 00 00 00       	mov    ecx,0xb
   14000261e:	e8 35 0d 00 00       	call   140003358 <signal>
   140002623:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002627:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000262c:	75 1b                	jne    140002649 <__mingw_SEH_error_handler+0x169>
   14000262e:	ba 01 00 00 00       	mov    edx,0x1
   140002633:	b9 0b 00 00 00       	mov    ecx,0xb
   140002638:	e8 1b 0d 00 00       	call   140003358 <signal>
   14000263d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002644:	e9 e1 00 00 00       	jmp    14000272a <__mingw_SEH_error_handler+0x24a>
   140002649:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000264e:	0f 84 d6 00 00 00    	je     14000272a <__mingw_SEH_error_handler+0x24a>
   140002654:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002658:	b9 0b 00 00 00       	mov    ecx,0xb
   14000265d:	ff d0                	call   rax
   14000265f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002666:	e9 bf 00 00 00       	jmp    14000272a <__mingw_SEH_error_handler+0x24a>
   14000266b:	ba 00 00 00 00       	mov    edx,0x0
   140002670:	b9 04 00 00 00       	mov    ecx,0x4
   140002675:	e8 de 0c 00 00       	call   140003358 <signal>
   14000267a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000267e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002683:	75 1b                	jne    1400026a0 <__mingw_SEH_error_handler+0x1c0>
   140002685:	ba 01 00 00 00       	mov    edx,0x1
   14000268a:	b9 04 00 00 00       	mov    ecx,0x4
   14000268f:	e8 c4 0c 00 00       	call   140003358 <signal>
   140002694:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000269b:	e9 8d 00 00 00       	jmp    14000272d <__mingw_SEH_error_handler+0x24d>
   1400026a0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026a5:	0f 84 82 00 00 00    	je     14000272d <__mingw_SEH_error_handler+0x24d>
   1400026ab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026af:	b9 04 00 00 00       	mov    ecx,0x4
   1400026b4:	ff d0                	call   rax
   1400026b6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026bd:	eb 6e                	jmp    14000272d <__mingw_SEH_error_handler+0x24d>
   1400026bf:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400026c6:	ba 00 00 00 00       	mov    edx,0x0
   1400026cb:	b9 08 00 00 00       	mov    ecx,0x8
   1400026d0:	e8 83 0c 00 00       	call   140003358 <signal>
   1400026d5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026d9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026de:	75 23                	jne    140002703 <__mingw_SEH_error_handler+0x223>
   1400026e0:	ba 01 00 00 00       	mov    edx,0x1
   1400026e5:	b9 08 00 00 00       	mov    ecx,0x8
   1400026ea:	e8 69 0c 00 00       	call   140003358 <signal>
   1400026ef:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400026f3:	74 05                	je     1400026fa <__mingw_SEH_error_handler+0x21a>
   1400026f5:	e8 a6 05 00 00       	call   140002ca0 <_fpreset>
   1400026fa:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002701:	eb 2d                	jmp    140002730 <__mingw_SEH_error_handler+0x250>
   140002703:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002708:	74 26                	je     140002730 <__mingw_SEH_error_handler+0x250>
   14000270a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000270e:	b9 08 00 00 00       	mov    ecx,0x8
   140002713:	ff d0                	call   rax
   140002715:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000271c:	eb 12                	jmp    140002730 <__mingw_SEH_error_handler+0x250>
   14000271e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002725:	eb 0a                	jmp    140002731 <__mingw_SEH_error_handler+0x251>
   140002727:	90                   	nop
   140002728:	eb 07                	jmp    140002731 <__mingw_SEH_error_handler+0x251>
   14000272a:	90                   	nop
   14000272b:	eb 04                	jmp    140002731 <__mingw_SEH_error_handler+0x251>
   14000272d:	90                   	nop
   14000272e:	eb 01                	jmp    140002731 <__mingw_SEH_error_handler+0x251>
   140002730:	90                   	nop
   140002731:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002734:	48 83 c4 30          	add    rsp,0x30
   140002738:	5d                   	pop    rbp
   140002739:	c3                   	ret

000000014000273a <_gnu_exception_handler>:
   14000273a:	55                   	push   rbp
   14000273b:	48 89 e5             	mov    rbp,rsp
   14000273e:	48 83 ec 30          	sub    rsp,0x30
   140002742:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002746:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000274d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002754:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002758:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000275b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000275d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002762:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002767:	75 1b                	jne    140002784 <_gnu_exception_handler+0x4a>
   140002769:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000276d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002770:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002773:	83 e0 01             	and    eax,0x1
   140002776:	85 c0                	test   eax,eax
   140002778:	75 0a                	jne    140002784 <_gnu_exception_handler+0x4a>
   14000277a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000277f:	e9 14 02 00 00       	jmp    140002998 <_gnu_exception_handler+0x25e>
   140002784:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002788:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000278b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000278d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002792:	0f 84 12 01 00 00    	je     1400028aa <_gnu_exception_handler+0x170>
   140002798:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000279d:	0f 87 c3 01 00 00    	ja     140002966 <_gnu_exception_handler+0x22c>
   1400027a3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400027a8:	0f 87 b8 01 00 00    	ja     140002966 <_gnu_exception_handler+0x22c>
   1400027ae:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400027b3:	0f 83 4c 01 00 00    	jae    140002905 <_gnu_exception_handler+0x1cb>
   1400027b9:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027be:	0f 84 3a 01 00 00    	je     1400028fe <_gnu_exception_handler+0x1c4>
   1400027c4:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027c9:	0f 87 97 01 00 00    	ja     140002966 <_gnu_exception_handler+0x22c>
   1400027cf:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027d4:	0f 84 83 01 00 00    	je     14000295d <_gnu_exception_handler+0x223>
   1400027da:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027df:	0f 87 81 01 00 00    	ja     140002966 <_gnu_exception_handler+0x22c>
   1400027e5:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400027ea:	0f 87 76 01 00 00    	ja     140002966 <_gnu_exception_handler+0x22c>
   1400027f0:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400027f5:	0f 83 03 01 00 00    	jae    1400028fe <_gnu_exception_handler+0x1c4>
   1400027fb:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002800:	0f 84 57 01 00 00    	je     14000295d <_gnu_exception_handler+0x223>
   140002806:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000280b:	0f 87 55 01 00 00    	ja     140002966 <_gnu_exception_handler+0x22c>
   140002811:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002816:	0f 84 8e 00 00 00    	je     1400028aa <_gnu_exception_handler+0x170>
   14000281c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002821:	0f 87 3f 01 00 00    	ja     140002966 <_gnu_exception_handler+0x22c>
   140002827:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000282c:	0f 84 2b 01 00 00    	je     14000295d <_gnu_exception_handler+0x223>
   140002832:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002837:	0f 87 29 01 00 00    	ja     140002966 <_gnu_exception_handler+0x22c>
   14000283d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002842:	0f 84 15 01 00 00    	je     14000295d <_gnu_exception_handler+0x223>
   140002848:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000284d:	0f 85 13 01 00 00    	jne    140002966 <_gnu_exception_handler+0x22c>
   140002853:	ba 00 00 00 00       	mov    edx,0x0
   140002858:	b9 0b 00 00 00       	mov    ecx,0xb
   14000285d:	e8 f6 0a 00 00       	call   140003358 <signal>
   140002862:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002866:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000286b:	75 1b                	jne    140002888 <_gnu_exception_handler+0x14e>
   14000286d:	ba 01 00 00 00       	mov    edx,0x1
   140002872:	b9 0b 00 00 00       	mov    ecx,0xb
   140002877:	e8 dc 0a 00 00       	call   140003358 <signal>
   14000287c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002883:	e9 e1 00 00 00       	jmp    140002969 <_gnu_exception_handler+0x22f>
   140002888:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000288d:	0f 84 d6 00 00 00    	je     140002969 <_gnu_exception_handler+0x22f>
   140002893:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002897:	b9 0b 00 00 00       	mov    ecx,0xb
   14000289c:	ff d0                	call   rax
   14000289e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028a5:	e9 bf 00 00 00       	jmp    140002969 <_gnu_exception_handler+0x22f>
   1400028aa:	ba 00 00 00 00       	mov    edx,0x0
   1400028af:	b9 04 00 00 00       	mov    ecx,0x4
   1400028b4:	e8 9f 0a 00 00       	call   140003358 <signal>
   1400028b9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028bd:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028c2:	75 1b                	jne    1400028df <_gnu_exception_handler+0x1a5>
   1400028c4:	ba 01 00 00 00       	mov    edx,0x1
   1400028c9:	b9 04 00 00 00       	mov    ecx,0x4
   1400028ce:	e8 85 0a 00 00       	call   140003358 <signal>
   1400028d3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028da:	e9 8d 00 00 00       	jmp    14000296c <_gnu_exception_handler+0x232>
   1400028df:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028e4:	0f 84 82 00 00 00    	je     14000296c <_gnu_exception_handler+0x232>
   1400028ea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028ee:	b9 04 00 00 00       	mov    ecx,0x4
   1400028f3:	ff d0                	call   rax
   1400028f5:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028fc:	eb 6e                	jmp    14000296c <_gnu_exception_handler+0x232>
   1400028fe:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002905:	ba 00 00 00 00       	mov    edx,0x0
   14000290a:	b9 08 00 00 00       	mov    ecx,0x8
   14000290f:	e8 44 0a 00 00       	call   140003358 <signal>
   140002914:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002918:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000291d:	75 23                	jne    140002942 <_gnu_exception_handler+0x208>
   14000291f:	ba 01 00 00 00       	mov    edx,0x1
   140002924:	b9 08 00 00 00       	mov    ecx,0x8
   140002929:	e8 2a 0a 00 00       	call   140003358 <signal>
   14000292e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002932:	74 05                	je     140002939 <_gnu_exception_handler+0x1ff>
   140002934:	e8 67 03 00 00       	call   140002ca0 <_fpreset>
   140002939:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002940:	eb 2d                	jmp    14000296f <_gnu_exception_handler+0x235>
   140002942:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002947:	74 26                	je     14000296f <_gnu_exception_handler+0x235>
   140002949:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000294d:	b9 08 00 00 00       	mov    ecx,0x8
   140002952:	ff d0                	call   rax
   140002954:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000295b:	eb 12                	jmp    14000296f <_gnu_exception_handler+0x235>
   14000295d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002964:	eb 0a                	jmp    140002970 <_gnu_exception_handler+0x236>
   140002966:	90                   	nop
   140002967:	eb 07                	jmp    140002970 <_gnu_exception_handler+0x236>
   140002969:	90                   	nop
   14000296a:	eb 04                	jmp    140002970 <_gnu_exception_handler+0x236>
   14000296c:	90                   	nop
   14000296d:	eb 01                	jmp    140002970 <_gnu_exception_handler+0x236>
   14000296f:	90                   	nop
   140002970:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002974:	75 1f                	jne    140002995 <_gnu_exception_handler+0x25b>
   140002976:	48 8b 05 93 67 00 00 	mov    rax,QWORD PTR [rip+0x6793]        # 140009110 <__mingw_oldexcpt_handler>
   14000297d:	48 85 c0             	test   rax,rax
   140002980:	74 13                	je     140002995 <_gnu_exception_handler+0x25b>
   140002982:	48 8b 15 87 67 00 00 	mov    rdx,QWORD PTR [rip+0x6787]        # 140009110 <__mingw_oldexcpt_handler>
   140002989:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000298d:	48 89 c1             	mov    rcx,rax
   140002990:	ff d2                	call   rdx
   140002992:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002995:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002998:	48 83 c4 30          	add    rsp,0x30
   14000299c:	5d                   	pop    rbp
   14000299d:	c3                   	ret
   14000299e:	90                   	nop
   14000299f:	90                   	nop

00000001400029a0 <___w64_mingwthr_add_key_dtor>:
   1400029a0:	55                   	push   rbp
   1400029a1:	48 89 e5             	mov    rbp,rsp
   1400029a4:	48 83 ec 30          	sub    rsp,0x30
   1400029a8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029ab:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400029af:	8b 05 93 67 00 00    	mov    eax,DWORD PTR [rip+0x6793]        # 140009148 <__mingwthr_cs_init>
   1400029b5:	85 c0                	test   eax,eax
   1400029b7:	75 07                	jne    1400029c0 <___w64_mingwthr_add_key_dtor+0x20>
   1400029b9:	b8 00 00 00 00       	mov    eax,0x0
   1400029be:	eb 7b                	jmp    140002a3b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029c0:	ba 18 00 00 00       	mov    edx,0x18
   1400029c5:	b9 01 00 00 00       	mov    ecx,0x1
   1400029ca:	e8 41 09 00 00       	call   140003310 <calloc>
   1400029cf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400029d3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029d8:	75 07                	jne    1400029e1 <___w64_mingwthr_add_key_dtor+0x41>
   1400029da:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400029df:	eb 5a                	jmp    140002a3b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029e1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029e5:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400029e8:	89 10                	mov    DWORD PTR [rax],edx
   1400029ea:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029ee:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400029f2:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   1400029f6:	48 8d 05 23 67 00 00 	lea    rax,[rip+0x6723]        # 140009120 <__mingwthr_cs>
   1400029fd:	48 89 c1             	mov    rcx,rax
   140002a00:	48 8b 05 91 77 00 00 	mov    rax,QWORD PTR [rip+0x7791]        # 14000a198 <__imp_EnterCriticalSection>
   140002a07:	ff d0                	call   rax
   140002a09:	48 8b 15 40 67 00 00 	mov    rdx,QWORD PTR [rip+0x6740]        # 140009150 <key_dtor_list>
   140002a10:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a14:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a18:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a1c:	48 89 05 2d 67 00 00 	mov    QWORD PTR [rip+0x672d],rax        # 140009150 <key_dtor_list>
   140002a23:	48 8d 05 f6 66 00 00 	lea    rax,[rip+0x66f6]        # 140009120 <__mingwthr_cs>
   140002a2a:	48 89 c1             	mov    rcx,rax
   140002a2d:	48 8b 05 94 77 00 00 	mov    rax,QWORD PTR [rip+0x7794]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002a34:	ff d0                	call   rax
   140002a36:	b8 00 00 00 00       	mov    eax,0x0
   140002a3b:	48 83 c4 30          	add    rsp,0x30
   140002a3f:	5d                   	pop    rbp
   140002a40:	c3                   	ret

0000000140002a41 <___w64_mingwthr_remove_key_dtor>:
   140002a41:	55                   	push   rbp
   140002a42:	48 89 e5             	mov    rbp,rsp
   140002a45:	48 83 ec 30          	sub    rsp,0x30
   140002a49:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a4c:	8b 05 f6 66 00 00    	mov    eax,DWORD PTR [rip+0x66f6]        # 140009148 <__mingwthr_cs_init>
   140002a52:	85 c0                	test   eax,eax
   140002a54:	75 0a                	jne    140002a60 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a56:	b8 00 00 00 00       	mov    eax,0x0
   140002a5b:	e9 9c 00 00 00       	jmp    140002afc <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a60:	48 8d 05 b9 66 00 00 	lea    rax,[rip+0x66b9]        # 140009120 <__mingwthr_cs>
   140002a67:	48 89 c1             	mov    rcx,rax
   140002a6a:	48 8b 05 27 77 00 00 	mov    rax,QWORD PTR [rip+0x7727]        # 14000a198 <__imp_EnterCriticalSection>
   140002a71:	ff d0                	call   rax
   140002a73:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a7a:	00 
   140002a7b:	48 8b 05 ce 66 00 00 	mov    rax,QWORD PTR [rip+0x66ce]        # 140009150 <key_dtor_list>
   140002a82:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a86:	eb 55                	jmp    140002add <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a88:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a8c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a8e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a91:	75 36                	jne    140002ac9 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a93:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a98:	75 11                	jne    140002aab <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a9a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a9e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002aa2:	48 89 05 a7 66 00 00 	mov    QWORD PTR [rip+0x66a7],rax        # 140009150 <key_dtor_list>
   140002aa9:	eb 10                	jmp    140002abb <___w64_mingwthr_remove_key_dtor+0x7a>
   140002aab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aaf:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002ab3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ab7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002abb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002abf:	48 89 c1             	mov    rcx,rax
   140002ac2:	e8 69 08 00 00       	call   140003330 <free>
   140002ac7:	eb 1b                	jmp    140002ae4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002ac9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002acd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ad1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ad5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ad9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002add:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002ae2:	75 a4                	jne    140002a88 <___w64_mingwthr_remove_key_dtor+0x47>
   140002ae4:	48 8d 05 35 66 00 00 	lea    rax,[rip+0x6635]        # 140009120 <__mingwthr_cs>
   140002aeb:	48 89 c1             	mov    rcx,rax
   140002aee:	48 8b 05 d3 76 00 00 	mov    rax,QWORD PTR [rip+0x76d3]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002af5:	ff d0                	call   rax
   140002af7:	b8 00 00 00 00       	mov    eax,0x0
   140002afc:	48 83 c4 30          	add    rsp,0x30
   140002b00:	5d                   	pop    rbp
   140002b01:	c3                   	ret

0000000140002b02 <__mingwthr_run_key_dtors>:
   140002b02:	55                   	push   rbp
   140002b03:	48 89 e5             	mov    rbp,rsp
   140002b06:	48 83 ec 30          	sub    rsp,0x30
   140002b0a:	8b 05 38 66 00 00    	mov    eax,DWORD PTR [rip+0x6638]        # 140009148 <__mingwthr_cs_init>
   140002b10:	85 c0                	test   eax,eax
   140002b12:	0f 84 82 00 00 00    	je     140002b9a <__mingwthr_run_key_dtors+0x98>
   140002b18:	48 8d 05 01 66 00 00 	lea    rax,[rip+0x6601]        # 140009120 <__mingwthr_cs>
   140002b1f:	48 89 c1             	mov    rcx,rax
   140002b22:	48 8b 05 6f 76 00 00 	mov    rax,QWORD PTR [rip+0x766f]        # 14000a198 <__imp_EnterCriticalSection>
   140002b29:	ff d0                	call   rax
   140002b2b:	48 8b 05 1e 66 00 00 	mov    rax,QWORD PTR [rip+0x661e]        # 140009150 <key_dtor_list>
   140002b32:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b36:	eb 46                	jmp    140002b7e <__mingwthr_run_key_dtors+0x7c>
   140002b38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b3c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b3e:	89 c1                	mov    ecx,eax
   140002b40:	48 8b 05 a1 76 00 00 	mov    rax,QWORD PTR [rip+0x76a1]        # 14000a1e8 <__imp_TlsGetValue>
   140002b47:	ff d0                	call   rax
   140002b49:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b4d:	48 8b 05 54 76 00 00 	mov    rax,QWORD PTR [rip+0x7654]        # 14000a1a8 <__imp_GetLastError>
   140002b54:	ff d0                	call   rax
   140002b56:	85 c0                	test   eax,eax
   140002b58:	75 18                	jne    140002b72 <__mingwthr_run_key_dtors+0x70>
   140002b5a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b5f:	74 11                	je     140002b72 <__mingwthr_run_key_dtors+0x70>
   140002b61:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b65:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002b69:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b6d:	48 89 c1             	mov    rcx,rax
   140002b70:	ff d2                	call   rdx
   140002b72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b76:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b7a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b7e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b83:	75 b3                	jne    140002b38 <__mingwthr_run_key_dtors+0x36>
   140002b85:	48 8d 05 94 65 00 00 	lea    rax,[rip+0x6594]        # 140009120 <__mingwthr_cs>
   140002b8c:	48 89 c1             	mov    rcx,rax
   140002b8f:	48 8b 05 32 76 00 00 	mov    rax,QWORD PTR [rip+0x7632]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002b96:	ff d0                	call   rax
   140002b98:	eb 01                	jmp    140002b9b <__mingwthr_run_key_dtors+0x99>
   140002b9a:	90                   	nop
   140002b9b:	48 83 c4 30          	add    rsp,0x30
   140002b9f:	5d                   	pop    rbp
   140002ba0:	c3                   	ret

0000000140002ba1 <__mingw_TLScallback>:
   140002ba1:	55                   	push   rbp
   140002ba2:	48 89 e5             	mov    rbp,rsp
   140002ba5:	48 83 ec 30          	sub    rsp,0x30
   140002ba9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002bad:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002bb0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002bb4:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002bb8:	0f 84 cc 00 00 00    	je     140002c8a <__mingw_TLScallback+0xe9>
   140002bbe:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002bc2:	0f 87 ca 00 00 00    	ja     140002c92 <__mingw_TLScallback+0xf1>
   140002bc8:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bcc:	0f 84 b1 00 00 00    	je     140002c83 <__mingw_TLScallback+0xe2>
   140002bd2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bd6:	0f 87 b6 00 00 00    	ja     140002c92 <__mingw_TLScallback+0xf1>
   140002bdc:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002be0:	74 33                	je     140002c15 <__mingw_TLScallback+0x74>
   140002be2:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002be6:	0f 85 a6 00 00 00    	jne    140002c92 <__mingw_TLScallback+0xf1>
   140002bec:	8b 05 56 65 00 00    	mov    eax,DWORD PTR [rip+0x6556]        # 140009148 <__mingwthr_cs_init>
   140002bf2:	85 c0                	test   eax,eax
   140002bf4:	75 13                	jne    140002c09 <__mingw_TLScallback+0x68>
   140002bf6:	48 8d 05 23 65 00 00 	lea    rax,[rip+0x6523]        # 140009120 <__mingwthr_cs>
   140002bfd:	48 89 c1             	mov    rcx,rax
   140002c00:	48 8b 05 b9 75 00 00 	mov    rax,QWORD PTR [rip+0x75b9]        # 14000a1c0 <__imp_InitializeCriticalSection>
   140002c07:	ff d0                	call   rax
   140002c09:	c7 05 35 65 00 00 01 	mov    DWORD PTR [rip+0x6535],0x1        # 140009148 <__mingwthr_cs_init>
   140002c10:	00 00 00 
   140002c13:	eb 7d                	jmp    140002c92 <__mingw_TLScallback+0xf1>
   140002c15:	e8 e8 fe ff ff       	call   140002b02 <__mingwthr_run_key_dtors>
   140002c1a:	8b 05 28 65 00 00    	mov    eax,DWORD PTR [rip+0x6528]        # 140009148 <__mingwthr_cs_init>
   140002c20:	83 f8 01             	cmp    eax,0x1
   140002c23:	75 6c                	jne    140002c91 <__mingw_TLScallback+0xf0>
   140002c25:	48 8b 05 24 65 00 00 	mov    rax,QWORD PTR [rip+0x6524]        # 140009150 <key_dtor_list>
   140002c2c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c30:	eb 20                	jmp    140002c52 <__mingw_TLScallback+0xb1>
   140002c32:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c36:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c3a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c3e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c42:	48 89 c1             	mov    rcx,rax
   140002c45:	e8 e6 06 00 00       	call   140003330 <free>
   140002c4a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c4e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c52:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c57:	75 d9                	jne    140002c32 <__mingw_TLScallback+0x91>
   140002c59:	48 c7 05 ec 64 00 00 	mov    QWORD PTR [rip+0x64ec],0x0        # 140009150 <key_dtor_list>
   140002c60:	00 00 00 00 
   140002c64:	c7 05 da 64 00 00 00 	mov    DWORD PTR [rip+0x64da],0x0        # 140009148 <__mingwthr_cs_init>
   140002c6b:	00 00 00 
   140002c6e:	48 8d 05 ab 64 00 00 	lea    rax,[rip+0x64ab]        # 140009120 <__mingwthr_cs>
   140002c75:	48 89 c1             	mov    rcx,rax
   140002c78:	48 8b 05 11 75 00 00 	mov    rax,QWORD PTR [rip+0x7511]        # 14000a190 <__IAT_start__>
   140002c7f:	ff d0                	call   rax
   140002c81:	eb 0e                	jmp    140002c91 <__mingw_TLScallback+0xf0>
   140002c83:	e8 18 00 00 00       	call   140002ca0 <_fpreset>
   140002c88:	eb 08                	jmp    140002c92 <__mingw_TLScallback+0xf1>
   140002c8a:	e8 73 fe ff ff       	call   140002b02 <__mingwthr_run_key_dtors>
   140002c8f:	eb 01                	jmp    140002c92 <__mingw_TLScallback+0xf1>
   140002c91:	90                   	nop
   140002c92:	b8 01 00 00 00       	mov    eax,0x1
   140002c97:	48 83 c4 30          	add    rsp,0x30
   140002c9b:	5d                   	pop    rbp
   140002c9c:	c3                   	ret
   140002c9d:	90                   	nop
   140002c9e:	90                   	nop
   140002c9f:	90                   	nop

0000000140002ca0 <_fpreset>:
   140002ca0:	55                   	push   rbp
   140002ca1:	48 89 e5             	mov    rbp,rsp
   140002ca4:	db e3                	fninit
   140002ca6:	90                   	nop
   140002ca7:	5d                   	pop    rbp
   140002ca8:	c3                   	ret
   140002ca9:	90                   	nop
   140002caa:	90                   	nop
   140002cab:	90                   	nop
   140002cac:	90                   	nop
   140002cad:	90                   	nop
   140002cae:	90                   	nop
   140002caf:	90                   	nop

0000000140002cb0 <_ValidateImageBase>:
   140002cb0:	55                   	push   rbp
   140002cb1:	48 89 e5             	mov    rbp,rsp
   140002cb4:	48 83 ec 20          	sub    rsp,0x20
   140002cb8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002cbc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cc0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cc4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cc8:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002ccb:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002ccf:	74 07                	je     140002cd8 <_ValidateImageBase+0x28>
   140002cd1:	b8 00 00 00 00       	mov    eax,0x0
   140002cd6:	eb 4e                	jmp    140002d26 <_ValidateImageBase+0x76>
   140002cd8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cdc:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002cdf:	48 63 d0             	movsxd rdx,eax
   140002ce2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ce6:	48 01 d0             	add    rax,rdx
   140002ce9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ced:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002cf1:	8b 00                	mov    eax,DWORD PTR [rax]
   140002cf3:	3d 50 45 00 00       	cmp    eax,0x4550
   140002cf8:	74 07                	je     140002d01 <_ValidateImageBase+0x51>
   140002cfa:	b8 00 00 00 00       	mov    eax,0x0
   140002cff:	eb 25                	jmp    140002d26 <_ValidateImageBase+0x76>
   140002d01:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d05:	48 83 c0 18          	add    rax,0x18
   140002d09:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d0d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d11:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d14:	66 3d 0b 02          	cmp    ax,0x20b
   140002d18:	74 07                	je     140002d21 <_ValidateImageBase+0x71>
   140002d1a:	b8 00 00 00 00       	mov    eax,0x0
   140002d1f:	eb 05                	jmp    140002d26 <_ValidateImageBase+0x76>
   140002d21:	b8 01 00 00 00       	mov    eax,0x1
   140002d26:	48 83 c4 20          	add    rsp,0x20
   140002d2a:	5d                   	pop    rbp
   140002d2b:	c3                   	ret

0000000140002d2c <_FindPESection>:
   140002d2c:	55                   	push   rbp
   140002d2d:	48 89 e5             	mov    rbp,rsp
   140002d30:	48 83 ec 20          	sub    rsp,0x20
   140002d34:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d38:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d3c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d40:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d43:	48 63 d0             	movsxd rdx,eax
   140002d46:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d4a:	48 01 d0             	add    rax,rdx
   140002d4d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d51:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d58:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d5c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d60:	0f b7 d0             	movzx  edx,ax
   140002d63:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d67:	48 01 d0             	add    rax,rdx
   140002d6a:	48 83 c0 18          	add    rax,0x18
   140002d6e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d72:	eb 36                	jmp    140002daa <_FindPESection+0x7e>
   140002d74:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d78:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d7b:	89 c0                	mov    eax,eax
   140002d7d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d81:	72 1e                	jb     140002da1 <_FindPESection+0x75>
   140002d83:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d87:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d8a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d8e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d91:	01 d0                	add    eax,edx
   140002d93:	89 c0                	mov    eax,eax
   140002d95:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d99:	73 06                	jae    140002da1 <_FindPESection+0x75>
   140002d9b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d9f:	eb 1e                	jmp    140002dbf <_FindPESection+0x93>
   140002da1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002da5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002daa:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dae:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002db2:	0f b7 c0             	movzx  eax,ax
   140002db5:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002db8:	72 ba                	jb     140002d74 <_FindPESection+0x48>
   140002dba:	b8 00 00 00 00       	mov    eax,0x0
   140002dbf:	48 83 c4 20          	add    rsp,0x20
   140002dc3:	5d                   	pop    rbp
   140002dc4:	c3                   	ret

0000000140002dc5 <_FindPESectionByName>:
   140002dc5:	55                   	push   rbp
   140002dc6:	48 89 e5             	mov    rbp,rsp
   140002dc9:	48 83 ec 40          	sub    rsp,0x40
   140002dcd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002dd1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002dd5:	48 89 c1             	mov    rcx,rax
   140002dd8:	e8 83 05 00 00       	call   140003360 <strlen>
   140002ddd:	48 83 f8 08          	cmp    rax,0x8
   140002de1:	76 0a                	jbe    140002ded <_FindPESectionByName+0x28>
   140002de3:	b8 00 00 00 00       	mov    eax,0x0
   140002de8:	e9 98 00 00 00       	jmp    140002e85 <_FindPESectionByName+0xc0>
   140002ded:	48 8b 05 6c 25 00 00 	mov    rax,QWORD PTR [rip+0x256c]        # 140005360 <.refptr.__ImageBase>
   140002df4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002df8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dfc:	48 89 c1             	mov    rcx,rax
   140002dff:	e8 ac fe ff ff       	call   140002cb0 <_ValidateImageBase>
   140002e04:	85 c0                	test   eax,eax
   140002e06:	75 07                	jne    140002e0f <_FindPESectionByName+0x4a>
   140002e08:	b8 00 00 00 00       	mov    eax,0x0
   140002e0d:	eb 76                	jmp    140002e85 <_FindPESectionByName+0xc0>
   140002e0f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e13:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e16:	48 63 d0             	movsxd rdx,eax
   140002e19:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e1d:	48 01 d0             	add    rax,rdx
   140002e20:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e24:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e2b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e2f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e33:	0f b7 d0             	movzx  edx,ax
   140002e36:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e3a:	48 01 d0             	add    rax,rdx
   140002e3d:	48 83 c0 18          	add    rax,0x18
   140002e41:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e45:	eb 29                	jmp    140002e70 <_FindPESectionByName+0xab>
   140002e47:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e4b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e4f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e55:	48 89 c1             	mov    rcx,rax
   140002e58:	e8 0b 05 00 00       	call   140003368 <strncmp>
   140002e5d:	85 c0                	test   eax,eax
   140002e5f:	75 06                	jne    140002e67 <_FindPESectionByName+0xa2>
   140002e61:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e65:	eb 1e                	jmp    140002e85 <_FindPESectionByName+0xc0>
   140002e67:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e6b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e70:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e74:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e78:	0f b7 c0             	movzx  eax,ax
   140002e7b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e7e:	72 c7                	jb     140002e47 <_FindPESectionByName+0x82>
   140002e80:	b8 00 00 00 00       	mov    eax,0x0
   140002e85:	48 83 c4 40          	add    rsp,0x40
   140002e89:	5d                   	pop    rbp
   140002e8a:	c3                   	ret

0000000140002e8b <__mingw_GetSectionForAddress>:
   140002e8b:	55                   	push   rbp
   140002e8c:	48 89 e5             	mov    rbp,rsp
   140002e8f:	48 83 ec 30          	sub    rsp,0x30
   140002e93:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e97:	48 8b 05 c2 24 00 00 	mov    rax,QWORD PTR [rip+0x24c2]        # 140005360 <.refptr.__ImageBase>
   140002e9e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ea2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ea6:	48 89 c1             	mov    rcx,rax
   140002ea9:	e8 02 fe ff ff       	call   140002cb0 <_ValidateImageBase>
   140002eae:	85 c0                	test   eax,eax
   140002eb0:	75 07                	jne    140002eb9 <__mingw_GetSectionForAddress+0x2e>
   140002eb2:	b8 00 00 00 00       	mov    eax,0x0
   140002eb7:	eb 1c                	jmp    140002ed5 <__mingw_GetSectionForAddress+0x4a>
   140002eb9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ebd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002ec1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ec5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002ec9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ecd:	48 89 c1             	mov    rcx,rax
   140002ed0:	e8 57 fe ff ff       	call   140002d2c <_FindPESection>
   140002ed5:	48 83 c4 30          	add    rsp,0x30
   140002ed9:	5d                   	pop    rbp
   140002eda:	c3                   	ret

0000000140002edb <__mingw_GetSectionCount>:
   140002edb:	55                   	push   rbp
   140002edc:	48 89 e5             	mov    rbp,rsp
   140002edf:	48 83 ec 30          	sub    rsp,0x30
   140002ee3:	48 8b 05 76 24 00 00 	mov    rax,QWORD PTR [rip+0x2476]        # 140005360 <.refptr.__ImageBase>
   140002eea:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002eee:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ef2:	48 89 c1             	mov    rcx,rax
   140002ef5:	e8 b6 fd ff ff       	call   140002cb0 <_ValidateImageBase>
   140002efa:	85 c0                	test   eax,eax
   140002efc:	75 07                	jne    140002f05 <__mingw_GetSectionCount+0x2a>
   140002efe:	b8 00 00 00 00       	mov    eax,0x0
   140002f03:	eb 20                	jmp    140002f25 <__mingw_GetSectionCount+0x4a>
   140002f05:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f09:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f0c:	48 63 d0             	movsxd rdx,eax
   140002f0f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f13:	48 01 d0             	add    rax,rdx
   140002f16:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f1a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002f1e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f22:	0f b7 c0             	movzx  eax,ax
   140002f25:	48 83 c4 30          	add    rsp,0x30
   140002f29:	5d                   	pop    rbp
   140002f2a:	c3                   	ret

0000000140002f2b <_FindPESectionExec>:
   140002f2b:	55                   	push   rbp
   140002f2c:	48 89 e5             	mov    rbp,rsp
   140002f2f:	48 83 ec 40          	sub    rsp,0x40
   140002f33:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f37:	48 8b 05 22 24 00 00 	mov    rax,QWORD PTR [rip+0x2422]        # 140005360 <.refptr.__ImageBase>
   140002f3e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f42:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f46:	48 89 c1             	mov    rcx,rax
   140002f49:	e8 62 fd ff ff       	call   140002cb0 <_ValidateImageBase>
   140002f4e:	85 c0                	test   eax,eax
   140002f50:	75 07                	jne    140002f59 <_FindPESectionExec+0x2e>
   140002f52:	b8 00 00 00 00       	mov    eax,0x0
   140002f57:	eb 78                	jmp    140002fd1 <_FindPESectionExec+0xa6>
   140002f59:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f5d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f60:	48 63 d0             	movsxd rdx,eax
   140002f63:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f67:	48 01 d0             	add    rax,rdx
   140002f6a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f6e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f75:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f79:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f7d:	0f b7 d0             	movzx  edx,ax
   140002f80:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f84:	48 01 d0             	add    rax,rdx
   140002f87:	48 83 c0 18          	add    rax,0x18
   140002f8b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f8f:	eb 2b                	jmp    140002fbc <_FindPESectionExec+0x91>
   140002f91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f95:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f98:	25 00 00 00 20       	and    eax,0x20000000
   140002f9d:	85 c0                	test   eax,eax
   140002f9f:	74 12                	je     140002fb3 <_FindPESectionExec+0x88>
   140002fa1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002fa6:	75 06                	jne    140002fae <_FindPESectionExec+0x83>
   140002fa8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fac:	eb 23                	jmp    140002fd1 <_FindPESectionExec+0xa6>
   140002fae:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002fb3:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002fb7:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002fbc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fc0:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002fc4:	0f b7 c0             	movzx  eax,ax
   140002fc7:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002fca:	72 c5                	jb     140002f91 <_FindPESectionExec+0x66>
   140002fcc:	b8 00 00 00 00       	mov    eax,0x0
   140002fd1:	48 83 c4 40          	add    rsp,0x40
   140002fd5:	5d                   	pop    rbp
   140002fd6:	c3                   	ret

0000000140002fd7 <_GetPEImageBase>:
   140002fd7:	55                   	push   rbp
   140002fd8:	48 89 e5             	mov    rbp,rsp
   140002fdb:	48 83 ec 30          	sub    rsp,0x30
   140002fdf:	48 8b 05 7a 23 00 00 	mov    rax,QWORD PTR [rip+0x237a]        # 140005360 <.refptr.__ImageBase>
   140002fe6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fea:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fee:	48 89 c1             	mov    rcx,rax
   140002ff1:	e8 ba fc ff ff       	call   140002cb0 <_ValidateImageBase>
   140002ff6:	85 c0                	test   eax,eax
   140002ff8:	75 07                	jne    140003001 <_GetPEImageBase+0x2a>
   140002ffa:	b8 00 00 00 00       	mov    eax,0x0
   140002fff:	eb 04                	jmp    140003005 <_GetPEImageBase+0x2e>
   140003001:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003005:	48 83 c4 30          	add    rsp,0x30
   140003009:	5d                   	pop    rbp
   14000300a:	c3                   	ret

000000014000300b <_IsNonwritableInCurrentImage>:
   14000300b:	55                   	push   rbp
   14000300c:	48 89 e5             	mov    rbp,rsp
   14000300f:	48 83 ec 40          	sub    rsp,0x40
   140003013:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003017:	48 8b 05 42 23 00 00 	mov    rax,QWORD PTR [rip+0x2342]        # 140005360 <.refptr.__ImageBase>
   14000301e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003022:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003026:	48 89 c1             	mov    rcx,rax
   140003029:	e8 82 fc ff ff       	call   140002cb0 <_ValidateImageBase>
   14000302e:	85 c0                	test   eax,eax
   140003030:	75 07                	jne    140003039 <_IsNonwritableInCurrentImage+0x2e>
   140003032:	b8 00 00 00 00       	mov    eax,0x0
   140003037:	eb 3d                	jmp    140003076 <_IsNonwritableInCurrentImage+0x6b>
   140003039:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000303d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003041:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003045:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003049:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000304d:	48 89 c1             	mov    rcx,rax
   140003050:	e8 d7 fc ff ff       	call   140002d2c <_FindPESection>
   140003055:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003059:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000305e:	75 07                	jne    140003067 <_IsNonwritableInCurrentImage+0x5c>
   140003060:	b8 00 00 00 00       	mov    eax,0x0
   140003065:	eb 0f                	jmp    140003076 <_IsNonwritableInCurrentImage+0x6b>
   140003067:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000306b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000306e:	f7 d0                	not    eax
   140003070:	c1 e8 1f             	shr    eax,0x1f
   140003073:	0f b6 c0             	movzx  eax,al
   140003076:	48 83 c4 40          	add    rsp,0x40
   14000307a:	5d                   	pop    rbp
   14000307b:	c3                   	ret

000000014000307c <__mingw_enum_import_library_names>:
   14000307c:	55                   	push   rbp
   14000307d:	48 89 e5             	mov    rbp,rsp
   140003080:	48 83 ec 50          	sub    rsp,0x50
   140003084:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003087:	48 8b 05 d2 22 00 00 	mov    rax,QWORD PTR [rip+0x22d2]        # 140005360 <.refptr.__ImageBase>
   14000308e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003092:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003096:	48 89 c1             	mov    rcx,rax
   140003099:	e8 12 fc ff ff       	call   140002cb0 <_ValidateImageBase>
   14000309e:	85 c0                	test   eax,eax
   1400030a0:	75 0a                	jne    1400030ac <__mingw_enum_import_library_names+0x30>
   1400030a2:	b8 00 00 00 00       	mov    eax,0x0
   1400030a7:	e9 ab 00 00 00       	jmp    140003157 <__mingw_enum_import_library_names+0xdb>
   1400030ac:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030b0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   1400030b3:	48 63 d0             	movsxd rdx,eax
   1400030b6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030ba:	48 01 d0             	add    rax,rdx
   1400030bd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400030c1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030c5:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   1400030cb:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400030ce:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400030d2:	75 07                	jne    1400030db <__mingw_enum_import_library_names+0x5f>
   1400030d4:	b8 00 00 00 00       	mov    eax,0x0
   1400030d9:	eb 7c                	jmp    140003157 <__mingw_enum_import_library_names+0xdb>
   1400030db:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030de:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030e2:	48 89 c1             	mov    rcx,rax
   1400030e5:	e8 42 fc ff ff       	call   140002d2c <_FindPESection>
   1400030ea:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400030ee:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   1400030f3:	75 07                	jne    1400030fc <__mingw_enum_import_library_names+0x80>
   1400030f5:	b8 00 00 00 00       	mov    eax,0x0
   1400030fa:	eb 5b                	jmp    140003157 <__mingw_enum_import_library_names+0xdb>
   1400030fc:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030ff:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003103:	48 01 d0             	add    rax,rdx
   140003106:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000310a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000310f:	75 07                	jne    140003118 <__mingw_enum_import_library_names+0x9c>
   140003111:	b8 00 00 00 00       	mov    eax,0x0
   140003116:	eb 3f                	jmp    140003157 <__mingw_enum_import_library_names+0xdb>
   140003118:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000311c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000311f:	85 c0                	test   eax,eax
   140003121:	75 0b                	jne    14000312e <__mingw_enum_import_library_names+0xb2>
   140003123:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003127:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000312a:	85 c0                	test   eax,eax
   14000312c:	74 23                	je     140003151 <__mingw_enum_import_library_names+0xd5>
   14000312e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003132:	7f 12                	jg     140003146 <__mingw_enum_import_library_names+0xca>
   140003134:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003138:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000313b:	89 c2                	mov    edx,eax
   14000313d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003141:	48 01 d0             	add    rax,rdx
   140003144:	eb 11                	jmp    140003157 <__mingw_enum_import_library_names+0xdb>
   140003146:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000314a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000314f:	eb c7                	jmp    140003118 <__mingw_enum_import_library_names+0x9c>
   140003151:	90                   	nop
   140003152:	b8 00 00 00 00       	mov    eax,0x0
   140003157:	48 83 c4 50          	add    rsp,0x50
   14000315b:	5d                   	pop    rbp
   14000315c:	c3                   	ret
   14000315d:	90                   	nop
   14000315e:	90                   	nop
   14000315f:	90                   	nop

0000000140003160 <___chkstk_ms>:
   140003160:	51                   	push   rcx
   140003161:	50                   	push   rax
   140003162:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003168:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000316d:	72 19                	jb     140003188 <___chkstk_ms+0x28>
   14000316f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003176:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000317a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003180:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003186:	77 e7                	ja     14000316f <___chkstk_ms+0xf>
   140003188:	48 29 c1             	sub    rcx,rax
   14000318b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000318f:	58                   	pop    rax
   140003190:	59                   	pop    rcx
   140003191:	c3                   	ret
   140003192:	90                   	nop
   140003193:	90                   	nop
   140003194:	90                   	nop
   140003195:	90                   	nop
   140003196:	90                   	nop
   140003197:	90                   	nop
   140003198:	90                   	nop
   140003199:	90                   	nop
   14000319a:	90                   	nop
   14000319b:	90                   	nop
   14000319c:	90                   	nop
   14000319d:	90                   	nop
   14000319e:	90                   	nop
   14000319f:	90                   	nop

00000001400031a0 <_initterm_e>:
   1400031a0:	55                   	push   rbp
   1400031a1:	48 89 e5             	mov    rbp,rsp
   1400031a4:	48 83 ec 30          	sub    rsp,0x30
   1400031a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400031ac:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400031b0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400031b4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031b8:	eb 29                	jmp    1400031e3 <_initterm_e+0x43>
   1400031ba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031be:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031c1:	48 85 c0             	test   rax,rax
   1400031c4:	74 17                	je     1400031dd <_initterm_e+0x3d>
   1400031c6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031ca:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031cd:	ff d0                	call   rax
   1400031cf:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400031d2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   1400031d6:	74 06                	je     1400031de <_initterm_e+0x3e>
   1400031d8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400031db:	eb 15                	jmp    1400031f2 <_initterm_e+0x52>
   1400031dd:	90                   	nop
   1400031de:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400031e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031e7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400031eb:	72 cd                	jb     1400031ba <_initterm_e+0x1a>
   1400031ed:	b8 00 00 00 00       	mov    eax,0x0
   1400031f2:	48 83 c4 30          	add    rsp,0x30
   1400031f6:	5d                   	pop    rbp
   1400031f7:	c3                   	ret
   1400031f8:	90                   	nop
   1400031f9:	90                   	nop
   1400031fa:	90                   	nop
   1400031fb:	90                   	nop
   1400031fc:	90                   	nop
   1400031fd:	90                   	nop
   1400031fe:	90                   	nop
   1400031ff:	90                   	nop

0000000140003200 <__p__fmode>:
   140003200:	55                   	push   rbp
   140003201:	48 89 e5             	mov    rbp,rsp
   140003204:	48 8b 05 c5 21 00 00 	mov    rax,QWORD PTR [rip+0x21c5]        # 1400053d0 <.refptr.__imp__fmode>
   14000320b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000320e:	5d                   	pop    rbp
   14000320f:	c3                   	ret

0000000140003210 <__p__commode>:
   140003210:	55                   	push   rbp
   140003211:	48 89 e5             	mov    rbp,rsp
   140003214:	48 8b 05 a5 21 00 00 	mov    rax,QWORD PTR [rip+0x21a5]        # 1400053c0 <.refptr.__imp__commode>
   14000321b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000321e:	5d                   	pop    rbp
   14000321f:	c3                   	ret

0000000140003220 <__p___initenv>:
   140003220:	55                   	push   rbp
   140003221:	48 89 e5             	mov    rbp,rsp
   140003224:	48 8b 05 85 21 00 00 	mov    rax,QWORD PTR [rip+0x2185]        # 1400053b0 <.refptr.__imp___initenv>
   14000322b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000322e:	5d                   	pop    rbp
   14000322f:	c3                   	ret

0000000140003230 <_set_invalid_parameter_handler>:
   140003230:	55                   	push   rbp
   140003231:	48 89 e5             	mov    rbp,rsp
   140003234:	48 83 ec 10          	sub    rsp,0x10
   140003238:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000323c:	48 8d 05 4d 5f 00 00 	lea    rax,[rip+0x5f4d]        # 140009190 <handler>
   140003243:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003247:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000324b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000324f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003253:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003257:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000325a:	48 89 d0             	mov    rax,rdx
   14000325d:	48 83 c4 10          	add    rsp,0x10
   140003261:	5d                   	pop    rbp
   140003262:	c3                   	ret

0000000140003263 <_get_invalid_parameter_handler>:
   140003263:	55                   	push   rbp
   140003264:	48 89 e5             	mov    rbp,rsp
   140003267:	48 8b 05 22 5f 00 00 	mov    rax,QWORD PTR [rip+0x5f22]        # 140009190 <handler>
   14000326e:	5d                   	pop    rbp
   14000326f:	c3                   	ret

0000000140003270 <_configthreadlocale>:
   140003270:	55                   	push   rbp
   140003271:	48 89 e5             	mov    rbp,rsp
   140003274:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003277:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000327b:	75 07                	jne    140003284 <_configthreadlocale+0x14>
   14000327d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140003282:	eb 05                	jmp    140003289 <_configthreadlocale+0x19>
   140003284:	b8 02 00 00 00       	mov    eax,0x2
   140003289:	5d                   	pop    rbp
   14000328a:	c3                   	ret
   14000328b:	90                   	nop
   14000328c:	90                   	nop
   14000328d:	90                   	nop
   14000328e:	90                   	nop
   14000328f:	90                   	nop

0000000140003290 <__acrt_iob_func>:
   140003290:	55                   	push   rbp
   140003291:	48 89 e5             	mov    rbp,rsp
   140003294:	48 83 ec 20          	sub    rsp,0x20
   140003298:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000329b:	e8 30 00 00 00       	call   1400032d0 <__iob_func>
   1400032a0:	48 89 c1             	mov    rcx,rax
   1400032a3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400032a6:	48 89 d0             	mov    rax,rdx
   1400032a9:	48 01 c0             	add    rax,rax
   1400032ac:	48 01 d0             	add    rax,rdx
   1400032af:	48 c1 e0 04          	shl    rax,0x4
   1400032b3:	48 01 c8             	add    rax,rcx
   1400032b6:	48 83 c4 20          	add    rsp,0x20
   1400032ba:	5d                   	pop    rbp
   1400032bb:	c3                   	ret
   1400032bc:	90                   	nop
   1400032bd:	90                   	nop
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <__C_specific_handler>:
   1400032c0:	ff 25 42 6f 00 00    	jmp    QWORD PTR [rip+0x6f42]        # 14000a208 <__imp___C_specific_handler>
   1400032c6:	90                   	nop
   1400032c7:	90                   	nop

00000001400032c8 <__getmainargs>:
   1400032c8:	ff 25 42 6f 00 00    	jmp    QWORD PTR [rip+0x6f42]        # 14000a210 <__imp___getmainargs>
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <__iob_func>:
   1400032d0:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a220 <__imp___iob_func>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop

00000001400032d8 <__set_app_type>:
   1400032d8:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a228 <__imp___set_app_type>
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <__setusermatherr>:
   1400032e0:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a230 <__imp___setusermatherr>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <_amsg_exit>:
   1400032e8:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a238 <__imp__amsg_exit>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <_cexit>:
   1400032f0:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a240 <__imp__cexit>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <_initterm>:
   1400032f8:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a258 <__imp__initterm>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <_crt_atexit>:
   140003300:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a260 <__imp__crt_atexit>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <abort>:
   140003308:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a268 <__imp_abort>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <calloc>:
   140003310:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a270 <__imp_calloc>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <exit>:
   140003318:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a278 <__imp_exit>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <fflush>:
   140003320:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a280 <__imp_fflush>
   140003326:	90                   	nop
   140003327:	90                   	nop

0000000140003328 <fprintf>:
   140003328:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a288 <__imp_fprintf>
   14000332e:	90                   	nop
   14000332f:	90                   	nop

0000000140003330 <free>:
   140003330:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a290 <__imp_free>
   140003336:	90                   	nop
   140003337:	90                   	nop

0000000140003338 <malloc>:
   140003338:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a298 <__imp_malloc>
   14000333e:	90                   	nop
   14000333f:	90                   	nop

0000000140003340 <memcpy>:
   140003340:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a2a0 <__imp_memcpy>
   140003346:	90                   	nop
   140003347:	90                   	nop

0000000140003348 <memset>:
   140003348:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a2a8 <__imp_memset>
   14000334e:	90                   	nop
   14000334f:	90                   	nop

0000000140003350 <setvbuf>:
   140003350:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a2b0 <__imp_setvbuf>
   140003356:	90                   	nop
   140003357:	90                   	nop

0000000140003358 <signal>:
   140003358:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a2b8 <__imp_signal>
   14000335e:	90                   	nop
   14000335f:	90                   	nop

0000000140003360 <strlen>:
   140003360:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a2c0 <__imp_strlen>
   140003366:	90                   	nop
   140003367:	90                   	nop

0000000140003368 <strncmp>:
   140003368:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a2c8 <__imp_strncmp>
   14000336e:	90                   	nop
   14000336f:	90                   	nop

0000000140003370 <vfprintf>:
   140003370:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a2d0 <__imp_vfprintf>
   140003376:	90                   	nop
   140003377:	90                   	nop
   140003378:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000337f:	00 

0000000140003380 <VirtualQuery>:
   140003380:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a1f8 <__imp_VirtualQuery>
   140003386:	90                   	nop
   140003387:	90                   	nop

0000000140003388 <VirtualProtect>:
   140003388:	ff 25 62 6e 00 00    	jmp    QWORD PTR [rip+0x6e62]        # 14000a1f0 <__imp_VirtualProtect>
   14000338e:	90                   	nop
   14000338f:	90                   	nop

0000000140003390 <TlsGetValue>:
   140003390:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 14000a1e8 <__imp_TlsGetValue>
   140003396:	90                   	nop
   140003397:	90                   	nop

0000000140003398 <Sleep>:
   140003398:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 14000a1e0 <__imp_Sleep>
   14000339e:	90                   	nop
   14000339f:	90                   	nop

00000001400033a0 <SetUnhandledExceptionFilter>:
   1400033a0:	ff 25 32 6e 00 00    	jmp    QWORD PTR [rip+0x6e32]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400033a6:	90                   	nop
   1400033a7:	90                   	nop

00000001400033a8 <LoadLibraryA>:
   1400033a8:	ff 25 22 6e 00 00    	jmp    QWORD PTR [rip+0x6e22]        # 14000a1d0 <__imp_LoadLibraryA>
   1400033ae:	90                   	nop
   1400033af:	90                   	nop

00000001400033b0 <LeaveCriticalSection>:
   1400033b0:	ff 25 12 6e 00 00    	jmp    QWORD PTR [rip+0x6e12]        # 14000a1c8 <__imp_LeaveCriticalSection>
   1400033b6:	90                   	nop
   1400033b7:	90                   	nop

00000001400033b8 <InitializeCriticalSection>:
   1400033b8:	ff 25 02 6e 00 00    	jmp    QWORD PTR [rip+0x6e02]        # 14000a1c0 <__imp_InitializeCriticalSection>
   1400033be:	90                   	nop
   1400033bf:	90                   	nop

00000001400033c0 <GetProcAddress>:
   1400033c0:	ff 25 f2 6d 00 00    	jmp    QWORD PTR [rip+0x6df2]        # 14000a1b8 <__imp_GetProcAddress>
   1400033c6:	90                   	nop
   1400033c7:	90                   	nop

00000001400033c8 <GetModuleHandleA>:
   1400033c8:	ff 25 e2 6d 00 00    	jmp    QWORD PTR [rip+0x6de2]        # 14000a1b0 <__imp_GetModuleHandleA>
   1400033ce:	90                   	nop
   1400033cf:	90                   	nop

00000001400033d0 <GetLastError>:
   1400033d0:	ff 25 d2 6d 00 00    	jmp    QWORD PTR [rip+0x6dd2]        # 14000a1a8 <__imp_GetLastError>
   1400033d6:	90                   	nop
   1400033d7:	90                   	nop

00000001400033d8 <FreeLibrary>:
   1400033d8:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 14000a1a0 <__imp_FreeLibrary>
   1400033de:	90                   	nop
   1400033df:	90                   	nop

00000001400033e0 <EnterCriticalSection>:
   1400033e0:	ff 25 b2 6d 00 00    	jmp    QWORD PTR [rip+0x6db2]        # 14000a198 <__imp_EnterCriticalSection>
   1400033e6:	90                   	nop
   1400033e7:	90                   	nop

00000001400033e8 <DeleteCriticalSection>:
   1400033e8:	ff 25 a2 6d 00 00    	jmp    QWORD PTR [rip+0x6da2]        # 14000a190 <__IAT_start__>
   1400033ee:	90                   	nop
   1400033ef:	90                   	nop

00000001400033f0 <register_frame_ctor>:
   1400033f0:	e9 7b e2 ff ff       	jmp    140001670 <__gcc_register_frame>
   1400033f5:	90                   	nop
   1400033f6:	90                   	nop
   1400033f7:	90                   	nop
   1400033f8:	90                   	nop
   1400033f9:	90                   	nop
   1400033fa:	90                   	nop
   1400033fb:	90                   	nop
   1400033fc:	90                   	nop
   1400033fd:	90                   	nop
   1400033fe:	90                   	nop
   1400033ff:	90                   	nop
