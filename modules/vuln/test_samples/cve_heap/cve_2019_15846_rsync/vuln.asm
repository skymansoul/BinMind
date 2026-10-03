
C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\test_samples\cve_heap\cve_2019_15846_rsync\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 8f 22 00 00       	call   1400032b8 <fflush>
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
   1400010e8:	48 8b 05 f9 90 00 00 	mov    rax,QWORD PTR [rip+0x90f9]        # 14000a1e8 <__imp_Sleep>
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
   14000113b:	e8 38 21 00 00       	call   140003278 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 b8 20 00 00       	call   140003220 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 67 21 00 00       	call   1400032e8 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 ff 20 00 00       	call   140003298 <abort>
   140001199:	e8 82 11 00 00       	call   140002320 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 31 90 00 00 	mov    rax,QWORD PTR [rip+0x9031]        # 14000a1e0 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 f6 1f 00 00       	call   1400031c0 <_set_invalid_parameter_handler>
   1400011ca:	e8 61 1a 00 00       	call   140002c30 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 77 20 00 00       	call   140003268 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 6b 20 00 00       	call   140003268 <__set_app_type>
   1400011fd:	e8 8e 1f 00 00       	call   140003190 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 8e 1f 00 00       	call   1400031a0 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 de 06 00 00       	call   140001900 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 43 20 00 00       	call   140003278 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 e8 11 00 00       	call   14000243a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 96 1f 00 00       	call   140003200 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 b0 1e 00 00       	call   140003130 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 ea 1f 00 00       	call   140003278 <_amsg_exit>
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
   1400012cb:	e8 88 1f 00 00       	call   140003258 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 95 1f 00 00       	call   140003278 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 6e 1f 00 00       	call   140003278 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 68 1f 00 00       	call   140003288 <_initterm>
   140001320:	e8 b2 05 00 00       	call   1400018d7 <__main>
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
   14000138d:	e8 1e 1e 00 00       	call   1400031b0 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 a6 03 00 00       	call   140001760 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 df 1e 00 00       	call   1400032b0 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 a0 1e 00 00       	call   140003280 <_cexit>
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
   140001511:	e8 ba 1d 00 00       	call   1400032d0 <malloc>
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
   14000155c:	e8 97 1d 00 00       	call   1400032f8 <strlen>
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
   140001585:	e8 46 1d 00 00       	call   1400032d0 <malloc>
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
   1400015e8:	e8 eb 1c 00 00       	call   1400032d8 <memcpy>
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
   140001642:	e8 49 1c 00 00       	call   140003290 <_crt_atexit>
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
   140001682:	ff 15 30 8b 00 00    	call   QWORD PTR [rip+0x8b30]        # 14000a1b8 <__imp_GetModuleHandleA>
   140001688:	48 89 c3             	mov    rbx,rax
   14000168b:	48 85 c0             	test   rax,rax
   14000168e:	74 70                	je     140001700 <__gcc_register_frame+0x90>
   140001690:	48 8d 0d 69 39 00 00 	lea    rcx,[rip+0x3969]        # 140005000 <.rdata>
   140001697:	ff 15 3b 8b 00 00    	call   QWORD PTR [rip+0x8b3b]        # 14000a1d8 <__imp_LoadLibraryA>
   14000169d:	4c 8b 0d 1c 8b 00 00 	mov    r9,QWORD PTR [rip+0x8b1c]        # 14000a1c0 <__imp_GetProcAddress>
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
   14000174e:	48 ff 25 53 8a 00 00 	rex.W jmp QWORD PTR [rip+0x8a53]        # 14000a1a8 <__imp_FreeLibrary>
   140001755:	0f 1f 00             	nop    DWORD PTR [rax]
   140001758:	48 83 c4 20          	add    rsp,0x20
   14000175c:	5d                   	pop    rbp
   14000175d:	c3                   	ret
   14000175e:	90                   	nop
   14000175f:	90                   	nop

0000000140001760 <main>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 81 ec b0 00 00 00 	sub    rsp,0xb0
   14000176b:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000176e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001772:	e8 60 01 00 00       	call   1400018d7 <__main>
   140001777:	48 c7 45 f8 20 00 00 	mov    QWORD PTR [rbp-0x8],0x20
   14000177e:	00 
   14000177f:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   140001783:	7e 19                	jle    14000179e <main+0x3e>
   140001785:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001789:	48 83 c0 08          	add    rax,0x8
   14000178d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001790:	48 89 c1             	mov    rcx,rax
   140001793:	e8 08 1b 00 00       	call   1400032a0 <atoi>
   140001798:	48 98                	cdqe
   14000179a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000179e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017a2:	ba 01 00 00 00       	mov    edx,0x1
   1400017a7:	48 89 c1             	mov    rcx,rax
   1400017aa:	e8 f9 1a 00 00       	call   1400032a8 <calloc>
   1400017af:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400017b3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400017b8:	75 07                	jne    1400017c1 <main+0x61>
   1400017ba:	b8 01 00 00 00       	mov    eax,0x1
   1400017bf:	eb 49                	jmp    14000180a <main+0xaa>
   1400017c1:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400017c8:	41 b8 80 00 00 00    	mov    r8d,0x80
   1400017ce:	ba 43 00 00 00       	mov    edx,0x43
   1400017d3:	48 89 c1             	mov    rcx,rax
   1400017d6:	e8 05 1b 00 00       	call   1400032e0 <memset>
   1400017db:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017df:	48 8d 0c 00          	lea    rcx,[rax+rax*1]
   1400017e3:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   1400017ea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017ee:	49 89 c8             	mov    r8,rcx
   1400017f1:	48 89 c1             	mov    rcx,rax
   1400017f4:	e8 df 1a 00 00       	call   1400032d8 <memcpy>
   1400017f9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017fd:	48 89 c1             	mov    rcx,rax
   140001800:	e8 c3 1a 00 00       	call   1400032c8 <free>
   140001805:	b8 00 00 00 00       	mov    eax,0x0
   14000180a:	48 81 c4 b0 00 00 00 	add    rsp,0xb0
   140001811:	5d                   	pop    rbp
   140001812:	c3                   	ret
   140001813:	90                   	nop
   140001814:	90                   	nop
   140001815:	90                   	nop
   140001816:	90                   	nop
   140001817:	90                   	nop
   140001818:	90                   	nop
   140001819:	90                   	nop
   14000181a:	90                   	nop
   14000181b:	90                   	nop
   14000181c:	90                   	nop
   14000181d:	90                   	nop
   14000181e:	90                   	nop
   14000181f:	90                   	nop

0000000140001820 <__do_global_dtors>:
   140001820:	55                   	push   rbp
   140001821:	48 89 e5             	mov    rbp,rsp
   140001824:	48 83 ec 20          	sub    rsp,0x20
   140001828:	eb 1e                	jmp    140001848 <__do_global_dtors+0x28>
   14000182a:	48 8b 05 df 27 00 00 	mov    rax,QWORD PTR [rip+0x27df]        # 140004010 <p.0>
   140001831:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001834:	ff d0                	call   rax
   140001836:	48 8b 05 d3 27 00 00 	mov    rax,QWORD PTR [rip+0x27d3]        # 140004010 <p.0>
   14000183d:	48 83 c0 08          	add    rax,0x8
   140001841:	48 89 05 c8 27 00 00 	mov    QWORD PTR [rip+0x27c8],rax        # 140004010 <p.0>
   140001848:	48 8b 05 c1 27 00 00 	mov    rax,QWORD PTR [rip+0x27c1]        # 140004010 <p.0>
   14000184f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001852:	48 85 c0             	test   rax,rax
   140001855:	75 d3                	jne    14000182a <__do_global_dtors+0xa>
   140001857:	90                   	nop
   140001858:	90                   	nop
   140001859:	48 83 c4 20          	add    rsp,0x20
   14000185d:	5d                   	pop    rbp
   14000185e:	c3                   	ret

000000014000185f <__do_global_ctors>:
   14000185f:	55                   	push   rbp
   140001860:	48 89 e5             	mov    rbp,rsp
   140001863:	48 83 ec 30          	sub    rsp,0x30
   140001867:	48 8b 05 e2 3a 00 00 	mov    rax,QWORD PTR [rip+0x3ae2]        # 140005350 <.refptr.__CTOR_LIST__>
   14000186e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001871:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001874:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001878:	75 25                	jne    14000189f <__do_global_ctors+0x40>
   14000187a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001881:	eb 04                	jmp    140001887 <__do_global_ctors+0x28>
   140001883:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001887:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000188a:	8d 50 01             	lea    edx,[rax+0x1]
   14000188d:	48 8b 05 bc 3a 00 00 	mov    rax,QWORD PTR [rip+0x3abc]        # 140005350 <.refptr.__CTOR_LIST__>
   140001894:	89 d2                	mov    edx,edx
   140001896:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000189a:	48 85 c0             	test   rax,rax
   14000189d:	75 e4                	jne    140001883 <__do_global_ctors+0x24>
   14000189f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018a2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400018a5:	eb 14                	jmp    1400018bb <__do_global_ctors+0x5c>
   1400018a7:	48 8b 05 a2 3a 00 00 	mov    rax,QWORD PTR [rip+0x3aa2]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018ae:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400018b1:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018b5:	ff d0                	call   rax
   1400018b7:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400018bb:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400018bf:	75 e6                	jne    1400018a7 <__do_global_ctors+0x48>
   1400018c1:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001820 <__do_global_dtors>
   1400018c8:	48 89 c1             	mov    rcx,rax
   1400018cb:	e8 5f fd ff ff       	call   14000162f <atexit>
   1400018d0:	90                   	nop
   1400018d1:	48 83 c4 30          	add    rsp,0x30
   1400018d5:	5d                   	pop    rbp
   1400018d6:	c3                   	ret

00000001400018d7 <__main>:
   1400018d7:	55                   	push   rbp
   1400018d8:	48 89 e5             	mov    rbp,rsp
   1400018db:	48 83 ec 20          	sub    rsp,0x20
   1400018df:	8b 05 9b 77 00 00    	mov    eax,DWORD PTR [rip+0x779b]        # 140009080 <initialized>
   1400018e5:	85 c0                	test   eax,eax
   1400018e7:	75 0f                	jne    1400018f8 <__main+0x21>
   1400018e9:	c7 05 8d 77 00 00 01 	mov    DWORD PTR [rip+0x778d],0x1        # 140009080 <initialized>
   1400018f0:	00 00 00 
   1400018f3:	e8 67 ff ff ff       	call   14000185f <__do_global_ctors>
   1400018f8:	90                   	nop
   1400018f9:	48 83 c4 20          	add    rsp,0x20
   1400018fd:	5d                   	pop    rbp
   1400018fe:	c3                   	ret
   1400018ff:	90                   	nop

0000000140001900 <_setargv>:
   140001900:	55                   	push   rbp
   140001901:	48 89 e5             	mov    rbp,rsp
   140001904:	b8 00 00 00 00       	mov    eax,0x0
   140001909:	5d                   	pop    rbp
   14000190a:	c3                   	ret
   14000190b:	90                   	nop
   14000190c:	90                   	nop
   14000190d:	90                   	nop
   14000190e:	90                   	nop
   14000190f:	90                   	nop

0000000140001910 <__dyn_tls_init>:
   140001910:	55                   	push   rbp
   140001911:	48 89 e5             	mov    rbp,rsp
   140001914:	48 83 ec 30          	sub    rsp,0x30
   140001918:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000191c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000191f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001923:	48 8b 05 06 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a06]        # 140005330 <.refptr._CRT_MT>
   14000192a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000192c:	83 f8 02             	cmp    eax,0x2
   14000192f:	74 0d                	je     14000193e <__dyn_tls_init+0x2e>
   140001931:	48 8b 05 f8 39 00 00 	mov    rax,QWORD PTR [rip+0x39f8]        # 140005330 <.refptr._CRT_MT>
   140001938:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000193e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001942:	74 1e                	je     140001962 <__dyn_tls_init+0x52>
   140001944:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001948:	75 5b                	jne    1400019a5 <__dyn_tls_init+0x95>
   14000194a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000194e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001951:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001955:	49 89 c8             	mov    r8,rcx
   140001958:	48 89 c1             	mov    rcx,rax
   14000195b:	e8 d1 11 00 00       	call   140002b31 <__mingw_TLScallback>
   140001960:	eb 43                	jmp    1400019a5 <__dyn_tls_init+0x95>
   140001962:	48 8d 05 2f 3d 00 00 	lea    rax,[rip+0x3d2f]        # 140005698 <___crt_xd_start__>
   140001969:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000196d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001972:	eb 22                	jmp    140001996 <__dyn_tls_init+0x86>
   140001974:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001978:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000197c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001980:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001983:	48 85 c0             	test   rax,rax
   140001986:	74 09                	je     140001991 <__dyn_tls_init+0x81>
   140001988:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000198c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000198f:	ff d0                	call   rax
   140001991:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001996:	48 8d 05 03 3d 00 00 	lea    rax,[rip+0x3d03]        # 1400056a0 <__xd_z>
   14000199d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   1400019a1:	75 d1                	jne    140001974 <__dyn_tls_init+0x64>
   1400019a3:	eb 01                	jmp    1400019a6 <__dyn_tls_init+0x96>
   1400019a5:	90                   	nop
   1400019a6:	48 83 c4 30          	add    rsp,0x30
   1400019aa:	5d                   	pop    rbp
   1400019ab:	c3                   	ret

00000001400019ac <__tlregdtor>:
   1400019ac:	55                   	push   rbp
   1400019ad:	48 89 e5             	mov    rbp,rsp
   1400019b0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019b4:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400019b9:	75 07                	jne    1400019c2 <__tlregdtor+0x16>
   1400019bb:	b8 00 00 00 00       	mov    eax,0x0
   1400019c0:	eb 05                	jmp    1400019c7 <__tlregdtor+0x1b>
   1400019c2:	b8 00 00 00 00       	mov    eax,0x0
   1400019c7:	5d                   	pop    rbp
   1400019c8:	c3                   	ret

00000001400019c9 <__dyn_tls_dtor>:
   1400019c9:	55                   	push   rbp
   1400019ca:	48 89 e5             	mov    rbp,rsp
   1400019cd:	48 83 ec 20          	sub    rsp,0x20
   1400019d1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019d5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019d8:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019dc:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   1400019e0:	74 06                	je     1400019e8 <__dyn_tls_dtor+0x1f>
   1400019e2:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400019e6:	75 18                	jne    140001a00 <__dyn_tls_dtor+0x37>
   1400019e8:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019ec:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019ef:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019f3:	49 89 c8             	mov    r8,rcx
   1400019f6:	48 89 c1             	mov    rcx,rax
   1400019f9:	e8 33 11 00 00       	call   140002b31 <__mingw_TLScallback>
   1400019fe:	eb 01                	jmp    140001a01 <__dyn_tls_dtor+0x38>
   140001a00:	90                   	nop
   140001a01:	48 83 c4 20          	add    rsp,0x20
   140001a05:	5d                   	pop    rbp
   140001a06:	c3                   	ret
   140001a07:	90                   	nop
   140001a08:	90                   	nop
   140001a09:	90                   	nop
   140001a0a:	90                   	nop
   140001a0b:	90                   	nop
   140001a0c:	90                   	nop
   140001a0d:	90                   	nop
   140001a0e:	90                   	nop
   140001a0f:	90                   	nop

0000000140001a10 <_matherr>:
   140001a10:	55                   	push   rbp
   140001a11:	53                   	push   rbx
   140001a12:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a19:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a1e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a22:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a26:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a2b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a2f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a33:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a35:	83 f8 06             	cmp    eax,0x6
   140001a38:	74 56                	je     140001a90 <_matherr+0x80>
   140001a3a:	83 f8 06             	cmp    eax,0x6
   140001a3d:	7f 78                	jg     140001ab7 <_matherr+0xa7>
   140001a3f:	83 f8 05             	cmp    eax,0x5
   140001a42:	74 59                	je     140001a9d <_matherr+0x8d>
   140001a44:	83 f8 05             	cmp    eax,0x5
   140001a47:	7f 6e                	jg     140001ab7 <_matherr+0xa7>
   140001a49:	83 f8 04             	cmp    eax,0x4
   140001a4c:	74 5c                	je     140001aaa <_matherr+0x9a>
   140001a4e:	83 f8 04             	cmp    eax,0x4
   140001a51:	7f 64                	jg     140001ab7 <_matherr+0xa7>
   140001a53:	83 f8 03             	cmp    eax,0x3
   140001a56:	74 2b                	je     140001a83 <_matherr+0x73>
   140001a58:	83 f8 03             	cmp    eax,0x3
   140001a5b:	7f 5a                	jg     140001ab7 <_matherr+0xa7>
   140001a5d:	83 f8 01             	cmp    eax,0x1
   140001a60:	74 07                	je     140001a69 <_matherr+0x59>
   140001a62:	83 f8 02             	cmp    eax,0x2
   140001a65:	74 0f                	je     140001a76 <_matherr+0x66>
   140001a67:	eb 4e                	jmp    140001ab7 <_matherr+0xa7>
   140001a69:	48 8d 05 30 36 00 00 	lea    rax,[rip+0x3630]        # 1400050a0 <.rdata>
   140001a70:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a74:	eb 4d                	jmp    140001ac3 <_matherr+0xb3>
   140001a76:	48 8d 05 42 36 00 00 	lea    rax,[rip+0x3642]        # 1400050bf <.rdata+0x1f>
   140001a7d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a81:	eb 40                	jmp    140001ac3 <_matherr+0xb3>
   140001a83:	48 8d 05 56 36 00 00 	lea    rax,[rip+0x3656]        # 1400050e0 <.rdata+0x40>
   140001a8a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a8e:	eb 33                	jmp    140001ac3 <_matherr+0xb3>
   140001a90:	48 8d 05 69 36 00 00 	lea    rax,[rip+0x3669]        # 140005100 <.rdata+0x60>
   140001a97:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a9b:	eb 26                	jmp    140001ac3 <_matherr+0xb3>
   140001a9d:	48 8d 05 84 36 00 00 	lea    rax,[rip+0x3684]        # 140005128 <.rdata+0x88>
   140001aa4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001aa8:	eb 19                	jmp    140001ac3 <_matherr+0xb3>
   140001aaa:	48 8d 05 9f 36 00 00 	lea    rax,[rip+0x369f]        # 140005150 <.rdata+0xb0>
   140001ab1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ab5:	eb 0c                	jmp    140001ac3 <_matherr+0xb3>
   140001ab7:	48 8d 05 c8 36 00 00 	lea    rax,[rip+0x36c8]        # 140005186 <.rdata+0xe6>
   140001abe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ac2:	90                   	nop
   140001ac3:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ac7:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001acd:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ad1:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001ad6:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ada:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001adf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ae3:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001ae7:	b9 02 00 00 00       	mov    ecx,0x2
   140001aec:	e8 2f 17 00 00       	call   140003220 <__acrt_iob_func>
   140001af1:	48 89 c1             	mov    rcx,rax
   140001af4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001af8:	48 8d 05 99 36 00 00 	lea    rax,[rip+0x3699]        # 140005198 <.rdata+0xf8>
   140001aff:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b06:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b0c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b12:	49 89 d9             	mov    r9,rbx
   140001b15:	49 89 d0             	mov    r8,rdx
   140001b18:	48 89 c2             	mov    rdx,rax
   140001b1b:	e8 a0 17 00 00       	call   1400032c0 <fprintf>
   140001b20:	b8 00 00 00 00       	mov    eax,0x0
   140001b25:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b29:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b2d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b32:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b39:	5b                   	pop    rbx
   140001b3a:	5d                   	pop    rbp
   140001b3b:	c3                   	ret
   140001b3c:	90                   	nop
   140001b3d:	90                   	nop
   140001b3e:	90                   	nop
   140001b3f:	90                   	nop

0000000140001b40 <__report_error>:
   140001b40:	55                   	push   rbp
   140001b41:	53                   	push   rbx
   140001b42:	48 83 ec 38          	sub    rsp,0x38
   140001b46:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b4b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b4f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b53:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b57:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b5b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b5f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b63:	b9 02 00 00 00       	mov    ecx,0x2
   140001b68:	e8 b3 16 00 00       	call   140003220 <__acrt_iob_func>
   140001b6d:	48 89 c1             	mov    rcx,rax
   140001b70:	48 8d 05 59 36 00 00 	lea    rax,[rip+0x3659]        # 1400051d0 <.rdata>
   140001b77:	48 89 c2             	mov    rdx,rax
   140001b7a:	e8 41 17 00 00       	call   1400032c0 <fprintf>
   140001b7f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b83:	b9 02 00 00 00       	mov    ecx,0x2
   140001b88:	e8 93 16 00 00       	call   140003220 <__acrt_iob_func>
   140001b8d:	48 89 c1             	mov    rcx,rax
   140001b90:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b94:	49 89 d8             	mov    r8,rbx
   140001b97:	48 89 c2             	mov    rdx,rax
   140001b9a:	e8 69 17 00 00       	call   140003308 <vfprintf>
   140001b9f:	e8 f4 16 00 00       	call   140003298 <abort>
   140001ba4:	90                   	nop

0000000140001ba5 <mark_section_writable>:
   140001ba5:	55                   	push   rbp
   140001ba6:	48 89 e5             	mov    rbp,rsp
   140001ba9:	48 83 ec 60          	sub    rsp,0x60
   140001bad:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001bb1:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001bb8:	e9 82 00 00 00       	jmp    140001c3f <mark_section_writable+0x9a>
   140001bbd:	48 8b 0d 1c 75 00 00 	mov    rcx,QWORD PTR [rip+0x751c]        # 1400090e0 <the_secs>
   140001bc4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bc7:	48 63 d0             	movsxd rdx,eax
   140001bca:	48 89 d0             	mov    rax,rdx
   140001bcd:	48 c1 e0 02          	shl    rax,0x2
   140001bd1:	48 01 d0             	add    rax,rdx
   140001bd4:	48 c1 e0 03          	shl    rax,0x3
   140001bd8:	48 01 c8             	add    rax,rcx
   140001bdb:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001bdf:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001be3:	72 56                	jb     140001c3b <mark_section_writable+0x96>
   140001be5:	48 8b 0d f4 74 00 00 	mov    rcx,QWORD PTR [rip+0x74f4]        # 1400090e0 <the_secs>
   140001bec:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bef:	48 63 d0             	movsxd rdx,eax
   140001bf2:	48 89 d0             	mov    rax,rdx
   140001bf5:	48 c1 e0 02          	shl    rax,0x2
   140001bf9:	48 01 d0             	add    rax,rdx
   140001bfc:	48 c1 e0 03          	shl    rax,0x3
   140001c00:	48 01 c8             	add    rax,rcx
   140001c03:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c07:	4c 8b 05 d2 74 00 00 	mov    r8,QWORD PTR [rip+0x74d2]        # 1400090e0 <the_secs>
   140001c0e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c11:	48 63 d0             	movsxd rdx,eax
   140001c14:	48 89 d0             	mov    rax,rdx
   140001c17:	48 c1 e0 02          	shl    rax,0x2
   140001c1b:	48 01 d0             	add    rax,rdx
   140001c1e:	48 c1 e0 03          	shl    rax,0x3
   140001c22:	4c 01 c0             	add    rax,r8
   140001c25:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c29:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c2c:	89 c0                	mov    eax,eax
   140001c2e:	48 01 c8             	add    rax,rcx
   140001c31:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c35:	0f 82 41 02 00 00    	jb     140001e7c <mark_section_writable+0x2d7>
   140001c3b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c3f:	8b 05 a3 74 00 00    	mov    eax,DWORD PTR [rip+0x74a3]        # 1400090e8 <maxSections>
   140001c45:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c48:	0f 8c 6f ff ff ff    	jl     140001bbd <mark_section_writable+0x18>
   140001c4e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c52:	48 89 c1             	mov    rcx,rax
   140001c55:	e8 c1 11 00 00       	call   140002e1b <__mingw_GetSectionForAddress>
   140001c5a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c5e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c63:	75 13                	jne    140001c78 <mark_section_writable+0xd3>
   140001c65:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c69:	48 8d 0d 80 35 00 00 	lea    rcx,[rip+0x3580]        # 1400051f0 <.rdata+0x20>
   140001c70:	48 89 c2             	mov    rdx,rax
   140001c73:	e8 c8 fe ff ff       	call   140001b40 <__report_error>
   140001c78:	48 8b 0d 61 74 00 00 	mov    rcx,QWORD PTR [rip+0x7461]        # 1400090e0 <the_secs>
   140001c7f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c82:	48 63 d0             	movsxd rdx,eax
   140001c85:	48 89 d0             	mov    rax,rdx
   140001c88:	48 c1 e0 02          	shl    rax,0x2
   140001c8c:	48 01 d0             	add    rax,rdx
   140001c8f:	48 c1 e0 03          	shl    rax,0x3
   140001c93:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c97:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c9b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c9f:	48 8b 0d 3a 74 00 00 	mov    rcx,QWORD PTR [rip+0x743a]        # 1400090e0 <the_secs>
   140001ca6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ca9:	48 63 d0             	movsxd rdx,eax
   140001cac:	48 89 d0             	mov    rax,rdx
   140001caf:	48 c1 e0 02          	shl    rax,0x2
   140001cb3:	48 01 d0             	add    rax,rdx
   140001cb6:	48 c1 e0 03          	shl    rax,0x3
   140001cba:	48 01 c8             	add    rax,rcx
   140001cbd:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001cc3:	e8 9f 12 00 00       	call   140002f67 <_GetPEImageBase>
   140001cc8:	48 89 c1             	mov    rcx,rax
   140001ccb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001ccf:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001cd2:	41 89 c1             	mov    r9d,eax
   140001cd5:	4c 8b 05 04 74 00 00 	mov    r8,QWORD PTR [rip+0x7404]        # 1400090e0 <the_secs>
   140001cdc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cdf:	48 63 d0             	movsxd rdx,eax
   140001ce2:	48 89 d0             	mov    rax,rdx
   140001ce5:	48 c1 e0 02          	shl    rax,0x2
   140001ce9:	48 01 d0             	add    rax,rdx
   140001cec:	48 c1 e0 03          	shl    rax,0x3
   140001cf0:	4c 01 c0             	add    rax,r8
   140001cf3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001cf7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001cfb:	48 8b 0d de 73 00 00 	mov    rcx,QWORD PTR [rip+0x73de]        # 1400090e0 <the_secs>
   140001d02:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d05:	48 63 d0             	movsxd rdx,eax
   140001d08:	48 89 d0             	mov    rax,rdx
   140001d0b:	48 c1 e0 02          	shl    rax,0x2
   140001d0f:	48 01 d0             	add    rax,rdx
   140001d12:	48 c1 e0 03          	shl    rax,0x3
   140001d16:	48 01 c8             	add    rax,rcx
   140001d19:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d1d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d21:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d27:	48 89 c1             	mov    rcx,rax
   140001d2a:	48 8b 05 cf 84 00 00 	mov    rax,QWORD PTR [rip+0x84cf]        # 14000a200 <__imp_VirtualQuery>
   140001d31:	ff d0                	call   rax
   140001d33:	48 85 c0             	test   rax,rax
   140001d36:	75 3f                	jne    140001d77 <mark_section_writable+0x1d2>
   140001d38:	48 8b 0d a1 73 00 00 	mov    rcx,QWORD PTR [rip+0x73a1]        # 1400090e0 <the_secs>
   140001d3f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d42:	48 63 d0             	movsxd rdx,eax
   140001d45:	48 89 d0             	mov    rax,rdx
   140001d48:	48 c1 e0 02          	shl    rax,0x2
   140001d4c:	48 01 d0             	add    rax,rdx
   140001d4f:	48 c1 e0 03          	shl    rax,0x3
   140001d53:	48 01 c8             	add    rax,rcx
   140001d56:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d5e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d61:	89 c1                	mov    ecx,eax
   140001d63:	48 8d 05 a6 34 00 00 	lea    rax,[rip+0x34a6]        # 140005210 <.rdata+0x40>
   140001d6a:	49 89 d0             	mov    r8,rdx
   140001d6d:	89 ca                	mov    edx,ecx
   140001d6f:	48 89 c1             	mov    rcx,rax
   140001d72:	e8 c9 fd ff ff       	call   140001b40 <__report_error>
   140001d77:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d7a:	83 f8 40             	cmp    eax,0x40
   140001d7d:	0f 84 e8 00 00 00    	je     140001e6b <mark_section_writable+0x2c6>
   140001d83:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d86:	83 f8 04             	cmp    eax,0x4
   140001d89:	0f 84 dc 00 00 00    	je     140001e6b <mark_section_writable+0x2c6>
   140001d8f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d92:	3d 80 00 00 00       	cmp    eax,0x80
   140001d97:	0f 84 ce 00 00 00    	je     140001e6b <mark_section_writable+0x2c6>
   140001d9d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001da0:	83 f8 08             	cmp    eax,0x8
   140001da3:	0f 84 c2 00 00 00    	je     140001e6b <mark_section_writable+0x2c6>
   140001da9:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dac:	83 f8 02             	cmp    eax,0x2
   140001daf:	75 09                	jne    140001dba <mark_section_writable+0x215>
   140001db1:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001db8:	eb 07                	jmp    140001dc1 <mark_section_writable+0x21c>
   140001dba:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001dc1:	48 8b 0d 18 73 00 00 	mov    rcx,QWORD PTR [rip+0x7318]        # 1400090e0 <the_secs>
   140001dc8:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dcb:	48 63 d0             	movsxd rdx,eax
   140001dce:	48 89 d0             	mov    rax,rdx
   140001dd1:	48 c1 e0 02          	shl    rax,0x2
   140001dd5:	48 01 d0             	add    rax,rdx
   140001dd8:	48 c1 e0 03          	shl    rax,0x3
   140001ddc:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001de0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001de4:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001de8:	48 8b 0d f1 72 00 00 	mov    rcx,QWORD PTR [rip+0x72f1]        # 1400090e0 <the_secs>
   140001def:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001df2:	48 63 d0             	movsxd rdx,eax
   140001df5:	48 89 d0             	mov    rax,rdx
   140001df8:	48 c1 e0 02          	shl    rax,0x2
   140001dfc:	48 01 d0             	add    rax,rdx
   140001dff:	48 c1 e0 03          	shl    rax,0x3
   140001e03:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e07:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e0b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e0f:	48 8b 0d ca 72 00 00 	mov    rcx,QWORD PTR [rip+0x72ca]        # 1400090e0 <the_secs>
   140001e16:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e19:	48 63 d0             	movsxd rdx,eax
   140001e1c:	48 89 d0             	mov    rax,rdx
   140001e1f:	48 c1 e0 02          	shl    rax,0x2
   140001e23:	48 01 d0             	add    rax,rdx
   140001e26:	48 c1 e0 03          	shl    rax,0x3
   140001e2a:	48 01 c8             	add    rax,rcx
   140001e2d:	49 89 c0             	mov    r8,rax
   140001e30:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e34:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e38:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e3b:	4d 89 c1             	mov    r9,r8
   140001e3e:	41 89 c8             	mov    r8d,ecx
   140001e41:	48 89 c1             	mov    rcx,rax
   140001e44:	48 8b 05 ad 83 00 00 	mov    rax,QWORD PTR [rip+0x83ad]        # 14000a1f8 <__imp_VirtualProtect>
   140001e4b:	ff d0                	call   rax
   140001e4d:	85 c0                	test   eax,eax
   140001e4f:	75 1a                	jne    140001e6b <mark_section_writable+0x2c6>
   140001e51:	48 8b 05 58 83 00 00 	mov    rax,QWORD PTR [rip+0x8358]        # 14000a1b0 <__imp_GetLastError>
   140001e58:	ff d0                	call   rax
   140001e5a:	89 c2                	mov    edx,eax
   140001e5c:	48 8d 05 e5 33 00 00 	lea    rax,[rip+0x33e5]        # 140005248 <.rdata+0x78>
   140001e63:	48 89 c1             	mov    rcx,rax
   140001e66:	e8 d5 fc ff ff       	call   140001b40 <__report_error>
   140001e6b:	8b 05 77 72 00 00    	mov    eax,DWORD PTR [rip+0x7277]        # 1400090e8 <maxSections>
   140001e71:	83 c0 01             	add    eax,0x1
   140001e74:	89 05 6e 72 00 00    	mov    DWORD PTR [rip+0x726e],eax        # 1400090e8 <maxSections>
   140001e7a:	eb 01                	jmp    140001e7d <mark_section_writable+0x2d8>
   140001e7c:	90                   	nop
   140001e7d:	48 83 c4 60          	add    rsp,0x60
   140001e81:	5d                   	pop    rbp
   140001e82:	c3                   	ret

0000000140001e83 <restore_modified_sections>:
   140001e83:	55                   	push   rbp
   140001e84:	48 89 e5             	mov    rbp,rsp
   140001e87:	48 83 ec 30          	sub    rsp,0x30
   140001e8b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e92:	e9 ad 00 00 00       	jmp    140001f44 <restore_modified_sections+0xc1>
   140001e97:	48 8b 0d 42 72 00 00 	mov    rcx,QWORD PTR [rip+0x7242]        # 1400090e0 <the_secs>
   140001e9e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ea1:	48 63 d0             	movsxd rdx,eax
   140001ea4:	48 89 d0             	mov    rax,rdx
   140001ea7:	48 c1 e0 02          	shl    rax,0x2
   140001eab:	48 01 d0             	add    rax,rdx
   140001eae:	48 c1 e0 03          	shl    rax,0x3
   140001eb2:	48 01 c8             	add    rax,rcx
   140001eb5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001eb7:	85 c0                	test   eax,eax
   140001eb9:	0f 84 80 00 00 00    	je     140001f3f <restore_modified_sections+0xbc>
   140001ebf:	48 8b 0d 1a 72 00 00 	mov    rcx,QWORD PTR [rip+0x721a]        # 1400090e0 <the_secs>
   140001ec6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ec9:	48 63 d0             	movsxd rdx,eax
   140001ecc:	48 89 d0             	mov    rax,rdx
   140001ecf:	48 c1 e0 02          	shl    rax,0x2
   140001ed3:	48 01 d0             	add    rax,rdx
   140001ed6:	48 c1 e0 03          	shl    rax,0x3
   140001eda:	48 01 c8             	add    rax,rcx
   140001edd:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001ee0:	48 8b 0d f9 71 00 00 	mov    rcx,QWORD PTR [rip+0x71f9]        # 1400090e0 <the_secs>
   140001ee7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eea:	48 63 d0             	movsxd rdx,eax
   140001eed:	48 89 d0             	mov    rax,rdx
   140001ef0:	48 c1 e0 02          	shl    rax,0x2
   140001ef4:	48 01 d0             	add    rax,rdx
   140001ef7:	48 c1 e0 03          	shl    rax,0x3
   140001efb:	48 01 c8             	add    rax,rcx
   140001efe:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f02:	4c 8b 05 d7 71 00 00 	mov    r8,QWORD PTR [rip+0x71d7]        # 1400090e0 <the_secs>
   140001f09:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f0c:	48 63 d0             	movsxd rdx,eax
   140001f0f:	48 89 d0             	mov    rax,rdx
   140001f12:	48 c1 e0 02          	shl    rax,0x2
   140001f16:	48 01 d0             	add    rax,rdx
   140001f19:	48 c1 e0 03          	shl    rax,0x3
   140001f1d:	4c 01 c0             	add    rax,r8
   140001f20:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f24:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f28:	49 89 d1             	mov    r9,rdx
   140001f2b:	45 89 d0             	mov    r8d,r10d
   140001f2e:	48 89 ca             	mov    rdx,rcx
   140001f31:	48 89 c1             	mov    rcx,rax
   140001f34:	48 8b 05 bd 82 00 00 	mov    rax,QWORD PTR [rip+0x82bd]        # 14000a1f8 <__imp_VirtualProtect>
   140001f3b:	ff d0                	call   rax
   140001f3d:	eb 01                	jmp    140001f40 <restore_modified_sections+0xbd>
   140001f3f:	90                   	nop
   140001f40:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f44:	8b 05 9e 71 00 00    	mov    eax,DWORD PTR [rip+0x719e]        # 1400090e8 <maxSections>
   140001f4a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f4d:	0f 8c 44 ff ff ff    	jl     140001e97 <restore_modified_sections+0x14>
   140001f53:	90                   	nop
   140001f54:	90                   	nop
   140001f55:	48 83 c4 30          	add    rsp,0x30
   140001f59:	5d                   	pop    rbp
   140001f5a:	c3                   	ret

0000000140001f5b <__write_memory>:
   140001f5b:	55                   	push   rbp
   140001f5c:	48 89 e5             	mov    rbp,rsp
   140001f5f:	48 83 ec 20          	sub    rsp,0x20
   140001f63:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f67:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f6b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f6f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f74:	74 25                	je     140001f9b <__write_memory+0x40>
   140001f76:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f7a:	48 89 c1             	mov    rcx,rax
   140001f7d:	e8 23 fc ff ff       	call   140001ba5 <mark_section_writable>
   140001f82:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f86:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f8a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f8e:	49 89 c8             	mov    r8,rcx
   140001f91:	48 89 c1             	mov    rcx,rax
   140001f94:	e8 3f 13 00 00       	call   1400032d8 <memcpy>
   140001f99:	eb 01                	jmp    140001f9c <__write_memory+0x41>
   140001f9b:	90                   	nop
   140001f9c:	48 83 c4 20          	add    rsp,0x20
   140001fa0:	5d                   	pop    rbp
   140001fa1:	c3                   	ret

0000000140001fa2 <do_pseudo_reloc>:
   140001fa2:	55                   	push   rbp
   140001fa3:	48 89 e5             	mov    rbp,rsp
   140001fa6:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001faa:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fae:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001fb2:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001fb6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001fba:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001fbe:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001fc2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fc6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001fca:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001fcf:	0f 8e 44 03 00 00    	jle    140002319 <do_pseudo_reloc+0x377>
   140001fd5:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001fda:	7e 25                	jle    140002001 <do_pseudo_reloc+0x5f>
   140001fdc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fe0:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fe2:	85 c0                	test   eax,eax
   140001fe4:	75 1b                	jne    140002001 <do_pseudo_reloc+0x5f>
   140001fe6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fea:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fed:	85 c0                	test   eax,eax
   140001fef:	75 10                	jne    140002001 <do_pseudo_reloc+0x5f>
   140001ff1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001ff5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001ff8:	85 c0                	test   eax,eax
   140001ffa:	75 05                	jne    140002001 <do_pseudo_reloc+0x5f>
   140001ffc:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002001:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002005:	8b 00                	mov    eax,DWORD PTR [rax]
   140002007:	85 c0                	test   eax,eax
   140002009:	75 0b                	jne    140002016 <do_pseudo_reloc+0x74>
   14000200b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000200f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002012:	85 c0                	test   eax,eax
   140002014:	74 59                	je     14000206f <do_pseudo_reloc+0xcd>
   140002016:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000201a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000201e:	eb 40                	jmp    140002060 <do_pseudo_reloc+0xbe>
   140002020:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002024:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002027:	89 c2                	mov    edx,eax
   140002029:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000202d:	48 01 d0             	add    rax,rdx
   140002030:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002034:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002038:	8b 10                	mov    edx,DWORD PTR [rax]
   14000203a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000203e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002040:	01 d0                	add    eax,edx
   140002042:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002045:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002049:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000204d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002053:	48 89 c1             	mov    rcx,rax
   140002056:	e8 00 ff ff ff       	call   140001f5b <__write_memory>
   14000205b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002060:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002064:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002068:	72 b6                	jb     140002020 <do_pseudo_reloc+0x7e>
   14000206a:	e9 ab 02 00 00       	jmp    14000231a <do_pseudo_reloc+0x378>
   14000206f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002073:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002076:	83 f8 01             	cmp    eax,0x1
   140002079:	74 18                	je     140002093 <do_pseudo_reloc+0xf1>
   14000207b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000207f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002082:	89 c2                	mov    edx,eax
   140002084:	48 8d 05 e5 31 00 00 	lea    rax,[rip+0x31e5]        # 140005270 <.rdata+0xa0>
   14000208b:	48 89 c1             	mov    rcx,rax
   14000208e:	e8 ad fa ff ff       	call   140001b40 <__report_error>
   140002093:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002097:	48 83 c0 0c          	add    rax,0xc
   14000209b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000209f:	e9 65 02 00 00       	jmp    140002309 <do_pseudo_reloc+0x367>
   1400020a4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020a8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020ab:	89 c2                	mov    edx,eax
   1400020ad:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020b1:	48 01 d0             	add    rax,rdx
   1400020b4:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020b8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020bc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020be:	89 c2                	mov    edx,eax
   1400020c0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020c4:	48 01 d0             	add    rax,rdx
   1400020c7:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020cb:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400020cf:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400020d2:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020d6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020da:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020dd:	0f b6 c0             	movzx  eax,al
   1400020e0:	83 f8 40             	cmp    eax,0x40
   1400020e3:	0f 84 b6 00 00 00    	je     14000219f <do_pseudo_reloc+0x1fd>
   1400020e9:	83 f8 40             	cmp    eax,0x40
   1400020ec:	0f 87 ba 00 00 00    	ja     1400021ac <do_pseudo_reloc+0x20a>
   1400020f2:	83 f8 20             	cmp    eax,0x20
   1400020f5:	74 77                	je     14000216e <do_pseudo_reloc+0x1cc>
   1400020f7:	83 f8 20             	cmp    eax,0x20
   1400020fa:	0f 87 ac 00 00 00    	ja     1400021ac <do_pseudo_reloc+0x20a>
   140002100:	83 f8 08             	cmp    eax,0x8
   140002103:	74 0a                	je     14000210f <do_pseudo_reloc+0x16d>
   140002105:	83 f8 10             	cmp    eax,0x10
   140002108:	74 38                	je     140002142 <do_pseudo_reloc+0x1a0>
   14000210a:	e9 9d 00 00 00       	jmp    1400021ac <do_pseudo_reloc+0x20a>
   14000210f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002113:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002116:	0f b6 c0             	movzx  eax,al
   140002119:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000211d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002121:	25 80 00 00 00       	and    eax,0x80
   140002126:	48 85 c0             	test   rax,rax
   140002129:	0f 84 9d 00 00 00    	je     1400021cc <do_pseudo_reloc+0x22a>
   14000212f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002133:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002139:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000213d:	e9 8a 00 00 00       	jmp    1400021cc <do_pseudo_reloc+0x22a>
   140002142:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002146:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002149:	0f b7 c0             	movzx  eax,ax
   14000214c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002150:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002154:	25 00 80 00 00       	and    eax,0x8000
   140002159:	48 85 c0             	test   rax,rax
   14000215c:	74 71                	je     1400021cf <do_pseudo_reloc+0x22d>
   14000215e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002162:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002168:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000216c:	eb 61                	jmp    1400021cf <do_pseudo_reloc+0x22d>
   14000216e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002172:	8b 00                	mov    eax,DWORD PTR [rax]
   140002174:	89 c0                	mov    eax,eax
   140002176:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000217a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000217e:	25 00 00 00 80       	and    eax,0x80000000
   140002183:	48 85 c0             	test   rax,rax
   140002186:	74 4a                	je     1400021d2 <do_pseudo_reloc+0x230>
   140002188:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000218c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002193:	ff ff ff 
   140002196:	48 09 d0             	or     rax,rdx
   140002199:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000219d:	eb 33                	jmp    1400021d2 <do_pseudo_reloc+0x230>
   14000219f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021a3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400021a6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021aa:	eb 27                	jmp    1400021d3 <do_pseudo_reloc+0x231>
   1400021ac:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   1400021b3:	00 
   1400021b4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021b8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021bb:	0f b6 c0             	movzx  eax,al
   1400021be:	48 8d 0d e3 30 00 00 	lea    rcx,[rip+0x30e3]        # 1400052a8 <.rdata+0xd8>
   1400021c5:	89 c2                	mov    edx,eax
   1400021c7:	e8 74 f9 ff ff       	call   140001b40 <__report_error>
   1400021cc:	90                   	nop
   1400021cd:	eb 04                	jmp    1400021d3 <do_pseudo_reloc+0x231>
   1400021cf:	90                   	nop
   1400021d0:	eb 01                	jmp    1400021d3 <do_pseudo_reloc+0x231>
   1400021d2:	90                   	nop
   1400021d3:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   1400021d7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021db:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021dd:	89 c2                	mov    edx,eax
   1400021df:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400021e3:	48 01 c2             	add    rdx,rax
   1400021e6:	48 89 c8             	mov    rax,rcx
   1400021e9:	48 29 d0             	sub    rax,rdx
   1400021ec:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021f0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021f4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400021f8:	48 01 d0             	add    rax,rdx
   1400021fb:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ff:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002203:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002206:	25 ff 00 00 00       	and    eax,0xff
   14000220b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000220e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002212:	77 67                	ja     14000227b <do_pseudo_reloc+0x2d9>
   140002214:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002217:	ba 01 00 00 00       	mov    edx,0x1
   14000221c:	89 c1                	mov    ecx,eax
   14000221e:	48 d3 e2             	shl    rdx,cl
   140002221:	48 89 d0             	mov    rax,rdx
   140002224:	48 83 e8 01          	sub    rax,0x1
   140002228:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000222c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000222f:	83 e8 01             	sub    eax,0x1
   140002232:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002239:	89 c1                	mov    ecx,eax
   14000223b:	48 d3 e2             	shl    rdx,cl
   14000223e:	48 89 d0             	mov    rax,rdx
   140002241:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002245:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002249:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000224d:	7c 0a                	jl     140002259 <do_pseudo_reloc+0x2b7>
   14000224f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002253:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002257:	7e 22                	jle    14000227b <do_pseudo_reloc+0x2d9>
   140002259:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000225d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002261:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002265:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002268:	48 8d 0d 69 30 00 00 	lea    rcx,[rip+0x3069]        # 1400052d8 <.rdata+0x108>
   14000226f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002274:	89 c2                	mov    edx,eax
   140002276:	e8 c5 f8 ff ff       	call   140001b40 <__report_error>
   14000227b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000227f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002282:	0f b6 c0             	movzx  eax,al
   140002285:	83 f8 40             	cmp    eax,0x40
   140002288:	74 63                	je     1400022ed <do_pseudo_reloc+0x34b>
   14000228a:	83 f8 40             	cmp    eax,0x40
   14000228d:	77 75                	ja     140002304 <do_pseudo_reloc+0x362>
   14000228f:	83 f8 20             	cmp    eax,0x20
   140002292:	74 41                	je     1400022d5 <do_pseudo_reloc+0x333>
   140002294:	83 f8 20             	cmp    eax,0x20
   140002297:	77 6b                	ja     140002304 <do_pseudo_reloc+0x362>
   140002299:	83 f8 08             	cmp    eax,0x8
   14000229c:	74 07                	je     1400022a5 <do_pseudo_reloc+0x303>
   14000229e:	83 f8 10             	cmp    eax,0x10
   1400022a1:	74 1a                	je     1400022bd <do_pseudo_reloc+0x31b>
   1400022a3:	eb 5f                	jmp    140002304 <do_pseudo_reloc+0x362>
   1400022a5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022a9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022ad:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400022b3:	48 89 c1             	mov    rcx,rax
   1400022b6:	e8 a0 fc ff ff       	call   140001f5b <__write_memory>
   1400022bb:	eb 47                	jmp    140002304 <do_pseudo_reloc+0x362>
   1400022bd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022c1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022c5:	41 b8 02 00 00 00    	mov    r8d,0x2
   1400022cb:	48 89 c1             	mov    rcx,rax
   1400022ce:	e8 88 fc ff ff       	call   140001f5b <__write_memory>
   1400022d3:	eb 2f                	jmp    140002304 <do_pseudo_reloc+0x362>
   1400022d5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022d9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022dd:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400022e3:	48 89 c1             	mov    rcx,rax
   1400022e6:	e8 70 fc ff ff       	call   140001f5b <__write_memory>
   1400022eb:	eb 17                	jmp    140002304 <do_pseudo_reloc+0x362>
   1400022ed:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022f1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022f5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400022fb:	48 89 c1             	mov    rcx,rax
   1400022fe:	e8 58 fc ff ff       	call   140001f5b <__write_memory>
   140002303:	90                   	nop
   140002304:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002309:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000230d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002311:	0f 82 8d fd ff ff    	jb     1400020a4 <do_pseudo_reloc+0x102>
   140002317:	eb 01                	jmp    14000231a <do_pseudo_reloc+0x378>
   140002319:	90                   	nop
   14000231a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000231e:	5d                   	pop    rbp
   14000231f:	c3                   	ret

0000000140002320 <_pei386_runtime_relocator>:
   140002320:	55                   	push   rbp
   140002321:	48 89 e5             	mov    rbp,rsp
   140002324:	48 83 ec 30          	sub    rsp,0x30
   140002328:	8b 05 be 6d 00 00    	mov    eax,DWORD PTR [rip+0x6dbe]        # 1400090ec <was_init.0>
   14000232e:	85 c0                	test   eax,eax
   140002330:	0f 85 88 00 00 00    	jne    1400023be <_pei386_runtime_relocator+0x9e>
   140002336:	8b 05 b0 6d 00 00    	mov    eax,DWORD PTR [rip+0x6db0]        # 1400090ec <was_init.0>
   14000233c:	83 c0 01             	add    eax,0x1
   14000233f:	89 05 a7 6d 00 00    	mov    DWORD PTR [rip+0x6da7],eax        # 1400090ec <was_init.0>
   140002345:	e8 21 0b 00 00       	call   140002e6b <__mingw_GetSectionCount>
   14000234a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000234d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002350:	48 63 d0             	movsxd rdx,eax
   140002353:	48 89 d0             	mov    rax,rdx
   140002356:	48 c1 e0 02          	shl    rax,0x2
   14000235a:	48 01 d0             	add    rax,rdx
   14000235d:	48 c1 e0 03          	shl    rax,0x3
   140002361:	48 83 c0 0f          	add    rax,0xf
   140002365:	48 c1 e8 04          	shr    rax,0x4
   140002369:	48 c1 e0 04          	shl    rax,0x4
   14000236d:	e8 7e 0d 00 00       	call   1400030f0 <___chkstk_ms>
   140002372:	48 29 c4             	sub    rsp,rax
   140002375:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000237a:	48 83 c0 0f          	add    rax,0xf
   14000237e:	48 c1 e8 04          	shr    rax,0x4
   140002382:	48 c1 e0 04          	shl    rax,0x4
   140002386:	48 89 05 53 6d 00 00 	mov    QWORD PTR [rip+0x6d53],rax        # 1400090e0 <the_secs>
   14000238d:	c7 05 51 6d 00 00 00 	mov    DWORD PTR [rip+0x6d51],0x0        # 1400090e8 <maxSections>
   140002394:	00 00 00 
   140002397:	48 8b 0d c2 2f 00 00 	mov    rcx,QWORD PTR [rip+0x2fc2]        # 140005360 <.refptr.__ImageBase>
   14000239e:	48 8b 15 cb 2f 00 00 	mov    rdx,QWORD PTR [rip+0x2fcb]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   1400023a5:	48 8b 05 d4 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd4]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   1400023ac:	49 89 c8             	mov    r8,rcx
   1400023af:	48 89 c1             	mov    rcx,rax
   1400023b2:	e8 eb fb ff ff       	call   140001fa2 <do_pseudo_reloc>
   1400023b7:	e8 c7 fa ff ff       	call   140001e83 <restore_modified_sections>
   1400023bc:	eb 01                	jmp    1400023bf <_pei386_runtime_relocator+0x9f>
   1400023be:	90                   	nop
   1400023bf:	48 89 ec             	mov    rsp,rbp
   1400023c2:	5d                   	pop    rbp
   1400023c3:	c3                   	ret
   1400023c4:	90                   	nop
   1400023c5:	90                   	nop
   1400023c6:	90                   	nop
   1400023c7:	90                   	nop
   1400023c8:	90                   	nop
   1400023c9:	90                   	nop
   1400023ca:	90                   	nop
   1400023cb:	90                   	nop
   1400023cc:	90                   	nop
   1400023cd:	90                   	nop
   1400023ce:	90                   	nop
   1400023cf:	90                   	nop

00000001400023d0 <__mingw_raise_matherr>:
   1400023d0:	55                   	push   rbp
   1400023d1:	48 89 e5             	mov    rbp,rsp
   1400023d4:	48 83 ec 50          	sub    rsp,0x50
   1400023d8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400023db:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400023df:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   1400023e4:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   1400023e9:	48 8b 05 00 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d00]        # 1400090f0 <stUserMathErr>
   1400023f0:	48 85 c0             	test   rax,rax
   1400023f3:	74 3e                	je     140002433 <__mingw_raise_matherr+0x63>
   1400023f5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400023f8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400023fb:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400023ff:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002403:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002408:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000240d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002412:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002417:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000241c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002421:	48 8b 15 c8 6c 00 00 	mov    rdx,QWORD PTR [rip+0x6cc8]        # 1400090f0 <stUserMathErr>
   140002428:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000242c:	48 89 c1             	mov    rcx,rax
   14000242f:	ff d2                	call   rdx
   140002431:	eb 01                	jmp    140002434 <__mingw_raise_matherr+0x64>
   140002433:	90                   	nop
   140002434:	48 83 c4 50          	add    rsp,0x50
   140002438:	5d                   	pop    rbp
   140002439:	c3                   	ret

000000014000243a <__mingw_setusermatherr>:
   14000243a:	55                   	push   rbp
   14000243b:	48 89 e5             	mov    rbp,rsp
   14000243e:	48 83 ec 20          	sub    rsp,0x20
   140002442:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002446:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000244a:	48 89 05 9f 6c 00 00 	mov    QWORD PTR [rip+0x6c9f],rax        # 1400090f0 <stUserMathErr>
   140002451:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002455:	48 89 c1             	mov    rcx,rax
   140002458:	e8 13 0e 00 00       	call   140003270 <__setusermatherr>
   14000245d:	90                   	nop
   14000245e:	48 83 c4 20          	add    rsp,0x20
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

0000000140002470 <__mingw_SEH_error_handler>:
   140002470:	55                   	push   rbp
   140002471:	48 89 e5             	mov    rbp,rsp
   140002474:	48 83 ec 30          	sub    rsp,0x30
   140002478:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000247c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002480:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002484:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002488:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000248f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002496:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000249a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000249d:	83 e0 02             	and    eax,0x2
   1400024a0:	85 c0                	test   eax,eax
   1400024a2:	74 0a                	je     1400024ae <__mingw_SEH_error_handler+0x3e>
   1400024a4:	b8 01 00 00 00       	mov    eax,0x1
   1400024a9:	e9 16 02 00 00       	jmp    1400026c4 <__mingw_SEH_error_handler+0x254>
   1400024ae:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024b2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024b4:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400024b9:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400024be:	75 18                	jne    1400024d8 <__mingw_SEH_error_handler+0x68>
   1400024c0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024c4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024c7:	83 e0 01             	and    eax,0x1
   1400024ca:	85 c0                	test   eax,eax
   1400024cc:	75 0a                	jne    1400024d8 <__mingw_SEH_error_handler+0x68>
   1400024ce:	b8 00 00 00 00       	mov    eax,0x0
   1400024d3:	e9 ec 01 00 00       	jmp    1400026c4 <__mingw_SEH_error_handler+0x254>
   1400024d8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024dc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024de:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024e3:	0f 84 12 01 00 00    	je     1400025fb <__mingw_SEH_error_handler+0x18b>
   1400024e9:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024ee:	0f 87 c3 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   1400024f4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400024f9:	0f 87 b8 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   1400024ff:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002504:	0f 83 4c 01 00 00    	jae    140002656 <__mingw_SEH_error_handler+0x1e6>
   14000250a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000250f:	0f 84 3a 01 00 00    	je     14000264f <__mingw_SEH_error_handler+0x1df>
   140002515:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000251a:	0f 87 97 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   140002520:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002525:	0f 84 83 01 00 00    	je     1400026ae <__mingw_SEH_error_handler+0x23e>
   14000252b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002530:	0f 87 81 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   140002536:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000253b:	0f 87 76 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   140002541:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002546:	0f 83 03 01 00 00    	jae    14000264f <__mingw_SEH_error_handler+0x1df>
   14000254c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002551:	0f 84 57 01 00 00    	je     1400026ae <__mingw_SEH_error_handler+0x23e>
   140002557:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000255c:	0f 87 55 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   140002562:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002567:	0f 84 8e 00 00 00    	je     1400025fb <__mingw_SEH_error_handler+0x18b>
   14000256d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002572:	0f 87 3f 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   140002578:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000257d:	0f 84 2b 01 00 00    	je     1400026ae <__mingw_SEH_error_handler+0x23e>
   140002583:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002588:	0f 87 29 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   14000258e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002593:	0f 84 15 01 00 00    	je     1400026ae <__mingw_SEH_error_handler+0x23e>
   140002599:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000259e:	0f 85 13 01 00 00    	jne    1400026b7 <__mingw_SEH_error_handler+0x247>
   1400025a4:	ba 00 00 00 00       	mov    edx,0x0
   1400025a9:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025ae:	e8 3d 0d 00 00       	call   1400032f0 <signal>
   1400025b3:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025b7:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025bc:	75 1b                	jne    1400025d9 <__mingw_SEH_error_handler+0x169>
   1400025be:	ba 01 00 00 00       	mov    edx,0x1
   1400025c3:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025c8:	e8 23 0d 00 00       	call   1400032f0 <signal>
   1400025cd:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025d4:	e9 e1 00 00 00       	jmp    1400026ba <__mingw_SEH_error_handler+0x24a>
   1400025d9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025de:	0f 84 d6 00 00 00    	je     1400026ba <__mingw_SEH_error_handler+0x24a>
   1400025e4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025e8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025ed:	ff d0                	call   rax
   1400025ef:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025f6:	e9 bf 00 00 00       	jmp    1400026ba <__mingw_SEH_error_handler+0x24a>
   1400025fb:	ba 00 00 00 00       	mov    edx,0x0
   140002600:	b9 04 00 00 00       	mov    ecx,0x4
   140002605:	e8 e6 0c 00 00       	call   1400032f0 <signal>
   14000260a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000260e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002613:	75 1b                	jne    140002630 <__mingw_SEH_error_handler+0x1c0>
   140002615:	ba 01 00 00 00       	mov    edx,0x1
   14000261a:	b9 04 00 00 00       	mov    ecx,0x4
   14000261f:	e8 cc 0c 00 00       	call   1400032f0 <signal>
   140002624:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000262b:	e9 8d 00 00 00       	jmp    1400026bd <__mingw_SEH_error_handler+0x24d>
   140002630:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002635:	0f 84 82 00 00 00    	je     1400026bd <__mingw_SEH_error_handler+0x24d>
   14000263b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000263f:	b9 04 00 00 00       	mov    ecx,0x4
   140002644:	ff d0                	call   rax
   140002646:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000264d:	eb 6e                	jmp    1400026bd <__mingw_SEH_error_handler+0x24d>
   14000264f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002656:	ba 00 00 00 00       	mov    edx,0x0
   14000265b:	b9 08 00 00 00       	mov    ecx,0x8
   140002660:	e8 8b 0c 00 00       	call   1400032f0 <signal>
   140002665:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002669:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000266e:	75 23                	jne    140002693 <__mingw_SEH_error_handler+0x223>
   140002670:	ba 01 00 00 00       	mov    edx,0x1
   140002675:	b9 08 00 00 00       	mov    ecx,0x8
   14000267a:	e8 71 0c 00 00       	call   1400032f0 <signal>
   14000267f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002683:	74 05                	je     14000268a <__mingw_SEH_error_handler+0x21a>
   140002685:	e8 a6 05 00 00       	call   140002c30 <_fpreset>
   14000268a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002691:	eb 2d                	jmp    1400026c0 <__mingw_SEH_error_handler+0x250>
   140002693:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002698:	74 26                	je     1400026c0 <__mingw_SEH_error_handler+0x250>
   14000269a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000269e:	b9 08 00 00 00       	mov    ecx,0x8
   1400026a3:	ff d0                	call   rax
   1400026a5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026ac:	eb 12                	jmp    1400026c0 <__mingw_SEH_error_handler+0x250>
   1400026ae:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026b5:	eb 0a                	jmp    1400026c1 <__mingw_SEH_error_handler+0x251>
   1400026b7:	90                   	nop
   1400026b8:	eb 07                	jmp    1400026c1 <__mingw_SEH_error_handler+0x251>
   1400026ba:	90                   	nop
   1400026bb:	eb 04                	jmp    1400026c1 <__mingw_SEH_error_handler+0x251>
   1400026bd:	90                   	nop
   1400026be:	eb 01                	jmp    1400026c1 <__mingw_SEH_error_handler+0x251>
   1400026c0:	90                   	nop
   1400026c1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400026c4:	48 83 c4 30          	add    rsp,0x30
   1400026c8:	5d                   	pop    rbp
   1400026c9:	c3                   	ret

00000001400026ca <_gnu_exception_handler>:
   1400026ca:	55                   	push   rbp
   1400026cb:	48 89 e5             	mov    rbp,rsp
   1400026ce:	48 83 ec 30          	sub    rsp,0x30
   1400026d2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400026d6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026dd:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400026e4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026e8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026ed:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400026f2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400026f7:	75 1b                	jne    140002714 <_gnu_exception_handler+0x4a>
   1400026f9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026fd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002700:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002703:	83 e0 01             	and    eax,0x1
   140002706:	85 c0                	test   eax,eax
   140002708:	75 0a                	jne    140002714 <_gnu_exception_handler+0x4a>
   14000270a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000270f:	e9 14 02 00 00       	jmp    140002928 <_gnu_exception_handler+0x25e>
   140002714:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002718:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000271b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000271d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002722:	0f 84 12 01 00 00    	je     14000283a <_gnu_exception_handler+0x170>
   140002728:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000272d:	0f 87 c3 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   140002733:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002738:	0f 87 b8 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   14000273e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002743:	0f 83 4c 01 00 00    	jae    140002895 <_gnu_exception_handler+0x1cb>
   140002749:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000274e:	0f 84 3a 01 00 00    	je     14000288e <_gnu_exception_handler+0x1c4>
   140002754:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002759:	0f 87 97 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   14000275f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002764:	0f 84 83 01 00 00    	je     1400028ed <_gnu_exception_handler+0x223>
   14000276a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000276f:	0f 87 81 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   140002775:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000277a:	0f 87 76 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   140002780:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002785:	0f 83 03 01 00 00    	jae    14000288e <_gnu_exception_handler+0x1c4>
   14000278b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002790:	0f 84 57 01 00 00    	je     1400028ed <_gnu_exception_handler+0x223>
   140002796:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000279b:	0f 87 55 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   1400027a1:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027a6:	0f 84 8e 00 00 00    	je     14000283a <_gnu_exception_handler+0x170>
   1400027ac:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027b1:	0f 87 3f 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   1400027b7:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027bc:	0f 84 2b 01 00 00    	je     1400028ed <_gnu_exception_handler+0x223>
   1400027c2:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027c7:	0f 87 29 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   1400027cd:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400027d2:	0f 84 15 01 00 00    	je     1400028ed <_gnu_exception_handler+0x223>
   1400027d8:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400027dd:	0f 85 13 01 00 00    	jne    1400028f6 <_gnu_exception_handler+0x22c>
   1400027e3:	ba 00 00 00 00       	mov    edx,0x0
   1400027e8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027ed:	e8 fe 0a 00 00       	call   1400032f0 <signal>
   1400027f2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027f6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027fb:	75 1b                	jne    140002818 <_gnu_exception_handler+0x14e>
   1400027fd:	ba 01 00 00 00       	mov    edx,0x1
   140002802:	b9 0b 00 00 00       	mov    ecx,0xb
   140002807:	e8 e4 0a 00 00       	call   1400032f0 <signal>
   14000280c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002813:	e9 e1 00 00 00       	jmp    1400028f9 <_gnu_exception_handler+0x22f>
   140002818:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000281d:	0f 84 d6 00 00 00    	je     1400028f9 <_gnu_exception_handler+0x22f>
   140002823:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002827:	b9 0b 00 00 00       	mov    ecx,0xb
   14000282c:	ff d0                	call   rax
   14000282e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002835:	e9 bf 00 00 00       	jmp    1400028f9 <_gnu_exception_handler+0x22f>
   14000283a:	ba 00 00 00 00       	mov    edx,0x0
   14000283f:	b9 04 00 00 00       	mov    ecx,0x4
   140002844:	e8 a7 0a 00 00       	call   1400032f0 <signal>
   140002849:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000284d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002852:	75 1b                	jne    14000286f <_gnu_exception_handler+0x1a5>
   140002854:	ba 01 00 00 00       	mov    edx,0x1
   140002859:	b9 04 00 00 00       	mov    ecx,0x4
   14000285e:	e8 8d 0a 00 00       	call   1400032f0 <signal>
   140002863:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000286a:	e9 8d 00 00 00       	jmp    1400028fc <_gnu_exception_handler+0x232>
   14000286f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002874:	0f 84 82 00 00 00    	je     1400028fc <_gnu_exception_handler+0x232>
   14000287a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000287e:	b9 04 00 00 00       	mov    ecx,0x4
   140002883:	ff d0                	call   rax
   140002885:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000288c:	eb 6e                	jmp    1400028fc <_gnu_exception_handler+0x232>
   14000288e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002895:	ba 00 00 00 00       	mov    edx,0x0
   14000289a:	b9 08 00 00 00       	mov    ecx,0x8
   14000289f:	e8 4c 0a 00 00       	call   1400032f0 <signal>
   1400028a4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028a8:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028ad:	75 23                	jne    1400028d2 <_gnu_exception_handler+0x208>
   1400028af:	ba 01 00 00 00       	mov    edx,0x1
   1400028b4:	b9 08 00 00 00       	mov    ecx,0x8
   1400028b9:	e8 32 0a 00 00       	call   1400032f0 <signal>
   1400028be:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400028c2:	74 05                	je     1400028c9 <_gnu_exception_handler+0x1ff>
   1400028c4:	e8 67 03 00 00       	call   140002c30 <_fpreset>
   1400028c9:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028d0:	eb 2d                	jmp    1400028ff <_gnu_exception_handler+0x235>
   1400028d2:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028d7:	74 26                	je     1400028ff <_gnu_exception_handler+0x235>
   1400028d9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028dd:	b9 08 00 00 00       	mov    ecx,0x8
   1400028e2:	ff d0                	call   rax
   1400028e4:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028eb:	eb 12                	jmp    1400028ff <_gnu_exception_handler+0x235>
   1400028ed:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028f4:	eb 0a                	jmp    140002900 <_gnu_exception_handler+0x236>
   1400028f6:	90                   	nop
   1400028f7:	eb 07                	jmp    140002900 <_gnu_exception_handler+0x236>
   1400028f9:	90                   	nop
   1400028fa:	eb 04                	jmp    140002900 <_gnu_exception_handler+0x236>
   1400028fc:	90                   	nop
   1400028fd:	eb 01                	jmp    140002900 <_gnu_exception_handler+0x236>
   1400028ff:	90                   	nop
   140002900:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002904:	75 1f                	jne    140002925 <_gnu_exception_handler+0x25b>
   140002906:	48 8b 05 03 68 00 00 	mov    rax,QWORD PTR [rip+0x6803]        # 140009110 <__mingw_oldexcpt_handler>
   14000290d:	48 85 c0             	test   rax,rax
   140002910:	74 13                	je     140002925 <_gnu_exception_handler+0x25b>
   140002912:	48 8b 15 f7 67 00 00 	mov    rdx,QWORD PTR [rip+0x67f7]        # 140009110 <__mingw_oldexcpt_handler>
   140002919:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000291d:	48 89 c1             	mov    rcx,rax
   140002920:	ff d2                	call   rdx
   140002922:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002925:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002928:	48 83 c4 30          	add    rsp,0x30
   14000292c:	5d                   	pop    rbp
   14000292d:	c3                   	ret
   14000292e:	90                   	nop
   14000292f:	90                   	nop

0000000140002930 <___w64_mingwthr_add_key_dtor>:
   140002930:	55                   	push   rbp
   140002931:	48 89 e5             	mov    rbp,rsp
   140002934:	48 83 ec 30          	sub    rsp,0x30
   140002938:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000293b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000293f:	8b 05 03 68 00 00    	mov    eax,DWORD PTR [rip+0x6803]        # 140009148 <__mingwthr_cs_init>
   140002945:	85 c0                	test   eax,eax
   140002947:	75 07                	jne    140002950 <___w64_mingwthr_add_key_dtor+0x20>
   140002949:	b8 00 00 00 00       	mov    eax,0x0
   14000294e:	eb 7b                	jmp    1400029cb <___w64_mingwthr_add_key_dtor+0x9b>
   140002950:	ba 18 00 00 00       	mov    edx,0x18
   140002955:	b9 01 00 00 00       	mov    ecx,0x1
   14000295a:	e8 49 09 00 00       	call   1400032a8 <calloc>
   14000295f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002963:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002968:	75 07                	jne    140002971 <___w64_mingwthr_add_key_dtor+0x41>
   14000296a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000296f:	eb 5a                	jmp    1400029cb <___w64_mingwthr_add_key_dtor+0x9b>
   140002971:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002975:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002978:	89 10                	mov    DWORD PTR [rax],edx
   14000297a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000297e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002982:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002986:	48 8d 05 93 67 00 00 	lea    rax,[rip+0x6793]        # 140009120 <__mingwthr_cs>
   14000298d:	48 89 c1             	mov    rcx,rax
   140002990:	48 8b 05 09 78 00 00 	mov    rax,QWORD PTR [rip+0x7809]        # 14000a1a0 <__imp_EnterCriticalSection>
   140002997:	ff d0                	call   rax
   140002999:	48 8b 15 b0 67 00 00 	mov    rdx,QWORD PTR [rip+0x67b0]        # 140009150 <key_dtor_list>
   1400029a0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029a4:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029a8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029ac:	48 89 05 9d 67 00 00 	mov    QWORD PTR [rip+0x679d],rax        # 140009150 <key_dtor_list>
   1400029b3:	48 8d 05 66 67 00 00 	lea    rax,[rip+0x6766]        # 140009120 <__mingwthr_cs>
   1400029ba:	48 89 c1             	mov    rcx,rax
   1400029bd:	48 8b 05 0c 78 00 00 	mov    rax,QWORD PTR [rip+0x780c]        # 14000a1d0 <__imp_LeaveCriticalSection>
   1400029c4:	ff d0                	call   rax
   1400029c6:	b8 00 00 00 00       	mov    eax,0x0
   1400029cb:	48 83 c4 30          	add    rsp,0x30
   1400029cf:	5d                   	pop    rbp
   1400029d0:	c3                   	ret

00000001400029d1 <___w64_mingwthr_remove_key_dtor>:
   1400029d1:	55                   	push   rbp
   1400029d2:	48 89 e5             	mov    rbp,rsp
   1400029d5:	48 83 ec 30          	sub    rsp,0x30
   1400029d9:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029dc:	8b 05 66 67 00 00    	mov    eax,DWORD PTR [rip+0x6766]        # 140009148 <__mingwthr_cs_init>
   1400029e2:	85 c0                	test   eax,eax
   1400029e4:	75 0a                	jne    1400029f0 <___w64_mingwthr_remove_key_dtor+0x1f>
   1400029e6:	b8 00 00 00 00       	mov    eax,0x0
   1400029eb:	e9 9c 00 00 00       	jmp    140002a8c <___w64_mingwthr_remove_key_dtor+0xbb>
   1400029f0:	48 8d 05 29 67 00 00 	lea    rax,[rip+0x6729]        # 140009120 <__mingwthr_cs>
   1400029f7:	48 89 c1             	mov    rcx,rax
   1400029fa:	48 8b 05 9f 77 00 00 	mov    rax,QWORD PTR [rip+0x779f]        # 14000a1a0 <__imp_EnterCriticalSection>
   140002a01:	ff d0                	call   rax
   140002a03:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a0a:	00 
   140002a0b:	48 8b 05 3e 67 00 00 	mov    rax,QWORD PTR [rip+0x673e]        # 140009150 <key_dtor_list>
   140002a12:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a16:	eb 55                	jmp    140002a6d <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a18:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a1c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a1e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a21:	75 36                	jne    140002a59 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a23:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a28:	75 11                	jne    140002a3b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a2e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a32:	48 89 05 17 67 00 00 	mov    QWORD PTR [rip+0x6717],rax        # 140009150 <key_dtor_list>
   140002a39:	eb 10                	jmp    140002a4b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a3b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a3f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a43:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a47:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a4b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a4f:	48 89 c1             	mov    rcx,rax
   140002a52:	e8 71 08 00 00       	call   1400032c8 <free>
   140002a57:	eb 1b                	jmp    140002a74 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a59:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a5d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a61:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a65:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a69:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a6d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a72:	75 a4                	jne    140002a18 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a74:	48 8d 05 a5 66 00 00 	lea    rax,[rip+0x66a5]        # 140009120 <__mingwthr_cs>
   140002a7b:	48 89 c1             	mov    rcx,rax
   140002a7e:	48 8b 05 4b 77 00 00 	mov    rax,QWORD PTR [rip+0x774b]        # 14000a1d0 <__imp_LeaveCriticalSection>
   140002a85:	ff d0                	call   rax
   140002a87:	b8 00 00 00 00       	mov    eax,0x0
   140002a8c:	48 83 c4 30          	add    rsp,0x30
   140002a90:	5d                   	pop    rbp
   140002a91:	c3                   	ret

0000000140002a92 <__mingwthr_run_key_dtors>:
   140002a92:	55                   	push   rbp
   140002a93:	48 89 e5             	mov    rbp,rsp
   140002a96:	48 83 ec 30          	sub    rsp,0x30
   140002a9a:	8b 05 a8 66 00 00    	mov    eax,DWORD PTR [rip+0x66a8]        # 140009148 <__mingwthr_cs_init>
   140002aa0:	85 c0                	test   eax,eax
   140002aa2:	0f 84 82 00 00 00    	je     140002b2a <__mingwthr_run_key_dtors+0x98>
   140002aa8:	48 8d 05 71 66 00 00 	lea    rax,[rip+0x6671]        # 140009120 <__mingwthr_cs>
   140002aaf:	48 89 c1             	mov    rcx,rax
   140002ab2:	48 8b 05 e7 76 00 00 	mov    rax,QWORD PTR [rip+0x76e7]        # 14000a1a0 <__imp_EnterCriticalSection>
   140002ab9:	ff d0                	call   rax
   140002abb:	48 8b 05 8e 66 00 00 	mov    rax,QWORD PTR [rip+0x668e]        # 140009150 <key_dtor_list>
   140002ac2:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ac6:	eb 46                	jmp    140002b0e <__mingwthr_run_key_dtors+0x7c>
   140002ac8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002acc:	8b 00                	mov    eax,DWORD PTR [rax]
   140002ace:	89 c1                	mov    ecx,eax
   140002ad0:	48 8b 05 19 77 00 00 	mov    rax,QWORD PTR [rip+0x7719]        # 14000a1f0 <__imp_TlsGetValue>
   140002ad7:	ff d0                	call   rax
   140002ad9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002add:	48 8b 05 cc 76 00 00 	mov    rax,QWORD PTR [rip+0x76cc]        # 14000a1b0 <__imp_GetLastError>
   140002ae4:	ff d0                	call   rax
   140002ae6:	85 c0                	test   eax,eax
   140002ae8:	75 18                	jne    140002b02 <__mingwthr_run_key_dtors+0x70>
   140002aea:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002aef:	74 11                	je     140002b02 <__mingwthr_run_key_dtors+0x70>
   140002af1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002af5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002af9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002afd:	48 89 c1             	mov    rcx,rax
   140002b00:	ff d2                	call   rdx
   140002b02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b06:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b0a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b0e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b13:	75 b3                	jne    140002ac8 <__mingwthr_run_key_dtors+0x36>
   140002b15:	48 8d 05 04 66 00 00 	lea    rax,[rip+0x6604]        # 140009120 <__mingwthr_cs>
   140002b1c:	48 89 c1             	mov    rcx,rax
   140002b1f:	48 8b 05 aa 76 00 00 	mov    rax,QWORD PTR [rip+0x76aa]        # 14000a1d0 <__imp_LeaveCriticalSection>
   140002b26:	ff d0                	call   rax
   140002b28:	eb 01                	jmp    140002b2b <__mingwthr_run_key_dtors+0x99>
   140002b2a:	90                   	nop
   140002b2b:	48 83 c4 30          	add    rsp,0x30
   140002b2f:	5d                   	pop    rbp
   140002b30:	c3                   	ret

0000000140002b31 <__mingw_TLScallback>:
   140002b31:	55                   	push   rbp
   140002b32:	48 89 e5             	mov    rbp,rsp
   140002b35:	48 83 ec 30          	sub    rsp,0x30
   140002b39:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b3d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b40:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b44:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b48:	0f 84 cc 00 00 00    	je     140002c1a <__mingw_TLScallback+0xe9>
   140002b4e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b52:	0f 87 ca 00 00 00    	ja     140002c22 <__mingw_TLScallback+0xf1>
   140002b58:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b5c:	0f 84 b1 00 00 00    	je     140002c13 <__mingw_TLScallback+0xe2>
   140002b62:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b66:	0f 87 b6 00 00 00    	ja     140002c22 <__mingw_TLScallback+0xf1>
   140002b6c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b70:	74 33                	je     140002ba5 <__mingw_TLScallback+0x74>
   140002b72:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b76:	0f 85 a6 00 00 00    	jne    140002c22 <__mingw_TLScallback+0xf1>
   140002b7c:	8b 05 c6 65 00 00    	mov    eax,DWORD PTR [rip+0x65c6]        # 140009148 <__mingwthr_cs_init>
   140002b82:	85 c0                	test   eax,eax
   140002b84:	75 13                	jne    140002b99 <__mingw_TLScallback+0x68>
   140002b86:	48 8d 05 93 65 00 00 	lea    rax,[rip+0x6593]        # 140009120 <__mingwthr_cs>
   140002b8d:	48 89 c1             	mov    rcx,rax
   140002b90:	48 8b 05 31 76 00 00 	mov    rax,QWORD PTR [rip+0x7631]        # 14000a1c8 <__imp_InitializeCriticalSection>
   140002b97:	ff d0                	call   rax
   140002b99:	c7 05 a5 65 00 00 01 	mov    DWORD PTR [rip+0x65a5],0x1        # 140009148 <__mingwthr_cs_init>
   140002ba0:	00 00 00 
   140002ba3:	eb 7d                	jmp    140002c22 <__mingw_TLScallback+0xf1>
   140002ba5:	e8 e8 fe ff ff       	call   140002a92 <__mingwthr_run_key_dtors>
   140002baa:	8b 05 98 65 00 00    	mov    eax,DWORD PTR [rip+0x6598]        # 140009148 <__mingwthr_cs_init>
   140002bb0:	83 f8 01             	cmp    eax,0x1
   140002bb3:	75 6c                	jne    140002c21 <__mingw_TLScallback+0xf0>
   140002bb5:	48 8b 05 94 65 00 00 	mov    rax,QWORD PTR [rip+0x6594]        # 140009150 <key_dtor_list>
   140002bbc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bc0:	eb 20                	jmp    140002be2 <__mingw_TLScallback+0xb1>
   140002bc2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bc6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002bca:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002bce:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bd2:	48 89 c1             	mov    rcx,rax
   140002bd5:	e8 ee 06 00 00       	call   1400032c8 <free>
   140002bda:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bde:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002be2:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002be7:	75 d9                	jne    140002bc2 <__mingw_TLScallback+0x91>
   140002be9:	48 c7 05 5c 65 00 00 	mov    QWORD PTR [rip+0x655c],0x0        # 140009150 <key_dtor_list>
   140002bf0:	00 00 00 00 
   140002bf4:	c7 05 4a 65 00 00 00 	mov    DWORD PTR [rip+0x654a],0x0        # 140009148 <__mingwthr_cs_init>
   140002bfb:	00 00 00 
   140002bfe:	48 8d 05 1b 65 00 00 	lea    rax,[rip+0x651b]        # 140009120 <__mingwthr_cs>
   140002c05:	48 89 c1             	mov    rcx,rax
   140002c08:	48 8b 05 89 75 00 00 	mov    rax,QWORD PTR [rip+0x7589]        # 14000a198 <__IAT_start__>
   140002c0f:	ff d0                	call   rax
   140002c11:	eb 0e                	jmp    140002c21 <__mingw_TLScallback+0xf0>
   140002c13:	e8 18 00 00 00       	call   140002c30 <_fpreset>
   140002c18:	eb 08                	jmp    140002c22 <__mingw_TLScallback+0xf1>
   140002c1a:	e8 73 fe ff ff       	call   140002a92 <__mingwthr_run_key_dtors>
   140002c1f:	eb 01                	jmp    140002c22 <__mingw_TLScallback+0xf1>
   140002c21:	90                   	nop
   140002c22:	b8 01 00 00 00       	mov    eax,0x1
   140002c27:	48 83 c4 30          	add    rsp,0x30
   140002c2b:	5d                   	pop    rbp
   140002c2c:	c3                   	ret
   140002c2d:	90                   	nop
   140002c2e:	90                   	nop
   140002c2f:	90                   	nop

0000000140002c30 <_fpreset>:
   140002c30:	55                   	push   rbp
   140002c31:	48 89 e5             	mov    rbp,rsp
   140002c34:	db e3                	fninit
   140002c36:	90                   	nop
   140002c37:	5d                   	pop    rbp
   140002c38:	c3                   	ret
   140002c39:	90                   	nop
   140002c3a:	90                   	nop
   140002c3b:	90                   	nop
   140002c3c:	90                   	nop
   140002c3d:	90                   	nop
   140002c3e:	90                   	nop
   140002c3f:	90                   	nop

0000000140002c40 <_ValidateImageBase>:
   140002c40:	55                   	push   rbp
   140002c41:	48 89 e5             	mov    rbp,rsp
   140002c44:	48 83 ec 20          	sub    rsp,0x20
   140002c48:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c4c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c50:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c58:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c5b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c5f:	74 07                	je     140002c68 <_ValidateImageBase+0x28>
   140002c61:	b8 00 00 00 00       	mov    eax,0x0
   140002c66:	eb 4e                	jmp    140002cb6 <_ValidateImageBase+0x76>
   140002c68:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c6c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c6f:	48 63 d0             	movsxd rdx,eax
   140002c72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c76:	48 01 d0             	add    rax,rdx
   140002c79:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c7d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c81:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c83:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c88:	74 07                	je     140002c91 <_ValidateImageBase+0x51>
   140002c8a:	b8 00 00 00 00       	mov    eax,0x0
   140002c8f:	eb 25                	jmp    140002cb6 <_ValidateImageBase+0x76>
   140002c91:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c95:	48 83 c0 18          	add    rax,0x18
   140002c99:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c9d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ca1:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002ca4:	66 3d 0b 02          	cmp    ax,0x20b
   140002ca8:	74 07                	je     140002cb1 <_ValidateImageBase+0x71>
   140002caa:	b8 00 00 00 00       	mov    eax,0x0
   140002caf:	eb 05                	jmp    140002cb6 <_ValidateImageBase+0x76>
   140002cb1:	b8 01 00 00 00       	mov    eax,0x1
   140002cb6:	48 83 c4 20          	add    rsp,0x20
   140002cba:	5d                   	pop    rbp
   140002cbb:	c3                   	ret

0000000140002cbc <_FindPESection>:
   140002cbc:	55                   	push   rbp
   140002cbd:	48 89 e5             	mov    rbp,rsp
   140002cc0:	48 83 ec 20          	sub    rsp,0x20
   140002cc4:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002cc8:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002ccc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cd0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002cd3:	48 63 d0             	movsxd rdx,eax
   140002cd6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cda:	48 01 d0             	add    rax,rdx
   140002cdd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ce1:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ce8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cec:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002cf0:	0f b7 d0             	movzx  edx,ax
   140002cf3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cf7:	48 01 d0             	add    rax,rdx
   140002cfa:	48 83 c0 18          	add    rax,0x18
   140002cfe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d02:	eb 36                	jmp    140002d3a <_FindPESection+0x7e>
   140002d04:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d08:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d0b:	89 c0                	mov    eax,eax
   140002d0d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d11:	72 1e                	jb     140002d31 <_FindPESection+0x75>
   140002d13:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d17:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d1a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d1e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d21:	01 d0                	add    eax,edx
   140002d23:	89 c0                	mov    eax,eax
   140002d25:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d29:	73 06                	jae    140002d31 <_FindPESection+0x75>
   140002d2b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d2f:	eb 1e                	jmp    140002d4f <_FindPESection+0x93>
   140002d31:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d35:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d3a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d3e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d42:	0f b7 c0             	movzx  eax,ax
   140002d45:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d48:	72 ba                	jb     140002d04 <_FindPESection+0x48>
   140002d4a:	b8 00 00 00 00       	mov    eax,0x0
   140002d4f:	48 83 c4 20          	add    rsp,0x20
   140002d53:	5d                   	pop    rbp
   140002d54:	c3                   	ret

0000000140002d55 <_FindPESectionByName>:
   140002d55:	55                   	push   rbp
   140002d56:	48 89 e5             	mov    rbp,rsp
   140002d59:	48 83 ec 40          	sub    rsp,0x40
   140002d5d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d61:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d65:	48 89 c1             	mov    rcx,rax
   140002d68:	e8 8b 05 00 00       	call   1400032f8 <strlen>
   140002d6d:	48 83 f8 08          	cmp    rax,0x8
   140002d71:	76 0a                	jbe    140002d7d <_FindPESectionByName+0x28>
   140002d73:	b8 00 00 00 00       	mov    eax,0x0
   140002d78:	e9 98 00 00 00       	jmp    140002e15 <_FindPESectionByName+0xc0>
   140002d7d:	48 8b 05 dc 25 00 00 	mov    rax,QWORD PTR [rip+0x25dc]        # 140005360 <.refptr.__ImageBase>
   140002d84:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d88:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d8c:	48 89 c1             	mov    rcx,rax
   140002d8f:	e8 ac fe ff ff       	call   140002c40 <_ValidateImageBase>
   140002d94:	85 c0                	test   eax,eax
   140002d96:	75 07                	jne    140002d9f <_FindPESectionByName+0x4a>
   140002d98:	b8 00 00 00 00       	mov    eax,0x0
   140002d9d:	eb 76                	jmp    140002e15 <_FindPESectionByName+0xc0>
   140002d9f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002da3:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002da6:	48 63 d0             	movsxd rdx,eax
   140002da9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dad:	48 01 d0             	add    rax,rdx
   140002db0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002db4:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002dbb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dbf:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002dc3:	0f b7 d0             	movzx  edx,ax
   140002dc6:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dca:	48 01 d0             	add    rax,rdx
   140002dcd:	48 83 c0 18          	add    rax,0x18
   140002dd1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002dd5:	eb 29                	jmp    140002e00 <_FindPESectionByName+0xab>
   140002dd7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ddb:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002ddf:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002de5:	48 89 c1             	mov    rcx,rax
   140002de8:	e8 13 05 00 00       	call   140003300 <strncmp>
   140002ded:	85 c0                	test   eax,eax
   140002def:	75 06                	jne    140002df7 <_FindPESectionByName+0xa2>
   140002df1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002df5:	eb 1e                	jmp    140002e15 <_FindPESectionByName+0xc0>
   140002df7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002dfb:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e00:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e04:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e08:	0f b7 c0             	movzx  eax,ax
   140002e0b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e0e:	72 c7                	jb     140002dd7 <_FindPESectionByName+0x82>
   140002e10:	b8 00 00 00 00       	mov    eax,0x0
   140002e15:	48 83 c4 40          	add    rsp,0x40
   140002e19:	5d                   	pop    rbp
   140002e1a:	c3                   	ret

0000000140002e1b <__mingw_GetSectionForAddress>:
   140002e1b:	55                   	push   rbp
   140002e1c:	48 89 e5             	mov    rbp,rsp
   140002e1f:	48 83 ec 30          	sub    rsp,0x30
   140002e23:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e27:	48 8b 05 32 25 00 00 	mov    rax,QWORD PTR [rip+0x2532]        # 140005360 <.refptr.__ImageBase>
   140002e2e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e32:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e36:	48 89 c1             	mov    rcx,rax
   140002e39:	e8 02 fe ff ff       	call   140002c40 <_ValidateImageBase>
   140002e3e:	85 c0                	test   eax,eax
   140002e40:	75 07                	jne    140002e49 <__mingw_GetSectionForAddress+0x2e>
   140002e42:	b8 00 00 00 00       	mov    eax,0x0
   140002e47:	eb 1c                	jmp    140002e65 <__mingw_GetSectionForAddress+0x4a>
   140002e49:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e4d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e51:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e55:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e59:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e5d:	48 89 c1             	mov    rcx,rax
   140002e60:	e8 57 fe ff ff       	call   140002cbc <_FindPESection>
   140002e65:	48 83 c4 30          	add    rsp,0x30
   140002e69:	5d                   	pop    rbp
   140002e6a:	c3                   	ret

0000000140002e6b <__mingw_GetSectionCount>:
   140002e6b:	55                   	push   rbp
   140002e6c:	48 89 e5             	mov    rbp,rsp
   140002e6f:	48 83 ec 30          	sub    rsp,0x30
   140002e73:	48 8b 05 e6 24 00 00 	mov    rax,QWORD PTR [rip+0x24e6]        # 140005360 <.refptr.__ImageBase>
   140002e7a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e7e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e82:	48 89 c1             	mov    rcx,rax
   140002e85:	e8 b6 fd ff ff       	call   140002c40 <_ValidateImageBase>
   140002e8a:	85 c0                	test   eax,eax
   140002e8c:	75 07                	jne    140002e95 <__mingw_GetSectionCount+0x2a>
   140002e8e:	b8 00 00 00 00       	mov    eax,0x0
   140002e93:	eb 20                	jmp    140002eb5 <__mingw_GetSectionCount+0x4a>
   140002e95:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e99:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e9c:	48 63 d0             	movsxd rdx,eax
   140002e9f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ea3:	48 01 d0             	add    rax,rdx
   140002ea6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002eaa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002eae:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002eb2:	0f b7 c0             	movzx  eax,ax
   140002eb5:	48 83 c4 30          	add    rsp,0x30
   140002eb9:	5d                   	pop    rbp
   140002eba:	c3                   	ret

0000000140002ebb <_FindPESectionExec>:
   140002ebb:	55                   	push   rbp
   140002ebc:	48 89 e5             	mov    rbp,rsp
   140002ebf:	48 83 ec 40          	sub    rsp,0x40
   140002ec3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ec7:	48 8b 05 92 24 00 00 	mov    rax,QWORD PTR [rip+0x2492]        # 140005360 <.refptr.__ImageBase>
   140002ece:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ed2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ed6:	48 89 c1             	mov    rcx,rax
   140002ed9:	e8 62 fd ff ff       	call   140002c40 <_ValidateImageBase>
   140002ede:	85 c0                	test   eax,eax
   140002ee0:	75 07                	jne    140002ee9 <_FindPESectionExec+0x2e>
   140002ee2:	b8 00 00 00 00       	mov    eax,0x0
   140002ee7:	eb 78                	jmp    140002f61 <_FindPESectionExec+0xa6>
   140002ee9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002eed:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ef0:	48 63 d0             	movsxd rdx,eax
   140002ef3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ef7:	48 01 d0             	add    rax,rdx
   140002efa:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002efe:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f05:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f09:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f0d:	0f b7 d0             	movzx  edx,ax
   140002f10:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f14:	48 01 d0             	add    rax,rdx
   140002f17:	48 83 c0 18          	add    rax,0x18
   140002f1b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f1f:	eb 2b                	jmp    140002f4c <_FindPESectionExec+0x91>
   140002f21:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f25:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f28:	25 00 00 00 20       	and    eax,0x20000000
   140002f2d:	85 c0                	test   eax,eax
   140002f2f:	74 12                	je     140002f43 <_FindPESectionExec+0x88>
   140002f31:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f36:	75 06                	jne    140002f3e <_FindPESectionExec+0x83>
   140002f38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f3c:	eb 23                	jmp    140002f61 <_FindPESectionExec+0xa6>
   140002f3e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f43:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f47:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f4c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f50:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f54:	0f b7 c0             	movzx  eax,ax
   140002f57:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f5a:	72 c5                	jb     140002f21 <_FindPESectionExec+0x66>
   140002f5c:	b8 00 00 00 00       	mov    eax,0x0
   140002f61:	48 83 c4 40          	add    rsp,0x40
   140002f65:	5d                   	pop    rbp
   140002f66:	c3                   	ret

0000000140002f67 <_GetPEImageBase>:
   140002f67:	55                   	push   rbp
   140002f68:	48 89 e5             	mov    rbp,rsp
   140002f6b:	48 83 ec 30          	sub    rsp,0x30
   140002f6f:	48 8b 05 ea 23 00 00 	mov    rax,QWORD PTR [rip+0x23ea]        # 140005360 <.refptr.__ImageBase>
   140002f76:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f7a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f7e:	48 89 c1             	mov    rcx,rax
   140002f81:	e8 ba fc ff ff       	call   140002c40 <_ValidateImageBase>
   140002f86:	85 c0                	test   eax,eax
   140002f88:	75 07                	jne    140002f91 <_GetPEImageBase+0x2a>
   140002f8a:	b8 00 00 00 00       	mov    eax,0x0
   140002f8f:	eb 04                	jmp    140002f95 <_GetPEImageBase+0x2e>
   140002f91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f95:	48 83 c4 30          	add    rsp,0x30
   140002f99:	5d                   	pop    rbp
   140002f9a:	c3                   	ret

0000000140002f9b <_IsNonwritableInCurrentImage>:
   140002f9b:	55                   	push   rbp
   140002f9c:	48 89 e5             	mov    rbp,rsp
   140002f9f:	48 83 ec 40          	sub    rsp,0x40
   140002fa3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002fa7:	48 8b 05 b2 23 00 00 	mov    rax,QWORD PTR [rip+0x23b2]        # 140005360 <.refptr.__ImageBase>
   140002fae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fb2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fb6:	48 89 c1             	mov    rcx,rax
   140002fb9:	e8 82 fc ff ff       	call   140002c40 <_ValidateImageBase>
   140002fbe:	85 c0                	test   eax,eax
   140002fc0:	75 07                	jne    140002fc9 <_IsNonwritableInCurrentImage+0x2e>
   140002fc2:	b8 00 00 00 00       	mov    eax,0x0
   140002fc7:	eb 3d                	jmp    140003006 <_IsNonwritableInCurrentImage+0x6b>
   140002fc9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002fcd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002fd1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fd5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002fd9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fdd:	48 89 c1             	mov    rcx,rax
   140002fe0:	e8 d7 fc ff ff       	call   140002cbc <_FindPESection>
   140002fe5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002fe9:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002fee:	75 07                	jne    140002ff7 <_IsNonwritableInCurrentImage+0x5c>
   140002ff0:	b8 00 00 00 00       	mov    eax,0x0
   140002ff5:	eb 0f                	jmp    140003006 <_IsNonwritableInCurrentImage+0x6b>
   140002ff7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ffb:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002ffe:	f7 d0                	not    eax
   140003000:	c1 e8 1f             	shr    eax,0x1f
   140003003:	0f b6 c0             	movzx  eax,al
   140003006:	48 83 c4 40          	add    rsp,0x40
   14000300a:	5d                   	pop    rbp
   14000300b:	c3                   	ret

000000014000300c <__mingw_enum_import_library_names>:
   14000300c:	55                   	push   rbp
   14000300d:	48 89 e5             	mov    rbp,rsp
   140003010:	48 83 ec 50          	sub    rsp,0x50
   140003014:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003017:	48 8b 05 42 23 00 00 	mov    rax,QWORD PTR [rip+0x2342]        # 140005360 <.refptr.__ImageBase>
   14000301e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003022:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003026:	48 89 c1             	mov    rcx,rax
   140003029:	e8 12 fc ff ff       	call   140002c40 <_ValidateImageBase>
   14000302e:	85 c0                	test   eax,eax
   140003030:	75 0a                	jne    14000303c <__mingw_enum_import_library_names+0x30>
   140003032:	b8 00 00 00 00       	mov    eax,0x0
   140003037:	e9 ab 00 00 00       	jmp    1400030e7 <__mingw_enum_import_library_names+0xdb>
   14000303c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003040:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003043:	48 63 d0             	movsxd rdx,eax
   140003046:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000304a:	48 01 d0             	add    rax,rdx
   14000304d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003051:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003055:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000305b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000305e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003062:	75 07                	jne    14000306b <__mingw_enum_import_library_names+0x5f>
   140003064:	b8 00 00 00 00       	mov    eax,0x0
   140003069:	eb 7c                	jmp    1400030e7 <__mingw_enum_import_library_names+0xdb>
   14000306b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000306e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003072:	48 89 c1             	mov    rcx,rax
   140003075:	e8 42 fc ff ff       	call   140002cbc <_FindPESection>
   14000307a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000307e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003083:	75 07                	jne    14000308c <__mingw_enum_import_library_names+0x80>
   140003085:	b8 00 00 00 00       	mov    eax,0x0
   14000308a:	eb 5b                	jmp    1400030e7 <__mingw_enum_import_library_names+0xdb>
   14000308c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000308f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003093:	48 01 d0             	add    rax,rdx
   140003096:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000309a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000309f:	75 07                	jne    1400030a8 <__mingw_enum_import_library_names+0x9c>
   1400030a1:	b8 00 00 00 00       	mov    eax,0x0
   1400030a6:	eb 3f                	jmp    1400030e7 <__mingw_enum_import_library_names+0xdb>
   1400030a8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030ac:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400030af:	85 c0                	test   eax,eax
   1400030b1:	75 0b                	jne    1400030be <__mingw_enum_import_library_names+0xb2>
   1400030b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030b7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030ba:	85 c0                	test   eax,eax
   1400030bc:	74 23                	je     1400030e1 <__mingw_enum_import_library_names+0xd5>
   1400030be:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400030c2:	7f 12                	jg     1400030d6 <__mingw_enum_import_library_names+0xca>
   1400030c4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030c8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030cb:	89 c2                	mov    edx,eax
   1400030cd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030d1:	48 01 d0             	add    rax,rdx
   1400030d4:	eb 11                	jmp    1400030e7 <__mingw_enum_import_library_names+0xdb>
   1400030d6:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   1400030da:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   1400030df:	eb c7                	jmp    1400030a8 <__mingw_enum_import_library_names+0x9c>
   1400030e1:	90                   	nop
   1400030e2:	b8 00 00 00 00       	mov    eax,0x0
   1400030e7:	48 83 c4 50          	add    rsp,0x50
   1400030eb:	5d                   	pop    rbp
   1400030ec:	c3                   	ret
   1400030ed:	90                   	nop
   1400030ee:	90                   	nop
   1400030ef:	90                   	nop

00000001400030f0 <___chkstk_ms>:
   1400030f0:	51                   	push   rcx
   1400030f1:	50                   	push   rax
   1400030f2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030f8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400030fd:	72 19                	jb     140003118 <___chkstk_ms+0x28>
   1400030ff:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003106:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000310a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003110:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003116:	77 e7                	ja     1400030ff <___chkstk_ms+0xf>
   140003118:	48 29 c1             	sub    rcx,rax
   14000311b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000311f:	58                   	pop    rax
   140003120:	59                   	pop    rcx
   140003121:	c3                   	ret
   140003122:	90                   	nop
   140003123:	90                   	nop
   140003124:	90                   	nop
   140003125:	90                   	nop
   140003126:	90                   	nop
   140003127:	90                   	nop
   140003128:	90                   	nop
   140003129:	90                   	nop
   14000312a:	90                   	nop
   14000312b:	90                   	nop
   14000312c:	90                   	nop
   14000312d:	90                   	nop
   14000312e:	90                   	nop
   14000312f:	90                   	nop

0000000140003130 <_initterm_e>:
   140003130:	55                   	push   rbp
   140003131:	48 89 e5             	mov    rbp,rsp
   140003134:	48 83 ec 30          	sub    rsp,0x30
   140003138:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000313c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003140:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003144:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003148:	eb 29                	jmp    140003173 <_initterm_e+0x43>
   14000314a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000314e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140003151:	48 85 c0             	test   rax,rax
   140003154:	74 17                	je     14000316d <_initterm_e+0x3d>
   140003156:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000315a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000315d:	ff d0                	call   rax
   14000315f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003162:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003166:	74 06                	je     14000316e <_initterm_e+0x3e>
   140003168:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000316b:	eb 15                	jmp    140003182 <_initterm_e+0x52>
   14000316d:	90                   	nop
   14000316e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140003173:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003177:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   14000317b:	72 cd                	jb     14000314a <_initterm_e+0x1a>
   14000317d:	b8 00 00 00 00       	mov    eax,0x0
   140003182:	48 83 c4 30          	add    rsp,0x30
   140003186:	5d                   	pop    rbp
   140003187:	c3                   	ret
   140003188:	90                   	nop
   140003189:	90                   	nop
   14000318a:	90                   	nop
   14000318b:	90                   	nop
   14000318c:	90                   	nop
   14000318d:	90                   	nop
   14000318e:	90                   	nop
   14000318f:	90                   	nop

0000000140003190 <__p__fmode>:
   140003190:	55                   	push   rbp
   140003191:	48 89 e5             	mov    rbp,rsp
   140003194:	48 8b 05 35 22 00 00 	mov    rax,QWORD PTR [rip+0x2235]        # 1400053d0 <.refptr.__imp__fmode>
   14000319b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000319e:	5d                   	pop    rbp
   14000319f:	c3                   	ret

00000001400031a0 <__p__commode>:
   1400031a0:	55                   	push   rbp
   1400031a1:	48 89 e5             	mov    rbp,rsp
   1400031a4:	48 8b 05 15 22 00 00 	mov    rax,QWORD PTR [rip+0x2215]        # 1400053c0 <.refptr.__imp__commode>
   1400031ab:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031ae:	5d                   	pop    rbp
   1400031af:	c3                   	ret

00000001400031b0 <__p___initenv>:
   1400031b0:	55                   	push   rbp
   1400031b1:	48 89 e5             	mov    rbp,rsp
   1400031b4:	48 8b 05 f5 21 00 00 	mov    rax,QWORD PTR [rip+0x21f5]        # 1400053b0 <.refptr.__imp___initenv>
   1400031bb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031be:	5d                   	pop    rbp
   1400031bf:	c3                   	ret

00000001400031c0 <_set_invalid_parameter_handler>:
   1400031c0:	55                   	push   rbp
   1400031c1:	48 89 e5             	mov    rbp,rsp
   1400031c4:	48 83 ec 10          	sub    rsp,0x10
   1400031c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400031cc:	48 8d 05 bd 5f 00 00 	lea    rax,[rip+0x5fbd]        # 140009190 <handler>
   1400031d3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031d7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400031db:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400031df:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400031e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031e7:	48 87 10             	xchg   QWORD PTR [rax],rdx
   1400031ea:	48 89 d0             	mov    rax,rdx
   1400031ed:	48 83 c4 10          	add    rsp,0x10
   1400031f1:	5d                   	pop    rbp
   1400031f2:	c3                   	ret

00000001400031f3 <_get_invalid_parameter_handler>:
   1400031f3:	55                   	push   rbp
   1400031f4:	48 89 e5             	mov    rbp,rsp
   1400031f7:	48 8b 05 92 5f 00 00 	mov    rax,QWORD PTR [rip+0x5f92]        # 140009190 <handler>
   1400031fe:	5d                   	pop    rbp
   1400031ff:	c3                   	ret

0000000140003200 <_configthreadlocale>:
   140003200:	55                   	push   rbp
   140003201:	48 89 e5             	mov    rbp,rsp
   140003204:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003207:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000320b:	75 07                	jne    140003214 <_configthreadlocale+0x14>
   14000320d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140003212:	eb 05                	jmp    140003219 <_configthreadlocale+0x19>
   140003214:	b8 02 00 00 00       	mov    eax,0x2
   140003219:	5d                   	pop    rbp
   14000321a:	c3                   	ret
   14000321b:	90                   	nop
   14000321c:	90                   	nop
   14000321d:	90                   	nop
   14000321e:	90                   	nop
   14000321f:	90                   	nop

0000000140003220 <__acrt_iob_func>:
   140003220:	55                   	push   rbp
   140003221:	48 89 e5             	mov    rbp,rsp
   140003224:	48 83 ec 20          	sub    rsp,0x20
   140003228:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000322b:	e8 30 00 00 00       	call   140003260 <__iob_func>
   140003230:	48 89 c1             	mov    rcx,rax
   140003233:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003236:	48 89 d0             	mov    rax,rdx
   140003239:	48 01 c0             	add    rax,rax
   14000323c:	48 01 d0             	add    rax,rdx
   14000323f:	48 c1 e0 04          	shl    rax,0x4
   140003243:	48 01 c8             	add    rax,rcx
   140003246:	48 83 c4 20          	add    rsp,0x20
   14000324a:	5d                   	pop    rbp
   14000324b:	c3                   	ret
   14000324c:	90                   	nop
   14000324d:	90                   	nop
   14000324e:	90                   	nop
   14000324f:	90                   	nop

0000000140003250 <__C_specific_handler>:
   140003250:	ff 25 ba 6f 00 00    	jmp    QWORD PTR [rip+0x6fba]        # 14000a210 <__imp___C_specific_handler>
   140003256:	90                   	nop
   140003257:	90                   	nop

0000000140003258 <__getmainargs>:
   140003258:	ff 25 ba 6f 00 00    	jmp    QWORD PTR [rip+0x6fba]        # 14000a218 <__imp___getmainargs>
   14000325e:	90                   	nop
   14000325f:	90                   	nop

0000000140003260 <__iob_func>:
   140003260:	ff 25 c2 6f 00 00    	jmp    QWORD PTR [rip+0x6fc2]        # 14000a228 <__imp___iob_func>
   140003266:	90                   	nop
   140003267:	90                   	nop

0000000140003268 <__set_app_type>:
   140003268:	ff 25 c2 6f 00 00    	jmp    QWORD PTR [rip+0x6fc2]        # 14000a230 <__imp___set_app_type>
   14000326e:	90                   	nop
   14000326f:	90                   	nop

0000000140003270 <__setusermatherr>:
   140003270:	ff 25 c2 6f 00 00    	jmp    QWORD PTR [rip+0x6fc2]        # 14000a238 <__imp___setusermatherr>
   140003276:	90                   	nop
   140003277:	90                   	nop

0000000140003278 <_amsg_exit>:
   140003278:	ff 25 c2 6f 00 00    	jmp    QWORD PTR [rip+0x6fc2]        # 14000a240 <__imp__amsg_exit>
   14000327e:	90                   	nop
   14000327f:	90                   	nop

0000000140003280 <_cexit>:
   140003280:	ff 25 c2 6f 00 00    	jmp    QWORD PTR [rip+0x6fc2]        # 14000a248 <__imp__cexit>
   140003286:	90                   	nop
   140003287:	90                   	nop

0000000140003288 <_initterm>:
   140003288:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a260 <__imp__initterm>
   14000328e:	90                   	nop
   14000328f:	90                   	nop

0000000140003290 <_crt_atexit>:
   140003290:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a268 <__imp__crt_atexit>
   140003296:	90                   	nop
   140003297:	90                   	nop

0000000140003298 <abort>:
   140003298:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a270 <__imp_abort>
   14000329e:	90                   	nop
   14000329f:	90                   	nop

00000001400032a0 <atoi>:
   1400032a0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a278 <__imp_atoi>
   1400032a6:	90                   	nop
   1400032a7:	90                   	nop

00000001400032a8 <calloc>:
   1400032a8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a280 <__imp_calloc>
   1400032ae:	90                   	nop
   1400032af:	90                   	nop

00000001400032b0 <exit>:
   1400032b0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a288 <__imp_exit>
   1400032b6:	90                   	nop
   1400032b7:	90                   	nop

00000001400032b8 <fflush>:
   1400032b8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a290 <__imp_fflush>
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <fprintf>:
   1400032c0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a298 <__imp_fprintf>
   1400032c6:	90                   	nop
   1400032c7:	90                   	nop

00000001400032c8 <free>:
   1400032c8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2a0 <__imp_free>
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <malloc>:
   1400032d0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2a8 <__imp_malloc>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop

00000001400032d8 <memcpy>:
   1400032d8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2b0 <__imp_memcpy>
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <memset>:
   1400032e0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2b8 <__imp_memset>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <setvbuf>:
   1400032e8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2c0 <__imp_setvbuf>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <signal>:
   1400032f0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2c8 <__imp_signal>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <strlen>:
   1400032f8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2d0 <__imp_strlen>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <strncmp>:
   140003300:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2d8 <__imp_strncmp>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <vfprintf>:
   140003308:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2e0 <__imp_vfprintf>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <VirtualQuery>:
   140003310:	ff 25 ea 6e 00 00    	jmp    QWORD PTR [rip+0x6eea]        # 14000a200 <__imp_VirtualQuery>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <VirtualProtect>:
   140003318:	ff 25 da 6e 00 00    	jmp    QWORD PTR [rip+0x6eda]        # 14000a1f8 <__imp_VirtualProtect>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <TlsGetValue>:
   140003320:	ff 25 ca 6e 00 00    	jmp    QWORD PTR [rip+0x6eca]        # 14000a1f0 <__imp_TlsGetValue>
   140003326:	90                   	nop
   140003327:	90                   	nop

0000000140003328 <Sleep>:
   140003328:	ff 25 ba 6e 00 00    	jmp    QWORD PTR [rip+0x6eba]        # 14000a1e8 <__imp_Sleep>
   14000332e:	90                   	nop
   14000332f:	90                   	nop

0000000140003330 <SetUnhandledExceptionFilter>:
   140003330:	ff 25 aa 6e 00 00    	jmp    QWORD PTR [rip+0x6eaa]        # 14000a1e0 <__imp_SetUnhandledExceptionFilter>
   140003336:	90                   	nop
   140003337:	90                   	nop

0000000140003338 <LoadLibraryA>:
   140003338:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a1d8 <__imp_LoadLibraryA>
   14000333e:	90                   	nop
   14000333f:	90                   	nop

0000000140003340 <LeaveCriticalSection>:
   140003340:	ff 25 8a 6e 00 00    	jmp    QWORD PTR [rip+0x6e8a]        # 14000a1d0 <__imp_LeaveCriticalSection>
   140003346:	90                   	nop
   140003347:	90                   	nop

0000000140003348 <InitializeCriticalSection>:
   140003348:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a1c8 <__imp_InitializeCriticalSection>
   14000334e:	90                   	nop
   14000334f:	90                   	nop

0000000140003350 <GetProcAddress>:
   140003350:	ff 25 6a 6e 00 00    	jmp    QWORD PTR [rip+0x6e6a]        # 14000a1c0 <__imp_GetProcAddress>
   140003356:	90                   	nop
   140003357:	90                   	nop

0000000140003358 <GetModuleHandleA>:
   140003358:	ff 25 5a 6e 00 00    	jmp    QWORD PTR [rip+0x6e5a]        # 14000a1b8 <__imp_GetModuleHandleA>
   14000335e:	90                   	nop
   14000335f:	90                   	nop

0000000140003360 <GetLastError>:
   140003360:	ff 25 4a 6e 00 00    	jmp    QWORD PTR [rip+0x6e4a]        # 14000a1b0 <__imp_GetLastError>
   140003366:	90                   	nop
   140003367:	90                   	nop

0000000140003368 <FreeLibrary>:
   140003368:	ff 25 3a 6e 00 00    	jmp    QWORD PTR [rip+0x6e3a]        # 14000a1a8 <__imp_FreeLibrary>
   14000336e:	90                   	nop
   14000336f:	90                   	nop

0000000140003370 <EnterCriticalSection>:
   140003370:	ff 25 2a 6e 00 00    	jmp    QWORD PTR [rip+0x6e2a]        # 14000a1a0 <__imp_EnterCriticalSection>
   140003376:	90                   	nop
   140003377:	90                   	nop

0000000140003378 <DeleteCriticalSection>:
   140003378:	ff 25 1a 6e 00 00    	jmp    QWORD PTR [rip+0x6e1a]        # 14000a198 <__IAT_start__>
   14000337e:	90                   	nop
   14000337f:	90                   	nop

0000000140003380 <register_frame_ctor>:
   140003380:	e9 eb e2 ff ff       	jmp    140001670 <__gcc_register_frame>
   140003385:	90                   	nop
   140003386:	90                   	nop
   140003387:	90                   	nop
   140003388:	90                   	nop
   140003389:	90                   	nop
   14000338a:	90                   	nop
   14000338b:	90                   	nop
   14000338c:	90                   	nop
   14000338d:	90                   	nop
   14000338e:	90                   	nop
   14000338f:	90                   	nop
