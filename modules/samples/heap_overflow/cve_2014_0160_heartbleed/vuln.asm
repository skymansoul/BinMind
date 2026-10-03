
C:\Users\Administrator\Desktop\BinMind\deemo\modules\samples\heap_overflow\cve_2014_0160_heartbleed\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 77 22 00 00       	call   1400032a0 <fflush>
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
   14000113b:	e8 28 21 00 00       	call   140003268 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 a8 20 00 00       	call   140003210 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 47 21 00 00       	call   1400032c8 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 ef 20 00 00       	call   140003288 <abort>
   140001199:	e8 72 11 00 00       	call   140002310 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 21 90 00 00 	mov    rax,QWORD PTR [rip+0x9021]        # 14000a1d0 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 e6 1f 00 00       	call   1400031b0 <_set_invalid_parameter_handler>
   1400011ca:	e8 51 1a 00 00       	call   140002c20 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 67 20 00 00       	call   140003258 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 5b 20 00 00       	call   140003258 <__set_app_type>
   1400011fd:	e8 7e 1f 00 00       	call   140003180 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 7e 1f 00 00       	call   140003190 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 ce 06 00 00       	call   1400018f0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 33 20 00 00       	call   140003268 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 d8 11 00 00       	call   14000242a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 86 1f 00 00       	call   1400031f0 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 a0 1e 00 00       	call   140003120 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 da 1f 00 00       	call   140003268 <_amsg_exit>
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
   1400012cb:	e8 78 1f 00 00       	call   140003248 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 85 1f 00 00       	call   140003268 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 5e 1f 00 00       	call   140003268 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 58 1f 00 00       	call   140003278 <_initterm>
   140001320:	e8 a2 05 00 00       	call   1400018c7 <__main>
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
   14000138d:	e8 0e 1e 00 00       	call   1400031a0 <__p___initenv>
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
   1400013cc:	e8 c7 1e 00 00       	call   140003298 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 90 1e 00 00       	call   140003270 <_cexit>
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
   140001511:	e8 a2 1d 00 00       	call   1400032b8 <malloc>
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
   14000155c:	e8 77 1d 00 00       	call   1400032d8 <strlen>
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
   140001585:	e8 2e 1d 00 00       	call   1400032b8 <malloc>
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
   1400015e8:	e8 d3 1c 00 00       	call   1400032c0 <memcpy>
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
   140001642:	e8 39 1c 00 00       	call   140003280 <_crt_atexit>
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

0000000140001760 <main>:
   140001760:	55                   	push   rbp
   140001761:	56                   	push   rsi
   140001762:	53                   	push   rbx
   140001763:	48 83 ec 30          	sub    rsp,0x30
   140001767:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   14000176c:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   14000176f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001773:	e8 4f 01 00 00       	call   1400018c7 <__main>
   140001778:	b9 10 00 00 00       	mov    ecx,0x10
   14000177d:	e8 36 1b 00 00       	call   1400032b8 <malloc>
   140001782:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001786:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000178b:	75 07                	jne    140001794 <main+0x34>
   14000178d:	b8 01 00 00 00       	mov    eax,0x1
   140001792:	eb 6c                	jmp    140001800 <main+0xa0>
   140001794:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001798:	66 c7 00 01 00       	mov    WORD PTR [rax],0x1
   14000179d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017a1:	66 c7 40 02 14 00    	mov    WORD PTR [rax+0x2],0x14
   1400017a7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017ab:	48 83 c0 04          	add    rax,0x4
   1400017af:	48 8d 15 9a 38 00 00 	lea    rdx,[rip+0x389a]        # 140005050 <.rdata>
   1400017b6:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400017bc:	48 89 c1             	mov    rcx,rax
   1400017bf:	e8 fc 1a 00 00       	call   1400032c0 <memcpy>
   1400017c4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017c8:	0f b7 40 02          	movzx  eax,WORD PTR [rax+0x2]
   1400017cc:	0f b7 f0             	movzx  esi,ax
   1400017cf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017d3:	48 8d 58 04          	lea    rbx,[rax+0x4]
   1400017d7:	b9 40 00 00 00       	mov    ecx,0x40
   1400017dc:	e8 d7 1a 00 00       	call   1400032b8 <malloc>
   1400017e1:	49 89 f0             	mov    r8,rsi
   1400017e4:	48 89 da             	mov    rdx,rbx
   1400017e7:	48 89 c1             	mov    rcx,rax
   1400017ea:	e8 d1 1a 00 00       	call   1400032c0 <memcpy>
   1400017ef:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017f3:	48 89 c1             	mov    rcx,rax
   1400017f6:	e8 b5 1a 00 00       	call   1400032b0 <free>
   1400017fb:	b8 00 00 00 00       	mov    eax,0x0
   140001800:	48 83 c4 30          	add    rsp,0x30
   140001804:	5b                   	pop    rbx
   140001805:	5e                   	pop    rsi
   140001806:	5d                   	pop    rbp
   140001807:	c3                   	ret
   140001808:	90                   	nop
   140001809:	90                   	nop
   14000180a:	90                   	nop
   14000180b:	90                   	nop
   14000180c:	90                   	nop
   14000180d:	90                   	nop
   14000180e:	90                   	nop
   14000180f:	90                   	nop

0000000140001810 <__do_global_dtors>:
   140001810:	55                   	push   rbp
   140001811:	48 89 e5             	mov    rbp,rsp
   140001814:	48 83 ec 20          	sub    rsp,0x20
   140001818:	eb 1e                	jmp    140001838 <__do_global_dtors+0x28>
   14000181a:	48 8b 05 ef 27 00 00 	mov    rax,QWORD PTR [rip+0x27ef]        # 140004010 <p.0>
   140001821:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001824:	ff d0                	call   rax
   140001826:	48 8b 05 e3 27 00 00 	mov    rax,QWORD PTR [rip+0x27e3]        # 140004010 <p.0>
   14000182d:	48 83 c0 08          	add    rax,0x8
   140001831:	48 89 05 d8 27 00 00 	mov    QWORD PTR [rip+0x27d8],rax        # 140004010 <p.0>
   140001838:	48 8b 05 d1 27 00 00 	mov    rax,QWORD PTR [rip+0x27d1]        # 140004010 <p.0>
   14000183f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001842:	48 85 c0             	test   rax,rax
   140001845:	75 d3                	jne    14000181a <__do_global_dtors+0xa>
   140001847:	90                   	nop
   140001848:	90                   	nop
   140001849:	48 83 c4 20          	add    rsp,0x20
   14000184d:	5d                   	pop    rbp
   14000184e:	c3                   	ret

000000014000184f <__do_global_ctors>:
   14000184f:	55                   	push   rbp
   140001850:	48 89 e5             	mov    rbp,rsp
   140001853:	48 83 ec 30          	sub    rsp,0x30
   140001857:	48 8b 05 f2 3a 00 00 	mov    rax,QWORD PTR [rip+0x3af2]        # 140005350 <.refptr.__CTOR_LIST__>
   14000185e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001861:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001864:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001868:	75 25                	jne    14000188f <__do_global_ctors+0x40>
   14000186a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001871:	eb 04                	jmp    140001877 <__do_global_ctors+0x28>
   140001873:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001877:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000187a:	8d 50 01             	lea    edx,[rax+0x1]
   14000187d:	48 8b 05 cc 3a 00 00 	mov    rax,QWORD PTR [rip+0x3acc]        # 140005350 <.refptr.__CTOR_LIST__>
   140001884:	89 d2                	mov    edx,edx
   140001886:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000188a:	48 85 c0             	test   rax,rax
   14000188d:	75 e4                	jne    140001873 <__do_global_ctors+0x24>
   14000188f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001892:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001895:	eb 14                	jmp    1400018ab <__do_global_ctors+0x5c>
   140001897:	48 8b 05 b2 3a 00 00 	mov    rax,QWORD PTR [rip+0x3ab2]        # 140005350 <.refptr.__CTOR_LIST__>
   14000189e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400018a1:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018a5:	ff d0                	call   rax
   1400018a7:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400018ab:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400018af:	75 e6                	jne    140001897 <__do_global_ctors+0x48>
   1400018b1:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001810 <__do_global_dtors>
   1400018b8:	48 89 c1             	mov    rcx,rax
   1400018bb:	e8 6f fd ff ff       	call   14000162f <atexit>
   1400018c0:	90                   	nop
   1400018c1:	48 83 c4 30          	add    rsp,0x30
   1400018c5:	5d                   	pop    rbp
   1400018c6:	c3                   	ret

00000001400018c7 <__main>:
   1400018c7:	55                   	push   rbp
   1400018c8:	48 89 e5             	mov    rbp,rsp
   1400018cb:	48 83 ec 20          	sub    rsp,0x20
   1400018cf:	8b 05 ab 77 00 00    	mov    eax,DWORD PTR [rip+0x77ab]        # 140009080 <initialized>
   1400018d5:	85 c0                	test   eax,eax
   1400018d7:	75 0f                	jne    1400018e8 <__main+0x21>
   1400018d9:	c7 05 9d 77 00 00 01 	mov    DWORD PTR [rip+0x779d],0x1        # 140009080 <initialized>
   1400018e0:	00 00 00 
   1400018e3:	e8 67 ff ff ff       	call   14000184f <__do_global_ctors>
   1400018e8:	90                   	nop
   1400018e9:	48 83 c4 20          	add    rsp,0x20
   1400018ed:	5d                   	pop    rbp
   1400018ee:	c3                   	ret
   1400018ef:	90                   	nop

00000001400018f0 <_setargv>:
   1400018f0:	55                   	push   rbp
   1400018f1:	48 89 e5             	mov    rbp,rsp
   1400018f4:	b8 00 00 00 00       	mov    eax,0x0
   1400018f9:	5d                   	pop    rbp
   1400018fa:	c3                   	ret
   1400018fb:	90                   	nop
   1400018fc:	90                   	nop
   1400018fd:	90                   	nop
   1400018fe:	90                   	nop
   1400018ff:	90                   	nop

0000000140001900 <__dyn_tls_init>:
   140001900:	55                   	push   rbp
   140001901:	48 89 e5             	mov    rbp,rsp
   140001904:	48 83 ec 30          	sub    rsp,0x30
   140001908:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000190c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000190f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001913:	48 8b 05 16 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a16]        # 140005330 <.refptr._CRT_MT>
   14000191a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000191c:	83 f8 02             	cmp    eax,0x2
   14000191f:	74 0d                	je     14000192e <__dyn_tls_init+0x2e>
   140001921:	48 8b 05 08 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a08]        # 140005330 <.refptr._CRT_MT>
   140001928:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000192e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001932:	74 1e                	je     140001952 <__dyn_tls_init+0x52>
   140001934:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001938:	75 5b                	jne    140001995 <__dyn_tls_init+0x95>
   14000193a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000193e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001941:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001945:	49 89 c8             	mov    r8,rcx
   140001948:	48 89 c1             	mov    rcx,rax
   14000194b:	e8 d1 11 00 00       	call   140002b21 <__mingw_TLScallback>
   140001950:	eb 43                	jmp    140001995 <__dyn_tls_init+0x95>
   140001952:	48 8d 05 3f 3d 00 00 	lea    rax,[rip+0x3d3f]        # 140005698 <___crt_xd_start__>
   140001959:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000195d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001962:	eb 22                	jmp    140001986 <__dyn_tls_init+0x86>
   140001964:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001968:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000196c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001970:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001973:	48 85 c0             	test   rax,rax
   140001976:	74 09                	je     140001981 <__dyn_tls_init+0x81>
   140001978:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000197c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000197f:	ff d0                	call   rax
   140001981:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001986:	48 8d 05 13 3d 00 00 	lea    rax,[rip+0x3d13]        # 1400056a0 <__xd_z>
   14000198d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001991:	75 d1                	jne    140001964 <__dyn_tls_init+0x64>
   140001993:	eb 01                	jmp    140001996 <__dyn_tls_init+0x96>
   140001995:	90                   	nop
   140001996:	48 83 c4 30          	add    rsp,0x30
   14000199a:	5d                   	pop    rbp
   14000199b:	c3                   	ret

000000014000199c <__tlregdtor>:
   14000199c:	55                   	push   rbp
   14000199d:	48 89 e5             	mov    rbp,rsp
   1400019a0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019a4:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400019a9:	75 07                	jne    1400019b2 <__tlregdtor+0x16>
   1400019ab:	b8 00 00 00 00       	mov    eax,0x0
   1400019b0:	eb 05                	jmp    1400019b7 <__tlregdtor+0x1b>
   1400019b2:	b8 00 00 00 00       	mov    eax,0x0
   1400019b7:	5d                   	pop    rbp
   1400019b8:	c3                   	ret

00000001400019b9 <__dyn_tls_dtor>:
   1400019b9:	55                   	push   rbp
   1400019ba:	48 89 e5             	mov    rbp,rsp
   1400019bd:	48 83 ec 20          	sub    rsp,0x20
   1400019c1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019c5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019c8:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019cc:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   1400019d0:	74 06                	je     1400019d8 <__dyn_tls_dtor+0x1f>
   1400019d2:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400019d6:	75 18                	jne    1400019f0 <__dyn_tls_dtor+0x37>
   1400019d8:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019dc:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019df:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019e3:	49 89 c8             	mov    r8,rcx
   1400019e6:	48 89 c1             	mov    rcx,rax
   1400019e9:	e8 33 11 00 00       	call   140002b21 <__mingw_TLScallback>
   1400019ee:	eb 01                	jmp    1400019f1 <__dyn_tls_dtor+0x38>
   1400019f0:	90                   	nop
   1400019f1:	48 83 c4 20          	add    rsp,0x20
   1400019f5:	5d                   	pop    rbp
   1400019f6:	c3                   	ret
   1400019f7:	90                   	nop
   1400019f8:	90                   	nop
   1400019f9:	90                   	nop
   1400019fa:	90                   	nop
   1400019fb:	90                   	nop
   1400019fc:	90                   	nop
   1400019fd:	90                   	nop
   1400019fe:	90                   	nop
   1400019ff:	90                   	nop

0000000140001a00 <_matherr>:
   140001a00:	55                   	push   rbp
   140001a01:	53                   	push   rbx
   140001a02:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a09:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a0e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a12:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a16:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a1b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a1f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a23:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a25:	83 f8 06             	cmp    eax,0x6
   140001a28:	74 56                	je     140001a80 <_matherr+0x80>
   140001a2a:	83 f8 06             	cmp    eax,0x6
   140001a2d:	7f 78                	jg     140001aa7 <_matherr+0xa7>
   140001a2f:	83 f8 05             	cmp    eax,0x5
   140001a32:	74 59                	je     140001a8d <_matherr+0x8d>
   140001a34:	83 f8 05             	cmp    eax,0x5
   140001a37:	7f 6e                	jg     140001aa7 <_matherr+0xa7>
   140001a39:	83 f8 04             	cmp    eax,0x4
   140001a3c:	74 5c                	je     140001a9a <_matherr+0x9a>
   140001a3e:	83 f8 04             	cmp    eax,0x4
   140001a41:	7f 64                	jg     140001aa7 <_matherr+0xa7>
   140001a43:	83 f8 03             	cmp    eax,0x3
   140001a46:	74 2b                	je     140001a73 <_matherr+0x73>
   140001a48:	83 f8 03             	cmp    eax,0x3
   140001a4b:	7f 5a                	jg     140001aa7 <_matherr+0xa7>
   140001a4d:	83 f8 01             	cmp    eax,0x1
   140001a50:	74 07                	je     140001a59 <_matherr+0x59>
   140001a52:	83 f8 02             	cmp    eax,0x2
   140001a55:	74 0f                	je     140001a66 <_matherr+0x66>
   140001a57:	eb 4e                	jmp    140001aa7 <_matherr+0xa7>
   140001a59:	48 8d 05 40 36 00 00 	lea    rax,[rip+0x3640]        # 1400050a0 <.rdata>
   140001a60:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a64:	eb 4d                	jmp    140001ab3 <_matherr+0xb3>
   140001a66:	48 8d 05 52 36 00 00 	lea    rax,[rip+0x3652]        # 1400050bf <.rdata+0x1f>
   140001a6d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a71:	eb 40                	jmp    140001ab3 <_matherr+0xb3>
   140001a73:	48 8d 05 66 36 00 00 	lea    rax,[rip+0x3666]        # 1400050e0 <.rdata+0x40>
   140001a7a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a7e:	eb 33                	jmp    140001ab3 <_matherr+0xb3>
   140001a80:	48 8d 05 79 36 00 00 	lea    rax,[rip+0x3679]        # 140005100 <.rdata+0x60>
   140001a87:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a8b:	eb 26                	jmp    140001ab3 <_matherr+0xb3>
   140001a8d:	48 8d 05 94 36 00 00 	lea    rax,[rip+0x3694]        # 140005128 <.rdata+0x88>
   140001a94:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a98:	eb 19                	jmp    140001ab3 <_matherr+0xb3>
   140001a9a:	48 8d 05 af 36 00 00 	lea    rax,[rip+0x36af]        # 140005150 <.rdata+0xb0>
   140001aa1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001aa5:	eb 0c                	jmp    140001ab3 <_matherr+0xb3>
   140001aa7:	48 8d 05 d8 36 00 00 	lea    rax,[rip+0x36d8]        # 140005186 <.rdata+0xe6>
   140001aae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ab2:	90                   	nop
   140001ab3:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ab7:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001abd:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ac1:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001ac6:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001aca:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001acf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ad3:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001ad7:	b9 02 00 00 00       	mov    ecx,0x2
   140001adc:	e8 2f 17 00 00       	call   140003210 <__acrt_iob_func>
   140001ae1:	48 89 c1             	mov    rcx,rax
   140001ae4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001ae8:	48 8d 05 a9 36 00 00 	lea    rax,[rip+0x36a9]        # 140005198 <.rdata+0xf8>
   140001aef:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001af6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001afc:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b02:	49 89 d9             	mov    r9,rbx
   140001b05:	49 89 d0             	mov    r8,rdx
   140001b08:	48 89 c2             	mov    rdx,rax
   140001b0b:	e8 98 17 00 00       	call   1400032a8 <fprintf>
   140001b10:	b8 00 00 00 00       	mov    eax,0x0
   140001b15:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b19:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b1d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b22:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b29:	5b                   	pop    rbx
   140001b2a:	5d                   	pop    rbp
   140001b2b:	c3                   	ret
   140001b2c:	90                   	nop
   140001b2d:	90                   	nop
   140001b2e:	90                   	nop
   140001b2f:	90                   	nop

0000000140001b30 <__report_error>:
   140001b30:	55                   	push   rbp
   140001b31:	53                   	push   rbx
   140001b32:	48 83 ec 38          	sub    rsp,0x38
   140001b36:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b3b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b3f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b43:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b47:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b4b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b4f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b53:	b9 02 00 00 00       	mov    ecx,0x2
   140001b58:	e8 b3 16 00 00       	call   140003210 <__acrt_iob_func>
   140001b5d:	48 89 c1             	mov    rcx,rax
   140001b60:	48 8d 05 69 36 00 00 	lea    rax,[rip+0x3669]        # 1400051d0 <.rdata>
   140001b67:	48 89 c2             	mov    rdx,rax
   140001b6a:	e8 39 17 00 00       	call   1400032a8 <fprintf>
   140001b6f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b73:	b9 02 00 00 00       	mov    ecx,0x2
   140001b78:	e8 93 16 00 00       	call   140003210 <__acrt_iob_func>
   140001b7d:	48 89 c1             	mov    rcx,rax
   140001b80:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b84:	49 89 d8             	mov    r8,rbx
   140001b87:	48 89 c2             	mov    rdx,rax
   140001b8a:	e8 59 17 00 00       	call   1400032e8 <vfprintf>
   140001b8f:	e8 f4 16 00 00       	call   140003288 <abort>
   140001b94:	90                   	nop

0000000140001b95 <mark_section_writable>:
   140001b95:	55                   	push   rbp
   140001b96:	48 89 e5             	mov    rbp,rsp
   140001b99:	48 83 ec 60          	sub    rsp,0x60
   140001b9d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001ba1:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001ba8:	e9 82 00 00 00       	jmp    140001c2f <mark_section_writable+0x9a>
   140001bad:	48 8b 0d 2c 75 00 00 	mov    rcx,QWORD PTR [rip+0x752c]        # 1400090e0 <the_secs>
   140001bb4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bb7:	48 63 d0             	movsxd rdx,eax
   140001bba:	48 89 d0             	mov    rax,rdx
   140001bbd:	48 c1 e0 02          	shl    rax,0x2
   140001bc1:	48 01 d0             	add    rax,rdx
   140001bc4:	48 c1 e0 03          	shl    rax,0x3
   140001bc8:	48 01 c8             	add    rax,rcx
   140001bcb:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001bcf:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001bd3:	72 56                	jb     140001c2b <mark_section_writable+0x96>
   140001bd5:	48 8b 0d 04 75 00 00 	mov    rcx,QWORD PTR [rip+0x7504]        # 1400090e0 <the_secs>
   140001bdc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bdf:	48 63 d0             	movsxd rdx,eax
   140001be2:	48 89 d0             	mov    rax,rdx
   140001be5:	48 c1 e0 02          	shl    rax,0x2
   140001be9:	48 01 d0             	add    rax,rdx
   140001bec:	48 c1 e0 03          	shl    rax,0x3
   140001bf0:	48 01 c8             	add    rax,rcx
   140001bf3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001bf7:	4c 8b 05 e2 74 00 00 	mov    r8,QWORD PTR [rip+0x74e2]        # 1400090e0 <the_secs>
   140001bfe:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c01:	48 63 d0             	movsxd rdx,eax
   140001c04:	48 89 d0             	mov    rax,rdx
   140001c07:	48 c1 e0 02          	shl    rax,0x2
   140001c0b:	48 01 d0             	add    rax,rdx
   140001c0e:	48 c1 e0 03          	shl    rax,0x3
   140001c12:	4c 01 c0             	add    rax,r8
   140001c15:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c19:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c1c:	89 c0                	mov    eax,eax
   140001c1e:	48 01 c8             	add    rax,rcx
   140001c21:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c25:	0f 82 41 02 00 00    	jb     140001e6c <mark_section_writable+0x2d7>
   140001c2b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c2f:	8b 05 b3 74 00 00    	mov    eax,DWORD PTR [rip+0x74b3]        # 1400090e8 <maxSections>
   140001c35:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c38:	0f 8c 6f ff ff ff    	jl     140001bad <mark_section_writable+0x18>
   140001c3e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c42:	48 89 c1             	mov    rcx,rax
   140001c45:	e8 c1 11 00 00       	call   140002e0b <__mingw_GetSectionForAddress>
   140001c4a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c4e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c53:	75 13                	jne    140001c68 <mark_section_writable+0xd3>
   140001c55:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c59:	48 8d 0d 90 35 00 00 	lea    rcx,[rip+0x3590]        # 1400051f0 <.rdata+0x20>
   140001c60:	48 89 c2             	mov    rdx,rax
   140001c63:	e8 c8 fe ff ff       	call   140001b30 <__report_error>
   140001c68:	48 8b 0d 71 74 00 00 	mov    rcx,QWORD PTR [rip+0x7471]        # 1400090e0 <the_secs>
   140001c6f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c72:	48 63 d0             	movsxd rdx,eax
   140001c75:	48 89 d0             	mov    rax,rdx
   140001c78:	48 c1 e0 02          	shl    rax,0x2
   140001c7c:	48 01 d0             	add    rax,rdx
   140001c7f:	48 c1 e0 03          	shl    rax,0x3
   140001c83:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c87:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c8b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c8f:	48 8b 0d 4a 74 00 00 	mov    rcx,QWORD PTR [rip+0x744a]        # 1400090e0 <the_secs>
   140001c96:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c99:	48 63 d0             	movsxd rdx,eax
   140001c9c:	48 89 d0             	mov    rax,rdx
   140001c9f:	48 c1 e0 02          	shl    rax,0x2
   140001ca3:	48 01 d0             	add    rax,rdx
   140001ca6:	48 c1 e0 03          	shl    rax,0x3
   140001caa:	48 01 c8             	add    rax,rcx
   140001cad:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001cb3:	e8 9f 12 00 00       	call   140002f57 <_GetPEImageBase>
   140001cb8:	48 89 c1             	mov    rcx,rax
   140001cbb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001cbf:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001cc2:	41 89 c1             	mov    r9d,eax
   140001cc5:	4c 8b 05 14 74 00 00 	mov    r8,QWORD PTR [rip+0x7414]        # 1400090e0 <the_secs>
   140001ccc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ccf:	48 63 d0             	movsxd rdx,eax
   140001cd2:	48 89 d0             	mov    rax,rdx
   140001cd5:	48 c1 e0 02          	shl    rax,0x2
   140001cd9:	48 01 d0             	add    rax,rdx
   140001cdc:	48 c1 e0 03          	shl    rax,0x3
   140001ce0:	4c 01 c0             	add    rax,r8
   140001ce3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001ce7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001ceb:	48 8b 0d ee 73 00 00 	mov    rcx,QWORD PTR [rip+0x73ee]        # 1400090e0 <the_secs>
   140001cf2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cf5:	48 63 d0             	movsxd rdx,eax
   140001cf8:	48 89 d0             	mov    rax,rdx
   140001cfb:	48 c1 e0 02          	shl    rax,0x2
   140001cff:	48 01 d0             	add    rax,rdx
   140001d02:	48 c1 e0 03          	shl    rax,0x3
   140001d06:	48 01 c8             	add    rax,rcx
   140001d09:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d0d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d11:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d17:	48 89 c1             	mov    rcx,rax
   140001d1a:	48 8b 05 cf 84 00 00 	mov    rax,QWORD PTR [rip+0x84cf]        # 14000a1f0 <__imp_VirtualQuery>
   140001d21:	ff d0                	call   rax
   140001d23:	48 85 c0             	test   rax,rax
   140001d26:	75 3f                	jne    140001d67 <mark_section_writable+0x1d2>
   140001d28:	48 8b 0d b1 73 00 00 	mov    rcx,QWORD PTR [rip+0x73b1]        # 1400090e0 <the_secs>
   140001d2f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d32:	48 63 d0             	movsxd rdx,eax
   140001d35:	48 89 d0             	mov    rax,rdx
   140001d38:	48 c1 e0 02          	shl    rax,0x2
   140001d3c:	48 01 d0             	add    rax,rdx
   140001d3f:	48 c1 e0 03          	shl    rax,0x3
   140001d43:	48 01 c8             	add    rax,rcx
   140001d46:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d4a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d4e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d51:	89 c1                	mov    ecx,eax
   140001d53:	48 8d 05 b6 34 00 00 	lea    rax,[rip+0x34b6]        # 140005210 <.rdata+0x40>
   140001d5a:	49 89 d0             	mov    r8,rdx
   140001d5d:	89 ca                	mov    edx,ecx
   140001d5f:	48 89 c1             	mov    rcx,rax
   140001d62:	e8 c9 fd ff ff       	call   140001b30 <__report_error>
   140001d67:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d6a:	83 f8 40             	cmp    eax,0x40
   140001d6d:	0f 84 e8 00 00 00    	je     140001e5b <mark_section_writable+0x2c6>
   140001d73:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d76:	83 f8 04             	cmp    eax,0x4
   140001d79:	0f 84 dc 00 00 00    	je     140001e5b <mark_section_writable+0x2c6>
   140001d7f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d82:	3d 80 00 00 00       	cmp    eax,0x80
   140001d87:	0f 84 ce 00 00 00    	je     140001e5b <mark_section_writable+0x2c6>
   140001d8d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d90:	83 f8 08             	cmp    eax,0x8
   140001d93:	0f 84 c2 00 00 00    	je     140001e5b <mark_section_writable+0x2c6>
   140001d99:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d9c:	83 f8 02             	cmp    eax,0x2
   140001d9f:	75 09                	jne    140001daa <mark_section_writable+0x215>
   140001da1:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001da8:	eb 07                	jmp    140001db1 <mark_section_writable+0x21c>
   140001daa:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001db1:	48 8b 0d 28 73 00 00 	mov    rcx,QWORD PTR [rip+0x7328]        # 1400090e0 <the_secs>
   140001db8:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dbb:	48 63 d0             	movsxd rdx,eax
   140001dbe:	48 89 d0             	mov    rax,rdx
   140001dc1:	48 c1 e0 02          	shl    rax,0x2
   140001dc5:	48 01 d0             	add    rax,rdx
   140001dc8:	48 c1 e0 03          	shl    rax,0x3
   140001dcc:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001dd0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001dd4:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001dd8:	48 8b 0d 01 73 00 00 	mov    rcx,QWORD PTR [rip+0x7301]        # 1400090e0 <the_secs>
   140001ddf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001de2:	48 63 d0             	movsxd rdx,eax
   140001de5:	48 89 d0             	mov    rax,rdx
   140001de8:	48 c1 e0 02          	shl    rax,0x2
   140001dec:	48 01 d0             	add    rax,rdx
   140001def:	48 c1 e0 03          	shl    rax,0x3
   140001df3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001df7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001dfb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001dff:	48 8b 0d da 72 00 00 	mov    rcx,QWORD PTR [rip+0x72da]        # 1400090e0 <the_secs>
   140001e06:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e09:	48 63 d0             	movsxd rdx,eax
   140001e0c:	48 89 d0             	mov    rax,rdx
   140001e0f:	48 c1 e0 02          	shl    rax,0x2
   140001e13:	48 01 d0             	add    rax,rdx
   140001e16:	48 c1 e0 03          	shl    rax,0x3
   140001e1a:	48 01 c8             	add    rax,rcx
   140001e1d:	49 89 c0             	mov    r8,rax
   140001e20:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e24:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e28:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e2b:	4d 89 c1             	mov    r9,r8
   140001e2e:	41 89 c8             	mov    r8d,ecx
   140001e31:	48 89 c1             	mov    rcx,rax
   140001e34:	48 8b 05 ad 83 00 00 	mov    rax,QWORD PTR [rip+0x83ad]        # 14000a1e8 <__imp_VirtualProtect>
   140001e3b:	ff d0                	call   rax
   140001e3d:	85 c0                	test   eax,eax
   140001e3f:	75 1a                	jne    140001e5b <mark_section_writable+0x2c6>
   140001e41:	48 8b 05 58 83 00 00 	mov    rax,QWORD PTR [rip+0x8358]        # 14000a1a0 <__imp_GetLastError>
   140001e48:	ff d0                	call   rax
   140001e4a:	89 c2                	mov    edx,eax
   140001e4c:	48 8d 05 f5 33 00 00 	lea    rax,[rip+0x33f5]        # 140005248 <.rdata+0x78>
   140001e53:	48 89 c1             	mov    rcx,rax
   140001e56:	e8 d5 fc ff ff       	call   140001b30 <__report_error>
   140001e5b:	8b 05 87 72 00 00    	mov    eax,DWORD PTR [rip+0x7287]        # 1400090e8 <maxSections>
   140001e61:	83 c0 01             	add    eax,0x1
   140001e64:	89 05 7e 72 00 00    	mov    DWORD PTR [rip+0x727e],eax        # 1400090e8 <maxSections>
   140001e6a:	eb 01                	jmp    140001e6d <mark_section_writable+0x2d8>
   140001e6c:	90                   	nop
   140001e6d:	48 83 c4 60          	add    rsp,0x60
   140001e71:	5d                   	pop    rbp
   140001e72:	c3                   	ret

0000000140001e73 <restore_modified_sections>:
   140001e73:	55                   	push   rbp
   140001e74:	48 89 e5             	mov    rbp,rsp
   140001e77:	48 83 ec 30          	sub    rsp,0x30
   140001e7b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e82:	e9 ad 00 00 00       	jmp    140001f34 <restore_modified_sections+0xc1>
   140001e87:	48 8b 0d 52 72 00 00 	mov    rcx,QWORD PTR [rip+0x7252]        # 1400090e0 <the_secs>
   140001e8e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e91:	48 63 d0             	movsxd rdx,eax
   140001e94:	48 89 d0             	mov    rax,rdx
   140001e97:	48 c1 e0 02          	shl    rax,0x2
   140001e9b:	48 01 d0             	add    rax,rdx
   140001e9e:	48 c1 e0 03          	shl    rax,0x3
   140001ea2:	48 01 c8             	add    rax,rcx
   140001ea5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ea7:	85 c0                	test   eax,eax
   140001ea9:	0f 84 80 00 00 00    	je     140001f2f <restore_modified_sections+0xbc>
   140001eaf:	48 8b 0d 2a 72 00 00 	mov    rcx,QWORD PTR [rip+0x722a]        # 1400090e0 <the_secs>
   140001eb6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eb9:	48 63 d0             	movsxd rdx,eax
   140001ebc:	48 89 d0             	mov    rax,rdx
   140001ebf:	48 c1 e0 02          	shl    rax,0x2
   140001ec3:	48 01 d0             	add    rax,rdx
   140001ec6:	48 c1 e0 03          	shl    rax,0x3
   140001eca:	48 01 c8             	add    rax,rcx
   140001ecd:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001ed0:	48 8b 0d 09 72 00 00 	mov    rcx,QWORD PTR [rip+0x7209]        # 1400090e0 <the_secs>
   140001ed7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eda:	48 63 d0             	movsxd rdx,eax
   140001edd:	48 89 d0             	mov    rax,rdx
   140001ee0:	48 c1 e0 02          	shl    rax,0x2
   140001ee4:	48 01 d0             	add    rax,rdx
   140001ee7:	48 c1 e0 03          	shl    rax,0x3
   140001eeb:	48 01 c8             	add    rax,rcx
   140001eee:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001ef2:	4c 8b 05 e7 71 00 00 	mov    r8,QWORD PTR [rip+0x71e7]        # 1400090e0 <the_secs>
   140001ef9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001efc:	48 63 d0             	movsxd rdx,eax
   140001eff:	48 89 d0             	mov    rax,rdx
   140001f02:	48 c1 e0 02          	shl    rax,0x2
   140001f06:	48 01 d0             	add    rax,rdx
   140001f09:	48 c1 e0 03          	shl    rax,0x3
   140001f0d:	4c 01 c0             	add    rax,r8
   140001f10:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f14:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f18:	49 89 d1             	mov    r9,rdx
   140001f1b:	45 89 d0             	mov    r8d,r10d
   140001f1e:	48 89 ca             	mov    rdx,rcx
   140001f21:	48 89 c1             	mov    rcx,rax
   140001f24:	48 8b 05 bd 82 00 00 	mov    rax,QWORD PTR [rip+0x82bd]        # 14000a1e8 <__imp_VirtualProtect>
   140001f2b:	ff d0                	call   rax
   140001f2d:	eb 01                	jmp    140001f30 <restore_modified_sections+0xbd>
   140001f2f:	90                   	nop
   140001f30:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f34:	8b 05 ae 71 00 00    	mov    eax,DWORD PTR [rip+0x71ae]        # 1400090e8 <maxSections>
   140001f3a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f3d:	0f 8c 44 ff ff ff    	jl     140001e87 <restore_modified_sections+0x14>
   140001f43:	90                   	nop
   140001f44:	90                   	nop
   140001f45:	48 83 c4 30          	add    rsp,0x30
   140001f49:	5d                   	pop    rbp
   140001f4a:	c3                   	ret

0000000140001f4b <__write_memory>:
   140001f4b:	55                   	push   rbp
   140001f4c:	48 89 e5             	mov    rbp,rsp
   140001f4f:	48 83 ec 20          	sub    rsp,0x20
   140001f53:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f57:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f5b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f5f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f64:	74 25                	je     140001f8b <__write_memory+0x40>
   140001f66:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f6a:	48 89 c1             	mov    rcx,rax
   140001f6d:	e8 23 fc ff ff       	call   140001b95 <mark_section_writable>
   140001f72:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f76:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f7a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f7e:	49 89 c8             	mov    r8,rcx
   140001f81:	48 89 c1             	mov    rcx,rax
   140001f84:	e8 37 13 00 00       	call   1400032c0 <memcpy>
   140001f89:	eb 01                	jmp    140001f8c <__write_memory+0x41>
   140001f8b:	90                   	nop
   140001f8c:	48 83 c4 20          	add    rsp,0x20
   140001f90:	5d                   	pop    rbp
   140001f91:	c3                   	ret

0000000140001f92 <do_pseudo_reloc>:
   140001f92:	55                   	push   rbp
   140001f93:	48 89 e5             	mov    rbp,rsp
   140001f96:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001f9a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f9e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001fa2:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001fa6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001faa:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001fae:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001fb2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fb6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001fba:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001fbf:	0f 8e 44 03 00 00    	jle    140002309 <do_pseudo_reloc+0x377>
   140001fc5:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001fca:	7e 25                	jle    140001ff1 <do_pseudo_reloc+0x5f>
   140001fcc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fd0:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fd2:	85 c0                	test   eax,eax
   140001fd4:	75 1b                	jne    140001ff1 <do_pseudo_reloc+0x5f>
   140001fd6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fda:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fdd:	85 c0                	test   eax,eax
   140001fdf:	75 10                	jne    140001ff1 <do_pseudo_reloc+0x5f>
   140001fe1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fe5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001fe8:	85 c0                	test   eax,eax
   140001fea:	75 05                	jne    140001ff1 <do_pseudo_reloc+0x5f>
   140001fec:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140001ff1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001ff5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ff7:	85 c0                	test   eax,eax
   140001ff9:	75 0b                	jne    140002006 <do_pseudo_reloc+0x74>
   140001ffb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fff:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002002:	85 c0                	test   eax,eax
   140002004:	74 59                	je     14000205f <do_pseudo_reloc+0xcd>
   140002006:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000200a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000200e:	eb 40                	jmp    140002050 <do_pseudo_reloc+0xbe>
   140002010:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002014:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002017:	89 c2                	mov    edx,eax
   140002019:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000201d:	48 01 d0             	add    rax,rdx
   140002020:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002024:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002028:	8b 10                	mov    edx,DWORD PTR [rax]
   14000202a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000202e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002030:	01 d0                	add    eax,edx
   140002032:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002035:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002039:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000203d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002043:	48 89 c1             	mov    rcx,rax
   140002046:	e8 00 ff ff ff       	call   140001f4b <__write_memory>
   14000204b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002050:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002054:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002058:	72 b6                	jb     140002010 <do_pseudo_reloc+0x7e>
   14000205a:	e9 ab 02 00 00       	jmp    14000230a <do_pseudo_reloc+0x378>
   14000205f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002063:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002066:	83 f8 01             	cmp    eax,0x1
   140002069:	74 18                	je     140002083 <do_pseudo_reloc+0xf1>
   14000206b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000206f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002072:	89 c2                	mov    edx,eax
   140002074:	48 8d 05 f5 31 00 00 	lea    rax,[rip+0x31f5]        # 140005270 <.rdata+0xa0>
   14000207b:	48 89 c1             	mov    rcx,rax
   14000207e:	e8 ad fa ff ff       	call   140001b30 <__report_error>
   140002083:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002087:	48 83 c0 0c          	add    rax,0xc
   14000208b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000208f:	e9 65 02 00 00       	jmp    1400022f9 <do_pseudo_reloc+0x367>
   140002094:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002098:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000209b:	89 c2                	mov    edx,eax
   14000209d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020a1:	48 01 d0             	add    rax,rdx
   1400020a4:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020a8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020ac:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020ae:	89 c2                	mov    edx,eax
   1400020b0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020b4:	48 01 d0             	add    rax,rdx
   1400020b7:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020bb:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400020bf:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400020c2:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020c6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020ca:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020cd:	0f b6 c0             	movzx  eax,al
   1400020d0:	83 f8 40             	cmp    eax,0x40
   1400020d3:	0f 84 b6 00 00 00    	je     14000218f <do_pseudo_reloc+0x1fd>
   1400020d9:	83 f8 40             	cmp    eax,0x40
   1400020dc:	0f 87 ba 00 00 00    	ja     14000219c <do_pseudo_reloc+0x20a>
   1400020e2:	83 f8 20             	cmp    eax,0x20
   1400020e5:	74 77                	je     14000215e <do_pseudo_reloc+0x1cc>
   1400020e7:	83 f8 20             	cmp    eax,0x20
   1400020ea:	0f 87 ac 00 00 00    	ja     14000219c <do_pseudo_reloc+0x20a>
   1400020f0:	83 f8 08             	cmp    eax,0x8
   1400020f3:	74 0a                	je     1400020ff <do_pseudo_reloc+0x16d>
   1400020f5:	83 f8 10             	cmp    eax,0x10
   1400020f8:	74 38                	je     140002132 <do_pseudo_reloc+0x1a0>
   1400020fa:	e9 9d 00 00 00       	jmp    14000219c <do_pseudo_reloc+0x20a>
   1400020ff:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002103:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002106:	0f b6 c0             	movzx  eax,al
   140002109:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000210d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002111:	25 80 00 00 00       	and    eax,0x80
   140002116:	48 85 c0             	test   rax,rax
   140002119:	0f 84 9d 00 00 00    	je     1400021bc <do_pseudo_reloc+0x22a>
   14000211f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002123:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002129:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000212d:	e9 8a 00 00 00       	jmp    1400021bc <do_pseudo_reloc+0x22a>
   140002132:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002136:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002139:	0f b7 c0             	movzx  eax,ax
   14000213c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002140:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002144:	25 00 80 00 00       	and    eax,0x8000
   140002149:	48 85 c0             	test   rax,rax
   14000214c:	74 71                	je     1400021bf <do_pseudo_reloc+0x22d>
   14000214e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002152:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002158:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000215c:	eb 61                	jmp    1400021bf <do_pseudo_reloc+0x22d>
   14000215e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002162:	8b 00                	mov    eax,DWORD PTR [rax]
   140002164:	89 c0                	mov    eax,eax
   140002166:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000216a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000216e:	25 00 00 00 80       	and    eax,0x80000000
   140002173:	48 85 c0             	test   rax,rax
   140002176:	74 4a                	je     1400021c2 <do_pseudo_reloc+0x230>
   140002178:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000217c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002183:	ff ff ff 
   140002186:	48 09 d0             	or     rax,rdx
   140002189:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000218d:	eb 33                	jmp    1400021c2 <do_pseudo_reloc+0x230>
   14000218f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002193:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002196:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000219a:	eb 27                	jmp    1400021c3 <do_pseudo_reloc+0x231>
   14000219c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   1400021a3:	00 
   1400021a4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021a8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021ab:	0f b6 c0             	movzx  eax,al
   1400021ae:	48 8d 0d f3 30 00 00 	lea    rcx,[rip+0x30f3]        # 1400052a8 <.rdata+0xd8>
   1400021b5:	89 c2                	mov    edx,eax
   1400021b7:	e8 74 f9 ff ff       	call   140001b30 <__report_error>
   1400021bc:	90                   	nop
   1400021bd:	eb 04                	jmp    1400021c3 <do_pseudo_reloc+0x231>
   1400021bf:	90                   	nop
   1400021c0:	eb 01                	jmp    1400021c3 <do_pseudo_reloc+0x231>
   1400021c2:	90                   	nop
   1400021c3:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   1400021c7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021cb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021cd:	89 c2                	mov    edx,eax
   1400021cf:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400021d3:	48 01 c2             	add    rdx,rax
   1400021d6:	48 89 c8             	mov    rax,rcx
   1400021d9:	48 29 d0             	sub    rax,rdx
   1400021dc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021e0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021e4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400021e8:	48 01 d0             	add    rax,rdx
   1400021eb:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ef:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021f3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021f6:	25 ff 00 00 00       	and    eax,0xff
   1400021fb:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400021fe:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002202:	77 67                	ja     14000226b <do_pseudo_reloc+0x2d9>
   140002204:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002207:	ba 01 00 00 00       	mov    edx,0x1
   14000220c:	89 c1                	mov    ecx,eax
   14000220e:	48 d3 e2             	shl    rdx,cl
   140002211:	48 89 d0             	mov    rax,rdx
   140002214:	48 83 e8 01          	sub    rax,0x1
   140002218:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000221c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000221f:	83 e8 01             	sub    eax,0x1
   140002222:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002229:	89 c1                	mov    ecx,eax
   14000222b:	48 d3 e2             	shl    rdx,cl
   14000222e:	48 89 d0             	mov    rax,rdx
   140002231:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002235:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002239:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000223d:	7c 0a                	jl     140002249 <do_pseudo_reloc+0x2b7>
   14000223f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002243:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002247:	7e 22                	jle    14000226b <do_pseudo_reloc+0x2d9>
   140002249:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000224d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002251:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002255:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002258:	48 8d 0d 79 30 00 00 	lea    rcx,[rip+0x3079]        # 1400052d8 <.rdata+0x108>
   14000225f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002264:	89 c2                	mov    edx,eax
   140002266:	e8 c5 f8 ff ff       	call   140001b30 <__report_error>
   14000226b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000226f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002272:	0f b6 c0             	movzx  eax,al
   140002275:	83 f8 40             	cmp    eax,0x40
   140002278:	74 63                	je     1400022dd <do_pseudo_reloc+0x34b>
   14000227a:	83 f8 40             	cmp    eax,0x40
   14000227d:	77 75                	ja     1400022f4 <do_pseudo_reloc+0x362>
   14000227f:	83 f8 20             	cmp    eax,0x20
   140002282:	74 41                	je     1400022c5 <do_pseudo_reloc+0x333>
   140002284:	83 f8 20             	cmp    eax,0x20
   140002287:	77 6b                	ja     1400022f4 <do_pseudo_reloc+0x362>
   140002289:	83 f8 08             	cmp    eax,0x8
   14000228c:	74 07                	je     140002295 <do_pseudo_reloc+0x303>
   14000228e:	83 f8 10             	cmp    eax,0x10
   140002291:	74 1a                	je     1400022ad <do_pseudo_reloc+0x31b>
   140002293:	eb 5f                	jmp    1400022f4 <do_pseudo_reloc+0x362>
   140002295:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002299:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000229d:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400022a3:	48 89 c1             	mov    rcx,rax
   1400022a6:	e8 a0 fc ff ff       	call   140001f4b <__write_memory>
   1400022ab:	eb 47                	jmp    1400022f4 <do_pseudo_reloc+0x362>
   1400022ad:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022b1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022b5:	41 b8 02 00 00 00    	mov    r8d,0x2
   1400022bb:	48 89 c1             	mov    rcx,rax
   1400022be:	e8 88 fc ff ff       	call   140001f4b <__write_memory>
   1400022c3:	eb 2f                	jmp    1400022f4 <do_pseudo_reloc+0x362>
   1400022c5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022c9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022cd:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400022d3:	48 89 c1             	mov    rcx,rax
   1400022d6:	e8 70 fc ff ff       	call   140001f4b <__write_memory>
   1400022db:	eb 17                	jmp    1400022f4 <do_pseudo_reloc+0x362>
   1400022dd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022e1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022e5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400022eb:	48 89 c1             	mov    rcx,rax
   1400022ee:	e8 58 fc ff ff       	call   140001f4b <__write_memory>
   1400022f3:	90                   	nop
   1400022f4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400022f9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022fd:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002301:	0f 82 8d fd ff ff    	jb     140002094 <do_pseudo_reloc+0x102>
   140002307:	eb 01                	jmp    14000230a <do_pseudo_reloc+0x378>
   140002309:	90                   	nop
   14000230a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000230e:	5d                   	pop    rbp
   14000230f:	c3                   	ret

0000000140002310 <_pei386_runtime_relocator>:
   140002310:	55                   	push   rbp
   140002311:	48 89 e5             	mov    rbp,rsp
   140002314:	48 83 ec 30          	sub    rsp,0x30
   140002318:	8b 05 ce 6d 00 00    	mov    eax,DWORD PTR [rip+0x6dce]        # 1400090ec <was_init.0>
   14000231e:	85 c0                	test   eax,eax
   140002320:	0f 85 88 00 00 00    	jne    1400023ae <_pei386_runtime_relocator+0x9e>
   140002326:	8b 05 c0 6d 00 00    	mov    eax,DWORD PTR [rip+0x6dc0]        # 1400090ec <was_init.0>
   14000232c:	83 c0 01             	add    eax,0x1
   14000232f:	89 05 b7 6d 00 00    	mov    DWORD PTR [rip+0x6db7],eax        # 1400090ec <was_init.0>
   140002335:	e8 21 0b 00 00       	call   140002e5b <__mingw_GetSectionCount>
   14000233a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000233d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002340:	48 63 d0             	movsxd rdx,eax
   140002343:	48 89 d0             	mov    rax,rdx
   140002346:	48 c1 e0 02          	shl    rax,0x2
   14000234a:	48 01 d0             	add    rax,rdx
   14000234d:	48 c1 e0 03          	shl    rax,0x3
   140002351:	48 83 c0 0f          	add    rax,0xf
   140002355:	48 c1 e8 04          	shr    rax,0x4
   140002359:	48 c1 e0 04          	shl    rax,0x4
   14000235d:	e8 7e 0d 00 00       	call   1400030e0 <___chkstk_ms>
   140002362:	48 29 c4             	sub    rsp,rax
   140002365:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000236a:	48 83 c0 0f          	add    rax,0xf
   14000236e:	48 c1 e8 04          	shr    rax,0x4
   140002372:	48 c1 e0 04          	shl    rax,0x4
   140002376:	48 89 05 63 6d 00 00 	mov    QWORD PTR [rip+0x6d63],rax        # 1400090e0 <the_secs>
   14000237d:	c7 05 61 6d 00 00 00 	mov    DWORD PTR [rip+0x6d61],0x0        # 1400090e8 <maxSections>
   140002384:	00 00 00 
   140002387:	48 8b 0d d2 2f 00 00 	mov    rcx,QWORD PTR [rip+0x2fd2]        # 140005360 <.refptr.__ImageBase>
   14000238e:	48 8b 15 db 2f 00 00 	mov    rdx,QWORD PTR [rip+0x2fdb]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002395:	48 8b 05 e4 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fe4]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000239c:	49 89 c8             	mov    r8,rcx
   14000239f:	48 89 c1             	mov    rcx,rax
   1400023a2:	e8 eb fb ff ff       	call   140001f92 <do_pseudo_reloc>
   1400023a7:	e8 c7 fa ff ff       	call   140001e73 <restore_modified_sections>
   1400023ac:	eb 01                	jmp    1400023af <_pei386_runtime_relocator+0x9f>
   1400023ae:	90                   	nop
   1400023af:	48 89 ec             	mov    rsp,rbp
   1400023b2:	5d                   	pop    rbp
   1400023b3:	c3                   	ret
   1400023b4:	90                   	nop
   1400023b5:	90                   	nop
   1400023b6:	90                   	nop
   1400023b7:	90                   	nop
   1400023b8:	90                   	nop
   1400023b9:	90                   	nop
   1400023ba:	90                   	nop
   1400023bb:	90                   	nop
   1400023bc:	90                   	nop
   1400023bd:	90                   	nop
   1400023be:	90                   	nop
   1400023bf:	90                   	nop

00000001400023c0 <__mingw_raise_matherr>:
   1400023c0:	55                   	push   rbp
   1400023c1:	48 89 e5             	mov    rbp,rsp
   1400023c4:	48 83 ec 50          	sub    rsp,0x50
   1400023c8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400023cb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400023cf:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   1400023d4:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   1400023d9:	48 8b 05 10 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d10]        # 1400090f0 <stUserMathErr>
   1400023e0:	48 85 c0             	test   rax,rax
   1400023e3:	74 3e                	je     140002423 <__mingw_raise_matherr+0x63>
   1400023e5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400023e8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400023eb:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400023ef:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400023f3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400023f8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400023fd:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002402:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002407:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000240c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002411:	48 8b 15 d8 6c 00 00 	mov    rdx,QWORD PTR [rip+0x6cd8]        # 1400090f0 <stUserMathErr>
   140002418:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000241c:	48 89 c1             	mov    rcx,rax
   14000241f:	ff d2                	call   rdx
   140002421:	eb 01                	jmp    140002424 <__mingw_raise_matherr+0x64>
   140002423:	90                   	nop
   140002424:	48 83 c4 50          	add    rsp,0x50
   140002428:	5d                   	pop    rbp
   140002429:	c3                   	ret

000000014000242a <__mingw_setusermatherr>:
   14000242a:	55                   	push   rbp
   14000242b:	48 89 e5             	mov    rbp,rsp
   14000242e:	48 83 ec 20          	sub    rsp,0x20
   140002432:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002436:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000243a:	48 89 05 af 6c 00 00 	mov    QWORD PTR [rip+0x6caf],rax        # 1400090f0 <stUserMathErr>
   140002441:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002445:	48 89 c1             	mov    rcx,rax
   140002448:	e8 13 0e 00 00       	call   140003260 <__setusermatherr>
   14000244d:	90                   	nop
   14000244e:	48 83 c4 20          	add    rsp,0x20
   140002452:	5d                   	pop    rbp
   140002453:	c3                   	ret
   140002454:	90                   	nop
   140002455:	90                   	nop
   140002456:	90                   	nop
   140002457:	90                   	nop
   140002458:	90                   	nop
   140002459:	90                   	nop
   14000245a:	90                   	nop
   14000245b:	90                   	nop
   14000245c:	90                   	nop
   14000245d:	90                   	nop
   14000245e:	90                   	nop
   14000245f:	90                   	nop

0000000140002460 <__mingw_SEH_error_handler>:
   140002460:	55                   	push   rbp
   140002461:	48 89 e5             	mov    rbp,rsp
   140002464:	48 83 ec 30          	sub    rsp,0x30
   140002468:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000246c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002470:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002474:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002478:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000247f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002486:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000248a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000248d:	83 e0 02             	and    eax,0x2
   140002490:	85 c0                	test   eax,eax
   140002492:	74 0a                	je     14000249e <__mingw_SEH_error_handler+0x3e>
   140002494:	b8 01 00 00 00       	mov    eax,0x1
   140002499:	e9 16 02 00 00       	jmp    1400026b4 <__mingw_SEH_error_handler+0x254>
   14000249e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024a2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024a4:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400024a9:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400024ae:	75 18                	jne    1400024c8 <__mingw_SEH_error_handler+0x68>
   1400024b0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024b4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024b7:	83 e0 01             	and    eax,0x1
   1400024ba:	85 c0                	test   eax,eax
   1400024bc:	75 0a                	jne    1400024c8 <__mingw_SEH_error_handler+0x68>
   1400024be:	b8 00 00 00 00       	mov    eax,0x0
   1400024c3:	e9 ec 01 00 00       	jmp    1400026b4 <__mingw_SEH_error_handler+0x254>
   1400024c8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024cc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024ce:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024d3:	0f 84 12 01 00 00    	je     1400025eb <__mingw_SEH_error_handler+0x18b>
   1400024d9:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024de:	0f 87 c3 01 00 00    	ja     1400026a7 <__mingw_SEH_error_handler+0x247>
   1400024e4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400024e9:	0f 87 b8 01 00 00    	ja     1400026a7 <__mingw_SEH_error_handler+0x247>
   1400024ef:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400024f4:	0f 83 4c 01 00 00    	jae    140002646 <__mingw_SEH_error_handler+0x1e6>
   1400024fa:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024ff:	0f 84 3a 01 00 00    	je     14000263f <__mingw_SEH_error_handler+0x1df>
   140002505:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000250a:	0f 87 97 01 00 00    	ja     1400026a7 <__mingw_SEH_error_handler+0x247>
   140002510:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002515:	0f 84 83 01 00 00    	je     14000269e <__mingw_SEH_error_handler+0x23e>
   14000251b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002520:	0f 87 81 01 00 00    	ja     1400026a7 <__mingw_SEH_error_handler+0x247>
   140002526:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000252b:	0f 87 76 01 00 00    	ja     1400026a7 <__mingw_SEH_error_handler+0x247>
   140002531:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002536:	0f 83 03 01 00 00    	jae    14000263f <__mingw_SEH_error_handler+0x1df>
   14000253c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002541:	0f 84 57 01 00 00    	je     14000269e <__mingw_SEH_error_handler+0x23e>
   140002547:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000254c:	0f 87 55 01 00 00    	ja     1400026a7 <__mingw_SEH_error_handler+0x247>
   140002552:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002557:	0f 84 8e 00 00 00    	je     1400025eb <__mingw_SEH_error_handler+0x18b>
   14000255d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002562:	0f 87 3f 01 00 00    	ja     1400026a7 <__mingw_SEH_error_handler+0x247>
   140002568:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000256d:	0f 84 2b 01 00 00    	je     14000269e <__mingw_SEH_error_handler+0x23e>
   140002573:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002578:	0f 87 29 01 00 00    	ja     1400026a7 <__mingw_SEH_error_handler+0x247>
   14000257e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002583:	0f 84 15 01 00 00    	je     14000269e <__mingw_SEH_error_handler+0x23e>
   140002589:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000258e:	0f 85 13 01 00 00    	jne    1400026a7 <__mingw_SEH_error_handler+0x247>
   140002594:	ba 00 00 00 00       	mov    edx,0x0
   140002599:	b9 0b 00 00 00       	mov    ecx,0xb
   14000259e:	e8 2d 0d 00 00       	call   1400032d0 <signal>
   1400025a3:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025a7:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025ac:	75 1b                	jne    1400025c9 <__mingw_SEH_error_handler+0x169>
   1400025ae:	ba 01 00 00 00       	mov    edx,0x1
   1400025b3:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025b8:	e8 13 0d 00 00       	call   1400032d0 <signal>
   1400025bd:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025c4:	e9 e1 00 00 00       	jmp    1400026aa <__mingw_SEH_error_handler+0x24a>
   1400025c9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025ce:	0f 84 d6 00 00 00    	je     1400026aa <__mingw_SEH_error_handler+0x24a>
   1400025d4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025d8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025dd:	ff d0                	call   rax
   1400025df:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025e6:	e9 bf 00 00 00       	jmp    1400026aa <__mingw_SEH_error_handler+0x24a>
   1400025eb:	ba 00 00 00 00       	mov    edx,0x0
   1400025f0:	b9 04 00 00 00       	mov    ecx,0x4
   1400025f5:	e8 d6 0c 00 00       	call   1400032d0 <signal>
   1400025fa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025fe:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002603:	75 1b                	jne    140002620 <__mingw_SEH_error_handler+0x1c0>
   140002605:	ba 01 00 00 00       	mov    edx,0x1
   14000260a:	b9 04 00 00 00       	mov    ecx,0x4
   14000260f:	e8 bc 0c 00 00       	call   1400032d0 <signal>
   140002614:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000261b:	e9 8d 00 00 00       	jmp    1400026ad <__mingw_SEH_error_handler+0x24d>
   140002620:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002625:	0f 84 82 00 00 00    	je     1400026ad <__mingw_SEH_error_handler+0x24d>
   14000262b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000262f:	b9 04 00 00 00       	mov    ecx,0x4
   140002634:	ff d0                	call   rax
   140002636:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000263d:	eb 6e                	jmp    1400026ad <__mingw_SEH_error_handler+0x24d>
   14000263f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002646:	ba 00 00 00 00       	mov    edx,0x0
   14000264b:	b9 08 00 00 00       	mov    ecx,0x8
   140002650:	e8 7b 0c 00 00       	call   1400032d0 <signal>
   140002655:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002659:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000265e:	75 23                	jne    140002683 <__mingw_SEH_error_handler+0x223>
   140002660:	ba 01 00 00 00       	mov    edx,0x1
   140002665:	b9 08 00 00 00       	mov    ecx,0x8
   14000266a:	e8 61 0c 00 00       	call   1400032d0 <signal>
   14000266f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002673:	74 05                	je     14000267a <__mingw_SEH_error_handler+0x21a>
   140002675:	e8 a6 05 00 00       	call   140002c20 <_fpreset>
   14000267a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002681:	eb 2d                	jmp    1400026b0 <__mingw_SEH_error_handler+0x250>
   140002683:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002688:	74 26                	je     1400026b0 <__mingw_SEH_error_handler+0x250>
   14000268a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000268e:	b9 08 00 00 00       	mov    ecx,0x8
   140002693:	ff d0                	call   rax
   140002695:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000269c:	eb 12                	jmp    1400026b0 <__mingw_SEH_error_handler+0x250>
   14000269e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026a5:	eb 0a                	jmp    1400026b1 <__mingw_SEH_error_handler+0x251>
   1400026a7:	90                   	nop
   1400026a8:	eb 07                	jmp    1400026b1 <__mingw_SEH_error_handler+0x251>
   1400026aa:	90                   	nop
   1400026ab:	eb 04                	jmp    1400026b1 <__mingw_SEH_error_handler+0x251>
   1400026ad:	90                   	nop
   1400026ae:	eb 01                	jmp    1400026b1 <__mingw_SEH_error_handler+0x251>
   1400026b0:	90                   	nop
   1400026b1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400026b4:	48 83 c4 30          	add    rsp,0x30
   1400026b8:	5d                   	pop    rbp
   1400026b9:	c3                   	ret

00000001400026ba <_gnu_exception_handler>:
   1400026ba:	55                   	push   rbp
   1400026bb:	48 89 e5             	mov    rbp,rsp
   1400026be:	48 83 ec 30          	sub    rsp,0x30
   1400026c2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400026c6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026cd:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400026d4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026d8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026db:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026dd:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400026e2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400026e7:	75 1b                	jne    140002704 <_gnu_exception_handler+0x4a>
   1400026e9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026ed:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026f0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400026f3:	83 e0 01             	and    eax,0x1
   1400026f6:	85 c0                	test   eax,eax
   1400026f8:	75 0a                	jne    140002704 <_gnu_exception_handler+0x4a>
   1400026fa:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400026ff:	e9 14 02 00 00       	jmp    140002918 <_gnu_exception_handler+0x25e>
   140002704:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002708:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000270b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000270d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002712:	0f 84 12 01 00 00    	je     14000282a <_gnu_exception_handler+0x170>
   140002718:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000271d:	0f 87 c3 01 00 00    	ja     1400028e6 <_gnu_exception_handler+0x22c>
   140002723:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002728:	0f 87 b8 01 00 00    	ja     1400028e6 <_gnu_exception_handler+0x22c>
   14000272e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002733:	0f 83 4c 01 00 00    	jae    140002885 <_gnu_exception_handler+0x1cb>
   140002739:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000273e:	0f 84 3a 01 00 00    	je     14000287e <_gnu_exception_handler+0x1c4>
   140002744:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002749:	0f 87 97 01 00 00    	ja     1400028e6 <_gnu_exception_handler+0x22c>
   14000274f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002754:	0f 84 83 01 00 00    	je     1400028dd <_gnu_exception_handler+0x223>
   14000275a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000275f:	0f 87 81 01 00 00    	ja     1400028e6 <_gnu_exception_handler+0x22c>
   140002765:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000276a:	0f 87 76 01 00 00    	ja     1400028e6 <_gnu_exception_handler+0x22c>
   140002770:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002775:	0f 83 03 01 00 00    	jae    14000287e <_gnu_exception_handler+0x1c4>
   14000277b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002780:	0f 84 57 01 00 00    	je     1400028dd <_gnu_exception_handler+0x223>
   140002786:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000278b:	0f 87 55 01 00 00    	ja     1400028e6 <_gnu_exception_handler+0x22c>
   140002791:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002796:	0f 84 8e 00 00 00    	je     14000282a <_gnu_exception_handler+0x170>
   14000279c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027a1:	0f 87 3f 01 00 00    	ja     1400028e6 <_gnu_exception_handler+0x22c>
   1400027a7:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027ac:	0f 84 2b 01 00 00    	je     1400028dd <_gnu_exception_handler+0x223>
   1400027b2:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027b7:	0f 87 29 01 00 00    	ja     1400028e6 <_gnu_exception_handler+0x22c>
   1400027bd:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400027c2:	0f 84 15 01 00 00    	je     1400028dd <_gnu_exception_handler+0x223>
   1400027c8:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400027cd:	0f 85 13 01 00 00    	jne    1400028e6 <_gnu_exception_handler+0x22c>
   1400027d3:	ba 00 00 00 00       	mov    edx,0x0
   1400027d8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027dd:	e8 ee 0a 00 00       	call   1400032d0 <signal>
   1400027e2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027e6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027eb:	75 1b                	jne    140002808 <_gnu_exception_handler+0x14e>
   1400027ed:	ba 01 00 00 00       	mov    edx,0x1
   1400027f2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027f7:	e8 d4 0a 00 00       	call   1400032d0 <signal>
   1400027fc:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002803:	e9 e1 00 00 00       	jmp    1400028e9 <_gnu_exception_handler+0x22f>
   140002808:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000280d:	0f 84 d6 00 00 00    	je     1400028e9 <_gnu_exception_handler+0x22f>
   140002813:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002817:	b9 0b 00 00 00       	mov    ecx,0xb
   14000281c:	ff d0                	call   rax
   14000281e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002825:	e9 bf 00 00 00       	jmp    1400028e9 <_gnu_exception_handler+0x22f>
   14000282a:	ba 00 00 00 00       	mov    edx,0x0
   14000282f:	b9 04 00 00 00       	mov    ecx,0x4
   140002834:	e8 97 0a 00 00       	call   1400032d0 <signal>
   140002839:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000283d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002842:	75 1b                	jne    14000285f <_gnu_exception_handler+0x1a5>
   140002844:	ba 01 00 00 00       	mov    edx,0x1
   140002849:	b9 04 00 00 00       	mov    ecx,0x4
   14000284e:	e8 7d 0a 00 00       	call   1400032d0 <signal>
   140002853:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000285a:	e9 8d 00 00 00       	jmp    1400028ec <_gnu_exception_handler+0x232>
   14000285f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002864:	0f 84 82 00 00 00    	je     1400028ec <_gnu_exception_handler+0x232>
   14000286a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000286e:	b9 04 00 00 00       	mov    ecx,0x4
   140002873:	ff d0                	call   rax
   140002875:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000287c:	eb 6e                	jmp    1400028ec <_gnu_exception_handler+0x232>
   14000287e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002885:	ba 00 00 00 00       	mov    edx,0x0
   14000288a:	b9 08 00 00 00       	mov    ecx,0x8
   14000288f:	e8 3c 0a 00 00       	call   1400032d0 <signal>
   140002894:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002898:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000289d:	75 23                	jne    1400028c2 <_gnu_exception_handler+0x208>
   14000289f:	ba 01 00 00 00       	mov    edx,0x1
   1400028a4:	b9 08 00 00 00       	mov    ecx,0x8
   1400028a9:	e8 22 0a 00 00       	call   1400032d0 <signal>
   1400028ae:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400028b2:	74 05                	je     1400028b9 <_gnu_exception_handler+0x1ff>
   1400028b4:	e8 67 03 00 00       	call   140002c20 <_fpreset>
   1400028b9:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028c0:	eb 2d                	jmp    1400028ef <_gnu_exception_handler+0x235>
   1400028c2:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028c7:	74 26                	je     1400028ef <_gnu_exception_handler+0x235>
   1400028c9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028cd:	b9 08 00 00 00       	mov    ecx,0x8
   1400028d2:	ff d0                	call   rax
   1400028d4:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028db:	eb 12                	jmp    1400028ef <_gnu_exception_handler+0x235>
   1400028dd:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028e4:	eb 0a                	jmp    1400028f0 <_gnu_exception_handler+0x236>
   1400028e6:	90                   	nop
   1400028e7:	eb 07                	jmp    1400028f0 <_gnu_exception_handler+0x236>
   1400028e9:	90                   	nop
   1400028ea:	eb 04                	jmp    1400028f0 <_gnu_exception_handler+0x236>
   1400028ec:	90                   	nop
   1400028ed:	eb 01                	jmp    1400028f0 <_gnu_exception_handler+0x236>
   1400028ef:	90                   	nop
   1400028f0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400028f4:	75 1f                	jne    140002915 <_gnu_exception_handler+0x25b>
   1400028f6:	48 8b 05 13 68 00 00 	mov    rax,QWORD PTR [rip+0x6813]        # 140009110 <__mingw_oldexcpt_handler>
   1400028fd:	48 85 c0             	test   rax,rax
   140002900:	74 13                	je     140002915 <_gnu_exception_handler+0x25b>
   140002902:	48 8b 15 07 68 00 00 	mov    rdx,QWORD PTR [rip+0x6807]        # 140009110 <__mingw_oldexcpt_handler>
   140002909:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000290d:	48 89 c1             	mov    rcx,rax
   140002910:	ff d2                	call   rdx
   140002912:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002915:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002918:	48 83 c4 30          	add    rsp,0x30
   14000291c:	5d                   	pop    rbp
   14000291d:	c3                   	ret
   14000291e:	90                   	nop
   14000291f:	90                   	nop

0000000140002920 <___w64_mingwthr_add_key_dtor>:
   140002920:	55                   	push   rbp
   140002921:	48 89 e5             	mov    rbp,rsp
   140002924:	48 83 ec 30          	sub    rsp,0x30
   140002928:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000292b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000292f:	8b 05 13 68 00 00    	mov    eax,DWORD PTR [rip+0x6813]        # 140009148 <__mingwthr_cs_init>
   140002935:	85 c0                	test   eax,eax
   140002937:	75 07                	jne    140002940 <___w64_mingwthr_add_key_dtor+0x20>
   140002939:	b8 00 00 00 00       	mov    eax,0x0
   14000293e:	eb 7b                	jmp    1400029bb <___w64_mingwthr_add_key_dtor+0x9b>
   140002940:	ba 18 00 00 00       	mov    edx,0x18
   140002945:	b9 01 00 00 00       	mov    ecx,0x1
   14000294a:	e8 41 09 00 00       	call   140003290 <calloc>
   14000294f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002953:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002958:	75 07                	jne    140002961 <___w64_mingwthr_add_key_dtor+0x41>
   14000295a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000295f:	eb 5a                	jmp    1400029bb <___w64_mingwthr_add_key_dtor+0x9b>
   140002961:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002965:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002968:	89 10                	mov    DWORD PTR [rax],edx
   14000296a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000296e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002972:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002976:	48 8d 05 a3 67 00 00 	lea    rax,[rip+0x67a3]        # 140009120 <__mingwthr_cs>
   14000297d:	48 89 c1             	mov    rcx,rax
   140002980:	48 8b 05 09 78 00 00 	mov    rax,QWORD PTR [rip+0x7809]        # 14000a190 <__imp_EnterCriticalSection>
   140002987:	ff d0                	call   rax
   140002989:	48 8b 15 c0 67 00 00 	mov    rdx,QWORD PTR [rip+0x67c0]        # 140009150 <key_dtor_list>
   140002990:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002994:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002998:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000299c:	48 89 05 ad 67 00 00 	mov    QWORD PTR [rip+0x67ad],rax        # 140009150 <key_dtor_list>
   1400029a3:	48 8d 05 76 67 00 00 	lea    rax,[rip+0x6776]        # 140009120 <__mingwthr_cs>
   1400029aa:	48 89 c1             	mov    rcx,rax
   1400029ad:	48 8b 05 0c 78 00 00 	mov    rax,QWORD PTR [rip+0x780c]        # 14000a1c0 <__imp_LeaveCriticalSection>
   1400029b4:	ff d0                	call   rax
   1400029b6:	b8 00 00 00 00       	mov    eax,0x0
   1400029bb:	48 83 c4 30          	add    rsp,0x30
   1400029bf:	5d                   	pop    rbp
   1400029c0:	c3                   	ret

00000001400029c1 <___w64_mingwthr_remove_key_dtor>:
   1400029c1:	55                   	push   rbp
   1400029c2:	48 89 e5             	mov    rbp,rsp
   1400029c5:	48 83 ec 30          	sub    rsp,0x30
   1400029c9:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029cc:	8b 05 76 67 00 00    	mov    eax,DWORD PTR [rip+0x6776]        # 140009148 <__mingwthr_cs_init>
   1400029d2:	85 c0                	test   eax,eax
   1400029d4:	75 0a                	jne    1400029e0 <___w64_mingwthr_remove_key_dtor+0x1f>
   1400029d6:	b8 00 00 00 00       	mov    eax,0x0
   1400029db:	e9 9c 00 00 00       	jmp    140002a7c <___w64_mingwthr_remove_key_dtor+0xbb>
   1400029e0:	48 8d 05 39 67 00 00 	lea    rax,[rip+0x6739]        # 140009120 <__mingwthr_cs>
   1400029e7:	48 89 c1             	mov    rcx,rax
   1400029ea:	48 8b 05 9f 77 00 00 	mov    rax,QWORD PTR [rip+0x779f]        # 14000a190 <__imp_EnterCriticalSection>
   1400029f1:	ff d0                	call   rax
   1400029f3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400029fa:	00 
   1400029fb:	48 8b 05 4e 67 00 00 	mov    rax,QWORD PTR [rip+0x674e]        # 140009150 <key_dtor_list>
   140002a02:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a06:	eb 55                	jmp    140002a5d <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a08:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a0c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a0e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a11:	75 36                	jne    140002a49 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a13:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a18:	75 11                	jne    140002a2b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a1a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a1e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a22:	48 89 05 27 67 00 00 	mov    QWORD PTR [rip+0x6727],rax        # 140009150 <key_dtor_list>
   140002a29:	eb 10                	jmp    140002a3b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a2b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a2f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a33:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a37:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a3b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a3f:	48 89 c1             	mov    rcx,rax
   140002a42:	e8 69 08 00 00       	call   1400032b0 <free>
   140002a47:	eb 1b                	jmp    140002a64 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a49:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a4d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a51:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a55:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a59:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a5d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a62:	75 a4                	jne    140002a08 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a64:	48 8d 05 b5 66 00 00 	lea    rax,[rip+0x66b5]        # 140009120 <__mingwthr_cs>
   140002a6b:	48 89 c1             	mov    rcx,rax
   140002a6e:	48 8b 05 4b 77 00 00 	mov    rax,QWORD PTR [rip+0x774b]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002a75:	ff d0                	call   rax
   140002a77:	b8 00 00 00 00       	mov    eax,0x0
   140002a7c:	48 83 c4 30          	add    rsp,0x30
   140002a80:	5d                   	pop    rbp
   140002a81:	c3                   	ret

0000000140002a82 <__mingwthr_run_key_dtors>:
   140002a82:	55                   	push   rbp
   140002a83:	48 89 e5             	mov    rbp,rsp
   140002a86:	48 83 ec 30          	sub    rsp,0x30
   140002a8a:	8b 05 b8 66 00 00    	mov    eax,DWORD PTR [rip+0x66b8]        # 140009148 <__mingwthr_cs_init>
   140002a90:	85 c0                	test   eax,eax
   140002a92:	0f 84 82 00 00 00    	je     140002b1a <__mingwthr_run_key_dtors+0x98>
   140002a98:	48 8d 05 81 66 00 00 	lea    rax,[rip+0x6681]        # 140009120 <__mingwthr_cs>
   140002a9f:	48 89 c1             	mov    rcx,rax
   140002aa2:	48 8b 05 e7 76 00 00 	mov    rax,QWORD PTR [rip+0x76e7]        # 14000a190 <__imp_EnterCriticalSection>
   140002aa9:	ff d0                	call   rax
   140002aab:	48 8b 05 9e 66 00 00 	mov    rax,QWORD PTR [rip+0x669e]        # 140009150 <key_dtor_list>
   140002ab2:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ab6:	eb 46                	jmp    140002afe <__mingwthr_run_key_dtors+0x7c>
   140002ab8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002abc:	8b 00                	mov    eax,DWORD PTR [rax]
   140002abe:	89 c1                	mov    ecx,eax
   140002ac0:	48 8b 05 19 77 00 00 	mov    rax,QWORD PTR [rip+0x7719]        # 14000a1e0 <__imp_TlsGetValue>
   140002ac7:	ff d0                	call   rax
   140002ac9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002acd:	48 8b 05 cc 76 00 00 	mov    rax,QWORD PTR [rip+0x76cc]        # 14000a1a0 <__imp_GetLastError>
   140002ad4:	ff d0                	call   rax
   140002ad6:	85 c0                	test   eax,eax
   140002ad8:	75 18                	jne    140002af2 <__mingwthr_run_key_dtors+0x70>
   140002ada:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002adf:	74 11                	je     140002af2 <__mingwthr_run_key_dtors+0x70>
   140002ae1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ae5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002ae9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aed:	48 89 c1             	mov    rcx,rax
   140002af0:	ff d2                	call   rdx
   140002af2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002af6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002afa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002afe:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b03:	75 b3                	jne    140002ab8 <__mingwthr_run_key_dtors+0x36>
   140002b05:	48 8d 05 14 66 00 00 	lea    rax,[rip+0x6614]        # 140009120 <__mingwthr_cs>
   140002b0c:	48 89 c1             	mov    rcx,rax
   140002b0f:	48 8b 05 aa 76 00 00 	mov    rax,QWORD PTR [rip+0x76aa]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002b16:	ff d0                	call   rax
   140002b18:	eb 01                	jmp    140002b1b <__mingwthr_run_key_dtors+0x99>
   140002b1a:	90                   	nop
   140002b1b:	48 83 c4 30          	add    rsp,0x30
   140002b1f:	5d                   	pop    rbp
   140002b20:	c3                   	ret

0000000140002b21 <__mingw_TLScallback>:
   140002b21:	55                   	push   rbp
   140002b22:	48 89 e5             	mov    rbp,rsp
   140002b25:	48 83 ec 30          	sub    rsp,0x30
   140002b29:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b2d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b30:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b34:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b38:	0f 84 cc 00 00 00    	je     140002c0a <__mingw_TLScallback+0xe9>
   140002b3e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b42:	0f 87 ca 00 00 00    	ja     140002c12 <__mingw_TLScallback+0xf1>
   140002b48:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b4c:	0f 84 b1 00 00 00    	je     140002c03 <__mingw_TLScallback+0xe2>
   140002b52:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b56:	0f 87 b6 00 00 00    	ja     140002c12 <__mingw_TLScallback+0xf1>
   140002b5c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b60:	74 33                	je     140002b95 <__mingw_TLScallback+0x74>
   140002b62:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b66:	0f 85 a6 00 00 00    	jne    140002c12 <__mingw_TLScallback+0xf1>
   140002b6c:	8b 05 d6 65 00 00    	mov    eax,DWORD PTR [rip+0x65d6]        # 140009148 <__mingwthr_cs_init>
   140002b72:	85 c0                	test   eax,eax
   140002b74:	75 13                	jne    140002b89 <__mingw_TLScallback+0x68>
   140002b76:	48 8d 05 a3 65 00 00 	lea    rax,[rip+0x65a3]        # 140009120 <__mingwthr_cs>
   140002b7d:	48 89 c1             	mov    rcx,rax
   140002b80:	48 8b 05 31 76 00 00 	mov    rax,QWORD PTR [rip+0x7631]        # 14000a1b8 <__imp_InitializeCriticalSection>
   140002b87:	ff d0                	call   rax
   140002b89:	c7 05 b5 65 00 00 01 	mov    DWORD PTR [rip+0x65b5],0x1        # 140009148 <__mingwthr_cs_init>
   140002b90:	00 00 00 
   140002b93:	eb 7d                	jmp    140002c12 <__mingw_TLScallback+0xf1>
   140002b95:	e8 e8 fe ff ff       	call   140002a82 <__mingwthr_run_key_dtors>
   140002b9a:	8b 05 a8 65 00 00    	mov    eax,DWORD PTR [rip+0x65a8]        # 140009148 <__mingwthr_cs_init>
   140002ba0:	83 f8 01             	cmp    eax,0x1
   140002ba3:	75 6c                	jne    140002c11 <__mingw_TLScallback+0xf0>
   140002ba5:	48 8b 05 a4 65 00 00 	mov    rax,QWORD PTR [rip+0x65a4]        # 140009150 <key_dtor_list>
   140002bac:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bb0:	eb 20                	jmp    140002bd2 <__mingw_TLScallback+0xb1>
   140002bb2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bb6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002bba:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002bbe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bc2:	48 89 c1             	mov    rcx,rax
   140002bc5:	e8 e6 06 00 00       	call   1400032b0 <free>
   140002bca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bce:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bd2:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002bd7:	75 d9                	jne    140002bb2 <__mingw_TLScallback+0x91>
   140002bd9:	48 c7 05 6c 65 00 00 	mov    QWORD PTR [rip+0x656c],0x0        # 140009150 <key_dtor_list>
   140002be0:	00 00 00 00 
   140002be4:	c7 05 5a 65 00 00 00 	mov    DWORD PTR [rip+0x655a],0x0        # 140009148 <__mingwthr_cs_init>
   140002beb:	00 00 00 
   140002bee:	48 8d 05 2b 65 00 00 	lea    rax,[rip+0x652b]        # 140009120 <__mingwthr_cs>
   140002bf5:	48 89 c1             	mov    rcx,rax
   140002bf8:	48 8b 05 89 75 00 00 	mov    rax,QWORD PTR [rip+0x7589]        # 14000a188 <__IAT_start__>
   140002bff:	ff d0                	call   rax
   140002c01:	eb 0e                	jmp    140002c11 <__mingw_TLScallback+0xf0>
   140002c03:	e8 18 00 00 00       	call   140002c20 <_fpreset>
   140002c08:	eb 08                	jmp    140002c12 <__mingw_TLScallback+0xf1>
   140002c0a:	e8 73 fe ff ff       	call   140002a82 <__mingwthr_run_key_dtors>
   140002c0f:	eb 01                	jmp    140002c12 <__mingw_TLScallback+0xf1>
   140002c11:	90                   	nop
   140002c12:	b8 01 00 00 00       	mov    eax,0x1
   140002c17:	48 83 c4 30          	add    rsp,0x30
   140002c1b:	5d                   	pop    rbp
   140002c1c:	c3                   	ret
   140002c1d:	90                   	nop
   140002c1e:	90                   	nop
   140002c1f:	90                   	nop

0000000140002c20 <_fpreset>:
   140002c20:	55                   	push   rbp
   140002c21:	48 89 e5             	mov    rbp,rsp
   140002c24:	db e3                	fninit
   140002c26:	90                   	nop
   140002c27:	5d                   	pop    rbp
   140002c28:	c3                   	ret
   140002c29:	90                   	nop
   140002c2a:	90                   	nop
   140002c2b:	90                   	nop
   140002c2c:	90                   	nop
   140002c2d:	90                   	nop
   140002c2e:	90                   	nop
   140002c2f:	90                   	nop

0000000140002c30 <_ValidateImageBase>:
   140002c30:	55                   	push   rbp
   140002c31:	48 89 e5             	mov    rbp,rsp
   140002c34:	48 83 ec 20          	sub    rsp,0x20
   140002c38:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c3c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c40:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c44:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c48:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c4b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c4f:	74 07                	je     140002c58 <_ValidateImageBase+0x28>
   140002c51:	b8 00 00 00 00       	mov    eax,0x0
   140002c56:	eb 4e                	jmp    140002ca6 <_ValidateImageBase+0x76>
   140002c58:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c5c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c5f:	48 63 d0             	movsxd rdx,eax
   140002c62:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c66:	48 01 d0             	add    rax,rdx
   140002c69:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c6d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c71:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c73:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c78:	74 07                	je     140002c81 <_ValidateImageBase+0x51>
   140002c7a:	b8 00 00 00 00       	mov    eax,0x0
   140002c7f:	eb 25                	jmp    140002ca6 <_ValidateImageBase+0x76>
   140002c81:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c85:	48 83 c0 18          	add    rax,0x18
   140002c89:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c8d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c91:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c94:	66 3d 0b 02          	cmp    ax,0x20b
   140002c98:	74 07                	je     140002ca1 <_ValidateImageBase+0x71>
   140002c9a:	b8 00 00 00 00       	mov    eax,0x0
   140002c9f:	eb 05                	jmp    140002ca6 <_ValidateImageBase+0x76>
   140002ca1:	b8 01 00 00 00       	mov    eax,0x1
   140002ca6:	48 83 c4 20          	add    rsp,0x20
   140002caa:	5d                   	pop    rbp
   140002cab:	c3                   	ret

0000000140002cac <_FindPESection>:
   140002cac:	55                   	push   rbp
   140002cad:	48 89 e5             	mov    rbp,rsp
   140002cb0:	48 83 ec 20          	sub    rsp,0x20
   140002cb4:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002cb8:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002cbc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cc0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002cc3:	48 63 d0             	movsxd rdx,eax
   140002cc6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cca:	48 01 d0             	add    rax,rdx
   140002ccd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002cd1:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002cd8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cdc:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002ce0:	0f b7 d0             	movzx  edx,ax
   140002ce3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ce7:	48 01 d0             	add    rax,rdx
   140002cea:	48 83 c0 18          	add    rax,0x18
   140002cee:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cf2:	eb 36                	jmp    140002d2a <_FindPESection+0x7e>
   140002cf4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cf8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002cfb:	89 c0                	mov    eax,eax
   140002cfd:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d01:	72 1e                	jb     140002d21 <_FindPESection+0x75>
   140002d03:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d07:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d0a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d0e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d11:	01 d0                	add    eax,edx
   140002d13:	89 c0                	mov    eax,eax
   140002d15:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d19:	73 06                	jae    140002d21 <_FindPESection+0x75>
   140002d1b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d1f:	eb 1e                	jmp    140002d3f <_FindPESection+0x93>
   140002d21:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d25:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d2a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d2e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d32:	0f b7 c0             	movzx  eax,ax
   140002d35:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d38:	72 ba                	jb     140002cf4 <_FindPESection+0x48>
   140002d3a:	b8 00 00 00 00       	mov    eax,0x0
   140002d3f:	48 83 c4 20          	add    rsp,0x20
   140002d43:	5d                   	pop    rbp
   140002d44:	c3                   	ret

0000000140002d45 <_FindPESectionByName>:
   140002d45:	55                   	push   rbp
   140002d46:	48 89 e5             	mov    rbp,rsp
   140002d49:	48 83 ec 40          	sub    rsp,0x40
   140002d4d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d51:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d55:	48 89 c1             	mov    rcx,rax
   140002d58:	e8 7b 05 00 00       	call   1400032d8 <strlen>
   140002d5d:	48 83 f8 08          	cmp    rax,0x8
   140002d61:	76 0a                	jbe    140002d6d <_FindPESectionByName+0x28>
   140002d63:	b8 00 00 00 00       	mov    eax,0x0
   140002d68:	e9 98 00 00 00       	jmp    140002e05 <_FindPESectionByName+0xc0>
   140002d6d:	48 8b 05 ec 25 00 00 	mov    rax,QWORD PTR [rip+0x25ec]        # 140005360 <.refptr.__ImageBase>
   140002d74:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d78:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d7c:	48 89 c1             	mov    rcx,rax
   140002d7f:	e8 ac fe ff ff       	call   140002c30 <_ValidateImageBase>
   140002d84:	85 c0                	test   eax,eax
   140002d86:	75 07                	jne    140002d8f <_FindPESectionByName+0x4a>
   140002d88:	b8 00 00 00 00       	mov    eax,0x0
   140002d8d:	eb 76                	jmp    140002e05 <_FindPESectionByName+0xc0>
   140002d8f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d93:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d96:	48 63 d0             	movsxd rdx,eax
   140002d99:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d9d:	48 01 d0             	add    rax,rdx
   140002da0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002da4:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002dab:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002daf:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002db3:	0f b7 d0             	movzx  edx,ax
   140002db6:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dba:	48 01 d0             	add    rax,rdx
   140002dbd:	48 83 c0 18          	add    rax,0x18
   140002dc1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002dc5:	eb 29                	jmp    140002df0 <_FindPESectionByName+0xab>
   140002dc7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dcb:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002dcf:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002dd5:	48 89 c1             	mov    rcx,rax
   140002dd8:	e8 03 05 00 00       	call   1400032e0 <strncmp>
   140002ddd:	85 c0                	test   eax,eax
   140002ddf:	75 06                	jne    140002de7 <_FindPESectionByName+0xa2>
   140002de1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002de5:	eb 1e                	jmp    140002e05 <_FindPESectionByName+0xc0>
   140002de7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002deb:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002df0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002df4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002df8:	0f b7 c0             	movzx  eax,ax
   140002dfb:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002dfe:	72 c7                	jb     140002dc7 <_FindPESectionByName+0x82>
   140002e00:	b8 00 00 00 00       	mov    eax,0x0
   140002e05:	48 83 c4 40          	add    rsp,0x40
   140002e09:	5d                   	pop    rbp
   140002e0a:	c3                   	ret

0000000140002e0b <__mingw_GetSectionForAddress>:
   140002e0b:	55                   	push   rbp
   140002e0c:	48 89 e5             	mov    rbp,rsp
   140002e0f:	48 83 ec 30          	sub    rsp,0x30
   140002e13:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e17:	48 8b 05 42 25 00 00 	mov    rax,QWORD PTR [rip+0x2542]        # 140005360 <.refptr.__ImageBase>
   140002e1e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e22:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e26:	48 89 c1             	mov    rcx,rax
   140002e29:	e8 02 fe ff ff       	call   140002c30 <_ValidateImageBase>
   140002e2e:	85 c0                	test   eax,eax
   140002e30:	75 07                	jne    140002e39 <__mingw_GetSectionForAddress+0x2e>
   140002e32:	b8 00 00 00 00       	mov    eax,0x0
   140002e37:	eb 1c                	jmp    140002e55 <__mingw_GetSectionForAddress+0x4a>
   140002e39:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e3d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e41:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e45:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e49:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e4d:	48 89 c1             	mov    rcx,rax
   140002e50:	e8 57 fe ff ff       	call   140002cac <_FindPESection>
   140002e55:	48 83 c4 30          	add    rsp,0x30
   140002e59:	5d                   	pop    rbp
   140002e5a:	c3                   	ret

0000000140002e5b <__mingw_GetSectionCount>:
   140002e5b:	55                   	push   rbp
   140002e5c:	48 89 e5             	mov    rbp,rsp
   140002e5f:	48 83 ec 30          	sub    rsp,0x30
   140002e63:	48 8b 05 f6 24 00 00 	mov    rax,QWORD PTR [rip+0x24f6]        # 140005360 <.refptr.__ImageBase>
   140002e6a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e6e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e72:	48 89 c1             	mov    rcx,rax
   140002e75:	e8 b6 fd ff ff       	call   140002c30 <_ValidateImageBase>
   140002e7a:	85 c0                	test   eax,eax
   140002e7c:	75 07                	jne    140002e85 <__mingw_GetSectionCount+0x2a>
   140002e7e:	b8 00 00 00 00       	mov    eax,0x0
   140002e83:	eb 20                	jmp    140002ea5 <__mingw_GetSectionCount+0x4a>
   140002e85:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e89:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e8c:	48 63 d0             	movsxd rdx,eax
   140002e8f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e93:	48 01 d0             	add    rax,rdx
   140002e96:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e9a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e9e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ea2:	0f b7 c0             	movzx  eax,ax
   140002ea5:	48 83 c4 30          	add    rsp,0x30
   140002ea9:	5d                   	pop    rbp
   140002eaa:	c3                   	ret

0000000140002eab <_FindPESectionExec>:
   140002eab:	55                   	push   rbp
   140002eac:	48 89 e5             	mov    rbp,rsp
   140002eaf:	48 83 ec 40          	sub    rsp,0x40
   140002eb3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002eb7:	48 8b 05 a2 24 00 00 	mov    rax,QWORD PTR [rip+0x24a2]        # 140005360 <.refptr.__ImageBase>
   140002ebe:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ec2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ec6:	48 89 c1             	mov    rcx,rax
   140002ec9:	e8 62 fd ff ff       	call   140002c30 <_ValidateImageBase>
   140002ece:	85 c0                	test   eax,eax
   140002ed0:	75 07                	jne    140002ed9 <_FindPESectionExec+0x2e>
   140002ed2:	b8 00 00 00 00       	mov    eax,0x0
   140002ed7:	eb 78                	jmp    140002f51 <_FindPESectionExec+0xa6>
   140002ed9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002edd:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ee0:	48 63 d0             	movsxd rdx,eax
   140002ee3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ee7:	48 01 d0             	add    rax,rdx
   140002eea:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002eee:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ef5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ef9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002efd:	0f b7 d0             	movzx  edx,ax
   140002f00:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f04:	48 01 d0             	add    rax,rdx
   140002f07:	48 83 c0 18          	add    rax,0x18
   140002f0b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f0f:	eb 2b                	jmp    140002f3c <_FindPESectionExec+0x91>
   140002f11:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f15:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f18:	25 00 00 00 20       	and    eax,0x20000000
   140002f1d:	85 c0                	test   eax,eax
   140002f1f:	74 12                	je     140002f33 <_FindPESectionExec+0x88>
   140002f21:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f26:	75 06                	jne    140002f2e <_FindPESectionExec+0x83>
   140002f28:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f2c:	eb 23                	jmp    140002f51 <_FindPESectionExec+0xa6>
   140002f2e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f33:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f37:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f3c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f40:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f44:	0f b7 c0             	movzx  eax,ax
   140002f47:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f4a:	72 c5                	jb     140002f11 <_FindPESectionExec+0x66>
   140002f4c:	b8 00 00 00 00       	mov    eax,0x0
   140002f51:	48 83 c4 40          	add    rsp,0x40
   140002f55:	5d                   	pop    rbp
   140002f56:	c3                   	ret

0000000140002f57 <_GetPEImageBase>:
   140002f57:	55                   	push   rbp
   140002f58:	48 89 e5             	mov    rbp,rsp
   140002f5b:	48 83 ec 30          	sub    rsp,0x30
   140002f5f:	48 8b 05 fa 23 00 00 	mov    rax,QWORD PTR [rip+0x23fa]        # 140005360 <.refptr.__ImageBase>
   140002f66:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f6a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f6e:	48 89 c1             	mov    rcx,rax
   140002f71:	e8 ba fc ff ff       	call   140002c30 <_ValidateImageBase>
   140002f76:	85 c0                	test   eax,eax
   140002f78:	75 07                	jne    140002f81 <_GetPEImageBase+0x2a>
   140002f7a:	b8 00 00 00 00       	mov    eax,0x0
   140002f7f:	eb 04                	jmp    140002f85 <_GetPEImageBase+0x2e>
   140002f81:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f85:	48 83 c4 30          	add    rsp,0x30
   140002f89:	5d                   	pop    rbp
   140002f8a:	c3                   	ret

0000000140002f8b <_IsNonwritableInCurrentImage>:
   140002f8b:	55                   	push   rbp
   140002f8c:	48 89 e5             	mov    rbp,rsp
   140002f8f:	48 83 ec 40          	sub    rsp,0x40
   140002f93:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f97:	48 8b 05 c2 23 00 00 	mov    rax,QWORD PTR [rip+0x23c2]        # 140005360 <.refptr.__ImageBase>
   140002f9e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fa2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fa6:	48 89 c1             	mov    rcx,rax
   140002fa9:	e8 82 fc ff ff       	call   140002c30 <_ValidateImageBase>
   140002fae:	85 c0                	test   eax,eax
   140002fb0:	75 07                	jne    140002fb9 <_IsNonwritableInCurrentImage+0x2e>
   140002fb2:	b8 00 00 00 00       	mov    eax,0x0
   140002fb7:	eb 3d                	jmp    140002ff6 <_IsNonwritableInCurrentImage+0x6b>
   140002fb9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002fbd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002fc1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fc5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002fc9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fcd:	48 89 c1             	mov    rcx,rax
   140002fd0:	e8 d7 fc ff ff       	call   140002cac <_FindPESection>
   140002fd5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002fd9:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002fde:	75 07                	jne    140002fe7 <_IsNonwritableInCurrentImage+0x5c>
   140002fe0:	b8 00 00 00 00       	mov    eax,0x0
   140002fe5:	eb 0f                	jmp    140002ff6 <_IsNonwritableInCurrentImage+0x6b>
   140002fe7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002feb:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fee:	f7 d0                	not    eax
   140002ff0:	c1 e8 1f             	shr    eax,0x1f
   140002ff3:	0f b6 c0             	movzx  eax,al
   140002ff6:	48 83 c4 40          	add    rsp,0x40
   140002ffa:	5d                   	pop    rbp
   140002ffb:	c3                   	ret

0000000140002ffc <__mingw_enum_import_library_names>:
   140002ffc:	55                   	push   rbp
   140002ffd:	48 89 e5             	mov    rbp,rsp
   140003000:	48 83 ec 50          	sub    rsp,0x50
   140003004:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003007:	48 8b 05 52 23 00 00 	mov    rax,QWORD PTR [rip+0x2352]        # 140005360 <.refptr.__ImageBase>
   14000300e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003012:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003016:	48 89 c1             	mov    rcx,rax
   140003019:	e8 12 fc ff ff       	call   140002c30 <_ValidateImageBase>
   14000301e:	85 c0                	test   eax,eax
   140003020:	75 0a                	jne    14000302c <__mingw_enum_import_library_names+0x30>
   140003022:	b8 00 00 00 00       	mov    eax,0x0
   140003027:	e9 ab 00 00 00       	jmp    1400030d7 <__mingw_enum_import_library_names+0xdb>
   14000302c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003030:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003033:	48 63 d0             	movsxd rdx,eax
   140003036:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000303a:	48 01 d0             	add    rax,rdx
   14000303d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003041:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003045:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000304b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000304e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003052:	75 07                	jne    14000305b <__mingw_enum_import_library_names+0x5f>
   140003054:	b8 00 00 00 00       	mov    eax,0x0
   140003059:	eb 7c                	jmp    1400030d7 <__mingw_enum_import_library_names+0xdb>
   14000305b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000305e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003062:	48 89 c1             	mov    rcx,rax
   140003065:	e8 42 fc ff ff       	call   140002cac <_FindPESection>
   14000306a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000306e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003073:	75 07                	jne    14000307c <__mingw_enum_import_library_names+0x80>
   140003075:	b8 00 00 00 00       	mov    eax,0x0
   14000307a:	eb 5b                	jmp    1400030d7 <__mingw_enum_import_library_names+0xdb>
   14000307c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000307f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003083:	48 01 d0             	add    rax,rdx
   140003086:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000308a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000308f:	75 07                	jne    140003098 <__mingw_enum_import_library_names+0x9c>
   140003091:	b8 00 00 00 00       	mov    eax,0x0
   140003096:	eb 3f                	jmp    1400030d7 <__mingw_enum_import_library_names+0xdb>
   140003098:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000309c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000309f:	85 c0                	test   eax,eax
   1400030a1:	75 0b                	jne    1400030ae <__mingw_enum_import_library_names+0xb2>
   1400030a3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030a7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030aa:	85 c0                	test   eax,eax
   1400030ac:	74 23                	je     1400030d1 <__mingw_enum_import_library_names+0xd5>
   1400030ae:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400030b2:	7f 12                	jg     1400030c6 <__mingw_enum_import_library_names+0xca>
   1400030b4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030b8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030bb:	89 c2                	mov    edx,eax
   1400030bd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030c1:	48 01 d0             	add    rax,rdx
   1400030c4:	eb 11                	jmp    1400030d7 <__mingw_enum_import_library_names+0xdb>
   1400030c6:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   1400030ca:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   1400030cf:	eb c7                	jmp    140003098 <__mingw_enum_import_library_names+0x9c>
   1400030d1:	90                   	nop
   1400030d2:	b8 00 00 00 00       	mov    eax,0x0
   1400030d7:	48 83 c4 50          	add    rsp,0x50
   1400030db:	5d                   	pop    rbp
   1400030dc:	c3                   	ret
   1400030dd:	90                   	nop
   1400030de:	90                   	nop
   1400030df:	90                   	nop

00000001400030e0 <___chkstk_ms>:
   1400030e0:	51                   	push   rcx
   1400030e1:	50                   	push   rax
   1400030e2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030e8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400030ed:	72 19                	jb     140003108 <___chkstk_ms+0x28>
   1400030ef:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400030f6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030fa:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003100:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003106:	77 e7                	ja     1400030ef <___chkstk_ms+0xf>
   140003108:	48 29 c1             	sub    rcx,rax
   14000310b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000310f:	58                   	pop    rax
   140003110:	59                   	pop    rcx
   140003111:	c3                   	ret
   140003112:	90                   	nop
   140003113:	90                   	nop
   140003114:	90                   	nop
   140003115:	90                   	nop
   140003116:	90                   	nop
   140003117:	90                   	nop
   140003118:	90                   	nop
   140003119:	90                   	nop
   14000311a:	90                   	nop
   14000311b:	90                   	nop
   14000311c:	90                   	nop
   14000311d:	90                   	nop
   14000311e:	90                   	nop
   14000311f:	90                   	nop

0000000140003120 <_initterm_e>:
   140003120:	55                   	push   rbp
   140003121:	48 89 e5             	mov    rbp,rsp
   140003124:	48 83 ec 30          	sub    rsp,0x30
   140003128:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000312c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003130:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003134:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003138:	eb 29                	jmp    140003163 <_initterm_e+0x43>
   14000313a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000313e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140003141:	48 85 c0             	test   rax,rax
   140003144:	74 17                	je     14000315d <_initterm_e+0x3d>
   140003146:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000314a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000314d:	ff d0                	call   rax
   14000314f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003152:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003156:	74 06                	je     14000315e <_initterm_e+0x3e>
   140003158:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000315b:	eb 15                	jmp    140003172 <_initterm_e+0x52>
   14000315d:	90                   	nop
   14000315e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140003163:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003167:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   14000316b:	72 cd                	jb     14000313a <_initterm_e+0x1a>
   14000316d:	b8 00 00 00 00       	mov    eax,0x0
   140003172:	48 83 c4 30          	add    rsp,0x30
   140003176:	5d                   	pop    rbp
   140003177:	c3                   	ret
   140003178:	90                   	nop
   140003179:	90                   	nop
   14000317a:	90                   	nop
   14000317b:	90                   	nop
   14000317c:	90                   	nop
   14000317d:	90                   	nop
   14000317e:	90                   	nop
   14000317f:	90                   	nop

0000000140003180 <__p__fmode>:
   140003180:	55                   	push   rbp
   140003181:	48 89 e5             	mov    rbp,rsp
   140003184:	48 8b 05 45 22 00 00 	mov    rax,QWORD PTR [rip+0x2245]        # 1400053d0 <.refptr.__imp__fmode>
   14000318b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000318e:	5d                   	pop    rbp
   14000318f:	c3                   	ret

0000000140003190 <__p__commode>:
   140003190:	55                   	push   rbp
   140003191:	48 89 e5             	mov    rbp,rsp
   140003194:	48 8b 05 25 22 00 00 	mov    rax,QWORD PTR [rip+0x2225]        # 1400053c0 <.refptr.__imp__commode>
   14000319b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000319e:	5d                   	pop    rbp
   14000319f:	c3                   	ret

00000001400031a0 <__p___initenv>:
   1400031a0:	55                   	push   rbp
   1400031a1:	48 89 e5             	mov    rbp,rsp
   1400031a4:	48 8b 05 05 22 00 00 	mov    rax,QWORD PTR [rip+0x2205]        # 1400053b0 <.refptr.__imp___initenv>
   1400031ab:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031ae:	5d                   	pop    rbp
   1400031af:	c3                   	ret

00000001400031b0 <_set_invalid_parameter_handler>:
   1400031b0:	55                   	push   rbp
   1400031b1:	48 89 e5             	mov    rbp,rsp
   1400031b4:	48 83 ec 10          	sub    rsp,0x10
   1400031b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400031bc:	48 8d 05 cd 5f 00 00 	lea    rax,[rip+0x5fcd]        # 140009190 <handler>
   1400031c3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031c7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400031cb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400031cf:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400031d3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031d7:	48 87 10             	xchg   QWORD PTR [rax],rdx
   1400031da:	48 89 d0             	mov    rax,rdx
   1400031dd:	48 83 c4 10          	add    rsp,0x10
   1400031e1:	5d                   	pop    rbp
   1400031e2:	c3                   	ret

00000001400031e3 <_get_invalid_parameter_handler>:
   1400031e3:	55                   	push   rbp
   1400031e4:	48 89 e5             	mov    rbp,rsp
   1400031e7:	48 8b 05 a2 5f 00 00 	mov    rax,QWORD PTR [rip+0x5fa2]        # 140009190 <handler>
   1400031ee:	5d                   	pop    rbp
   1400031ef:	c3                   	ret

00000001400031f0 <_configthreadlocale>:
   1400031f0:	55                   	push   rbp
   1400031f1:	48 89 e5             	mov    rbp,rsp
   1400031f4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031f7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   1400031fb:	75 07                	jne    140003204 <_configthreadlocale+0x14>
   1400031fd:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140003202:	eb 05                	jmp    140003209 <_configthreadlocale+0x19>
   140003204:	b8 02 00 00 00       	mov    eax,0x2
   140003209:	5d                   	pop    rbp
   14000320a:	c3                   	ret
   14000320b:	90                   	nop
   14000320c:	90                   	nop
   14000320d:	90                   	nop
   14000320e:	90                   	nop
   14000320f:	90                   	nop

0000000140003210 <__acrt_iob_func>:
   140003210:	55                   	push   rbp
   140003211:	48 89 e5             	mov    rbp,rsp
   140003214:	48 83 ec 20          	sub    rsp,0x20
   140003218:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000321b:	e8 30 00 00 00       	call   140003250 <__iob_func>
   140003220:	48 89 c1             	mov    rcx,rax
   140003223:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003226:	48 89 d0             	mov    rax,rdx
   140003229:	48 01 c0             	add    rax,rax
   14000322c:	48 01 d0             	add    rax,rdx
   14000322f:	48 c1 e0 04          	shl    rax,0x4
   140003233:	48 01 c8             	add    rax,rcx
   140003236:	48 83 c4 20          	add    rsp,0x20
   14000323a:	5d                   	pop    rbp
   14000323b:	c3                   	ret
   14000323c:	90                   	nop
   14000323d:	90                   	nop
   14000323e:	90                   	nop
   14000323f:	90                   	nop

0000000140003240 <__C_specific_handler>:
   140003240:	ff 25 ba 6f 00 00    	jmp    QWORD PTR [rip+0x6fba]        # 14000a200 <__imp___C_specific_handler>
   140003246:	90                   	nop
   140003247:	90                   	nop

0000000140003248 <__getmainargs>:
   140003248:	ff 25 ba 6f 00 00    	jmp    QWORD PTR [rip+0x6fba]        # 14000a208 <__imp___getmainargs>
   14000324e:	90                   	nop
   14000324f:	90                   	nop

0000000140003250 <__iob_func>:
   140003250:	ff 25 c2 6f 00 00    	jmp    QWORD PTR [rip+0x6fc2]        # 14000a218 <__imp___iob_func>
   140003256:	90                   	nop
   140003257:	90                   	nop

0000000140003258 <__set_app_type>:
   140003258:	ff 25 c2 6f 00 00    	jmp    QWORD PTR [rip+0x6fc2]        # 14000a220 <__imp___set_app_type>
   14000325e:	90                   	nop
   14000325f:	90                   	nop

0000000140003260 <__setusermatherr>:
   140003260:	ff 25 c2 6f 00 00    	jmp    QWORD PTR [rip+0x6fc2]        # 14000a228 <__imp___setusermatherr>
   140003266:	90                   	nop
   140003267:	90                   	nop

0000000140003268 <_amsg_exit>:
   140003268:	ff 25 c2 6f 00 00    	jmp    QWORD PTR [rip+0x6fc2]        # 14000a230 <__imp__amsg_exit>
   14000326e:	90                   	nop
   14000326f:	90                   	nop

0000000140003270 <_cexit>:
   140003270:	ff 25 c2 6f 00 00    	jmp    QWORD PTR [rip+0x6fc2]        # 14000a238 <__imp__cexit>
   140003276:	90                   	nop
   140003277:	90                   	nop

0000000140003278 <_initterm>:
   140003278:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a250 <__imp__initterm>
   14000327e:	90                   	nop
   14000327f:	90                   	nop

0000000140003280 <_crt_atexit>:
   140003280:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a258 <__imp__crt_atexit>
   140003286:	90                   	nop
   140003287:	90                   	nop

0000000140003288 <abort>:
   140003288:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a260 <__imp_abort>
   14000328e:	90                   	nop
   14000328f:	90                   	nop

0000000140003290 <calloc>:
   140003290:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a268 <__imp_calloc>
   140003296:	90                   	nop
   140003297:	90                   	nop

0000000140003298 <exit>:
   140003298:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a270 <__imp_exit>
   14000329e:	90                   	nop
   14000329f:	90                   	nop

00000001400032a0 <fflush>:
   1400032a0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a278 <__imp_fflush>
   1400032a6:	90                   	nop
   1400032a7:	90                   	nop

00000001400032a8 <fprintf>:
   1400032a8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a280 <__imp_fprintf>
   1400032ae:	90                   	nop
   1400032af:	90                   	nop

00000001400032b0 <free>:
   1400032b0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a288 <__imp_free>
   1400032b6:	90                   	nop
   1400032b7:	90                   	nop

00000001400032b8 <malloc>:
   1400032b8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a290 <__imp_malloc>
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <memcpy>:
   1400032c0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a298 <__imp_memcpy>
   1400032c6:	90                   	nop
   1400032c7:	90                   	nop

00000001400032c8 <setvbuf>:
   1400032c8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2a0 <__imp_setvbuf>
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <signal>:
   1400032d0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2a8 <__imp_signal>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop

00000001400032d8 <strlen>:
   1400032d8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2b0 <__imp_strlen>
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <strncmp>:
   1400032e0:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2b8 <__imp_strncmp>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <vfprintf>:
   1400032e8:	ff 25 d2 6f 00 00    	jmp    QWORD PTR [rip+0x6fd2]        # 14000a2c0 <__imp_vfprintf>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <VirtualQuery>:
   1400032f0:	ff 25 fa 6e 00 00    	jmp    QWORD PTR [rip+0x6efa]        # 14000a1f0 <__imp_VirtualQuery>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <VirtualProtect>:
   1400032f8:	ff 25 ea 6e 00 00    	jmp    QWORD PTR [rip+0x6eea]        # 14000a1e8 <__imp_VirtualProtect>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <TlsGetValue>:
   140003300:	ff 25 da 6e 00 00    	jmp    QWORD PTR [rip+0x6eda]        # 14000a1e0 <__imp_TlsGetValue>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <Sleep>:
   140003308:	ff 25 ca 6e 00 00    	jmp    QWORD PTR [rip+0x6eca]        # 14000a1d8 <__imp_Sleep>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <SetUnhandledExceptionFilter>:
   140003310:	ff 25 ba 6e 00 00    	jmp    QWORD PTR [rip+0x6eba]        # 14000a1d0 <__imp_SetUnhandledExceptionFilter>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <LoadLibraryA>:
   140003318:	ff 25 aa 6e 00 00    	jmp    QWORD PTR [rip+0x6eaa]        # 14000a1c8 <__imp_LoadLibraryA>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <LeaveCriticalSection>:
   140003320:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140003326:	90                   	nop
   140003327:	90                   	nop

0000000140003328 <InitializeCriticalSection>:
   140003328:	ff 25 8a 6e 00 00    	jmp    QWORD PTR [rip+0x6e8a]        # 14000a1b8 <__imp_InitializeCriticalSection>
   14000332e:	90                   	nop
   14000332f:	90                   	nop

0000000140003330 <GetProcAddress>:
   140003330:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a1b0 <__imp_GetProcAddress>
   140003336:	90                   	nop
   140003337:	90                   	nop

0000000140003338 <GetModuleHandleA>:
   140003338:	ff 25 6a 6e 00 00    	jmp    QWORD PTR [rip+0x6e6a]        # 14000a1a8 <__imp_GetModuleHandleA>
   14000333e:	90                   	nop
   14000333f:	90                   	nop

0000000140003340 <GetLastError>:
   140003340:	ff 25 5a 6e 00 00    	jmp    QWORD PTR [rip+0x6e5a]        # 14000a1a0 <__imp_GetLastError>
   140003346:	90                   	nop
   140003347:	90                   	nop

0000000140003348 <FreeLibrary>:
   140003348:	ff 25 4a 6e 00 00    	jmp    QWORD PTR [rip+0x6e4a]        # 14000a198 <__imp_FreeLibrary>
   14000334e:	90                   	nop
   14000334f:	90                   	nop

0000000140003350 <EnterCriticalSection>:
   140003350:	ff 25 3a 6e 00 00    	jmp    QWORD PTR [rip+0x6e3a]        # 14000a190 <__imp_EnterCriticalSection>
   140003356:	90                   	nop
   140003357:	90                   	nop

0000000140003358 <DeleteCriticalSection>:
   140003358:	ff 25 2a 6e 00 00    	jmp    QWORD PTR [rip+0x6e2a]        # 14000a188 <__IAT_start__>
   14000335e:	90                   	nop
   14000335f:	90                   	nop

0000000140003360 <register_frame_ctor>:
   140003360:	e9 0b e3 ff ff       	jmp    140001670 <__gcc_register_frame>
   140003365:	90                   	nop
   140003366:	90                   	nop
   140003367:	90                   	nop
   140003368:	90                   	nop
   140003369:	90                   	nop
   14000336a:	90                   	nop
   14000336b:	90                   	nop
   14000336c:	90                   	nop
   14000336d:	90                   	nop
   14000336e:	90                   	nop
   14000336f:	90                   	nop
