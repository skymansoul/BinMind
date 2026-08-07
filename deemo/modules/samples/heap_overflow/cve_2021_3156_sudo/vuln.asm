
C:\Users\Administrator\Desktop\BinMind\round2\samples\heap_overflow\cve_2021_3156_sudo\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 c7 23 00 00       	call   1400033f0 <fflush>
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
   14000113b:	e8 78 22 00 00       	call   1400033b8 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 f8 21 00 00       	call   140003360 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 97 22 00 00       	call   140003418 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 3f 22 00 00       	call   1400033d8 <abort>
   140001199:	e8 c2 12 00 00       	call   140002460 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 21 90 00 00 	mov    rax,QWORD PTR [rip+0x9021]        # 14000a1d0 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 36 21 00 00       	call   140003300 <_set_invalid_parameter_handler>
   1400011ca:	e8 a1 1b 00 00       	call   140002d70 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 b7 21 00 00       	call   1400033a8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 ab 21 00 00       	call   1400033a8 <__set_app_type>
   1400011fd:	e8 ce 20 00 00       	call   1400032d0 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 ce 20 00 00       	call   1400032e0 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 1e 08 00 00       	call   140001a40 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 83 21 00 00       	call   1400033b8 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 28 13 00 00       	call   14000257a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 d6 20 00 00       	call   140003340 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 f0 1f 00 00       	call   140003270 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 2a 21 00 00       	call   1400033b8 <_amsg_exit>
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
   1400012cb:	e8 c8 20 00 00       	call   140003398 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 d5 20 00 00       	call   1400033b8 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 ae 20 00 00       	call   1400033b8 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 a8 20 00 00       	call   1400033c8 <_initterm>
   140001320:	e8 f2 06 00 00       	call   140001a17 <__main>
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
   14000138d:	e8 5e 1f 00 00       	call   1400032f0 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 f6 04 00 00       	call   1400018b0 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 17 20 00 00       	call   1400033e8 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 e0 1f 00 00       	call   1400033c0 <_cexit>
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
   140001511:	e8 f2 1e 00 00       	call   140003408 <malloc>
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
   14000155c:	e8 c7 1e 00 00       	call   140003428 <strlen>
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
   140001585:	e8 7e 1e 00 00       	call   140003408 <malloc>
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
   1400015e8:	e8 23 1e 00 00       	call   140003410 <memcpy>
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
   140001642:	e8 89 1d 00 00       	call   1400033d0 <_crt_atexit>
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

0000000140001760 <build_argv>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 40          	sub    rsp,0x40
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000176f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140001772:	83 c0 01             	add    eax,0x1
   140001775:	48 98                	cdqe
   140001777:	48 c1 e0 03          	shl    rax,0x3
   14000177b:	48 89 c1             	mov    rcx,rax
   14000177e:	e8 85 1c 00 00       	call   140003408 <malloc>
   140001783:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001787:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000178c:	75 0a                	jne    140001798 <build_argv+0x38>
   14000178e:	b8 00 00 00 00       	mov    eax,0x0
   140001793:	e9 12 01 00 00       	jmp    1400018aa <build_argv+0x14a>
   140001798:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000179f:	e9 db 00 00 00       	jmp    14000187f <build_argv+0x11f>
   1400017a4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400017a7:	48 98                	cdqe
   1400017a9:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   1400017b0:	00 
   1400017b1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017b5:	48 01 d0             	add    rax,rdx
   1400017b8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017bb:	48 89 c1             	mov    rcx,rax
   1400017be:	e8 65 1c 00 00       	call   140003428 <strlen>
   1400017c3:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400017c7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400017cb:	48 83 c0 02          	add    rax,0x2
   1400017cf:	48 89 c1             	mov    rcx,rax
   1400017d2:	e8 31 1c 00 00       	call   140003408 <malloc>
   1400017d7:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400017db:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   1400017e0:	0f 84 94 00 00 00    	je     14000187a <build_argv+0x11a>
   1400017e6:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400017ea:	48 8d 48 01          	lea    rcx,[rax+0x1]
   1400017ee:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400017f1:	48 98                	cdqe
   1400017f3:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   1400017fa:	00 
   1400017fb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017ff:	48 01 d0             	add    rax,rdx
   140001802:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140001805:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001809:	49 89 c8             	mov    r8,rcx
   14000180c:	48 89 c1             	mov    rcx,rax
   14000180f:	e8 fc 1b 00 00       	call   140003410 <memcpy>
   140001814:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001817:	48 98                	cdqe
   140001819:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140001820:	00 
   140001821:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001825:	48 01 d0             	add    rax,rdx
   140001828:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000182b:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   14000182f:	48 83 ea 01          	sub    rdx,0x1
   140001833:	48 01 d0             	add    rax,rdx
   140001836:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140001839:	3c 5c                	cmp    al,0x5c
   14000183b:	75 20                	jne    14000185d <build_argv+0xfd>
   14000183d:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140001841:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001845:	48 01 d0             	add    rax,rdx
   140001848:	c6 00 5c             	mov    BYTE PTR [rax],0x5c
   14000184b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000184f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140001853:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001857:	48 01 d0             	add    rax,rdx
   14000185a:	c6 00 00             	mov    BYTE PTR [rax],0x0
   14000185d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001860:	48 98                	cdqe
   140001862:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140001869:	00 
   14000186a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000186e:	48 01 c2             	add    rdx,rax
   140001871:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001875:	48 89 02             	mov    QWORD PTR [rdx],rax
   140001878:	eb 01                	jmp    14000187b <build_argv+0x11b>
   14000187a:	90                   	nop
   14000187b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   14000187f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001882:	3b 45 18             	cmp    eax,DWORD PTR [rbp+0x18]
   140001885:	0f 8c 19 ff ff ff    	jl     1400017a4 <build_argv+0x44>
   14000188b:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000188e:	48 98                	cdqe
   140001890:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140001897:	00 
   140001898:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000189c:	48 01 d0             	add    rax,rdx
   14000189f:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   1400018a6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400018aa:	48 83 c4 40          	add    rsp,0x40
   1400018ae:	5d                   	pop    rbp
   1400018af:	c3                   	ret

00000001400018b0 <main>:
   1400018b0:	55                   	push   rbp
   1400018b1:	48 89 e5             	mov    rbp,rsp
   1400018b4:	48 83 ec 40          	sub    rsp,0x40
   1400018b8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400018bb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400018bf:	e8 53 01 00 00       	call   140001a17 <__main>
   1400018c4:	48 8d 05 85 37 00 00 	lea    rax,[rip+0x3785]        # 140005050 <.rdata>
   1400018cb:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400018cf:	48 8d 05 83 37 00 00 	lea    rax,[rip+0x3783]        # 140005059 <.rdata+0x9>
   1400018d6:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400018da:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400018de:	ba 02 00 00 00       	mov    edx,0x2
   1400018e3:	48 89 c1             	mov    rcx,rax
   1400018e6:	e8 75 fe ff ff       	call   140001760 <build_argv>
   1400018eb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400018ef:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400018f4:	74 5a                	je     140001950 <main+0xa0>
   1400018f6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400018fd:	eb 3f                	jmp    14000193e <main+0x8e>
   1400018ff:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001902:	48 98                	cdqe
   140001904:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   14000190b:	00 
   14000190c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001910:	48 01 d0             	add    rax,rdx
   140001913:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001916:	48 85 c0             	test   rax,rax
   140001919:	74 1f                	je     14000193a <main+0x8a>
   14000191b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000191e:	48 98                	cdqe
   140001920:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140001927:	00 
   140001928:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000192c:	48 01 d0             	add    rax,rdx
   14000192f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001932:	48 89 c1             	mov    rcx,rax
   140001935:	e8 c6 1a 00 00       	call   140003400 <free>
   14000193a:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   14000193e:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140001942:	7e bb                	jle    1400018ff <main+0x4f>
   140001944:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001948:	48 89 c1             	mov    rcx,rax
   14000194b:	e8 b0 1a 00 00       	call   140003400 <free>
   140001950:	b8 00 00 00 00       	mov    eax,0x0
   140001955:	48 83 c4 40          	add    rsp,0x40
   140001959:	5d                   	pop    rbp
   14000195a:	c3                   	ret
   14000195b:	90                   	nop
   14000195c:	90                   	nop
   14000195d:	90                   	nop
   14000195e:	90                   	nop
   14000195f:	90                   	nop

0000000140001960 <__do_global_dtors>:
   140001960:	55                   	push   rbp
   140001961:	48 89 e5             	mov    rbp,rsp
   140001964:	48 83 ec 20          	sub    rsp,0x20
   140001968:	eb 1e                	jmp    140001988 <__do_global_dtors+0x28>
   14000196a:	48 8b 05 9f 26 00 00 	mov    rax,QWORD PTR [rip+0x269f]        # 140004010 <p.0>
   140001971:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001974:	ff d0                	call   rax
   140001976:	48 8b 05 93 26 00 00 	mov    rax,QWORD PTR [rip+0x2693]        # 140004010 <p.0>
   14000197d:	48 83 c0 08          	add    rax,0x8
   140001981:	48 89 05 88 26 00 00 	mov    QWORD PTR [rip+0x2688],rax        # 140004010 <p.0>
   140001988:	48 8b 05 81 26 00 00 	mov    rax,QWORD PTR [rip+0x2681]        # 140004010 <p.0>
   14000198f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001992:	48 85 c0             	test   rax,rax
   140001995:	75 d3                	jne    14000196a <__do_global_dtors+0xa>
   140001997:	90                   	nop
   140001998:	90                   	nop
   140001999:	48 83 c4 20          	add    rsp,0x20
   14000199d:	5d                   	pop    rbp
   14000199e:	c3                   	ret

000000014000199f <__do_global_ctors>:
   14000199f:	55                   	push   rbp
   1400019a0:	48 89 e5             	mov    rbp,rsp
   1400019a3:	48 83 ec 30          	sub    rsp,0x30
   1400019a7:	48 8b 05 a2 39 00 00 	mov    rax,QWORD PTR [rip+0x39a2]        # 140005350 <.refptr.__CTOR_LIST__>
   1400019ae:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019b1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400019b4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400019b8:	75 25                	jne    1400019df <__do_global_ctors+0x40>
   1400019ba:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400019c1:	eb 04                	jmp    1400019c7 <__do_global_ctors+0x28>
   1400019c3:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400019c7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400019ca:	8d 50 01             	lea    edx,[rax+0x1]
   1400019cd:	48 8b 05 7c 39 00 00 	mov    rax,QWORD PTR [rip+0x397c]        # 140005350 <.refptr.__CTOR_LIST__>
   1400019d4:	89 d2                	mov    edx,edx
   1400019d6:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400019da:	48 85 c0             	test   rax,rax
   1400019dd:	75 e4                	jne    1400019c3 <__do_global_ctors+0x24>
   1400019df:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400019e2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400019e5:	eb 14                	jmp    1400019fb <__do_global_ctors+0x5c>
   1400019e7:	48 8b 05 62 39 00 00 	mov    rax,QWORD PTR [rip+0x3962]        # 140005350 <.refptr.__CTOR_LIST__>
   1400019ee:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400019f1:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400019f5:	ff d0                	call   rax
   1400019f7:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400019fb:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400019ff:	75 e6                	jne    1400019e7 <__do_global_ctors+0x48>
   140001a01:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001960 <__do_global_dtors>
   140001a08:	48 89 c1             	mov    rcx,rax
   140001a0b:	e8 1f fc ff ff       	call   14000162f <atexit>
   140001a10:	90                   	nop
   140001a11:	48 83 c4 30          	add    rsp,0x30
   140001a15:	5d                   	pop    rbp
   140001a16:	c3                   	ret

0000000140001a17 <__main>:
   140001a17:	55                   	push   rbp
   140001a18:	48 89 e5             	mov    rbp,rsp
   140001a1b:	48 83 ec 20          	sub    rsp,0x20
   140001a1f:	8b 05 5b 76 00 00    	mov    eax,DWORD PTR [rip+0x765b]        # 140009080 <initialized>
   140001a25:	85 c0                	test   eax,eax
   140001a27:	75 0f                	jne    140001a38 <__main+0x21>
   140001a29:	c7 05 4d 76 00 00 01 	mov    DWORD PTR [rip+0x764d],0x1        # 140009080 <initialized>
   140001a30:	00 00 00 
   140001a33:	e8 67 ff ff ff       	call   14000199f <__do_global_ctors>
   140001a38:	90                   	nop
   140001a39:	48 83 c4 20          	add    rsp,0x20
   140001a3d:	5d                   	pop    rbp
   140001a3e:	c3                   	ret
   140001a3f:	90                   	nop

0000000140001a40 <_setargv>:
   140001a40:	55                   	push   rbp
   140001a41:	48 89 e5             	mov    rbp,rsp
   140001a44:	b8 00 00 00 00       	mov    eax,0x0
   140001a49:	5d                   	pop    rbp
   140001a4a:	c3                   	ret
   140001a4b:	90                   	nop
   140001a4c:	90                   	nop
   140001a4d:	90                   	nop
   140001a4e:	90                   	nop
   140001a4f:	90                   	nop

0000000140001a50 <__dyn_tls_init>:
   140001a50:	55                   	push   rbp
   140001a51:	48 89 e5             	mov    rbp,rsp
   140001a54:	48 83 ec 30          	sub    rsp,0x30
   140001a58:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a5c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a5f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a63:	48 8b 05 c6 38 00 00 	mov    rax,QWORD PTR [rip+0x38c6]        # 140005330 <.refptr._CRT_MT>
   140001a6a:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a6c:	83 f8 02             	cmp    eax,0x2
   140001a6f:	74 0d                	je     140001a7e <__dyn_tls_init+0x2e>
   140001a71:	48 8b 05 b8 38 00 00 	mov    rax,QWORD PTR [rip+0x38b8]        # 140005330 <.refptr._CRT_MT>
   140001a78:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   140001a7e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001a82:	74 1e                	je     140001aa2 <__dyn_tls_init+0x52>
   140001a84:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001a88:	75 5b                	jne    140001ae5 <__dyn_tls_init+0x95>
   140001a8a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a8e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a91:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a95:	49 89 c8             	mov    r8,rcx
   140001a98:	48 89 c1             	mov    rcx,rax
   140001a9b:	e8 d1 11 00 00       	call   140002c71 <__mingw_TLScallback>
   140001aa0:	eb 43                	jmp    140001ae5 <__dyn_tls_init+0x95>
   140001aa2:	48 8d 05 ef 3b 00 00 	lea    rax,[rip+0x3bef]        # 140005698 <___crt_xd_start__>
   140001aa9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001aad:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001ab2:	eb 22                	jmp    140001ad6 <__dyn_tls_init+0x86>
   140001ab4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001ab8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001abc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001ac0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001ac3:	48 85 c0             	test   rax,rax
   140001ac6:	74 09                	je     140001ad1 <__dyn_tls_init+0x81>
   140001ac8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001acc:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001acf:	ff d0                	call   rax
   140001ad1:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001ad6:	48 8d 05 c3 3b 00 00 	lea    rax,[rip+0x3bc3]        # 1400056a0 <__xd_z>
   140001add:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001ae1:	75 d1                	jne    140001ab4 <__dyn_tls_init+0x64>
   140001ae3:	eb 01                	jmp    140001ae6 <__dyn_tls_init+0x96>
   140001ae5:	90                   	nop
   140001ae6:	48 83 c4 30          	add    rsp,0x30
   140001aea:	5d                   	pop    rbp
   140001aeb:	c3                   	ret

0000000140001aec <__tlregdtor>:
   140001aec:	55                   	push   rbp
   140001aed:	48 89 e5             	mov    rbp,rsp
   140001af0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001af4:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001af9:	75 07                	jne    140001b02 <__tlregdtor+0x16>
   140001afb:	b8 00 00 00 00       	mov    eax,0x0
   140001b00:	eb 05                	jmp    140001b07 <__tlregdtor+0x1b>
   140001b02:	b8 00 00 00 00       	mov    eax,0x0
   140001b07:	5d                   	pop    rbp
   140001b08:	c3                   	ret

0000000140001b09 <__dyn_tls_dtor>:
   140001b09:	55                   	push   rbp
   140001b0a:	48 89 e5             	mov    rbp,rsp
   140001b0d:	48 83 ec 20          	sub    rsp,0x20
   140001b11:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b15:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001b18:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001b1c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001b20:	74 06                	je     140001b28 <__dyn_tls_dtor+0x1f>
   140001b22:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001b26:	75 18                	jne    140001b40 <__dyn_tls_dtor+0x37>
   140001b28:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001b2c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001b2f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001b33:	49 89 c8             	mov    r8,rcx
   140001b36:	48 89 c1             	mov    rcx,rax
   140001b39:	e8 33 11 00 00       	call   140002c71 <__mingw_TLScallback>
   140001b3e:	eb 01                	jmp    140001b41 <__dyn_tls_dtor+0x38>
   140001b40:	90                   	nop
   140001b41:	48 83 c4 20          	add    rsp,0x20
   140001b45:	5d                   	pop    rbp
   140001b46:	c3                   	ret
   140001b47:	90                   	nop
   140001b48:	90                   	nop
   140001b49:	90                   	nop
   140001b4a:	90                   	nop
   140001b4b:	90                   	nop
   140001b4c:	90                   	nop
   140001b4d:	90                   	nop
   140001b4e:	90                   	nop
   140001b4f:	90                   	nop

0000000140001b50 <_matherr>:
   140001b50:	55                   	push   rbp
   140001b51:	53                   	push   rbx
   140001b52:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001b59:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001b5e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001b62:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001b66:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001b6b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001b6f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b73:	8b 00                	mov    eax,DWORD PTR [rax]
   140001b75:	83 f8 06             	cmp    eax,0x6
   140001b78:	74 56                	je     140001bd0 <_matherr+0x80>
   140001b7a:	83 f8 06             	cmp    eax,0x6
   140001b7d:	7f 78                	jg     140001bf7 <_matherr+0xa7>
   140001b7f:	83 f8 05             	cmp    eax,0x5
   140001b82:	74 59                	je     140001bdd <_matherr+0x8d>
   140001b84:	83 f8 05             	cmp    eax,0x5
   140001b87:	7f 6e                	jg     140001bf7 <_matherr+0xa7>
   140001b89:	83 f8 04             	cmp    eax,0x4
   140001b8c:	74 5c                	je     140001bea <_matherr+0x9a>
   140001b8e:	83 f8 04             	cmp    eax,0x4
   140001b91:	7f 64                	jg     140001bf7 <_matherr+0xa7>
   140001b93:	83 f8 03             	cmp    eax,0x3
   140001b96:	74 2b                	je     140001bc3 <_matherr+0x73>
   140001b98:	83 f8 03             	cmp    eax,0x3
   140001b9b:	7f 5a                	jg     140001bf7 <_matherr+0xa7>
   140001b9d:	83 f8 01             	cmp    eax,0x1
   140001ba0:	74 07                	je     140001ba9 <_matherr+0x59>
   140001ba2:	83 f8 02             	cmp    eax,0x2
   140001ba5:	74 0f                	je     140001bb6 <_matherr+0x66>
   140001ba7:	eb 4e                	jmp    140001bf7 <_matherr+0xa7>
   140001ba9:	48 8d 05 f0 34 00 00 	lea    rax,[rip+0x34f0]        # 1400050a0 <.rdata>
   140001bb0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bb4:	eb 4d                	jmp    140001c03 <_matherr+0xb3>
   140001bb6:	48 8d 05 02 35 00 00 	lea    rax,[rip+0x3502]        # 1400050bf <.rdata+0x1f>
   140001bbd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bc1:	eb 40                	jmp    140001c03 <_matherr+0xb3>
   140001bc3:	48 8d 05 16 35 00 00 	lea    rax,[rip+0x3516]        # 1400050e0 <.rdata+0x40>
   140001bca:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bce:	eb 33                	jmp    140001c03 <_matherr+0xb3>
   140001bd0:	48 8d 05 29 35 00 00 	lea    rax,[rip+0x3529]        # 140005100 <.rdata+0x60>
   140001bd7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bdb:	eb 26                	jmp    140001c03 <_matherr+0xb3>
   140001bdd:	48 8d 05 44 35 00 00 	lea    rax,[rip+0x3544]        # 140005128 <.rdata+0x88>
   140001be4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001be8:	eb 19                	jmp    140001c03 <_matherr+0xb3>
   140001bea:	48 8d 05 5f 35 00 00 	lea    rax,[rip+0x355f]        # 140005150 <.rdata+0xb0>
   140001bf1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bf5:	eb 0c                	jmp    140001c03 <_matherr+0xb3>
   140001bf7:	48 8d 05 88 35 00 00 	lea    rax,[rip+0x3588]        # 140005186 <.rdata+0xe6>
   140001bfe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c02:	90                   	nop
   140001c03:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c07:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001c0d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c11:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001c16:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c1a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001c1f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c23:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001c27:	b9 02 00 00 00       	mov    ecx,0x2
   140001c2c:	e8 2f 17 00 00       	call   140003360 <__acrt_iob_func>
   140001c31:	48 89 c1             	mov    rcx,rax
   140001c34:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001c38:	48 8d 05 59 35 00 00 	lea    rax,[rip+0x3559]        # 140005198 <.rdata+0xf8>
   140001c3f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001c46:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001c4c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001c52:	49 89 d9             	mov    r9,rbx
   140001c55:	49 89 d0             	mov    r8,rdx
   140001c58:	48 89 c2             	mov    rdx,rax
   140001c5b:	e8 98 17 00 00       	call   1400033f8 <fprintf>
   140001c60:	b8 00 00 00 00       	mov    eax,0x0
   140001c65:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001c69:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001c6d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001c72:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001c79:	5b                   	pop    rbx
   140001c7a:	5d                   	pop    rbp
   140001c7b:	c3                   	ret
   140001c7c:	90                   	nop
   140001c7d:	90                   	nop
   140001c7e:	90                   	nop
   140001c7f:	90                   	nop

0000000140001c80 <__report_error>:
   140001c80:	55                   	push   rbp
   140001c81:	53                   	push   rbx
   140001c82:	48 83 ec 38          	sub    rsp,0x38
   140001c86:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001c8b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001c8f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001c93:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001c97:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001c9b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001c9f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ca3:	b9 02 00 00 00       	mov    ecx,0x2
   140001ca8:	e8 b3 16 00 00       	call   140003360 <__acrt_iob_func>
   140001cad:	48 89 c1             	mov    rcx,rax
   140001cb0:	48 8d 05 19 35 00 00 	lea    rax,[rip+0x3519]        # 1400051d0 <.rdata>
   140001cb7:	48 89 c2             	mov    rdx,rax
   140001cba:	e8 39 17 00 00       	call   1400033f8 <fprintf>
   140001cbf:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001cc3:	b9 02 00 00 00       	mov    ecx,0x2
   140001cc8:	e8 93 16 00 00       	call   140003360 <__acrt_iob_func>
   140001ccd:	48 89 c1             	mov    rcx,rax
   140001cd0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001cd4:	49 89 d8             	mov    r8,rbx
   140001cd7:	48 89 c2             	mov    rdx,rax
   140001cda:	e8 59 17 00 00       	call   140003438 <vfprintf>
   140001cdf:	e8 f4 16 00 00       	call   1400033d8 <abort>
   140001ce4:	90                   	nop

0000000140001ce5 <mark_section_writable>:
   140001ce5:	55                   	push   rbp
   140001ce6:	48 89 e5             	mov    rbp,rsp
   140001ce9:	48 83 ec 60          	sub    rsp,0x60
   140001ced:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001cf1:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001cf8:	e9 82 00 00 00       	jmp    140001d7f <mark_section_writable+0x9a>
   140001cfd:	48 8b 0d dc 73 00 00 	mov    rcx,QWORD PTR [rip+0x73dc]        # 1400090e0 <the_secs>
   140001d04:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d07:	48 63 d0             	movsxd rdx,eax
   140001d0a:	48 89 d0             	mov    rax,rdx
   140001d0d:	48 c1 e0 02          	shl    rax,0x2
   140001d11:	48 01 d0             	add    rax,rdx
   140001d14:	48 c1 e0 03          	shl    rax,0x3
   140001d18:	48 01 c8             	add    rax,rcx
   140001d1b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d1f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001d23:	72 56                	jb     140001d7b <mark_section_writable+0x96>
   140001d25:	48 8b 0d b4 73 00 00 	mov    rcx,QWORD PTR [rip+0x73b4]        # 1400090e0 <the_secs>
   140001d2c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d2f:	48 63 d0             	movsxd rdx,eax
   140001d32:	48 89 d0             	mov    rax,rdx
   140001d35:	48 c1 e0 02          	shl    rax,0x2
   140001d39:	48 01 d0             	add    rax,rdx
   140001d3c:	48 c1 e0 03          	shl    rax,0x3
   140001d40:	48 01 c8             	add    rax,rcx
   140001d43:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001d47:	4c 8b 05 92 73 00 00 	mov    r8,QWORD PTR [rip+0x7392]        # 1400090e0 <the_secs>
   140001d4e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d51:	48 63 d0             	movsxd rdx,eax
   140001d54:	48 89 d0             	mov    rax,rdx
   140001d57:	48 c1 e0 02          	shl    rax,0x2
   140001d5b:	48 01 d0             	add    rax,rdx
   140001d5e:	48 c1 e0 03          	shl    rax,0x3
   140001d62:	4c 01 c0             	add    rax,r8
   140001d65:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001d69:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d6c:	89 c0                	mov    eax,eax
   140001d6e:	48 01 c8             	add    rax,rcx
   140001d71:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001d75:	0f 82 41 02 00 00    	jb     140001fbc <mark_section_writable+0x2d7>
   140001d7b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001d7f:	8b 05 63 73 00 00    	mov    eax,DWORD PTR [rip+0x7363]        # 1400090e8 <maxSections>
   140001d85:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001d88:	0f 8c 6f ff ff ff    	jl     140001cfd <mark_section_writable+0x18>
   140001d8e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001d92:	48 89 c1             	mov    rcx,rax
   140001d95:	e8 c1 11 00 00       	call   140002f5b <__mingw_GetSectionForAddress>
   140001d9a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001d9e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001da3:	75 13                	jne    140001db8 <mark_section_writable+0xd3>
   140001da5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001da9:	48 8d 0d 40 34 00 00 	lea    rcx,[rip+0x3440]        # 1400051f0 <.rdata+0x20>
   140001db0:	48 89 c2             	mov    rdx,rax
   140001db3:	e8 c8 fe ff ff       	call   140001c80 <__report_error>
   140001db8:	48 8b 0d 21 73 00 00 	mov    rcx,QWORD PTR [rip+0x7321]        # 1400090e0 <the_secs>
   140001dbf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dc2:	48 63 d0             	movsxd rdx,eax
   140001dc5:	48 89 d0             	mov    rax,rdx
   140001dc8:	48 c1 e0 02          	shl    rax,0x2
   140001dcc:	48 01 d0             	add    rax,rdx
   140001dcf:	48 c1 e0 03          	shl    rax,0x3
   140001dd3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001dd7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001ddb:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001ddf:	48 8b 0d fa 72 00 00 	mov    rcx,QWORD PTR [rip+0x72fa]        # 1400090e0 <the_secs>
   140001de6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001de9:	48 63 d0             	movsxd rdx,eax
   140001dec:	48 89 d0             	mov    rax,rdx
   140001def:	48 c1 e0 02          	shl    rax,0x2
   140001df3:	48 01 d0             	add    rax,rdx
   140001df6:	48 c1 e0 03          	shl    rax,0x3
   140001dfa:	48 01 c8             	add    rax,rcx
   140001dfd:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001e03:	e8 9f 12 00 00       	call   1400030a7 <_GetPEImageBase>
   140001e08:	48 89 c1             	mov    rcx,rax
   140001e0b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001e0f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001e12:	41 89 c1             	mov    r9d,eax
   140001e15:	4c 8b 05 c4 72 00 00 	mov    r8,QWORD PTR [rip+0x72c4]        # 1400090e0 <the_secs>
   140001e1c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e1f:	48 63 d0             	movsxd rdx,eax
   140001e22:	48 89 d0             	mov    rax,rdx
   140001e25:	48 c1 e0 02          	shl    rax,0x2
   140001e29:	48 01 d0             	add    rax,rdx
   140001e2c:	48 c1 e0 03          	shl    rax,0x3
   140001e30:	4c 01 c0             	add    rax,r8
   140001e33:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001e37:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001e3b:	48 8b 0d 9e 72 00 00 	mov    rcx,QWORD PTR [rip+0x729e]        # 1400090e0 <the_secs>
   140001e42:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e45:	48 63 d0             	movsxd rdx,eax
   140001e48:	48 89 d0             	mov    rax,rdx
   140001e4b:	48 c1 e0 02          	shl    rax,0x2
   140001e4f:	48 01 d0             	add    rax,rdx
   140001e52:	48 c1 e0 03          	shl    rax,0x3
   140001e56:	48 01 c8             	add    rax,rcx
   140001e59:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001e5d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001e61:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001e67:	48 89 c1             	mov    rcx,rax
   140001e6a:	48 8b 05 7f 83 00 00 	mov    rax,QWORD PTR [rip+0x837f]        # 14000a1f0 <__imp_VirtualQuery>
   140001e71:	ff d0                	call   rax
   140001e73:	48 85 c0             	test   rax,rax
   140001e76:	75 3f                	jne    140001eb7 <mark_section_writable+0x1d2>
   140001e78:	48 8b 0d 61 72 00 00 	mov    rcx,QWORD PTR [rip+0x7261]        # 1400090e0 <the_secs>
   140001e7f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e82:	48 63 d0             	movsxd rdx,eax
   140001e85:	48 89 d0             	mov    rax,rdx
   140001e88:	48 c1 e0 02          	shl    rax,0x2
   140001e8c:	48 01 d0             	add    rax,rdx
   140001e8f:	48 c1 e0 03          	shl    rax,0x3
   140001e93:	48 01 c8             	add    rax,rcx
   140001e96:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001e9a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001e9e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001ea1:	89 c1                	mov    ecx,eax
   140001ea3:	48 8d 05 66 33 00 00 	lea    rax,[rip+0x3366]        # 140005210 <.rdata+0x40>
   140001eaa:	49 89 d0             	mov    r8,rdx
   140001ead:	89 ca                	mov    edx,ecx
   140001eaf:	48 89 c1             	mov    rcx,rax
   140001eb2:	e8 c9 fd ff ff       	call   140001c80 <__report_error>
   140001eb7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001eba:	83 f8 40             	cmp    eax,0x40
   140001ebd:	0f 84 e8 00 00 00    	je     140001fab <mark_section_writable+0x2c6>
   140001ec3:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001ec6:	83 f8 04             	cmp    eax,0x4
   140001ec9:	0f 84 dc 00 00 00    	je     140001fab <mark_section_writable+0x2c6>
   140001ecf:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001ed2:	3d 80 00 00 00       	cmp    eax,0x80
   140001ed7:	0f 84 ce 00 00 00    	je     140001fab <mark_section_writable+0x2c6>
   140001edd:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001ee0:	83 f8 08             	cmp    eax,0x8
   140001ee3:	0f 84 c2 00 00 00    	je     140001fab <mark_section_writable+0x2c6>
   140001ee9:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001eec:	83 f8 02             	cmp    eax,0x2
   140001eef:	75 09                	jne    140001efa <mark_section_writable+0x215>
   140001ef1:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001ef8:	eb 07                	jmp    140001f01 <mark_section_writable+0x21c>
   140001efa:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001f01:	48 8b 0d d8 71 00 00 	mov    rcx,QWORD PTR [rip+0x71d8]        # 1400090e0 <the_secs>
   140001f08:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f0b:	48 63 d0             	movsxd rdx,eax
   140001f0e:	48 89 d0             	mov    rax,rdx
   140001f11:	48 c1 e0 02          	shl    rax,0x2
   140001f15:	48 01 d0             	add    rax,rdx
   140001f18:	48 c1 e0 03          	shl    rax,0x3
   140001f1c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001f20:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001f24:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001f28:	48 8b 0d b1 71 00 00 	mov    rcx,QWORD PTR [rip+0x71b1]        # 1400090e0 <the_secs>
   140001f2f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f32:	48 63 d0             	movsxd rdx,eax
   140001f35:	48 89 d0             	mov    rax,rdx
   140001f38:	48 c1 e0 02          	shl    rax,0x2
   140001f3c:	48 01 d0             	add    rax,rdx
   140001f3f:	48 c1 e0 03          	shl    rax,0x3
   140001f43:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001f47:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001f4b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001f4f:	48 8b 0d 8a 71 00 00 	mov    rcx,QWORD PTR [rip+0x718a]        # 1400090e0 <the_secs>
   140001f56:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f59:	48 63 d0             	movsxd rdx,eax
   140001f5c:	48 89 d0             	mov    rax,rdx
   140001f5f:	48 c1 e0 02          	shl    rax,0x2
   140001f63:	48 01 d0             	add    rax,rdx
   140001f66:	48 c1 e0 03          	shl    rax,0x3
   140001f6a:	48 01 c8             	add    rax,rcx
   140001f6d:	49 89 c0             	mov    r8,rax
   140001f70:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001f74:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001f78:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001f7b:	4d 89 c1             	mov    r9,r8
   140001f7e:	41 89 c8             	mov    r8d,ecx
   140001f81:	48 89 c1             	mov    rcx,rax
   140001f84:	48 8b 05 5d 82 00 00 	mov    rax,QWORD PTR [rip+0x825d]        # 14000a1e8 <__imp_VirtualProtect>
   140001f8b:	ff d0                	call   rax
   140001f8d:	85 c0                	test   eax,eax
   140001f8f:	75 1a                	jne    140001fab <mark_section_writable+0x2c6>
   140001f91:	48 8b 05 08 82 00 00 	mov    rax,QWORD PTR [rip+0x8208]        # 14000a1a0 <__imp_GetLastError>
   140001f98:	ff d0                	call   rax
   140001f9a:	89 c2                	mov    edx,eax
   140001f9c:	48 8d 05 a5 32 00 00 	lea    rax,[rip+0x32a5]        # 140005248 <.rdata+0x78>
   140001fa3:	48 89 c1             	mov    rcx,rax
   140001fa6:	e8 d5 fc ff ff       	call   140001c80 <__report_error>
   140001fab:	8b 05 37 71 00 00    	mov    eax,DWORD PTR [rip+0x7137]        # 1400090e8 <maxSections>
   140001fb1:	83 c0 01             	add    eax,0x1
   140001fb4:	89 05 2e 71 00 00    	mov    DWORD PTR [rip+0x712e],eax        # 1400090e8 <maxSections>
   140001fba:	eb 01                	jmp    140001fbd <mark_section_writable+0x2d8>
   140001fbc:	90                   	nop
   140001fbd:	48 83 c4 60          	add    rsp,0x60
   140001fc1:	5d                   	pop    rbp
   140001fc2:	c3                   	ret

0000000140001fc3 <restore_modified_sections>:
   140001fc3:	55                   	push   rbp
   140001fc4:	48 89 e5             	mov    rbp,rsp
   140001fc7:	48 83 ec 30          	sub    rsp,0x30
   140001fcb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001fd2:	e9 ad 00 00 00       	jmp    140002084 <restore_modified_sections+0xc1>
   140001fd7:	48 8b 0d 02 71 00 00 	mov    rcx,QWORD PTR [rip+0x7102]        # 1400090e0 <the_secs>
   140001fde:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001fe1:	48 63 d0             	movsxd rdx,eax
   140001fe4:	48 89 d0             	mov    rax,rdx
   140001fe7:	48 c1 e0 02          	shl    rax,0x2
   140001feb:	48 01 d0             	add    rax,rdx
   140001fee:	48 c1 e0 03          	shl    rax,0x3
   140001ff2:	48 01 c8             	add    rax,rcx
   140001ff5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ff7:	85 c0                	test   eax,eax
   140001ff9:	0f 84 80 00 00 00    	je     14000207f <restore_modified_sections+0xbc>
   140001fff:	48 8b 0d da 70 00 00 	mov    rcx,QWORD PTR [rip+0x70da]        # 1400090e0 <the_secs>
   140002006:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002009:	48 63 d0             	movsxd rdx,eax
   14000200c:	48 89 d0             	mov    rax,rdx
   14000200f:	48 c1 e0 02          	shl    rax,0x2
   140002013:	48 01 d0             	add    rax,rdx
   140002016:	48 c1 e0 03          	shl    rax,0x3
   14000201a:	48 01 c8             	add    rax,rcx
   14000201d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140002020:	48 8b 0d b9 70 00 00 	mov    rcx,QWORD PTR [rip+0x70b9]        # 1400090e0 <the_secs>
   140002027:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000202a:	48 63 d0             	movsxd rdx,eax
   14000202d:	48 89 d0             	mov    rax,rdx
   140002030:	48 c1 e0 02          	shl    rax,0x2
   140002034:	48 01 d0             	add    rax,rdx
   140002037:	48 c1 e0 03          	shl    rax,0x3
   14000203b:	48 01 c8             	add    rax,rcx
   14000203e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140002042:	4c 8b 05 97 70 00 00 	mov    r8,QWORD PTR [rip+0x7097]        # 1400090e0 <the_secs>
   140002049:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000204c:	48 63 d0             	movsxd rdx,eax
   14000204f:	48 89 d0             	mov    rax,rdx
   140002052:	48 c1 e0 02          	shl    rax,0x2
   140002056:	48 01 d0             	add    rax,rdx
   140002059:	48 c1 e0 03          	shl    rax,0x3
   14000205d:	4c 01 c0             	add    rax,r8
   140002060:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140002064:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140002068:	49 89 d1             	mov    r9,rdx
   14000206b:	45 89 d0             	mov    r8d,r10d
   14000206e:	48 89 ca             	mov    rdx,rcx
   140002071:	48 89 c1             	mov    rcx,rax
   140002074:	48 8b 05 6d 81 00 00 	mov    rax,QWORD PTR [rip+0x816d]        # 14000a1e8 <__imp_VirtualProtect>
   14000207b:	ff d0                	call   rax
   14000207d:	eb 01                	jmp    140002080 <restore_modified_sections+0xbd>
   14000207f:	90                   	nop
   140002080:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140002084:	8b 05 5e 70 00 00    	mov    eax,DWORD PTR [rip+0x705e]        # 1400090e8 <maxSections>
   14000208a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   14000208d:	0f 8c 44 ff ff ff    	jl     140001fd7 <restore_modified_sections+0x14>
   140002093:	90                   	nop
   140002094:	90                   	nop
   140002095:	48 83 c4 30          	add    rsp,0x30
   140002099:	5d                   	pop    rbp
   14000209a:	c3                   	ret

000000014000209b <__write_memory>:
   14000209b:	55                   	push   rbp
   14000209c:	48 89 e5             	mov    rbp,rsp
   14000209f:	48 83 ec 20          	sub    rsp,0x20
   1400020a3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400020a7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400020ab:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400020af:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400020b4:	74 25                	je     1400020db <__write_memory+0x40>
   1400020b6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400020ba:	48 89 c1             	mov    rcx,rax
   1400020bd:	e8 23 fc ff ff       	call   140001ce5 <mark_section_writable>
   1400020c2:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400020c6:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400020ca:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400020ce:	49 89 c8             	mov    r8,rcx
   1400020d1:	48 89 c1             	mov    rcx,rax
   1400020d4:	e8 37 13 00 00       	call   140003410 <memcpy>
   1400020d9:	eb 01                	jmp    1400020dc <__write_memory+0x41>
   1400020db:	90                   	nop
   1400020dc:	48 83 c4 20          	add    rsp,0x20
   1400020e0:	5d                   	pop    rbp
   1400020e1:	c3                   	ret

00000001400020e2 <do_pseudo_reloc>:
   1400020e2:	55                   	push   rbp
   1400020e3:	48 89 e5             	mov    rbp,rsp
   1400020e6:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   1400020ea:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400020ee:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400020f2:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400020f6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400020fa:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   1400020fe:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002102:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002106:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000210a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000210f:	0f 8e 44 03 00 00    	jle    140002459 <do_pseudo_reloc+0x377>
   140002115:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000211a:	7e 25                	jle    140002141 <do_pseudo_reloc+0x5f>
   14000211c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002120:	8b 00                	mov    eax,DWORD PTR [rax]
   140002122:	85 c0                	test   eax,eax
   140002124:	75 1b                	jne    140002141 <do_pseudo_reloc+0x5f>
   140002126:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000212a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000212d:	85 c0                	test   eax,eax
   14000212f:	75 10                	jne    140002141 <do_pseudo_reloc+0x5f>
   140002131:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002135:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002138:	85 c0                	test   eax,eax
   14000213a:	75 05                	jne    140002141 <do_pseudo_reloc+0x5f>
   14000213c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002141:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002145:	8b 00                	mov    eax,DWORD PTR [rax]
   140002147:	85 c0                	test   eax,eax
   140002149:	75 0b                	jne    140002156 <do_pseudo_reloc+0x74>
   14000214b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000214f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002152:	85 c0                	test   eax,eax
   140002154:	74 59                	je     1400021af <do_pseudo_reloc+0xcd>
   140002156:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000215a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000215e:	eb 40                	jmp    1400021a0 <do_pseudo_reloc+0xbe>
   140002160:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002164:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002167:	89 c2                	mov    edx,eax
   140002169:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000216d:	48 01 d0             	add    rax,rdx
   140002170:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002174:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002178:	8b 10                	mov    edx,DWORD PTR [rax]
   14000217a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000217e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002180:	01 d0                	add    eax,edx
   140002182:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002185:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002189:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000218d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002193:	48 89 c1             	mov    rcx,rax
   140002196:	e8 00 ff ff ff       	call   14000209b <__write_memory>
   14000219b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   1400021a0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400021a4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400021a8:	72 b6                	jb     140002160 <do_pseudo_reloc+0x7e>
   1400021aa:	e9 ab 02 00 00       	jmp    14000245a <do_pseudo_reloc+0x378>
   1400021af:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021b3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021b6:	83 f8 01             	cmp    eax,0x1
   1400021b9:	74 18                	je     1400021d3 <do_pseudo_reloc+0xf1>
   1400021bb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021bf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021c2:	89 c2                	mov    edx,eax
   1400021c4:	48 8d 05 a5 30 00 00 	lea    rax,[rip+0x30a5]        # 140005270 <.rdata+0xa0>
   1400021cb:	48 89 c1             	mov    rcx,rax
   1400021ce:	e8 ad fa ff ff       	call   140001c80 <__report_error>
   1400021d3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021d7:	48 83 c0 0c          	add    rax,0xc
   1400021db:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400021df:	e9 65 02 00 00       	jmp    140002449 <do_pseudo_reloc+0x367>
   1400021e4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021e8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400021eb:	89 c2                	mov    edx,eax
   1400021ed:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400021f1:	48 01 d0             	add    rax,rdx
   1400021f4:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400021f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021fc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021fe:	89 c2                	mov    edx,eax
   140002200:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002204:	48 01 d0             	add    rax,rdx
   140002207:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000220b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000220f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002212:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002216:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000221a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000221d:	0f b6 c0             	movzx  eax,al
   140002220:	83 f8 40             	cmp    eax,0x40
   140002223:	0f 84 b6 00 00 00    	je     1400022df <do_pseudo_reloc+0x1fd>
   140002229:	83 f8 40             	cmp    eax,0x40
   14000222c:	0f 87 ba 00 00 00    	ja     1400022ec <do_pseudo_reloc+0x20a>
   140002232:	83 f8 20             	cmp    eax,0x20
   140002235:	74 77                	je     1400022ae <do_pseudo_reloc+0x1cc>
   140002237:	83 f8 20             	cmp    eax,0x20
   14000223a:	0f 87 ac 00 00 00    	ja     1400022ec <do_pseudo_reloc+0x20a>
   140002240:	83 f8 08             	cmp    eax,0x8
   140002243:	74 0a                	je     14000224f <do_pseudo_reloc+0x16d>
   140002245:	83 f8 10             	cmp    eax,0x10
   140002248:	74 38                	je     140002282 <do_pseudo_reloc+0x1a0>
   14000224a:	e9 9d 00 00 00       	jmp    1400022ec <do_pseudo_reloc+0x20a>
   14000224f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002253:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002256:	0f b6 c0             	movzx  eax,al
   140002259:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000225d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002261:	25 80 00 00 00       	and    eax,0x80
   140002266:	48 85 c0             	test   rax,rax
   140002269:	0f 84 9d 00 00 00    	je     14000230c <do_pseudo_reloc+0x22a>
   14000226f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002273:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002279:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000227d:	e9 8a 00 00 00       	jmp    14000230c <do_pseudo_reloc+0x22a>
   140002282:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002286:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002289:	0f b7 c0             	movzx  eax,ax
   14000228c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002290:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002294:	25 00 80 00 00       	and    eax,0x8000
   140002299:	48 85 c0             	test   rax,rax
   14000229c:	74 71                	je     14000230f <do_pseudo_reloc+0x22d>
   14000229e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022a2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400022a8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022ac:	eb 61                	jmp    14000230f <do_pseudo_reloc+0x22d>
   1400022ae:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022b2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400022b4:	89 c0                	mov    eax,eax
   1400022b6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022ba:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022be:	25 00 00 00 80       	and    eax,0x80000000
   1400022c3:	48 85 c0             	test   rax,rax
   1400022c6:	74 4a                	je     140002312 <do_pseudo_reloc+0x230>
   1400022c8:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022cc:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   1400022d3:	ff ff ff 
   1400022d6:	48 09 d0             	or     rax,rdx
   1400022d9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022dd:	eb 33                	jmp    140002312 <do_pseudo_reloc+0x230>
   1400022df:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022e3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400022e6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022ea:	eb 27                	jmp    140002313 <do_pseudo_reloc+0x231>
   1400022ec:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   1400022f3:	00 
   1400022f4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022f8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022fb:	0f b6 c0             	movzx  eax,al
   1400022fe:	48 8d 0d a3 2f 00 00 	lea    rcx,[rip+0x2fa3]        # 1400052a8 <.rdata+0xd8>
   140002305:	89 c2                	mov    edx,eax
   140002307:	e8 74 f9 ff ff       	call   140001c80 <__report_error>
   14000230c:	90                   	nop
   14000230d:	eb 04                	jmp    140002313 <do_pseudo_reloc+0x231>
   14000230f:	90                   	nop
   140002310:	eb 01                	jmp    140002313 <do_pseudo_reloc+0x231>
   140002312:	90                   	nop
   140002313:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002317:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000231b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000231d:	89 c2                	mov    edx,eax
   14000231f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002323:	48 01 c2             	add    rdx,rax
   140002326:	48 89 c8             	mov    rax,rcx
   140002329:	48 29 d0             	sub    rax,rdx
   14000232c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002330:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002334:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002338:	48 01 d0             	add    rax,rdx
   14000233b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000233f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002343:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002346:	25 ff 00 00 00       	and    eax,0xff
   14000234b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000234e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002352:	77 67                	ja     1400023bb <do_pseudo_reloc+0x2d9>
   140002354:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002357:	ba 01 00 00 00       	mov    edx,0x1
   14000235c:	89 c1                	mov    ecx,eax
   14000235e:	48 d3 e2             	shl    rdx,cl
   140002361:	48 89 d0             	mov    rax,rdx
   140002364:	48 83 e8 01          	sub    rax,0x1
   140002368:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000236c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000236f:	83 e8 01             	sub    eax,0x1
   140002372:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002379:	89 c1                	mov    ecx,eax
   14000237b:	48 d3 e2             	shl    rdx,cl
   14000237e:	48 89 d0             	mov    rax,rdx
   140002381:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002385:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002389:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000238d:	7c 0a                	jl     140002399 <do_pseudo_reloc+0x2b7>
   14000238f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002393:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002397:	7e 22                	jle    1400023bb <do_pseudo_reloc+0x2d9>
   140002399:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000239d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400023a1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400023a5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400023a8:	48 8d 0d 29 2f 00 00 	lea    rcx,[rip+0x2f29]        # 1400052d8 <.rdata+0x108>
   1400023af:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400023b4:	89 c2                	mov    edx,eax
   1400023b6:	e8 c5 f8 ff ff       	call   140001c80 <__report_error>
   1400023bb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400023bf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400023c2:	0f b6 c0             	movzx  eax,al
   1400023c5:	83 f8 40             	cmp    eax,0x40
   1400023c8:	74 63                	je     14000242d <do_pseudo_reloc+0x34b>
   1400023ca:	83 f8 40             	cmp    eax,0x40
   1400023cd:	77 75                	ja     140002444 <do_pseudo_reloc+0x362>
   1400023cf:	83 f8 20             	cmp    eax,0x20
   1400023d2:	74 41                	je     140002415 <do_pseudo_reloc+0x333>
   1400023d4:	83 f8 20             	cmp    eax,0x20
   1400023d7:	77 6b                	ja     140002444 <do_pseudo_reloc+0x362>
   1400023d9:	83 f8 08             	cmp    eax,0x8
   1400023dc:	74 07                	je     1400023e5 <do_pseudo_reloc+0x303>
   1400023de:	83 f8 10             	cmp    eax,0x10
   1400023e1:	74 1a                	je     1400023fd <do_pseudo_reloc+0x31b>
   1400023e3:	eb 5f                	jmp    140002444 <do_pseudo_reloc+0x362>
   1400023e5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400023e9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400023ed:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400023f3:	48 89 c1             	mov    rcx,rax
   1400023f6:	e8 a0 fc ff ff       	call   14000209b <__write_memory>
   1400023fb:	eb 47                	jmp    140002444 <do_pseudo_reloc+0x362>
   1400023fd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002401:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002405:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000240b:	48 89 c1             	mov    rcx,rax
   14000240e:	e8 88 fc ff ff       	call   14000209b <__write_memory>
   140002413:	eb 2f                	jmp    140002444 <do_pseudo_reloc+0x362>
   140002415:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002419:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000241d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002423:	48 89 c1             	mov    rcx,rax
   140002426:	e8 70 fc ff ff       	call   14000209b <__write_memory>
   14000242b:	eb 17                	jmp    140002444 <do_pseudo_reloc+0x362>
   14000242d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002431:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002435:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000243b:	48 89 c1             	mov    rcx,rax
   14000243e:	e8 58 fc ff ff       	call   14000209b <__write_memory>
   140002443:	90                   	nop
   140002444:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002449:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000244d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002451:	0f 82 8d fd ff ff    	jb     1400021e4 <do_pseudo_reloc+0x102>
   140002457:	eb 01                	jmp    14000245a <do_pseudo_reloc+0x378>
   140002459:	90                   	nop
   14000245a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000245e:	5d                   	pop    rbp
   14000245f:	c3                   	ret

0000000140002460 <_pei386_runtime_relocator>:
   140002460:	55                   	push   rbp
   140002461:	48 89 e5             	mov    rbp,rsp
   140002464:	48 83 ec 30          	sub    rsp,0x30
   140002468:	8b 05 7e 6c 00 00    	mov    eax,DWORD PTR [rip+0x6c7e]        # 1400090ec <was_init.0>
   14000246e:	85 c0                	test   eax,eax
   140002470:	0f 85 88 00 00 00    	jne    1400024fe <_pei386_runtime_relocator+0x9e>
   140002476:	8b 05 70 6c 00 00    	mov    eax,DWORD PTR [rip+0x6c70]        # 1400090ec <was_init.0>
   14000247c:	83 c0 01             	add    eax,0x1
   14000247f:	89 05 67 6c 00 00    	mov    DWORD PTR [rip+0x6c67],eax        # 1400090ec <was_init.0>
   140002485:	e8 21 0b 00 00       	call   140002fab <__mingw_GetSectionCount>
   14000248a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000248d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002490:	48 63 d0             	movsxd rdx,eax
   140002493:	48 89 d0             	mov    rax,rdx
   140002496:	48 c1 e0 02          	shl    rax,0x2
   14000249a:	48 01 d0             	add    rax,rdx
   14000249d:	48 c1 e0 03          	shl    rax,0x3
   1400024a1:	48 83 c0 0f          	add    rax,0xf
   1400024a5:	48 c1 e8 04          	shr    rax,0x4
   1400024a9:	48 c1 e0 04          	shl    rax,0x4
   1400024ad:	e8 7e 0d 00 00       	call   140003230 <___chkstk_ms>
   1400024b2:	48 29 c4             	sub    rsp,rax
   1400024b5:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400024ba:	48 83 c0 0f          	add    rax,0xf
   1400024be:	48 c1 e8 04          	shr    rax,0x4
   1400024c2:	48 c1 e0 04          	shl    rax,0x4
   1400024c6:	48 89 05 13 6c 00 00 	mov    QWORD PTR [rip+0x6c13],rax        # 1400090e0 <the_secs>
   1400024cd:	c7 05 11 6c 00 00 00 	mov    DWORD PTR [rip+0x6c11],0x0        # 1400090e8 <maxSections>
   1400024d4:	00 00 00 
   1400024d7:	48 8b 0d 82 2e 00 00 	mov    rcx,QWORD PTR [rip+0x2e82]        # 140005360 <.refptr.__ImageBase>
   1400024de:	48 8b 15 8b 2e 00 00 	mov    rdx,QWORD PTR [rip+0x2e8b]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   1400024e5:	48 8b 05 94 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e94]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   1400024ec:	49 89 c8             	mov    r8,rcx
   1400024ef:	48 89 c1             	mov    rcx,rax
   1400024f2:	e8 eb fb ff ff       	call   1400020e2 <do_pseudo_reloc>
   1400024f7:	e8 c7 fa ff ff       	call   140001fc3 <restore_modified_sections>
   1400024fc:	eb 01                	jmp    1400024ff <_pei386_runtime_relocator+0x9f>
   1400024fe:	90                   	nop
   1400024ff:	48 89 ec             	mov    rsp,rbp
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

0000000140002510 <__mingw_raise_matherr>:
   140002510:	55                   	push   rbp
   140002511:	48 89 e5             	mov    rbp,rsp
   140002514:	48 83 ec 50          	sub    rsp,0x50
   140002518:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000251b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000251f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002524:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002529:	48 8b 05 c0 6b 00 00 	mov    rax,QWORD PTR [rip+0x6bc0]        # 1400090f0 <stUserMathErr>
   140002530:	48 85 c0             	test   rax,rax
   140002533:	74 3e                	je     140002573 <__mingw_raise_matherr+0x63>
   140002535:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002538:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000253b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000253f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002543:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002548:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000254d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002552:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002557:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000255c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002561:	48 8b 15 88 6b 00 00 	mov    rdx,QWORD PTR [rip+0x6b88]        # 1400090f0 <stUserMathErr>
   140002568:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000256c:	48 89 c1             	mov    rcx,rax
   14000256f:	ff d2                	call   rdx
   140002571:	eb 01                	jmp    140002574 <__mingw_raise_matherr+0x64>
   140002573:	90                   	nop
   140002574:	48 83 c4 50          	add    rsp,0x50
   140002578:	5d                   	pop    rbp
   140002579:	c3                   	ret

000000014000257a <__mingw_setusermatherr>:
   14000257a:	55                   	push   rbp
   14000257b:	48 89 e5             	mov    rbp,rsp
   14000257e:	48 83 ec 20          	sub    rsp,0x20
   140002582:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002586:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000258a:	48 89 05 5f 6b 00 00 	mov    QWORD PTR [rip+0x6b5f],rax        # 1400090f0 <stUserMathErr>
   140002591:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002595:	48 89 c1             	mov    rcx,rax
   140002598:	e8 13 0e 00 00       	call   1400033b0 <__setusermatherr>
   14000259d:	90                   	nop
   14000259e:	48 83 c4 20          	add    rsp,0x20
   1400025a2:	5d                   	pop    rbp
   1400025a3:	c3                   	ret
   1400025a4:	90                   	nop
   1400025a5:	90                   	nop
   1400025a6:	90                   	nop
   1400025a7:	90                   	nop
   1400025a8:	90                   	nop
   1400025a9:	90                   	nop
   1400025aa:	90                   	nop
   1400025ab:	90                   	nop
   1400025ac:	90                   	nop
   1400025ad:	90                   	nop
   1400025ae:	90                   	nop
   1400025af:	90                   	nop

00000001400025b0 <__mingw_SEH_error_handler>:
   1400025b0:	55                   	push   rbp
   1400025b1:	48 89 e5             	mov    rbp,rsp
   1400025b4:	48 83 ec 30          	sub    rsp,0x30
   1400025b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400025bc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400025c0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400025c4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400025c8:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400025cf:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400025d6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400025da:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400025dd:	83 e0 02             	and    eax,0x2
   1400025e0:	85 c0                	test   eax,eax
   1400025e2:	74 0a                	je     1400025ee <__mingw_SEH_error_handler+0x3e>
   1400025e4:	b8 01 00 00 00       	mov    eax,0x1
   1400025e9:	e9 16 02 00 00       	jmp    140002804 <__mingw_SEH_error_handler+0x254>
   1400025ee:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400025f2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400025f4:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400025f9:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400025fe:	75 18                	jne    140002618 <__mingw_SEH_error_handler+0x68>
   140002600:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002604:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002607:	83 e0 01             	and    eax,0x1
   14000260a:	85 c0                	test   eax,eax
   14000260c:	75 0a                	jne    140002618 <__mingw_SEH_error_handler+0x68>
   14000260e:	b8 00 00 00 00       	mov    eax,0x0
   140002613:	e9 ec 01 00 00       	jmp    140002804 <__mingw_SEH_error_handler+0x254>
   140002618:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000261c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000261e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002623:	0f 84 12 01 00 00    	je     14000273b <__mingw_SEH_error_handler+0x18b>
   140002629:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000262e:	0f 87 c3 01 00 00    	ja     1400027f7 <__mingw_SEH_error_handler+0x247>
   140002634:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002639:	0f 87 b8 01 00 00    	ja     1400027f7 <__mingw_SEH_error_handler+0x247>
   14000263f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002644:	0f 83 4c 01 00 00    	jae    140002796 <__mingw_SEH_error_handler+0x1e6>
   14000264a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000264f:	0f 84 3a 01 00 00    	je     14000278f <__mingw_SEH_error_handler+0x1df>
   140002655:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000265a:	0f 87 97 01 00 00    	ja     1400027f7 <__mingw_SEH_error_handler+0x247>
   140002660:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002665:	0f 84 83 01 00 00    	je     1400027ee <__mingw_SEH_error_handler+0x23e>
   14000266b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002670:	0f 87 81 01 00 00    	ja     1400027f7 <__mingw_SEH_error_handler+0x247>
   140002676:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000267b:	0f 87 76 01 00 00    	ja     1400027f7 <__mingw_SEH_error_handler+0x247>
   140002681:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002686:	0f 83 03 01 00 00    	jae    14000278f <__mingw_SEH_error_handler+0x1df>
   14000268c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002691:	0f 84 57 01 00 00    	je     1400027ee <__mingw_SEH_error_handler+0x23e>
   140002697:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000269c:	0f 87 55 01 00 00    	ja     1400027f7 <__mingw_SEH_error_handler+0x247>
   1400026a2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400026a7:	0f 84 8e 00 00 00    	je     14000273b <__mingw_SEH_error_handler+0x18b>
   1400026ad:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400026b2:	0f 87 3f 01 00 00    	ja     1400027f7 <__mingw_SEH_error_handler+0x247>
   1400026b8:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400026bd:	0f 84 2b 01 00 00    	je     1400027ee <__mingw_SEH_error_handler+0x23e>
   1400026c3:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400026c8:	0f 87 29 01 00 00    	ja     1400027f7 <__mingw_SEH_error_handler+0x247>
   1400026ce:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400026d3:	0f 84 15 01 00 00    	je     1400027ee <__mingw_SEH_error_handler+0x23e>
   1400026d9:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400026de:	0f 85 13 01 00 00    	jne    1400027f7 <__mingw_SEH_error_handler+0x247>
   1400026e4:	ba 00 00 00 00       	mov    edx,0x0
   1400026e9:	b9 0b 00 00 00       	mov    ecx,0xb
   1400026ee:	e8 2d 0d 00 00       	call   140003420 <signal>
   1400026f3:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026f7:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026fc:	75 1b                	jne    140002719 <__mingw_SEH_error_handler+0x169>
   1400026fe:	ba 01 00 00 00       	mov    edx,0x1
   140002703:	b9 0b 00 00 00       	mov    ecx,0xb
   140002708:	e8 13 0d 00 00       	call   140003420 <signal>
   14000270d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002714:	e9 e1 00 00 00       	jmp    1400027fa <__mingw_SEH_error_handler+0x24a>
   140002719:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000271e:	0f 84 d6 00 00 00    	je     1400027fa <__mingw_SEH_error_handler+0x24a>
   140002724:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002728:	b9 0b 00 00 00       	mov    ecx,0xb
   14000272d:	ff d0                	call   rax
   14000272f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002736:	e9 bf 00 00 00       	jmp    1400027fa <__mingw_SEH_error_handler+0x24a>
   14000273b:	ba 00 00 00 00       	mov    edx,0x0
   140002740:	b9 04 00 00 00       	mov    ecx,0x4
   140002745:	e8 d6 0c 00 00       	call   140003420 <signal>
   14000274a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000274e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002753:	75 1b                	jne    140002770 <__mingw_SEH_error_handler+0x1c0>
   140002755:	ba 01 00 00 00       	mov    edx,0x1
   14000275a:	b9 04 00 00 00       	mov    ecx,0x4
   14000275f:	e8 bc 0c 00 00       	call   140003420 <signal>
   140002764:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000276b:	e9 8d 00 00 00       	jmp    1400027fd <__mingw_SEH_error_handler+0x24d>
   140002770:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002775:	0f 84 82 00 00 00    	je     1400027fd <__mingw_SEH_error_handler+0x24d>
   14000277b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000277f:	b9 04 00 00 00       	mov    ecx,0x4
   140002784:	ff d0                	call   rax
   140002786:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000278d:	eb 6e                	jmp    1400027fd <__mingw_SEH_error_handler+0x24d>
   14000278f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002796:	ba 00 00 00 00       	mov    edx,0x0
   14000279b:	b9 08 00 00 00       	mov    ecx,0x8
   1400027a0:	e8 7b 0c 00 00       	call   140003420 <signal>
   1400027a5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027a9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027ae:	75 23                	jne    1400027d3 <__mingw_SEH_error_handler+0x223>
   1400027b0:	ba 01 00 00 00       	mov    edx,0x1
   1400027b5:	b9 08 00 00 00       	mov    ecx,0x8
   1400027ba:	e8 61 0c 00 00       	call   140003420 <signal>
   1400027bf:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400027c3:	74 05                	je     1400027ca <__mingw_SEH_error_handler+0x21a>
   1400027c5:	e8 a6 05 00 00       	call   140002d70 <_fpreset>
   1400027ca:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400027d1:	eb 2d                	jmp    140002800 <__mingw_SEH_error_handler+0x250>
   1400027d3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027d8:	74 26                	je     140002800 <__mingw_SEH_error_handler+0x250>
   1400027da:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027de:	b9 08 00 00 00       	mov    ecx,0x8
   1400027e3:	ff d0                	call   rax
   1400027e5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400027ec:	eb 12                	jmp    140002800 <__mingw_SEH_error_handler+0x250>
   1400027ee:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400027f5:	eb 0a                	jmp    140002801 <__mingw_SEH_error_handler+0x251>
   1400027f7:	90                   	nop
   1400027f8:	eb 07                	jmp    140002801 <__mingw_SEH_error_handler+0x251>
   1400027fa:	90                   	nop
   1400027fb:	eb 04                	jmp    140002801 <__mingw_SEH_error_handler+0x251>
   1400027fd:	90                   	nop
   1400027fe:	eb 01                	jmp    140002801 <__mingw_SEH_error_handler+0x251>
   140002800:	90                   	nop
   140002801:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002804:	48 83 c4 30          	add    rsp,0x30
   140002808:	5d                   	pop    rbp
   140002809:	c3                   	ret

000000014000280a <_gnu_exception_handler>:
   14000280a:	55                   	push   rbp
   14000280b:	48 89 e5             	mov    rbp,rsp
   14000280e:	48 83 ec 30          	sub    rsp,0x30
   140002812:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002816:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000281d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002824:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002828:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000282b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000282d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002832:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002837:	75 1b                	jne    140002854 <_gnu_exception_handler+0x4a>
   140002839:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000283d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002840:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002843:	83 e0 01             	and    eax,0x1
   140002846:	85 c0                	test   eax,eax
   140002848:	75 0a                	jne    140002854 <_gnu_exception_handler+0x4a>
   14000284a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000284f:	e9 14 02 00 00       	jmp    140002a68 <_gnu_exception_handler+0x25e>
   140002854:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002858:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000285b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000285d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002862:	0f 84 12 01 00 00    	je     14000297a <_gnu_exception_handler+0x170>
   140002868:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000286d:	0f 87 c3 01 00 00    	ja     140002a36 <_gnu_exception_handler+0x22c>
   140002873:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002878:	0f 87 b8 01 00 00    	ja     140002a36 <_gnu_exception_handler+0x22c>
   14000287e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002883:	0f 83 4c 01 00 00    	jae    1400029d5 <_gnu_exception_handler+0x1cb>
   140002889:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000288e:	0f 84 3a 01 00 00    	je     1400029ce <_gnu_exception_handler+0x1c4>
   140002894:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002899:	0f 87 97 01 00 00    	ja     140002a36 <_gnu_exception_handler+0x22c>
   14000289f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400028a4:	0f 84 83 01 00 00    	je     140002a2d <_gnu_exception_handler+0x223>
   1400028aa:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400028af:	0f 87 81 01 00 00    	ja     140002a36 <_gnu_exception_handler+0x22c>
   1400028b5:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400028ba:	0f 87 76 01 00 00    	ja     140002a36 <_gnu_exception_handler+0x22c>
   1400028c0:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400028c5:	0f 83 03 01 00 00    	jae    1400029ce <_gnu_exception_handler+0x1c4>
   1400028cb:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400028d0:	0f 84 57 01 00 00    	je     140002a2d <_gnu_exception_handler+0x223>
   1400028d6:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400028db:	0f 87 55 01 00 00    	ja     140002a36 <_gnu_exception_handler+0x22c>
   1400028e1:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400028e6:	0f 84 8e 00 00 00    	je     14000297a <_gnu_exception_handler+0x170>
   1400028ec:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400028f1:	0f 87 3f 01 00 00    	ja     140002a36 <_gnu_exception_handler+0x22c>
   1400028f7:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400028fc:	0f 84 2b 01 00 00    	je     140002a2d <_gnu_exception_handler+0x223>
   140002902:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002907:	0f 87 29 01 00 00    	ja     140002a36 <_gnu_exception_handler+0x22c>
   14000290d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002912:	0f 84 15 01 00 00    	je     140002a2d <_gnu_exception_handler+0x223>
   140002918:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000291d:	0f 85 13 01 00 00    	jne    140002a36 <_gnu_exception_handler+0x22c>
   140002923:	ba 00 00 00 00       	mov    edx,0x0
   140002928:	b9 0b 00 00 00       	mov    ecx,0xb
   14000292d:	e8 ee 0a 00 00       	call   140003420 <signal>
   140002932:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002936:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000293b:	75 1b                	jne    140002958 <_gnu_exception_handler+0x14e>
   14000293d:	ba 01 00 00 00       	mov    edx,0x1
   140002942:	b9 0b 00 00 00       	mov    ecx,0xb
   140002947:	e8 d4 0a 00 00       	call   140003420 <signal>
   14000294c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002953:	e9 e1 00 00 00       	jmp    140002a39 <_gnu_exception_handler+0x22f>
   140002958:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000295d:	0f 84 d6 00 00 00    	je     140002a39 <_gnu_exception_handler+0x22f>
   140002963:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002967:	b9 0b 00 00 00       	mov    ecx,0xb
   14000296c:	ff d0                	call   rax
   14000296e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002975:	e9 bf 00 00 00       	jmp    140002a39 <_gnu_exception_handler+0x22f>
   14000297a:	ba 00 00 00 00       	mov    edx,0x0
   14000297f:	b9 04 00 00 00       	mov    ecx,0x4
   140002984:	e8 97 0a 00 00       	call   140003420 <signal>
   140002989:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000298d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002992:	75 1b                	jne    1400029af <_gnu_exception_handler+0x1a5>
   140002994:	ba 01 00 00 00       	mov    edx,0x1
   140002999:	b9 04 00 00 00       	mov    ecx,0x4
   14000299e:	e8 7d 0a 00 00       	call   140003420 <signal>
   1400029a3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400029aa:	e9 8d 00 00 00       	jmp    140002a3c <_gnu_exception_handler+0x232>
   1400029af:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400029b4:	0f 84 82 00 00 00    	je     140002a3c <_gnu_exception_handler+0x232>
   1400029ba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029be:	b9 04 00 00 00       	mov    ecx,0x4
   1400029c3:	ff d0                	call   rax
   1400029c5:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400029cc:	eb 6e                	jmp    140002a3c <_gnu_exception_handler+0x232>
   1400029ce:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400029d5:	ba 00 00 00 00       	mov    edx,0x0
   1400029da:	b9 08 00 00 00       	mov    ecx,0x8
   1400029df:	e8 3c 0a 00 00       	call   140003420 <signal>
   1400029e4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029e8:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400029ed:	75 23                	jne    140002a12 <_gnu_exception_handler+0x208>
   1400029ef:	ba 01 00 00 00       	mov    edx,0x1
   1400029f4:	b9 08 00 00 00       	mov    ecx,0x8
   1400029f9:	e8 22 0a 00 00       	call   140003420 <signal>
   1400029fe:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002a02:	74 05                	je     140002a09 <_gnu_exception_handler+0x1ff>
   140002a04:	e8 67 03 00 00       	call   140002d70 <_fpreset>
   140002a09:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a10:	eb 2d                	jmp    140002a3f <_gnu_exception_handler+0x235>
   140002a12:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a17:	74 26                	je     140002a3f <_gnu_exception_handler+0x235>
   140002a19:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a1d:	b9 08 00 00 00       	mov    ecx,0x8
   140002a22:	ff d0                	call   rax
   140002a24:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a2b:	eb 12                	jmp    140002a3f <_gnu_exception_handler+0x235>
   140002a2d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a34:	eb 0a                	jmp    140002a40 <_gnu_exception_handler+0x236>
   140002a36:	90                   	nop
   140002a37:	eb 07                	jmp    140002a40 <_gnu_exception_handler+0x236>
   140002a39:	90                   	nop
   140002a3a:	eb 04                	jmp    140002a40 <_gnu_exception_handler+0x236>
   140002a3c:	90                   	nop
   140002a3d:	eb 01                	jmp    140002a40 <_gnu_exception_handler+0x236>
   140002a3f:	90                   	nop
   140002a40:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002a44:	75 1f                	jne    140002a65 <_gnu_exception_handler+0x25b>
   140002a46:	48 8b 05 c3 66 00 00 	mov    rax,QWORD PTR [rip+0x66c3]        # 140009110 <__mingw_oldexcpt_handler>
   140002a4d:	48 85 c0             	test   rax,rax
   140002a50:	74 13                	je     140002a65 <_gnu_exception_handler+0x25b>
   140002a52:	48 8b 15 b7 66 00 00 	mov    rdx,QWORD PTR [rip+0x66b7]        # 140009110 <__mingw_oldexcpt_handler>
   140002a59:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002a5d:	48 89 c1             	mov    rcx,rax
   140002a60:	ff d2                	call   rdx
   140002a62:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002a65:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002a68:	48 83 c4 30          	add    rsp,0x30
   140002a6c:	5d                   	pop    rbp
   140002a6d:	c3                   	ret
   140002a6e:	90                   	nop
   140002a6f:	90                   	nop

0000000140002a70 <___w64_mingwthr_add_key_dtor>:
   140002a70:	55                   	push   rbp
   140002a71:	48 89 e5             	mov    rbp,rsp
   140002a74:	48 83 ec 30          	sub    rsp,0x30
   140002a78:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a7b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002a7f:	8b 05 c3 66 00 00    	mov    eax,DWORD PTR [rip+0x66c3]        # 140009148 <__mingwthr_cs_init>
   140002a85:	85 c0                	test   eax,eax
   140002a87:	75 07                	jne    140002a90 <___w64_mingwthr_add_key_dtor+0x20>
   140002a89:	b8 00 00 00 00       	mov    eax,0x0
   140002a8e:	eb 7b                	jmp    140002b0b <___w64_mingwthr_add_key_dtor+0x9b>
   140002a90:	ba 18 00 00 00       	mov    edx,0x18
   140002a95:	b9 01 00 00 00       	mov    ecx,0x1
   140002a9a:	e8 41 09 00 00       	call   1400033e0 <calloc>
   140002a9f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002aa3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002aa8:	75 07                	jne    140002ab1 <___w64_mingwthr_add_key_dtor+0x41>
   140002aaa:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140002aaf:	eb 5a                	jmp    140002b0b <___w64_mingwthr_add_key_dtor+0x9b>
   140002ab1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ab5:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002ab8:	89 10                	mov    DWORD PTR [rax],edx
   140002aba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002abe:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002ac2:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002ac6:	48 8d 05 53 66 00 00 	lea    rax,[rip+0x6653]        # 140009120 <__mingwthr_cs>
   140002acd:	48 89 c1             	mov    rcx,rax
   140002ad0:	48 8b 05 b9 76 00 00 	mov    rax,QWORD PTR [rip+0x76b9]        # 14000a190 <__imp_EnterCriticalSection>
   140002ad7:	ff d0                	call   rax
   140002ad9:	48 8b 15 70 66 00 00 	mov    rdx,QWORD PTR [rip+0x6670]        # 140009150 <key_dtor_list>
   140002ae0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ae4:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002ae8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002aec:	48 89 05 5d 66 00 00 	mov    QWORD PTR [rip+0x665d],rax        # 140009150 <key_dtor_list>
   140002af3:	48 8d 05 26 66 00 00 	lea    rax,[rip+0x6626]        # 140009120 <__mingwthr_cs>
   140002afa:	48 89 c1             	mov    rcx,rax
   140002afd:	48 8b 05 bc 76 00 00 	mov    rax,QWORD PTR [rip+0x76bc]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002b04:	ff d0                	call   rax
   140002b06:	b8 00 00 00 00       	mov    eax,0x0
   140002b0b:	48 83 c4 30          	add    rsp,0x30
   140002b0f:	5d                   	pop    rbp
   140002b10:	c3                   	ret

0000000140002b11 <___w64_mingwthr_remove_key_dtor>:
   140002b11:	55                   	push   rbp
   140002b12:	48 89 e5             	mov    rbp,rsp
   140002b15:	48 83 ec 30          	sub    rsp,0x30
   140002b19:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002b1c:	8b 05 26 66 00 00    	mov    eax,DWORD PTR [rip+0x6626]        # 140009148 <__mingwthr_cs_init>
   140002b22:	85 c0                	test   eax,eax
   140002b24:	75 0a                	jne    140002b30 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002b26:	b8 00 00 00 00       	mov    eax,0x0
   140002b2b:	e9 9c 00 00 00       	jmp    140002bcc <___w64_mingwthr_remove_key_dtor+0xbb>
   140002b30:	48 8d 05 e9 65 00 00 	lea    rax,[rip+0x65e9]        # 140009120 <__mingwthr_cs>
   140002b37:	48 89 c1             	mov    rcx,rax
   140002b3a:	48 8b 05 4f 76 00 00 	mov    rax,QWORD PTR [rip+0x764f]        # 14000a190 <__imp_EnterCriticalSection>
   140002b41:	ff d0                	call   rax
   140002b43:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002b4a:	00 
   140002b4b:	48 8b 05 fe 65 00 00 	mov    rax,QWORD PTR [rip+0x65fe]        # 140009150 <key_dtor_list>
   140002b52:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b56:	eb 55                	jmp    140002bad <___w64_mingwthr_remove_key_dtor+0x9c>
   140002b58:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b5c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b5e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002b61:	75 36                	jne    140002b99 <___w64_mingwthr_remove_key_dtor+0x88>
   140002b63:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b68:	75 11                	jne    140002b7b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002b6a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b6e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b72:	48 89 05 d7 65 00 00 	mov    QWORD PTR [rip+0x65d7],rax        # 140009150 <key_dtor_list>
   140002b79:	eb 10                	jmp    140002b8b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002b7b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b7f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002b83:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b87:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002b8b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b8f:	48 89 c1             	mov    rcx,rax
   140002b92:	e8 69 08 00 00       	call   140003400 <free>
   140002b97:	eb 1b                	jmp    140002bb4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002b99:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b9d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ba1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ba5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ba9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002bad:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002bb2:	75 a4                	jne    140002b58 <___w64_mingwthr_remove_key_dtor+0x47>
   140002bb4:	48 8d 05 65 65 00 00 	lea    rax,[rip+0x6565]        # 140009120 <__mingwthr_cs>
   140002bbb:	48 89 c1             	mov    rcx,rax
   140002bbe:	48 8b 05 fb 75 00 00 	mov    rax,QWORD PTR [rip+0x75fb]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002bc5:	ff d0                	call   rax
   140002bc7:	b8 00 00 00 00       	mov    eax,0x0
   140002bcc:	48 83 c4 30          	add    rsp,0x30
   140002bd0:	5d                   	pop    rbp
   140002bd1:	c3                   	ret

0000000140002bd2 <__mingwthr_run_key_dtors>:
   140002bd2:	55                   	push   rbp
   140002bd3:	48 89 e5             	mov    rbp,rsp
   140002bd6:	48 83 ec 30          	sub    rsp,0x30
   140002bda:	8b 05 68 65 00 00    	mov    eax,DWORD PTR [rip+0x6568]        # 140009148 <__mingwthr_cs_init>
   140002be0:	85 c0                	test   eax,eax
   140002be2:	0f 84 82 00 00 00    	je     140002c6a <__mingwthr_run_key_dtors+0x98>
   140002be8:	48 8d 05 31 65 00 00 	lea    rax,[rip+0x6531]        # 140009120 <__mingwthr_cs>
   140002bef:	48 89 c1             	mov    rcx,rax
   140002bf2:	48 8b 05 97 75 00 00 	mov    rax,QWORD PTR [rip+0x7597]        # 14000a190 <__imp_EnterCriticalSection>
   140002bf9:	ff d0                	call   rax
   140002bfb:	48 8b 05 4e 65 00 00 	mov    rax,QWORD PTR [rip+0x654e]        # 140009150 <key_dtor_list>
   140002c02:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c06:	eb 46                	jmp    140002c4e <__mingwthr_run_key_dtors+0x7c>
   140002c08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c0c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c0e:	89 c1                	mov    ecx,eax
   140002c10:	48 8b 05 c9 75 00 00 	mov    rax,QWORD PTR [rip+0x75c9]        # 14000a1e0 <__imp_TlsGetValue>
   140002c17:	ff d0                	call   rax
   140002c19:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c1d:	48 8b 05 7c 75 00 00 	mov    rax,QWORD PTR [rip+0x757c]        # 14000a1a0 <__imp_GetLastError>
   140002c24:	ff d0                	call   rax
   140002c26:	85 c0                	test   eax,eax
   140002c28:	75 18                	jne    140002c42 <__mingwthr_run_key_dtors+0x70>
   140002c2a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002c2f:	74 11                	je     140002c42 <__mingwthr_run_key_dtors+0x70>
   140002c31:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c35:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002c39:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c3d:	48 89 c1             	mov    rcx,rax
   140002c40:	ff d2                	call   rdx
   140002c42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c46:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c4a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c4e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c53:	75 b3                	jne    140002c08 <__mingwthr_run_key_dtors+0x36>
   140002c55:	48 8d 05 c4 64 00 00 	lea    rax,[rip+0x64c4]        # 140009120 <__mingwthr_cs>
   140002c5c:	48 89 c1             	mov    rcx,rax
   140002c5f:	48 8b 05 5a 75 00 00 	mov    rax,QWORD PTR [rip+0x755a]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002c66:	ff d0                	call   rax
   140002c68:	eb 01                	jmp    140002c6b <__mingwthr_run_key_dtors+0x99>
   140002c6a:	90                   	nop
   140002c6b:	48 83 c4 30          	add    rsp,0x30
   140002c6f:	5d                   	pop    rbp
   140002c70:	c3                   	ret

0000000140002c71 <__mingw_TLScallback>:
   140002c71:	55                   	push   rbp
   140002c72:	48 89 e5             	mov    rbp,rsp
   140002c75:	48 83 ec 30          	sub    rsp,0x30
   140002c79:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c7d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002c80:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002c84:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002c88:	0f 84 cc 00 00 00    	je     140002d5a <__mingw_TLScallback+0xe9>
   140002c8e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002c92:	0f 87 ca 00 00 00    	ja     140002d62 <__mingw_TLScallback+0xf1>
   140002c98:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002c9c:	0f 84 b1 00 00 00    	je     140002d53 <__mingw_TLScallback+0xe2>
   140002ca2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002ca6:	0f 87 b6 00 00 00    	ja     140002d62 <__mingw_TLScallback+0xf1>
   140002cac:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002cb0:	74 33                	je     140002ce5 <__mingw_TLScallback+0x74>
   140002cb2:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002cb6:	0f 85 a6 00 00 00    	jne    140002d62 <__mingw_TLScallback+0xf1>
   140002cbc:	8b 05 86 64 00 00    	mov    eax,DWORD PTR [rip+0x6486]        # 140009148 <__mingwthr_cs_init>
   140002cc2:	85 c0                	test   eax,eax
   140002cc4:	75 13                	jne    140002cd9 <__mingw_TLScallback+0x68>
   140002cc6:	48 8d 05 53 64 00 00 	lea    rax,[rip+0x6453]        # 140009120 <__mingwthr_cs>
   140002ccd:	48 89 c1             	mov    rcx,rax
   140002cd0:	48 8b 05 e1 74 00 00 	mov    rax,QWORD PTR [rip+0x74e1]        # 14000a1b8 <__imp_InitializeCriticalSection>
   140002cd7:	ff d0                	call   rax
   140002cd9:	c7 05 65 64 00 00 01 	mov    DWORD PTR [rip+0x6465],0x1        # 140009148 <__mingwthr_cs_init>
   140002ce0:	00 00 00 
   140002ce3:	eb 7d                	jmp    140002d62 <__mingw_TLScallback+0xf1>
   140002ce5:	e8 e8 fe ff ff       	call   140002bd2 <__mingwthr_run_key_dtors>
   140002cea:	8b 05 58 64 00 00    	mov    eax,DWORD PTR [rip+0x6458]        # 140009148 <__mingwthr_cs_init>
   140002cf0:	83 f8 01             	cmp    eax,0x1
   140002cf3:	75 6c                	jne    140002d61 <__mingw_TLScallback+0xf0>
   140002cf5:	48 8b 05 54 64 00 00 	mov    rax,QWORD PTR [rip+0x6454]        # 140009150 <key_dtor_list>
   140002cfc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d00:	eb 20                	jmp    140002d22 <__mingw_TLScallback+0xb1>
   140002d02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d06:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002d0a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002d0e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d12:	48 89 c1             	mov    rcx,rax
   140002d15:	e8 e6 06 00 00       	call   140003400 <free>
   140002d1a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d1e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d22:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002d27:	75 d9                	jne    140002d02 <__mingw_TLScallback+0x91>
   140002d29:	48 c7 05 1c 64 00 00 	mov    QWORD PTR [rip+0x641c],0x0        # 140009150 <key_dtor_list>
   140002d30:	00 00 00 00 
   140002d34:	c7 05 0a 64 00 00 00 	mov    DWORD PTR [rip+0x640a],0x0        # 140009148 <__mingwthr_cs_init>
   140002d3b:	00 00 00 
   140002d3e:	48 8d 05 db 63 00 00 	lea    rax,[rip+0x63db]        # 140009120 <__mingwthr_cs>
   140002d45:	48 89 c1             	mov    rcx,rax
   140002d48:	48 8b 05 39 74 00 00 	mov    rax,QWORD PTR [rip+0x7439]        # 14000a188 <__IAT_start__>
   140002d4f:	ff d0                	call   rax
   140002d51:	eb 0e                	jmp    140002d61 <__mingw_TLScallback+0xf0>
   140002d53:	e8 18 00 00 00       	call   140002d70 <_fpreset>
   140002d58:	eb 08                	jmp    140002d62 <__mingw_TLScallback+0xf1>
   140002d5a:	e8 73 fe ff ff       	call   140002bd2 <__mingwthr_run_key_dtors>
   140002d5f:	eb 01                	jmp    140002d62 <__mingw_TLScallback+0xf1>
   140002d61:	90                   	nop
   140002d62:	b8 01 00 00 00       	mov    eax,0x1
   140002d67:	48 83 c4 30          	add    rsp,0x30
   140002d6b:	5d                   	pop    rbp
   140002d6c:	c3                   	ret
   140002d6d:	90                   	nop
   140002d6e:	90                   	nop
   140002d6f:	90                   	nop

0000000140002d70 <_fpreset>:
   140002d70:	55                   	push   rbp
   140002d71:	48 89 e5             	mov    rbp,rsp
   140002d74:	db e3                	fninit
   140002d76:	90                   	nop
   140002d77:	5d                   	pop    rbp
   140002d78:	c3                   	ret
   140002d79:	90                   	nop
   140002d7a:	90                   	nop
   140002d7b:	90                   	nop
   140002d7c:	90                   	nop
   140002d7d:	90                   	nop
   140002d7e:	90                   	nop
   140002d7f:	90                   	nop

0000000140002d80 <_ValidateImageBase>:
   140002d80:	55                   	push   rbp
   140002d81:	48 89 e5             	mov    rbp,rsp
   140002d84:	48 83 ec 20          	sub    rsp,0x20
   140002d88:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d8c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d90:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d98:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d9b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002d9f:	74 07                	je     140002da8 <_ValidateImageBase+0x28>
   140002da1:	b8 00 00 00 00       	mov    eax,0x0
   140002da6:	eb 4e                	jmp    140002df6 <_ValidateImageBase+0x76>
   140002da8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dac:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002daf:	48 63 d0             	movsxd rdx,eax
   140002db2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002db6:	48 01 d0             	add    rax,rdx
   140002db9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002dbd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002dc1:	8b 00                	mov    eax,DWORD PTR [rax]
   140002dc3:	3d 50 45 00 00       	cmp    eax,0x4550
   140002dc8:	74 07                	je     140002dd1 <_ValidateImageBase+0x51>
   140002dca:	b8 00 00 00 00       	mov    eax,0x0
   140002dcf:	eb 25                	jmp    140002df6 <_ValidateImageBase+0x76>
   140002dd1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002dd5:	48 83 c0 18          	add    rax,0x18
   140002dd9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ddd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002de1:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002de4:	66 3d 0b 02          	cmp    ax,0x20b
   140002de8:	74 07                	je     140002df1 <_ValidateImageBase+0x71>
   140002dea:	b8 00 00 00 00       	mov    eax,0x0
   140002def:	eb 05                	jmp    140002df6 <_ValidateImageBase+0x76>
   140002df1:	b8 01 00 00 00       	mov    eax,0x1
   140002df6:	48 83 c4 20          	add    rsp,0x20
   140002dfa:	5d                   	pop    rbp
   140002dfb:	c3                   	ret

0000000140002dfc <_FindPESection>:
   140002dfc:	55                   	push   rbp
   140002dfd:	48 89 e5             	mov    rbp,rsp
   140002e00:	48 83 ec 20          	sub    rsp,0x20
   140002e04:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e08:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002e0c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e10:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e13:	48 63 d0             	movsxd rdx,eax
   140002e16:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e1a:	48 01 d0             	add    rax,rdx
   140002e1d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e21:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e28:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e2c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e30:	0f b7 d0             	movzx  edx,ax
   140002e33:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e37:	48 01 d0             	add    rax,rdx
   140002e3a:	48 83 c0 18          	add    rax,0x18
   140002e3e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e42:	eb 36                	jmp    140002e7a <_FindPESection+0x7e>
   140002e44:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e48:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002e4b:	89 c0                	mov    eax,eax
   140002e4d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002e51:	72 1e                	jb     140002e71 <_FindPESection+0x75>
   140002e53:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e57:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002e5a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e5e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002e61:	01 d0                	add    eax,edx
   140002e63:	89 c0                	mov    eax,eax
   140002e65:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002e69:	73 06                	jae    140002e71 <_FindPESection+0x75>
   140002e6b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e6f:	eb 1e                	jmp    140002e8f <_FindPESection+0x93>
   140002e71:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e75:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e7a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e7e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e82:	0f b7 c0             	movzx  eax,ax
   140002e85:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e88:	72 ba                	jb     140002e44 <_FindPESection+0x48>
   140002e8a:	b8 00 00 00 00       	mov    eax,0x0
   140002e8f:	48 83 c4 20          	add    rsp,0x20
   140002e93:	5d                   	pop    rbp
   140002e94:	c3                   	ret

0000000140002e95 <_FindPESectionByName>:
   140002e95:	55                   	push   rbp
   140002e96:	48 89 e5             	mov    rbp,rsp
   140002e99:	48 83 ec 40          	sub    rsp,0x40
   140002e9d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ea1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ea5:	48 89 c1             	mov    rcx,rax
   140002ea8:	e8 7b 05 00 00       	call   140003428 <strlen>
   140002ead:	48 83 f8 08          	cmp    rax,0x8
   140002eb1:	76 0a                	jbe    140002ebd <_FindPESectionByName+0x28>
   140002eb3:	b8 00 00 00 00       	mov    eax,0x0
   140002eb8:	e9 98 00 00 00       	jmp    140002f55 <_FindPESectionByName+0xc0>
   140002ebd:	48 8b 05 9c 24 00 00 	mov    rax,QWORD PTR [rip+0x249c]        # 140005360 <.refptr.__ImageBase>
   140002ec4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ec8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ecc:	48 89 c1             	mov    rcx,rax
   140002ecf:	e8 ac fe ff ff       	call   140002d80 <_ValidateImageBase>
   140002ed4:	85 c0                	test   eax,eax
   140002ed6:	75 07                	jne    140002edf <_FindPESectionByName+0x4a>
   140002ed8:	b8 00 00 00 00       	mov    eax,0x0
   140002edd:	eb 76                	jmp    140002f55 <_FindPESectionByName+0xc0>
   140002edf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ee3:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ee6:	48 63 d0             	movsxd rdx,eax
   140002ee9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002eed:	48 01 d0             	add    rax,rdx
   140002ef0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002ef4:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002efb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002eff:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f03:	0f b7 d0             	movzx  edx,ax
   140002f06:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f0a:	48 01 d0             	add    rax,rdx
   140002f0d:	48 83 c0 18          	add    rax,0x18
   140002f11:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f15:	eb 29                	jmp    140002f40 <_FindPESectionByName+0xab>
   140002f17:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f1b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002f1f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002f25:	48 89 c1             	mov    rcx,rax
   140002f28:	e8 03 05 00 00       	call   140003430 <strncmp>
   140002f2d:	85 c0                	test   eax,eax
   140002f2f:	75 06                	jne    140002f37 <_FindPESectionByName+0xa2>
   140002f31:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f35:	eb 1e                	jmp    140002f55 <_FindPESectionByName+0xc0>
   140002f37:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f3b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f40:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f44:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f48:	0f b7 c0             	movzx  eax,ax
   140002f4b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f4e:	72 c7                	jb     140002f17 <_FindPESectionByName+0x82>
   140002f50:	b8 00 00 00 00       	mov    eax,0x0
   140002f55:	48 83 c4 40          	add    rsp,0x40
   140002f59:	5d                   	pop    rbp
   140002f5a:	c3                   	ret

0000000140002f5b <__mingw_GetSectionForAddress>:
   140002f5b:	55                   	push   rbp
   140002f5c:	48 89 e5             	mov    rbp,rsp
   140002f5f:	48 83 ec 30          	sub    rsp,0x30
   140002f63:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f67:	48 8b 05 f2 23 00 00 	mov    rax,QWORD PTR [rip+0x23f2]        # 140005360 <.refptr.__ImageBase>
   140002f6e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f76:	48 89 c1             	mov    rcx,rax
   140002f79:	e8 02 fe ff ff       	call   140002d80 <_ValidateImageBase>
   140002f7e:	85 c0                	test   eax,eax
   140002f80:	75 07                	jne    140002f89 <__mingw_GetSectionForAddress+0x2e>
   140002f82:	b8 00 00 00 00       	mov    eax,0x0
   140002f87:	eb 1c                	jmp    140002fa5 <__mingw_GetSectionForAddress+0x4a>
   140002f89:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f8d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002f91:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f95:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002f99:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f9d:	48 89 c1             	mov    rcx,rax
   140002fa0:	e8 57 fe ff ff       	call   140002dfc <_FindPESection>
   140002fa5:	48 83 c4 30          	add    rsp,0x30
   140002fa9:	5d                   	pop    rbp
   140002faa:	c3                   	ret

0000000140002fab <__mingw_GetSectionCount>:
   140002fab:	55                   	push   rbp
   140002fac:	48 89 e5             	mov    rbp,rsp
   140002faf:	48 83 ec 30          	sub    rsp,0x30
   140002fb3:	48 8b 05 a6 23 00 00 	mov    rax,QWORD PTR [rip+0x23a6]        # 140005360 <.refptr.__ImageBase>
   140002fba:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fbe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fc2:	48 89 c1             	mov    rcx,rax
   140002fc5:	e8 b6 fd ff ff       	call   140002d80 <_ValidateImageBase>
   140002fca:	85 c0                	test   eax,eax
   140002fcc:	75 07                	jne    140002fd5 <__mingw_GetSectionCount+0x2a>
   140002fce:	b8 00 00 00 00       	mov    eax,0x0
   140002fd3:	eb 20                	jmp    140002ff5 <__mingw_GetSectionCount+0x4a>
   140002fd5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fd9:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002fdc:	48 63 d0             	movsxd rdx,eax
   140002fdf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fe3:	48 01 d0             	add    rax,rdx
   140002fe6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fee:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ff2:	0f b7 c0             	movzx  eax,ax
   140002ff5:	48 83 c4 30          	add    rsp,0x30
   140002ff9:	5d                   	pop    rbp
   140002ffa:	c3                   	ret

0000000140002ffb <_FindPESectionExec>:
   140002ffb:	55                   	push   rbp
   140002ffc:	48 89 e5             	mov    rbp,rsp
   140002fff:	48 83 ec 40          	sub    rsp,0x40
   140003003:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003007:	48 8b 05 52 23 00 00 	mov    rax,QWORD PTR [rip+0x2352]        # 140005360 <.refptr.__ImageBase>
   14000300e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003012:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003016:	48 89 c1             	mov    rcx,rax
   140003019:	e8 62 fd ff ff       	call   140002d80 <_ValidateImageBase>
   14000301e:	85 c0                	test   eax,eax
   140003020:	75 07                	jne    140003029 <_FindPESectionExec+0x2e>
   140003022:	b8 00 00 00 00       	mov    eax,0x0
   140003027:	eb 78                	jmp    1400030a1 <_FindPESectionExec+0xa6>
   140003029:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000302d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003030:	48 63 d0             	movsxd rdx,eax
   140003033:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003037:	48 01 d0             	add    rax,rdx
   14000303a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000303e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140003045:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003049:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   14000304d:	0f b7 d0             	movzx  edx,ax
   140003050:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003054:	48 01 d0             	add    rax,rdx
   140003057:	48 83 c0 18          	add    rax,0x18
   14000305b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000305f:	eb 2b                	jmp    14000308c <_FindPESectionExec+0x91>
   140003061:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003065:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003068:	25 00 00 00 20       	and    eax,0x20000000
   14000306d:	85 c0                	test   eax,eax
   14000306f:	74 12                	je     140003083 <_FindPESectionExec+0x88>
   140003071:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140003076:	75 06                	jne    14000307e <_FindPESectionExec+0x83>
   140003078:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000307c:	eb 23                	jmp    1400030a1 <_FindPESectionExec+0xa6>
   14000307e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140003083:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140003087:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   14000308c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003090:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140003094:	0f b7 c0             	movzx  eax,ax
   140003097:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   14000309a:	72 c5                	jb     140003061 <_FindPESectionExec+0x66>
   14000309c:	b8 00 00 00 00       	mov    eax,0x0
   1400030a1:	48 83 c4 40          	add    rsp,0x40
   1400030a5:	5d                   	pop    rbp
   1400030a6:	c3                   	ret

00000001400030a7 <_GetPEImageBase>:
   1400030a7:	55                   	push   rbp
   1400030a8:	48 89 e5             	mov    rbp,rsp
   1400030ab:	48 83 ec 30          	sub    rsp,0x30
   1400030af:	48 8b 05 aa 22 00 00 	mov    rax,QWORD PTR [rip+0x22aa]        # 140005360 <.refptr.__ImageBase>
   1400030b6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030ba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030be:	48 89 c1             	mov    rcx,rax
   1400030c1:	e8 ba fc ff ff       	call   140002d80 <_ValidateImageBase>
   1400030c6:	85 c0                	test   eax,eax
   1400030c8:	75 07                	jne    1400030d1 <_GetPEImageBase+0x2a>
   1400030ca:	b8 00 00 00 00       	mov    eax,0x0
   1400030cf:	eb 04                	jmp    1400030d5 <_GetPEImageBase+0x2e>
   1400030d1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030d5:	48 83 c4 30          	add    rsp,0x30
   1400030d9:	5d                   	pop    rbp
   1400030da:	c3                   	ret

00000001400030db <_IsNonwritableInCurrentImage>:
   1400030db:	55                   	push   rbp
   1400030dc:	48 89 e5             	mov    rbp,rsp
   1400030df:	48 83 ec 40          	sub    rsp,0x40
   1400030e3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400030e7:	48 8b 05 72 22 00 00 	mov    rax,QWORD PTR [rip+0x2272]        # 140005360 <.refptr.__ImageBase>
   1400030ee:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030f2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030f6:	48 89 c1             	mov    rcx,rax
   1400030f9:	e8 82 fc ff ff       	call   140002d80 <_ValidateImageBase>
   1400030fe:	85 c0                	test   eax,eax
   140003100:	75 07                	jne    140003109 <_IsNonwritableInCurrentImage+0x2e>
   140003102:	b8 00 00 00 00       	mov    eax,0x0
   140003107:	eb 3d                	jmp    140003146 <_IsNonwritableInCurrentImage+0x6b>
   140003109:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000310d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003111:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003115:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003119:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000311d:	48 89 c1             	mov    rcx,rax
   140003120:	e8 d7 fc ff ff       	call   140002dfc <_FindPESection>
   140003125:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003129:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000312e:	75 07                	jne    140003137 <_IsNonwritableInCurrentImage+0x5c>
   140003130:	b8 00 00 00 00       	mov    eax,0x0
   140003135:	eb 0f                	jmp    140003146 <_IsNonwritableInCurrentImage+0x6b>
   140003137:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000313b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000313e:	f7 d0                	not    eax
   140003140:	c1 e8 1f             	shr    eax,0x1f
   140003143:	0f b6 c0             	movzx  eax,al
   140003146:	48 83 c4 40          	add    rsp,0x40
   14000314a:	5d                   	pop    rbp
   14000314b:	c3                   	ret

000000014000314c <__mingw_enum_import_library_names>:
   14000314c:	55                   	push   rbp
   14000314d:	48 89 e5             	mov    rbp,rsp
   140003150:	48 83 ec 50          	sub    rsp,0x50
   140003154:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003157:	48 8b 05 02 22 00 00 	mov    rax,QWORD PTR [rip+0x2202]        # 140005360 <.refptr.__ImageBase>
   14000315e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003162:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003166:	48 89 c1             	mov    rcx,rax
   140003169:	e8 12 fc ff ff       	call   140002d80 <_ValidateImageBase>
   14000316e:	85 c0                	test   eax,eax
   140003170:	75 0a                	jne    14000317c <__mingw_enum_import_library_names+0x30>
   140003172:	b8 00 00 00 00       	mov    eax,0x0
   140003177:	e9 ab 00 00 00       	jmp    140003227 <__mingw_enum_import_library_names+0xdb>
   14000317c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003180:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003183:	48 63 d0             	movsxd rdx,eax
   140003186:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000318a:	48 01 d0             	add    rax,rdx
   14000318d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003191:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003195:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000319b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000319e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400031a2:	75 07                	jne    1400031ab <__mingw_enum_import_library_names+0x5f>
   1400031a4:	b8 00 00 00 00       	mov    eax,0x0
   1400031a9:	eb 7c                	jmp    140003227 <__mingw_enum_import_library_names+0xdb>
   1400031ab:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400031ae:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400031b2:	48 89 c1             	mov    rcx,rax
   1400031b5:	e8 42 fc ff ff       	call   140002dfc <_FindPESection>
   1400031ba:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400031be:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   1400031c3:	75 07                	jne    1400031cc <__mingw_enum_import_library_names+0x80>
   1400031c5:	b8 00 00 00 00       	mov    eax,0x0
   1400031ca:	eb 5b                	jmp    140003227 <__mingw_enum_import_library_names+0xdb>
   1400031cc:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400031cf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400031d3:	48 01 d0             	add    rax,rdx
   1400031d6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031da:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400031df:	75 07                	jne    1400031e8 <__mingw_enum_import_library_names+0x9c>
   1400031e1:	b8 00 00 00 00       	mov    eax,0x0
   1400031e6:	eb 3f                	jmp    140003227 <__mingw_enum_import_library_names+0xdb>
   1400031e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031ec:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400031ef:	85 c0                	test   eax,eax
   1400031f1:	75 0b                	jne    1400031fe <__mingw_enum_import_library_names+0xb2>
   1400031f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031f7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400031fa:	85 c0                	test   eax,eax
   1400031fc:	74 23                	je     140003221 <__mingw_enum_import_library_names+0xd5>
   1400031fe:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003202:	7f 12                	jg     140003216 <__mingw_enum_import_library_names+0xca>
   140003204:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003208:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000320b:	89 c2                	mov    edx,eax
   14000320d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003211:	48 01 d0             	add    rax,rdx
   140003214:	eb 11                	jmp    140003227 <__mingw_enum_import_library_names+0xdb>
   140003216:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000321a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000321f:	eb c7                	jmp    1400031e8 <__mingw_enum_import_library_names+0x9c>
   140003221:	90                   	nop
   140003222:	b8 00 00 00 00       	mov    eax,0x0
   140003227:	48 83 c4 50          	add    rsp,0x50
   14000322b:	5d                   	pop    rbp
   14000322c:	c3                   	ret
   14000322d:	90                   	nop
   14000322e:	90                   	nop
   14000322f:	90                   	nop

0000000140003230 <___chkstk_ms>:
   140003230:	51                   	push   rcx
   140003231:	50                   	push   rax
   140003232:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003238:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000323d:	72 19                	jb     140003258 <___chkstk_ms+0x28>
   14000323f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003246:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000324a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003250:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003256:	77 e7                	ja     14000323f <___chkstk_ms+0xf>
   140003258:	48 29 c1             	sub    rcx,rax
   14000325b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000325f:	58                   	pop    rax
   140003260:	59                   	pop    rcx
   140003261:	c3                   	ret
   140003262:	90                   	nop
   140003263:	90                   	nop
   140003264:	90                   	nop
   140003265:	90                   	nop
   140003266:	90                   	nop
   140003267:	90                   	nop
   140003268:	90                   	nop
   140003269:	90                   	nop
   14000326a:	90                   	nop
   14000326b:	90                   	nop
   14000326c:	90                   	nop
   14000326d:	90                   	nop
   14000326e:	90                   	nop
   14000326f:	90                   	nop

0000000140003270 <_initterm_e>:
   140003270:	55                   	push   rbp
   140003271:	48 89 e5             	mov    rbp,rsp
   140003274:	48 83 ec 30          	sub    rsp,0x30
   140003278:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000327c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003280:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003284:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003288:	eb 29                	jmp    1400032b3 <_initterm_e+0x43>
   14000328a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000328e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140003291:	48 85 c0             	test   rax,rax
   140003294:	74 17                	je     1400032ad <_initterm_e+0x3d>
   140003296:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000329a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000329d:	ff d0                	call   rax
   14000329f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400032a2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   1400032a6:	74 06                	je     1400032ae <_initterm_e+0x3e>
   1400032a8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400032ab:	eb 15                	jmp    1400032c2 <_initterm_e+0x52>
   1400032ad:	90                   	nop
   1400032ae:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400032b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400032b7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400032bb:	72 cd                	jb     14000328a <_initterm_e+0x1a>
   1400032bd:	b8 00 00 00 00       	mov    eax,0x0
   1400032c2:	48 83 c4 30          	add    rsp,0x30
   1400032c6:	5d                   	pop    rbp
   1400032c7:	c3                   	ret
   1400032c8:	90                   	nop
   1400032c9:	90                   	nop
   1400032ca:	90                   	nop
   1400032cb:	90                   	nop
   1400032cc:	90                   	nop
   1400032cd:	90                   	nop
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <__p__fmode>:
   1400032d0:	55                   	push   rbp
   1400032d1:	48 89 e5             	mov    rbp,rsp
   1400032d4:	48 8b 05 f5 20 00 00 	mov    rax,QWORD PTR [rip+0x20f5]        # 1400053d0 <.refptr.__imp__fmode>
   1400032db:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400032de:	5d                   	pop    rbp
   1400032df:	c3                   	ret

00000001400032e0 <__p__commode>:
   1400032e0:	55                   	push   rbp
   1400032e1:	48 89 e5             	mov    rbp,rsp
   1400032e4:	48 8b 05 d5 20 00 00 	mov    rax,QWORD PTR [rip+0x20d5]        # 1400053c0 <.refptr.__imp__commode>
   1400032eb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400032ee:	5d                   	pop    rbp
   1400032ef:	c3                   	ret

00000001400032f0 <__p___initenv>:
   1400032f0:	55                   	push   rbp
   1400032f1:	48 89 e5             	mov    rbp,rsp
   1400032f4:	48 8b 05 b5 20 00 00 	mov    rax,QWORD PTR [rip+0x20b5]        # 1400053b0 <.refptr.__imp___initenv>
   1400032fb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400032fe:	5d                   	pop    rbp
   1400032ff:	c3                   	ret

0000000140003300 <_set_invalid_parameter_handler>:
   140003300:	55                   	push   rbp
   140003301:	48 89 e5             	mov    rbp,rsp
   140003304:	48 83 ec 10          	sub    rsp,0x10
   140003308:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000330c:	48 8d 05 7d 5e 00 00 	lea    rax,[rip+0x5e7d]        # 140009190 <handler>
   140003313:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003317:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000331b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000331f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003323:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003327:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000332a:	48 89 d0             	mov    rax,rdx
   14000332d:	48 83 c4 10          	add    rsp,0x10
   140003331:	5d                   	pop    rbp
   140003332:	c3                   	ret

0000000140003333 <_get_invalid_parameter_handler>:
   140003333:	55                   	push   rbp
   140003334:	48 89 e5             	mov    rbp,rsp
   140003337:	48 8b 05 52 5e 00 00 	mov    rax,QWORD PTR [rip+0x5e52]        # 140009190 <handler>
   14000333e:	5d                   	pop    rbp
   14000333f:	c3                   	ret

0000000140003340 <_configthreadlocale>:
   140003340:	55                   	push   rbp
   140003341:	48 89 e5             	mov    rbp,rsp
   140003344:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003347:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000334b:	75 07                	jne    140003354 <_configthreadlocale+0x14>
   14000334d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140003352:	eb 05                	jmp    140003359 <_configthreadlocale+0x19>
   140003354:	b8 02 00 00 00       	mov    eax,0x2
   140003359:	5d                   	pop    rbp
   14000335a:	c3                   	ret
   14000335b:	90                   	nop
   14000335c:	90                   	nop
   14000335d:	90                   	nop
   14000335e:	90                   	nop
   14000335f:	90                   	nop

0000000140003360 <__acrt_iob_func>:
   140003360:	55                   	push   rbp
   140003361:	48 89 e5             	mov    rbp,rsp
   140003364:	48 83 ec 20          	sub    rsp,0x20
   140003368:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000336b:	e8 30 00 00 00       	call   1400033a0 <__iob_func>
   140003370:	48 89 c1             	mov    rcx,rax
   140003373:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003376:	48 89 d0             	mov    rax,rdx
   140003379:	48 01 c0             	add    rax,rax
   14000337c:	48 01 d0             	add    rax,rdx
   14000337f:	48 c1 e0 04          	shl    rax,0x4
   140003383:	48 01 c8             	add    rax,rcx
   140003386:	48 83 c4 20          	add    rsp,0x20
   14000338a:	5d                   	pop    rbp
   14000338b:	c3                   	ret
   14000338c:	90                   	nop
   14000338d:	90                   	nop
   14000338e:	90                   	nop
   14000338f:	90                   	nop

0000000140003390 <__C_specific_handler>:
   140003390:	ff 25 6a 6e 00 00    	jmp    QWORD PTR [rip+0x6e6a]        # 14000a200 <__imp___C_specific_handler>
   140003396:	90                   	nop
   140003397:	90                   	nop

0000000140003398 <__getmainargs>:
   140003398:	ff 25 6a 6e 00 00    	jmp    QWORD PTR [rip+0x6e6a]        # 14000a208 <__imp___getmainargs>
   14000339e:	90                   	nop
   14000339f:	90                   	nop

00000001400033a0 <__iob_func>:
   1400033a0:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a218 <__imp___iob_func>
   1400033a6:	90                   	nop
   1400033a7:	90                   	nop

00000001400033a8 <__set_app_type>:
   1400033a8:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a220 <__imp___set_app_type>
   1400033ae:	90                   	nop
   1400033af:	90                   	nop

00000001400033b0 <__setusermatherr>:
   1400033b0:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a228 <__imp___setusermatherr>
   1400033b6:	90                   	nop
   1400033b7:	90                   	nop

00000001400033b8 <_amsg_exit>:
   1400033b8:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a230 <__imp__amsg_exit>
   1400033be:	90                   	nop
   1400033bf:	90                   	nop

00000001400033c0 <_cexit>:
   1400033c0:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a238 <__imp__cexit>
   1400033c6:	90                   	nop
   1400033c7:	90                   	nop

00000001400033c8 <_initterm>:
   1400033c8:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a250 <__imp__initterm>
   1400033ce:	90                   	nop
   1400033cf:	90                   	nop

00000001400033d0 <_crt_atexit>:
   1400033d0:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a258 <__imp__crt_atexit>
   1400033d6:	90                   	nop
   1400033d7:	90                   	nop

00000001400033d8 <abort>:
   1400033d8:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a260 <__imp_abort>
   1400033de:	90                   	nop
   1400033df:	90                   	nop

00000001400033e0 <calloc>:
   1400033e0:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a268 <__imp_calloc>
   1400033e6:	90                   	nop
   1400033e7:	90                   	nop

00000001400033e8 <exit>:
   1400033e8:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a270 <__imp_exit>
   1400033ee:	90                   	nop
   1400033ef:	90                   	nop

00000001400033f0 <fflush>:
   1400033f0:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a278 <__imp_fflush>
   1400033f6:	90                   	nop
   1400033f7:	90                   	nop

00000001400033f8 <fprintf>:
   1400033f8:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a280 <__imp_fprintf>
   1400033fe:	90                   	nop
   1400033ff:	90                   	nop

0000000140003400 <free>:
   140003400:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a288 <__imp_free>
   140003406:	90                   	nop
   140003407:	90                   	nop

0000000140003408 <malloc>:
   140003408:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a290 <__imp_malloc>
   14000340e:	90                   	nop
   14000340f:	90                   	nop

0000000140003410 <memcpy>:
   140003410:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a298 <__imp_memcpy>
   140003416:	90                   	nop
   140003417:	90                   	nop

0000000140003418 <setvbuf>:
   140003418:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a2a0 <__imp_setvbuf>
   14000341e:	90                   	nop
   14000341f:	90                   	nop

0000000140003420 <signal>:
   140003420:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a2a8 <__imp_signal>
   140003426:	90                   	nop
   140003427:	90                   	nop

0000000140003428 <strlen>:
   140003428:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a2b0 <__imp_strlen>
   14000342e:	90                   	nop
   14000342f:	90                   	nop

0000000140003430 <strncmp>:
   140003430:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a2b8 <__imp_strncmp>
   140003436:	90                   	nop
   140003437:	90                   	nop

0000000140003438 <vfprintf>:
   140003438:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a2c0 <__imp_vfprintf>
   14000343e:	90                   	nop
   14000343f:	90                   	nop

0000000140003440 <VirtualQuery>:
   140003440:	ff 25 aa 6d 00 00    	jmp    QWORD PTR [rip+0x6daa]        # 14000a1f0 <__imp_VirtualQuery>
   140003446:	90                   	nop
   140003447:	90                   	nop

0000000140003448 <VirtualProtect>:
   140003448:	ff 25 9a 6d 00 00    	jmp    QWORD PTR [rip+0x6d9a]        # 14000a1e8 <__imp_VirtualProtect>
   14000344e:	90                   	nop
   14000344f:	90                   	nop

0000000140003450 <TlsGetValue>:
   140003450:	ff 25 8a 6d 00 00    	jmp    QWORD PTR [rip+0x6d8a]        # 14000a1e0 <__imp_TlsGetValue>
   140003456:	90                   	nop
   140003457:	90                   	nop

0000000140003458 <Sleep>:
   140003458:	ff 25 7a 6d 00 00    	jmp    QWORD PTR [rip+0x6d7a]        # 14000a1d8 <__imp_Sleep>
   14000345e:	90                   	nop
   14000345f:	90                   	nop

0000000140003460 <SetUnhandledExceptionFilter>:
   140003460:	ff 25 6a 6d 00 00    	jmp    QWORD PTR [rip+0x6d6a]        # 14000a1d0 <__imp_SetUnhandledExceptionFilter>
   140003466:	90                   	nop
   140003467:	90                   	nop

0000000140003468 <LoadLibraryA>:
   140003468:	ff 25 5a 6d 00 00    	jmp    QWORD PTR [rip+0x6d5a]        # 14000a1c8 <__imp_LoadLibraryA>
   14000346e:	90                   	nop
   14000346f:	90                   	nop

0000000140003470 <LeaveCriticalSection>:
   140003470:	ff 25 4a 6d 00 00    	jmp    QWORD PTR [rip+0x6d4a]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140003476:	90                   	nop
   140003477:	90                   	nop

0000000140003478 <InitializeCriticalSection>:
   140003478:	ff 25 3a 6d 00 00    	jmp    QWORD PTR [rip+0x6d3a]        # 14000a1b8 <__imp_InitializeCriticalSection>
   14000347e:	90                   	nop
   14000347f:	90                   	nop

0000000140003480 <GetProcAddress>:
   140003480:	ff 25 2a 6d 00 00    	jmp    QWORD PTR [rip+0x6d2a]        # 14000a1b0 <__imp_GetProcAddress>
   140003486:	90                   	nop
   140003487:	90                   	nop

0000000140003488 <GetModuleHandleA>:
   140003488:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 14000a1a8 <__imp_GetModuleHandleA>
   14000348e:	90                   	nop
   14000348f:	90                   	nop

0000000140003490 <GetLastError>:
   140003490:	ff 25 0a 6d 00 00    	jmp    QWORD PTR [rip+0x6d0a]        # 14000a1a0 <__imp_GetLastError>
   140003496:	90                   	nop
   140003497:	90                   	nop

0000000140003498 <FreeLibrary>:
   140003498:	ff 25 fa 6c 00 00    	jmp    QWORD PTR [rip+0x6cfa]        # 14000a198 <__imp_FreeLibrary>
   14000349e:	90                   	nop
   14000349f:	90                   	nop

00000001400034a0 <EnterCriticalSection>:
   1400034a0:	ff 25 ea 6c 00 00    	jmp    QWORD PTR [rip+0x6cea]        # 14000a190 <__imp_EnterCriticalSection>
   1400034a6:	90                   	nop
   1400034a7:	90                   	nop

00000001400034a8 <DeleteCriticalSection>:
   1400034a8:	ff 25 da 6c 00 00    	jmp    QWORD PTR [rip+0x6cda]        # 14000a188 <__IAT_start__>
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
