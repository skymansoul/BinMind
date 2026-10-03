
C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\test_samples\cve_heap\cve_2018_1000001_glibc\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 57 22 00 00       	call   140003280 <fflush>
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
   14000113b:	e8 08 21 00 00       	call   140003248 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 88 20 00 00       	call   1400031f0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 27 21 00 00       	call   1400032a8 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 cf 20 00 00       	call   140003268 <abort>
   140001199:	e8 52 11 00 00       	call   1400022f0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 29 90 00 00 	mov    rax,QWORD PTR [rip+0x9029]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 c6 1f 00 00       	call   140003190 <_set_invalid_parameter_handler>
   1400011ca:	e8 31 1a 00 00       	call   140002c00 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 47 20 00 00       	call   140003238 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 3b 20 00 00       	call   140003238 <__set_app_type>
   1400011fd:	e8 5e 1f 00 00       	call   140003160 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 5e 1f 00 00       	call   140003170 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 ae 06 00 00       	call   1400018d0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 13 20 00 00       	call   140003248 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 b8 11 00 00       	call   14000240a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 66 1f 00 00       	call   1400031d0 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 80 1e 00 00       	call   140003100 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 ba 1f 00 00       	call   140003248 <_amsg_exit>
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
   1400012cb:	e8 58 1f 00 00       	call   140003228 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 65 1f 00 00       	call   140003248 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 3e 1f 00 00       	call   140003248 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 38 1f 00 00       	call   140003258 <_initterm>
   140001320:	e8 82 05 00 00       	call   1400018a7 <__main>
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
   14000138d:	e8 ee 1d 00 00       	call   140003180 <__p___initenv>
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
   1400013cc:	e8 a7 1e 00 00       	call   140003278 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 70 1e 00 00       	call   140003250 <_cexit>
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
   140001511:	e8 82 1d 00 00       	call   140003298 <malloc>
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
   14000155c:	e8 5f 1d 00 00       	call   1400032c0 <strlen>
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
   140001585:	e8 0e 1d 00 00       	call   140003298 <malloc>
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
   1400015e8:	e8 b3 1c 00 00       	call   1400032a0 <memcpy>
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
   140001642:	e8 19 1c 00 00       	call   140003260 <_crt_atexit>
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

0000000140001760 <main>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 30          	sub    rsp,0x30
   140001768:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000176b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000176f:	e8 33 01 00 00       	call   1400018a7 <__main>
   140001774:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   140001778:	7f 07                	jg     140001781 <main+0x21>
   14000177a:	b8 00 00 00 00       	mov    eax,0x0
   14000177f:	eb 61                	jmp    1400017e2 <main+0x82>
   140001781:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001785:	48 83 c0 08          	add    rax,0x8
   140001789:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000178c:	48 89 c1             	mov    rcx,rax
   14000178f:	e8 2c 1b 00 00       	call   1400032c0 <strlen>
   140001794:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001798:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000179c:	48 83 c0 02          	add    rax,0x2
   1400017a0:	48 89 c1             	mov    rcx,rax
   1400017a3:	e8 f0 1a 00 00       	call   140003298 <malloc>
   1400017a8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400017ac:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400017b1:	75 07                	jne    1400017ba <main+0x5a>
   1400017b3:	b8 01 00 00 00       	mov    eax,0x1
   1400017b8:	eb 28                	jmp    1400017e2 <main+0x82>
   1400017ba:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400017be:	48 83 c0 08          	add    rax,0x8
   1400017c2:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400017c5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017c9:	48 89 c1             	mov    rcx,rax
   1400017cc:	e8 e7 1a 00 00       	call   1400032b8 <strcpy>
   1400017d1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017d5:	48 89 c1             	mov    rcx,rax
   1400017d8:	e8 b3 1a 00 00       	call   140003290 <free>
   1400017dd:	b8 00 00 00 00       	mov    eax,0x0
   1400017e2:	48 83 c4 30          	add    rsp,0x30
   1400017e6:	5d                   	pop    rbp
   1400017e7:	c3                   	ret
   1400017e8:	90                   	nop
   1400017e9:	90                   	nop
   1400017ea:	90                   	nop
   1400017eb:	90                   	nop
   1400017ec:	90                   	nop
   1400017ed:	90                   	nop
   1400017ee:	90                   	nop
   1400017ef:	90                   	nop

00000001400017f0 <__do_global_dtors>:
   1400017f0:	55                   	push   rbp
   1400017f1:	48 89 e5             	mov    rbp,rsp
   1400017f4:	48 83 ec 20          	sub    rsp,0x20
   1400017f8:	eb 1e                	jmp    140001818 <__do_global_dtors+0x28>
   1400017fa:	48 8b 05 0f 28 00 00 	mov    rax,QWORD PTR [rip+0x280f]        # 140004010 <p.0>
   140001801:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001804:	ff d0                	call   rax
   140001806:	48 8b 05 03 28 00 00 	mov    rax,QWORD PTR [rip+0x2803]        # 140004010 <p.0>
   14000180d:	48 83 c0 08          	add    rax,0x8
   140001811:	48 89 05 f8 27 00 00 	mov    QWORD PTR [rip+0x27f8],rax        # 140004010 <p.0>
   140001818:	48 8b 05 f1 27 00 00 	mov    rax,QWORD PTR [rip+0x27f1]        # 140004010 <p.0>
   14000181f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001822:	48 85 c0             	test   rax,rax
   140001825:	75 d3                	jne    1400017fa <__do_global_dtors+0xa>
   140001827:	90                   	nop
   140001828:	90                   	nop
   140001829:	48 83 c4 20          	add    rsp,0x20
   14000182d:	5d                   	pop    rbp
   14000182e:	c3                   	ret

000000014000182f <__do_global_ctors>:
   14000182f:	55                   	push   rbp
   140001830:	48 89 e5             	mov    rbp,rsp
   140001833:	48 83 ec 30          	sub    rsp,0x30
   140001837:	48 8b 05 12 3b 00 00 	mov    rax,QWORD PTR [rip+0x3b12]        # 140005350 <.refptr.__CTOR_LIST__>
   14000183e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001841:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001844:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001848:	75 25                	jne    14000186f <__do_global_ctors+0x40>
   14000184a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001851:	eb 04                	jmp    140001857 <__do_global_ctors+0x28>
   140001853:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001857:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000185a:	8d 50 01             	lea    edx,[rax+0x1]
   14000185d:	48 8b 05 ec 3a 00 00 	mov    rax,QWORD PTR [rip+0x3aec]        # 140005350 <.refptr.__CTOR_LIST__>
   140001864:	89 d2                	mov    edx,edx
   140001866:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000186a:	48 85 c0             	test   rax,rax
   14000186d:	75 e4                	jne    140001853 <__do_global_ctors+0x24>
   14000186f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001872:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001875:	eb 14                	jmp    14000188b <__do_global_ctors+0x5c>
   140001877:	48 8b 05 d2 3a 00 00 	mov    rax,QWORD PTR [rip+0x3ad2]        # 140005350 <.refptr.__CTOR_LIST__>
   14000187e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001881:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001885:	ff d0                	call   rax
   140001887:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000188b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000188f:	75 e6                	jne    140001877 <__do_global_ctors+0x48>
   140001891:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400017f0 <__do_global_dtors>
   140001898:	48 89 c1             	mov    rcx,rax
   14000189b:	e8 8f fd ff ff       	call   14000162f <atexit>
   1400018a0:	90                   	nop
   1400018a1:	48 83 c4 30          	add    rsp,0x30
   1400018a5:	5d                   	pop    rbp
   1400018a6:	c3                   	ret

00000001400018a7 <__main>:
   1400018a7:	55                   	push   rbp
   1400018a8:	48 89 e5             	mov    rbp,rsp
   1400018ab:	48 83 ec 20          	sub    rsp,0x20
   1400018af:	8b 05 cb 77 00 00    	mov    eax,DWORD PTR [rip+0x77cb]        # 140009080 <initialized>
   1400018b5:	85 c0                	test   eax,eax
   1400018b7:	75 0f                	jne    1400018c8 <__main+0x21>
   1400018b9:	c7 05 bd 77 00 00 01 	mov    DWORD PTR [rip+0x77bd],0x1        # 140009080 <initialized>
   1400018c0:	00 00 00 
   1400018c3:	e8 67 ff ff ff       	call   14000182f <__do_global_ctors>
   1400018c8:	90                   	nop
   1400018c9:	48 83 c4 20          	add    rsp,0x20
   1400018cd:	5d                   	pop    rbp
   1400018ce:	c3                   	ret
   1400018cf:	90                   	nop

00000001400018d0 <_setargv>:
   1400018d0:	55                   	push   rbp
   1400018d1:	48 89 e5             	mov    rbp,rsp
   1400018d4:	b8 00 00 00 00       	mov    eax,0x0
   1400018d9:	5d                   	pop    rbp
   1400018da:	c3                   	ret
   1400018db:	90                   	nop
   1400018dc:	90                   	nop
   1400018dd:	90                   	nop
   1400018de:	90                   	nop
   1400018df:	90                   	nop

00000001400018e0 <__dyn_tls_init>:
   1400018e0:	55                   	push   rbp
   1400018e1:	48 89 e5             	mov    rbp,rsp
   1400018e4:	48 83 ec 30          	sub    rsp,0x30
   1400018e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400018ec:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400018ef:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400018f3:	48 8b 05 36 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a36]        # 140005330 <.refptr._CRT_MT>
   1400018fa:	8b 00                	mov    eax,DWORD PTR [rax]
   1400018fc:	83 f8 02             	cmp    eax,0x2
   1400018ff:	74 0d                	je     14000190e <__dyn_tls_init+0x2e>
   140001901:	48 8b 05 28 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a28]        # 140005330 <.refptr._CRT_MT>
   140001908:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000190e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001912:	74 1e                	je     140001932 <__dyn_tls_init+0x52>
   140001914:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001918:	75 5b                	jne    140001975 <__dyn_tls_init+0x95>
   14000191a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000191e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001921:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001925:	49 89 c8             	mov    r8,rcx
   140001928:	48 89 c1             	mov    rcx,rax
   14000192b:	e8 d1 11 00 00       	call   140002b01 <__mingw_TLScallback>
   140001930:	eb 43                	jmp    140001975 <__dyn_tls_init+0x95>
   140001932:	48 8d 05 5f 3d 00 00 	lea    rax,[rip+0x3d5f]        # 140005698 <___crt_xd_start__>
   140001939:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000193d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001942:	eb 22                	jmp    140001966 <__dyn_tls_init+0x86>
   140001944:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001948:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000194c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001950:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001953:	48 85 c0             	test   rax,rax
   140001956:	74 09                	je     140001961 <__dyn_tls_init+0x81>
   140001958:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000195c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000195f:	ff d0                	call   rax
   140001961:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001966:	48 8d 05 33 3d 00 00 	lea    rax,[rip+0x3d33]        # 1400056a0 <__xd_z>
   14000196d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001971:	75 d1                	jne    140001944 <__dyn_tls_init+0x64>
   140001973:	eb 01                	jmp    140001976 <__dyn_tls_init+0x96>
   140001975:	90                   	nop
   140001976:	48 83 c4 30          	add    rsp,0x30
   14000197a:	5d                   	pop    rbp
   14000197b:	c3                   	ret

000000014000197c <__tlregdtor>:
   14000197c:	55                   	push   rbp
   14000197d:	48 89 e5             	mov    rbp,rsp
   140001980:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001984:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001989:	75 07                	jne    140001992 <__tlregdtor+0x16>
   14000198b:	b8 00 00 00 00       	mov    eax,0x0
   140001990:	eb 05                	jmp    140001997 <__tlregdtor+0x1b>
   140001992:	b8 00 00 00 00       	mov    eax,0x0
   140001997:	5d                   	pop    rbp
   140001998:	c3                   	ret

0000000140001999 <__dyn_tls_dtor>:
   140001999:	55                   	push   rbp
   14000199a:	48 89 e5             	mov    rbp,rsp
   14000199d:	48 83 ec 20          	sub    rsp,0x20
   1400019a1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019a5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019a8:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019ac:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   1400019b0:	74 06                	je     1400019b8 <__dyn_tls_dtor+0x1f>
   1400019b2:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400019b6:	75 18                	jne    1400019d0 <__dyn_tls_dtor+0x37>
   1400019b8:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019bc:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019bf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019c3:	49 89 c8             	mov    r8,rcx
   1400019c6:	48 89 c1             	mov    rcx,rax
   1400019c9:	e8 33 11 00 00       	call   140002b01 <__mingw_TLScallback>
   1400019ce:	eb 01                	jmp    1400019d1 <__dyn_tls_dtor+0x38>
   1400019d0:	90                   	nop
   1400019d1:	48 83 c4 20          	add    rsp,0x20
   1400019d5:	5d                   	pop    rbp
   1400019d6:	c3                   	ret
   1400019d7:	90                   	nop
   1400019d8:	90                   	nop
   1400019d9:	90                   	nop
   1400019da:	90                   	nop
   1400019db:	90                   	nop
   1400019dc:	90                   	nop
   1400019dd:	90                   	nop
   1400019de:	90                   	nop
   1400019df:	90                   	nop

00000001400019e0 <_matherr>:
   1400019e0:	55                   	push   rbp
   1400019e1:	53                   	push   rbx
   1400019e2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400019e9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400019ee:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   1400019f2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   1400019f6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   1400019fb:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   1400019ff:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a03:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a05:	83 f8 06             	cmp    eax,0x6
   140001a08:	74 56                	je     140001a60 <_matherr+0x80>
   140001a0a:	83 f8 06             	cmp    eax,0x6
   140001a0d:	7f 78                	jg     140001a87 <_matherr+0xa7>
   140001a0f:	83 f8 05             	cmp    eax,0x5
   140001a12:	74 59                	je     140001a6d <_matherr+0x8d>
   140001a14:	83 f8 05             	cmp    eax,0x5
   140001a17:	7f 6e                	jg     140001a87 <_matherr+0xa7>
   140001a19:	83 f8 04             	cmp    eax,0x4
   140001a1c:	74 5c                	je     140001a7a <_matherr+0x9a>
   140001a1e:	83 f8 04             	cmp    eax,0x4
   140001a21:	7f 64                	jg     140001a87 <_matherr+0xa7>
   140001a23:	83 f8 03             	cmp    eax,0x3
   140001a26:	74 2b                	je     140001a53 <_matherr+0x73>
   140001a28:	83 f8 03             	cmp    eax,0x3
   140001a2b:	7f 5a                	jg     140001a87 <_matherr+0xa7>
   140001a2d:	83 f8 01             	cmp    eax,0x1
   140001a30:	74 07                	je     140001a39 <_matherr+0x59>
   140001a32:	83 f8 02             	cmp    eax,0x2
   140001a35:	74 0f                	je     140001a46 <_matherr+0x66>
   140001a37:	eb 4e                	jmp    140001a87 <_matherr+0xa7>
   140001a39:	48 8d 05 60 36 00 00 	lea    rax,[rip+0x3660]        # 1400050a0 <.rdata>
   140001a40:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a44:	eb 4d                	jmp    140001a93 <_matherr+0xb3>
   140001a46:	48 8d 05 72 36 00 00 	lea    rax,[rip+0x3672]        # 1400050bf <.rdata+0x1f>
   140001a4d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a51:	eb 40                	jmp    140001a93 <_matherr+0xb3>
   140001a53:	48 8d 05 86 36 00 00 	lea    rax,[rip+0x3686]        # 1400050e0 <.rdata+0x40>
   140001a5a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a5e:	eb 33                	jmp    140001a93 <_matherr+0xb3>
   140001a60:	48 8d 05 99 36 00 00 	lea    rax,[rip+0x3699]        # 140005100 <.rdata+0x60>
   140001a67:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a6b:	eb 26                	jmp    140001a93 <_matherr+0xb3>
   140001a6d:	48 8d 05 b4 36 00 00 	lea    rax,[rip+0x36b4]        # 140005128 <.rdata+0x88>
   140001a74:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a78:	eb 19                	jmp    140001a93 <_matherr+0xb3>
   140001a7a:	48 8d 05 cf 36 00 00 	lea    rax,[rip+0x36cf]        # 140005150 <.rdata+0xb0>
   140001a81:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a85:	eb 0c                	jmp    140001a93 <_matherr+0xb3>
   140001a87:	48 8d 05 f8 36 00 00 	lea    rax,[rip+0x36f8]        # 140005186 <.rdata+0xe6>
   140001a8e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a92:	90                   	nop
   140001a93:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a97:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001a9d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001aa1:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001aa6:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001aaa:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001aaf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ab3:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001ab7:	b9 02 00 00 00       	mov    ecx,0x2
   140001abc:	e8 2f 17 00 00       	call   1400031f0 <__acrt_iob_func>
   140001ac1:	48 89 c1             	mov    rcx,rax
   140001ac4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001ac8:	48 8d 05 c9 36 00 00 	lea    rax,[rip+0x36c9]        # 140005198 <.rdata+0xf8>
   140001acf:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001ad6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001adc:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001ae2:	49 89 d9             	mov    r9,rbx
   140001ae5:	49 89 d0             	mov    r8,rdx
   140001ae8:	48 89 c2             	mov    rdx,rax
   140001aeb:	e8 98 17 00 00       	call   140003288 <fprintf>
   140001af0:	b8 00 00 00 00       	mov    eax,0x0
   140001af5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001af9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001afd:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b02:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b09:	5b                   	pop    rbx
   140001b0a:	5d                   	pop    rbp
   140001b0b:	c3                   	ret
   140001b0c:	90                   	nop
   140001b0d:	90                   	nop
   140001b0e:	90                   	nop
   140001b0f:	90                   	nop

0000000140001b10 <__report_error>:
   140001b10:	55                   	push   rbp
   140001b11:	53                   	push   rbx
   140001b12:	48 83 ec 38          	sub    rsp,0x38
   140001b16:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b1b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b1f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b23:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b27:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b2b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b2f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b33:	b9 02 00 00 00       	mov    ecx,0x2
   140001b38:	e8 b3 16 00 00       	call   1400031f0 <__acrt_iob_func>
   140001b3d:	48 89 c1             	mov    rcx,rax
   140001b40:	48 8d 05 89 36 00 00 	lea    rax,[rip+0x3689]        # 1400051d0 <.rdata>
   140001b47:	48 89 c2             	mov    rdx,rax
   140001b4a:	e8 39 17 00 00       	call   140003288 <fprintf>
   140001b4f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b53:	b9 02 00 00 00       	mov    ecx,0x2
   140001b58:	e8 93 16 00 00       	call   1400031f0 <__acrt_iob_func>
   140001b5d:	48 89 c1             	mov    rcx,rax
   140001b60:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b64:	49 89 d8             	mov    r8,rbx
   140001b67:	48 89 c2             	mov    rdx,rax
   140001b6a:	e8 61 17 00 00       	call   1400032d0 <vfprintf>
   140001b6f:	e8 f4 16 00 00       	call   140003268 <abort>
   140001b74:	90                   	nop

0000000140001b75 <mark_section_writable>:
   140001b75:	55                   	push   rbp
   140001b76:	48 89 e5             	mov    rbp,rsp
   140001b79:	48 83 ec 60          	sub    rsp,0x60
   140001b7d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b81:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001b88:	e9 82 00 00 00       	jmp    140001c0f <mark_section_writable+0x9a>
   140001b8d:	48 8b 0d 4c 75 00 00 	mov    rcx,QWORD PTR [rip+0x754c]        # 1400090e0 <the_secs>
   140001b94:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b97:	48 63 d0             	movsxd rdx,eax
   140001b9a:	48 89 d0             	mov    rax,rdx
   140001b9d:	48 c1 e0 02          	shl    rax,0x2
   140001ba1:	48 01 d0             	add    rax,rdx
   140001ba4:	48 c1 e0 03          	shl    rax,0x3
   140001ba8:	48 01 c8             	add    rax,rcx
   140001bab:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001baf:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001bb3:	72 56                	jb     140001c0b <mark_section_writable+0x96>
   140001bb5:	48 8b 0d 24 75 00 00 	mov    rcx,QWORD PTR [rip+0x7524]        # 1400090e0 <the_secs>
   140001bbc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bbf:	48 63 d0             	movsxd rdx,eax
   140001bc2:	48 89 d0             	mov    rax,rdx
   140001bc5:	48 c1 e0 02          	shl    rax,0x2
   140001bc9:	48 01 d0             	add    rax,rdx
   140001bcc:	48 c1 e0 03          	shl    rax,0x3
   140001bd0:	48 01 c8             	add    rax,rcx
   140001bd3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001bd7:	4c 8b 05 02 75 00 00 	mov    r8,QWORD PTR [rip+0x7502]        # 1400090e0 <the_secs>
   140001bde:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001be1:	48 63 d0             	movsxd rdx,eax
   140001be4:	48 89 d0             	mov    rax,rdx
   140001be7:	48 c1 e0 02          	shl    rax,0x2
   140001beb:	48 01 d0             	add    rax,rdx
   140001bee:	48 c1 e0 03          	shl    rax,0x3
   140001bf2:	4c 01 c0             	add    rax,r8
   140001bf5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001bf9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001bfc:	89 c0                	mov    eax,eax
   140001bfe:	48 01 c8             	add    rax,rcx
   140001c01:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c05:	0f 82 41 02 00 00    	jb     140001e4c <mark_section_writable+0x2d7>
   140001c0b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c0f:	8b 05 d3 74 00 00    	mov    eax,DWORD PTR [rip+0x74d3]        # 1400090e8 <maxSections>
   140001c15:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c18:	0f 8c 6f ff ff ff    	jl     140001b8d <mark_section_writable+0x18>
   140001c1e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c22:	48 89 c1             	mov    rcx,rax
   140001c25:	e8 c1 11 00 00       	call   140002deb <__mingw_GetSectionForAddress>
   140001c2a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c2e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c33:	75 13                	jne    140001c48 <mark_section_writable+0xd3>
   140001c35:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c39:	48 8d 0d b0 35 00 00 	lea    rcx,[rip+0x35b0]        # 1400051f0 <.rdata+0x20>
   140001c40:	48 89 c2             	mov    rdx,rax
   140001c43:	e8 c8 fe ff ff       	call   140001b10 <__report_error>
   140001c48:	48 8b 0d 91 74 00 00 	mov    rcx,QWORD PTR [rip+0x7491]        # 1400090e0 <the_secs>
   140001c4f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c52:	48 63 d0             	movsxd rdx,eax
   140001c55:	48 89 d0             	mov    rax,rdx
   140001c58:	48 c1 e0 02          	shl    rax,0x2
   140001c5c:	48 01 d0             	add    rax,rdx
   140001c5f:	48 c1 e0 03          	shl    rax,0x3
   140001c63:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c67:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c6b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c6f:	48 8b 0d 6a 74 00 00 	mov    rcx,QWORD PTR [rip+0x746a]        # 1400090e0 <the_secs>
   140001c76:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c79:	48 63 d0             	movsxd rdx,eax
   140001c7c:	48 89 d0             	mov    rax,rdx
   140001c7f:	48 c1 e0 02          	shl    rax,0x2
   140001c83:	48 01 d0             	add    rax,rdx
   140001c86:	48 c1 e0 03          	shl    rax,0x3
   140001c8a:	48 01 c8             	add    rax,rcx
   140001c8d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001c93:	e8 9f 12 00 00       	call   140002f37 <_GetPEImageBase>
   140001c98:	48 89 c1             	mov    rcx,rax
   140001c9b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c9f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001ca2:	41 89 c1             	mov    r9d,eax
   140001ca5:	4c 8b 05 34 74 00 00 	mov    r8,QWORD PTR [rip+0x7434]        # 1400090e0 <the_secs>
   140001cac:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001caf:	48 63 d0             	movsxd rdx,eax
   140001cb2:	48 89 d0             	mov    rax,rdx
   140001cb5:	48 c1 e0 02          	shl    rax,0x2
   140001cb9:	48 01 d0             	add    rax,rdx
   140001cbc:	48 c1 e0 03          	shl    rax,0x3
   140001cc0:	4c 01 c0             	add    rax,r8
   140001cc3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001cc7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001ccb:	48 8b 0d 0e 74 00 00 	mov    rcx,QWORD PTR [rip+0x740e]        # 1400090e0 <the_secs>
   140001cd2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cd5:	48 63 d0             	movsxd rdx,eax
   140001cd8:	48 89 d0             	mov    rax,rdx
   140001cdb:	48 c1 e0 02          	shl    rax,0x2
   140001cdf:	48 01 d0             	add    rax,rdx
   140001ce2:	48 c1 e0 03          	shl    rax,0x3
   140001ce6:	48 01 c8             	add    rax,rcx
   140001ce9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001ced:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001cf1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001cf7:	48 89 c1             	mov    rcx,rax
   140001cfa:	48 8b 05 f7 84 00 00 	mov    rax,QWORD PTR [rip+0x84f7]        # 14000a1f8 <__imp_VirtualQuery>
   140001d01:	ff d0                	call   rax
   140001d03:	48 85 c0             	test   rax,rax
   140001d06:	75 3f                	jne    140001d47 <mark_section_writable+0x1d2>
   140001d08:	48 8b 0d d1 73 00 00 	mov    rcx,QWORD PTR [rip+0x73d1]        # 1400090e0 <the_secs>
   140001d0f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d12:	48 63 d0             	movsxd rdx,eax
   140001d15:	48 89 d0             	mov    rax,rdx
   140001d18:	48 c1 e0 02          	shl    rax,0x2
   140001d1c:	48 01 d0             	add    rax,rdx
   140001d1f:	48 c1 e0 03          	shl    rax,0x3
   140001d23:	48 01 c8             	add    rax,rcx
   140001d26:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d2e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d31:	89 c1                	mov    ecx,eax
   140001d33:	48 8d 05 d6 34 00 00 	lea    rax,[rip+0x34d6]        # 140005210 <.rdata+0x40>
   140001d3a:	49 89 d0             	mov    r8,rdx
   140001d3d:	89 ca                	mov    edx,ecx
   140001d3f:	48 89 c1             	mov    rcx,rax
   140001d42:	e8 c9 fd ff ff       	call   140001b10 <__report_error>
   140001d47:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d4a:	83 f8 40             	cmp    eax,0x40
   140001d4d:	0f 84 e8 00 00 00    	je     140001e3b <mark_section_writable+0x2c6>
   140001d53:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d56:	83 f8 04             	cmp    eax,0x4
   140001d59:	0f 84 dc 00 00 00    	je     140001e3b <mark_section_writable+0x2c6>
   140001d5f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d62:	3d 80 00 00 00       	cmp    eax,0x80
   140001d67:	0f 84 ce 00 00 00    	je     140001e3b <mark_section_writable+0x2c6>
   140001d6d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d70:	83 f8 08             	cmp    eax,0x8
   140001d73:	0f 84 c2 00 00 00    	je     140001e3b <mark_section_writable+0x2c6>
   140001d79:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d7c:	83 f8 02             	cmp    eax,0x2
   140001d7f:	75 09                	jne    140001d8a <mark_section_writable+0x215>
   140001d81:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001d88:	eb 07                	jmp    140001d91 <mark_section_writable+0x21c>
   140001d8a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001d91:	48 8b 0d 48 73 00 00 	mov    rcx,QWORD PTR [rip+0x7348]        # 1400090e0 <the_secs>
   140001d98:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d9b:	48 63 d0             	movsxd rdx,eax
   140001d9e:	48 89 d0             	mov    rax,rdx
   140001da1:	48 c1 e0 02          	shl    rax,0x2
   140001da5:	48 01 d0             	add    rax,rdx
   140001da8:	48 c1 e0 03          	shl    rax,0x3
   140001dac:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001db0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001db4:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001db8:	48 8b 0d 21 73 00 00 	mov    rcx,QWORD PTR [rip+0x7321]        # 1400090e0 <the_secs>
   140001dbf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dc2:	48 63 d0             	movsxd rdx,eax
   140001dc5:	48 89 d0             	mov    rax,rdx
   140001dc8:	48 c1 e0 02          	shl    rax,0x2
   140001dcc:	48 01 d0             	add    rax,rdx
   140001dcf:	48 c1 e0 03          	shl    rax,0x3
   140001dd3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001dd7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001ddb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001ddf:	48 8b 0d fa 72 00 00 	mov    rcx,QWORD PTR [rip+0x72fa]        # 1400090e0 <the_secs>
   140001de6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001de9:	48 63 d0             	movsxd rdx,eax
   140001dec:	48 89 d0             	mov    rax,rdx
   140001def:	48 c1 e0 02          	shl    rax,0x2
   140001df3:	48 01 d0             	add    rax,rdx
   140001df6:	48 c1 e0 03          	shl    rax,0x3
   140001dfa:	48 01 c8             	add    rax,rcx
   140001dfd:	49 89 c0             	mov    r8,rax
   140001e00:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e04:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e08:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e0b:	4d 89 c1             	mov    r9,r8
   140001e0e:	41 89 c8             	mov    r8d,ecx
   140001e11:	48 89 c1             	mov    rcx,rax
   140001e14:	48 8b 05 d5 83 00 00 	mov    rax,QWORD PTR [rip+0x83d5]        # 14000a1f0 <__imp_VirtualProtect>
   140001e1b:	ff d0                	call   rax
   140001e1d:	85 c0                	test   eax,eax
   140001e1f:	75 1a                	jne    140001e3b <mark_section_writable+0x2c6>
   140001e21:	48 8b 05 80 83 00 00 	mov    rax,QWORD PTR [rip+0x8380]        # 14000a1a8 <__imp_GetLastError>
   140001e28:	ff d0                	call   rax
   140001e2a:	89 c2                	mov    edx,eax
   140001e2c:	48 8d 05 15 34 00 00 	lea    rax,[rip+0x3415]        # 140005248 <.rdata+0x78>
   140001e33:	48 89 c1             	mov    rcx,rax
   140001e36:	e8 d5 fc ff ff       	call   140001b10 <__report_error>
   140001e3b:	8b 05 a7 72 00 00    	mov    eax,DWORD PTR [rip+0x72a7]        # 1400090e8 <maxSections>
   140001e41:	83 c0 01             	add    eax,0x1
   140001e44:	89 05 9e 72 00 00    	mov    DWORD PTR [rip+0x729e],eax        # 1400090e8 <maxSections>
   140001e4a:	eb 01                	jmp    140001e4d <mark_section_writable+0x2d8>
   140001e4c:	90                   	nop
   140001e4d:	48 83 c4 60          	add    rsp,0x60
   140001e51:	5d                   	pop    rbp
   140001e52:	c3                   	ret

0000000140001e53 <restore_modified_sections>:
   140001e53:	55                   	push   rbp
   140001e54:	48 89 e5             	mov    rbp,rsp
   140001e57:	48 83 ec 30          	sub    rsp,0x30
   140001e5b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e62:	e9 ad 00 00 00       	jmp    140001f14 <restore_modified_sections+0xc1>
   140001e67:	48 8b 0d 72 72 00 00 	mov    rcx,QWORD PTR [rip+0x7272]        # 1400090e0 <the_secs>
   140001e6e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e71:	48 63 d0             	movsxd rdx,eax
   140001e74:	48 89 d0             	mov    rax,rdx
   140001e77:	48 c1 e0 02          	shl    rax,0x2
   140001e7b:	48 01 d0             	add    rax,rdx
   140001e7e:	48 c1 e0 03          	shl    rax,0x3
   140001e82:	48 01 c8             	add    rax,rcx
   140001e85:	8b 00                	mov    eax,DWORD PTR [rax]
   140001e87:	85 c0                	test   eax,eax
   140001e89:	0f 84 80 00 00 00    	je     140001f0f <restore_modified_sections+0xbc>
   140001e8f:	48 8b 0d 4a 72 00 00 	mov    rcx,QWORD PTR [rip+0x724a]        # 1400090e0 <the_secs>
   140001e96:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e99:	48 63 d0             	movsxd rdx,eax
   140001e9c:	48 89 d0             	mov    rax,rdx
   140001e9f:	48 c1 e0 02          	shl    rax,0x2
   140001ea3:	48 01 d0             	add    rax,rdx
   140001ea6:	48 c1 e0 03          	shl    rax,0x3
   140001eaa:	48 01 c8             	add    rax,rcx
   140001ead:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001eb0:	48 8b 0d 29 72 00 00 	mov    rcx,QWORD PTR [rip+0x7229]        # 1400090e0 <the_secs>
   140001eb7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eba:	48 63 d0             	movsxd rdx,eax
   140001ebd:	48 89 d0             	mov    rax,rdx
   140001ec0:	48 c1 e0 02          	shl    rax,0x2
   140001ec4:	48 01 d0             	add    rax,rdx
   140001ec7:	48 c1 e0 03          	shl    rax,0x3
   140001ecb:	48 01 c8             	add    rax,rcx
   140001ece:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001ed2:	4c 8b 05 07 72 00 00 	mov    r8,QWORD PTR [rip+0x7207]        # 1400090e0 <the_secs>
   140001ed9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001edc:	48 63 d0             	movsxd rdx,eax
   140001edf:	48 89 d0             	mov    rax,rdx
   140001ee2:	48 c1 e0 02          	shl    rax,0x2
   140001ee6:	48 01 d0             	add    rax,rdx
   140001ee9:	48 c1 e0 03          	shl    rax,0x3
   140001eed:	4c 01 c0             	add    rax,r8
   140001ef0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001ef4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001ef8:	49 89 d1             	mov    r9,rdx
   140001efb:	45 89 d0             	mov    r8d,r10d
   140001efe:	48 89 ca             	mov    rdx,rcx
   140001f01:	48 89 c1             	mov    rcx,rax
   140001f04:	48 8b 05 e5 82 00 00 	mov    rax,QWORD PTR [rip+0x82e5]        # 14000a1f0 <__imp_VirtualProtect>
   140001f0b:	ff d0                	call   rax
   140001f0d:	eb 01                	jmp    140001f10 <restore_modified_sections+0xbd>
   140001f0f:	90                   	nop
   140001f10:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f14:	8b 05 ce 71 00 00    	mov    eax,DWORD PTR [rip+0x71ce]        # 1400090e8 <maxSections>
   140001f1a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f1d:	0f 8c 44 ff ff ff    	jl     140001e67 <restore_modified_sections+0x14>
   140001f23:	90                   	nop
   140001f24:	90                   	nop
   140001f25:	48 83 c4 30          	add    rsp,0x30
   140001f29:	5d                   	pop    rbp
   140001f2a:	c3                   	ret

0000000140001f2b <__write_memory>:
   140001f2b:	55                   	push   rbp
   140001f2c:	48 89 e5             	mov    rbp,rsp
   140001f2f:	48 83 ec 20          	sub    rsp,0x20
   140001f33:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f37:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f3b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f3f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f44:	74 25                	je     140001f6b <__write_memory+0x40>
   140001f46:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f4a:	48 89 c1             	mov    rcx,rax
   140001f4d:	e8 23 fc ff ff       	call   140001b75 <mark_section_writable>
   140001f52:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f56:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f5a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f5e:	49 89 c8             	mov    r8,rcx
   140001f61:	48 89 c1             	mov    rcx,rax
   140001f64:	e8 37 13 00 00       	call   1400032a0 <memcpy>
   140001f69:	eb 01                	jmp    140001f6c <__write_memory+0x41>
   140001f6b:	90                   	nop
   140001f6c:	48 83 c4 20          	add    rsp,0x20
   140001f70:	5d                   	pop    rbp
   140001f71:	c3                   	ret

0000000140001f72 <do_pseudo_reloc>:
   140001f72:	55                   	push   rbp
   140001f73:	48 89 e5             	mov    rbp,rsp
   140001f76:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001f7a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f7e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f82:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f86:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001f8a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001f8e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001f92:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f96:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001f9a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001f9f:	0f 8e 44 03 00 00    	jle    1400022e9 <do_pseudo_reloc+0x377>
   140001fa5:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001faa:	7e 25                	jle    140001fd1 <do_pseudo_reloc+0x5f>
   140001fac:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fb0:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fb2:	85 c0                	test   eax,eax
   140001fb4:	75 1b                	jne    140001fd1 <do_pseudo_reloc+0x5f>
   140001fb6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fba:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fbd:	85 c0                	test   eax,eax
   140001fbf:	75 10                	jne    140001fd1 <do_pseudo_reloc+0x5f>
   140001fc1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fc5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001fc8:	85 c0                	test   eax,eax
   140001fca:	75 05                	jne    140001fd1 <do_pseudo_reloc+0x5f>
   140001fcc:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140001fd1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fd5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fd7:	85 c0                	test   eax,eax
   140001fd9:	75 0b                	jne    140001fe6 <do_pseudo_reloc+0x74>
   140001fdb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fdf:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fe2:	85 c0                	test   eax,eax
   140001fe4:	74 59                	je     14000203f <do_pseudo_reloc+0xcd>
   140001fe6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fea:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001fee:	eb 40                	jmp    140002030 <do_pseudo_reloc+0xbe>
   140001ff0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001ff4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001ff7:	89 c2                	mov    edx,eax
   140001ff9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001ffd:	48 01 d0             	add    rax,rdx
   140002000:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002004:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002008:	8b 10                	mov    edx,DWORD PTR [rax]
   14000200a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000200e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002010:	01 d0                	add    eax,edx
   140002012:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002015:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002019:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000201d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002023:	48 89 c1             	mov    rcx,rax
   140002026:	e8 00 ff ff ff       	call   140001f2b <__write_memory>
   14000202b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002030:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002034:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002038:	72 b6                	jb     140001ff0 <do_pseudo_reloc+0x7e>
   14000203a:	e9 ab 02 00 00       	jmp    1400022ea <do_pseudo_reloc+0x378>
   14000203f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002043:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002046:	83 f8 01             	cmp    eax,0x1
   140002049:	74 18                	je     140002063 <do_pseudo_reloc+0xf1>
   14000204b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000204f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002052:	89 c2                	mov    edx,eax
   140002054:	48 8d 05 15 32 00 00 	lea    rax,[rip+0x3215]        # 140005270 <.rdata+0xa0>
   14000205b:	48 89 c1             	mov    rcx,rax
   14000205e:	e8 ad fa ff ff       	call   140001b10 <__report_error>
   140002063:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002067:	48 83 c0 0c          	add    rax,0xc
   14000206b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000206f:	e9 65 02 00 00       	jmp    1400022d9 <do_pseudo_reloc+0x367>
   140002074:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002078:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000207b:	89 c2                	mov    edx,eax
   14000207d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002081:	48 01 d0             	add    rax,rdx
   140002084:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002088:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000208c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000208e:	89 c2                	mov    edx,eax
   140002090:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002094:	48 01 d0             	add    rax,rdx
   140002097:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000209b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000209f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400020a2:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020a6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020aa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020ad:	0f b6 c0             	movzx  eax,al
   1400020b0:	83 f8 40             	cmp    eax,0x40
   1400020b3:	0f 84 b6 00 00 00    	je     14000216f <do_pseudo_reloc+0x1fd>
   1400020b9:	83 f8 40             	cmp    eax,0x40
   1400020bc:	0f 87 ba 00 00 00    	ja     14000217c <do_pseudo_reloc+0x20a>
   1400020c2:	83 f8 20             	cmp    eax,0x20
   1400020c5:	74 77                	je     14000213e <do_pseudo_reloc+0x1cc>
   1400020c7:	83 f8 20             	cmp    eax,0x20
   1400020ca:	0f 87 ac 00 00 00    	ja     14000217c <do_pseudo_reloc+0x20a>
   1400020d0:	83 f8 08             	cmp    eax,0x8
   1400020d3:	74 0a                	je     1400020df <do_pseudo_reloc+0x16d>
   1400020d5:	83 f8 10             	cmp    eax,0x10
   1400020d8:	74 38                	je     140002112 <do_pseudo_reloc+0x1a0>
   1400020da:	e9 9d 00 00 00       	jmp    14000217c <do_pseudo_reloc+0x20a>
   1400020df:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020e3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400020e6:	0f b6 c0             	movzx  eax,al
   1400020e9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020ed:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020f1:	25 80 00 00 00       	and    eax,0x80
   1400020f6:	48 85 c0             	test   rax,rax
   1400020f9:	0f 84 9d 00 00 00    	je     14000219c <do_pseudo_reloc+0x22a>
   1400020ff:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002103:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002109:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000210d:	e9 8a 00 00 00       	jmp    14000219c <do_pseudo_reloc+0x22a>
   140002112:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002116:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002119:	0f b7 c0             	movzx  eax,ax
   14000211c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002120:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002124:	25 00 80 00 00       	and    eax,0x8000
   140002129:	48 85 c0             	test   rax,rax
   14000212c:	74 71                	je     14000219f <do_pseudo_reloc+0x22d>
   14000212e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002132:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002138:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000213c:	eb 61                	jmp    14000219f <do_pseudo_reloc+0x22d>
   14000213e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002142:	8b 00                	mov    eax,DWORD PTR [rax]
   140002144:	89 c0                	mov    eax,eax
   140002146:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000214a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000214e:	25 00 00 00 80       	and    eax,0x80000000
   140002153:	48 85 c0             	test   rax,rax
   140002156:	74 4a                	je     1400021a2 <do_pseudo_reloc+0x230>
   140002158:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000215c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002163:	ff ff ff 
   140002166:	48 09 d0             	or     rax,rdx
   140002169:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000216d:	eb 33                	jmp    1400021a2 <do_pseudo_reloc+0x230>
   14000216f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002173:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002176:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000217a:	eb 27                	jmp    1400021a3 <do_pseudo_reloc+0x231>
   14000217c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002183:	00 
   140002184:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002188:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000218b:	0f b6 c0             	movzx  eax,al
   14000218e:	48 8d 0d 13 31 00 00 	lea    rcx,[rip+0x3113]        # 1400052a8 <.rdata+0xd8>
   140002195:	89 c2                	mov    edx,eax
   140002197:	e8 74 f9 ff ff       	call   140001b10 <__report_error>
   14000219c:	90                   	nop
   14000219d:	eb 04                	jmp    1400021a3 <do_pseudo_reloc+0x231>
   14000219f:	90                   	nop
   1400021a0:	eb 01                	jmp    1400021a3 <do_pseudo_reloc+0x231>
   1400021a2:	90                   	nop
   1400021a3:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   1400021a7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021ad:	89 c2                	mov    edx,eax
   1400021af:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400021b3:	48 01 c2             	add    rdx,rax
   1400021b6:	48 89 c8             	mov    rax,rcx
   1400021b9:	48 29 d0             	sub    rax,rdx
   1400021bc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021c0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021c4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400021c8:	48 01 d0             	add    rax,rdx
   1400021cb:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021cf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021d3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021d6:	25 ff 00 00 00       	and    eax,0xff
   1400021db:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400021de:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400021e2:	77 67                	ja     14000224b <do_pseudo_reloc+0x2d9>
   1400021e4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021e7:	ba 01 00 00 00       	mov    edx,0x1
   1400021ec:	89 c1                	mov    ecx,eax
   1400021ee:	48 d3 e2             	shl    rdx,cl
   1400021f1:	48 89 d0             	mov    rax,rdx
   1400021f4:	48 83 e8 01          	sub    rax,0x1
   1400021f8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400021fc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021ff:	83 e8 01             	sub    eax,0x1
   140002202:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002209:	89 c1                	mov    ecx,eax
   14000220b:	48 d3 e2             	shl    rdx,cl
   14000220e:	48 89 d0             	mov    rax,rdx
   140002211:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002215:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002219:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000221d:	7c 0a                	jl     140002229 <do_pseudo_reloc+0x2b7>
   14000221f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002223:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002227:	7e 22                	jle    14000224b <do_pseudo_reloc+0x2d9>
   140002229:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000222d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002231:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002235:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002238:	48 8d 0d 99 30 00 00 	lea    rcx,[rip+0x3099]        # 1400052d8 <.rdata+0x108>
   14000223f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002244:	89 c2                	mov    edx,eax
   140002246:	e8 c5 f8 ff ff       	call   140001b10 <__report_error>
   14000224b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000224f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002252:	0f b6 c0             	movzx  eax,al
   140002255:	83 f8 40             	cmp    eax,0x40
   140002258:	74 63                	je     1400022bd <do_pseudo_reloc+0x34b>
   14000225a:	83 f8 40             	cmp    eax,0x40
   14000225d:	77 75                	ja     1400022d4 <do_pseudo_reloc+0x362>
   14000225f:	83 f8 20             	cmp    eax,0x20
   140002262:	74 41                	je     1400022a5 <do_pseudo_reloc+0x333>
   140002264:	83 f8 20             	cmp    eax,0x20
   140002267:	77 6b                	ja     1400022d4 <do_pseudo_reloc+0x362>
   140002269:	83 f8 08             	cmp    eax,0x8
   14000226c:	74 07                	je     140002275 <do_pseudo_reloc+0x303>
   14000226e:	83 f8 10             	cmp    eax,0x10
   140002271:	74 1a                	je     14000228d <do_pseudo_reloc+0x31b>
   140002273:	eb 5f                	jmp    1400022d4 <do_pseudo_reloc+0x362>
   140002275:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002279:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000227d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002283:	48 89 c1             	mov    rcx,rax
   140002286:	e8 a0 fc ff ff       	call   140001f2b <__write_memory>
   14000228b:	eb 47                	jmp    1400022d4 <do_pseudo_reloc+0x362>
   14000228d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002291:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002295:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000229b:	48 89 c1             	mov    rcx,rax
   14000229e:	e8 88 fc ff ff       	call   140001f2b <__write_memory>
   1400022a3:	eb 2f                	jmp    1400022d4 <do_pseudo_reloc+0x362>
   1400022a5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022a9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022ad:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400022b3:	48 89 c1             	mov    rcx,rax
   1400022b6:	e8 70 fc ff ff       	call   140001f2b <__write_memory>
   1400022bb:	eb 17                	jmp    1400022d4 <do_pseudo_reloc+0x362>
   1400022bd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022c1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022c5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400022cb:	48 89 c1             	mov    rcx,rax
   1400022ce:	e8 58 fc ff ff       	call   140001f2b <__write_memory>
   1400022d3:	90                   	nop
   1400022d4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400022d9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022dd:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400022e1:	0f 82 8d fd ff ff    	jb     140002074 <do_pseudo_reloc+0x102>
   1400022e7:	eb 01                	jmp    1400022ea <do_pseudo_reloc+0x378>
   1400022e9:	90                   	nop
   1400022ea:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400022ee:	5d                   	pop    rbp
   1400022ef:	c3                   	ret

00000001400022f0 <_pei386_runtime_relocator>:
   1400022f0:	55                   	push   rbp
   1400022f1:	48 89 e5             	mov    rbp,rsp
   1400022f4:	48 83 ec 30          	sub    rsp,0x30
   1400022f8:	8b 05 ee 6d 00 00    	mov    eax,DWORD PTR [rip+0x6dee]        # 1400090ec <was_init.0>
   1400022fe:	85 c0                	test   eax,eax
   140002300:	0f 85 88 00 00 00    	jne    14000238e <_pei386_runtime_relocator+0x9e>
   140002306:	8b 05 e0 6d 00 00    	mov    eax,DWORD PTR [rip+0x6de0]        # 1400090ec <was_init.0>
   14000230c:	83 c0 01             	add    eax,0x1
   14000230f:	89 05 d7 6d 00 00    	mov    DWORD PTR [rip+0x6dd7],eax        # 1400090ec <was_init.0>
   140002315:	e8 21 0b 00 00       	call   140002e3b <__mingw_GetSectionCount>
   14000231a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000231d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002320:	48 63 d0             	movsxd rdx,eax
   140002323:	48 89 d0             	mov    rax,rdx
   140002326:	48 c1 e0 02          	shl    rax,0x2
   14000232a:	48 01 d0             	add    rax,rdx
   14000232d:	48 c1 e0 03          	shl    rax,0x3
   140002331:	48 83 c0 0f          	add    rax,0xf
   140002335:	48 c1 e8 04          	shr    rax,0x4
   140002339:	48 c1 e0 04          	shl    rax,0x4
   14000233d:	e8 7e 0d 00 00       	call   1400030c0 <___chkstk_ms>
   140002342:	48 29 c4             	sub    rsp,rax
   140002345:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000234a:	48 83 c0 0f          	add    rax,0xf
   14000234e:	48 c1 e8 04          	shr    rax,0x4
   140002352:	48 c1 e0 04          	shl    rax,0x4
   140002356:	48 89 05 83 6d 00 00 	mov    QWORD PTR [rip+0x6d83],rax        # 1400090e0 <the_secs>
   14000235d:	c7 05 81 6d 00 00 00 	mov    DWORD PTR [rip+0x6d81],0x0        # 1400090e8 <maxSections>
   140002364:	00 00 00 
   140002367:	48 8b 0d f2 2f 00 00 	mov    rcx,QWORD PTR [rip+0x2ff2]        # 140005360 <.refptr.__ImageBase>
   14000236e:	48 8b 15 fb 2f 00 00 	mov    rdx,QWORD PTR [rip+0x2ffb]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002375:	48 8b 05 04 30 00 00 	mov    rax,QWORD PTR [rip+0x3004]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000237c:	49 89 c8             	mov    r8,rcx
   14000237f:	48 89 c1             	mov    rcx,rax
   140002382:	e8 eb fb ff ff       	call   140001f72 <do_pseudo_reloc>
   140002387:	e8 c7 fa ff ff       	call   140001e53 <restore_modified_sections>
   14000238c:	eb 01                	jmp    14000238f <_pei386_runtime_relocator+0x9f>
   14000238e:	90                   	nop
   14000238f:	48 89 ec             	mov    rsp,rbp
   140002392:	5d                   	pop    rbp
   140002393:	c3                   	ret
   140002394:	90                   	nop
   140002395:	90                   	nop
   140002396:	90                   	nop
   140002397:	90                   	nop
   140002398:	90                   	nop
   140002399:	90                   	nop
   14000239a:	90                   	nop
   14000239b:	90                   	nop
   14000239c:	90                   	nop
   14000239d:	90                   	nop
   14000239e:	90                   	nop
   14000239f:	90                   	nop

00000001400023a0 <__mingw_raise_matherr>:
   1400023a0:	55                   	push   rbp
   1400023a1:	48 89 e5             	mov    rbp,rsp
   1400023a4:	48 83 ec 50          	sub    rsp,0x50
   1400023a8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400023ab:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400023af:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   1400023b4:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   1400023b9:	48 8b 05 30 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d30]        # 1400090f0 <stUserMathErr>
   1400023c0:	48 85 c0             	test   rax,rax
   1400023c3:	74 3e                	je     140002403 <__mingw_raise_matherr+0x63>
   1400023c5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400023c8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400023cb:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400023cf:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400023d3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400023d8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400023dd:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400023e2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400023e7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400023ec:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400023f1:	48 8b 15 f8 6c 00 00 	mov    rdx,QWORD PTR [rip+0x6cf8]        # 1400090f0 <stUserMathErr>
   1400023f8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400023fc:	48 89 c1             	mov    rcx,rax
   1400023ff:	ff d2                	call   rdx
   140002401:	eb 01                	jmp    140002404 <__mingw_raise_matherr+0x64>
   140002403:	90                   	nop
   140002404:	48 83 c4 50          	add    rsp,0x50
   140002408:	5d                   	pop    rbp
   140002409:	c3                   	ret

000000014000240a <__mingw_setusermatherr>:
   14000240a:	55                   	push   rbp
   14000240b:	48 89 e5             	mov    rbp,rsp
   14000240e:	48 83 ec 20          	sub    rsp,0x20
   140002412:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002416:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000241a:	48 89 05 cf 6c 00 00 	mov    QWORD PTR [rip+0x6ccf],rax        # 1400090f0 <stUserMathErr>
   140002421:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002425:	48 89 c1             	mov    rcx,rax
   140002428:	e8 13 0e 00 00       	call   140003240 <__setusermatherr>
   14000242d:	90                   	nop
   14000242e:	48 83 c4 20          	add    rsp,0x20
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

0000000140002440 <__mingw_SEH_error_handler>:
   140002440:	55                   	push   rbp
   140002441:	48 89 e5             	mov    rbp,rsp
   140002444:	48 83 ec 30          	sub    rsp,0x30
   140002448:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000244c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002450:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002454:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002458:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000245f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002466:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000246a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000246d:	83 e0 02             	and    eax,0x2
   140002470:	85 c0                	test   eax,eax
   140002472:	74 0a                	je     14000247e <__mingw_SEH_error_handler+0x3e>
   140002474:	b8 01 00 00 00       	mov    eax,0x1
   140002479:	e9 16 02 00 00       	jmp    140002694 <__mingw_SEH_error_handler+0x254>
   14000247e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002482:	8b 00                	mov    eax,DWORD PTR [rax]
   140002484:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002489:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000248e:	75 18                	jne    1400024a8 <__mingw_SEH_error_handler+0x68>
   140002490:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002494:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002497:	83 e0 01             	and    eax,0x1
   14000249a:	85 c0                	test   eax,eax
   14000249c:	75 0a                	jne    1400024a8 <__mingw_SEH_error_handler+0x68>
   14000249e:	b8 00 00 00 00       	mov    eax,0x0
   1400024a3:	e9 ec 01 00 00       	jmp    140002694 <__mingw_SEH_error_handler+0x254>
   1400024a8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024ac:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024ae:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024b3:	0f 84 12 01 00 00    	je     1400025cb <__mingw_SEH_error_handler+0x18b>
   1400024b9:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024be:	0f 87 c3 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   1400024c4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400024c9:	0f 87 b8 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   1400024cf:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400024d4:	0f 83 4c 01 00 00    	jae    140002626 <__mingw_SEH_error_handler+0x1e6>
   1400024da:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024df:	0f 84 3a 01 00 00    	je     14000261f <__mingw_SEH_error_handler+0x1df>
   1400024e5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024ea:	0f 87 97 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   1400024f0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024f5:	0f 84 83 01 00 00    	je     14000267e <__mingw_SEH_error_handler+0x23e>
   1400024fb:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002500:	0f 87 81 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   140002506:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000250b:	0f 87 76 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   140002511:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002516:	0f 83 03 01 00 00    	jae    14000261f <__mingw_SEH_error_handler+0x1df>
   14000251c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002521:	0f 84 57 01 00 00    	je     14000267e <__mingw_SEH_error_handler+0x23e>
   140002527:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000252c:	0f 87 55 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   140002532:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002537:	0f 84 8e 00 00 00    	je     1400025cb <__mingw_SEH_error_handler+0x18b>
   14000253d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002542:	0f 87 3f 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   140002548:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000254d:	0f 84 2b 01 00 00    	je     14000267e <__mingw_SEH_error_handler+0x23e>
   140002553:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002558:	0f 87 29 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   14000255e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002563:	0f 84 15 01 00 00    	je     14000267e <__mingw_SEH_error_handler+0x23e>
   140002569:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000256e:	0f 85 13 01 00 00    	jne    140002687 <__mingw_SEH_error_handler+0x247>
   140002574:	ba 00 00 00 00       	mov    edx,0x0
   140002579:	b9 0b 00 00 00       	mov    ecx,0xb
   14000257e:	e8 2d 0d 00 00       	call   1400032b0 <signal>
   140002583:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002587:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000258c:	75 1b                	jne    1400025a9 <__mingw_SEH_error_handler+0x169>
   14000258e:	ba 01 00 00 00       	mov    edx,0x1
   140002593:	b9 0b 00 00 00       	mov    ecx,0xb
   140002598:	e8 13 0d 00 00       	call   1400032b0 <signal>
   14000259d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025a4:	e9 e1 00 00 00       	jmp    14000268a <__mingw_SEH_error_handler+0x24a>
   1400025a9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025ae:	0f 84 d6 00 00 00    	je     14000268a <__mingw_SEH_error_handler+0x24a>
   1400025b4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025b8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025bd:	ff d0                	call   rax
   1400025bf:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025c6:	e9 bf 00 00 00       	jmp    14000268a <__mingw_SEH_error_handler+0x24a>
   1400025cb:	ba 00 00 00 00       	mov    edx,0x0
   1400025d0:	b9 04 00 00 00       	mov    ecx,0x4
   1400025d5:	e8 d6 0c 00 00       	call   1400032b0 <signal>
   1400025da:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025de:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025e3:	75 1b                	jne    140002600 <__mingw_SEH_error_handler+0x1c0>
   1400025e5:	ba 01 00 00 00       	mov    edx,0x1
   1400025ea:	b9 04 00 00 00       	mov    ecx,0x4
   1400025ef:	e8 bc 0c 00 00       	call   1400032b0 <signal>
   1400025f4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025fb:	e9 8d 00 00 00       	jmp    14000268d <__mingw_SEH_error_handler+0x24d>
   140002600:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002605:	0f 84 82 00 00 00    	je     14000268d <__mingw_SEH_error_handler+0x24d>
   14000260b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000260f:	b9 04 00 00 00       	mov    ecx,0x4
   140002614:	ff d0                	call   rax
   140002616:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000261d:	eb 6e                	jmp    14000268d <__mingw_SEH_error_handler+0x24d>
   14000261f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002626:	ba 00 00 00 00       	mov    edx,0x0
   14000262b:	b9 08 00 00 00       	mov    ecx,0x8
   140002630:	e8 7b 0c 00 00       	call   1400032b0 <signal>
   140002635:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002639:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000263e:	75 23                	jne    140002663 <__mingw_SEH_error_handler+0x223>
   140002640:	ba 01 00 00 00       	mov    edx,0x1
   140002645:	b9 08 00 00 00       	mov    ecx,0x8
   14000264a:	e8 61 0c 00 00       	call   1400032b0 <signal>
   14000264f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002653:	74 05                	je     14000265a <__mingw_SEH_error_handler+0x21a>
   140002655:	e8 a6 05 00 00       	call   140002c00 <_fpreset>
   14000265a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002661:	eb 2d                	jmp    140002690 <__mingw_SEH_error_handler+0x250>
   140002663:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002668:	74 26                	je     140002690 <__mingw_SEH_error_handler+0x250>
   14000266a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000266e:	b9 08 00 00 00       	mov    ecx,0x8
   140002673:	ff d0                	call   rax
   140002675:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000267c:	eb 12                	jmp    140002690 <__mingw_SEH_error_handler+0x250>
   14000267e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002685:	eb 0a                	jmp    140002691 <__mingw_SEH_error_handler+0x251>
   140002687:	90                   	nop
   140002688:	eb 07                	jmp    140002691 <__mingw_SEH_error_handler+0x251>
   14000268a:	90                   	nop
   14000268b:	eb 04                	jmp    140002691 <__mingw_SEH_error_handler+0x251>
   14000268d:	90                   	nop
   14000268e:	eb 01                	jmp    140002691 <__mingw_SEH_error_handler+0x251>
   140002690:	90                   	nop
   140002691:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002694:	48 83 c4 30          	add    rsp,0x30
   140002698:	5d                   	pop    rbp
   140002699:	c3                   	ret

000000014000269a <_gnu_exception_handler>:
   14000269a:	55                   	push   rbp
   14000269b:	48 89 e5             	mov    rbp,rsp
   14000269e:	48 83 ec 30          	sub    rsp,0x30
   1400026a2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400026a6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026ad:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400026b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026b8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026bb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026bd:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400026c2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400026c7:	75 1b                	jne    1400026e4 <_gnu_exception_handler+0x4a>
   1400026c9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026cd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026d0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400026d3:	83 e0 01             	and    eax,0x1
   1400026d6:	85 c0                	test   eax,eax
   1400026d8:	75 0a                	jne    1400026e4 <_gnu_exception_handler+0x4a>
   1400026da:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400026df:	e9 14 02 00 00       	jmp    1400028f8 <_gnu_exception_handler+0x25e>
   1400026e4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026e8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026ed:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026f2:	0f 84 12 01 00 00    	je     14000280a <_gnu_exception_handler+0x170>
   1400026f8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026fd:	0f 87 c3 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   140002703:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002708:	0f 87 b8 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   14000270e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002713:	0f 83 4c 01 00 00    	jae    140002865 <_gnu_exception_handler+0x1cb>
   140002719:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000271e:	0f 84 3a 01 00 00    	je     14000285e <_gnu_exception_handler+0x1c4>
   140002724:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002729:	0f 87 97 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   14000272f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002734:	0f 84 83 01 00 00    	je     1400028bd <_gnu_exception_handler+0x223>
   14000273a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000273f:	0f 87 81 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   140002745:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000274a:	0f 87 76 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   140002750:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002755:	0f 83 03 01 00 00    	jae    14000285e <_gnu_exception_handler+0x1c4>
   14000275b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002760:	0f 84 57 01 00 00    	je     1400028bd <_gnu_exception_handler+0x223>
   140002766:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000276b:	0f 87 55 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   140002771:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002776:	0f 84 8e 00 00 00    	je     14000280a <_gnu_exception_handler+0x170>
   14000277c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002781:	0f 87 3f 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   140002787:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000278c:	0f 84 2b 01 00 00    	je     1400028bd <_gnu_exception_handler+0x223>
   140002792:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002797:	0f 87 29 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   14000279d:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400027a2:	0f 84 15 01 00 00    	je     1400028bd <_gnu_exception_handler+0x223>
   1400027a8:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400027ad:	0f 85 13 01 00 00    	jne    1400028c6 <_gnu_exception_handler+0x22c>
   1400027b3:	ba 00 00 00 00       	mov    edx,0x0
   1400027b8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027bd:	e8 ee 0a 00 00       	call   1400032b0 <signal>
   1400027c2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027c6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027cb:	75 1b                	jne    1400027e8 <_gnu_exception_handler+0x14e>
   1400027cd:	ba 01 00 00 00       	mov    edx,0x1
   1400027d2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027d7:	e8 d4 0a 00 00       	call   1400032b0 <signal>
   1400027dc:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027e3:	e9 e1 00 00 00       	jmp    1400028c9 <_gnu_exception_handler+0x22f>
   1400027e8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027ed:	0f 84 d6 00 00 00    	je     1400028c9 <_gnu_exception_handler+0x22f>
   1400027f3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027f7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027fc:	ff d0                	call   rax
   1400027fe:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002805:	e9 bf 00 00 00       	jmp    1400028c9 <_gnu_exception_handler+0x22f>
   14000280a:	ba 00 00 00 00       	mov    edx,0x0
   14000280f:	b9 04 00 00 00       	mov    ecx,0x4
   140002814:	e8 97 0a 00 00       	call   1400032b0 <signal>
   140002819:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000281d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002822:	75 1b                	jne    14000283f <_gnu_exception_handler+0x1a5>
   140002824:	ba 01 00 00 00       	mov    edx,0x1
   140002829:	b9 04 00 00 00       	mov    ecx,0x4
   14000282e:	e8 7d 0a 00 00       	call   1400032b0 <signal>
   140002833:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000283a:	e9 8d 00 00 00       	jmp    1400028cc <_gnu_exception_handler+0x232>
   14000283f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002844:	0f 84 82 00 00 00    	je     1400028cc <_gnu_exception_handler+0x232>
   14000284a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000284e:	b9 04 00 00 00       	mov    ecx,0x4
   140002853:	ff d0                	call   rax
   140002855:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000285c:	eb 6e                	jmp    1400028cc <_gnu_exception_handler+0x232>
   14000285e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002865:	ba 00 00 00 00       	mov    edx,0x0
   14000286a:	b9 08 00 00 00       	mov    ecx,0x8
   14000286f:	e8 3c 0a 00 00       	call   1400032b0 <signal>
   140002874:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002878:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000287d:	75 23                	jne    1400028a2 <_gnu_exception_handler+0x208>
   14000287f:	ba 01 00 00 00       	mov    edx,0x1
   140002884:	b9 08 00 00 00       	mov    ecx,0x8
   140002889:	e8 22 0a 00 00       	call   1400032b0 <signal>
   14000288e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002892:	74 05                	je     140002899 <_gnu_exception_handler+0x1ff>
   140002894:	e8 67 03 00 00       	call   140002c00 <_fpreset>
   140002899:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028a0:	eb 2d                	jmp    1400028cf <_gnu_exception_handler+0x235>
   1400028a2:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028a7:	74 26                	je     1400028cf <_gnu_exception_handler+0x235>
   1400028a9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028ad:	b9 08 00 00 00       	mov    ecx,0x8
   1400028b2:	ff d0                	call   rax
   1400028b4:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028bb:	eb 12                	jmp    1400028cf <_gnu_exception_handler+0x235>
   1400028bd:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028c4:	eb 0a                	jmp    1400028d0 <_gnu_exception_handler+0x236>
   1400028c6:	90                   	nop
   1400028c7:	eb 07                	jmp    1400028d0 <_gnu_exception_handler+0x236>
   1400028c9:	90                   	nop
   1400028ca:	eb 04                	jmp    1400028d0 <_gnu_exception_handler+0x236>
   1400028cc:	90                   	nop
   1400028cd:	eb 01                	jmp    1400028d0 <_gnu_exception_handler+0x236>
   1400028cf:	90                   	nop
   1400028d0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400028d4:	75 1f                	jne    1400028f5 <_gnu_exception_handler+0x25b>
   1400028d6:	48 8b 05 33 68 00 00 	mov    rax,QWORD PTR [rip+0x6833]        # 140009110 <__mingw_oldexcpt_handler>
   1400028dd:	48 85 c0             	test   rax,rax
   1400028e0:	74 13                	je     1400028f5 <_gnu_exception_handler+0x25b>
   1400028e2:	48 8b 15 27 68 00 00 	mov    rdx,QWORD PTR [rip+0x6827]        # 140009110 <__mingw_oldexcpt_handler>
   1400028e9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028ed:	48 89 c1             	mov    rcx,rax
   1400028f0:	ff d2                	call   rdx
   1400028f2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400028f5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400028f8:	48 83 c4 30          	add    rsp,0x30
   1400028fc:	5d                   	pop    rbp
   1400028fd:	c3                   	ret
   1400028fe:	90                   	nop
   1400028ff:	90                   	nop

0000000140002900 <___w64_mingwthr_add_key_dtor>:
   140002900:	55                   	push   rbp
   140002901:	48 89 e5             	mov    rbp,rsp
   140002904:	48 83 ec 30          	sub    rsp,0x30
   140002908:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000290b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000290f:	8b 05 33 68 00 00    	mov    eax,DWORD PTR [rip+0x6833]        # 140009148 <__mingwthr_cs_init>
   140002915:	85 c0                	test   eax,eax
   140002917:	75 07                	jne    140002920 <___w64_mingwthr_add_key_dtor+0x20>
   140002919:	b8 00 00 00 00       	mov    eax,0x0
   14000291e:	eb 7b                	jmp    14000299b <___w64_mingwthr_add_key_dtor+0x9b>
   140002920:	ba 18 00 00 00       	mov    edx,0x18
   140002925:	b9 01 00 00 00       	mov    ecx,0x1
   14000292a:	e8 41 09 00 00       	call   140003270 <calloc>
   14000292f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002933:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002938:	75 07                	jne    140002941 <___w64_mingwthr_add_key_dtor+0x41>
   14000293a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000293f:	eb 5a                	jmp    14000299b <___w64_mingwthr_add_key_dtor+0x9b>
   140002941:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002945:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002948:	89 10                	mov    DWORD PTR [rax],edx
   14000294a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000294e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002952:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002956:	48 8d 05 c3 67 00 00 	lea    rax,[rip+0x67c3]        # 140009120 <__mingwthr_cs>
   14000295d:	48 89 c1             	mov    rcx,rax
   140002960:	48 8b 05 31 78 00 00 	mov    rax,QWORD PTR [rip+0x7831]        # 14000a198 <__imp_EnterCriticalSection>
   140002967:	ff d0                	call   rax
   140002969:	48 8b 15 e0 67 00 00 	mov    rdx,QWORD PTR [rip+0x67e0]        # 140009150 <key_dtor_list>
   140002970:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002974:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002978:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000297c:	48 89 05 cd 67 00 00 	mov    QWORD PTR [rip+0x67cd],rax        # 140009150 <key_dtor_list>
   140002983:	48 8d 05 96 67 00 00 	lea    rax,[rip+0x6796]        # 140009120 <__mingwthr_cs>
   14000298a:	48 89 c1             	mov    rcx,rax
   14000298d:	48 8b 05 34 78 00 00 	mov    rax,QWORD PTR [rip+0x7834]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002994:	ff d0                	call   rax
   140002996:	b8 00 00 00 00       	mov    eax,0x0
   14000299b:	48 83 c4 30          	add    rsp,0x30
   14000299f:	5d                   	pop    rbp
   1400029a0:	c3                   	ret

00000001400029a1 <___w64_mingwthr_remove_key_dtor>:
   1400029a1:	55                   	push   rbp
   1400029a2:	48 89 e5             	mov    rbp,rsp
   1400029a5:	48 83 ec 30          	sub    rsp,0x30
   1400029a9:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029ac:	8b 05 96 67 00 00    	mov    eax,DWORD PTR [rip+0x6796]        # 140009148 <__mingwthr_cs_init>
   1400029b2:	85 c0                	test   eax,eax
   1400029b4:	75 0a                	jne    1400029c0 <___w64_mingwthr_remove_key_dtor+0x1f>
   1400029b6:	b8 00 00 00 00       	mov    eax,0x0
   1400029bb:	e9 9c 00 00 00       	jmp    140002a5c <___w64_mingwthr_remove_key_dtor+0xbb>
   1400029c0:	48 8d 05 59 67 00 00 	lea    rax,[rip+0x6759]        # 140009120 <__mingwthr_cs>
   1400029c7:	48 89 c1             	mov    rcx,rax
   1400029ca:	48 8b 05 c7 77 00 00 	mov    rax,QWORD PTR [rip+0x77c7]        # 14000a198 <__imp_EnterCriticalSection>
   1400029d1:	ff d0                	call   rax
   1400029d3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400029da:	00 
   1400029db:	48 8b 05 6e 67 00 00 	mov    rax,QWORD PTR [rip+0x676e]        # 140009150 <key_dtor_list>
   1400029e2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029e6:	eb 55                	jmp    140002a3d <___w64_mingwthr_remove_key_dtor+0x9c>
   1400029e8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ec:	8b 00                	mov    eax,DWORD PTR [rax]
   1400029ee:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   1400029f1:	75 36                	jne    140002a29 <___w64_mingwthr_remove_key_dtor+0x88>
   1400029f3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029f8:	75 11                	jne    140002a0b <___w64_mingwthr_remove_key_dtor+0x6a>
   1400029fa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029fe:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a02:	48 89 05 47 67 00 00 	mov    QWORD PTR [rip+0x6747],rax        # 140009150 <key_dtor_list>
   140002a09:	eb 10                	jmp    140002a1b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a0b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a0f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a13:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a17:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a1b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a1f:	48 89 c1             	mov    rcx,rax
   140002a22:	e8 69 08 00 00       	call   140003290 <free>
   140002a27:	eb 1b                	jmp    140002a44 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a29:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a2d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a31:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a35:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a39:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a3d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a42:	75 a4                	jne    1400029e8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a44:	48 8d 05 d5 66 00 00 	lea    rax,[rip+0x66d5]        # 140009120 <__mingwthr_cs>
   140002a4b:	48 89 c1             	mov    rcx,rax
   140002a4e:	48 8b 05 73 77 00 00 	mov    rax,QWORD PTR [rip+0x7773]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002a55:	ff d0                	call   rax
   140002a57:	b8 00 00 00 00       	mov    eax,0x0
   140002a5c:	48 83 c4 30          	add    rsp,0x30
   140002a60:	5d                   	pop    rbp
   140002a61:	c3                   	ret

0000000140002a62 <__mingwthr_run_key_dtors>:
   140002a62:	55                   	push   rbp
   140002a63:	48 89 e5             	mov    rbp,rsp
   140002a66:	48 83 ec 30          	sub    rsp,0x30
   140002a6a:	8b 05 d8 66 00 00    	mov    eax,DWORD PTR [rip+0x66d8]        # 140009148 <__mingwthr_cs_init>
   140002a70:	85 c0                	test   eax,eax
   140002a72:	0f 84 82 00 00 00    	je     140002afa <__mingwthr_run_key_dtors+0x98>
   140002a78:	48 8d 05 a1 66 00 00 	lea    rax,[rip+0x66a1]        # 140009120 <__mingwthr_cs>
   140002a7f:	48 89 c1             	mov    rcx,rax
   140002a82:	48 8b 05 0f 77 00 00 	mov    rax,QWORD PTR [rip+0x770f]        # 14000a198 <__imp_EnterCriticalSection>
   140002a89:	ff d0                	call   rax
   140002a8b:	48 8b 05 be 66 00 00 	mov    rax,QWORD PTR [rip+0x66be]        # 140009150 <key_dtor_list>
   140002a92:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a96:	eb 46                	jmp    140002ade <__mingwthr_run_key_dtors+0x7c>
   140002a98:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a9c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a9e:	89 c1                	mov    ecx,eax
   140002aa0:	48 8b 05 41 77 00 00 	mov    rax,QWORD PTR [rip+0x7741]        # 14000a1e8 <__imp_TlsGetValue>
   140002aa7:	ff d0                	call   rax
   140002aa9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002aad:	48 8b 05 f4 76 00 00 	mov    rax,QWORD PTR [rip+0x76f4]        # 14000a1a8 <__imp_GetLastError>
   140002ab4:	ff d0                	call   rax
   140002ab6:	85 c0                	test   eax,eax
   140002ab8:	75 18                	jne    140002ad2 <__mingwthr_run_key_dtors+0x70>
   140002aba:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002abf:	74 11                	je     140002ad2 <__mingwthr_run_key_dtors+0x70>
   140002ac1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ac5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002ac9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002acd:	48 89 c1             	mov    rcx,rax
   140002ad0:	ff d2                	call   rdx
   140002ad2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ad6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ada:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ade:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ae3:	75 b3                	jne    140002a98 <__mingwthr_run_key_dtors+0x36>
   140002ae5:	48 8d 05 34 66 00 00 	lea    rax,[rip+0x6634]        # 140009120 <__mingwthr_cs>
   140002aec:	48 89 c1             	mov    rcx,rax
   140002aef:	48 8b 05 d2 76 00 00 	mov    rax,QWORD PTR [rip+0x76d2]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002af6:	ff d0                	call   rax
   140002af8:	eb 01                	jmp    140002afb <__mingwthr_run_key_dtors+0x99>
   140002afa:	90                   	nop
   140002afb:	48 83 c4 30          	add    rsp,0x30
   140002aff:	5d                   	pop    rbp
   140002b00:	c3                   	ret

0000000140002b01 <__mingw_TLScallback>:
   140002b01:	55                   	push   rbp
   140002b02:	48 89 e5             	mov    rbp,rsp
   140002b05:	48 83 ec 30          	sub    rsp,0x30
   140002b09:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b0d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b10:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b14:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b18:	0f 84 cc 00 00 00    	je     140002bea <__mingw_TLScallback+0xe9>
   140002b1e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b22:	0f 87 ca 00 00 00    	ja     140002bf2 <__mingw_TLScallback+0xf1>
   140002b28:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b2c:	0f 84 b1 00 00 00    	je     140002be3 <__mingw_TLScallback+0xe2>
   140002b32:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b36:	0f 87 b6 00 00 00    	ja     140002bf2 <__mingw_TLScallback+0xf1>
   140002b3c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b40:	74 33                	je     140002b75 <__mingw_TLScallback+0x74>
   140002b42:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b46:	0f 85 a6 00 00 00    	jne    140002bf2 <__mingw_TLScallback+0xf1>
   140002b4c:	8b 05 f6 65 00 00    	mov    eax,DWORD PTR [rip+0x65f6]        # 140009148 <__mingwthr_cs_init>
   140002b52:	85 c0                	test   eax,eax
   140002b54:	75 13                	jne    140002b69 <__mingw_TLScallback+0x68>
   140002b56:	48 8d 05 c3 65 00 00 	lea    rax,[rip+0x65c3]        # 140009120 <__mingwthr_cs>
   140002b5d:	48 89 c1             	mov    rcx,rax
   140002b60:	48 8b 05 59 76 00 00 	mov    rax,QWORD PTR [rip+0x7659]        # 14000a1c0 <__imp_InitializeCriticalSection>
   140002b67:	ff d0                	call   rax
   140002b69:	c7 05 d5 65 00 00 01 	mov    DWORD PTR [rip+0x65d5],0x1        # 140009148 <__mingwthr_cs_init>
   140002b70:	00 00 00 
   140002b73:	eb 7d                	jmp    140002bf2 <__mingw_TLScallback+0xf1>
   140002b75:	e8 e8 fe ff ff       	call   140002a62 <__mingwthr_run_key_dtors>
   140002b7a:	8b 05 c8 65 00 00    	mov    eax,DWORD PTR [rip+0x65c8]        # 140009148 <__mingwthr_cs_init>
   140002b80:	83 f8 01             	cmp    eax,0x1
   140002b83:	75 6c                	jne    140002bf1 <__mingw_TLScallback+0xf0>
   140002b85:	48 8b 05 c4 65 00 00 	mov    rax,QWORD PTR [rip+0x65c4]        # 140009150 <key_dtor_list>
   140002b8c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b90:	eb 20                	jmp    140002bb2 <__mingw_TLScallback+0xb1>
   140002b92:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b96:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b9a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b9e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ba2:	48 89 c1             	mov    rcx,rax
   140002ba5:	e8 e6 06 00 00       	call   140003290 <free>
   140002baa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bb2:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002bb7:	75 d9                	jne    140002b92 <__mingw_TLScallback+0x91>
   140002bb9:	48 c7 05 8c 65 00 00 	mov    QWORD PTR [rip+0x658c],0x0        # 140009150 <key_dtor_list>
   140002bc0:	00 00 00 00 
   140002bc4:	c7 05 7a 65 00 00 00 	mov    DWORD PTR [rip+0x657a],0x0        # 140009148 <__mingwthr_cs_init>
   140002bcb:	00 00 00 
   140002bce:	48 8d 05 4b 65 00 00 	lea    rax,[rip+0x654b]        # 140009120 <__mingwthr_cs>
   140002bd5:	48 89 c1             	mov    rcx,rax
   140002bd8:	48 8b 05 b1 75 00 00 	mov    rax,QWORD PTR [rip+0x75b1]        # 14000a190 <__IAT_start__>
   140002bdf:	ff d0                	call   rax
   140002be1:	eb 0e                	jmp    140002bf1 <__mingw_TLScallback+0xf0>
   140002be3:	e8 18 00 00 00       	call   140002c00 <_fpreset>
   140002be8:	eb 08                	jmp    140002bf2 <__mingw_TLScallback+0xf1>
   140002bea:	e8 73 fe ff ff       	call   140002a62 <__mingwthr_run_key_dtors>
   140002bef:	eb 01                	jmp    140002bf2 <__mingw_TLScallback+0xf1>
   140002bf1:	90                   	nop
   140002bf2:	b8 01 00 00 00       	mov    eax,0x1
   140002bf7:	48 83 c4 30          	add    rsp,0x30
   140002bfb:	5d                   	pop    rbp
   140002bfc:	c3                   	ret
   140002bfd:	90                   	nop
   140002bfe:	90                   	nop
   140002bff:	90                   	nop

0000000140002c00 <_fpreset>:
   140002c00:	55                   	push   rbp
   140002c01:	48 89 e5             	mov    rbp,rsp
   140002c04:	db e3                	fninit
   140002c06:	90                   	nop
   140002c07:	5d                   	pop    rbp
   140002c08:	c3                   	ret
   140002c09:	90                   	nop
   140002c0a:	90                   	nop
   140002c0b:	90                   	nop
   140002c0c:	90                   	nop
   140002c0d:	90                   	nop
   140002c0e:	90                   	nop
   140002c0f:	90                   	nop

0000000140002c10 <_ValidateImageBase>:
   140002c10:	55                   	push   rbp
   140002c11:	48 89 e5             	mov    rbp,rsp
   140002c14:	48 83 ec 20          	sub    rsp,0x20
   140002c18:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c1c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c20:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c24:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c28:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c2b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c2f:	74 07                	je     140002c38 <_ValidateImageBase+0x28>
   140002c31:	b8 00 00 00 00       	mov    eax,0x0
   140002c36:	eb 4e                	jmp    140002c86 <_ValidateImageBase+0x76>
   140002c38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c3c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c3f:	48 63 d0             	movsxd rdx,eax
   140002c42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c46:	48 01 d0             	add    rax,rdx
   140002c49:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c4d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c51:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c53:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c58:	74 07                	je     140002c61 <_ValidateImageBase+0x51>
   140002c5a:	b8 00 00 00 00       	mov    eax,0x0
   140002c5f:	eb 25                	jmp    140002c86 <_ValidateImageBase+0x76>
   140002c61:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c65:	48 83 c0 18          	add    rax,0x18
   140002c69:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c6d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c71:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c74:	66 3d 0b 02          	cmp    ax,0x20b
   140002c78:	74 07                	je     140002c81 <_ValidateImageBase+0x71>
   140002c7a:	b8 00 00 00 00       	mov    eax,0x0
   140002c7f:	eb 05                	jmp    140002c86 <_ValidateImageBase+0x76>
   140002c81:	b8 01 00 00 00       	mov    eax,0x1
   140002c86:	48 83 c4 20          	add    rsp,0x20
   140002c8a:	5d                   	pop    rbp
   140002c8b:	c3                   	ret

0000000140002c8c <_FindPESection>:
   140002c8c:	55                   	push   rbp
   140002c8d:	48 89 e5             	mov    rbp,rsp
   140002c90:	48 83 ec 20          	sub    rsp,0x20
   140002c94:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c98:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002c9c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ca0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ca3:	48 63 d0             	movsxd rdx,eax
   140002ca6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002caa:	48 01 d0             	add    rax,rdx
   140002cad:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002cb1:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002cb8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cbc:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002cc0:	0f b7 d0             	movzx  edx,ax
   140002cc3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cc7:	48 01 d0             	add    rax,rdx
   140002cca:	48 83 c0 18          	add    rax,0x18
   140002cce:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cd2:	eb 36                	jmp    140002d0a <_FindPESection+0x7e>
   140002cd4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cd8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002cdb:	89 c0                	mov    eax,eax
   140002cdd:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002ce1:	72 1e                	jb     140002d01 <_FindPESection+0x75>
   140002ce3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ce7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002cea:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cee:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002cf1:	01 d0                	add    eax,edx
   140002cf3:	89 c0                	mov    eax,eax
   140002cf5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cf9:	73 06                	jae    140002d01 <_FindPESection+0x75>
   140002cfb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cff:	eb 1e                	jmp    140002d1f <_FindPESection+0x93>
   140002d01:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d05:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d0a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d0e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d12:	0f b7 c0             	movzx  eax,ax
   140002d15:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d18:	72 ba                	jb     140002cd4 <_FindPESection+0x48>
   140002d1a:	b8 00 00 00 00       	mov    eax,0x0
   140002d1f:	48 83 c4 20          	add    rsp,0x20
   140002d23:	5d                   	pop    rbp
   140002d24:	c3                   	ret

0000000140002d25 <_FindPESectionByName>:
   140002d25:	55                   	push   rbp
   140002d26:	48 89 e5             	mov    rbp,rsp
   140002d29:	48 83 ec 40          	sub    rsp,0x40
   140002d2d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d31:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d35:	48 89 c1             	mov    rcx,rax
   140002d38:	e8 83 05 00 00       	call   1400032c0 <strlen>
   140002d3d:	48 83 f8 08          	cmp    rax,0x8
   140002d41:	76 0a                	jbe    140002d4d <_FindPESectionByName+0x28>
   140002d43:	b8 00 00 00 00       	mov    eax,0x0
   140002d48:	e9 98 00 00 00       	jmp    140002de5 <_FindPESectionByName+0xc0>
   140002d4d:	48 8b 05 0c 26 00 00 	mov    rax,QWORD PTR [rip+0x260c]        # 140005360 <.refptr.__ImageBase>
   140002d54:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d58:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d5c:	48 89 c1             	mov    rcx,rax
   140002d5f:	e8 ac fe ff ff       	call   140002c10 <_ValidateImageBase>
   140002d64:	85 c0                	test   eax,eax
   140002d66:	75 07                	jne    140002d6f <_FindPESectionByName+0x4a>
   140002d68:	b8 00 00 00 00       	mov    eax,0x0
   140002d6d:	eb 76                	jmp    140002de5 <_FindPESectionByName+0xc0>
   140002d6f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d73:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d76:	48 63 d0             	movsxd rdx,eax
   140002d79:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d7d:	48 01 d0             	add    rax,rdx
   140002d80:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002d84:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d8b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d8f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d93:	0f b7 d0             	movzx  edx,ax
   140002d96:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d9a:	48 01 d0             	add    rax,rdx
   140002d9d:	48 83 c0 18          	add    rax,0x18
   140002da1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002da5:	eb 29                	jmp    140002dd0 <_FindPESectionByName+0xab>
   140002da7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dab:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002daf:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002db5:	48 89 c1             	mov    rcx,rax
   140002db8:	e8 0b 05 00 00       	call   1400032c8 <strncmp>
   140002dbd:	85 c0                	test   eax,eax
   140002dbf:	75 06                	jne    140002dc7 <_FindPESectionByName+0xa2>
   140002dc1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dc5:	eb 1e                	jmp    140002de5 <_FindPESectionByName+0xc0>
   140002dc7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002dcb:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002dd0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dd4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002dd8:	0f b7 c0             	movzx  eax,ax
   140002ddb:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002dde:	72 c7                	jb     140002da7 <_FindPESectionByName+0x82>
   140002de0:	b8 00 00 00 00       	mov    eax,0x0
   140002de5:	48 83 c4 40          	add    rsp,0x40
   140002de9:	5d                   	pop    rbp
   140002dea:	c3                   	ret

0000000140002deb <__mingw_GetSectionForAddress>:
   140002deb:	55                   	push   rbp
   140002dec:	48 89 e5             	mov    rbp,rsp
   140002def:	48 83 ec 30          	sub    rsp,0x30
   140002df3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002df7:	48 8b 05 62 25 00 00 	mov    rax,QWORD PTR [rip+0x2562]        # 140005360 <.refptr.__ImageBase>
   140002dfe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e06:	48 89 c1             	mov    rcx,rax
   140002e09:	e8 02 fe ff ff       	call   140002c10 <_ValidateImageBase>
   140002e0e:	85 c0                	test   eax,eax
   140002e10:	75 07                	jne    140002e19 <__mingw_GetSectionForAddress+0x2e>
   140002e12:	b8 00 00 00 00       	mov    eax,0x0
   140002e17:	eb 1c                	jmp    140002e35 <__mingw_GetSectionForAddress+0x4a>
   140002e19:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e1d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e21:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e25:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e29:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e2d:	48 89 c1             	mov    rcx,rax
   140002e30:	e8 57 fe ff ff       	call   140002c8c <_FindPESection>
   140002e35:	48 83 c4 30          	add    rsp,0x30
   140002e39:	5d                   	pop    rbp
   140002e3a:	c3                   	ret

0000000140002e3b <__mingw_GetSectionCount>:
   140002e3b:	55                   	push   rbp
   140002e3c:	48 89 e5             	mov    rbp,rsp
   140002e3f:	48 83 ec 30          	sub    rsp,0x30
   140002e43:	48 8b 05 16 25 00 00 	mov    rax,QWORD PTR [rip+0x2516]        # 140005360 <.refptr.__ImageBase>
   140002e4a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e4e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e52:	48 89 c1             	mov    rcx,rax
   140002e55:	e8 b6 fd ff ff       	call   140002c10 <_ValidateImageBase>
   140002e5a:	85 c0                	test   eax,eax
   140002e5c:	75 07                	jne    140002e65 <__mingw_GetSectionCount+0x2a>
   140002e5e:	b8 00 00 00 00       	mov    eax,0x0
   140002e63:	eb 20                	jmp    140002e85 <__mingw_GetSectionCount+0x4a>
   140002e65:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e69:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e6c:	48 63 d0             	movsxd rdx,eax
   140002e6f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e73:	48 01 d0             	add    rax,rdx
   140002e76:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e7a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e7e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e82:	0f b7 c0             	movzx  eax,ax
   140002e85:	48 83 c4 30          	add    rsp,0x30
   140002e89:	5d                   	pop    rbp
   140002e8a:	c3                   	ret

0000000140002e8b <_FindPESectionExec>:
   140002e8b:	55                   	push   rbp
   140002e8c:	48 89 e5             	mov    rbp,rsp
   140002e8f:	48 83 ec 40          	sub    rsp,0x40
   140002e93:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e97:	48 8b 05 c2 24 00 00 	mov    rax,QWORD PTR [rip+0x24c2]        # 140005360 <.refptr.__ImageBase>
   140002e9e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ea2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ea6:	48 89 c1             	mov    rcx,rax
   140002ea9:	e8 62 fd ff ff       	call   140002c10 <_ValidateImageBase>
   140002eae:	85 c0                	test   eax,eax
   140002eb0:	75 07                	jne    140002eb9 <_FindPESectionExec+0x2e>
   140002eb2:	b8 00 00 00 00       	mov    eax,0x0
   140002eb7:	eb 78                	jmp    140002f31 <_FindPESectionExec+0xa6>
   140002eb9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ebd:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ec0:	48 63 d0             	movsxd rdx,eax
   140002ec3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ec7:	48 01 d0             	add    rax,rdx
   140002eca:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002ece:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ed5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ed9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002edd:	0f b7 d0             	movzx  edx,ax
   140002ee0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ee4:	48 01 d0             	add    rax,rdx
   140002ee7:	48 83 c0 18          	add    rax,0x18
   140002eeb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002eef:	eb 2b                	jmp    140002f1c <_FindPESectionExec+0x91>
   140002ef1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ef5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002ef8:	25 00 00 00 20       	and    eax,0x20000000
   140002efd:	85 c0                	test   eax,eax
   140002eff:	74 12                	je     140002f13 <_FindPESectionExec+0x88>
   140002f01:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f06:	75 06                	jne    140002f0e <_FindPESectionExec+0x83>
   140002f08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f0c:	eb 23                	jmp    140002f31 <_FindPESectionExec+0xa6>
   140002f0e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f13:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f17:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f1c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f20:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f24:	0f b7 c0             	movzx  eax,ax
   140002f27:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f2a:	72 c5                	jb     140002ef1 <_FindPESectionExec+0x66>
   140002f2c:	b8 00 00 00 00       	mov    eax,0x0
   140002f31:	48 83 c4 40          	add    rsp,0x40
   140002f35:	5d                   	pop    rbp
   140002f36:	c3                   	ret

0000000140002f37 <_GetPEImageBase>:
   140002f37:	55                   	push   rbp
   140002f38:	48 89 e5             	mov    rbp,rsp
   140002f3b:	48 83 ec 30          	sub    rsp,0x30
   140002f3f:	48 8b 05 1a 24 00 00 	mov    rax,QWORD PTR [rip+0x241a]        # 140005360 <.refptr.__ImageBase>
   140002f46:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f4a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f4e:	48 89 c1             	mov    rcx,rax
   140002f51:	e8 ba fc ff ff       	call   140002c10 <_ValidateImageBase>
   140002f56:	85 c0                	test   eax,eax
   140002f58:	75 07                	jne    140002f61 <_GetPEImageBase+0x2a>
   140002f5a:	b8 00 00 00 00       	mov    eax,0x0
   140002f5f:	eb 04                	jmp    140002f65 <_GetPEImageBase+0x2e>
   140002f61:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f65:	48 83 c4 30          	add    rsp,0x30
   140002f69:	5d                   	pop    rbp
   140002f6a:	c3                   	ret

0000000140002f6b <_IsNonwritableInCurrentImage>:
   140002f6b:	55                   	push   rbp
   140002f6c:	48 89 e5             	mov    rbp,rsp
   140002f6f:	48 83 ec 40          	sub    rsp,0x40
   140002f73:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f77:	48 8b 05 e2 23 00 00 	mov    rax,QWORD PTR [rip+0x23e2]        # 140005360 <.refptr.__ImageBase>
   140002f7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f82:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f86:	48 89 c1             	mov    rcx,rax
   140002f89:	e8 82 fc ff ff       	call   140002c10 <_ValidateImageBase>
   140002f8e:	85 c0                	test   eax,eax
   140002f90:	75 07                	jne    140002f99 <_IsNonwritableInCurrentImage+0x2e>
   140002f92:	b8 00 00 00 00       	mov    eax,0x0
   140002f97:	eb 3d                	jmp    140002fd6 <_IsNonwritableInCurrentImage+0x6b>
   140002f99:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f9d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002fa1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fa5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002fa9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fad:	48 89 c1             	mov    rcx,rax
   140002fb0:	e8 d7 fc ff ff       	call   140002c8c <_FindPESection>
   140002fb5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002fb9:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002fbe:	75 07                	jne    140002fc7 <_IsNonwritableInCurrentImage+0x5c>
   140002fc0:	b8 00 00 00 00       	mov    eax,0x0
   140002fc5:	eb 0f                	jmp    140002fd6 <_IsNonwritableInCurrentImage+0x6b>
   140002fc7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002fcb:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fce:	f7 d0                	not    eax
   140002fd0:	c1 e8 1f             	shr    eax,0x1f
   140002fd3:	0f b6 c0             	movzx  eax,al
   140002fd6:	48 83 c4 40          	add    rsp,0x40
   140002fda:	5d                   	pop    rbp
   140002fdb:	c3                   	ret

0000000140002fdc <__mingw_enum_import_library_names>:
   140002fdc:	55                   	push   rbp
   140002fdd:	48 89 e5             	mov    rbp,rsp
   140002fe0:	48 83 ec 50          	sub    rsp,0x50
   140002fe4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002fe7:	48 8b 05 72 23 00 00 	mov    rax,QWORD PTR [rip+0x2372]        # 140005360 <.refptr.__ImageBase>
   140002fee:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ff2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ff6:	48 89 c1             	mov    rcx,rax
   140002ff9:	e8 12 fc ff ff       	call   140002c10 <_ValidateImageBase>
   140002ffe:	85 c0                	test   eax,eax
   140003000:	75 0a                	jne    14000300c <__mingw_enum_import_library_names+0x30>
   140003002:	b8 00 00 00 00       	mov    eax,0x0
   140003007:	e9 ab 00 00 00       	jmp    1400030b7 <__mingw_enum_import_library_names+0xdb>
   14000300c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003010:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003013:	48 63 d0             	movsxd rdx,eax
   140003016:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000301a:	48 01 d0             	add    rax,rdx
   14000301d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003021:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003025:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000302b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000302e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003032:	75 07                	jne    14000303b <__mingw_enum_import_library_names+0x5f>
   140003034:	b8 00 00 00 00       	mov    eax,0x0
   140003039:	eb 7c                	jmp    1400030b7 <__mingw_enum_import_library_names+0xdb>
   14000303b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000303e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003042:	48 89 c1             	mov    rcx,rax
   140003045:	e8 42 fc ff ff       	call   140002c8c <_FindPESection>
   14000304a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000304e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003053:	75 07                	jne    14000305c <__mingw_enum_import_library_names+0x80>
   140003055:	b8 00 00 00 00       	mov    eax,0x0
   14000305a:	eb 5b                	jmp    1400030b7 <__mingw_enum_import_library_names+0xdb>
   14000305c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000305f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003063:	48 01 d0             	add    rax,rdx
   140003066:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000306a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000306f:	75 07                	jne    140003078 <__mingw_enum_import_library_names+0x9c>
   140003071:	b8 00 00 00 00       	mov    eax,0x0
   140003076:	eb 3f                	jmp    1400030b7 <__mingw_enum_import_library_names+0xdb>
   140003078:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000307c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000307f:	85 c0                	test   eax,eax
   140003081:	75 0b                	jne    14000308e <__mingw_enum_import_library_names+0xb2>
   140003083:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003087:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000308a:	85 c0                	test   eax,eax
   14000308c:	74 23                	je     1400030b1 <__mingw_enum_import_library_names+0xd5>
   14000308e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003092:	7f 12                	jg     1400030a6 <__mingw_enum_import_library_names+0xca>
   140003094:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003098:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000309b:	89 c2                	mov    edx,eax
   14000309d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030a1:	48 01 d0             	add    rax,rdx
   1400030a4:	eb 11                	jmp    1400030b7 <__mingw_enum_import_library_names+0xdb>
   1400030a6:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   1400030aa:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   1400030af:	eb c7                	jmp    140003078 <__mingw_enum_import_library_names+0x9c>
   1400030b1:	90                   	nop
   1400030b2:	b8 00 00 00 00       	mov    eax,0x0
   1400030b7:	48 83 c4 50          	add    rsp,0x50
   1400030bb:	5d                   	pop    rbp
   1400030bc:	c3                   	ret
   1400030bd:	90                   	nop
   1400030be:	90                   	nop
   1400030bf:	90                   	nop

00000001400030c0 <___chkstk_ms>:
   1400030c0:	51                   	push   rcx
   1400030c1:	50                   	push   rax
   1400030c2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030c8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400030cd:	72 19                	jb     1400030e8 <___chkstk_ms+0x28>
   1400030cf:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400030d6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030da:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400030e0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030e6:	77 e7                	ja     1400030cf <___chkstk_ms+0xf>
   1400030e8:	48 29 c1             	sub    rcx,rax
   1400030eb:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030ef:	58                   	pop    rax
   1400030f0:	59                   	pop    rcx
   1400030f1:	c3                   	ret
   1400030f2:	90                   	nop
   1400030f3:	90                   	nop
   1400030f4:	90                   	nop
   1400030f5:	90                   	nop
   1400030f6:	90                   	nop
   1400030f7:	90                   	nop
   1400030f8:	90                   	nop
   1400030f9:	90                   	nop
   1400030fa:	90                   	nop
   1400030fb:	90                   	nop
   1400030fc:	90                   	nop
   1400030fd:	90                   	nop
   1400030fe:	90                   	nop
   1400030ff:	90                   	nop

0000000140003100 <_initterm_e>:
   140003100:	55                   	push   rbp
   140003101:	48 89 e5             	mov    rbp,rsp
   140003104:	48 83 ec 30          	sub    rsp,0x30
   140003108:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000310c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003110:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003114:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003118:	eb 29                	jmp    140003143 <_initterm_e+0x43>
   14000311a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000311e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140003121:	48 85 c0             	test   rax,rax
   140003124:	74 17                	je     14000313d <_initterm_e+0x3d>
   140003126:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000312a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000312d:	ff d0                	call   rax
   14000312f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003132:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003136:	74 06                	je     14000313e <_initterm_e+0x3e>
   140003138:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000313b:	eb 15                	jmp    140003152 <_initterm_e+0x52>
   14000313d:	90                   	nop
   14000313e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140003143:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003147:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   14000314b:	72 cd                	jb     14000311a <_initterm_e+0x1a>
   14000314d:	b8 00 00 00 00       	mov    eax,0x0
   140003152:	48 83 c4 30          	add    rsp,0x30
   140003156:	5d                   	pop    rbp
   140003157:	c3                   	ret
   140003158:	90                   	nop
   140003159:	90                   	nop
   14000315a:	90                   	nop
   14000315b:	90                   	nop
   14000315c:	90                   	nop
   14000315d:	90                   	nop
   14000315e:	90                   	nop
   14000315f:	90                   	nop

0000000140003160 <__p__fmode>:
   140003160:	55                   	push   rbp
   140003161:	48 89 e5             	mov    rbp,rsp
   140003164:	48 8b 05 65 22 00 00 	mov    rax,QWORD PTR [rip+0x2265]        # 1400053d0 <.refptr.__imp__fmode>
   14000316b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000316e:	5d                   	pop    rbp
   14000316f:	c3                   	ret

0000000140003170 <__p__commode>:
   140003170:	55                   	push   rbp
   140003171:	48 89 e5             	mov    rbp,rsp
   140003174:	48 8b 05 45 22 00 00 	mov    rax,QWORD PTR [rip+0x2245]        # 1400053c0 <.refptr.__imp__commode>
   14000317b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000317e:	5d                   	pop    rbp
   14000317f:	c3                   	ret

0000000140003180 <__p___initenv>:
   140003180:	55                   	push   rbp
   140003181:	48 89 e5             	mov    rbp,rsp
   140003184:	48 8b 05 25 22 00 00 	mov    rax,QWORD PTR [rip+0x2225]        # 1400053b0 <.refptr.__imp___initenv>
   14000318b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000318e:	5d                   	pop    rbp
   14000318f:	c3                   	ret

0000000140003190 <_set_invalid_parameter_handler>:
   140003190:	55                   	push   rbp
   140003191:	48 89 e5             	mov    rbp,rsp
   140003194:	48 83 ec 10          	sub    rsp,0x10
   140003198:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000319c:	48 8d 05 ed 5f 00 00 	lea    rax,[rip+0x5fed]        # 140009190 <handler>
   1400031a3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031a7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400031ab:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400031af:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400031b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031b7:	48 87 10             	xchg   QWORD PTR [rax],rdx
   1400031ba:	48 89 d0             	mov    rax,rdx
   1400031bd:	48 83 c4 10          	add    rsp,0x10
   1400031c1:	5d                   	pop    rbp
   1400031c2:	c3                   	ret

00000001400031c3 <_get_invalid_parameter_handler>:
   1400031c3:	55                   	push   rbp
   1400031c4:	48 89 e5             	mov    rbp,rsp
   1400031c7:	48 8b 05 c2 5f 00 00 	mov    rax,QWORD PTR [rip+0x5fc2]        # 140009190 <handler>
   1400031ce:	5d                   	pop    rbp
   1400031cf:	c3                   	ret

00000001400031d0 <_configthreadlocale>:
   1400031d0:	55                   	push   rbp
   1400031d1:	48 89 e5             	mov    rbp,rsp
   1400031d4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031d7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   1400031db:	75 07                	jne    1400031e4 <_configthreadlocale+0x14>
   1400031dd:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400031e2:	eb 05                	jmp    1400031e9 <_configthreadlocale+0x19>
   1400031e4:	b8 02 00 00 00       	mov    eax,0x2
   1400031e9:	5d                   	pop    rbp
   1400031ea:	c3                   	ret
   1400031eb:	90                   	nop
   1400031ec:	90                   	nop
   1400031ed:	90                   	nop
   1400031ee:	90                   	nop
   1400031ef:	90                   	nop

00000001400031f0 <__acrt_iob_func>:
   1400031f0:	55                   	push   rbp
   1400031f1:	48 89 e5             	mov    rbp,rsp
   1400031f4:	48 83 ec 20          	sub    rsp,0x20
   1400031f8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031fb:	e8 30 00 00 00       	call   140003230 <__iob_func>
   140003200:	48 89 c1             	mov    rcx,rax
   140003203:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003206:	48 89 d0             	mov    rax,rdx
   140003209:	48 01 c0             	add    rax,rax
   14000320c:	48 01 d0             	add    rax,rdx
   14000320f:	48 c1 e0 04          	shl    rax,0x4
   140003213:	48 01 c8             	add    rax,rcx
   140003216:	48 83 c4 20          	add    rsp,0x20
   14000321a:	5d                   	pop    rbp
   14000321b:	c3                   	ret
   14000321c:	90                   	nop
   14000321d:	90                   	nop
   14000321e:	90                   	nop
   14000321f:	90                   	nop

0000000140003220 <__C_specific_handler>:
   140003220:	ff 25 e2 6f 00 00    	jmp    QWORD PTR [rip+0x6fe2]        # 14000a208 <__imp___C_specific_handler>
   140003226:	90                   	nop
   140003227:	90                   	nop

0000000140003228 <__getmainargs>:
   140003228:	ff 25 e2 6f 00 00    	jmp    QWORD PTR [rip+0x6fe2]        # 14000a210 <__imp___getmainargs>
   14000322e:	90                   	nop
   14000322f:	90                   	nop

0000000140003230 <__iob_func>:
   140003230:	ff 25 ea 6f 00 00    	jmp    QWORD PTR [rip+0x6fea]        # 14000a220 <__imp___iob_func>
   140003236:	90                   	nop
   140003237:	90                   	nop

0000000140003238 <__set_app_type>:
   140003238:	ff 25 ea 6f 00 00    	jmp    QWORD PTR [rip+0x6fea]        # 14000a228 <__imp___set_app_type>
   14000323e:	90                   	nop
   14000323f:	90                   	nop

0000000140003240 <__setusermatherr>:
   140003240:	ff 25 ea 6f 00 00    	jmp    QWORD PTR [rip+0x6fea]        # 14000a230 <__imp___setusermatherr>
   140003246:	90                   	nop
   140003247:	90                   	nop

0000000140003248 <_amsg_exit>:
   140003248:	ff 25 ea 6f 00 00    	jmp    QWORD PTR [rip+0x6fea]        # 14000a238 <__imp__amsg_exit>
   14000324e:	90                   	nop
   14000324f:	90                   	nop

0000000140003250 <_cexit>:
   140003250:	ff 25 ea 6f 00 00    	jmp    QWORD PTR [rip+0x6fea]        # 14000a240 <__imp__cexit>
   140003256:	90                   	nop
   140003257:	90                   	nop

0000000140003258 <_initterm>:
   140003258:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a258 <__imp__initterm>
   14000325e:	90                   	nop
   14000325f:	90                   	nop

0000000140003260 <_crt_atexit>:
   140003260:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a260 <__imp__crt_atexit>
   140003266:	90                   	nop
   140003267:	90                   	nop

0000000140003268 <abort>:
   140003268:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a268 <__imp_abort>
   14000326e:	90                   	nop
   14000326f:	90                   	nop

0000000140003270 <calloc>:
   140003270:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a270 <__imp_calloc>
   140003276:	90                   	nop
   140003277:	90                   	nop

0000000140003278 <exit>:
   140003278:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a278 <__imp_exit>
   14000327e:	90                   	nop
   14000327f:	90                   	nop

0000000140003280 <fflush>:
   140003280:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a280 <__imp_fflush>
   140003286:	90                   	nop
   140003287:	90                   	nop

0000000140003288 <fprintf>:
   140003288:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a288 <__imp_fprintf>
   14000328e:	90                   	nop
   14000328f:	90                   	nop

0000000140003290 <free>:
   140003290:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a290 <__imp_free>
   140003296:	90                   	nop
   140003297:	90                   	nop

0000000140003298 <malloc>:
   140003298:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a298 <__imp_malloc>
   14000329e:	90                   	nop
   14000329f:	90                   	nop

00000001400032a0 <memcpy>:
   1400032a0:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a2a0 <__imp_memcpy>
   1400032a6:	90                   	nop
   1400032a7:	90                   	nop

00000001400032a8 <setvbuf>:
   1400032a8:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a2a8 <__imp_setvbuf>
   1400032ae:	90                   	nop
   1400032af:	90                   	nop

00000001400032b0 <signal>:
   1400032b0:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a2b0 <__imp_signal>
   1400032b6:	90                   	nop
   1400032b7:	90                   	nop

00000001400032b8 <strcpy>:
   1400032b8:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a2b8 <__imp_strcpy>
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <strlen>:
   1400032c0:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a2c0 <__imp_strlen>
   1400032c6:	90                   	nop
   1400032c7:	90                   	nop

00000001400032c8 <strncmp>:
   1400032c8:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a2c8 <__imp_strncmp>
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <vfprintf>:
   1400032d0:	ff 25 fa 6f 00 00    	jmp    QWORD PTR [rip+0x6ffa]        # 14000a2d0 <__imp_vfprintf>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop
   1400032d8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   1400032df:	00 

00000001400032e0 <VirtualQuery>:
   1400032e0:	ff 25 12 6f 00 00    	jmp    QWORD PTR [rip+0x6f12]        # 14000a1f8 <__imp_VirtualQuery>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <VirtualProtect>:
   1400032e8:	ff 25 02 6f 00 00    	jmp    QWORD PTR [rip+0x6f02]        # 14000a1f0 <__imp_VirtualProtect>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <TlsGetValue>:
   1400032f0:	ff 25 f2 6e 00 00    	jmp    QWORD PTR [rip+0x6ef2]        # 14000a1e8 <__imp_TlsGetValue>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <Sleep>:
   1400032f8:	ff 25 e2 6e 00 00    	jmp    QWORD PTR [rip+0x6ee2]        # 14000a1e0 <__imp_Sleep>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <SetUnhandledExceptionFilter>:
   140003300:	ff 25 d2 6e 00 00    	jmp    QWORD PTR [rip+0x6ed2]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <LoadLibraryA>:
   140003308:	ff 25 c2 6e 00 00    	jmp    QWORD PTR [rip+0x6ec2]        # 14000a1d0 <__imp_LoadLibraryA>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <LeaveCriticalSection>:
   140003310:	ff 25 b2 6e 00 00    	jmp    QWORD PTR [rip+0x6eb2]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <InitializeCriticalSection>:
   140003318:	ff 25 a2 6e 00 00    	jmp    QWORD PTR [rip+0x6ea2]        # 14000a1c0 <__imp_InitializeCriticalSection>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <GetProcAddress>:
   140003320:	ff 25 92 6e 00 00    	jmp    QWORD PTR [rip+0x6e92]        # 14000a1b8 <__imp_GetProcAddress>
   140003326:	90                   	nop
   140003327:	90                   	nop

0000000140003328 <GetModuleHandleA>:
   140003328:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a1b0 <__imp_GetModuleHandleA>
   14000332e:	90                   	nop
   14000332f:	90                   	nop

0000000140003330 <GetLastError>:
   140003330:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a1a8 <__imp_GetLastError>
   140003336:	90                   	nop
   140003337:	90                   	nop

0000000140003338 <FreeLibrary>:
   140003338:	ff 25 62 6e 00 00    	jmp    QWORD PTR [rip+0x6e62]        # 14000a1a0 <__imp_FreeLibrary>
   14000333e:	90                   	nop
   14000333f:	90                   	nop

0000000140003340 <EnterCriticalSection>:
   140003340:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 14000a198 <__imp_EnterCriticalSection>
   140003346:	90                   	nop
   140003347:	90                   	nop

0000000140003348 <DeleteCriticalSection>:
   140003348:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 14000a190 <__IAT_start__>
   14000334e:	90                   	nop
   14000334f:	90                   	nop

0000000140003350 <register_frame_ctor>:
   140003350:	e9 1b e3 ff ff       	jmp    140001670 <__gcc_register_frame>
   140003355:	90                   	nop
   140003356:	90                   	nop
   140003357:	90                   	nop
   140003358:	90                   	nop
   140003359:	90                   	nop
   14000335a:	90                   	nop
   14000335b:	90                   	nop
   14000335c:	90                   	nop
   14000335d:	90                   	nop
   14000335e:	90                   	nop
   14000335f:	90                   	nop
