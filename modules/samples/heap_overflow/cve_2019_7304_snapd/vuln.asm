
C:\Users\Administrator\Desktop\BinMind\deemo\modules\samples\heap_overflow\cve_2019_7304_snapd\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 07 23 00 00       	call   140003330 <fflush>
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
   14000113b:	e8 b8 21 00 00       	call   1400032f8 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 38 21 00 00       	call   1400032a0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 df 21 00 00       	call   140003360 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 7f 21 00 00       	call   140003318 <abort>
   140001199:	e8 02 12 00 00       	call   1400023a0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 29 90 00 00 	mov    rax,QWORD PTR [rip+0x9029]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 76 20 00 00       	call   140003240 <_set_invalid_parameter_handler>
   1400011ca:	e8 e1 1a 00 00       	call   140002cb0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 f7 20 00 00       	call   1400032e8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 eb 20 00 00       	call   1400032e8 <__set_app_type>
   1400011fd:	e8 0e 20 00 00       	call   140003210 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 0e 20 00 00       	call   140003220 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 5e 07 00 00       	call   140001980 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 c3 20 00 00       	call   1400032f8 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 68 12 00 00       	call   1400024ba <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 16 20 00 00       	call   140003280 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 30 1f 00 00       	call   1400031b0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 6a 20 00 00       	call   1400032f8 <_amsg_exit>
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
   1400012cb:	e8 08 20 00 00       	call   1400032d8 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 15 20 00 00       	call   1400032f8 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 ee 1f 00 00       	call   1400032f8 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 e8 1f 00 00       	call   140003308 <_initterm>
   140001320:	e8 32 06 00 00       	call   140001957 <__main>
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
   14000138d:	e8 9e 1e 00 00       	call   140003230 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 5d 04 00 00       	call   140001817 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 57 1f 00 00       	call   140003328 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 20 1f 00 00       	call   140003300 <_cexit>
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
   140001511:	e8 32 1e 00 00       	call   140003348 <malloc>
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
   14000155c:	e8 0f 1e 00 00       	call   140003370 <strlen>
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
   140001585:	e8 be 1d 00 00       	call   140003348 <malloc>
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
   1400015e8:	e8 63 1d 00 00       	call   140003350 <memcpy>
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
   140001642:	e8 c9 1c 00 00       	call   140003310 <_crt_atexit>
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

0000000140001760 <join_path>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 40          	sub    rsp,0x40
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001770:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001774:	48 89 c1             	mov    rcx,rax
   140001777:	e8 f4 1b 00 00       	call   140003370 <strlen>
   14000177c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001780:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001784:	48 89 c1             	mov    rcx,rax
   140001787:	e8 e4 1b 00 00       	call   140003370 <strlen>
   14000178c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001790:	b9 30 00 00 00       	mov    ecx,0x30
   140001795:	e8 ae 1b 00 00       	call   140003348 <malloc>
   14000179a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000179e:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   1400017a3:	75 07                	jne    1400017ac <join_path+0x4c>
   1400017a5:	b8 00 00 00 00       	mov    eax,0x0
   1400017aa:	eb 65                	jmp    140001811 <join_path+0xb1>
   1400017ac:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
   1400017b0:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400017b4:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400017b8:	49 89 c8             	mov    r8,rcx
   1400017bb:	48 89 c1             	mov    rcx,rax
   1400017be:	e8 8d 1b 00 00       	call   140003350 <memcpy>
   1400017c3:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400017c7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017cb:	48 01 d0             	add    rax,rdx
   1400017ce:	c6 00 2f             	mov    BYTE PTR [rax],0x2f
   1400017d1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017d5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400017d9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400017dd:	48 8d 0c 02          	lea    rcx,[rdx+rax*1]
   1400017e1:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400017e5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400017e9:	49 89 d0             	mov    r8,rdx
   1400017ec:	48 89 c2             	mov    rdx,rax
   1400017ef:	e8 5c 1b 00 00       	call   140003350 <memcpy>
   1400017f4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400017f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017fc:	48 01 d0             	add    rax,rdx
   1400017ff:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140001803:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001807:	48 01 d0             	add    rax,rdx
   14000180a:	c6 00 00             	mov    BYTE PTR [rax],0x0
   14000180d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001811:	48 83 c4 40          	add    rsp,0x40
   140001815:	5d                   	pop    rbp
   140001816:	c3                   	ret

0000000140001817 <main>:
   140001817:	55                   	push   rbp
   140001818:	48 89 e5             	mov    rbp,rsp
   14000181b:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140001822:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140001825:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001829:	e8 29 01 00 00       	call   140001957 <__main>
   14000182e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140001832:	41 b8 1e 00 00 00    	mov    r8d,0x1e
   140001838:	ba 42 00 00 00       	mov    edx,0x42
   14000183d:	48 89 c1             	mov    rcx,rax
   140001840:	e8 13 1b 00 00       	call   140003358 <memset>
   140001845:	c6 45 ee 00          	mov    BYTE PTR [rbp-0x12],0x0
   140001849:	48 8d 45 90          	lea    rax,[rbp-0x70]
   14000184d:	41 b8 28 00 00 00    	mov    r8d,0x28
   140001853:	ba 52 00 00 00       	mov    edx,0x52
   140001858:	48 89 c1             	mov    rcx,rax
   14000185b:	e8 f8 1a 00 00       	call   140003358 <memset>
   140001860:	c6 45 b8 00          	mov    BYTE PTR [rbp-0x48],0x0
   140001864:	48 8d 55 90          	lea    rdx,[rbp-0x70]
   140001868:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000186c:	48 89 c1             	mov    rcx,rax
   14000186f:	e8 ec fe ff ff       	call   140001760 <join_path>
   140001874:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001878:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000187d:	74 0c                	je     14000188b <main+0x74>
   14000187f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001883:	48 89 c1             	mov    rcx,rax
   140001886:	e8 b5 1a 00 00       	call   140003340 <free>
   14000188b:	b8 00 00 00 00       	mov    eax,0x0
   140001890:	48 81 c4 90 00 00 00 	add    rsp,0x90
   140001897:	5d                   	pop    rbp
   140001898:	c3                   	ret
   140001899:	90                   	nop
   14000189a:	90                   	nop
   14000189b:	90                   	nop
   14000189c:	90                   	nop
   14000189d:	90                   	nop
   14000189e:	90                   	nop
   14000189f:	90                   	nop

00000001400018a0 <__do_global_dtors>:
   1400018a0:	55                   	push   rbp
   1400018a1:	48 89 e5             	mov    rbp,rsp
   1400018a4:	48 83 ec 20          	sub    rsp,0x20
   1400018a8:	eb 1e                	jmp    1400018c8 <__do_global_dtors+0x28>
   1400018aa:	48 8b 05 5f 27 00 00 	mov    rax,QWORD PTR [rip+0x275f]        # 140004010 <p.0>
   1400018b1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018b4:	ff d0                	call   rax
   1400018b6:	48 8b 05 53 27 00 00 	mov    rax,QWORD PTR [rip+0x2753]        # 140004010 <p.0>
   1400018bd:	48 83 c0 08          	add    rax,0x8
   1400018c1:	48 89 05 48 27 00 00 	mov    QWORD PTR [rip+0x2748],rax        # 140004010 <p.0>
   1400018c8:	48 8b 05 41 27 00 00 	mov    rax,QWORD PTR [rip+0x2741]        # 140004010 <p.0>
   1400018cf:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018d2:	48 85 c0             	test   rax,rax
   1400018d5:	75 d3                	jne    1400018aa <__do_global_dtors+0xa>
   1400018d7:	90                   	nop
   1400018d8:	90                   	nop
   1400018d9:	48 83 c4 20          	add    rsp,0x20
   1400018dd:	5d                   	pop    rbp
   1400018de:	c3                   	ret

00000001400018df <__do_global_ctors>:
   1400018df:	55                   	push   rbp
   1400018e0:	48 89 e5             	mov    rbp,rsp
   1400018e3:	48 83 ec 30          	sub    rsp,0x30
   1400018e7:	48 8b 05 62 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a62]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018ee:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018f1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400018f4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400018f8:	75 25                	jne    14000191f <__do_global_ctors+0x40>
   1400018fa:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001901:	eb 04                	jmp    140001907 <__do_global_ctors+0x28>
   140001903:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001907:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000190a:	8d 50 01             	lea    edx,[rax+0x1]
   14000190d:	48 8b 05 3c 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a3c]        # 140005350 <.refptr.__CTOR_LIST__>
   140001914:	89 d2                	mov    edx,edx
   140001916:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000191a:	48 85 c0             	test   rax,rax
   14000191d:	75 e4                	jne    140001903 <__do_global_ctors+0x24>
   14000191f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001922:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001925:	eb 14                	jmp    14000193b <__do_global_ctors+0x5c>
   140001927:	48 8b 05 22 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a22]        # 140005350 <.refptr.__CTOR_LIST__>
   14000192e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001931:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001935:	ff d0                	call   rax
   140001937:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000193b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000193f:	75 e6                	jne    140001927 <__do_global_ctors+0x48>
   140001941:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400018a0 <__do_global_dtors>
   140001948:	48 89 c1             	mov    rcx,rax
   14000194b:	e8 df fc ff ff       	call   14000162f <atexit>
   140001950:	90                   	nop
   140001951:	48 83 c4 30          	add    rsp,0x30
   140001955:	5d                   	pop    rbp
   140001956:	c3                   	ret

0000000140001957 <__main>:
   140001957:	55                   	push   rbp
   140001958:	48 89 e5             	mov    rbp,rsp
   14000195b:	48 83 ec 20          	sub    rsp,0x20
   14000195f:	8b 05 1b 77 00 00    	mov    eax,DWORD PTR [rip+0x771b]        # 140009080 <initialized>
   140001965:	85 c0                	test   eax,eax
   140001967:	75 0f                	jne    140001978 <__main+0x21>
   140001969:	c7 05 0d 77 00 00 01 	mov    DWORD PTR [rip+0x770d],0x1        # 140009080 <initialized>
   140001970:	00 00 00 
   140001973:	e8 67 ff ff ff       	call   1400018df <__do_global_ctors>
   140001978:	90                   	nop
   140001979:	48 83 c4 20          	add    rsp,0x20
   14000197d:	5d                   	pop    rbp
   14000197e:	c3                   	ret
   14000197f:	90                   	nop

0000000140001980 <_setargv>:
   140001980:	55                   	push   rbp
   140001981:	48 89 e5             	mov    rbp,rsp
   140001984:	b8 00 00 00 00       	mov    eax,0x0
   140001989:	5d                   	pop    rbp
   14000198a:	c3                   	ret
   14000198b:	90                   	nop
   14000198c:	90                   	nop
   14000198d:	90                   	nop
   14000198e:	90                   	nop
   14000198f:	90                   	nop

0000000140001990 <__dyn_tls_init>:
   140001990:	55                   	push   rbp
   140001991:	48 89 e5             	mov    rbp,rsp
   140001994:	48 83 ec 30          	sub    rsp,0x30
   140001998:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000199c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000199f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019a3:	48 8b 05 86 39 00 00 	mov    rax,QWORD PTR [rip+0x3986]        # 140005330 <.refptr._CRT_MT>
   1400019aa:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019ac:	83 f8 02             	cmp    eax,0x2
   1400019af:	74 0d                	je     1400019be <__dyn_tls_init+0x2e>
   1400019b1:	48 8b 05 78 39 00 00 	mov    rax,QWORD PTR [rip+0x3978]        # 140005330 <.refptr._CRT_MT>
   1400019b8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400019be:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   1400019c2:	74 1e                	je     1400019e2 <__dyn_tls_init+0x52>
   1400019c4:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   1400019c8:	75 5b                	jne    140001a25 <__dyn_tls_init+0x95>
   1400019ca:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019ce:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019d1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019d5:	49 89 c8             	mov    r8,rcx
   1400019d8:	48 89 c1             	mov    rcx,rax
   1400019db:	e8 d1 11 00 00       	call   140002bb1 <__mingw_TLScallback>
   1400019e0:	eb 43                	jmp    140001a25 <__dyn_tls_init+0x95>
   1400019e2:	48 8d 05 af 3c 00 00 	lea    rax,[rip+0x3caf]        # 140005698 <___crt_xd_start__>
   1400019e9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400019ed:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019f2:	eb 22                	jmp    140001a16 <__dyn_tls_init+0x86>
   1400019f4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400019f8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400019fc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001a00:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a03:	48 85 c0             	test   rax,rax
   140001a06:	74 09                	je     140001a11 <__dyn_tls_init+0x81>
   140001a08:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001a0c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a0f:	ff d0                	call   rax
   140001a11:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001a16:	48 8d 05 83 3c 00 00 	lea    rax,[rip+0x3c83]        # 1400056a0 <__xd_z>
   140001a1d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001a21:	75 d1                	jne    1400019f4 <__dyn_tls_init+0x64>
   140001a23:	eb 01                	jmp    140001a26 <__dyn_tls_init+0x96>
   140001a25:	90                   	nop
   140001a26:	48 83 c4 30          	add    rsp,0x30
   140001a2a:	5d                   	pop    rbp
   140001a2b:	c3                   	ret

0000000140001a2c <__tlregdtor>:
   140001a2c:	55                   	push   rbp
   140001a2d:	48 89 e5             	mov    rbp,rsp
   140001a30:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a34:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001a39:	75 07                	jne    140001a42 <__tlregdtor+0x16>
   140001a3b:	b8 00 00 00 00       	mov    eax,0x0
   140001a40:	eb 05                	jmp    140001a47 <__tlregdtor+0x1b>
   140001a42:	b8 00 00 00 00       	mov    eax,0x0
   140001a47:	5d                   	pop    rbp
   140001a48:	c3                   	ret

0000000140001a49 <__dyn_tls_dtor>:
   140001a49:	55                   	push   rbp
   140001a4a:	48 89 e5             	mov    rbp,rsp
   140001a4d:	48 83 ec 20          	sub    rsp,0x20
   140001a51:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a55:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a58:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a5c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a60:	74 06                	je     140001a68 <__dyn_tls_dtor+0x1f>
   140001a62:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a66:	75 18                	jne    140001a80 <__dyn_tls_dtor+0x37>
   140001a68:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a6c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a6f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a73:	49 89 c8             	mov    r8,rcx
   140001a76:	48 89 c1             	mov    rcx,rax
   140001a79:	e8 33 11 00 00       	call   140002bb1 <__mingw_TLScallback>
   140001a7e:	eb 01                	jmp    140001a81 <__dyn_tls_dtor+0x38>
   140001a80:	90                   	nop
   140001a81:	48 83 c4 20          	add    rsp,0x20
   140001a85:	5d                   	pop    rbp
   140001a86:	c3                   	ret
   140001a87:	90                   	nop
   140001a88:	90                   	nop
   140001a89:	90                   	nop
   140001a8a:	90                   	nop
   140001a8b:	90                   	nop
   140001a8c:	90                   	nop
   140001a8d:	90                   	nop
   140001a8e:	90                   	nop
   140001a8f:	90                   	nop

0000000140001a90 <_matherr>:
   140001a90:	55                   	push   rbp
   140001a91:	53                   	push   rbx
   140001a92:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a99:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a9e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001aa2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001aa6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001aab:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001aaf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ab3:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ab5:	83 f8 06             	cmp    eax,0x6
   140001ab8:	74 56                	je     140001b10 <_matherr+0x80>
   140001aba:	83 f8 06             	cmp    eax,0x6
   140001abd:	7f 78                	jg     140001b37 <_matherr+0xa7>
   140001abf:	83 f8 05             	cmp    eax,0x5
   140001ac2:	74 59                	je     140001b1d <_matherr+0x8d>
   140001ac4:	83 f8 05             	cmp    eax,0x5
   140001ac7:	7f 6e                	jg     140001b37 <_matherr+0xa7>
   140001ac9:	83 f8 04             	cmp    eax,0x4
   140001acc:	74 5c                	je     140001b2a <_matherr+0x9a>
   140001ace:	83 f8 04             	cmp    eax,0x4
   140001ad1:	7f 64                	jg     140001b37 <_matherr+0xa7>
   140001ad3:	83 f8 03             	cmp    eax,0x3
   140001ad6:	74 2b                	je     140001b03 <_matherr+0x73>
   140001ad8:	83 f8 03             	cmp    eax,0x3
   140001adb:	7f 5a                	jg     140001b37 <_matherr+0xa7>
   140001add:	83 f8 01             	cmp    eax,0x1
   140001ae0:	74 07                	je     140001ae9 <_matherr+0x59>
   140001ae2:	83 f8 02             	cmp    eax,0x2
   140001ae5:	74 0f                	je     140001af6 <_matherr+0x66>
   140001ae7:	eb 4e                	jmp    140001b37 <_matherr+0xa7>
   140001ae9:	48 8d 05 b0 35 00 00 	lea    rax,[rip+0x35b0]        # 1400050a0 <.rdata>
   140001af0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001af4:	eb 4d                	jmp    140001b43 <_matherr+0xb3>
   140001af6:	48 8d 05 c2 35 00 00 	lea    rax,[rip+0x35c2]        # 1400050bf <.rdata+0x1f>
   140001afd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b01:	eb 40                	jmp    140001b43 <_matherr+0xb3>
   140001b03:	48 8d 05 d6 35 00 00 	lea    rax,[rip+0x35d6]        # 1400050e0 <.rdata+0x40>
   140001b0a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b0e:	eb 33                	jmp    140001b43 <_matherr+0xb3>
   140001b10:	48 8d 05 e9 35 00 00 	lea    rax,[rip+0x35e9]        # 140005100 <.rdata+0x60>
   140001b17:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b1b:	eb 26                	jmp    140001b43 <_matherr+0xb3>
   140001b1d:	48 8d 05 04 36 00 00 	lea    rax,[rip+0x3604]        # 140005128 <.rdata+0x88>
   140001b24:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b28:	eb 19                	jmp    140001b43 <_matherr+0xb3>
   140001b2a:	48 8d 05 1f 36 00 00 	lea    rax,[rip+0x361f]        # 140005150 <.rdata+0xb0>
   140001b31:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b35:	eb 0c                	jmp    140001b43 <_matherr+0xb3>
   140001b37:	48 8d 05 48 36 00 00 	lea    rax,[rip+0x3648]        # 140005186 <.rdata+0xe6>
   140001b3e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b42:	90                   	nop
   140001b43:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b47:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b4d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b51:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b56:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b5a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b5f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b63:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b67:	b9 02 00 00 00       	mov    ecx,0x2
   140001b6c:	e8 2f 17 00 00       	call   1400032a0 <__acrt_iob_func>
   140001b71:	48 89 c1             	mov    rcx,rax
   140001b74:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b78:	48 8d 05 19 36 00 00 	lea    rax,[rip+0x3619]        # 140005198 <.rdata+0xf8>
   140001b7f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b86:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b8c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b92:	49 89 d9             	mov    r9,rbx
   140001b95:	49 89 d0             	mov    r8,rdx
   140001b98:	48 89 c2             	mov    rdx,rax
   140001b9b:	e8 98 17 00 00       	call   140003338 <fprintf>
   140001ba0:	b8 00 00 00 00       	mov    eax,0x0
   140001ba5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001ba9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001bad:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001bb2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001bb9:	5b                   	pop    rbx
   140001bba:	5d                   	pop    rbp
   140001bbb:	c3                   	ret
   140001bbc:	90                   	nop
   140001bbd:	90                   	nop
   140001bbe:	90                   	nop
   140001bbf:	90                   	nop

0000000140001bc0 <__report_error>:
   140001bc0:	55                   	push   rbp
   140001bc1:	53                   	push   rbx
   140001bc2:	48 83 ec 38          	sub    rsp,0x38
   140001bc6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001bcb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001bcf:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001bd3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001bd7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001bdb:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001bdf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001be3:	b9 02 00 00 00       	mov    ecx,0x2
   140001be8:	e8 b3 16 00 00       	call   1400032a0 <__acrt_iob_func>
   140001bed:	48 89 c1             	mov    rcx,rax
   140001bf0:	48 8d 05 d9 35 00 00 	lea    rax,[rip+0x35d9]        # 1400051d0 <.rdata>
   140001bf7:	48 89 c2             	mov    rdx,rax
   140001bfa:	e8 39 17 00 00       	call   140003338 <fprintf>
   140001bff:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001c03:	b9 02 00 00 00       	mov    ecx,0x2
   140001c08:	e8 93 16 00 00       	call   1400032a0 <__acrt_iob_func>
   140001c0d:	48 89 c1             	mov    rcx,rax
   140001c10:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001c14:	49 89 d8             	mov    r8,rbx
   140001c17:	48 89 c2             	mov    rdx,rax
   140001c1a:	e8 61 17 00 00       	call   140003380 <vfprintf>
   140001c1f:	e8 f4 16 00 00       	call   140003318 <abort>
   140001c24:	90                   	nop

0000000140001c25 <mark_section_writable>:
   140001c25:	55                   	push   rbp
   140001c26:	48 89 e5             	mov    rbp,rsp
   140001c29:	48 83 ec 60          	sub    rsp,0x60
   140001c2d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001c31:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001c38:	e9 82 00 00 00       	jmp    140001cbf <mark_section_writable+0x9a>
   140001c3d:	48 8b 0d 9c 74 00 00 	mov    rcx,QWORD PTR [rip+0x749c]        # 1400090e0 <the_secs>
   140001c44:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c47:	48 63 d0             	movsxd rdx,eax
   140001c4a:	48 89 d0             	mov    rax,rdx
   140001c4d:	48 c1 e0 02          	shl    rax,0x2
   140001c51:	48 01 d0             	add    rax,rdx
   140001c54:	48 c1 e0 03          	shl    rax,0x3
   140001c58:	48 01 c8             	add    rax,rcx
   140001c5b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c5f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c63:	72 56                	jb     140001cbb <mark_section_writable+0x96>
   140001c65:	48 8b 0d 74 74 00 00 	mov    rcx,QWORD PTR [rip+0x7474]        # 1400090e0 <the_secs>
   140001c6c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c6f:	48 63 d0             	movsxd rdx,eax
   140001c72:	48 89 d0             	mov    rax,rdx
   140001c75:	48 c1 e0 02          	shl    rax,0x2
   140001c79:	48 01 d0             	add    rax,rdx
   140001c7c:	48 c1 e0 03          	shl    rax,0x3
   140001c80:	48 01 c8             	add    rax,rcx
   140001c83:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c87:	4c 8b 05 52 74 00 00 	mov    r8,QWORD PTR [rip+0x7452]        # 1400090e0 <the_secs>
   140001c8e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c91:	48 63 d0             	movsxd rdx,eax
   140001c94:	48 89 d0             	mov    rax,rdx
   140001c97:	48 c1 e0 02          	shl    rax,0x2
   140001c9b:	48 01 d0             	add    rax,rdx
   140001c9e:	48 c1 e0 03          	shl    rax,0x3
   140001ca2:	4c 01 c0             	add    rax,r8
   140001ca5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001ca9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001cac:	89 c0                	mov    eax,eax
   140001cae:	48 01 c8             	add    rax,rcx
   140001cb1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001cb5:	0f 82 41 02 00 00    	jb     140001efc <mark_section_writable+0x2d7>
   140001cbb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001cbf:	8b 05 23 74 00 00    	mov    eax,DWORD PTR [rip+0x7423]        # 1400090e8 <maxSections>
   140001cc5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001cc8:	0f 8c 6f ff ff ff    	jl     140001c3d <mark_section_writable+0x18>
   140001cce:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001cd2:	48 89 c1             	mov    rcx,rax
   140001cd5:	e8 c1 11 00 00       	call   140002e9b <__mingw_GetSectionForAddress>
   140001cda:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001cde:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001ce3:	75 13                	jne    140001cf8 <mark_section_writable+0xd3>
   140001ce5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001ce9:	48 8d 0d 00 35 00 00 	lea    rcx,[rip+0x3500]        # 1400051f0 <.rdata+0x20>
   140001cf0:	48 89 c2             	mov    rdx,rax
   140001cf3:	e8 c8 fe ff ff       	call   140001bc0 <__report_error>
   140001cf8:	48 8b 0d e1 73 00 00 	mov    rcx,QWORD PTR [rip+0x73e1]        # 1400090e0 <the_secs>
   140001cff:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d02:	48 63 d0             	movsxd rdx,eax
   140001d05:	48 89 d0             	mov    rax,rdx
   140001d08:	48 c1 e0 02          	shl    rax,0x2
   140001d0c:	48 01 d0             	add    rax,rdx
   140001d0f:	48 c1 e0 03          	shl    rax,0x3
   140001d13:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d17:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d1b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001d1f:	48 8b 0d ba 73 00 00 	mov    rcx,QWORD PTR [rip+0x73ba]        # 1400090e0 <the_secs>
   140001d26:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d29:	48 63 d0             	movsxd rdx,eax
   140001d2c:	48 89 d0             	mov    rax,rdx
   140001d2f:	48 c1 e0 02          	shl    rax,0x2
   140001d33:	48 01 d0             	add    rax,rdx
   140001d36:	48 c1 e0 03          	shl    rax,0x3
   140001d3a:	48 01 c8             	add    rax,rcx
   140001d3d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d43:	e8 9f 12 00 00       	call   140002fe7 <_GetPEImageBase>
   140001d48:	48 89 c1             	mov    rcx,rax
   140001d4b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d4f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d52:	41 89 c1             	mov    r9d,eax
   140001d55:	4c 8b 05 84 73 00 00 	mov    r8,QWORD PTR [rip+0x7384]        # 1400090e0 <the_secs>
   140001d5c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d5f:	48 63 d0             	movsxd rdx,eax
   140001d62:	48 89 d0             	mov    rax,rdx
   140001d65:	48 c1 e0 02          	shl    rax,0x2
   140001d69:	48 01 d0             	add    rax,rdx
   140001d6c:	48 c1 e0 03          	shl    rax,0x3
   140001d70:	4c 01 c0             	add    rax,r8
   140001d73:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d77:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d7b:	48 8b 0d 5e 73 00 00 	mov    rcx,QWORD PTR [rip+0x735e]        # 1400090e0 <the_secs>
   140001d82:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d85:	48 63 d0             	movsxd rdx,eax
   140001d88:	48 89 d0             	mov    rax,rdx
   140001d8b:	48 c1 e0 02          	shl    rax,0x2
   140001d8f:	48 01 d0             	add    rax,rdx
   140001d92:	48 c1 e0 03          	shl    rax,0x3
   140001d96:	48 01 c8             	add    rax,rcx
   140001d99:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d9d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001da1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001da7:	48 89 c1             	mov    rcx,rax
   140001daa:	48 8b 05 47 84 00 00 	mov    rax,QWORD PTR [rip+0x8447]        # 14000a1f8 <__imp_VirtualQuery>
   140001db1:	ff d0                	call   rax
   140001db3:	48 85 c0             	test   rax,rax
   140001db6:	75 3f                	jne    140001df7 <mark_section_writable+0x1d2>
   140001db8:	48 8b 0d 21 73 00 00 	mov    rcx,QWORD PTR [rip+0x7321]        # 1400090e0 <the_secs>
   140001dbf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dc2:	48 63 d0             	movsxd rdx,eax
   140001dc5:	48 89 d0             	mov    rax,rdx
   140001dc8:	48 c1 e0 02          	shl    rax,0x2
   140001dcc:	48 01 d0             	add    rax,rdx
   140001dcf:	48 c1 e0 03          	shl    rax,0x3
   140001dd3:	48 01 c8             	add    rax,rcx
   140001dd6:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001dda:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001dde:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001de1:	89 c1                	mov    ecx,eax
   140001de3:	48 8d 05 26 34 00 00 	lea    rax,[rip+0x3426]        # 140005210 <.rdata+0x40>
   140001dea:	49 89 d0             	mov    r8,rdx
   140001ded:	89 ca                	mov    edx,ecx
   140001def:	48 89 c1             	mov    rcx,rax
   140001df2:	e8 c9 fd ff ff       	call   140001bc0 <__report_error>
   140001df7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dfa:	83 f8 40             	cmp    eax,0x40
   140001dfd:	0f 84 e8 00 00 00    	je     140001eeb <mark_section_writable+0x2c6>
   140001e03:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e06:	83 f8 04             	cmp    eax,0x4
   140001e09:	0f 84 dc 00 00 00    	je     140001eeb <mark_section_writable+0x2c6>
   140001e0f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e12:	3d 80 00 00 00       	cmp    eax,0x80
   140001e17:	0f 84 ce 00 00 00    	je     140001eeb <mark_section_writable+0x2c6>
   140001e1d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e20:	83 f8 08             	cmp    eax,0x8
   140001e23:	0f 84 c2 00 00 00    	je     140001eeb <mark_section_writable+0x2c6>
   140001e29:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e2c:	83 f8 02             	cmp    eax,0x2
   140001e2f:	75 09                	jne    140001e3a <mark_section_writable+0x215>
   140001e31:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001e38:	eb 07                	jmp    140001e41 <mark_section_writable+0x21c>
   140001e3a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e41:	48 8b 0d 98 72 00 00 	mov    rcx,QWORD PTR [rip+0x7298]        # 1400090e0 <the_secs>
   140001e48:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e4b:	48 63 d0             	movsxd rdx,eax
   140001e4e:	48 89 d0             	mov    rax,rdx
   140001e51:	48 c1 e0 02          	shl    rax,0x2
   140001e55:	48 01 d0             	add    rax,rdx
   140001e58:	48 c1 e0 03          	shl    rax,0x3
   140001e5c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e60:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e64:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e68:	48 8b 0d 71 72 00 00 	mov    rcx,QWORD PTR [rip+0x7271]        # 1400090e0 <the_secs>
   140001e6f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e72:	48 63 d0             	movsxd rdx,eax
   140001e75:	48 89 d0             	mov    rax,rdx
   140001e78:	48 c1 e0 02          	shl    rax,0x2
   140001e7c:	48 01 d0             	add    rax,rdx
   140001e7f:	48 c1 e0 03          	shl    rax,0x3
   140001e83:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e87:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e8b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e8f:	48 8b 0d 4a 72 00 00 	mov    rcx,QWORD PTR [rip+0x724a]        # 1400090e0 <the_secs>
   140001e96:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e99:	48 63 d0             	movsxd rdx,eax
   140001e9c:	48 89 d0             	mov    rax,rdx
   140001e9f:	48 c1 e0 02          	shl    rax,0x2
   140001ea3:	48 01 d0             	add    rax,rdx
   140001ea6:	48 c1 e0 03          	shl    rax,0x3
   140001eaa:	48 01 c8             	add    rax,rcx
   140001ead:	49 89 c0             	mov    r8,rax
   140001eb0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001eb4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001eb8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001ebb:	4d 89 c1             	mov    r9,r8
   140001ebe:	41 89 c8             	mov    r8d,ecx
   140001ec1:	48 89 c1             	mov    rcx,rax
   140001ec4:	48 8b 05 25 83 00 00 	mov    rax,QWORD PTR [rip+0x8325]        # 14000a1f0 <__imp_VirtualProtect>
   140001ecb:	ff d0                	call   rax
   140001ecd:	85 c0                	test   eax,eax
   140001ecf:	75 1a                	jne    140001eeb <mark_section_writable+0x2c6>
   140001ed1:	48 8b 05 d0 82 00 00 	mov    rax,QWORD PTR [rip+0x82d0]        # 14000a1a8 <__imp_GetLastError>
   140001ed8:	ff d0                	call   rax
   140001eda:	89 c2                	mov    edx,eax
   140001edc:	48 8d 05 65 33 00 00 	lea    rax,[rip+0x3365]        # 140005248 <.rdata+0x78>
   140001ee3:	48 89 c1             	mov    rcx,rax
   140001ee6:	e8 d5 fc ff ff       	call   140001bc0 <__report_error>
   140001eeb:	8b 05 f7 71 00 00    	mov    eax,DWORD PTR [rip+0x71f7]        # 1400090e8 <maxSections>
   140001ef1:	83 c0 01             	add    eax,0x1
   140001ef4:	89 05 ee 71 00 00    	mov    DWORD PTR [rip+0x71ee],eax        # 1400090e8 <maxSections>
   140001efa:	eb 01                	jmp    140001efd <mark_section_writable+0x2d8>
   140001efc:	90                   	nop
   140001efd:	48 83 c4 60          	add    rsp,0x60
   140001f01:	5d                   	pop    rbp
   140001f02:	c3                   	ret

0000000140001f03 <restore_modified_sections>:
   140001f03:	55                   	push   rbp
   140001f04:	48 89 e5             	mov    rbp,rsp
   140001f07:	48 83 ec 30          	sub    rsp,0x30
   140001f0b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001f12:	e9 ad 00 00 00       	jmp    140001fc4 <restore_modified_sections+0xc1>
   140001f17:	48 8b 0d c2 71 00 00 	mov    rcx,QWORD PTR [rip+0x71c2]        # 1400090e0 <the_secs>
   140001f1e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f21:	48 63 d0             	movsxd rdx,eax
   140001f24:	48 89 d0             	mov    rax,rdx
   140001f27:	48 c1 e0 02          	shl    rax,0x2
   140001f2b:	48 01 d0             	add    rax,rdx
   140001f2e:	48 c1 e0 03          	shl    rax,0x3
   140001f32:	48 01 c8             	add    rax,rcx
   140001f35:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f37:	85 c0                	test   eax,eax
   140001f39:	0f 84 80 00 00 00    	je     140001fbf <restore_modified_sections+0xbc>
   140001f3f:	48 8b 0d 9a 71 00 00 	mov    rcx,QWORD PTR [rip+0x719a]        # 1400090e0 <the_secs>
   140001f46:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f49:	48 63 d0             	movsxd rdx,eax
   140001f4c:	48 89 d0             	mov    rax,rdx
   140001f4f:	48 c1 e0 02          	shl    rax,0x2
   140001f53:	48 01 d0             	add    rax,rdx
   140001f56:	48 c1 e0 03          	shl    rax,0x3
   140001f5a:	48 01 c8             	add    rax,rcx
   140001f5d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f60:	48 8b 0d 79 71 00 00 	mov    rcx,QWORD PTR [rip+0x7179]        # 1400090e0 <the_secs>
   140001f67:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f6a:	48 63 d0             	movsxd rdx,eax
   140001f6d:	48 89 d0             	mov    rax,rdx
   140001f70:	48 c1 e0 02          	shl    rax,0x2
   140001f74:	48 01 d0             	add    rax,rdx
   140001f77:	48 c1 e0 03          	shl    rax,0x3
   140001f7b:	48 01 c8             	add    rax,rcx
   140001f7e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f82:	4c 8b 05 57 71 00 00 	mov    r8,QWORD PTR [rip+0x7157]        # 1400090e0 <the_secs>
   140001f89:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f8c:	48 63 d0             	movsxd rdx,eax
   140001f8f:	48 89 d0             	mov    rax,rdx
   140001f92:	48 c1 e0 02          	shl    rax,0x2
   140001f96:	48 01 d0             	add    rax,rdx
   140001f99:	48 c1 e0 03          	shl    rax,0x3
   140001f9d:	4c 01 c0             	add    rax,r8
   140001fa0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001fa4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001fa8:	49 89 d1             	mov    r9,rdx
   140001fab:	45 89 d0             	mov    r8d,r10d
   140001fae:	48 89 ca             	mov    rdx,rcx
   140001fb1:	48 89 c1             	mov    rcx,rax
   140001fb4:	48 8b 05 35 82 00 00 	mov    rax,QWORD PTR [rip+0x8235]        # 14000a1f0 <__imp_VirtualProtect>
   140001fbb:	ff d0                	call   rax
   140001fbd:	eb 01                	jmp    140001fc0 <restore_modified_sections+0xbd>
   140001fbf:	90                   	nop
   140001fc0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001fc4:	8b 05 1e 71 00 00    	mov    eax,DWORD PTR [rip+0x711e]        # 1400090e8 <maxSections>
   140001fca:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001fcd:	0f 8c 44 ff ff ff    	jl     140001f17 <restore_modified_sections+0x14>
   140001fd3:	90                   	nop
   140001fd4:	90                   	nop
   140001fd5:	48 83 c4 30          	add    rsp,0x30
   140001fd9:	5d                   	pop    rbp
   140001fda:	c3                   	ret

0000000140001fdb <__write_memory>:
   140001fdb:	55                   	push   rbp
   140001fdc:	48 89 e5             	mov    rbp,rsp
   140001fdf:	48 83 ec 20          	sub    rsp,0x20
   140001fe3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fe7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001feb:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001fef:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001ff4:	74 25                	je     14000201b <__write_memory+0x40>
   140001ff6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001ffa:	48 89 c1             	mov    rcx,rax
   140001ffd:	e8 23 fc ff ff       	call   140001c25 <mark_section_writable>
   140002002:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140002006:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000200a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000200e:	49 89 c8             	mov    r8,rcx
   140002011:	48 89 c1             	mov    rcx,rax
   140002014:	e8 37 13 00 00       	call   140003350 <memcpy>
   140002019:	eb 01                	jmp    14000201c <__write_memory+0x41>
   14000201b:	90                   	nop
   14000201c:	48 83 c4 20          	add    rsp,0x20
   140002020:	5d                   	pop    rbp
   140002021:	c3                   	ret

0000000140002022 <do_pseudo_reloc>:
   140002022:	55                   	push   rbp
   140002023:	48 89 e5             	mov    rbp,rsp
   140002026:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   14000202a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000202e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002032:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002036:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000203a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000203e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002042:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002046:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000204a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000204f:	0f 8e 44 03 00 00    	jle    140002399 <do_pseudo_reloc+0x377>
   140002055:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000205a:	7e 25                	jle    140002081 <do_pseudo_reloc+0x5f>
   14000205c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002060:	8b 00                	mov    eax,DWORD PTR [rax]
   140002062:	85 c0                	test   eax,eax
   140002064:	75 1b                	jne    140002081 <do_pseudo_reloc+0x5f>
   140002066:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000206a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000206d:	85 c0                	test   eax,eax
   14000206f:	75 10                	jne    140002081 <do_pseudo_reloc+0x5f>
   140002071:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002075:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002078:	85 c0                	test   eax,eax
   14000207a:	75 05                	jne    140002081 <do_pseudo_reloc+0x5f>
   14000207c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002081:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002085:	8b 00                	mov    eax,DWORD PTR [rax]
   140002087:	85 c0                	test   eax,eax
   140002089:	75 0b                	jne    140002096 <do_pseudo_reloc+0x74>
   14000208b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000208f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002092:	85 c0                	test   eax,eax
   140002094:	74 59                	je     1400020ef <do_pseudo_reloc+0xcd>
   140002096:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000209a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000209e:	eb 40                	jmp    1400020e0 <do_pseudo_reloc+0xbe>
   1400020a0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020a4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020a7:	89 c2                	mov    edx,eax
   1400020a9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020ad:	48 01 d0             	add    rax,rdx
   1400020b0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020b4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020b8:	8b 10                	mov    edx,DWORD PTR [rax]
   1400020ba:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020be:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020c0:	01 d0                	add    eax,edx
   1400020c2:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   1400020c5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020c9:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   1400020cd:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400020d3:	48 89 c1             	mov    rcx,rax
   1400020d6:	e8 00 ff ff ff       	call   140001fdb <__write_memory>
   1400020db:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   1400020e0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020e4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400020e8:	72 b6                	jb     1400020a0 <do_pseudo_reloc+0x7e>
   1400020ea:	e9 ab 02 00 00       	jmp    14000239a <do_pseudo_reloc+0x378>
   1400020ef:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020f3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020f6:	83 f8 01             	cmp    eax,0x1
   1400020f9:	74 18                	je     140002113 <do_pseudo_reloc+0xf1>
   1400020fb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020ff:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002102:	89 c2                	mov    edx,eax
   140002104:	48 8d 05 65 31 00 00 	lea    rax,[rip+0x3165]        # 140005270 <.rdata+0xa0>
   14000210b:	48 89 c1             	mov    rcx,rax
   14000210e:	e8 ad fa ff ff       	call   140001bc0 <__report_error>
   140002113:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002117:	48 83 c0 0c          	add    rax,0xc
   14000211b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000211f:	e9 65 02 00 00       	jmp    140002389 <do_pseudo_reloc+0x367>
   140002124:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002128:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000212b:	89 c2                	mov    edx,eax
   14000212d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002131:	48 01 d0             	add    rax,rdx
   140002134:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002138:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000213c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000213e:	89 c2                	mov    edx,eax
   140002140:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002144:	48 01 d0             	add    rax,rdx
   140002147:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000214b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000214f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002152:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002156:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000215a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000215d:	0f b6 c0             	movzx  eax,al
   140002160:	83 f8 40             	cmp    eax,0x40
   140002163:	0f 84 b6 00 00 00    	je     14000221f <do_pseudo_reloc+0x1fd>
   140002169:	83 f8 40             	cmp    eax,0x40
   14000216c:	0f 87 ba 00 00 00    	ja     14000222c <do_pseudo_reloc+0x20a>
   140002172:	83 f8 20             	cmp    eax,0x20
   140002175:	74 77                	je     1400021ee <do_pseudo_reloc+0x1cc>
   140002177:	83 f8 20             	cmp    eax,0x20
   14000217a:	0f 87 ac 00 00 00    	ja     14000222c <do_pseudo_reloc+0x20a>
   140002180:	83 f8 08             	cmp    eax,0x8
   140002183:	74 0a                	je     14000218f <do_pseudo_reloc+0x16d>
   140002185:	83 f8 10             	cmp    eax,0x10
   140002188:	74 38                	je     1400021c2 <do_pseudo_reloc+0x1a0>
   14000218a:	e9 9d 00 00 00       	jmp    14000222c <do_pseudo_reloc+0x20a>
   14000218f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002193:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002196:	0f b6 c0             	movzx  eax,al
   140002199:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000219d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021a1:	25 80 00 00 00       	and    eax,0x80
   1400021a6:	48 85 c0             	test   rax,rax
   1400021a9:	0f 84 9d 00 00 00    	je     14000224c <do_pseudo_reloc+0x22a>
   1400021af:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021b3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400021b9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021bd:	e9 8a 00 00 00       	jmp    14000224c <do_pseudo_reloc+0x22a>
   1400021c2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021c6:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400021c9:	0f b7 c0             	movzx  eax,ax
   1400021cc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021d0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021d4:	25 00 80 00 00       	and    eax,0x8000
   1400021d9:	48 85 c0             	test   rax,rax
   1400021dc:	74 71                	je     14000224f <do_pseudo_reloc+0x22d>
   1400021de:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021e2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400021e8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ec:	eb 61                	jmp    14000224f <do_pseudo_reloc+0x22d>
   1400021ee:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021f2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021f4:	89 c0                	mov    eax,eax
   1400021f6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021fa:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021fe:	25 00 00 00 80       	and    eax,0x80000000
   140002203:	48 85 c0             	test   rax,rax
   140002206:	74 4a                	je     140002252 <do_pseudo_reloc+0x230>
   140002208:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000220c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002213:	ff ff ff 
   140002216:	48 09 d0             	or     rax,rdx
   140002219:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000221d:	eb 33                	jmp    140002252 <do_pseudo_reloc+0x230>
   14000221f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002223:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002226:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000222a:	eb 27                	jmp    140002253 <do_pseudo_reloc+0x231>
   14000222c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002233:	00 
   140002234:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002238:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000223b:	0f b6 c0             	movzx  eax,al
   14000223e:	48 8d 0d 63 30 00 00 	lea    rcx,[rip+0x3063]        # 1400052a8 <.rdata+0xd8>
   140002245:	89 c2                	mov    edx,eax
   140002247:	e8 74 f9 ff ff       	call   140001bc0 <__report_error>
   14000224c:	90                   	nop
   14000224d:	eb 04                	jmp    140002253 <do_pseudo_reloc+0x231>
   14000224f:	90                   	nop
   140002250:	eb 01                	jmp    140002253 <do_pseudo_reloc+0x231>
   140002252:	90                   	nop
   140002253:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002257:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000225b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000225d:	89 c2                	mov    edx,eax
   14000225f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002263:	48 01 c2             	add    rdx,rax
   140002266:	48 89 c8             	mov    rax,rcx
   140002269:	48 29 d0             	sub    rax,rdx
   14000226c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002270:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002274:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002278:	48 01 d0             	add    rax,rdx
   14000227b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000227f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002283:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002286:	25 ff 00 00 00       	and    eax,0xff
   14000228b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000228e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002292:	77 67                	ja     1400022fb <do_pseudo_reloc+0x2d9>
   140002294:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002297:	ba 01 00 00 00       	mov    edx,0x1
   14000229c:	89 c1                	mov    ecx,eax
   14000229e:	48 d3 e2             	shl    rdx,cl
   1400022a1:	48 89 d0             	mov    rax,rdx
   1400022a4:	48 83 e8 01          	sub    rax,0x1
   1400022a8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400022ac:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022af:	83 e8 01             	sub    eax,0x1
   1400022b2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400022b9:	89 c1                	mov    ecx,eax
   1400022bb:	48 d3 e2             	shl    rdx,cl
   1400022be:	48 89 d0             	mov    rax,rdx
   1400022c1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400022c5:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022c9:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   1400022cd:	7c 0a                	jl     1400022d9 <do_pseudo_reloc+0x2b7>
   1400022cf:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022d3:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400022d7:	7e 22                	jle    1400022fb <do_pseudo_reloc+0x2d9>
   1400022d9:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400022dd:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400022e1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400022e5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022e8:	48 8d 0d e9 2f 00 00 	lea    rcx,[rip+0x2fe9]        # 1400052d8 <.rdata+0x108>
   1400022ef:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400022f4:	89 c2                	mov    edx,eax
   1400022f6:	e8 c5 f8 ff ff       	call   140001bc0 <__report_error>
   1400022fb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022ff:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002302:	0f b6 c0             	movzx  eax,al
   140002305:	83 f8 40             	cmp    eax,0x40
   140002308:	74 63                	je     14000236d <do_pseudo_reloc+0x34b>
   14000230a:	83 f8 40             	cmp    eax,0x40
   14000230d:	77 75                	ja     140002384 <do_pseudo_reloc+0x362>
   14000230f:	83 f8 20             	cmp    eax,0x20
   140002312:	74 41                	je     140002355 <do_pseudo_reloc+0x333>
   140002314:	83 f8 20             	cmp    eax,0x20
   140002317:	77 6b                	ja     140002384 <do_pseudo_reloc+0x362>
   140002319:	83 f8 08             	cmp    eax,0x8
   14000231c:	74 07                	je     140002325 <do_pseudo_reloc+0x303>
   14000231e:	83 f8 10             	cmp    eax,0x10
   140002321:	74 1a                	je     14000233d <do_pseudo_reloc+0x31b>
   140002323:	eb 5f                	jmp    140002384 <do_pseudo_reloc+0x362>
   140002325:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002329:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000232d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002333:	48 89 c1             	mov    rcx,rax
   140002336:	e8 a0 fc ff ff       	call   140001fdb <__write_memory>
   14000233b:	eb 47                	jmp    140002384 <do_pseudo_reloc+0x362>
   14000233d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002341:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002345:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000234b:	48 89 c1             	mov    rcx,rax
   14000234e:	e8 88 fc ff ff       	call   140001fdb <__write_memory>
   140002353:	eb 2f                	jmp    140002384 <do_pseudo_reloc+0x362>
   140002355:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002359:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000235d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002363:	48 89 c1             	mov    rcx,rax
   140002366:	e8 70 fc ff ff       	call   140001fdb <__write_memory>
   14000236b:	eb 17                	jmp    140002384 <do_pseudo_reloc+0x362>
   14000236d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002371:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002375:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000237b:	48 89 c1             	mov    rcx,rax
   14000237e:	e8 58 fc ff ff       	call   140001fdb <__write_memory>
   140002383:	90                   	nop
   140002384:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002389:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000238d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002391:	0f 82 8d fd ff ff    	jb     140002124 <do_pseudo_reloc+0x102>
   140002397:	eb 01                	jmp    14000239a <do_pseudo_reloc+0x378>
   140002399:	90                   	nop
   14000239a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000239e:	5d                   	pop    rbp
   14000239f:	c3                   	ret

00000001400023a0 <_pei386_runtime_relocator>:
   1400023a0:	55                   	push   rbp
   1400023a1:	48 89 e5             	mov    rbp,rsp
   1400023a4:	48 83 ec 30          	sub    rsp,0x30
   1400023a8:	8b 05 3e 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d3e]        # 1400090ec <was_init.0>
   1400023ae:	85 c0                	test   eax,eax
   1400023b0:	0f 85 88 00 00 00    	jne    14000243e <_pei386_runtime_relocator+0x9e>
   1400023b6:	8b 05 30 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d30]        # 1400090ec <was_init.0>
   1400023bc:	83 c0 01             	add    eax,0x1
   1400023bf:	89 05 27 6d 00 00    	mov    DWORD PTR [rip+0x6d27],eax        # 1400090ec <was_init.0>
   1400023c5:	e8 21 0b 00 00       	call   140002eeb <__mingw_GetSectionCount>
   1400023ca:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400023cd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400023d0:	48 63 d0             	movsxd rdx,eax
   1400023d3:	48 89 d0             	mov    rax,rdx
   1400023d6:	48 c1 e0 02          	shl    rax,0x2
   1400023da:	48 01 d0             	add    rax,rdx
   1400023dd:	48 c1 e0 03          	shl    rax,0x3
   1400023e1:	48 83 c0 0f          	add    rax,0xf
   1400023e5:	48 c1 e8 04          	shr    rax,0x4
   1400023e9:	48 c1 e0 04          	shl    rax,0x4
   1400023ed:	e8 7e 0d 00 00       	call   140003170 <___chkstk_ms>
   1400023f2:	48 29 c4             	sub    rsp,rax
   1400023f5:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400023fa:	48 83 c0 0f          	add    rax,0xf
   1400023fe:	48 c1 e8 04          	shr    rax,0x4
   140002402:	48 c1 e0 04          	shl    rax,0x4
   140002406:	48 89 05 d3 6c 00 00 	mov    QWORD PTR [rip+0x6cd3],rax        # 1400090e0 <the_secs>
   14000240d:	c7 05 d1 6c 00 00 00 	mov    DWORD PTR [rip+0x6cd1],0x0        # 1400090e8 <maxSections>
   140002414:	00 00 00 
   140002417:	48 8b 0d 42 2f 00 00 	mov    rcx,QWORD PTR [rip+0x2f42]        # 140005360 <.refptr.__ImageBase>
   14000241e:	48 8b 15 4b 2f 00 00 	mov    rdx,QWORD PTR [rip+0x2f4b]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002425:	48 8b 05 54 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f54]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000242c:	49 89 c8             	mov    r8,rcx
   14000242f:	48 89 c1             	mov    rcx,rax
   140002432:	e8 eb fb ff ff       	call   140002022 <do_pseudo_reloc>
   140002437:	e8 c7 fa ff ff       	call   140001f03 <restore_modified_sections>
   14000243c:	eb 01                	jmp    14000243f <_pei386_runtime_relocator+0x9f>
   14000243e:	90                   	nop
   14000243f:	48 89 ec             	mov    rsp,rbp
   140002442:	5d                   	pop    rbp
   140002443:	c3                   	ret
   140002444:	90                   	nop
   140002445:	90                   	nop
   140002446:	90                   	nop
   140002447:	90                   	nop
   140002448:	90                   	nop
   140002449:	90                   	nop
   14000244a:	90                   	nop
   14000244b:	90                   	nop
   14000244c:	90                   	nop
   14000244d:	90                   	nop
   14000244e:	90                   	nop
   14000244f:	90                   	nop

0000000140002450 <__mingw_raise_matherr>:
   140002450:	55                   	push   rbp
   140002451:	48 89 e5             	mov    rbp,rsp
   140002454:	48 83 ec 50          	sub    rsp,0x50
   140002458:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000245b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000245f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002464:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002469:	48 8b 05 80 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c80]        # 1400090f0 <stUserMathErr>
   140002470:	48 85 c0             	test   rax,rax
   140002473:	74 3e                	je     1400024b3 <__mingw_raise_matherr+0x63>
   140002475:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002478:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000247b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000247f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002483:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002488:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000248d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002492:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002497:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000249c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400024a1:	48 8b 15 48 6c 00 00 	mov    rdx,QWORD PTR [rip+0x6c48]        # 1400090f0 <stUserMathErr>
   1400024a8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400024ac:	48 89 c1             	mov    rcx,rax
   1400024af:	ff d2                	call   rdx
   1400024b1:	eb 01                	jmp    1400024b4 <__mingw_raise_matherr+0x64>
   1400024b3:	90                   	nop
   1400024b4:	48 83 c4 50          	add    rsp,0x50
   1400024b8:	5d                   	pop    rbp
   1400024b9:	c3                   	ret

00000001400024ba <__mingw_setusermatherr>:
   1400024ba:	55                   	push   rbp
   1400024bb:	48 89 e5             	mov    rbp,rsp
   1400024be:	48 83 ec 20          	sub    rsp,0x20
   1400024c2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024c6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024ca:	48 89 05 1f 6c 00 00 	mov    QWORD PTR [rip+0x6c1f],rax        # 1400090f0 <stUserMathErr>
   1400024d1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024d5:	48 89 c1             	mov    rcx,rax
   1400024d8:	e8 13 0e 00 00       	call   1400032f0 <__setusermatherr>
   1400024dd:	90                   	nop
   1400024de:	48 83 c4 20          	add    rsp,0x20
   1400024e2:	5d                   	pop    rbp
   1400024e3:	c3                   	ret
   1400024e4:	90                   	nop
   1400024e5:	90                   	nop
   1400024e6:	90                   	nop
   1400024e7:	90                   	nop
   1400024e8:	90                   	nop
   1400024e9:	90                   	nop
   1400024ea:	90                   	nop
   1400024eb:	90                   	nop
   1400024ec:	90                   	nop
   1400024ed:	90                   	nop
   1400024ee:	90                   	nop
   1400024ef:	90                   	nop

00000001400024f0 <__mingw_SEH_error_handler>:
   1400024f0:	55                   	push   rbp
   1400024f1:	48 89 e5             	mov    rbp,rsp
   1400024f4:	48 83 ec 30          	sub    rsp,0x30
   1400024f8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024fc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002500:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002504:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002508:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000250f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002516:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000251a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000251d:	83 e0 02             	and    eax,0x2
   140002520:	85 c0                	test   eax,eax
   140002522:	74 0a                	je     14000252e <__mingw_SEH_error_handler+0x3e>
   140002524:	b8 01 00 00 00       	mov    eax,0x1
   140002529:	e9 16 02 00 00       	jmp    140002744 <__mingw_SEH_error_handler+0x254>
   14000252e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002532:	8b 00                	mov    eax,DWORD PTR [rax]
   140002534:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002539:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000253e:	75 18                	jne    140002558 <__mingw_SEH_error_handler+0x68>
   140002540:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002544:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002547:	83 e0 01             	and    eax,0x1
   14000254a:	85 c0                	test   eax,eax
   14000254c:	75 0a                	jne    140002558 <__mingw_SEH_error_handler+0x68>
   14000254e:	b8 00 00 00 00       	mov    eax,0x0
   140002553:	e9 ec 01 00 00       	jmp    140002744 <__mingw_SEH_error_handler+0x254>
   140002558:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000255c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000255e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002563:	0f 84 12 01 00 00    	je     14000267b <__mingw_SEH_error_handler+0x18b>
   140002569:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000256e:	0f 87 c3 01 00 00    	ja     140002737 <__mingw_SEH_error_handler+0x247>
   140002574:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002579:	0f 87 b8 01 00 00    	ja     140002737 <__mingw_SEH_error_handler+0x247>
   14000257f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002584:	0f 83 4c 01 00 00    	jae    1400026d6 <__mingw_SEH_error_handler+0x1e6>
   14000258a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000258f:	0f 84 3a 01 00 00    	je     1400026cf <__mingw_SEH_error_handler+0x1df>
   140002595:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000259a:	0f 87 97 01 00 00    	ja     140002737 <__mingw_SEH_error_handler+0x247>
   1400025a0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025a5:	0f 84 83 01 00 00    	je     14000272e <__mingw_SEH_error_handler+0x23e>
   1400025ab:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025b0:	0f 87 81 01 00 00    	ja     140002737 <__mingw_SEH_error_handler+0x247>
   1400025b6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400025bb:	0f 87 76 01 00 00    	ja     140002737 <__mingw_SEH_error_handler+0x247>
   1400025c1:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400025c6:	0f 83 03 01 00 00    	jae    1400026cf <__mingw_SEH_error_handler+0x1df>
   1400025cc:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025d1:	0f 84 57 01 00 00    	je     14000272e <__mingw_SEH_error_handler+0x23e>
   1400025d7:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025dc:	0f 87 55 01 00 00    	ja     140002737 <__mingw_SEH_error_handler+0x247>
   1400025e2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025e7:	0f 84 8e 00 00 00    	je     14000267b <__mingw_SEH_error_handler+0x18b>
   1400025ed:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025f2:	0f 87 3f 01 00 00    	ja     140002737 <__mingw_SEH_error_handler+0x247>
   1400025f8:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025fd:	0f 84 2b 01 00 00    	je     14000272e <__mingw_SEH_error_handler+0x23e>
   140002603:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002608:	0f 87 29 01 00 00    	ja     140002737 <__mingw_SEH_error_handler+0x247>
   14000260e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002613:	0f 84 15 01 00 00    	je     14000272e <__mingw_SEH_error_handler+0x23e>
   140002619:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000261e:	0f 85 13 01 00 00    	jne    140002737 <__mingw_SEH_error_handler+0x247>
   140002624:	ba 00 00 00 00       	mov    edx,0x0
   140002629:	b9 0b 00 00 00       	mov    ecx,0xb
   14000262e:	e8 35 0d 00 00       	call   140003368 <signal>
   140002633:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002637:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000263c:	75 1b                	jne    140002659 <__mingw_SEH_error_handler+0x169>
   14000263e:	ba 01 00 00 00       	mov    edx,0x1
   140002643:	b9 0b 00 00 00       	mov    ecx,0xb
   140002648:	e8 1b 0d 00 00       	call   140003368 <signal>
   14000264d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002654:	e9 e1 00 00 00       	jmp    14000273a <__mingw_SEH_error_handler+0x24a>
   140002659:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000265e:	0f 84 d6 00 00 00    	je     14000273a <__mingw_SEH_error_handler+0x24a>
   140002664:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002668:	b9 0b 00 00 00       	mov    ecx,0xb
   14000266d:	ff d0                	call   rax
   14000266f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002676:	e9 bf 00 00 00       	jmp    14000273a <__mingw_SEH_error_handler+0x24a>
   14000267b:	ba 00 00 00 00       	mov    edx,0x0
   140002680:	b9 04 00 00 00       	mov    ecx,0x4
   140002685:	e8 de 0c 00 00       	call   140003368 <signal>
   14000268a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000268e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002693:	75 1b                	jne    1400026b0 <__mingw_SEH_error_handler+0x1c0>
   140002695:	ba 01 00 00 00       	mov    edx,0x1
   14000269a:	b9 04 00 00 00       	mov    ecx,0x4
   14000269f:	e8 c4 0c 00 00       	call   140003368 <signal>
   1400026a4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026ab:	e9 8d 00 00 00       	jmp    14000273d <__mingw_SEH_error_handler+0x24d>
   1400026b0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026b5:	0f 84 82 00 00 00    	je     14000273d <__mingw_SEH_error_handler+0x24d>
   1400026bb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026bf:	b9 04 00 00 00       	mov    ecx,0x4
   1400026c4:	ff d0                	call   rax
   1400026c6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026cd:	eb 6e                	jmp    14000273d <__mingw_SEH_error_handler+0x24d>
   1400026cf:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400026d6:	ba 00 00 00 00       	mov    edx,0x0
   1400026db:	b9 08 00 00 00       	mov    ecx,0x8
   1400026e0:	e8 83 0c 00 00       	call   140003368 <signal>
   1400026e5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026e9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026ee:	75 23                	jne    140002713 <__mingw_SEH_error_handler+0x223>
   1400026f0:	ba 01 00 00 00       	mov    edx,0x1
   1400026f5:	b9 08 00 00 00       	mov    ecx,0x8
   1400026fa:	e8 69 0c 00 00       	call   140003368 <signal>
   1400026ff:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002703:	74 05                	je     14000270a <__mingw_SEH_error_handler+0x21a>
   140002705:	e8 a6 05 00 00       	call   140002cb0 <_fpreset>
   14000270a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002711:	eb 2d                	jmp    140002740 <__mingw_SEH_error_handler+0x250>
   140002713:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002718:	74 26                	je     140002740 <__mingw_SEH_error_handler+0x250>
   14000271a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000271e:	b9 08 00 00 00       	mov    ecx,0x8
   140002723:	ff d0                	call   rax
   140002725:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000272c:	eb 12                	jmp    140002740 <__mingw_SEH_error_handler+0x250>
   14000272e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002735:	eb 0a                	jmp    140002741 <__mingw_SEH_error_handler+0x251>
   140002737:	90                   	nop
   140002738:	eb 07                	jmp    140002741 <__mingw_SEH_error_handler+0x251>
   14000273a:	90                   	nop
   14000273b:	eb 04                	jmp    140002741 <__mingw_SEH_error_handler+0x251>
   14000273d:	90                   	nop
   14000273e:	eb 01                	jmp    140002741 <__mingw_SEH_error_handler+0x251>
   140002740:	90                   	nop
   140002741:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002744:	48 83 c4 30          	add    rsp,0x30
   140002748:	5d                   	pop    rbp
   140002749:	c3                   	ret

000000014000274a <_gnu_exception_handler>:
   14000274a:	55                   	push   rbp
   14000274b:	48 89 e5             	mov    rbp,rsp
   14000274e:	48 83 ec 30          	sub    rsp,0x30
   140002752:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002756:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000275d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002764:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002768:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000276b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000276d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002772:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002777:	75 1b                	jne    140002794 <_gnu_exception_handler+0x4a>
   140002779:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000277d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002780:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002783:	83 e0 01             	and    eax,0x1
   140002786:	85 c0                	test   eax,eax
   140002788:	75 0a                	jne    140002794 <_gnu_exception_handler+0x4a>
   14000278a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000278f:	e9 14 02 00 00       	jmp    1400029a8 <_gnu_exception_handler+0x25e>
   140002794:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002798:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000279b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000279d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400027a2:	0f 84 12 01 00 00    	je     1400028ba <_gnu_exception_handler+0x170>
   1400027a8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400027ad:	0f 87 c3 01 00 00    	ja     140002976 <_gnu_exception_handler+0x22c>
   1400027b3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400027b8:	0f 87 b8 01 00 00    	ja     140002976 <_gnu_exception_handler+0x22c>
   1400027be:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400027c3:	0f 83 4c 01 00 00    	jae    140002915 <_gnu_exception_handler+0x1cb>
   1400027c9:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027ce:	0f 84 3a 01 00 00    	je     14000290e <_gnu_exception_handler+0x1c4>
   1400027d4:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027d9:	0f 87 97 01 00 00    	ja     140002976 <_gnu_exception_handler+0x22c>
   1400027df:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027e4:	0f 84 83 01 00 00    	je     14000296d <_gnu_exception_handler+0x223>
   1400027ea:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027ef:	0f 87 81 01 00 00    	ja     140002976 <_gnu_exception_handler+0x22c>
   1400027f5:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400027fa:	0f 87 76 01 00 00    	ja     140002976 <_gnu_exception_handler+0x22c>
   140002800:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002805:	0f 83 03 01 00 00    	jae    14000290e <_gnu_exception_handler+0x1c4>
   14000280b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002810:	0f 84 57 01 00 00    	je     14000296d <_gnu_exception_handler+0x223>
   140002816:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000281b:	0f 87 55 01 00 00    	ja     140002976 <_gnu_exception_handler+0x22c>
   140002821:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002826:	0f 84 8e 00 00 00    	je     1400028ba <_gnu_exception_handler+0x170>
   14000282c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002831:	0f 87 3f 01 00 00    	ja     140002976 <_gnu_exception_handler+0x22c>
   140002837:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000283c:	0f 84 2b 01 00 00    	je     14000296d <_gnu_exception_handler+0x223>
   140002842:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002847:	0f 87 29 01 00 00    	ja     140002976 <_gnu_exception_handler+0x22c>
   14000284d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002852:	0f 84 15 01 00 00    	je     14000296d <_gnu_exception_handler+0x223>
   140002858:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000285d:	0f 85 13 01 00 00    	jne    140002976 <_gnu_exception_handler+0x22c>
   140002863:	ba 00 00 00 00       	mov    edx,0x0
   140002868:	b9 0b 00 00 00       	mov    ecx,0xb
   14000286d:	e8 f6 0a 00 00       	call   140003368 <signal>
   140002872:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002876:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000287b:	75 1b                	jne    140002898 <_gnu_exception_handler+0x14e>
   14000287d:	ba 01 00 00 00       	mov    edx,0x1
   140002882:	b9 0b 00 00 00       	mov    ecx,0xb
   140002887:	e8 dc 0a 00 00       	call   140003368 <signal>
   14000288c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002893:	e9 e1 00 00 00       	jmp    140002979 <_gnu_exception_handler+0x22f>
   140002898:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000289d:	0f 84 d6 00 00 00    	je     140002979 <_gnu_exception_handler+0x22f>
   1400028a3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028a7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400028ac:	ff d0                	call   rax
   1400028ae:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028b5:	e9 bf 00 00 00       	jmp    140002979 <_gnu_exception_handler+0x22f>
   1400028ba:	ba 00 00 00 00       	mov    edx,0x0
   1400028bf:	b9 04 00 00 00       	mov    ecx,0x4
   1400028c4:	e8 9f 0a 00 00       	call   140003368 <signal>
   1400028c9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028cd:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028d2:	75 1b                	jne    1400028ef <_gnu_exception_handler+0x1a5>
   1400028d4:	ba 01 00 00 00       	mov    edx,0x1
   1400028d9:	b9 04 00 00 00       	mov    ecx,0x4
   1400028de:	e8 85 0a 00 00       	call   140003368 <signal>
   1400028e3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028ea:	e9 8d 00 00 00       	jmp    14000297c <_gnu_exception_handler+0x232>
   1400028ef:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028f4:	0f 84 82 00 00 00    	je     14000297c <_gnu_exception_handler+0x232>
   1400028fa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028fe:	b9 04 00 00 00       	mov    ecx,0x4
   140002903:	ff d0                	call   rax
   140002905:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000290c:	eb 6e                	jmp    14000297c <_gnu_exception_handler+0x232>
   14000290e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002915:	ba 00 00 00 00       	mov    edx,0x0
   14000291a:	b9 08 00 00 00       	mov    ecx,0x8
   14000291f:	e8 44 0a 00 00       	call   140003368 <signal>
   140002924:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002928:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000292d:	75 23                	jne    140002952 <_gnu_exception_handler+0x208>
   14000292f:	ba 01 00 00 00       	mov    edx,0x1
   140002934:	b9 08 00 00 00       	mov    ecx,0x8
   140002939:	e8 2a 0a 00 00       	call   140003368 <signal>
   14000293e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002942:	74 05                	je     140002949 <_gnu_exception_handler+0x1ff>
   140002944:	e8 67 03 00 00       	call   140002cb0 <_fpreset>
   140002949:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002950:	eb 2d                	jmp    14000297f <_gnu_exception_handler+0x235>
   140002952:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002957:	74 26                	je     14000297f <_gnu_exception_handler+0x235>
   140002959:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000295d:	b9 08 00 00 00       	mov    ecx,0x8
   140002962:	ff d0                	call   rax
   140002964:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000296b:	eb 12                	jmp    14000297f <_gnu_exception_handler+0x235>
   14000296d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002974:	eb 0a                	jmp    140002980 <_gnu_exception_handler+0x236>
   140002976:	90                   	nop
   140002977:	eb 07                	jmp    140002980 <_gnu_exception_handler+0x236>
   140002979:	90                   	nop
   14000297a:	eb 04                	jmp    140002980 <_gnu_exception_handler+0x236>
   14000297c:	90                   	nop
   14000297d:	eb 01                	jmp    140002980 <_gnu_exception_handler+0x236>
   14000297f:	90                   	nop
   140002980:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002984:	75 1f                	jne    1400029a5 <_gnu_exception_handler+0x25b>
   140002986:	48 8b 05 83 67 00 00 	mov    rax,QWORD PTR [rip+0x6783]        # 140009110 <__mingw_oldexcpt_handler>
   14000298d:	48 85 c0             	test   rax,rax
   140002990:	74 13                	je     1400029a5 <_gnu_exception_handler+0x25b>
   140002992:	48 8b 15 77 67 00 00 	mov    rdx,QWORD PTR [rip+0x6777]        # 140009110 <__mingw_oldexcpt_handler>
   140002999:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000299d:	48 89 c1             	mov    rcx,rax
   1400029a0:	ff d2                	call   rdx
   1400029a2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400029a5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400029a8:	48 83 c4 30          	add    rsp,0x30
   1400029ac:	5d                   	pop    rbp
   1400029ad:	c3                   	ret
   1400029ae:	90                   	nop
   1400029af:	90                   	nop

00000001400029b0 <___w64_mingwthr_add_key_dtor>:
   1400029b0:	55                   	push   rbp
   1400029b1:	48 89 e5             	mov    rbp,rsp
   1400029b4:	48 83 ec 30          	sub    rsp,0x30
   1400029b8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029bb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400029bf:	8b 05 83 67 00 00    	mov    eax,DWORD PTR [rip+0x6783]        # 140009148 <__mingwthr_cs_init>
   1400029c5:	85 c0                	test   eax,eax
   1400029c7:	75 07                	jne    1400029d0 <___w64_mingwthr_add_key_dtor+0x20>
   1400029c9:	b8 00 00 00 00       	mov    eax,0x0
   1400029ce:	eb 7b                	jmp    140002a4b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029d0:	ba 18 00 00 00       	mov    edx,0x18
   1400029d5:	b9 01 00 00 00       	mov    ecx,0x1
   1400029da:	e8 41 09 00 00       	call   140003320 <calloc>
   1400029df:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400029e3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029e8:	75 07                	jne    1400029f1 <___w64_mingwthr_add_key_dtor+0x41>
   1400029ea:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400029ef:	eb 5a                	jmp    140002a4b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029f1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029f5:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400029f8:	89 10                	mov    DWORD PTR [rax],edx
   1400029fa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029fe:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002a02:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002a06:	48 8d 05 13 67 00 00 	lea    rax,[rip+0x6713]        # 140009120 <__mingwthr_cs>
   140002a0d:	48 89 c1             	mov    rcx,rax
   140002a10:	48 8b 05 81 77 00 00 	mov    rax,QWORD PTR [rip+0x7781]        # 14000a198 <__imp_EnterCriticalSection>
   140002a17:	ff d0                	call   rax
   140002a19:	48 8b 15 30 67 00 00 	mov    rdx,QWORD PTR [rip+0x6730]        # 140009150 <key_dtor_list>
   140002a20:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a24:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a28:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a2c:	48 89 05 1d 67 00 00 	mov    QWORD PTR [rip+0x671d],rax        # 140009150 <key_dtor_list>
   140002a33:	48 8d 05 e6 66 00 00 	lea    rax,[rip+0x66e6]        # 140009120 <__mingwthr_cs>
   140002a3a:	48 89 c1             	mov    rcx,rax
   140002a3d:	48 8b 05 84 77 00 00 	mov    rax,QWORD PTR [rip+0x7784]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002a44:	ff d0                	call   rax
   140002a46:	b8 00 00 00 00       	mov    eax,0x0
   140002a4b:	48 83 c4 30          	add    rsp,0x30
   140002a4f:	5d                   	pop    rbp
   140002a50:	c3                   	ret

0000000140002a51 <___w64_mingwthr_remove_key_dtor>:
   140002a51:	55                   	push   rbp
   140002a52:	48 89 e5             	mov    rbp,rsp
   140002a55:	48 83 ec 30          	sub    rsp,0x30
   140002a59:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a5c:	8b 05 e6 66 00 00    	mov    eax,DWORD PTR [rip+0x66e6]        # 140009148 <__mingwthr_cs_init>
   140002a62:	85 c0                	test   eax,eax
   140002a64:	75 0a                	jne    140002a70 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a66:	b8 00 00 00 00       	mov    eax,0x0
   140002a6b:	e9 9c 00 00 00       	jmp    140002b0c <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a70:	48 8d 05 a9 66 00 00 	lea    rax,[rip+0x66a9]        # 140009120 <__mingwthr_cs>
   140002a77:	48 89 c1             	mov    rcx,rax
   140002a7a:	48 8b 05 17 77 00 00 	mov    rax,QWORD PTR [rip+0x7717]        # 14000a198 <__imp_EnterCriticalSection>
   140002a81:	ff d0                	call   rax
   140002a83:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a8a:	00 
   140002a8b:	48 8b 05 be 66 00 00 	mov    rax,QWORD PTR [rip+0x66be]        # 140009150 <key_dtor_list>
   140002a92:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a96:	eb 55                	jmp    140002aed <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a98:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a9c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a9e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002aa1:	75 36                	jne    140002ad9 <___w64_mingwthr_remove_key_dtor+0x88>
   140002aa3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002aa8:	75 11                	jne    140002abb <___w64_mingwthr_remove_key_dtor+0x6a>
   140002aaa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aae:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ab2:	48 89 05 97 66 00 00 	mov    QWORD PTR [rip+0x6697],rax        # 140009150 <key_dtor_list>
   140002ab9:	eb 10                	jmp    140002acb <___w64_mingwthr_remove_key_dtor+0x7a>
   140002abb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002abf:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002ac3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ac7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002acb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002acf:	48 89 c1             	mov    rcx,rax
   140002ad2:	e8 69 08 00 00       	call   140003340 <free>
   140002ad7:	eb 1b                	jmp    140002af4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002ad9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002add:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ae1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ae5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ae9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002aed:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002af2:	75 a4                	jne    140002a98 <___w64_mingwthr_remove_key_dtor+0x47>
   140002af4:	48 8d 05 25 66 00 00 	lea    rax,[rip+0x6625]        # 140009120 <__mingwthr_cs>
   140002afb:	48 89 c1             	mov    rcx,rax
   140002afe:	48 8b 05 c3 76 00 00 	mov    rax,QWORD PTR [rip+0x76c3]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002b05:	ff d0                	call   rax
   140002b07:	b8 00 00 00 00       	mov    eax,0x0
   140002b0c:	48 83 c4 30          	add    rsp,0x30
   140002b10:	5d                   	pop    rbp
   140002b11:	c3                   	ret

0000000140002b12 <__mingwthr_run_key_dtors>:
   140002b12:	55                   	push   rbp
   140002b13:	48 89 e5             	mov    rbp,rsp
   140002b16:	48 83 ec 30          	sub    rsp,0x30
   140002b1a:	8b 05 28 66 00 00    	mov    eax,DWORD PTR [rip+0x6628]        # 140009148 <__mingwthr_cs_init>
   140002b20:	85 c0                	test   eax,eax
   140002b22:	0f 84 82 00 00 00    	je     140002baa <__mingwthr_run_key_dtors+0x98>
   140002b28:	48 8d 05 f1 65 00 00 	lea    rax,[rip+0x65f1]        # 140009120 <__mingwthr_cs>
   140002b2f:	48 89 c1             	mov    rcx,rax
   140002b32:	48 8b 05 5f 76 00 00 	mov    rax,QWORD PTR [rip+0x765f]        # 14000a198 <__imp_EnterCriticalSection>
   140002b39:	ff d0                	call   rax
   140002b3b:	48 8b 05 0e 66 00 00 	mov    rax,QWORD PTR [rip+0x660e]        # 140009150 <key_dtor_list>
   140002b42:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b46:	eb 46                	jmp    140002b8e <__mingwthr_run_key_dtors+0x7c>
   140002b48:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b4c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b4e:	89 c1                	mov    ecx,eax
   140002b50:	48 8b 05 91 76 00 00 	mov    rax,QWORD PTR [rip+0x7691]        # 14000a1e8 <__imp_TlsGetValue>
   140002b57:	ff d0                	call   rax
   140002b59:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b5d:	48 8b 05 44 76 00 00 	mov    rax,QWORD PTR [rip+0x7644]        # 14000a1a8 <__imp_GetLastError>
   140002b64:	ff d0                	call   rax
   140002b66:	85 c0                	test   eax,eax
   140002b68:	75 18                	jne    140002b82 <__mingwthr_run_key_dtors+0x70>
   140002b6a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b6f:	74 11                	je     140002b82 <__mingwthr_run_key_dtors+0x70>
   140002b71:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b75:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002b79:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b7d:	48 89 c1             	mov    rcx,rax
   140002b80:	ff d2                	call   rdx
   140002b82:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b86:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b8a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b8e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b93:	75 b3                	jne    140002b48 <__mingwthr_run_key_dtors+0x36>
   140002b95:	48 8d 05 84 65 00 00 	lea    rax,[rip+0x6584]        # 140009120 <__mingwthr_cs>
   140002b9c:	48 89 c1             	mov    rcx,rax
   140002b9f:	48 8b 05 22 76 00 00 	mov    rax,QWORD PTR [rip+0x7622]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002ba6:	ff d0                	call   rax
   140002ba8:	eb 01                	jmp    140002bab <__mingwthr_run_key_dtors+0x99>
   140002baa:	90                   	nop
   140002bab:	48 83 c4 30          	add    rsp,0x30
   140002baf:	5d                   	pop    rbp
   140002bb0:	c3                   	ret

0000000140002bb1 <__mingw_TLScallback>:
   140002bb1:	55                   	push   rbp
   140002bb2:	48 89 e5             	mov    rbp,rsp
   140002bb5:	48 83 ec 30          	sub    rsp,0x30
   140002bb9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002bbd:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002bc0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002bc4:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002bc8:	0f 84 cc 00 00 00    	je     140002c9a <__mingw_TLScallback+0xe9>
   140002bce:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002bd2:	0f 87 ca 00 00 00    	ja     140002ca2 <__mingw_TLScallback+0xf1>
   140002bd8:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bdc:	0f 84 b1 00 00 00    	je     140002c93 <__mingw_TLScallback+0xe2>
   140002be2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002be6:	0f 87 b6 00 00 00    	ja     140002ca2 <__mingw_TLScallback+0xf1>
   140002bec:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002bf0:	74 33                	je     140002c25 <__mingw_TLScallback+0x74>
   140002bf2:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002bf6:	0f 85 a6 00 00 00    	jne    140002ca2 <__mingw_TLScallback+0xf1>
   140002bfc:	8b 05 46 65 00 00    	mov    eax,DWORD PTR [rip+0x6546]        # 140009148 <__mingwthr_cs_init>
   140002c02:	85 c0                	test   eax,eax
   140002c04:	75 13                	jne    140002c19 <__mingw_TLScallback+0x68>
   140002c06:	48 8d 05 13 65 00 00 	lea    rax,[rip+0x6513]        # 140009120 <__mingwthr_cs>
   140002c0d:	48 89 c1             	mov    rcx,rax
   140002c10:	48 8b 05 a9 75 00 00 	mov    rax,QWORD PTR [rip+0x75a9]        # 14000a1c0 <__imp_InitializeCriticalSection>
   140002c17:	ff d0                	call   rax
   140002c19:	c7 05 25 65 00 00 01 	mov    DWORD PTR [rip+0x6525],0x1        # 140009148 <__mingwthr_cs_init>
   140002c20:	00 00 00 
   140002c23:	eb 7d                	jmp    140002ca2 <__mingw_TLScallback+0xf1>
   140002c25:	e8 e8 fe ff ff       	call   140002b12 <__mingwthr_run_key_dtors>
   140002c2a:	8b 05 18 65 00 00    	mov    eax,DWORD PTR [rip+0x6518]        # 140009148 <__mingwthr_cs_init>
   140002c30:	83 f8 01             	cmp    eax,0x1
   140002c33:	75 6c                	jne    140002ca1 <__mingw_TLScallback+0xf0>
   140002c35:	48 8b 05 14 65 00 00 	mov    rax,QWORD PTR [rip+0x6514]        # 140009150 <key_dtor_list>
   140002c3c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c40:	eb 20                	jmp    140002c62 <__mingw_TLScallback+0xb1>
   140002c42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c46:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c4a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c4e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c52:	48 89 c1             	mov    rcx,rax
   140002c55:	e8 e6 06 00 00       	call   140003340 <free>
   140002c5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c5e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c62:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c67:	75 d9                	jne    140002c42 <__mingw_TLScallback+0x91>
   140002c69:	48 c7 05 dc 64 00 00 	mov    QWORD PTR [rip+0x64dc],0x0        # 140009150 <key_dtor_list>
   140002c70:	00 00 00 00 
   140002c74:	c7 05 ca 64 00 00 00 	mov    DWORD PTR [rip+0x64ca],0x0        # 140009148 <__mingwthr_cs_init>
   140002c7b:	00 00 00 
   140002c7e:	48 8d 05 9b 64 00 00 	lea    rax,[rip+0x649b]        # 140009120 <__mingwthr_cs>
   140002c85:	48 89 c1             	mov    rcx,rax
   140002c88:	48 8b 05 01 75 00 00 	mov    rax,QWORD PTR [rip+0x7501]        # 14000a190 <__IAT_start__>
   140002c8f:	ff d0                	call   rax
   140002c91:	eb 0e                	jmp    140002ca1 <__mingw_TLScallback+0xf0>
   140002c93:	e8 18 00 00 00       	call   140002cb0 <_fpreset>
   140002c98:	eb 08                	jmp    140002ca2 <__mingw_TLScallback+0xf1>
   140002c9a:	e8 73 fe ff ff       	call   140002b12 <__mingwthr_run_key_dtors>
   140002c9f:	eb 01                	jmp    140002ca2 <__mingw_TLScallback+0xf1>
   140002ca1:	90                   	nop
   140002ca2:	b8 01 00 00 00       	mov    eax,0x1
   140002ca7:	48 83 c4 30          	add    rsp,0x30
   140002cab:	5d                   	pop    rbp
   140002cac:	c3                   	ret
   140002cad:	90                   	nop
   140002cae:	90                   	nop
   140002caf:	90                   	nop

0000000140002cb0 <_fpreset>:
   140002cb0:	55                   	push   rbp
   140002cb1:	48 89 e5             	mov    rbp,rsp
   140002cb4:	db e3                	fninit
   140002cb6:	90                   	nop
   140002cb7:	5d                   	pop    rbp
   140002cb8:	c3                   	ret
   140002cb9:	90                   	nop
   140002cba:	90                   	nop
   140002cbb:	90                   	nop
   140002cbc:	90                   	nop
   140002cbd:	90                   	nop
   140002cbe:	90                   	nop
   140002cbf:	90                   	nop

0000000140002cc0 <_ValidateImageBase>:
   140002cc0:	55                   	push   rbp
   140002cc1:	48 89 e5             	mov    rbp,rsp
   140002cc4:	48 83 ec 20          	sub    rsp,0x20
   140002cc8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ccc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cd0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cd4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cd8:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002cdb:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002cdf:	74 07                	je     140002ce8 <_ValidateImageBase+0x28>
   140002ce1:	b8 00 00 00 00       	mov    eax,0x0
   140002ce6:	eb 4e                	jmp    140002d36 <_ValidateImageBase+0x76>
   140002ce8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cec:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002cef:	48 63 d0             	movsxd rdx,eax
   140002cf2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cf6:	48 01 d0             	add    rax,rdx
   140002cf9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002cfd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d01:	8b 00                	mov    eax,DWORD PTR [rax]
   140002d03:	3d 50 45 00 00       	cmp    eax,0x4550
   140002d08:	74 07                	je     140002d11 <_ValidateImageBase+0x51>
   140002d0a:	b8 00 00 00 00       	mov    eax,0x0
   140002d0f:	eb 25                	jmp    140002d36 <_ValidateImageBase+0x76>
   140002d11:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d15:	48 83 c0 18          	add    rax,0x18
   140002d19:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d1d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d21:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d24:	66 3d 0b 02          	cmp    ax,0x20b
   140002d28:	74 07                	je     140002d31 <_ValidateImageBase+0x71>
   140002d2a:	b8 00 00 00 00       	mov    eax,0x0
   140002d2f:	eb 05                	jmp    140002d36 <_ValidateImageBase+0x76>
   140002d31:	b8 01 00 00 00       	mov    eax,0x1
   140002d36:	48 83 c4 20          	add    rsp,0x20
   140002d3a:	5d                   	pop    rbp
   140002d3b:	c3                   	ret

0000000140002d3c <_FindPESection>:
   140002d3c:	55                   	push   rbp
   140002d3d:	48 89 e5             	mov    rbp,rsp
   140002d40:	48 83 ec 20          	sub    rsp,0x20
   140002d44:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d48:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d4c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d50:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d53:	48 63 d0             	movsxd rdx,eax
   140002d56:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d5a:	48 01 d0             	add    rax,rdx
   140002d5d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d61:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d68:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d6c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d70:	0f b7 d0             	movzx  edx,ax
   140002d73:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d77:	48 01 d0             	add    rax,rdx
   140002d7a:	48 83 c0 18          	add    rax,0x18
   140002d7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d82:	eb 36                	jmp    140002dba <_FindPESection+0x7e>
   140002d84:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d88:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d8b:	89 c0                	mov    eax,eax
   140002d8d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d91:	72 1e                	jb     140002db1 <_FindPESection+0x75>
   140002d93:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d97:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d9a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d9e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002da1:	01 d0                	add    eax,edx
   140002da3:	89 c0                	mov    eax,eax
   140002da5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002da9:	73 06                	jae    140002db1 <_FindPESection+0x75>
   140002dab:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002daf:	eb 1e                	jmp    140002dcf <_FindPESection+0x93>
   140002db1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002db5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002dba:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dbe:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002dc2:	0f b7 c0             	movzx  eax,ax
   140002dc5:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002dc8:	72 ba                	jb     140002d84 <_FindPESection+0x48>
   140002dca:	b8 00 00 00 00       	mov    eax,0x0
   140002dcf:	48 83 c4 20          	add    rsp,0x20
   140002dd3:	5d                   	pop    rbp
   140002dd4:	c3                   	ret

0000000140002dd5 <_FindPESectionByName>:
   140002dd5:	55                   	push   rbp
   140002dd6:	48 89 e5             	mov    rbp,rsp
   140002dd9:	48 83 ec 40          	sub    rsp,0x40
   140002ddd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002de1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002de5:	48 89 c1             	mov    rcx,rax
   140002de8:	e8 83 05 00 00       	call   140003370 <strlen>
   140002ded:	48 83 f8 08          	cmp    rax,0x8
   140002df1:	76 0a                	jbe    140002dfd <_FindPESectionByName+0x28>
   140002df3:	b8 00 00 00 00       	mov    eax,0x0
   140002df8:	e9 98 00 00 00       	jmp    140002e95 <_FindPESectionByName+0xc0>
   140002dfd:	48 8b 05 5c 25 00 00 	mov    rax,QWORD PTR [rip+0x255c]        # 140005360 <.refptr.__ImageBase>
   140002e04:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e08:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e0c:	48 89 c1             	mov    rcx,rax
   140002e0f:	e8 ac fe ff ff       	call   140002cc0 <_ValidateImageBase>
   140002e14:	85 c0                	test   eax,eax
   140002e16:	75 07                	jne    140002e1f <_FindPESectionByName+0x4a>
   140002e18:	b8 00 00 00 00       	mov    eax,0x0
   140002e1d:	eb 76                	jmp    140002e95 <_FindPESectionByName+0xc0>
   140002e1f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e23:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e26:	48 63 d0             	movsxd rdx,eax
   140002e29:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e2d:	48 01 d0             	add    rax,rdx
   140002e30:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e34:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e3b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e3f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e43:	0f b7 d0             	movzx  edx,ax
   140002e46:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e4a:	48 01 d0             	add    rax,rdx
   140002e4d:	48 83 c0 18          	add    rax,0x18
   140002e51:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e55:	eb 29                	jmp    140002e80 <_FindPESectionByName+0xab>
   140002e57:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e5b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e5f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e65:	48 89 c1             	mov    rcx,rax
   140002e68:	e8 0b 05 00 00       	call   140003378 <strncmp>
   140002e6d:	85 c0                	test   eax,eax
   140002e6f:	75 06                	jne    140002e77 <_FindPESectionByName+0xa2>
   140002e71:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e75:	eb 1e                	jmp    140002e95 <_FindPESectionByName+0xc0>
   140002e77:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e7b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e80:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e84:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e88:	0f b7 c0             	movzx  eax,ax
   140002e8b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e8e:	72 c7                	jb     140002e57 <_FindPESectionByName+0x82>
   140002e90:	b8 00 00 00 00       	mov    eax,0x0
   140002e95:	48 83 c4 40          	add    rsp,0x40
   140002e99:	5d                   	pop    rbp
   140002e9a:	c3                   	ret

0000000140002e9b <__mingw_GetSectionForAddress>:
   140002e9b:	55                   	push   rbp
   140002e9c:	48 89 e5             	mov    rbp,rsp
   140002e9f:	48 83 ec 30          	sub    rsp,0x30
   140002ea3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ea7:	48 8b 05 b2 24 00 00 	mov    rax,QWORD PTR [rip+0x24b2]        # 140005360 <.refptr.__ImageBase>
   140002eae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002eb2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002eb6:	48 89 c1             	mov    rcx,rax
   140002eb9:	e8 02 fe ff ff       	call   140002cc0 <_ValidateImageBase>
   140002ebe:	85 c0                	test   eax,eax
   140002ec0:	75 07                	jne    140002ec9 <__mingw_GetSectionForAddress+0x2e>
   140002ec2:	b8 00 00 00 00       	mov    eax,0x0
   140002ec7:	eb 1c                	jmp    140002ee5 <__mingw_GetSectionForAddress+0x4a>
   140002ec9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ecd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002ed1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ed5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002ed9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002edd:	48 89 c1             	mov    rcx,rax
   140002ee0:	e8 57 fe ff ff       	call   140002d3c <_FindPESection>
   140002ee5:	48 83 c4 30          	add    rsp,0x30
   140002ee9:	5d                   	pop    rbp
   140002eea:	c3                   	ret

0000000140002eeb <__mingw_GetSectionCount>:
   140002eeb:	55                   	push   rbp
   140002eec:	48 89 e5             	mov    rbp,rsp
   140002eef:	48 83 ec 30          	sub    rsp,0x30
   140002ef3:	48 8b 05 66 24 00 00 	mov    rax,QWORD PTR [rip+0x2466]        # 140005360 <.refptr.__ImageBase>
   140002efa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002efe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f02:	48 89 c1             	mov    rcx,rax
   140002f05:	e8 b6 fd ff ff       	call   140002cc0 <_ValidateImageBase>
   140002f0a:	85 c0                	test   eax,eax
   140002f0c:	75 07                	jne    140002f15 <__mingw_GetSectionCount+0x2a>
   140002f0e:	b8 00 00 00 00       	mov    eax,0x0
   140002f13:	eb 20                	jmp    140002f35 <__mingw_GetSectionCount+0x4a>
   140002f15:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f19:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f1c:	48 63 d0             	movsxd rdx,eax
   140002f1f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f23:	48 01 d0             	add    rax,rdx
   140002f26:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002f2e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f32:	0f b7 c0             	movzx  eax,ax
   140002f35:	48 83 c4 30          	add    rsp,0x30
   140002f39:	5d                   	pop    rbp
   140002f3a:	c3                   	ret

0000000140002f3b <_FindPESectionExec>:
   140002f3b:	55                   	push   rbp
   140002f3c:	48 89 e5             	mov    rbp,rsp
   140002f3f:	48 83 ec 40          	sub    rsp,0x40
   140002f43:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f47:	48 8b 05 12 24 00 00 	mov    rax,QWORD PTR [rip+0x2412]        # 140005360 <.refptr.__ImageBase>
   140002f4e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f52:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f56:	48 89 c1             	mov    rcx,rax
   140002f59:	e8 62 fd ff ff       	call   140002cc0 <_ValidateImageBase>
   140002f5e:	85 c0                	test   eax,eax
   140002f60:	75 07                	jne    140002f69 <_FindPESectionExec+0x2e>
   140002f62:	b8 00 00 00 00       	mov    eax,0x0
   140002f67:	eb 78                	jmp    140002fe1 <_FindPESectionExec+0xa6>
   140002f69:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f6d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f70:	48 63 d0             	movsxd rdx,eax
   140002f73:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f77:	48 01 d0             	add    rax,rdx
   140002f7a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f7e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f85:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f89:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f8d:	0f b7 d0             	movzx  edx,ax
   140002f90:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f94:	48 01 d0             	add    rax,rdx
   140002f97:	48 83 c0 18          	add    rax,0x18
   140002f9b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f9f:	eb 2b                	jmp    140002fcc <_FindPESectionExec+0x91>
   140002fa1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fa5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fa8:	25 00 00 00 20       	and    eax,0x20000000
   140002fad:	85 c0                	test   eax,eax
   140002faf:	74 12                	je     140002fc3 <_FindPESectionExec+0x88>
   140002fb1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002fb6:	75 06                	jne    140002fbe <_FindPESectionExec+0x83>
   140002fb8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fbc:	eb 23                	jmp    140002fe1 <_FindPESectionExec+0xa6>
   140002fbe:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002fc3:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002fc7:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002fcc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fd0:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002fd4:	0f b7 c0             	movzx  eax,ax
   140002fd7:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002fda:	72 c5                	jb     140002fa1 <_FindPESectionExec+0x66>
   140002fdc:	b8 00 00 00 00       	mov    eax,0x0
   140002fe1:	48 83 c4 40          	add    rsp,0x40
   140002fe5:	5d                   	pop    rbp
   140002fe6:	c3                   	ret

0000000140002fe7 <_GetPEImageBase>:
   140002fe7:	55                   	push   rbp
   140002fe8:	48 89 e5             	mov    rbp,rsp
   140002feb:	48 83 ec 30          	sub    rsp,0x30
   140002fef:	48 8b 05 6a 23 00 00 	mov    rax,QWORD PTR [rip+0x236a]        # 140005360 <.refptr.__ImageBase>
   140002ff6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ffa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ffe:	48 89 c1             	mov    rcx,rax
   140003001:	e8 ba fc ff ff       	call   140002cc0 <_ValidateImageBase>
   140003006:	85 c0                	test   eax,eax
   140003008:	75 07                	jne    140003011 <_GetPEImageBase+0x2a>
   14000300a:	b8 00 00 00 00       	mov    eax,0x0
   14000300f:	eb 04                	jmp    140003015 <_GetPEImageBase+0x2e>
   140003011:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003015:	48 83 c4 30          	add    rsp,0x30
   140003019:	5d                   	pop    rbp
   14000301a:	c3                   	ret

000000014000301b <_IsNonwritableInCurrentImage>:
   14000301b:	55                   	push   rbp
   14000301c:	48 89 e5             	mov    rbp,rsp
   14000301f:	48 83 ec 40          	sub    rsp,0x40
   140003023:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003027:	48 8b 05 32 23 00 00 	mov    rax,QWORD PTR [rip+0x2332]        # 140005360 <.refptr.__ImageBase>
   14000302e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003032:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003036:	48 89 c1             	mov    rcx,rax
   140003039:	e8 82 fc ff ff       	call   140002cc0 <_ValidateImageBase>
   14000303e:	85 c0                	test   eax,eax
   140003040:	75 07                	jne    140003049 <_IsNonwritableInCurrentImage+0x2e>
   140003042:	b8 00 00 00 00       	mov    eax,0x0
   140003047:	eb 3d                	jmp    140003086 <_IsNonwritableInCurrentImage+0x6b>
   140003049:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000304d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003051:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003055:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003059:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000305d:	48 89 c1             	mov    rcx,rax
   140003060:	e8 d7 fc ff ff       	call   140002d3c <_FindPESection>
   140003065:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003069:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000306e:	75 07                	jne    140003077 <_IsNonwritableInCurrentImage+0x5c>
   140003070:	b8 00 00 00 00       	mov    eax,0x0
   140003075:	eb 0f                	jmp    140003086 <_IsNonwritableInCurrentImage+0x6b>
   140003077:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000307b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000307e:	f7 d0                	not    eax
   140003080:	c1 e8 1f             	shr    eax,0x1f
   140003083:	0f b6 c0             	movzx  eax,al
   140003086:	48 83 c4 40          	add    rsp,0x40
   14000308a:	5d                   	pop    rbp
   14000308b:	c3                   	ret

000000014000308c <__mingw_enum_import_library_names>:
   14000308c:	55                   	push   rbp
   14000308d:	48 89 e5             	mov    rbp,rsp
   140003090:	48 83 ec 50          	sub    rsp,0x50
   140003094:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003097:	48 8b 05 c2 22 00 00 	mov    rax,QWORD PTR [rip+0x22c2]        # 140005360 <.refptr.__ImageBase>
   14000309e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400030a2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030a6:	48 89 c1             	mov    rcx,rax
   1400030a9:	e8 12 fc ff ff       	call   140002cc0 <_ValidateImageBase>
   1400030ae:	85 c0                	test   eax,eax
   1400030b0:	75 0a                	jne    1400030bc <__mingw_enum_import_library_names+0x30>
   1400030b2:	b8 00 00 00 00       	mov    eax,0x0
   1400030b7:	e9 ab 00 00 00       	jmp    140003167 <__mingw_enum_import_library_names+0xdb>
   1400030bc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030c0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   1400030c3:	48 63 d0             	movsxd rdx,eax
   1400030c6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030ca:	48 01 d0             	add    rax,rdx
   1400030cd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400030d1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030d5:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   1400030db:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400030de:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400030e2:	75 07                	jne    1400030eb <__mingw_enum_import_library_names+0x5f>
   1400030e4:	b8 00 00 00 00       	mov    eax,0x0
   1400030e9:	eb 7c                	jmp    140003167 <__mingw_enum_import_library_names+0xdb>
   1400030eb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030ee:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030f2:	48 89 c1             	mov    rcx,rax
   1400030f5:	e8 42 fc ff ff       	call   140002d3c <_FindPESection>
   1400030fa:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400030fe:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003103:	75 07                	jne    14000310c <__mingw_enum_import_library_names+0x80>
   140003105:	b8 00 00 00 00       	mov    eax,0x0
   14000310a:	eb 5b                	jmp    140003167 <__mingw_enum_import_library_names+0xdb>
   14000310c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000310f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003113:	48 01 d0             	add    rax,rdx
   140003116:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000311a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000311f:	75 07                	jne    140003128 <__mingw_enum_import_library_names+0x9c>
   140003121:	b8 00 00 00 00       	mov    eax,0x0
   140003126:	eb 3f                	jmp    140003167 <__mingw_enum_import_library_names+0xdb>
   140003128:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000312c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000312f:	85 c0                	test   eax,eax
   140003131:	75 0b                	jne    14000313e <__mingw_enum_import_library_names+0xb2>
   140003133:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003137:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000313a:	85 c0                	test   eax,eax
   14000313c:	74 23                	je     140003161 <__mingw_enum_import_library_names+0xd5>
   14000313e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003142:	7f 12                	jg     140003156 <__mingw_enum_import_library_names+0xca>
   140003144:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003148:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000314b:	89 c2                	mov    edx,eax
   14000314d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003151:	48 01 d0             	add    rax,rdx
   140003154:	eb 11                	jmp    140003167 <__mingw_enum_import_library_names+0xdb>
   140003156:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000315a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000315f:	eb c7                	jmp    140003128 <__mingw_enum_import_library_names+0x9c>
   140003161:	90                   	nop
   140003162:	b8 00 00 00 00       	mov    eax,0x0
   140003167:	48 83 c4 50          	add    rsp,0x50
   14000316b:	5d                   	pop    rbp
   14000316c:	c3                   	ret
   14000316d:	90                   	nop
   14000316e:	90                   	nop
   14000316f:	90                   	nop

0000000140003170 <___chkstk_ms>:
   140003170:	51                   	push   rcx
   140003171:	50                   	push   rax
   140003172:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003178:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000317d:	72 19                	jb     140003198 <___chkstk_ms+0x28>
   14000317f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003186:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000318a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003190:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003196:	77 e7                	ja     14000317f <___chkstk_ms+0xf>
   140003198:	48 29 c1             	sub    rcx,rax
   14000319b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000319f:	58                   	pop    rax
   1400031a0:	59                   	pop    rcx
   1400031a1:	c3                   	ret
   1400031a2:	90                   	nop
   1400031a3:	90                   	nop
   1400031a4:	90                   	nop
   1400031a5:	90                   	nop
   1400031a6:	90                   	nop
   1400031a7:	90                   	nop
   1400031a8:	90                   	nop
   1400031a9:	90                   	nop
   1400031aa:	90                   	nop
   1400031ab:	90                   	nop
   1400031ac:	90                   	nop
   1400031ad:	90                   	nop
   1400031ae:	90                   	nop
   1400031af:	90                   	nop

00000001400031b0 <_initterm_e>:
   1400031b0:	55                   	push   rbp
   1400031b1:	48 89 e5             	mov    rbp,rsp
   1400031b4:	48 83 ec 30          	sub    rsp,0x30
   1400031b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400031bc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400031c0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400031c4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031c8:	eb 29                	jmp    1400031f3 <_initterm_e+0x43>
   1400031ca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031ce:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031d1:	48 85 c0             	test   rax,rax
   1400031d4:	74 17                	je     1400031ed <_initterm_e+0x3d>
   1400031d6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031da:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031dd:	ff d0                	call   rax
   1400031df:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400031e2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   1400031e6:	74 06                	je     1400031ee <_initterm_e+0x3e>
   1400031e8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400031eb:	eb 15                	jmp    140003202 <_initterm_e+0x52>
   1400031ed:	90                   	nop
   1400031ee:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400031f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031f7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400031fb:	72 cd                	jb     1400031ca <_initterm_e+0x1a>
   1400031fd:	b8 00 00 00 00       	mov    eax,0x0
   140003202:	48 83 c4 30          	add    rsp,0x30
   140003206:	5d                   	pop    rbp
   140003207:	c3                   	ret
   140003208:	90                   	nop
   140003209:	90                   	nop
   14000320a:	90                   	nop
   14000320b:	90                   	nop
   14000320c:	90                   	nop
   14000320d:	90                   	nop
   14000320e:	90                   	nop
   14000320f:	90                   	nop

0000000140003210 <__p__fmode>:
   140003210:	55                   	push   rbp
   140003211:	48 89 e5             	mov    rbp,rsp
   140003214:	48 8b 05 b5 21 00 00 	mov    rax,QWORD PTR [rip+0x21b5]        # 1400053d0 <.refptr.__imp__fmode>
   14000321b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000321e:	5d                   	pop    rbp
   14000321f:	c3                   	ret

0000000140003220 <__p__commode>:
   140003220:	55                   	push   rbp
   140003221:	48 89 e5             	mov    rbp,rsp
   140003224:	48 8b 05 95 21 00 00 	mov    rax,QWORD PTR [rip+0x2195]        # 1400053c0 <.refptr.__imp__commode>
   14000322b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000322e:	5d                   	pop    rbp
   14000322f:	c3                   	ret

0000000140003230 <__p___initenv>:
   140003230:	55                   	push   rbp
   140003231:	48 89 e5             	mov    rbp,rsp
   140003234:	48 8b 05 75 21 00 00 	mov    rax,QWORD PTR [rip+0x2175]        # 1400053b0 <.refptr.__imp___initenv>
   14000323b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000323e:	5d                   	pop    rbp
   14000323f:	c3                   	ret

0000000140003240 <_set_invalid_parameter_handler>:
   140003240:	55                   	push   rbp
   140003241:	48 89 e5             	mov    rbp,rsp
   140003244:	48 83 ec 10          	sub    rsp,0x10
   140003248:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000324c:	48 8d 05 3d 5f 00 00 	lea    rax,[rip+0x5f3d]        # 140009190 <handler>
   140003253:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003257:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000325b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000325f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003263:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003267:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000326a:	48 89 d0             	mov    rax,rdx
   14000326d:	48 83 c4 10          	add    rsp,0x10
   140003271:	5d                   	pop    rbp
   140003272:	c3                   	ret

0000000140003273 <_get_invalid_parameter_handler>:
   140003273:	55                   	push   rbp
   140003274:	48 89 e5             	mov    rbp,rsp
   140003277:	48 8b 05 12 5f 00 00 	mov    rax,QWORD PTR [rip+0x5f12]        # 140009190 <handler>
   14000327e:	5d                   	pop    rbp
   14000327f:	c3                   	ret

0000000140003280 <_configthreadlocale>:
   140003280:	55                   	push   rbp
   140003281:	48 89 e5             	mov    rbp,rsp
   140003284:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003287:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000328b:	75 07                	jne    140003294 <_configthreadlocale+0x14>
   14000328d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140003292:	eb 05                	jmp    140003299 <_configthreadlocale+0x19>
   140003294:	b8 02 00 00 00       	mov    eax,0x2
   140003299:	5d                   	pop    rbp
   14000329a:	c3                   	ret
   14000329b:	90                   	nop
   14000329c:	90                   	nop
   14000329d:	90                   	nop
   14000329e:	90                   	nop
   14000329f:	90                   	nop

00000001400032a0 <__acrt_iob_func>:
   1400032a0:	55                   	push   rbp
   1400032a1:	48 89 e5             	mov    rbp,rsp
   1400032a4:	48 83 ec 20          	sub    rsp,0x20
   1400032a8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400032ab:	e8 30 00 00 00       	call   1400032e0 <__iob_func>
   1400032b0:	48 89 c1             	mov    rcx,rax
   1400032b3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400032b6:	48 89 d0             	mov    rax,rdx
   1400032b9:	48 01 c0             	add    rax,rax
   1400032bc:	48 01 d0             	add    rax,rdx
   1400032bf:	48 c1 e0 04          	shl    rax,0x4
   1400032c3:	48 01 c8             	add    rax,rcx
   1400032c6:	48 83 c4 20          	add    rsp,0x20
   1400032ca:	5d                   	pop    rbp
   1400032cb:	c3                   	ret
   1400032cc:	90                   	nop
   1400032cd:	90                   	nop
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <__C_specific_handler>:
   1400032d0:	ff 25 32 6f 00 00    	jmp    QWORD PTR [rip+0x6f32]        # 14000a208 <__imp___C_specific_handler>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop

00000001400032d8 <__getmainargs>:
   1400032d8:	ff 25 32 6f 00 00    	jmp    QWORD PTR [rip+0x6f32]        # 14000a210 <__imp___getmainargs>
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <__iob_func>:
   1400032e0:	ff 25 3a 6f 00 00    	jmp    QWORD PTR [rip+0x6f3a]        # 14000a220 <__imp___iob_func>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <__set_app_type>:
   1400032e8:	ff 25 3a 6f 00 00    	jmp    QWORD PTR [rip+0x6f3a]        # 14000a228 <__imp___set_app_type>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <__setusermatherr>:
   1400032f0:	ff 25 3a 6f 00 00    	jmp    QWORD PTR [rip+0x6f3a]        # 14000a230 <__imp___setusermatherr>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <_amsg_exit>:
   1400032f8:	ff 25 3a 6f 00 00    	jmp    QWORD PTR [rip+0x6f3a]        # 14000a238 <__imp__amsg_exit>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <_cexit>:
   140003300:	ff 25 3a 6f 00 00    	jmp    QWORD PTR [rip+0x6f3a]        # 14000a240 <__imp__cexit>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <_initterm>:
   140003308:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a258 <__imp__initterm>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <_crt_atexit>:
   140003310:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a260 <__imp__crt_atexit>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <abort>:
   140003318:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a268 <__imp_abort>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <calloc>:
   140003320:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a270 <__imp_calloc>
   140003326:	90                   	nop
   140003327:	90                   	nop

0000000140003328 <exit>:
   140003328:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a278 <__imp_exit>
   14000332e:	90                   	nop
   14000332f:	90                   	nop

0000000140003330 <fflush>:
   140003330:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a280 <__imp_fflush>
   140003336:	90                   	nop
   140003337:	90                   	nop

0000000140003338 <fprintf>:
   140003338:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a288 <__imp_fprintf>
   14000333e:	90                   	nop
   14000333f:	90                   	nop

0000000140003340 <free>:
   140003340:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a290 <__imp_free>
   140003346:	90                   	nop
   140003347:	90                   	nop

0000000140003348 <malloc>:
   140003348:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a298 <__imp_malloc>
   14000334e:	90                   	nop
   14000334f:	90                   	nop

0000000140003350 <memcpy>:
   140003350:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a2a0 <__imp_memcpy>
   140003356:	90                   	nop
   140003357:	90                   	nop

0000000140003358 <memset>:
   140003358:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a2a8 <__imp_memset>
   14000335e:	90                   	nop
   14000335f:	90                   	nop

0000000140003360 <setvbuf>:
   140003360:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a2b0 <__imp_setvbuf>
   140003366:	90                   	nop
   140003367:	90                   	nop

0000000140003368 <signal>:
   140003368:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a2b8 <__imp_signal>
   14000336e:	90                   	nop
   14000336f:	90                   	nop

0000000140003370 <strlen>:
   140003370:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a2c0 <__imp_strlen>
   140003376:	90                   	nop
   140003377:	90                   	nop

0000000140003378 <strncmp>:
   140003378:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a2c8 <__imp_strncmp>
   14000337e:	90                   	nop
   14000337f:	90                   	nop

0000000140003380 <vfprintf>:
   140003380:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a2d0 <__imp_vfprintf>
   140003386:	90                   	nop
   140003387:	90                   	nop
   140003388:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000338f:	00 

0000000140003390 <VirtualQuery>:
   140003390:	ff 25 62 6e 00 00    	jmp    QWORD PTR [rip+0x6e62]        # 14000a1f8 <__imp_VirtualQuery>
   140003396:	90                   	nop
   140003397:	90                   	nop

0000000140003398 <VirtualProtect>:
   140003398:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 14000a1f0 <__imp_VirtualProtect>
   14000339e:	90                   	nop
   14000339f:	90                   	nop

00000001400033a0 <TlsGetValue>:
   1400033a0:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 14000a1e8 <__imp_TlsGetValue>
   1400033a6:	90                   	nop
   1400033a7:	90                   	nop

00000001400033a8 <Sleep>:
   1400033a8:	ff 25 32 6e 00 00    	jmp    QWORD PTR [rip+0x6e32]        # 14000a1e0 <__imp_Sleep>
   1400033ae:	90                   	nop
   1400033af:	90                   	nop

00000001400033b0 <SetUnhandledExceptionFilter>:
   1400033b0:	ff 25 22 6e 00 00    	jmp    QWORD PTR [rip+0x6e22]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400033b6:	90                   	nop
   1400033b7:	90                   	nop

00000001400033b8 <LoadLibraryA>:
   1400033b8:	ff 25 12 6e 00 00    	jmp    QWORD PTR [rip+0x6e12]        # 14000a1d0 <__imp_LoadLibraryA>
   1400033be:	90                   	nop
   1400033bf:	90                   	nop

00000001400033c0 <LeaveCriticalSection>:
   1400033c0:	ff 25 02 6e 00 00    	jmp    QWORD PTR [rip+0x6e02]        # 14000a1c8 <__imp_LeaveCriticalSection>
   1400033c6:	90                   	nop
   1400033c7:	90                   	nop

00000001400033c8 <InitializeCriticalSection>:
   1400033c8:	ff 25 f2 6d 00 00    	jmp    QWORD PTR [rip+0x6df2]        # 14000a1c0 <__imp_InitializeCriticalSection>
   1400033ce:	90                   	nop
   1400033cf:	90                   	nop

00000001400033d0 <GetProcAddress>:
   1400033d0:	ff 25 e2 6d 00 00    	jmp    QWORD PTR [rip+0x6de2]        # 14000a1b8 <__imp_GetProcAddress>
   1400033d6:	90                   	nop
   1400033d7:	90                   	nop

00000001400033d8 <GetModuleHandleA>:
   1400033d8:	ff 25 d2 6d 00 00    	jmp    QWORD PTR [rip+0x6dd2]        # 14000a1b0 <__imp_GetModuleHandleA>
   1400033de:	90                   	nop
   1400033df:	90                   	nop

00000001400033e0 <GetLastError>:
   1400033e0:	ff 25 c2 6d 00 00    	jmp    QWORD PTR [rip+0x6dc2]        # 14000a1a8 <__imp_GetLastError>
   1400033e6:	90                   	nop
   1400033e7:	90                   	nop

00000001400033e8 <FreeLibrary>:
   1400033e8:	ff 25 b2 6d 00 00    	jmp    QWORD PTR [rip+0x6db2]        # 14000a1a0 <__imp_FreeLibrary>
   1400033ee:	90                   	nop
   1400033ef:	90                   	nop

00000001400033f0 <EnterCriticalSection>:
   1400033f0:	ff 25 a2 6d 00 00    	jmp    QWORD PTR [rip+0x6da2]        # 14000a198 <__imp_EnterCriticalSection>
   1400033f6:	90                   	nop
   1400033f7:	90                   	nop

00000001400033f8 <DeleteCriticalSection>:
   1400033f8:	ff 25 92 6d 00 00    	jmp    QWORD PTR [rip+0x6d92]        # 14000a190 <__IAT_start__>
   1400033fe:	90                   	nop
   1400033ff:	90                   	nop

0000000140003400 <register_frame_ctor>:
   140003400:	e9 6b e2 ff ff       	jmp    140001670 <__gcc_register_frame>
   140003405:	90                   	nop
   140003406:	90                   	nop
   140003407:	90                   	nop
   140003408:	90                   	nop
   140003409:	90                   	nop
   14000340a:	90                   	nop
   14000340b:	90                   	nop
   14000340c:	90                   	nop
   14000340d:	90                   	nop
   14000340e:	90                   	nop
   14000340f:	90                   	nop
