
C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\test_samples\heap_overflow\sample10_realloc_shrink_overflow\main.exe:     file format pei-x86-64


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
   140001024:	e8 67 22 00 00       	call   140003290 <fflush>
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
   14000113b:	e8 18 21 00 00       	call   140003258 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 98 20 00 00       	call   140003200 <__acrt_iob_func>
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
   140001194:	e8 df 20 00 00       	call   140003278 <abort>
   140001199:	e8 62 11 00 00       	call   140002300 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 31 90 00 00 	mov    rax,QWORD PTR [rip+0x9031]        # 14000a1e0 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 d6 1f 00 00       	call   1400031a0 <_set_invalid_parameter_handler>
   1400011ca:	e8 41 1a 00 00       	call   140002c10 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 57 20 00 00       	call   140003248 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 4b 20 00 00       	call   140003248 <__set_app_type>
   1400011fd:	e8 6e 1f 00 00       	call   140003170 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 6e 1f 00 00       	call   140003180 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 be 06 00 00       	call   1400018e0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 23 20 00 00       	call   140003258 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 c8 11 00 00       	call   14000241a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 76 1f 00 00       	call   1400031e0 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 90 1e 00 00       	call   140003110 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 ca 1f 00 00       	call   140003258 <_amsg_exit>
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
   1400012cb:	e8 68 1f 00 00       	call   140003238 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 75 1f 00 00       	call   140003258 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 4e 1f 00 00       	call   140003258 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 48 1f 00 00       	call   140003268 <_initterm>
   140001320:	e8 92 05 00 00       	call   1400018b7 <__main>
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
   14000138d:	e8 fe 1d 00 00       	call   140003190 <__p___initenv>
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
   1400013cc:	e8 b7 1e 00 00       	call   140003288 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 80 1e 00 00       	call   140003260 <_cexit>
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
   140001511:	e8 92 1d 00 00       	call   1400032a8 <malloc>
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
   140001585:	e8 1e 1d 00 00       	call   1400032a8 <malloc>
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
   1400015e8:	e8 c3 1c 00 00       	call   1400032b0 <memcpy>
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
   140001642:	e8 29 1c 00 00       	call   140003270 <_crt_atexit>
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
   140001764:	48 83 ec 30          	sub    rsp,0x30
   140001768:	e8 4a 01 00 00       	call   1400018b7 <__main>
   14000176d:	b9 40 00 00 00       	mov    ecx,0x40
   140001772:	e8 31 1b 00 00       	call   1400032a8 <malloc>
   140001777:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000177b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140001780:	75 07                	jne    140001789 <main+0x29>
   140001782:	b8 01 00 00 00       	mov    eax,0x1
   140001787:	eb 62                	jmp    1400017eb <main+0x8b>
   140001789:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000178d:	41 b8 40 00 00 00    	mov    r8d,0x40
   140001793:	ba 00 00 00 00       	mov    edx,0x0
   140001798:	48 89 c1             	mov    rcx,rax
   14000179b:	e8 18 1b 00 00       	call   1400032b8 <memset>
   1400017a0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017a4:	ba 20 00 00 00       	mov    edx,0x20
   1400017a9:	48 89 c1             	mov    rcx,rax
   1400017ac:	e8 0f 1b 00 00       	call   1400032c0 <realloc>
   1400017b1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400017b5:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400017ba:	75 07                	jne    1400017c3 <main+0x63>
   1400017bc:	b8 01 00 00 00       	mov    eax,0x1
   1400017c1:	eb 28                	jmp    1400017eb <main+0x8b>
   1400017c3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017c7:	41 b8 40 00 00 00    	mov    r8d,0x40
   1400017cd:	ba 58 00 00 00       	mov    edx,0x58
   1400017d2:	48 89 c1             	mov    rcx,rax
   1400017d5:	e8 de 1a 00 00       	call   1400032b8 <memset>
   1400017da:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017de:	48 89 c1             	mov    rcx,rax
   1400017e1:	e8 ba 1a 00 00       	call   1400032a0 <free>
   1400017e6:	b8 00 00 00 00       	mov    eax,0x0
   1400017eb:	48 83 c4 30          	add    rsp,0x30
   1400017ef:	5d                   	pop    rbp
   1400017f0:	c3                   	ret
   1400017f1:	90                   	nop
   1400017f2:	90                   	nop
   1400017f3:	90                   	nop
   1400017f4:	90                   	nop
   1400017f5:	90                   	nop
   1400017f6:	90                   	nop
   1400017f7:	90                   	nop
   1400017f8:	90                   	nop
   1400017f9:	90                   	nop
   1400017fa:	90                   	nop
   1400017fb:	90                   	nop
   1400017fc:	90                   	nop
   1400017fd:	90                   	nop
   1400017fe:	90                   	nop
   1400017ff:	90                   	nop

0000000140001800 <__do_global_dtors>:
   140001800:	55                   	push   rbp
   140001801:	48 89 e5             	mov    rbp,rsp
   140001804:	48 83 ec 20          	sub    rsp,0x20
   140001808:	eb 1e                	jmp    140001828 <__do_global_dtors+0x28>
   14000180a:	48 8b 05 ff 27 00 00 	mov    rax,QWORD PTR [rip+0x27ff]        # 140004010 <p.0>
   140001811:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001814:	ff d0                	call   rax
   140001816:	48 8b 05 f3 27 00 00 	mov    rax,QWORD PTR [rip+0x27f3]        # 140004010 <p.0>
   14000181d:	48 83 c0 08          	add    rax,0x8
   140001821:	48 89 05 e8 27 00 00 	mov    QWORD PTR [rip+0x27e8],rax        # 140004010 <p.0>
   140001828:	48 8b 05 e1 27 00 00 	mov    rax,QWORD PTR [rip+0x27e1]        # 140004010 <p.0>
   14000182f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001832:	48 85 c0             	test   rax,rax
   140001835:	75 d3                	jne    14000180a <__do_global_dtors+0xa>
   140001837:	90                   	nop
   140001838:	90                   	nop
   140001839:	48 83 c4 20          	add    rsp,0x20
   14000183d:	5d                   	pop    rbp
   14000183e:	c3                   	ret

000000014000183f <__do_global_ctors>:
   14000183f:	55                   	push   rbp
   140001840:	48 89 e5             	mov    rbp,rsp
   140001843:	48 83 ec 30          	sub    rsp,0x30
   140001847:	48 8b 05 02 3b 00 00 	mov    rax,QWORD PTR [rip+0x3b02]        # 140005350 <.refptr.__CTOR_LIST__>
   14000184e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001851:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001854:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001858:	75 25                	jne    14000187f <__do_global_ctors+0x40>
   14000185a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001861:	eb 04                	jmp    140001867 <__do_global_ctors+0x28>
   140001863:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001867:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000186a:	8d 50 01             	lea    edx,[rax+0x1]
   14000186d:	48 8b 05 dc 3a 00 00 	mov    rax,QWORD PTR [rip+0x3adc]        # 140005350 <.refptr.__CTOR_LIST__>
   140001874:	89 d2                	mov    edx,edx
   140001876:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000187a:	48 85 c0             	test   rax,rax
   14000187d:	75 e4                	jne    140001863 <__do_global_ctors+0x24>
   14000187f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001882:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001885:	eb 14                	jmp    14000189b <__do_global_ctors+0x5c>
   140001887:	48 8b 05 c2 3a 00 00 	mov    rax,QWORD PTR [rip+0x3ac2]        # 140005350 <.refptr.__CTOR_LIST__>
   14000188e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001891:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001895:	ff d0                	call   rax
   140001897:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000189b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000189f:	75 e6                	jne    140001887 <__do_global_ctors+0x48>
   1400018a1:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001800 <__do_global_dtors>
   1400018a8:	48 89 c1             	mov    rcx,rax
   1400018ab:	e8 7f fd ff ff       	call   14000162f <atexit>
   1400018b0:	90                   	nop
   1400018b1:	48 83 c4 30          	add    rsp,0x30
   1400018b5:	5d                   	pop    rbp
   1400018b6:	c3                   	ret

00000001400018b7 <__main>:
   1400018b7:	55                   	push   rbp
   1400018b8:	48 89 e5             	mov    rbp,rsp
   1400018bb:	48 83 ec 20          	sub    rsp,0x20
   1400018bf:	8b 05 bb 77 00 00    	mov    eax,DWORD PTR [rip+0x77bb]        # 140009080 <initialized>
   1400018c5:	85 c0                	test   eax,eax
   1400018c7:	75 0f                	jne    1400018d8 <__main+0x21>
   1400018c9:	c7 05 ad 77 00 00 01 	mov    DWORD PTR [rip+0x77ad],0x1        # 140009080 <initialized>
   1400018d0:	00 00 00 
   1400018d3:	e8 67 ff ff ff       	call   14000183f <__do_global_ctors>
   1400018d8:	90                   	nop
   1400018d9:	48 83 c4 20          	add    rsp,0x20
   1400018dd:	5d                   	pop    rbp
   1400018de:	c3                   	ret
   1400018df:	90                   	nop

00000001400018e0 <_setargv>:
   1400018e0:	55                   	push   rbp
   1400018e1:	48 89 e5             	mov    rbp,rsp
   1400018e4:	b8 00 00 00 00       	mov    eax,0x0
   1400018e9:	5d                   	pop    rbp
   1400018ea:	c3                   	ret
   1400018eb:	90                   	nop
   1400018ec:	90                   	nop
   1400018ed:	90                   	nop
   1400018ee:	90                   	nop
   1400018ef:	90                   	nop

00000001400018f0 <__dyn_tls_init>:
   1400018f0:	55                   	push   rbp
   1400018f1:	48 89 e5             	mov    rbp,rsp
   1400018f4:	48 83 ec 30          	sub    rsp,0x30
   1400018f8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400018fc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400018ff:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001903:	48 8b 05 26 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a26]        # 140005330 <.refptr._CRT_MT>
   14000190a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000190c:	83 f8 02             	cmp    eax,0x2
   14000190f:	74 0d                	je     14000191e <__dyn_tls_init+0x2e>
   140001911:	48 8b 05 18 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a18]        # 140005330 <.refptr._CRT_MT>
   140001918:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000191e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001922:	74 1e                	je     140001942 <__dyn_tls_init+0x52>
   140001924:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001928:	75 5b                	jne    140001985 <__dyn_tls_init+0x95>
   14000192a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000192e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001931:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001935:	49 89 c8             	mov    r8,rcx
   140001938:	48 89 c1             	mov    rcx,rax
   14000193b:	e8 d1 11 00 00       	call   140002b11 <__mingw_TLScallback>
   140001940:	eb 43                	jmp    140001985 <__dyn_tls_init+0x95>
   140001942:	48 8d 05 4f 3d 00 00 	lea    rax,[rip+0x3d4f]        # 140005698 <___crt_xd_start__>
   140001949:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000194d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001952:	eb 22                	jmp    140001976 <__dyn_tls_init+0x86>
   140001954:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001958:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000195c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001960:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001963:	48 85 c0             	test   rax,rax
   140001966:	74 09                	je     140001971 <__dyn_tls_init+0x81>
   140001968:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000196c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000196f:	ff d0                	call   rax
   140001971:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001976:	48 8d 05 23 3d 00 00 	lea    rax,[rip+0x3d23]        # 1400056a0 <__xd_z>
   14000197d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001981:	75 d1                	jne    140001954 <__dyn_tls_init+0x64>
   140001983:	eb 01                	jmp    140001986 <__dyn_tls_init+0x96>
   140001985:	90                   	nop
   140001986:	48 83 c4 30          	add    rsp,0x30
   14000198a:	5d                   	pop    rbp
   14000198b:	c3                   	ret

000000014000198c <__tlregdtor>:
   14000198c:	55                   	push   rbp
   14000198d:	48 89 e5             	mov    rbp,rsp
   140001990:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001994:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001999:	75 07                	jne    1400019a2 <__tlregdtor+0x16>
   14000199b:	b8 00 00 00 00       	mov    eax,0x0
   1400019a0:	eb 05                	jmp    1400019a7 <__tlregdtor+0x1b>
   1400019a2:	b8 00 00 00 00       	mov    eax,0x0
   1400019a7:	5d                   	pop    rbp
   1400019a8:	c3                   	ret

00000001400019a9 <__dyn_tls_dtor>:
   1400019a9:	55                   	push   rbp
   1400019aa:	48 89 e5             	mov    rbp,rsp
   1400019ad:	48 83 ec 20          	sub    rsp,0x20
   1400019b1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019b5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019b8:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019bc:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   1400019c0:	74 06                	je     1400019c8 <__dyn_tls_dtor+0x1f>
   1400019c2:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400019c6:	75 18                	jne    1400019e0 <__dyn_tls_dtor+0x37>
   1400019c8:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019cc:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019cf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019d3:	49 89 c8             	mov    r8,rcx
   1400019d6:	48 89 c1             	mov    rcx,rax
   1400019d9:	e8 33 11 00 00       	call   140002b11 <__mingw_TLScallback>
   1400019de:	eb 01                	jmp    1400019e1 <__dyn_tls_dtor+0x38>
   1400019e0:	90                   	nop
   1400019e1:	48 83 c4 20          	add    rsp,0x20
   1400019e5:	5d                   	pop    rbp
   1400019e6:	c3                   	ret
   1400019e7:	90                   	nop
   1400019e8:	90                   	nop
   1400019e9:	90                   	nop
   1400019ea:	90                   	nop
   1400019eb:	90                   	nop
   1400019ec:	90                   	nop
   1400019ed:	90                   	nop
   1400019ee:	90                   	nop
   1400019ef:	90                   	nop

00000001400019f0 <_matherr>:
   1400019f0:	55                   	push   rbp
   1400019f1:	53                   	push   rbx
   1400019f2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400019f9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400019fe:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a02:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a06:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a0b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a0f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a13:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a15:	83 f8 06             	cmp    eax,0x6
   140001a18:	74 56                	je     140001a70 <_matherr+0x80>
   140001a1a:	83 f8 06             	cmp    eax,0x6
   140001a1d:	7f 78                	jg     140001a97 <_matherr+0xa7>
   140001a1f:	83 f8 05             	cmp    eax,0x5
   140001a22:	74 59                	je     140001a7d <_matherr+0x8d>
   140001a24:	83 f8 05             	cmp    eax,0x5
   140001a27:	7f 6e                	jg     140001a97 <_matherr+0xa7>
   140001a29:	83 f8 04             	cmp    eax,0x4
   140001a2c:	74 5c                	je     140001a8a <_matherr+0x9a>
   140001a2e:	83 f8 04             	cmp    eax,0x4
   140001a31:	7f 64                	jg     140001a97 <_matherr+0xa7>
   140001a33:	83 f8 03             	cmp    eax,0x3
   140001a36:	74 2b                	je     140001a63 <_matherr+0x73>
   140001a38:	83 f8 03             	cmp    eax,0x3
   140001a3b:	7f 5a                	jg     140001a97 <_matherr+0xa7>
   140001a3d:	83 f8 01             	cmp    eax,0x1
   140001a40:	74 07                	je     140001a49 <_matherr+0x59>
   140001a42:	83 f8 02             	cmp    eax,0x2
   140001a45:	74 0f                	je     140001a56 <_matherr+0x66>
   140001a47:	eb 4e                	jmp    140001a97 <_matherr+0xa7>
   140001a49:	48 8d 05 50 36 00 00 	lea    rax,[rip+0x3650]        # 1400050a0 <.rdata>
   140001a50:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a54:	eb 4d                	jmp    140001aa3 <_matherr+0xb3>
   140001a56:	48 8d 05 62 36 00 00 	lea    rax,[rip+0x3662]        # 1400050bf <.rdata+0x1f>
   140001a5d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a61:	eb 40                	jmp    140001aa3 <_matherr+0xb3>
   140001a63:	48 8d 05 76 36 00 00 	lea    rax,[rip+0x3676]        # 1400050e0 <.rdata+0x40>
   140001a6a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a6e:	eb 33                	jmp    140001aa3 <_matherr+0xb3>
   140001a70:	48 8d 05 89 36 00 00 	lea    rax,[rip+0x3689]        # 140005100 <.rdata+0x60>
   140001a77:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a7b:	eb 26                	jmp    140001aa3 <_matherr+0xb3>
   140001a7d:	48 8d 05 a4 36 00 00 	lea    rax,[rip+0x36a4]        # 140005128 <.rdata+0x88>
   140001a84:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a88:	eb 19                	jmp    140001aa3 <_matherr+0xb3>
   140001a8a:	48 8d 05 bf 36 00 00 	lea    rax,[rip+0x36bf]        # 140005150 <.rdata+0xb0>
   140001a91:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a95:	eb 0c                	jmp    140001aa3 <_matherr+0xb3>
   140001a97:	48 8d 05 e8 36 00 00 	lea    rax,[rip+0x36e8]        # 140005186 <.rdata+0xe6>
   140001a9e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001aa2:	90                   	nop
   140001aa3:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001aa7:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001aad:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ab1:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001ab6:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001aba:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001abf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ac3:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001ac7:	b9 02 00 00 00       	mov    ecx,0x2
   140001acc:	e8 2f 17 00 00       	call   140003200 <__acrt_iob_func>
   140001ad1:	48 89 c1             	mov    rcx,rax
   140001ad4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001ad8:	48 8d 05 b9 36 00 00 	lea    rax,[rip+0x36b9]        # 140005198 <.rdata+0xf8>
   140001adf:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001ae6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001aec:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001af2:	49 89 d9             	mov    r9,rbx
   140001af5:	49 89 d0             	mov    r8,rdx
   140001af8:	48 89 c2             	mov    rdx,rax
   140001afb:	e8 98 17 00 00       	call   140003298 <fprintf>
   140001b00:	b8 00 00 00 00       	mov    eax,0x0
   140001b05:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b09:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b0d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b12:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b19:	5b                   	pop    rbx
   140001b1a:	5d                   	pop    rbp
   140001b1b:	c3                   	ret
   140001b1c:	90                   	nop
   140001b1d:	90                   	nop
   140001b1e:	90                   	nop
   140001b1f:	90                   	nop

0000000140001b20 <__report_error>:
   140001b20:	55                   	push   rbp
   140001b21:	53                   	push   rbx
   140001b22:	48 83 ec 38          	sub    rsp,0x38
   140001b26:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b2b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b2f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b33:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b37:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b3b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b3f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b43:	b9 02 00 00 00       	mov    ecx,0x2
   140001b48:	e8 b3 16 00 00       	call   140003200 <__acrt_iob_func>
   140001b4d:	48 89 c1             	mov    rcx,rax
   140001b50:	48 8d 05 79 36 00 00 	lea    rax,[rip+0x3679]        # 1400051d0 <.rdata>
   140001b57:	48 89 c2             	mov    rdx,rax
   140001b5a:	e8 39 17 00 00       	call   140003298 <fprintf>
   140001b5f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b63:	b9 02 00 00 00       	mov    ecx,0x2
   140001b68:	e8 93 16 00 00       	call   140003200 <__acrt_iob_func>
   140001b6d:	48 89 c1             	mov    rcx,rax
   140001b70:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b74:	49 89 d8             	mov    r8,rbx
   140001b77:	48 89 c2             	mov    rdx,rax
   140001b7a:	e8 69 17 00 00       	call   1400032e8 <vfprintf>
   140001b7f:	e8 f4 16 00 00       	call   140003278 <abort>
   140001b84:	90                   	nop

0000000140001b85 <mark_section_writable>:
   140001b85:	55                   	push   rbp
   140001b86:	48 89 e5             	mov    rbp,rsp
   140001b89:	48 83 ec 60          	sub    rsp,0x60
   140001b8d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b91:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001b98:	e9 82 00 00 00       	jmp    140001c1f <mark_section_writable+0x9a>
   140001b9d:	48 8b 0d 3c 75 00 00 	mov    rcx,QWORD PTR [rip+0x753c]        # 1400090e0 <the_secs>
   140001ba4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ba7:	48 63 d0             	movsxd rdx,eax
   140001baa:	48 89 d0             	mov    rax,rdx
   140001bad:	48 c1 e0 02          	shl    rax,0x2
   140001bb1:	48 01 d0             	add    rax,rdx
   140001bb4:	48 c1 e0 03          	shl    rax,0x3
   140001bb8:	48 01 c8             	add    rax,rcx
   140001bbb:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001bbf:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001bc3:	72 56                	jb     140001c1b <mark_section_writable+0x96>
   140001bc5:	48 8b 0d 14 75 00 00 	mov    rcx,QWORD PTR [rip+0x7514]        # 1400090e0 <the_secs>
   140001bcc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bcf:	48 63 d0             	movsxd rdx,eax
   140001bd2:	48 89 d0             	mov    rax,rdx
   140001bd5:	48 c1 e0 02          	shl    rax,0x2
   140001bd9:	48 01 d0             	add    rax,rdx
   140001bdc:	48 c1 e0 03          	shl    rax,0x3
   140001be0:	48 01 c8             	add    rax,rcx
   140001be3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001be7:	4c 8b 05 f2 74 00 00 	mov    r8,QWORD PTR [rip+0x74f2]        # 1400090e0 <the_secs>
   140001bee:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bf1:	48 63 d0             	movsxd rdx,eax
   140001bf4:	48 89 d0             	mov    rax,rdx
   140001bf7:	48 c1 e0 02          	shl    rax,0x2
   140001bfb:	48 01 d0             	add    rax,rdx
   140001bfe:	48 c1 e0 03          	shl    rax,0x3
   140001c02:	4c 01 c0             	add    rax,r8
   140001c05:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c09:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c0c:	89 c0                	mov    eax,eax
   140001c0e:	48 01 c8             	add    rax,rcx
   140001c11:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c15:	0f 82 41 02 00 00    	jb     140001e5c <mark_section_writable+0x2d7>
   140001c1b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c1f:	8b 05 c3 74 00 00    	mov    eax,DWORD PTR [rip+0x74c3]        # 1400090e8 <maxSections>
   140001c25:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c28:	0f 8c 6f ff ff ff    	jl     140001b9d <mark_section_writable+0x18>
   140001c2e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c32:	48 89 c1             	mov    rcx,rax
   140001c35:	e8 c1 11 00 00       	call   140002dfb <__mingw_GetSectionForAddress>
   140001c3a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c3e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c43:	75 13                	jne    140001c58 <mark_section_writable+0xd3>
   140001c45:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c49:	48 8d 0d a0 35 00 00 	lea    rcx,[rip+0x35a0]        # 1400051f0 <.rdata+0x20>
   140001c50:	48 89 c2             	mov    rdx,rax
   140001c53:	e8 c8 fe ff ff       	call   140001b20 <__report_error>
   140001c58:	48 8b 0d 81 74 00 00 	mov    rcx,QWORD PTR [rip+0x7481]        # 1400090e0 <the_secs>
   140001c5f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c62:	48 63 d0             	movsxd rdx,eax
   140001c65:	48 89 d0             	mov    rax,rdx
   140001c68:	48 c1 e0 02          	shl    rax,0x2
   140001c6c:	48 01 d0             	add    rax,rdx
   140001c6f:	48 c1 e0 03          	shl    rax,0x3
   140001c73:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c77:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c7b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c7f:	48 8b 0d 5a 74 00 00 	mov    rcx,QWORD PTR [rip+0x745a]        # 1400090e0 <the_secs>
   140001c86:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c89:	48 63 d0             	movsxd rdx,eax
   140001c8c:	48 89 d0             	mov    rax,rdx
   140001c8f:	48 c1 e0 02          	shl    rax,0x2
   140001c93:	48 01 d0             	add    rax,rdx
   140001c96:	48 c1 e0 03          	shl    rax,0x3
   140001c9a:	48 01 c8             	add    rax,rcx
   140001c9d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001ca3:	e8 9f 12 00 00       	call   140002f47 <_GetPEImageBase>
   140001ca8:	48 89 c1             	mov    rcx,rax
   140001cab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001caf:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001cb2:	41 89 c1             	mov    r9d,eax
   140001cb5:	4c 8b 05 24 74 00 00 	mov    r8,QWORD PTR [rip+0x7424]        # 1400090e0 <the_secs>
   140001cbc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cbf:	48 63 d0             	movsxd rdx,eax
   140001cc2:	48 89 d0             	mov    rax,rdx
   140001cc5:	48 c1 e0 02          	shl    rax,0x2
   140001cc9:	48 01 d0             	add    rax,rdx
   140001ccc:	48 c1 e0 03          	shl    rax,0x3
   140001cd0:	4c 01 c0             	add    rax,r8
   140001cd3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001cd7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001cdb:	48 8b 0d fe 73 00 00 	mov    rcx,QWORD PTR [rip+0x73fe]        # 1400090e0 <the_secs>
   140001ce2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ce5:	48 63 d0             	movsxd rdx,eax
   140001ce8:	48 89 d0             	mov    rax,rdx
   140001ceb:	48 c1 e0 02          	shl    rax,0x2
   140001cef:	48 01 d0             	add    rax,rdx
   140001cf2:	48 c1 e0 03          	shl    rax,0x3
   140001cf6:	48 01 c8             	add    rax,rcx
   140001cf9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001cfd:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d01:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d07:	48 89 c1             	mov    rcx,rax
   140001d0a:	48 8b 05 ef 84 00 00 	mov    rax,QWORD PTR [rip+0x84ef]        # 14000a200 <__imp_VirtualQuery>
   140001d11:	ff d0                	call   rax
   140001d13:	48 85 c0             	test   rax,rax
   140001d16:	75 3f                	jne    140001d57 <mark_section_writable+0x1d2>
   140001d18:	48 8b 0d c1 73 00 00 	mov    rcx,QWORD PTR [rip+0x73c1]        # 1400090e0 <the_secs>
   140001d1f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d22:	48 63 d0             	movsxd rdx,eax
   140001d25:	48 89 d0             	mov    rax,rdx
   140001d28:	48 c1 e0 02          	shl    rax,0x2
   140001d2c:	48 01 d0             	add    rax,rdx
   140001d2f:	48 c1 e0 03          	shl    rax,0x3
   140001d33:	48 01 c8             	add    rax,rcx
   140001d36:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d3a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d3e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d41:	89 c1                	mov    ecx,eax
   140001d43:	48 8d 05 c6 34 00 00 	lea    rax,[rip+0x34c6]        # 140005210 <.rdata+0x40>
   140001d4a:	49 89 d0             	mov    r8,rdx
   140001d4d:	89 ca                	mov    edx,ecx
   140001d4f:	48 89 c1             	mov    rcx,rax
   140001d52:	e8 c9 fd ff ff       	call   140001b20 <__report_error>
   140001d57:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d5a:	83 f8 40             	cmp    eax,0x40
   140001d5d:	0f 84 e8 00 00 00    	je     140001e4b <mark_section_writable+0x2c6>
   140001d63:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d66:	83 f8 04             	cmp    eax,0x4
   140001d69:	0f 84 dc 00 00 00    	je     140001e4b <mark_section_writable+0x2c6>
   140001d6f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d72:	3d 80 00 00 00       	cmp    eax,0x80
   140001d77:	0f 84 ce 00 00 00    	je     140001e4b <mark_section_writable+0x2c6>
   140001d7d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d80:	83 f8 08             	cmp    eax,0x8
   140001d83:	0f 84 c2 00 00 00    	je     140001e4b <mark_section_writable+0x2c6>
   140001d89:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d8c:	83 f8 02             	cmp    eax,0x2
   140001d8f:	75 09                	jne    140001d9a <mark_section_writable+0x215>
   140001d91:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001d98:	eb 07                	jmp    140001da1 <mark_section_writable+0x21c>
   140001d9a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001da1:	48 8b 0d 38 73 00 00 	mov    rcx,QWORD PTR [rip+0x7338]        # 1400090e0 <the_secs>
   140001da8:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dab:	48 63 d0             	movsxd rdx,eax
   140001dae:	48 89 d0             	mov    rax,rdx
   140001db1:	48 c1 e0 02          	shl    rax,0x2
   140001db5:	48 01 d0             	add    rax,rdx
   140001db8:	48 c1 e0 03          	shl    rax,0x3
   140001dbc:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001dc0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001dc4:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001dc8:	48 8b 0d 11 73 00 00 	mov    rcx,QWORD PTR [rip+0x7311]        # 1400090e0 <the_secs>
   140001dcf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dd2:	48 63 d0             	movsxd rdx,eax
   140001dd5:	48 89 d0             	mov    rax,rdx
   140001dd8:	48 c1 e0 02          	shl    rax,0x2
   140001ddc:	48 01 d0             	add    rax,rdx
   140001ddf:	48 c1 e0 03          	shl    rax,0x3
   140001de3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001de7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001deb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001def:	48 8b 0d ea 72 00 00 	mov    rcx,QWORD PTR [rip+0x72ea]        # 1400090e0 <the_secs>
   140001df6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001df9:	48 63 d0             	movsxd rdx,eax
   140001dfc:	48 89 d0             	mov    rax,rdx
   140001dff:	48 c1 e0 02          	shl    rax,0x2
   140001e03:	48 01 d0             	add    rax,rdx
   140001e06:	48 c1 e0 03          	shl    rax,0x3
   140001e0a:	48 01 c8             	add    rax,rcx
   140001e0d:	49 89 c0             	mov    r8,rax
   140001e10:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e14:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e18:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e1b:	4d 89 c1             	mov    r9,r8
   140001e1e:	41 89 c8             	mov    r8d,ecx
   140001e21:	48 89 c1             	mov    rcx,rax
   140001e24:	48 8b 05 cd 83 00 00 	mov    rax,QWORD PTR [rip+0x83cd]        # 14000a1f8 <__imp_VirtualProtect>
   140001e2b:	ff d0                	call   rax
   140001e2d:	85 c0                	test   eax,eax
   140001e2f:	75 1a                	jne    140001e4b <mark_section_writable+0x2c6>
   140001e31:	48 8b 05 78 83 00 00 	mov    rax,QWORD PTR [rip+0x8378]        # 14000a1b0 <__imp_GetLastError>
   140001e38:	ff d0                	call   rax
   140001e3a:	89 c2                	mov    edx,eax
   140001e3c:	48 8d 05 05 34 00 00 	lea    rax,[rip+0x3405]        # 140005248 <.rdata+0x78>
   140001e43:	48 89 c1             	mov    rcx,rax
   140001e46:	e8 d5 fc ff ff       	call   140001b20 <__report_error>
   140001e4b:	8b 05 97 72 00 00    	mov    eax,DWORD PTR [rip+0x7297]        # 1400090e8 <maxSections>
   140001e51:	83 c0 01             	add    eax,0x1
   140001e54:	89 05 8e 72 00 00    	mov    DWORD PTR [rip+0x728e],eax        # 1400090e8 <maxSections>
   140001e5a:	eb 01                	jmp    140001e5d <mark_section_writable+0x2d8>
   140001e5c:	90                   	nop
   140001e5d:	48 83 c4 60          	add    rsp,0x60
   140001e61:	5d                   	pop    rbp
   140001e62:	c3                   	ret

0000000140001e63 <restore_modified_sections>:
   140001e63:	55                   	push   rbp
   140001e64:	48 89 e5             	mov    rbp,rsp
   140001e67:	48 83 ec 30          	sub    rsp,0x30
   140001e6b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e72:	e9 ad 00 00 00       	jmp    140001f24 <restore_modified_sections+0xc1>
   140001e77:	48 8b 0d 62 72 00 00 	mov    rcx,QWORD PTR [rip+0x7262]        # 1400090e0 <the_secs>
   140001e7e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e81:	48 63 d0             	movsxd rdx,eax
   140001e84:	48 89 d0             	mov    rax,rdx
   140001e87:	48 c1 e0 02          	shl    rax,0x2
   140001e8b:	48 01 d0             	add    rax,rdx
   140001e8e:	48 c1 e0 03          	shl    rax,0x3
   140001e92:	48 01 c8             	add    rax,rcx
   140001e95:	8b 00                	mov    eax,DWORD PTR [rax]
   140001e97:	85 c0                	test   eax,eax
   140001e99:	0f 84 80 00 00 00    	je     140001f1f <restore_modified_sections+0xbc>
   140001e9f:	48 8b 0d 3a 72 00 00 	mov    rcx,QWORD PTR [rip+0x723a]        # 1400090e0 <the_secs>
   140001ea6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ea9:	48 63 d0             	movsxd rdx,eax
   140001eac:	48 89 d0             	mov    rax,rdx
   140001eaf:	48 c1 e0 02          	shl    rax,0x2
   140001eb3:	48 01 d0             	add    rax,rdx
   140001eb6:	48 c1 e0 03          	shl    rax,0x3
   140001eba:	48 01 c8             	add    rax,rcx
   140001ebd:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001ec0:	48 8b 0d 19 72 00 00 	mov    rcx,QWORD PTR [rip+0x7219]        # 1400090e0 <the_secs>
   140001ec7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eca:	48 63 d0             	movsxd rdx,eax
   140001ecd:	48 89 d0             	mov    rax,rdx
   140001ed0:	48 c1 e0 02          	shl    rax,0x2
   140001ed4:	48 01 d0             	add    rax,rdx
   140001ed7:	48 c1 e0 03          	shl    rax,0x3
   140001edb:	48 01 c8             	add    rax,rcx
   140001ede:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001ee2:	4c 8b 05 f7 71 00 00 	mov    r8,QWORD PTR [rip+0x71f7]        # 1400090e0 <the_secs>
   140001ee9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eec:	48 63 d0             	movsxd rdx,eax
   140001eef:	48 89 d0             	mov    rax,rdx
   140001ef2:	48 c1 e0 02          	shl    rax,0x2
   140001ef6:	48 01 d0             	add    rax,rdx
   140001ef9:	48 c1 e0 03          	shl    rax,0x3
   140001efd:	4c 01 c0             	add    rax,r8
   140001f00:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f04:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f08:	49 89 d1             	mov    r9,rdx
   140001f0b:	45 89 d0             	mov    r8d,r10d
   140001f0e:	48 89 ca             	mov    rdx,rcx
   140001f11:	48 89 c1             	mov    rcx,rax
   140001f14:	48 8b 05 dd 82 00 00 	mov    rax,QWORD PTR [rip+0x82dd]        # 14000a1f8 <__imp_VirtualProtect>
   140001f1b:	ff d0                	call   rax
   140001f1d:	eb 01                	jmp    140001f20 <restore_modified_sections+0xbd>
   140001f1f:	90                   	nop
   140001f20:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f24:	8b 05 be 71 00 00    	mov    eax,DWORD PTR [rip+0x71be]        # 1400090e8 <maxSections>
   140001f2a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f2d:	0f 8c 44 ff ff ff    	jl     140001e77 <restore_modified_sections+0x14>
   140001f33:	90                   	nop
   140001f34:	90                   	nop
   140001f35:	48 83 c4 30          	add    rsp,0x30
   140001f39:	5d                   	pop    rbp
   140001f3a:	c3                   	ret

0000000140001f3b <__write_memory>:
   140001f3b:	55                   	push   rbp
   140001f3c:	48 89 e5             	mov    rbp,rsp
   140001f3f:	48 83 ec 20          	sub    rsp,0x20
   140001f43:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f47:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f4b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f4f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f54:	74 25                	je     140001f7b <__write_memory+0x40>
   140001f56:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f5a:	48 89 c1             	mov    rcx,rax
   140001f5d:	e8 23 fc ff ff       	call   140001b85 <mark_section_writable>
   140001f62:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f66:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f6a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f6e:	49 89 c8             	mov    r8,rcx
   140001f71:	48 89 c1             	mov    rcx,rax
   140001f74:	e8 37 13 00 00       	call   1400032b0 <memcpy>
   140001f79:	eb 01                	jmp    140001f7c <__write_memory+0x41>
   140001f7b:	90                   	nop
   140001f7c:	48 83 c4 20          	add    rsp,0x20
   140001f80:	5d                   	pop    rbp
   140001f81:	c3                   	ret

0000000140001f82 <do_pseudo_reloc>:
   140001f82:	55                   	push   rbp
   140001f83:	48 89 e5             	mov    rbp,rsp
   140001f86:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001f8a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f8e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f92:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f96:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001f9a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001f9e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001fa2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fa6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001faa:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001faf:	0f 8e 44 03 00 00    	jle    1400022f9 <do_pseudo_reloc+0x377>
   140001fb5:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001fba:	7e 25                	jle    140001fe1 <do_pseudo_reloc+0x5f>
   140001fbc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fc0:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fc2:	85 c0                	test   eax,eax
   140001fc4:	75 1b                	jne    140001fe1 <do_pseudo_reloc+0x5f>
   140001fc6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fca:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fcd:	85 c0                	test   eax,eax
   140001fcf:	75 10                	jne    140001fe1 <do_pseudo_reloc+0x5f>
   140001fd1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fd5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001fd8:	85 c0                	test   eax,eax
   140001fda:	75 05                	jne    140001fe1 <do_pseudo_reloc+0x5f>
   140001fdc:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140001fe1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fe5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fe7:	85 c0                	test   eax,eax
   140001fe9:	75 0b                	jne    140001ff6 <do_pseudo_reloc+0x74>
   140001feb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fef:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001ff2:	85 c0                	test   eax,eax
   140001ff4:	74 59                	je     14000204f <do_pseudo_reloc+0xcd>
   140001ff6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001ffa:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001ffe:	eb 40                	jmp    140002040 <do_pseudo_reloc+0xbe>
   140002000:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002004:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002007:	89 c2                	mov    edx,eax
   140002009:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000200d:	48 01 d0             	add    rax,rdx
   140002010:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002014:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002018:	8b 10                	mov    edx,DWORD PTR [rax]
   14000201a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000201e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002020:	01 d0                	add    eax,edx
   140002022:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002025:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002029:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000202d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002033:	48 89 c1             	mov    rcx,rax
   140002036:	e8 00 ff ff ff       	call   140001f3b <__write_memory>
   14000203b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002040:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002044:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002048:	72 b6                	jb     140002000 <do_pseudo_reloc+0x7e>
   14000204a:	e9 ab 02 00 00       	jmp    1400022fa <do_pseudo_reloc+0x378>
   14000204f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002053:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002056:	83 f8 01             	cmp    eax,0x1
   140002059:	74 18                	je     140002073 <do_pseudo_reloc+0xf1>
   14000205b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000205f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002062:	89 c2                	mov    edx,eax
   140002064:	48 8d 05 05 32 00 00 	lea    rax,[rip+0x3205]        # 140005270 <.rdata+0xa0>
   14000206b:	48 89 c1             	mov    rcx,rax
   14000206e:	e8 ad fa ff ff       	call   140001b20 <__report_error>
   140002073:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002077:	48 83 c0 0c          	add    rax,0xc
   14000207b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000207f:	e9 65 02 00 00       	jmp    1400022e9 <do_pseudo_reloc+0x367>
   140002084:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002088:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000208b:	89 c2                	mov    edx,eax
   14000208d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002091:	48 01 d0             	add    rax,rdx
   140002094:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002098:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000209c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000209e:	89 c2                	mov    edx,eax
   1400020a0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020a4:	48 01 d0             	add    rax,rdx
   1400020a7:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020ab:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400020af:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400020b2:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020b6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020ba:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020bd:	0f b6 c0             	movzx  eax,al
   1400020c0:	83 f8 40             	cmp    eax,0x40
   1400020c3:	0f 84 b6 00 00 00    	je     14000217f <do_pseudo_reloc+0x1fd>
   1400020c9:	83 f8 40             	cmp    eax,0x40
   1400020cc:	0f 87 ba 00 00 00    	ja     14000218c <do_pseudo_reloc+0x20a>
   1400020d2:	83 f8 20             	cmp    eax,0x20
   1400020d5:	74 77                	je     14000214e <do_pseudo_reloc+0x1cc>
   1400020d7:	83 f8 20             	cmp    eax,0x20
   1400020da:	0f 87 ac 00 00 00    	ja     14000218c <do_pseudo_reloc+0x20a>
   1400020e0:	83 f8 08             	cmp    eax,0x8
   1400020e3:	74 0a                	je     1400020ef <do_pseudo_reloc+0x16d>
   1400020e5:	83 f8 10             	cmp    eax,0x10
   1400020e8:	74 38                	je     140002122 <do_pseudo_reloc+0x1a0>
   1400020ea:	e9 9d 00 00 00       	jmp    14000218c <do_pseudo_reloc+0x20a>
   1400020ef:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020f3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400020f6:	0f b6 c0             	movzx  eax,al
   1400020f9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020fd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002101:	25 80 00 00 00       	and    eax,0x80
   140002106:	48 85 c0             	test   rax,rax
   140002109:	0f 84 9d 00 00 00    	je     1400021ac <do_pseudo_reloc+0x22a>
   14000210f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002113:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002119:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000211d:	e9 8a 00 00 00       	jmp    1400021ac <do_pseudo_reloc+0x22a>
   140002122:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002126:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002129:	0f b7 c0             	movzx  eax,ax
   14000212c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002130:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002134:	25 00 80 00 00       	and    eax,0x8000
   140002139:	48 85 c0             	test   rax,rax
   14000213c:	74 71                	je     1400021af <do_pseudo_reloc+0x22d>
   14000213e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002142:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002148:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000214c:	eb 61                	jmp    1400021af <do_pseudo_reloc+0x22d>
   14000214e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002152:	8b 00                	mov    eax,DWORD PTR [rax]
   140002154:	89 c0                	mov    eax,eax
   140002156:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000215a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000215e:	25 00 00 00 80       	and    eax,0x80000000
   140002163:	48 85 c0             	test   rax,rax
   140002166:	74 4a                	je     1400021b2 <do_pseudo_reloc+0x230>
   140002168:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000216c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002173:	ff ff ff 
   140002176:	48 09 d0             	or     rax,rdx
   140002179:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000217d:	eb 33                	jmp    1400021b2 <do_pseudo_reloc+0x230>
   14000217f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002183:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002186:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000218a:	eb 27                	jmp    1400021b3 <do_pseudo_reloc+0x231>
   14000218c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002193:	00 
   140002194:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002198:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000219b:	0f b6 c0             	movzx  eax,al
   14000219e:	48 8d 0d 03 31 00 00 	lea    rcx,[rip+0x3103]        # 1400052a8 <.rdata+0xd8>
   1400021a5:	89 c2                	mov    edx,eax
   1400021a7:	e8 74 f9 ff ff       	call   140001b20 <__report_error>
   1400021ac:	90                   	nop
   1400021ad:	eb 04                	jmp    1400021b3 <do_pseudo_reloc+0x231>
   1400021af:	90                   	nop
   1400021b0:	eb 01                	jmp    1400021b3 <do_pseudo_reloc+0x231>
   1400021b2:	90                   	nop
   1400021b3:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   1400021b7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021bb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021bd:	89 c2                	mov    edx,eax
   1400021bf:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400021c3:	48 01 c2             	add    rdx,rax
   1400021c6:	48 89 c8             	mov    rax,rcx
   1400021c9:	48 29 d0             	sub    rax,rdx
   1400021cc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021d0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021d4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400021d8:	48 01 d0             	add    rax,rdx
   1400021db:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021df:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021e3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021e6:	25 ff 00 00 00       	and    eax,0xff
   1400021eb:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400021ee:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400021f2:	77 67                	ja     14000225b <do_pseudo_reloc+0x2d9>
   1400021f4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021f7:	ba 01 00 00 00       	mov    edx,0x1
   1400021fc:	89 c1                	mov    ecx,eax
   1400021fe:	48 d3 e2             	shl    rdx,cl
   140002201:	48 89 d0             	mov    rax,rdx
   140002204:	48 83 e8 01          	sub    rax,0x1
   140002208:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000220c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000220f:	83 e8 01             	sub    eax,0x1
   140002212:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002219:	89 c1                	mov    ecx,eax
   14000221b:	48 d3 e2             	shl    rdx,cl
   14000221e:	48 89 d0             	mov    rax,rdx
   140002221:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002225:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002229:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000222d:	7c 0a                	jl     140002239 <do_pseudo_reloc+0x2b7>
   14000222f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002233:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002237:	7e 22                	jle    14000225b <do_pseudo_reloc+0x2d9>
   140002239:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000223d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002241:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002245:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002248:	48 8d 0d 89 30 00 00 	lea    rcx,[rip+0x3089]        # 1400052d8 <.rdata+0x108>
   14000224f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002254:	89 c2                	mov    edx,eax
   140002256:	e8 c5 f8 ff ff       	call   140001b20 <__report_error>
   14000225b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000225f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002262:	0f b6 c0             	movzx  eax,al
   140002265:	83 f8 40             	cmp    eax,0x40
   140002268:	74 63                	je     1400022cd <do_pseudo_reloc+0x34b>
   14000226a:	83 f8 40             	cmp    eax,0x40
   14000226d:	77 75                	ja     1400022e4 <do_pseudo_reloc+0x362>
   14000226f:	83 f8 20             	cmp    eax,0x20
   140002272:	74 41                	je     1400022b5 <do_pseudo_reloc+0x333>
   140002274:	83 f8 20             	cmp    eax,0x20
   140002277:	77 6b                	ja     1400022e4 <do_pseudo_reloc+0x362>
   140002279:	83 f8 08             	cmp    eax,0x8
   14000227c:	74 07                	je     140002285 <do_pseudo_reloc+0x303>
   14000227e:	83 f8 10             	cmp    eax,0x10
   140002281:	74 1a                	je     14000229d <do_pseudo_reloc+0x31b>
   140002283:	eb 5f                	jmp    1400022e4 <do_pseudo_reloc+0x362>
   140002285:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002289:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000228d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002293:	48 89 c1             	mov    rcx,rax
   140002296:	e8 a0 fc ff ff       	call   140001f3b <__write_memory>
   14000229b:	eb 47                	jmp    1400022e4 <do_pseudo_reloc+0x362>
   14000229d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022a1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022a5:	41 b8 02 00 00 00    	mov    r8d,0x2
   1400022ab:	48 89 c1             	mov    rcx,rax
   1400022ae:	e8 88 fc ff ff       	call   140001f3b <__write_memory>
   1400022b3:	eb 2f                	jmp    1400022e4 <do_pseudo_reloc+0x362>
   1400022b5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022b9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022bd:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400022c3:	48 89 c1             	mov    rcx,rax
   1400022c6:	e8 70 fc ff ff       	call   140001f3b <__write_memory>
   1400022cb:	eb 17                	jmp    1400022e4 <do_pseudo_reloc+0x362>
   1400022cd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022d1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022d5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400022db:	48 89 c1             	mov    rcx,rax
   1400022de:	e8 58 fc ff ff       	call   140001f3b <__write_memory>
   1400022e3:	90                   	nop
   1400022e4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400022e9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022ed:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400022f1:	0f 82 8d fd ff ff    	jb     140002084 <do_pseudo_reloc+0x102>
   1400022f7:	eb 01                	jmp    1400022fa <do_pseudo_reloc+0x378>
   1400022f9:	90                   	nop
   1400022fa:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400022fe:	5d                   	pop    rbp
   1400022ff:	c3                   	ret

0000000140002300 <_pei386_runtime_relocator>:
   140002300:	55                   	push   rbp
   140002301:	48 89 e5             	mov    rbp,rsp
   140002304:	48 83 ec 30          	sub    rsp,0x30
   140002308:	8b 05 de 6d 00 00    	mov    eax,DWORD PTR [rip+0x6dde]        # 1400090ec <was_init.0>
   14000230e:	85 c0                	test   eax,eax
   140002310:	0f 85 88 00 00 00    	jne    14000239e <_pei386_runtime_relocator+0x9e>
   140002316:	8b 05 d0 6d 00 00    	mov    eax,DWORD PTR [rip+0x6dd0]        # 1400090ec <was_init.0>
   14000231c:	83 c0 01             	add    eax,0x1
   14000231f:	89 05 c7 6d 00 00    	mov    DWORD PTR [rip+0x6dc7],eax        # 1400090ec <was_init.0>
   140002325:	e8 21 0b 00 00       	call   140002e4b <__mingw_GetSectionCount>
   14000232a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000232d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002330:	48 63 d0             	movsxd rdx,eax
   140002333:	48 89 d0             	mov    rax,rdx
   140002336:	48 c1 e0 02          	shl    rax,0x2
   14000233a:	48 01 d0             	add    rax,rdx
   14000233d:	48 c1 e0 03          	shl    rax,0x3
   140002341:	48 83 c0 0f          	add    rax,0xf
   140002345:	48 c1 e8 04          	shr    rax,0x4
   140002349:	48 c1 e0 04          	shl    rax,0x4
   14000234d:	e8 7e 0d 00 00       	call   1400030d0 <___chkstk_ms>
   140002352:	48 29 c4             	sub    rsp,rax
   140002355:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000235a:	48 83 c0 0f          	add    rax,0xf
   14000235e:	48 c1 e8 04          	shr    rax,0x4
   140002362:	48 c1 e0 04          	shl    rax,0x4
   140002366:	48 89 05 73 6d 00 00 	mov    QWORD PTR [rip+0x6d73],rax        # 1400090e0 <the_secs>
   14000236d:	c7 05 71 6d 00 00 00 	mov    DWORD PTR [rip+0x6d71],0x0        # 1400090e8 <maxSections>
   140002374:	00 00 00 
   140002377:	48 8b 0d e2 2f 00 00 	mov    rcx,QWORD PTR [rip+0x2fe2]        # 140005360 <.refptr.__ImageBase>
   14000237e:	48 8b 15 eb 2f 00 00 	mov    rdx,QWORD PTR [rip+0x2feb]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002385:	48 8b 05 f4 2f 00 00 	mov    rax,QWORD PTR [rip+0x2ff4]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000238c:	49 89 c8             	mov    r8,rcx
   14000238f:	48 89 c1             	mov    rcx,rax
   140002392:	e8 eb fb ff ff       	call   140001f82 <do_pseudo_reloc>
   140002397:	e8 c7 fa ff ff       	call   140001e63 <restore_modified_sections>
   14000239c:	eb 01                	jmp    14000239f <_pei386_runtime_relocator+0x9f>
   14000239e:	90                   	nop
   14000239f:	48 89 ec             	mov    rsp,rbp
   1400023a2:	5d                   	pop    rbp
   1400023a3:	c3                   	ret
   1400023a4:	90                   	nop
   1400023a5:	90                   	nop
   1400023a6:	90                   	nop
   1400023a7:	90                   	nop
   1400023a8:	90                   	nop
   1400023a9:	90                   	nop
   1400023aa:	90                   	nop
   1400023ab:	90                   	nop
   1400023ac:	90                   	nop
   1400023ad:	90                   	nop
   1400023ae:	90                   	nop
   1400023af:	90                   	nop

00000001400023b0 <__mingw_raise_matherr>:
   1400023b0:	55                   	push   rbp
   1400023b1:	48 89 e5             	mov    rbp,rsp
   1400023b4:	48 83 ec 50          	sub    rsp,0x50
   1400023b8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400023bb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400023bf:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   1400023c4:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   1400023c9:	48 8b 05 20 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d20]        # 1400090f0 <stUserMathErr>
   1400023d0:	48 85 c0             	test   rax,rax
   1400023d3:	74 3e                	je     140002413 <__mingw_raise_matherr+0x63>
   1400023d5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400023d8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400023db:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400023df:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400023e3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400023e8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400023ed:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400023f2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400023f7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400023fc:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002401:	48 8b 15 e8 6c 00 00 	mov    rdx,QWORD PTR [rip+0x6ce8]        # 1400090f0 <stUserMathErr>
   140002408:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000240c:	48 89 c1             	mov    rcx,rax
   14000240f:	ff d2                	call   rdx
   140002411:	eb 01                	jmp    140002414 <__mingw_raise_matherr+0x64>
   140002413:	90                   	nop
   140002414:	48 83 c4 50          	add    rsp,0x50
   140002418:	5d                   	pop    rbp
   140002419:	c3                   	ret

000000014000241a <__mingw_setusermatherr>:
   14000241a:	55                   	push   rbp
   14000241b:	48 89 e5             	mov    rbp,rsp
   14000241e:	48 83 ec 20          	sub    rsp,0x20
   140002422:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002426:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000242a:	48 89 05 bf 6c 00 00 	mov    QWORD PTR [rip+0x6cbf],rax        # 1400090f0 <stUserMathErr>
   140002431:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002435:	48 89 c1             	mov    rcx,rax
   140002438:	e8 13 0e 00 00       	call   140003250 <__setusermatherr>
   14000243d:	90                   	nop
   14000243e:	48 83 c4 20          	add    rsp,0x20
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

0000000140002450 <__mingw_SEH_error_handler>:
   140002450:	55                   	push   rbp
   140002451:	48 89 e5             	mov    rbp,rsp
   140002454:	48 83 ec 30          	sub    rsp,0x30
   140002458:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000245c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002460:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002464:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002468:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000246f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002476:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000247a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000247d:	83 e0 02             	and    eax,0x2
   140002480:	85 c0                	test   eax,eax
   140002482:	74 0a                	je     14000248e <__mingw_SEH_error_handler+0x3e>
   140002484:	b8 01 00 00 00       	mov    eax,0x1
   140002489:	e9 16 02 00 00       	jmp    1400026a4 <__mingw_SEH_error_handler+0x254>
   14000248e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002492:	8b 00                	mov    eax,DWORD PTR [rax]
   140002494:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002499:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000249e:	75 18                	jne    1400024b8 <__mingw_SEH_error_handler+0x68>
   1400024a0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024a4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024a7:	83 e0 01             	and    eax,0x1
   1400024aa:	85 c0                	test   eax,eax
   1400024ac:	75 0a                	jne    1400024b8 <__mingw_SEH_error_handler+0x68>
   1400024ae:	b8 00 00 00 00       	mov    eax,0x0
   1400024b3:	e9 ec 01 00 00       	jmp    1400026a4 <__mingw_SEH_error_handler+0x254>
   1400024b8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024bc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024be:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024c3:	0f 84 12 01 00 00    	je     1400025db <__mingw_SEH_error_handler+0x18b>
   1400024c9:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024ce:	0f 87 c3 01 00 00    	ja     140002697 <__mingw_SEH_error_handler+0x247>
   1400024d4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400024d9:	0f 87 b8 01 00 00    	ja     140002697 <__mingw_SEH_error_handler+0x247>
   1400024df:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400024e4:	0f 83 4c 01 00 00    	jae    140002636 <__mingw_SEH_error_handler+0x1e6>
   1400024ea:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024ef:	0f 84 3a 01 00 00    	je     14000262f <__mingw_SEH_error_handler+0x1df>
   1400024f5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024fa:	0f 87 97 01 00 00    	ja     140002697 <__mingw_SEH_error_handler+0x247>
   140002500:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002505:	0f 84 83 01 00 00    	je     14000268e <__mingw_SEH_error_handler+0x23e>
   14000250b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002510:	0f 87 81 01 00 00    	ja     140002697 <__mingw_SEH_error_handler+0x247>
   140002516:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000251b:	0f 87 76 01 00 00    	ja     140002697 <__mingw_SEH_error_handler+0x247>
   140002521:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002526:	0f 83 03 01 00 00    	jae    14000262f <__mingw_SEH_error_handler+0x1df>
   14000252c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002531:	0f 84 57 01 00 00    	je     14000268e <__mingw_SEH_error_handler+0x23e>
   140002537:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000253c:	0f 87 55 01 00 00    	ja     140002697 <__mingw_SEH_error_handler+0x247>
   140002542:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002547:	0f 84 8e 00 00 00    	je     1400025db <__mingw_SEH_error_handler+0x18b>
   14000254d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002552:	0f 87 3f 01 00 00    	ja     140002697 <__mingw_SEH_error_handler+0x247>
   140002558:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000255d:	0f 84 2b 01 00 00    	je     14000268e <__mingw_SEH_error_handler+0x23e>
   140002563:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002568:	0f 87 29 01 00 00    	ja     140002697 <__mingw_SEH_error_handler+0x247>
   14000256e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002573:	0f 84 15 01 00 00    	je     14000268e <__mingw_SEH_error_handler+0x23e>
   140002579:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000257e:	0f 85 13 01 00 00    	jne    140002697 <__mingw_SEH_error_handler+0x247>
   140002584:	ba 00 00 00 00       	mov    edx,0x0
   140002589:	b9 0b 00 00 00       	mov    ecx,0xb
   14000258e:	e8 3d 0d 00 00       	call   1400032d0 <signal>
   140002593:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002597:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000259c:	75 1b                	jne    1400025b9 <__mingw_SEH_error_handler+0x169>
   14000259e:	ba 01 00 00 00       	mov    edx,0x1
   1400025a3:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025a8:	e8 23 0d 00 00       	call   1400032d0 <signal>
   1400025ad:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025b4:	e9 e1 00 00 00       	jmp    14000269a <__mingw_SEH_error_handler+0x24a>
   1400025b9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025be:	0f 84 d6 00 00 00    	je     14000269a <__mingw_SEH_error_handler+0x24a>
   1400025c4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025c8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025cd:	ff d0                	call   rax
   1400025cf:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025d6:	e9 bf 00 00 00       	jmp    14000269a <__mingw_SEH_error_handler+0x24a>
   1400025db:	ba 00 00 00 00       	mov    edx,0x0
   1400025e0:	b9 04 00 00 00       	mov    ecx,0x4
   1400025e5:	e8 e6 0c 00 00       	call   1400032d0 <signal>
   1400025ea:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025ee:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025f3:	75 1b                	jne    140002610 <__mingw_SEH_error_handler+0x1c0>
   1400025f5:	ba 01 00 00 00       	mov    edx,0x1
   1400025fa:	b9 04 00 00 00       	mov    ecx,0x4
   1400025ff:	e8 cc 0c 00 00       	call   1400032d0 <signal>
   140002604:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000260b:	e9 8d 00 00 00       	jmp    14000269d <__mingw_SEH_error_handler+0x24d>
   140002610:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002615:	0f 84 82 00 00 00    	je     14000269d <__mingw_SEH_error_handler+0x24d>
   14000261b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000261f:	b9 04 00 00 00       	mov    ecx,0x4
   140002624:	ff d0                	call   rax
   140002626:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000262d:	eb 6e                	jmp    14000269d <__mingw_SEH_error_handler+0x24d>
   14000262f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002636:	ba 00 00 00 00       	mov    edx,0x0
   14000263b:	b9 08 00 00 00       	mov    ecx,0x8
   140002640:	e8 8b 0c 00 00       	call   1400032d0 <signal>
   140002645:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002649:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000264e:	75 23                	jne    140002673 <__mingw_SEH_error_handler+0x223>
   140002650:	ba 01 00 00 00       	mov    edx,0x1
   140002655:	b9 08 00 00 00       	mov    ecx,0x8
   14000265a:	e8 71 0c 00 00       	call   1400032d0 <signal>
   14000265f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002663:	74 05                	je     14000266a <__mingw_SEH_error_handler+0x21a>
   140002665:	e8 a6 05 00 00       	call   140002c10 <_fpreset>
   14000266a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002671:	eb 2d                	jmp    1400026a0 <__mingw_SEH_error_handler+0x250>
   140002673:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002678:	74 26                	je     1400026a0 <__mingw_SEH_error_handler+0x250>
   14000267a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000267e:	b9 08 00 00 00       	mov    ecx,0x8
   140002683:	ff d0                	call   rax
   140002685:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000268c:	eb 12                	jmp    1400026a0 <__mingw_SEH_error_handler+0x250>
   14000268e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002695:	eb 0a                	jmp    1400026a1 <__mingw_SEH_error_handler+0x251>
   140002697:	90                   	nop
   140002698:	eb 07                	jmp    1400026a1 <__mingw_SEH_error_handler+0x251>
   14000269a:	90                   	nop
   14000269b:	eb 04                	jmp    1400026a1 <__mingw_SEH_error_handler+0x251>
   14000269d:	90                   	nop
   14000269e:	eb 01                	jmp    1400026a1 <__mingw_SEH_error_handler+0x251>
   1400026a0:	90                   	nop
   1400026a1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400026a4:	48 83 c4 30          	add    rsp,0x30
   1400026a8:	5d                   	pop    rbp
   1400026a9:	c3                   	ret

00000001400026aa <_gnu_exception_handler>:
   1400026aa:	55                   	push   rbp
   1400026ab:	48 89 e5             	mov    rbp,rsp
   1400026ae:	48 83 ec 30          	sub    rsp,0x30
   1400026b2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400026b6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026bd:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400026c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026c8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026cb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026cd:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400026d2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400026d7:	75 1b                	jne    1400026f4 <_gnu_exception_handler+0x4a>
   1400026d9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026dd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026e0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400026e3:	83 e0 01             	and    eax,0x1
   1400026e6:	85 c0                	test   eax,eax
   1400026e8:	75 0a                	jne    1400026f4 <_gnu_exception_handler+0x4a>
   1400026ea:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400026ef:	e9 14 02 00 00       	jmp    140002908 <_gnu_exception_handler+0x25e>
   1400026f4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026f8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026fb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026fd:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002702:	0f 84 12 01 00 00    	je     14000281a <_gnu_exception_handler+0x170>
   140002708:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000270d:	0f 87 c3 01 00 00    	ja     1400028d6 <_gnu_exception_handler+0x22c>
   140002713:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002718:	0f 87 b8 01 00 00    	ja     1400028d6 <_gnu_exception_handler+0x22c>
   14000271e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002723:	0f 83 4c 01 00 00    	jae    140002875 <_gnu_exception_handler+0x1cb>
   140002729:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000272e:	0f 84 3a 01 00 00    	je     14000286e <_gnu_exception_handler+0x1c4>
   140002734:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002739:	0f 87 97 01 00 00    	ja     1400028d6 <_gnu_exception_handler+0x22c>
   14000273f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002744:	0f 84 83 01 00 00    	je     1400028cd <_gnu_exception_handler+0x223>
   14000274a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000274f:	0f 87 81 01 00 00    	ja     1400028d6 <_gnu_exception_handler+0x22c>
   140002755:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000275a:	0f 87 76 01 00 00    	ja     1400028d6 <_gnu_exception_handler+0x22c>
   140002760:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002765:	0f 83 03 01 00 00    	jae    14000286e <_gnu_exception_handler+0x1c4>
   14000276b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002770:	0f 84 57 01 00 00    	je     1400028cd <_gnu_exception_handler+0x223>
   140002776:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000277b:	0f 87 55 01 00 00    	ja     1400028d6 <_gnu_exception_handler+0x22c>
   140002781:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002786:	0f 84 8e 00 00 00    	je     14000281a <_gnu_exception_handler+0x170>
   14000278c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002791:	0f 87 3f 01 00 00    	ja     1400028d6 <_gnu_exception_handler+0x22c>
   140002797:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000279c:	0f 84 2b 01 00 00    	je     1400028cd <_gnu_exception_handler+0x223>
   1400027a2:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027a7:	0f 87 29 01 00 00    	ja     1400028d6 <_gnu_exception_handler+0x22c>
   1400027ad:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400027b2:	0f 84 15 01 00 00    	je     1400028cd <_gnu_exception_handler+0x223>
   1400027b8:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400027bd:	0f 85 13 01 00 00    	jne    1400028d6 <_gnu_exception_handler+0x22c>
   1400027c3:	ba 00 00 00 00       	mov    edx,0x0
   1400027c8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027cd:	e8 fe 0a 00 00       	call   1400032d0 <signal>
   1400027d2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027d6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027db:	75 1b                	jne    1400027f8 <_gnu_exception_handler+0x14e>
   1400027dd:	ba 01 00 00 00       	mov    edx,0x1
   1400027e2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027e7:	e8 e4 0a 00 00       	call   1400032d0 <signal>
   1400027ec:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027f3:	e9 e1 00 00 00       	jmp    1400028d9 <_gnu_exception_handler+0x22f>
   1400027f8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027fd:	0f 84 d6 00 00 00    	je     1400028d9 <_gnu_exception_handler+0x22f>
   140002803:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002807:	b9 0b 00 00 00       	mov    ecx,0xb
   14000280c:	ff d0                	call   rax
   14000280e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002815:	e9 bf 00 00 00       	jmp    1400028d9 <_gnu_exception_handler+0x22f>
   14000281a:	ba 00 00 00 00       	mov    edx,0x0
   14000281f:	b9 04 00 00 00       	mov    ecx,0x4
   140002824:	e8 a7 0a 00 00       	call   1400032d0 <signal>
   140002829:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000282d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002832:	75 1b                	jne    14000284f <_gnu_exception_handler+0x1a5>
   140002834:	ba 01 00 00 00       	mov    edx,0x1
   140002839:	b9 04 00 00 00       	mov    ecx,0x4
   14000283e:	e8 8d 0a 00 00       	call   1400032d0 <signal>
   140002843:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000284a:	e9 8d 00 00 00       	jmp    1400028dc <_gnu_exception_handler+0x232>
   14000284f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002854:	0f 84 82 00 00 00    	je     1400028dc <_gnu_exception_handler+0x232>
   14000285a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000285e:	b9 04 00 00 00       	mov    ecx,0x4
   140002863:	ff d0                	call   rax
   140002865:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000286c:	eb 6e                	jmp    1400028dc <_gnu_exception_handler+0x232>
   14000286e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002875:	ba 00 00 00 00       	mov    edx,0x0
   14000287a:	b9 08 00 00 00       	mov    ecx,0x8
   14000287f:	e8 4c 0a 00 00       	call   1400032d0 <signal>
   140002884:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002888:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000288d:	75 23                	jne    1400028b2 <_gnu_exception_handler+0x208>
   14000288f:	ba 01 00 00 00       	mov    edx,0x1
   140002894:	b9 08 00 00 00       	mov    ecx,0x8
   140002899:	e8 32 0a 00 00       	call   1400032d0 <signal>
   14000289e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400028a2:	74 05                	je     1400028a9 <_gnu_exception_handler+0x1ff>
   1400028a4:	e8 67 03 00 00       	call   140002c10 <_fpreset>
   1400028a9:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028b0:	eb 2d                	jmp    1400028df <_gnu_exception_handler+0x235>
   1400028b2:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028b7:	74 26                	je     1400028df <_gnu_exception_handler+0x235>
   1400028b9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028bd:	b9 08 00 00 00       	mov    ecx,0x8
   1400028c2:	ff d0                	call   rax
   1400028c4:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028cb:	eb 12                	jmp    1400028df <_gnu_exception_handler+0x235>
   1400028cd:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028d4:	eb 0a                	jmp    1400028e0 <_gnu_exception_handler+0x236>
   1400028d6:	90                   	nop
   1400028d7:	eb 07                	jmp    1400028e0 <_gnu_exception_handler+0x236>
   1400028d9:	90                   	nop
   1400028da:	eb 04                	jmp    1400028e0 <_gnu_exception_handler+0x236>
   1400028dc:	90                   	nop
   1400028dd:	eb 01                	jmp    1400028e0 <_gnu_exception_handler+0x236>
   1400028df:	90                   	nop
   1400028e0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400028e4:	75 1f                	jne    140002905 <_gnu_exception_handler+0x25b>
   1400028e6:	48 8b 05 23 68 00 00 	mov    rax,QWORD PTR [rip+0x6823]        # 140009110 <__mingw_oldexcpt_handler>
   1400028ed:	48 85 c0             	test   rax,rax
   1400028f0:	74 13                	je     140002905 <_gnu_exception_handler+0x25b>
   1400028f2:	48 8b 15 17 68 00 00 	mov    rdx,QWORD PTR [rip+0x6817]        # 140009110 <__mingw_oldexcpt_handler>
   1400028f9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028fd:	48 89 c1             	mov    rcx,rax
   140002900:	ff d2                	call   rdx
   140002902:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002905:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002908:	48 83 c4 30          	add    rsp,0x30
   14000290c:	5d                   	pop    rbp
   14000290d:	c3                   	ret
   14000290e:	90                   	nop
   14000290f:	90                   	nop

0000000140002910 <___w64_mingwthr_add_key_dtor>:
   140002910:	55                   	push   rbp
   140002911:	48 89 e5             	mov    rbp,rsp
   140002914:	48 83 ec 30          	sub    rsp,0x30
   140002918:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000291b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000291f:	8b 05 23 68 00 00    	mov    eax,DWORD PTR [rip+0x6823]        # 140009148 <__mingwthr_cs_init>
   140002925:	85 c0                	test   eax,eax
   140002927:	75 07                	jne    140002930 <___w64_mingwthr_add_key_dtor+0x20>
   140002929:	b8 00 00 00 00       	mov    eax,0x0
   14000292e:	eb 7b                	jmp    1400029ab <___w64_mingwthr_add_key_dtor+0x9b>
   140002930:	ba 18 00 00 00       	mov    edx,0x18
   140002935:	b9 01 00 00 00       	mov    ecx,0x1
   14000293a:	e8 41 09 00 00       	call   140003280 <calloc>
   14000293f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002943:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002948:	75 07                	jne    140002951 <___w64_mingwthr_add_key_dtor+0x41>
   14000294a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000294f:	eb 5a                	jmp    1400029ab <___w64_mingwthr_add_key_dtor+0x9b>
   140002951:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002955:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002958:	89 10                	mov    DWORD PTR [rax],edx
   14000295a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000295e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002962:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002966:	48 8d 05 b3 67 00 00 	lea    rax,[rip+0x67b3]        # 140009120 <__mingwthr_cs>
   14000296d:	48 89 c1             	mov    rcx,rax
   140002970:	48 8b 05 29 78 00 00 	mov    rax,QWORD PTR [rip+0x7829]        # 14000a1a0 <__imp_EnterCriticalSection>
   140002977:	ff d0                	call   rax
   140002979:	48 8b 15 d0 67 00 00 	mov    rdx,QWORD PTR [rip+0x67d0]        # 140009150 <key_dtor_list>
   140002980:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002984:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002988:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000298c:	48 89 05 bd 67 00 00 	mov    QWORD PTR [rip+0x67bd],rax        # 140009150 <key_dtor_list>
   140002993:	48 8d 05 86 67 00 00 	lea    rax,[rip+0x6786]        # 140009120 <__mingwthr_cs>
   14000299a:	48 89 c1             	mov    rcx,rax
   14000299d:	48 8b 05 2c 78 00 00 	mov    rax,QWORD PTR [rip+0x782c]        # 14000a1d0 <__imp_LeaveCriticalSection>
   1400029a4:	ff d0                	call   rax
   1400029a6:	b8 00 00 00 00       	mov    eax,0x0
   1400029ab:	48 83 c4 30          	add    rsp,0x30
   1400029af:	5d                   	pop    rbp
   1400029b0:	c3                   	ret

00000001400029b1 <___w64_mingwthr_remove_key_dtor>:
   1400029b1:	55                   	push   rbp
   1400029b2:	48 89 e5             	mov    rbp,rsp
   1400029b5:	48 83 ec 30          	sub    rsp,0x30
   1400029b9:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029bc:	8b 05 86 67 00 00    	mov    eax,DWORD PTR [rip+0x6786]        # 140009148 <__mingwthr_cs_init>
   1400029c2:	85 c0                	test   eax,eax
   1400029c4:	75 0a                	jne    1400029d0 <___w64_mingwthr_remove_key_dtor+0x1f>
   1400029c6:	b8 00 00 00 00       	mov    eax,0x0
   1400029cb:	e9 9c 00 00 00       	jmp    140002a6c <___w64_mingwthr_remove_key_dtor+0xbb>
   1400029d0:	48 8d 05 49 67 00 00 	lea    rax,[rip+0x6749]        # 140009120 <__mingwthr_cs>
   1400029d7:	48 89 c1             	mov    rcx,rax
   1400029da:	48 8b 05 bf 77 00 00 	mov    rax,QWORD PTR [rip+0x77bf]        # 14000a1a0 <__imp_EnterCriticalSection>
   1400029e1:	ff d0                	call   rax
   1400029e3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400029ea:	00 
   1400029eb:	48 8b 05 5e 67 00 00 	mov    rax,QWORD PTR [rip+0x675e]        # 140009150 <key_dtor_list>
   1400029f2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029f6:	eb 55                	jmp    140002a4d <___w64_mingwthr_remove_key_dtor+0x9c>
   1400029f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029fc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400029fe:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a01:	75 36                	jne    140002a39 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a03:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a08:	75 11                	jne    140002a1b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a0a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a0e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a12:	48 89 05 37 67 00 00 	mov    QWORD PTR [rip+0x6737],rax        # 140009150 <key_dtor_list>
   140002a19:	eb 10                	jmp    140002a2b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a1b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a1f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a23:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a27:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a2b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a2f:	48 89 c1             	mov    rcx,rax
   140002a32:	e8 69 08 00 00       	call   1400032a0 <free>
   140002a37:	eb 1b                	jmp    140002a54 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a39:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a3d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a41:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a45:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a49:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a4d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a52:	75 a4                	jne    1400029f8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a54:	48 8d 05 c5 66 00 00 	lea    rax,[rip+0x66c5]        # 140009120 <__mingwthr_cs>
   140002a5b:	48 89 c1             	mov    rcx,rax
   140002a5e:	48 8b 05 6b 77 00 00 	mov    rax,QWORD PTR [rip+0x776b]        # 14000a1d0 <__imp_LeaveCriticalSection>
   140002a65:	ff d0                	call   rax
   140002a67:	b8 00 00 00 00       	mov    eax,0x0
   140002a6c:	48 83 c4 30          	add    rsp,0x30
   140002a70:	5d                   	pop    rbp
   140002a71:	c3                   	ret

0000000140002a72 <__mingwthr_run_key_dtors>:
   140002a72:	55                   	push   rbp
   140002a73:	48 89 e5             	mov    rbp,rsp
   140002a76:	48 83 ec 30          	sub    rsp,0x30
   140002a7a:	8b 05 c8 66 00 00    	mov    eax,DWORD PTR [rip+0x66c8]        # 140009148 <__mingwthr_cs_init>
   140002a80:	85 c0                	test   eax,eax
   140002a82:	0f 84 82 00 00 00    	je     140002b0a <__mingwthr_run_key_dtors+0x98>
   140002a88:	48 8d 05 91 66 00 00 	lea    rax,[rip+0x6691]        # 140009120 <__mingwthr_cs>
   140002a8f:	48 89 c1             	mov    rcx,rax
   140002a92:	48 8b 05 07 77 00 00 	mov    rax,QWORD PTR [rip+0x7707]        # 14000a1a0 <__imp_EnterCriticalSection>
   140002a99:	ff d0                	call   rax
   140002a9b:	48 8b 05 ae 66 00 00 	mov    rax,QWORD PTR [rip+0x66ae]        # 140009150 <key_dtor_list>
   140002aa2:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002aa6:	eb 46                	jmp    140002aee <__mingwthr_run_key_dtors+0x7c>
   140002aa8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002aac:	8b 00                	mov    eax,DWORD PTR [rax]
   140002aae:	89 c1                	mov    ecx,eax
   140002ab0:	48 8b 05 39 77 00 00 	mov    rax,QWORD PTR [rip+0x7739]        # 14000a1f0 <__imp_TlsGetValue>
   140002ab7:	ff d0                	call   rax
   140002ab9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002abd:	48 8b 05 ec 76 00 00 	mov    rax,QWORD PTR [rip+0x76ec]        # 14000a1b0 <__imp_GetLastError>
   140002ac4:	ff d0                	call   rax
   140002ac6:	85 c0                	test   eax,eax
   140002ac8:	75 18                	jne    140002ae2 <__mingwthr_run_key_dtors+0x70>
   140002aca:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002acf:	74 11                	je     140002ae2 <__mingwthr_run_key_dtors+0x70>
   140002ad1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ad5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002ad9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002add:	48 89 c1             	mov    rcx,rax
   140002ae0:	ff d2                	call   rdx
   140002ae2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ae6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002aea:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002aee:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002af3:	75 b3                	jne    140002aa8 <__mingwthr_run_key_dtors+0x36>
   140002af5:	48 8d 05 24 66 00 00 	lea    rax,[rip+0x6624]        # 140009120 <__mingwthr_cs>
   140002afc:	48 89 c1             	mov    rcx,rax
   140002aff:	48 8b 05 ca 76 00 00 	mov    rax,QWORD PTR [rip+0x76ca]        # 14000a1d0 <__imp_LeaveCriticalSection>
   140002b06:	ff d0                	call   rax
   140002b08:	eb 01                	jmp    140002b0b <__mingwthr_run_key_dtors+0x99>
   140002b0a:	90                   	nop
   140002b0b:	48 83 c4 30          	add    rsp,0x30
   140002b0f:	5d                   	pop    rbp
   140002b10:	c3                   	ret

0000000140002b11 <__mingw_TLScallback>:
   140002b11:	55                   	push   rbp
   140002b12:	48 89 e5             	mov    rbp,rsp
   140002b15:	48 83 ec 30          	sub    rsp,0x30
   140002b19:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b1d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b20:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b24:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b28:	0f 84 cc 00 00 00    	je     140002bfa <__mingw_TLScallback+0xe9>
   140002b2e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b32:	0f 87 ca 00 00 00    	ja     140002c02 <__mingw_TLScallback+0xf1>
   140002b38:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b3c:	0f 84 b1 00 00 00    	je     140002bf3 <__mingw_TLScallback+0xe2>
   140002b42:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b46:	0f 87 b6 00 00 00    	ja     140002c02 <__mingw_TLScallback+0xf1>
   140002b4c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b50:	74 33                	je     140002b85 <__mingw_TLScallback+0x74>
   140002b52:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b56:	0f 85 a6 00 00 00    	jne    140002c02 <__mingw_TLScallback+0xf1>
   140002b5c:	8b 05 e6 65 00 00    	mov    eax,DWORD PTR [rip+0x65e6]        # 140009148 <__mingwthr_cs_init>
   140002b62:	85 c0                	test   eax,eax
   140002b64:	75 13                	jne    140002b79 <__mingw_TLScallback+0x68>
   140002b66:	48 8d 05 b3 65 00 00 	lea    rax,[rip+0x65b3]        # 140009120 <__mingwthr_cs>
   140002b6d:	48 89 c1             	mov    rcx,rax
   140002b70:	48 8b 05 51 76 00 00 	mov    rax,QWORD PTR [rip+0x7651]        # 14000a1c8 <__imp_InitializeCriticalSection>
   140002b77:	ff d0                	call   rax
   140002b79:	c7 05 c5 65 00 00 01 	mov    DWORD PTR [rip+0x65c5],0x1        # 140009148 <__mingwthr_cs_init>
   140002b80:	00 00 00 
   140002b83:	eb 7d                	jmp    140002c02 <__mingw_TLScallback+0xf1>
   140002b85:	e8 e8 fe ff ff       	call   140002a72 <__mingwthr_run_key_dtors>
   140002b8a:	8b 05 b8 65 00 00    	mov    eax,DWORD PTR [rip+0x65b8]        # 140009148 <__mingwthr_cs_init>
   140002b90:	83 f8 01             	cmp    eax,0x1
   140002b93:	75 6c                	jne    140002c01 <__mingw_TLScallback+0xf0>
   140002b95:	48 8b 05 b4 65 00 00 	mov    rax,QWORD PTR [rip+0x65b4]        # 140009150 <key_dtor_list>
   140002b9c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ba0:	eb 20                	jmp    140002bc2 <__mingw_TLScallback+0xb1>
   140002ba2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ba6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002baa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002bae:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bb2:	48 89 c1             	mov    rcx,rax
   140002bb5:	e8 e6 06 00 00       	call   1400032a0 <free>
   140002bba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bbe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bc2:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002bc7:	75 d9                	jne    140002ba2 <__mingw_TLScallback+0x91>
   140002bc9:	48 c7 05 7c 65 00 00 	mov    QWORD PTR [rip+0x657c],0x0        # 140009150 <key_dtor_list>
   140002bd0:	00 00 00 00 
   140002bd4:	c7 05 6a 65 00 00 00 	mov    DWORD PTR [rip+0x656a],0x0        # 140009148 <__mingwthr_cs_init>
   140002bdb:	00 00 00 
   140002bde:	48 8d 05 3b 65 00 00 	lea    rax,[rip+0x653b]        # 140009120 <__mingwthr_cs>
   140002be5:	48 89 c1             	mov    rcx,rax
   140002be8:	48 8b 05 a9 75 00 00 	mov    rax,QWORD PTR [rip+0x75a9]        # 14000a198 <__IAT_start__>
   140002bef:	ff d0                	call   rax
   140002bf1:	eb 0e                	jmp    140002c01 <__mingw_TLScallback+0xf0>
   140002bf3:	e8 18 00 00 00       	call   140002c10 <_fpreset>
   140002bf8:	eb 08                	jmp    140002c02 <__mingw_TLScallback+0xf1>
   140002bfa:	e8 73 fe ff ff       	call   140002a72 <__mingwthr_run_key_dtors>
   140002bff:	eb 01                	jmp    140002c02 <__mingw_TLScallback+0xf1>
   140002c01:	90                   	nop
   140002c02:	b8 01 00 00 00       	mov    eax,0x1
   140002c07:	48 83 c4 30          	add    rsp,0x30
   140002c0b:	5d                   	pop    rbp
   140002c0c:	c3                   	ret
   140002c0d:	90                   	nop
   140002c0e:	90                   	nop
   140002c0f:	90                   	nop

0000000140002c10 <_fpreset>:
   140002c10:	55                   	push   rbp
   140002c11:	48 89 e5             	mov    rbp,rsp
   140002c14:	db e3                	fninit
   140002c16:	90                   	nop
   140002c17:	5d                   	pop    rbp
   140002c18:	c3                   	ret
   140002c19:	90                   	nop
   140002c1a:	90                   	nop
   140002c1b:	90                   	nop
   140002c1c:	90                   	nop
   140002c1d:	90                   	nop
   140002c1e:	90                   	nop
   140002c1f:	90                   	nop

0000000140002c20 <_ValidateImageBase>:
   140002c20:	55                   	push   rbp
   140002c21:	48 89 e5             	mov    rbp,rsp
   140002c24:	48 83 ec 20          	sub    rsp,0x20
   140002c28:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c2c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c30:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c34:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c38:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c3b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c3f:	74 07                	je     140002c48 <_ValidateImageBase+0x28>
   140002c41:	b8 00 00 00 00       	mov    eax,0x0
   140002c46:	eb 4e                	jmp    140002c96 <_ValidateImageBase+0x76>
   140002c48:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c4c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c4f:	48 63 d0             	movsxd rdx,eax
   140002c52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c56:	48 01 d0             	add    rax,rdx
   140002c59:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c5d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c61:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c63:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c68:	74 07                	je     140002c71 <_ValidateImageBase+0x51>
   140002c6a:	b8 00 00 00 00       	mov    eax,0x0
   140002c6f:	eb 25                	jmp    140002c96 <_ValidateImageBase+0x76>
   140002c71:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c75:	48 83 c0 18          	add    rax,0x18
   140002c79:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c7d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c81:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c84:	66 3d 0b 02          	cmp    ax,0x20b
   140002c88:	74 07                	je     140002c91 <_ValidateImageBase+0x71>
   140002c8a:	b8 00 00 00 00       	mov    eax,0x0
   140002c8f:	eb 05                	jmp    140002c96 <_ValidateImageBase+0x76>
   140002c91:	b8 01 00 00 00       	mov    eax,0x1
   140002c96:	48 83 c4 20          	add    rsp,0x20
   140002c9a:	5d                   	pop    rbp
   140002c9b:	c3                   	ret

0000000140002c9c <_FindPESection>:
   140002c9c:	55                   	push   rbp
   140002c9d:	48 89 e5             	mov    rbp,rsp
   140002ca0:	48 83 ec 20          	sub    rsp,0x20
   140002ca4:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ca8:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002cac:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cb0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002cb3:	48 63 d0             	movsxd rdx,eax
   140002cb6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cba:	48 01 d0             	add    rax,rdx
   140002cbd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002cc1:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002cc8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ccc:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002cd0:	0f b7 d0             	movzx  edx,ax
   140002cd3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cd7:	48 01 d0             	add    rax,rdx
   140002cda:	48 83 c0 18          	add    rax,0x18
   140002cde:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ce2:	eb 36                	jmp    140002d1a <_FindPESection+0x7e>
   140002ce4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ce8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002ceb:	89 c0                	mov    eax,eax
   140002ced:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cf1:	72 1e                	jb     140002d11 <_FindPESection+0x75>
   140002cf3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cf7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002cfa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cfe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d01:	01 d0                	add    eax,edx
   140002d03:	89 c0                	mov    eax,eax
   140002d05:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d09:	73 06                	jae    140002d11 <_FindPESection+0x75>
   140002d0b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d0f:	eb 1e                	jmp    140002d2f <_FindPESection+0x93>
   140002d11:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d15:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d1a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d1e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d22:	0f b7 c0             	movzx  eax,ax
   140002d25:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d28:	72 ba                	jb     140002ce4 <_FindPESection+0x48>
   140002d2a:	b8 00 00 00 00       	mov    eax,0x0
   140002d2f:	48 83 c4 20          	add    rsp,0x20
   140002d33:	5d                   	pop    rbp
   140002d34:	c3                   	ret

0000000140002d35 <_FindPESectionByName>:
   140002d35:	55                   	push   rbp
   140002d36:	48 89 e5             	mov    rbp,rsp
   140002d39:	48 83 ec 40          	sub    rsp,0x40
   140002d3d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d41:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d45:	48 89 c1             	mov    rcx,rax
   140002d48:	e8 8b 05 00 00       	call   1400032d8 <strlen>
   140002d4d:	48 83 f8 08          	cmp    rax,0x8
   140002d51:	76 0a                	jbe    140002d5d <_FindPESectionByName+0x28>
   140002d53:	b8 00 00 00 00       	mov    eax,0x0
   140002d58:	e9 98 00 00 00       	jmp    140002df5 <_FindPESectionByName+0xc0>
   140002d5d:	48 8b 05 fc 25 00 00 	mov    rax,QWORD PTR [rip+0x25fc]        # 140005360 <.refptr.__ImageBase>
   140002d64:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d68:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d6c:	48 89 c1             	mov    rcx,rax
   140002d6f:	e8 ac fe ff ff       	call   140002c20 <_ValidateImageBase>
   140002d74:	85 c0                	test   eax,eax
   140002d76:	75 07                	jne    140002d7f <_FindPESectionByName+0x4a>
   140002d78:	b8 00 00 00 00       	mov    eax,0x0
   140002d7d:	eb 76                	jmp    140002df5 <_FindPESectionByName+0xc0>
   140002d7f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d83:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d86:	48 63 d0             	movsxd rdx,eax
   140002d89:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d8d:	48 01 d0             	add    rax,rdx
   140002d90:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002d94:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d9b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d9f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002da3:	0f b7 d0             	movzx  edx,ax
   140002da6:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002daa:	48 01 d0             	add    rax,rdx
   140002dad:	48 83 c0 18          	add    rax,0x18
   140002db1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002db5:	eb 29                	jmp    140002de0 <_FindPESectionByName+0xab>
   140002db7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dbb:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002dbf:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002dc5:	48 89 c1             	mov    rcx,rax
   140002dc8:	e8 13 05 00 00       	call   1400032e0 <strncmp>
   140002dcd:	85 c0                	test   eax,eax
   140002dcf:	75 06                	jne    140002dd7 <_FindPESectionByName+0xa2>
   140002dd1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dd5:	eb 1e                	jmp    140002df5 <_FindPESectionByName+0xc0>
   140002dd7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002ddb:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002de0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002de4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002de8:	0f b7 c0             	movzx  eax,ax
   140002deb:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002dee:	72 c7                	jb     140002db7 <_FindPESectionByName+0x82>
   140002df0:	b8 00 00 00 00       	mov    eax,0x0
   140002df5:	48 83 c4 40          	add    rsp,0x40
   140002df9:	5d                   	pop    rbp
   140002dfa:	c3                   	ret

0000000140002dfb <__mingw_GetSectionForAddress>:
   140002dfb:	55                   	push   rbp
   140002dfc:	48 89 e5             	mov    rbp,rsp
   140002dff:	48 83 ec 30          	sub    rsp,0x30
   140002e03:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e07:	48 8b 05 52 25 00 00 	mov    rax,QWORD PTR [rip+0x2552]        # 140005360 <.refptr.__ImageBase>
   140002e0e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e12:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e16:	48 89 c1             	mov    rcx,rax
   140002e19:	e8 02 fe ff ff       	call   140002c20 <_ValidateImageBase>
   140002e1e:	85 c0                	test   eax,eax
   140002e20:	75 07                	jne    140002e29 <__mingw_GetSectionForAddress+0x2e>
   140002e22:	b8 00 00 00 00       	mov    eax,0x0
   140002e27:	eb 1c                	jmp    140002e45 <__mingw_GetSectionForAddress+0x4a>
   140002e29:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e2d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e31:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e35:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e39:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e3d:	48 89 c1             	mov    rcx,rax
   140002e40:	e8 57 fe ff ff       	call   140002c9c <_FindPESection>
   140002e45:	48 83 c4 30          	add    rsp,0x30
   140002e49:	5d                   	pop    rbp
   140002e4a:	c3                   	ret

0000000140002e4b <__mingw_GetSectionCount>:
   140002e4b:	55                   	push   rbp
   140002e4c:	48 89 e5             	mov    rbp,rsp
   140002e4f:	48 83 ec 30          	sub    rsp,0x30
   140002e53:	48 8b 05 06 25 00 00 	mov    rax,QWORD PTR [rip+0x2506]        # 140005360 <.refptr.__ImageBase>
   140002e5a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e5e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e62:	48 89 c1             	mov    rcx,rax
   140002e65:	e8 b6 fd ff ff       	call   140002c20 <_ValidateImageBase>
   140002e6a:	85 c0                	test   eax,eax
   140002e6c:	75 07                	jne    140002e75 <__mingw_GetSectionCount+0x2a>
   140002e6e:	b8 00 00 00 00       	mov    eax,0x0
   140002e73:	eb 20                	jmp    140002e95 <__mingw_GetSectionCount+0x4a>
   140002e75:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e79:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e7c:	48 63 d0             	movsxd rdx,eax
   140002e7f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e83:	48 01 d0             	add    rax,rdx
   140002e86:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e8a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e8e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e92:	0f b7 c0             	movzx  eax,ax
   140002e95:	48 83 c4 30          	add    rsp,0x30
   140002e99:	5d                   	pop    rbp
   140002e9a:	c3                   	ret

0000000140002e9b <_FindPESectionExec>:
   140002e9b:	55                   	push   rbp
   140002e9c:	48 89 e5             	mov    rbp,rsp
   140002e9f:	48 83 ec 40          	sub    rsp,0x40
   140002ea3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ea7:	48 8b 05 b2 24 00 00 	mov    rax,QWORD PTR [rip+0x24b2]        # 140005360 <.refptr.__ImageBase>
   140002eae:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002eb2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002eb6:	48 89 c1             	mov    rcx,rax
   140002eb9:	e8 62 fd ff ff       	call   140002c20 <_ValidateImageBase>
   140002ebe:	85 c0                	test   eax,eax
   140002ec0:	75 07                	jne    140002ec9 <_FindPESectionExec+0x2e>
   140002ec2:	b8 00 00 00 00       	mov    eax,0x0
   140002ec7:	eb 78                	jmp    140002f41 <_FindPESectionExec+0xa6>
   140002ec9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ecd:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ed0:	48 63 d0             	movsxd rdx,eax
   140002ed3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ed7:	48 01 d0             	add    rax,rdx
   140002eda:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002ede:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ee5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ee9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002eed:	0f b7 d0             	movzx  edx,ax
   140002ef0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ef4:	48 01 d0             	add    rax,rdx
   140002ef7:	48 83 c0 18          	add    rax,0x18
   140002efb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002eff:	eb 2b                	jmp    140002f2c <_FindPESectionExec+0x91>
   140002f01:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f05:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f08:	25 00 00 00 20       	and    eax,0x20000000
   140002f0d:	85 c0                	test   eax,eax
   140002f0f:	74 12                	je     140002f23 <_FindPESectionExec+0x88>
   140002f11:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f16:	75 06                	jne    140002f1e <_FindPESectionExec+0x83>
   140002f18:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f1c:	eb 23                	jmp    140002f41 <_FindPESectionExec+0xa6>
   140002f1e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f23:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f27:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f2c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f30:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f34:	0f b7 c0             	movzx  eax,ax
   140002f37:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f3a:	72 c5                	jb     140002f01 <_FindPESectionExec+0x66>
   140002f3c:	b8 00 00 00 00       	mov    eax,0x0
   140002f41:	48 83 c4 40          	add    rsp,0x40
   140002f45:	5d                   	pop    rbp
   140002f46:	c3                   	ret

0000000140002f47 <_GetPEImageBase>:
   140002f47:	55                   	push   rbp
   140002f48:	48 89 e5             	mov    rbp,rsp
   140002f4b:	48 83 ec 30          	sub    rsp,0x30
   140002f4f:	48 8b 05 0a 24 00 00 	mov    rax,QWORD PTR [rip+0x240a]        # 140005360 <.refptr.__ImageBase>
   140002f56:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f5a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f5e:	48 89 c1             	mov    rcx,rax
   140002f61:	e8 ba fc ff ff       	call   140002c20 <_ValidateImageBase>
   140002f66:	85 c0                	test   eax,eax
   140002f68:	75 07                	jne    140002f71 <_GetPEImageBase+0x2a>
   140002f6a:	b8 00 00 00 00       	mov    eax,0x0
   140002f6f:	eb 04                	jmp    140002f75 <_GetPEImageBase+0x2e>
   140002f71:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f75:	48 83 c4 30          	add    rsp,0x30
   140002f79:	5d                   	pop    rbp
   140002f7a:	c3                   	ret

0000000140002f7b <_IsNonwritableInCurrentImage>:
   140002f7b:	55                   	push   rbp
   140002f7c:	48 89 e5             	mov    rbp,rsp
   140002f7f:	48 83 ec 40          	sub    rsp,0x40
   140002f83:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f87:	48 8b 05 d2 23 00 00 	mov    rax,QWORD PTR [rip+0x23d2]        # 140005360 <.refptr.__ImageBase>
   140002f8e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f92:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f96:	48 89 c1             	mov    rcx,rax
   140002f99:	e8 82 fc ff ff       	call   140002c20 <_ValidateImageBase>
   140002f9e:	85 c0                	test   eax,eax
   140002fa0:	75 07                	jne    140002fa9 <_IsNonwritableInCurrentImage+0x2e>
   140002fa2:	b8 00 00 00 00       	mov    eax,0x0
   140002fa7:	eb 3d                	jmp    140002fe6 <_IsNonwritableInCurrentImage+0x6b>
   140002fa9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002fad:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002fb1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fb5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002fb9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fbd:	48 89 c1             	mov    rcx,rax
   140002fc0:	e8 d7 fc ff ff       	call   140002c9c <_FindPESection>
   140002fc5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002fc9:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002fce:	75 07                	jne    140002fd7 <_IsNonwritableInCurrentImage+0x5c>
   140002fd0:	b8 00 00 00 00       	mov    eax,0x0
   140002fd5:	eb 0f                	jmp    140002fe6 <_IsNonwritableInCurrentImage+0x6b>
   140002fd7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002fdb:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fde:	f7 d0                	not    eax
   140002fe0:	c1 e8 1f             	shr    eax,0x1f
   140002fe3:	0f b6 c0             	movzx  eax,al
   140002fe6:	48 83 c4 40          	add    rsp,0x40
   140002fea:	5d                   	pop    rbp
   140002feb:	c3                   	ret

0000000140002fec <__mingw_enum_import_library_names>:
   140002fec:	55                   	push   rbp
   140002fed:	48 89 e5             	mov    rbp,rsp
   140002ff0:	48 83 ec 50          	sub    rsp,0x50
   140002ff4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002ff7:	48 8b 05 62 23 00 00 	mov    rax,QWORD PTR [rip+0x2362]        # 140005360 <.refptr.__ImageBase>
   140002ffe:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003002:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003006:	48 89 c1             	mov    rcx,rax
   140003009:	e8 12 fc ff ff       	call   140002c20 <_ValidateImageBase>
   14000300e:	85 c0                	test   eax,eax
   140003010:	75 0a                	jne    14000301c <__mingw_enum_import_library_names+0x30>
   140003012:	b8 00 00 00 00       	mov    eax,0x0
   140003017:	e9 ab 00 00 00       	jmp    1400030c7 <__mingw_enum_import_library_names+0xdb>
   14000301c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003020:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003023:	48 63 d0             	movsxd rdx,eax
   140003026:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000302a:	48 01 d0             	add    rax,rdx
   14000302d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003031:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003035:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000303b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000303e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003042:	75 07                	jne    14000304b <__mingw_enum_import_library_names+0x5f>
   140003044:	b8 00 00 00 00       	mov    eax,0x0
   140003049:	eb 7c                	jmp    1400030c7 <__mingw_enum_import_library_names+0xdb>
   14000304b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000304e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003052:	48 89 c1             	mov    rcx,rax
   140003055:	e8 42 fc ff ff       	call   140002c9c <_FindPESection>
   14000305a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000305e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003063:	75 07                	jne    14000306c <__mingw_enum_import_library_names+0x80>
   140003065:	b8 00 00 00 00       	mov    eax,0x0
   14000306a:	eb 5b                	jmp    1400030c7 <__mingw_enum_import_library_names+0xdb>
   14000306c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000306f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003073:	48 01 d0             	add    rax,rdx
   140003076:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000307a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000307f:	75 07                	jne    140003088 <__mingw_enum_import_library_names+0x9c>
   140003081:	b8 00 00 00 00       	mov    eax,0x0
   140003086:	eb 3f                	jmp    1400030c7 <__mingw_enum_import_library_names+0xdb>
   140003088:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000308c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000308f:	85 c0                	test   eax,eax
   140003091:	75 0b                	jne    14000309e <__mingw_enum_import_library_names+0xb2>
   140003093:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003097:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000309a:	85 c0                	test   eax,eax
   14000309c:	74 23                	je     1400030c1 <__mingw_enum_import_library_names+0xd5>
   14000309e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400030a2:	7f 12                	jg     1400030b6 <__mingw_enum_import_library_names+0xca>
   1400030a4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030a8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030ab:	89 c2                	mov    edx,eax
   1400030ad:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030b1:	48 01 d0             	add    rax,rdx
   1400030b4:	eb 11                	jmp    1400030c7 <__mingw_enum_import_library_names+0xdb>
   1400030b6:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   1400030ba:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   1400030bf:	eb c7                	jmp    140003088 <__mingw_enum_import_library_names+0x9c>
   1400030c1:	90                   	nop
   1400030c2:	b8 00 00 00 00       	mov    eax,0x0
   1400030c7:	48 83 c4 50          	add    rsp,0x50
   1400030cb:	5d                   	pop    rbp
   1400030cc:	c3                   	ret
   1400030cd:	90                   	nop
   1400030ce:	90                   	nop
   1400030cf:	90                   	nop

00000001400030d0 <___chkstk_ms>:
   1400030d0:	51                   	push   rcx
   1400030d1:	50                   	push   rax
   1400030d2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030d8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400030dd:	72 19                	jb     1400030f8 <___chkstk_ms+0x28>
   1400030df:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400030e6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030ea:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400030f0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030f6:	77 e7                	ja     1400030df <___chkstk_ms+0xf>
   1400030f8:	48 29 c1             	sub    rcx,rax
   1400030fb:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030ff:	58                   	pop    rax
   140003100:	59                   	pop    rcx
   140003101:	c3                   	ret
   140003102:	90                   	nop
   140003103:	90                   	nop
   140003104:	90                   	nop
   140003105:	90                   	nop
   140003106:	90                   	nop
   140003107:	90                   	nop
   140003108:	90                   	nop
   140003109:	90                   	nop
   14000310a:	90                   	nop
   14000310b:	90                   	nop
   14000310c:	90                   	nop
   14000310d:	90                   	nop
   14000310e:	90                   	nop
   14000310f:	90                   	nop

0000000140003110 <_initterm_e>:
   140003110:	55                   	push   rbp
   140003111:	48 89 e5             	mov    rbp,rsp
   140003114:	48 83 ec 30          	sub    rsp,0x30
   140003118:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000311c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003120:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003124:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003128:	eb 29                	jmp    140003153 <_initterm_e+0x43>
   14000312a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000312e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140003131:	48 85 c0             	test   rax,rax
   140003134:	74 17                	je     14000314d <_initterm_e+0x3d>
   140003136:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000313a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000313d:	ff d0                	call   rax
   14000313f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003142:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003146:	74 06                	je     14000314e <_initterm_e+0x3e>
   140003148:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000314b:	eb 15                	jmp    140003162 <_initterm_e+0x52>
   14000314d:	90                   	nop
   14000314e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140003153:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003157:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   14000315b:	72 cd                	jb     14000312a <_initterm_e+0x1a>
   14000315d:	b8 00 00 00 00       	mov    eax,0x0
   140003162:	48 83 c4 30          	add    rsp,0x30
   140003166:	5d                   	pop    rbp
   140003167:	c3                   	ret
   140003168:	90                   	nop
   140003169:	90                   	nop
   14000316a:	90                   	nop
   14000316b:	90                   	nop
   14000316c:	90                   	nop
   14000316d:	90                   	nop
   14000316e:	90                   	nop
   14000316f:	90                   	nop

0000000140003170 <__p__fmode>:
   140003170:	55                   	push   rbp
   140003171:	48 89 e5             	mov    rbp,rsp
   140003174:	48 8b 05 55 22 00 00 	mov    rax,QWORD PTR [rip+0x2255]        # 1400053d0 <.refptr.__imp__fmode>
   14000317b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000317e:	5d                   	pop    rbp
   14000317f:	c3                   	ret

0000000140003180 <__p__commode>:
   140003180:	55                   	push   rbp
   140003181:	48 89 e5             	mov    rbp,rsp
   140003184:	48 8b 05 35 22 00 00 	mov    rax,QWORD PTR [rip+0x2235]        # 1400053c0 <.refptr.__imp__commode>
   14000318b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000318e:	5d                   	pop    rbp
   14000318f:	c3                   	ret

0000000140003190 <__p___initenv>:
   140003190:	55                   	push   rbp
   140003191:	48 89 e5             	mov    rbp,rsp
   140003194:	48 8b 05 15 22 00 00 	mov    rax,QWORD PTR [rip+0x2215]        # 1400053b0 <.refptr.__imp___initenv>
   14000319b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000319e:	5d                   	pop    rbp
   14000319f:	c3                   	ret

00000001400031a0 <_set_invalid_parameter_handler>:
   1400031a0:	55                   	push   rbp
   1400031a1:	48 89 e5             	mov    rbp,rsp
   1400031a4:	48 83 ec 10          	sub    rsp,0x10
   1400031a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400031ac:	48 8d 05 dd 5f 00 00 	lea    rax,[rip+0x5fdd]        # 140009190 <handler>
   1400031b3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031b7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400031bb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400031bf:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400031c3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031c7:	48 87 10             	xchg   QWORD PTR [rax],rdx
   1400031ca:	48 89 d0             	mov    rax,rdx
   1400031cd:	48 83 c4 10          	add    rsp,0x10
   1400031d1:	5d                   	pop    rbp
   1400031d2:	c3                   	ret

00000001400031d3 <_get_invalid_parameter_handler>:
   1400031d3:	55                   	push   rbp
   1400031d4:	48 89 e5             	mov    rbp,rsp
   1400031d7:	48 8b 05 b2 5f 00 00 	mov    rax,QWORD PTR [rip+0x5fb2]        # 140009190 <handler>
   1400031de:	5d                   	pop    rbp
   1400031df:	c3                   	ret

00000001400031e0 <_configthreadlocale>:
   1400031e0:	55                   	push   rbp
   1400031e1:	48 89 e5             	mov    rbp,rsp
   1400031e4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031e7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   1400031eb:	75 07                	jne    1400031f4 <_configthreadlocale+0x14>
   1400031ed:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400031f2:	eb 05                	jmp    1400031f9 <_configthreadlocale+0x19>
   1400031f4:	b8 02 00 00 00       	mov    eax,0x2
   1400031f9:	5d                   	pop    rbp
   1400031fa:	c3                   	ret
   1400031fb:	90                   	nop
   1400031fc:	90                   	nop
   1400031fd:	90                   	nop
   1400031fe:	90                   	nop
   1400031ff:	90                   	nop

0000000140003200 <__acrt_iob_func>:
   140003200:	55                   	push   rbp
   140003201:	48 89 e5             	mov    rbp,rsp
   140003204:	48 83 ec 20          	sub    rsp,0x20
   140003208:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000320b:	e8 30 00 00 00       	call   140003240 <__iob_func>
   140003210:	48 89 c1             	mov    rcx,rax
   140003213:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003216:	48 89 d0             	mov    rax,rdx
   140003219:	48 01 c0             	add    rax,rax
   14000321c:	48 01 d0             	add    rax,rdx
   14000321f:	48 c1 e0 04          	shl    rax,0x4
   140003223:	48 01 c8             	add    rax,rcx
   140003226:	48 83 c4 20          	add    rsp,0x20
   14000322a:	5d                   	pop    rbp
   14000322b:	c3                   	ret
   14000322c:	90                   	nop
   14000322d:	90                   	nop
   14000322e:	90                   	nop
   14000322f:	90                   	nop

0000000140003230 <__C_specific_handler>:
   140003230:	ff 25 da 6f 00 00    	jmp    QWORD PTR [rip+0x6fda]        # 14000a210 <__imp___C_specific_handler>
   140003236:	90                   	nop
   140003237:	90                   	nop

0000000140003238 <__getmainargs>:
   140003238:	ff 25 da 6f 00 00    	jmp    QWORD PTR [rip+0x6fda]        # 14000a218 <__imp___getmainargs>
   14000323e:	90                   	nop
   14000323f:	90                   	nop

0000000140003240 <__iob_func>:
   140003240:	ff 25 e2 6f 00 00    	jmp    QWORD PTR [rip+0x6fe2]        # 14000a228 <__imp___iob_func>
   140003246:	90                   	nop
   140003247:	90                   	nop

0000000140003248 <__set_app_type>:
   140003248:	ff 25 e2 6f 00 00    	jmp    QWORD PTR [rip+0x6fe2]        # 14000a230 <__imp___set_app_type>
   14000324e:	90                   	nop
   14000324f:	90                   	nop

0000000140003250 <__setusermatherr>:
   140003250:	ff 25 e2 6f 00 00    	jmp    QWORD PTR [rip+0x6fe2]        # 14000a238 <__imp___setusermatherr>
   140003256:	90                   	nop
   140003257:	90                   	nop

0000000140003258 <_amsg_exit>:
   140003258:	ff 25 e2 6f 00 00    	jmp    QWORD PTR [rip+0x6fe2]        # 14000a240 <__imp__amsg_exit>
   14000325e:	90                   	nop
   14000325f:	90                   	nop

0000000140003260 <_cexit>:
   140003260:	ff 25 e2 6f 00 00    	jmp    QWORD PTR [rip+0x6fe2]        # 14000a248 <__imp__cexit>
   140003266:	90                   	nop
   140003267:	90                   	nop

0000000140003268 <_initterm>:
   140003268:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a260 <__imp__initterm>
   14000326e:	90                   	nop
   14000326f:	90                   	nop

0000000140003270 <_crt_atexit>:
   140003270:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a268 <__imp__crt_atexit>
   140003276:	90                   	nop
   140003277:	90                   	nop

0000000140003278 <abort>:
   140003278:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a270 <__imp_abort>
   14000327e:	90                   	nop
   14000327f:	90                   	nop

0000000140003280 <calloc>:
   140003280:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a278 <__imp_calloc>
   140003286:	90                   	nop
   140003287:	90                   	nop

0000000140003288 <exit>:
   140003288:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a280 <__imp_exit>
   14000328e:	90                   	nop
   14000328f:	90                   	nop

0000000140003290 <fflush>:
   140003290:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a288 <__imp_fflush>
   140003296:	90                   	nop
   140003297:	90                   	nop

0000000140003298 <fprintf>:
   140003298:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a290 <__imp_fprintf>
   14000329e:	90                   	nop
   14000329f:	90                   	nop

00000001400032a0 <free>:
   1400032a0:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a298 <__imp_free>
   1400032a6:	90                   	nop
   1400032a7:	90                   	nop

00000001400032a8 <malloc>:
   1400032a8:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a2a0 <__imp_malloc>
   1400032ae:	90                   	nop
   1400032af:	90                   	nop

00000001400032b0 <memcpy>:
   1400032b0:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a2a8 <__imp_memcpy>
   1400032b6:	90                   	nop
   1400032b7:	90                   	nop

00000001400032b8 <memset>:
   1400032b8:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a2b0 <__imp_memset>
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <realloc>:
   1400032c0:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a2b8 <__imp_realloc>
   1400032c6:	90                   	nop
   1400032c7:	90                   	nop

00000001400032c8 <setvbuf>:
   1400032c8:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a2c0 <__imp_setvbuf>
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <signal>:
   1400032d0:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a2c8 <__imp_signal>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop

00000001400032d8 <strlen>:
   1400032d8:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a2d0 <__imp_strlen>
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <strncmp>:
   1400032e0:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a2d8 <__imp_strncmp>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <vfprintf>:
   1400032e8:	ff 25 f2 6f 00 00    	jmp    QWORD PTR [rip+0x6ff2]        # 14000a2e0 <__imp_vfprintf>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <VirtualQuery>:
   1400032f0:	ff 25 0a 6f 00 00    	jmp    QWORD PTR [rip+0x6f0a]        # 14000a200 <__imp_VirtualQuery>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <VirtualProtect>:
   1400032f8:	ff 25 fa 6e 00 00    	jmp    QWORD PTR [rip+0x6efa]        # 14000a1f8 <__imp_VirtualProtect>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <TlsGetValue>:
   140003300:	ff 25 ea 6e 00 00    	jmp    QWORD PTR [rip+0x6eea]        # 14000a1f0 <__imp_TlsGetValue>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <Sleep>:
   140003308:	ff 25 da 6e 00 00    	jmp    QWORD PTR [rip+0x6eda]        # 14000a1e8 <__imp_Sleep>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <SetUnhandledExceptionFilter>:
   140003310:	ff 25 ca 6e 00 00    	jmp    QWORD PTR [rip+0x6eca]        # 14000a1e0 <__imp_SetUnhandledExceptionFilter>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <LoadLibraryA>:
   140003318:	ff 25 ba 6e 00 00    	jmp    QWORD PTR [rip+0x6eba]        # 14000a1d8 <__imp_LoadLibraryA>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <LeaveCriticalSection>:
   140003320:	ff 25 aa 6e 00 00    	jmp    QWORD PTR [rip+0x6eaa]        # 14000a1d0 <__imp_LeaveCriticalSection>
   140003326:	90                   	nop
   140003327:	90                   	nop

0000000140003328 <InitializeCriticalSection>:
   140003328:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a1c8 <__imp_InitializeCriticalSection>
   14000332e:	90                   	nop
   14000332f:	90                   	nop

0000000140003330 <GetProcAddress>:
   140003330:	ff 25 8a 6e 00 00    	jmp    QWORD PTR [rip+0x6e8a]        # 14000a1c0 <__imp_GetProcAddress>
   140003336:	90                   	nop
   140003337:	90                   	nop

0000000140003338 <GetModuleHandleA>:
   140003338:	ff 25 7a 6e 00 00    	jmp    QWORD PTR [rip+0x6e7a]        # 14000a1b8 <__imp_GetModuleHandleA>
   14000333e:	90                   	nop
   14000333f:	90                   	nop

0000000140003340 <GetLastError>:
   140003340:	ff 25 6a 6e 00 00    	jmp    QWORD PTR [rip+0x6e6a]        # 14000a1b0 <__imp_GetLastError>
   140003346:	90                   	nop
   140003347:	90                   	nop

0000000140003348 <FreeLibrary>:
   140003348:	ff 25 5a 6e 00 00    	jmp    QWORD PTR [rip+0x6e5a]        # 14000a1a8 <__imp_FreeLibrary>
   14000334e:	90                   	nop
   14000334f:	90                   	nop

0000000140003350 <EnterCriticalSection>:
   140003350:	ff 25 4a 6e 00 00    	jmp    QWORD PTR [rip+0x6e4a]        # 14000a1a0 <__imp_EnterCriticalSection>
   140003356:	90                   	nop
   140003357:	90                   	nop

0000000140003358 <DeleteCriticalSection>:
   140003358:	ff 25 3a 6e 00 00    	jmp    QWORD PTR [rip+0x6e3a]        # 14000a198 <__IAT_start__>
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
