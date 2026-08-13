
C:\Users\Administrator\Desktop\BinMind\deemo\modules\samples\heap_overflow\cve_2016_2173_openssl_enc\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 67 24 00 00       	call   140003490 <fflush>
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
   14000113b:	e8 18 23 00 00       	call   140003458 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 98 22 00 00       	call   140003400 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 3f 23 00 00       	call   1400034c0 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 df 22 00 00       	call   140003478 <abort>
   140001199:	e8 62 13 00 00       	call   140002500 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 29 90 00 00 	mov    rax,QWORD PTR [rip+0x9029]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 d6 21 00 00       	call   1400033a0 <_set_invalid_parameter_handler>
   1400011ca:	e8 41 1c 00 00       	call   140002e10 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 57 22 00 00       	call   140003448 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 4b 22 00 00       	call   140003448 <__set_app_type>
   1400011fd:	e8 6e 21 00 00       	call   140003370 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 6e 21 00 00       	call   140003380 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 be 08 00 00       	call   140001ae0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 23 22 00 00       	call   140003458 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 c8 13 00 00       	call   14000261a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 76 21 00 00       	call   1400033e0 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 90 20 00 00       	call   140003310 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 ca 21 00 00       	call   140003458 <_amsg_exit>
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
   1400012cb:	e8 68 21 00 00       	call   140003438 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 75 21 00 00       	call   140003458 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 4e 21 00 00       	call   140003458 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 48 21 00 00       	call   140003468 <_initterm>
   140001320:	e8 92 07 00 00       	call   140001ab7 <__main>
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
   14000138d:	e8 fe 1f 00 00       	call   140003390 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 db 05 00 00       	call   140001995 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 b7 20 00 00       	call   140003488 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 80 20 00 00       	call   140003460 <_cexit>
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
   140001511:	e8 92 1f 00 00       	call   1400034a8 <malloc>
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
   14000155c:	e8 6f 1f 00 00       	call   1400034d0 <strlen>
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
   140001585:	e8 1e 1f 00 00       	call   1400034a8 <malloc>
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
   1400015e8:	e8 c3 1e 00 00       	call   1400034b0 <memcpy>
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
   140001642:	e8 29 1e 00 00       	call   140003470 <_crt_atexit>
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

0000000140001760 <encode>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 40          	sub    rsp,0x40
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001770:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001774:	48 ba ab aa aa aa aa 	movabs rdx,0xaaaaaaaaaaaaaaab
   14000177b:	aa aa aa 
   14000177e:	48 f7 e2             	mul    rdx
   140001781:	48 89 d0             	mov    rax,rdx
   140001784:	48 d1 e8             	shr    rax,1
   140001787:	48 c1 e0 02          	shl    rax,0x2
   14000178b:	48 83 c0 05          	add    rax,0x5
   14000178f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001793:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001797:	48 89 c1             	mov    rcx,rax
   14000179a:	e8 09 1d 00 00       	call   1400034a8 <malloc>
   14000179f:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400017a3:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   1400017a8:	75 0a                	jne    1400017b4 <encode+0x54>
   1400017aa:	b8 00 00 00 00       	mov    eax,0x0
   1400017af:	e9 db 01 00 00       	jmp    14000198f <encode+0x22f>
   1400017b4:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400017bb:	00 
   1400017bc:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   1400017c3:	00 
   1400017c4:	e9 e2 00 00 00       	jmp    1400018ab <encode+0x14b>
   1400017c9:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400017cd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017d1:	48 01 d0             	add    rax,rdx
   1400017d4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400017d7:	c0 e8 02             	shr    al,0x2
   1400017da:	89 c1                	mov    ecx,eax
   1400017dc:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   1400017e0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400017e4:	48 01 d0             	add    rax,rdx
   1400017e7:	89 ca                	mov    edx,ecx
   1400017e9:	88 10                	mov    BYTE PTR [rax],dl
   1400017eb:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400017ef:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017f3:	48 01 d0             	add    rax,rdx
   1400017f6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400017f9:	c1 e0 04             	shl    eax,0x4
   1400017fc:	83 e0 30             	and    eax,0x30
   1400017ff:	89 c1                	mov    ecx,eax
   140001801:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001805:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140001809:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000180d:	48 01 d0             	add    rax,rdx
   140001810:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140001813:	c0 e8 04             	shr    al,0x4
   140001816:	41 89 c0             	mov    r8d,eax
   140001819:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000181d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140001821:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001825:	48 01 d0             	add    rax,rdx
   140001828:	44 09 c1             	or     ecx,r8d
   14000182b:	89 ca                	mov    edx,ecx
   14000182d:	88 10                	mov    BYTE PTR [rax],dl
   14000182f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001833:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140001837:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000183b:	48 01 d0             	add    rax,rdx
   14000183e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140001841:	c1 e0 02             	shl    eax,0x2
   140001844:	83 e0 3c             	and    eax,0x3c
   140001847:	89 c1                	mov    ecx,eax
   140001849:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000184d:	48 8d 50 02          	lea    rdx,[rax+0x2]
   140001851:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001855:	48 01 d0             	add    rax,rdx
   140001858:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000185b:	c0 e8 06             	shr    al,0x6
   14000185e:	41 89 c0             	mov    r8d,eax
   140001861:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001865:	48 8d 50 02          	lea    rdx,[rax+0x2]
   140001869:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000186d:	48 01 d0             	add    rax,rdx
   140001870:	44 09 c1             	or     ecx,r8d
   140001873:	89 ca                	mov    edx,ecx
   140001875:	88 10                	mov    BYTE PTR [rax],dl
   140001877:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000187b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000187f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001883:	48 01 d0             	add    rax,rdx
   140001886:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140001889:	89 c1                	mov    ecx,eax
   14000188b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000188f:	48 8d 50 03          	lea    rdx,[rax+0x3]
   140001893:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001897:	48 01 d0             	add    rax,rdx
   14000189a:	83 e1 3f             	and    ecx,0x3f
   14000189d:	89 ca                	mov    edx,ecx
   14000189f:	88 10                	mov    BYTE PTR [rax],dl
   1400018a1:	48 83 45 f8 03       	add    QWORD PTR [rbp-0x8],0x3
   1400018a6:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   1400018ab:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400018af:	48 83 c0 03          	add    rax,0x3
   1400018b3:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   1400018b7:	0f 83 0c ff ff ff    	jae    1400017c9 <encode+0x69>
   1400018bd:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   1400018c1:	48 ba ab aa aa aa aa 	movabs rdx,0xaaaaaaaaaaaaaaab
   1400018c8:	aa aa aa 
   1400018cb:	48 89 c8             	mov    rax,rcx
   1400018ce:	48 f7 e2             	mul    rdx
   1400018d1:	48 d1 ea             	shr    rdx,1
   1400018d4:	48 89 d0             	mov    rax,rdx
   1400018d7:	48 01 c0             	add    rax,rax
   1400018da:	48 01 d0             	add    rax,rdx
   1400018dd:	48 29 c1             	sub    rcx,rax
   1400018e0:	48 89 ca             	mov    rdx,rcx
   1400018e3:	48 83 fa 01          	cmp    rdx,0x1
   1400018e7:	75 32                	jne    14000191b <encode+0x1bb>
   1400018e9:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   1400018ed:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400018f1:	48 01 d0             	add    rax,rdx
   1400018f4:	c6 00 00             	mov    BYTE PTR [rax],0x0
   1400018f7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400018fb:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400018ff:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001903:	48 01 d0             	add    rax,rdx
   140001906:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140001909:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000190d:	48 8d 50 02          	lea    rdx,[rax+0x2]
   140001911:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001915:	48 01 d0             	add    rax,rdx
   140001918:	c6 00 00             	mov    BYTE PTR [rax],0x0
   14000191b:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   14000191f:	48 ba ab aa aa aa aa 	movabs rdx,0xaaaaaaaaaaaaaaab
   140001926:	aa aa aa 
   140001929:	48 89 c8             	mov    rax,rcx
   14000192c:	48 f7 e2             	mul    rdx
   14000192f:	48 d1 ea             	shr    rdx,1
   140001932:	48 89 d0             	mov    rax,rdx
   140001935:	48 01 c0             	add    rax,rax
   140001938:	48 01 d0             	add    rax,rdx
   14000193b:	48 29 c1             	sub    rcx,rax
   14000193e:	48 89 ca             	mov    rdx,rcx
   140001941:	48 83 fa 02          	cmp    rdx,0x2
   140001945:	75 44                	jne    14000198b <encode+0x22b>
   140001947:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000194b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000194f:	48 01 d0             	add    rax,rdx
   140001952:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140001955:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001959:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000195d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001961:	48 01 d0             	add    rax,rdx
   140001964:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140001967:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000196b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000196f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001973:	48 01 d0             	add    rax,rdx
   140001976:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140001979:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000197d:	48 8d 50 03          	lea    rdx,[rax+0x3]
   140001981:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001985:	48 01 d0             	add    rax,rdx
   140001988:	c6 00 00             	mov    BYTE PTR [rax],0x0
   14000198b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000198f:	48 83 c4 40          	add    rsp,0x40
   140001993:	5d                   	pop    rbp
   140001994:	c3                   	ret

0000000140001995 <main>:
   140001995:	55                   	push   rbp
   140001996:	48 89 e5             	mov    rbp,rsp
   140001999:	48 83 ec 30          	sub    rsp,0x30
   14000199d:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400019a0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400019a4:	e8 0e 01 00 00       	call   140001ab7 <__main>
   1400019a9:	48 8d 45 f0          	lea    rax,[rbp-0x10]
   1400019ad:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400019b3:	ba 41 00 00 00       	mov    edx,0x41
   1400019b8:	48 89 c1             	mov    rcx,rax
   1400019bb:	e8 f8 1a 00 00       	call   1400034b8 <memset>
   1400019c0:	48 8d 45 f0          	lea    rax,[rbp-0x10]
   1400019c4:	ba 05 00 00 00       	mov    edx,0x5
   1400019c9:	48 89 c1             	mov    rcx,rax
   1400019cc:	e8 8f fd ff ff       	call   140001760 <encode>
   1400019d1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400019d5:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400019da:	74 0c                	je     1400019e8 <main+0x53>
   1400019dc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400019e0:	48 89 c1             	mov    rcx,rax
   1400019e3:	e8 b8 1a 00 00       	call   1400034a0 <free>
   1400019e8:	b8 00 00 00 00       	mov    eax,0x0
   1400019ed:	48 83 c4 30          	add    rsp,0x30
   1400019f1:	5d                   	pop    rbp
   1400019f2:	c3                   	ret
   1400019f3:	90                   	nop
   1400019f4:	90                   	nop
   1400019f5:	90                   	nop
   1400019f6:	90                   	nop
   1400019f7:	90                   	nop
   1400019f8:	90                   	nop
   1400019f9:	90                   	nop
   1400019fa:	90                   	nop
   1400019fb:	90                   	nop
   1400019fc:	90                   	nop
   1400019fd:	90                   	nop
   1400019fe:	90                   	nop
   1400019ff:	90                   	nop

0000000140001a00 <__do_global_dtors>:
   140001a00:	55                   	push   rbp
   140001a01:	48 89 e5             	mov    rbp,rsp
   140001a04:	48 83 ec 20          	sub    rsp,0x20
   140001a08:	eb 1e                	jmp    140001a28 <__do_global_dtors+0x28>
   140001a0a:	48 8b 05 ff 25 00 00 	mov    rax,QWORD PTR [rip+0x25ff]        # 140004010 <p.0>
   140001a11:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a14:	ff d0                	call   rax
   140001a16:	48 8b 05 f3 25 00 00 	mov    rax,QWORD PTR [rip+0x25f3]        # 140004010 <p.0>
   140001a1d:	48 83 c0 08          	add    rax,0x8
   140001a21:	48 89 05 e8 25 00 00 	mov    QWORD PTR [rip+0x25e8],rax        # 140004010 <p.0>
   140001a28:	48 8b 05 e1 25 00 00 	mov    rax,QWORD PTR [rip+0x25e1]        # 140004010 <p.0>
   140001a2f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a32:	48 85 c0             	test   rax,rax
   140001a35:	75 d3                	jne    140001a0a <__do_global_dtors+0xa>
   140001a37:	90                   	nop
   140001a38:	90                   	nop
   140001a39:	48 83 c4 20          	add    rsp,0x20
   140001a3d:	5d                   	pop    rbp
   140001a3e:	c3                   	ret

0000000140001a3f <__do_global_ctors>:
   140001a3f:	55                   	push   rbp
   140001a40:	48 89 e5             	mov    rbp,rsp
   140001a43:	48 83 ec 30          	sub    rsp,0x30
   140001a47:	48 8b 05 02 39 00 00 	mov    rax,QWORD PTR [rip+0x3902]        # 140005350 <.refptr.__CTOR_LIST__>
   140001a4e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a51:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001a54:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001a58:	75 25                	jne    140001a7f <__do_global_ctors+0x40>
   140001a5a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001a61:	eb 04                	jmp    140001a67 <__do_global_ctors+0x28>
   140001a63:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001a67:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001a6a:	8d 50 01             	lea    edx,[rax+0x1]
   140001a6d:	48 8b 05 dc 38 00 00 	mov    rax,QWORD PTR [rip+0x38dc]        # 140005350 <.refptr.__CTOR_LIST__>
   140001a74:	89 d2                	mov    edx,edx
   140001a76:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001a7a:	48 85 c0             	test   rax,rax
   140001a7d:	75 e4                	jne    140001a63 <__do_global_ctors+0x24>
   140001a7f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001a82:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001a85:	eb 14                	jmp    140001a9b <__do_global_ctors+0x5c>
   140001a87:	48 8b 05 c2 38 00 00 	mov    rax,QWORD PTR [rip+0x38c2]        # 140005350 <.refptr.__CTOR_LIST__>
   140001a8e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001a91:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001a95:	ff d0                	call   rax
   140001a97:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140001a9b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140001a9f:	75 e6                	jne    140001a87 <__do_global_ctors+0x48>
   140001aa1:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001a00 <__do_global_dtors>
   140001aa8:	48 89 c1             	mov    rcx,rax
   140001aab:	e8 7f fb ff ff       	call   14000162f <atexit>
   140001ab0:	90                   	nop
   140001ab1:	48 83 c4 30          	add    rsp,0x30
   140001ab5:	5d                   	pop    rbp
   140001ab6:	c3                   	ret

0000000140001ab7 <__main>:
   140001ab7:	55                   	push   rbp
   140001ab8:	48 89 e5             	mov    rbp,rsp
   140001abb:	48 83 ec 20          	sub    rsp,0x20
   140001abf:	8b 05 bb 75 00 00    	mov    eax,DWORD PTR [rip+0x75bb]        # 140009080 <initialized>
   140001ac5:	85 c0                	test   eax,eax
   140001ac7:	75 0f                	jne    140001ad8 <__main+0x21>
   140001ac9:	c7 05 ad 75 00 00 01 	mov    DWORD PTR [rip+0x75ad],0x1        # 140009080 <initialized>
   140001ad0:	00 00 00 
   140001ad3:	e8 67 ff ff ff       	call   140001a3f <__do_global_ctors>
   140001ad8:	90                   	nop
   140001ad9:	48 83 c4 20          	add    rsp,0x20
   140001add:	5d                   	pop    rbp
   140001ade:	c3                   	ret
   140001adf:	90                   	nop

0000000140001ae0 <_setargv>:
   140001ae0:	55                   	push   rbp
   140001ae1:	48 89 e5             	mov    rbp,rsp
   140001ae4:	b8 00 00 00 00       	mov    eax,0x0
   140001ae9:	5d                   	pop    rbp
   140001aea:	c3                   	ret
   140001aeb:	90                   	nop
   140001aec:	90                   	nop
   140001aed:	90                   	nop
   140001aee:	90                   	nop
   140001aef:	90                   	nop

0000000140001af0 <__dyn_tls_init>:
   140001af0:	55                   	push   rbp
   140001af1:	48 89 e5             	mov    rbp,rsp
   140001af4:	48 83 ec 30          	sub    rsp,0x30
   140001af8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001afc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001aff:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001b03:	48 8b 05 26 38 00 00 	mov    rax,QWORD PTR [rip+0x3826]        # 140005330 <.refptr._CRT_MT>
   140001b0a:	8b 00                	mov    eax,DWORD PTR [rax]
   140001b0c:	83 f8 02             	cmp    eax,0x2
   140001b0f:	74 0d                	je     140001b1e <__dyn_tls_init+0x2e>
   140001b11:	48 8b 05 18 38 00 00 	mov    rax,QWORD PTR [rip+0x3818]        # 140005330 <.refptr._CRT_MT>
   140001b18:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   140001b1e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001b22:	74 1e                	je     140001b42 <__dyn_tls_init+0x52>
   140001b24:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001b28:	75 5b                	jne    140001b85 <__dyn_tls_init+0x95>
   140001b2a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001b2e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001b31:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001b35:	49 89 c8             	mov    r8,rcx
   140001b38:	48 89 c1             	mov    rcx,rax
   140001b3b:	e8 d1 11 00 00       	call   140002d11 <__mingw_TLScallback>
   140001b40:	eb 43                	jmp    140001b85 <__dyn_tls_init+0x95>
   140001b42:	48 8d 05 4f 3b 00 00 	lea    rax,[rip+0x3b4f]        # 140005698 <___crt_xd_start__>
   140001b49:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b4d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001b52:	eb 22                	jmp    140001b76 <__dyn_tls_init+0x86>
   140001b54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001b58:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001b5c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001b60:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001b63:	48 85 c0             	test   rax,rax
   140001b66:	74 09                	je     140001b71 <__dyn_tls_init+0x81>
   140001b68:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001b6c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001b6f:	ff d0                	call   rax
   140001b71:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001b76:	48 8d 05 23 3b 00 00 	lea    rax,[rip+0x3b23]        # 1400056a0 <__xd_z>
   140001b7d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001b81:	75 d1                	jne    140001b54 <__dyn_tls_init+0x64>
   140001b83:	eb 01                	jmp    140001b86 <__dyn_tls_init+0x96>
   140001b85:	90                   	nop
   140001b86:	48 83 c4 30          	add    rsp,0x30
   140001b8a:	5d                   	pop    rbp
   140001b8b:	c3                   	ret

0000000140001b8c <__tlregdtor>:
   140001b8c:	55                   	push   rbp
   140001b8d:	48 89 e5             	mov    rbp,rsp
   140001b90:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b94:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001b99:	75 07                	jne    140001ba2 <__tlregdtor+0x16>
   140001b9b:	b8 00 00 00 00       	mov    eax,0x0
   140001ba0:	eb 05                	jmp    140001ba7 <__tlregdtor+0x1b>
   140001ba2:	b8 00 00 00 00       	mov    eax,0x0
   140001ba7:	5d                   	pop    rbp
   140001ba8:	c3                   	ret

0000000140001ba9 <__dyn_tls_dtor>:
   140001ba9:	55                   	push   rbp
   140001baa:	48 89 e5             	mov    rbp,rsp
   140001bad:	48 83 ec 20          	sub    rsp,0x20
   140001bb1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001bb5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001bb8:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001bbc:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001bc0:	74 06                	je     140001bc8 <__dyn_tls_dtor+0x1f>
   140001bc2:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001bc6:	75 18                	jne    140001be0 <__dyn_tls_dtor+0x37>
   140001bc8:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001bcc:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001bcf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001bd3:	49 89 c8             	mov    r8,rcx
   140001bd6:	48 89 c1             	mov    rcx,rax
   140001bd9:	e8 33 11 00 00       	call   140002d11 <__mingw_TLScallback>
   140001bde:	eb 01                	jmp    140001be1 <__dyn_tls_dtor+0x38>
   140001be0:	90                   	nop
   140001be1:	48 83 c4 20          	add    rsp,0x20
   140001be5:	5d                   	pop    rbp
   140001be6:	c3                   	ret
   140001be7:	90                   	nop
   140001be8:	90                   	nop
   140001be9:	90                   	nop
   140001bea:	90                   	nop
   140001beb:	90                   	nop
   140001bec:	90                   	nop
   140001bed:	90                   	nop
   140001bee:	90                   	nop
   140001bef:	90                   	nop

0000000140001bf0 <_matherr>:
   140001bf0:	55                   	push   rbp
   140001bf1:	53                   	push   rbx
   140001bf2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001bf9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001bfe:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001c02:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001c06:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001c0b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001c0f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001c13:	8b 00                	mov    eax,DWORD PTR [rax]
   140001c15:	83 f8 06             	cmp    eax,0x6
   140001c18:	74 56                	je     140001c70 <_matherr+0x80>
   140001c1a:	83 f8 06             	cmp    eax,0x6
   140001c1d:	7f 78                	jg     140001c97 <_matherr+0xa7>
   140001c1f:	83 f8 05             	cmp    eax,0x5
   140001c22:	74 59                	je     140001c7d <_matherr+0x8d>
   140001c24:	83 f8 05             	cmp    eax,0x5
   140001c27:	7f 6e                	jg     140001c97 <_matherr+0xa7>
   140001c29:	83 f8 04             	cmp    eax,0x4
   140001c2c:	74 5c                	je     140001c8a <_matherr+0x9a>
   140001c2e:	83 f8 04             	cmp    eax,0x4
   140001c31:	7f 64                	jg     140001c97 <_matherr+0xa7>
   140001c33:	83 f8 03             	cmp    eax,0x3
   140001c36:	74 2b                	je     140001c63 <_matherr+0x73>
   140001c38:	83 f8 03             	cmp    eax,0x3
   140001c3b:	7f 5a                	jg     140001c97 <_matherr+0xa7>
   140001c3d:	83 f8 01             	cmp    eax,0x1
   140001c40:	74 07                	je     140001c49 <_matherr+0x59>
   140001c42:	83 f8 02             	cmp    eax,0x2
   140001c45:	74 0f                	je     140001c56 <_matherr+0x66>
   140001c47:	eb 4e                	jmp    140001c97 <_matherr+0xa7>
   140001c49:	48 8d 05 50 34 00 00 	lea    rax,[rip+0x3450]        # 1400050a0 <.rdata>
   140001c50:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c54:	eb 4d                	jmp    140001ca3 <_matherr+0xb3>
   140001c56:	48 8d 05 62 34 00 00 	lea    rax,[rip+0x3462]        # 1400050bf <.rdata+0x1f>
   140001c5d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c61:	eb 40                	jmp    140001ca3 <_matherr+0xb3>
   140001c63:	48 8d 05 76 34 00 00 	lea    rax,[rip+0x3476]        # 1400050e0 <.rdata+0x40>
   140001c6a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c6e:	eb 33                	jmp    140001ca3 <_matherr+0xb3>
   140001c70:	48 8d 05 89 34 00 00 	lea    rax,[rip+0x3489]        # 140005100 <.rdata+0x60>
   140001c77:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c7b:	eb 26                	jmp    140001ca3 <_matherr+0xb3>
   140001c7d:	48 8d 05 a4 34 00 00 	lea    rax,[rip+0x34a4]        # 140005128 <.rdata+0x88>
   140001c84:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c88:	eb 19                	jmp    140001ca3 <_matherr+0xb3>
   140001c8a:	48 8d 05 bf 34 00 00 	lea    rax,[rip+0x34bf]        # 140005150 <.rdata+0xb0>
   140001c91:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c95:	eb 0c                	jmp    140001ca3 <_matherr+0xb3>
   140001c97:	48 8d 05 e8 34 00 00 	lea    rax,[rip+0x34e8]        # 140005186 <.rdata+0xe6>
   140001c9e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ca2:	90                   	nop
   140001ca3:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ca7:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001cad:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001cb1:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001cb6:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001cba:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001cbf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001cc3:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001cc7:	b9 02 00 00 00       	mov    ecx,0x2
   140001ccc:	e8 2f 17 00 00       	call   140003400 <__acrt_iob_func>
   140001cd1:	48 89 c1             	mov    rcx,rax
   140001cd4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001cd8:	48 8d 05 b9 34 00 00 	lea    rax,[rip+0x34b9]        # 140005198 <.rdata+0xf8>
   140001cdf:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001ce6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001cec:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001cf2:	49 89 d9             	mov    r9,rbx
   140001cf5:	49 89 d0             	mov    r8,rdx
   140001cf8:	48 89 c2             	mov    rdx,rax
   140001cfb:	e8 98 17 00 00       	call   140003498 <fprintf>
   140001d00:	b8 00 00 00 00       	mov    eax,0x0
   140001d05:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001d09:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001d0d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001d12:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001d19:	5b                   	pop    rbx
   140001d1a:	5d                   	pop    rbp
   140001d1b:	c3                   	ret
   140001d1c:	90                   	nop
   140001d1d:	90                   	nop
   140001d1e:	90                   	nop
   140001d1f:	90                   	nop

0000000140001d20 <__report_error>:
   140001d20:	55                   	push   rbp
   140001d21:	53                   	push   rbx
   140001d22:	48 83 ec 38          	sub    rsp,0x38
   140001d26:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001d2b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001d2f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001d33:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001d37:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001d3b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001d3f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001d43:	b9 02 00 00 00       	mov    ecx,0x2
   140001d48:	e8 b3 16 00 00       	call   140003400 <__acrt_iob_func>
   140001d4d:	48 89 c1             	mov    rcx,rax
   140001d50:	48 8d 05 79 34 00 00 	lea    rax,[rip+0x3479]        # 1400051d0 <.rdata>
   140001d57:	48 89 c2             	mov    rdx,rax
   140001d5a:	e8 39 17 00 00       	call   140003498 <fprintf>
   140001d5f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001d63:	b9 02 00 00 00       	mov    ecx,0x2
   140001d68:	e8 93 16 00 00       	call   140003400 <__acrt_iob_func>
   140001d6d:	48 89 c1             	mov    rcx,rax
   140001d70:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001d74:	49 89 d8             	mov    r8,rbx
   140001d77:	48 89 c2             	mov    rdx,rax
   140001d7a:	e8 61 17 00 00       	call   1400034e0 <vfprintf>
   140001d7f:	e8 f4 16 00 00       	call   140003478 <abort>
   140001d84:	90                   	nop

0000000140001d85 <mark_section_writable>:
   140001d85:	55                   	push   rbp
   140001d86:	48 89 e5             	mov    rbp,rsp
   140001d89:	48 83 ec 60          	sub    rsp,0x60
   140001d8d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001d91:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001d98:	e9 82 00 00 00       	jmp    140001e1f <mark_section_writable+0x9a>
   140001d9d:	48 8b 0d 3c 73 00 00 	mov    rcx,QWORD PTR [rip+0x733c]        # 1400090e0 <the_secs>
   140001da4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001da7:	48 63 d0             	movsxd rdx,eax
   140001daa:	48 89 d0             	mov    rax,rdx
   140001dad:	48 c1 e0 02          	shl    rax,0x2
   140001db1:	48 01 d0             	add    rax,rdx
   140001db4:	48 c1 e0 03          	shl    rax,0x3
   140001db8:	48 01 c8             	add    rax,rcx
   140001dbb:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001dbf:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001dc3:	72 56                	jb     140001e1b <mark_section_writable+0x96>
   140001dc5:	48 8b 0d 14 73 00 00 	mov    rcx,QWORD PTR [rip+0x7314]        # 1400090e0 <the_secs>
   140001dcc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dcf:	48 63 d0             	movsxd rdx,eax
   140001dd2:	48 89 d0             	mov    rax,rdx
   140001dd5:	48 c1 e0 02          	shl    rax,0x2
   140001dd9:	48 01 d0             	add    rax,rdx
   140001ddc:	48 c1 e0 03          	shl    rax,0x3
   140001de0:	48 01 c8             	add    rax,rcx
   140001de3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001de7:	4c 8b 05 f2 72 00 00 	mov    r8,QWORD PTR [rip+0x72f2]        # 1400090e0 <the_secs>
   140001dee:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001df1:	48 63 d0             	movsxd rdx,eax
   140001df4:	48 89 d0             	mov    rax,rdx
   140001df7:	48 c1 e0 02          	shl    rax,0x2
   140001dfb:	48 01 d0             	add    rax,rdx
   140001dfe:	48 c1 e0 03          	shl    rax,0x3
   140001e02:	4c 01 c0             	add    rax,r8
   140001e05:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001e09:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001e0c:	89 c0                	mov    eax,eax
   140001e0e:	48 01 c8             	add    rax,rcx
   140001e11:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001e15:	0f 82 41 02 00 00    	jb     14000205c <mark_section_writable+0x2d7>
   140001e1b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001e1f:	8b 05 c3 72 00 00    	mov    eax,DWORD PTR [rip+0x72c3]        # 1400090e8 <maxSections>
   140001e25:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001e28:	0f 8c 6f ff ff ff    	jl     140001d9d <mark_section_writable+0x18>
   140001e2e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001e32:	48 89 c1             	mov    rcx,rax
   140001e35:	e8 c1 11 00 00       	call   140002ffb <__mingw_GetSectionForAddress>
   140001e3a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001e3e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001e43:	75 13                	jne    140001e58 <mark_section_writable+0xd3>
   140001e45:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001e49:	48 8d 0d a0 33 00 00 	lea    rcx,[rip+0x33a0]        # 1400051f0 <.rdata+0x20>
   140001e50:	48 89 c2             	mov    rdx,rax
   140001e53:	e8 c8 fe ff ff       	call   140001d20 <__report_error>
   140001e58:	48 8b 0d 81 72 00 00 	mov    rcx,QWORD PTR [rip+0x7281]        # 1400090e0 <the_secs>
   140001e5f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e62:	48 63 d0             	movsxd rdx,eax
   140001e65:	48 89 d0             	mov    rax,rdx
   140001e68:	48 c1 e0 02          	shl    rax,0x2
   140001e6c:	48 01 d0             	add    rax,rdx
   140001e6f:	48 c1 e0 03          	shl    rax,0x3
   140001e73:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e77:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001e7b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001e7f:	48 8b 0d 5a 72 00 00 	mov    rcx,QWORD PTR [rip+0x725a]        # 1400090e0 <the_secs>
   140001e86:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e89:	48 63 d0             	movsxd rdx,eax
   140001e8c:	48 89 d0             	mov    rax,rdx
   140001e8f:	48 c1 e0 02          	shl    rax,0x2
   140001e93:	48 01 d0             	add    rax,rdx
   140001e96:	48 c1 e0 03          	shl    rax,0x3
   140001e9a:	48 01 c8             	add    rax,rcx
   140001e9d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001ea3:	e8 9f 12 00 00       	call   140003147 <_GetPEImageBase>
   140001ea8:	48 89 c1             	mov    rcx,rax
   140001eab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001eaf:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001eb2:	41 89 c1             	mov    r9d,eax
   140001eb5:	4c 8b 05 24 72 00 00 	mov    r8,QWORD PTR [rip+0x7224]        # 1400090e0 <the_secs>
   140001ebc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ebf:	48 63 d0             	movsxd rdx,eax
   140001ec2:	48 89 d0             	mov    rax,rdx
   140001ec5:	48 c1 e0 02          	shl    rax,0x2
   140001ec9:	48 01 d0             	add    rax,rdx
   140001ecc:	48 c1 e0 03          	shl    rax,0x3
   140001ed0:	4c 01 c0             	add    rax,r8
   140001ed3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001ed7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001edb:	48 8b 0d fe 71 00 00 	mov    rcx,QWORD PTR [rip+0x71fe]        # 1400090e0 <the_secs>
   140001ee2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ee5:	48 63 d0             	movsxd rdx,eax
   140001ee8:	48 89 d0             	mov    rax,rdx
   140001eeb:	48 c1 e0 02          	shl    rax,0x2
   140001eef:	48 01 d0             	add    rax,rdx
   140001ef2:	48 c1 e0 03          	shl    rax,0x3
   140001ef6:	48 01 c8             	add    rax,rcx
   140001ef9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001efd:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001f01:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001f07:	48 89 c1             	mov    rcx,rax
   140001f0a:	48 8b 05 e7 82 00 00 	mov    rax,QWORD PTR [rip+0x82e7]        # 14000a1f8 <__imp_VirtualQuery>
   140001f11:	ff d0                	call   rax
   140001f13:	48 85 c0             	test   rax,rax
   140001f16:	75 3f                	jne    140001f57 <mark_section_writable+0x1d2>
   140001f18:	48 8b 0d c1 71 00 00 	mov    rcx,QWORD PTR [rip+0x71c1]        # 1400090e0 <the_secs>
   140001f1f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f22:	48 63 d0             	movsxd rdx,eax
   140001f25:	48 89 d0             	mov    rax,rdx
   140001f28:	48 c1 e0 02          	shl    rax,0x2
   140001f2c:	48 01 d0             	add    rax,rdx
   140001f2f:	48 c1 e0 03          	shl    rax,0x3
   140001f33:	48 01 c8             	add    rax,rcx
   140001f36:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001f3a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001f3e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001f41:	89 c1                	mov    ecx,eax
   140001f43:	48 8d 05 c6 32 00 00 	lea    rax,[rip+0x32c6]        # 140005210 <.rdata+0x40>
   140001f4a:	49 89 d0             	mov    r8,rdx
   140001f4d:	89 ca                	mov    edx,ecx
   140001f4f:	48 89 c1             	mov    rcx,rax
   140001f52:	e8 c9 fd ff ff       	call   140001d20 <__report_error>
   140001f57:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001f5a:	83 f8 40             	cmp    eax,0x40
   140001f5d:	0f 84 e8 00 00 00    	je     14000204b <mark_section_writable+0x2c6>
   140001f63:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001f66:	83 f8 04             	cmp    eax,0x4
   140001f69:	0f 84 dc 00 00 00    	je     14000204b <mark_section_writable+0x2c6>
   140001f6f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001f72:	3d 80 00 00 00       	cmp    eax,0x80
   140001f77:	0f 84 ce 00 00 00    	je     14000204b <mark_section_writable+0x2c6>
   140001f7d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001f80:	83 f8 08             	cmp    eax,0x8
   140001f83:	0f 84 c2 00 00 00    	je     14000204b <mark_section_writable+0x2c6>
   140001f89:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001f8c:	83 f8 02             	cmp    eax,0x2
   140001f8f:	75 09                	jne    140001f9a <mark_section_writable+0x215>
   140001f91:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001f98:	eb 07                	jmp    140001fa1 <mark_section_writable+0x21c>
   140001f9a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001fa1:	48 8b 0d 38 71 00 00 	mov    rcx,QWORD PTR [rip+0x7138]        # 1400090e0 <the_secs>
   140001fa8:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001fab:	48 63 d0             	movsxd rdx,eax
   140001fae:	48 89 d0             	mov    rax,rdx
   140001fb1:	48 c1 e0 02          	shl    rax,0x2
   140001fb5:	48 01 d0             	add    rax,rdx
   140001fb8:	48 c1 e0 03          	shl    rax,0x3
   140001fbc:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001fc0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001fc4:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001fc8:	48 8b 0d 11 71 00 00 	mov    rcx,QWORD PTR [rip+0x7111]        # 1400090e0 <the_secs>
   140001fcf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001fd2:	48 63 d0             	movsxd rdx,eax
   140001fd5:	48 89 d0             	mov    rax,rdx
   140001fd8:	48 c1 e0 02          	shl    rax,0x2
   140001fdc:	48 01 d0             	add    rax,rdx
   140001fdf:	48 c1 e0 03          	shl    rax,0x3
   140001fe3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001fe7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001feb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001fef:	48 8b 0d ea 70 00 00 	mov    rcx,QWORD PTR [rip+0x70ea]        # 1400090e0 <the_secs>
   140001ff6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ff9:	48 63 d0             	movsxd rdx,eax
   140001ffc:	48 89 d0             	mov    rax,rdx
   140001fff:	48 c1 e0 02          	shl    rax,0x2
   140002003:	48 01 d0             	add    rax,rdx
   140002006:	48 c1 e0 03          	shl    rax,0x3
   14000200a:	48 01 c8             	add    rax,rcx
   14000200d:	49 89 c0             	mov    r8,rax
   140002010:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140002014:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140002018:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   14000201b:	4d 89 c1             	mov    r9,r8
   14000201e:	41 89 c8             	mov    r8d,ecx
   140002021:	48 89 c1             	mov    rcx,rax
   140002024:	48 8b 05 c5 81 00 00 	mov    rax,QWORD PTR [rip+0x81c5]        # 14000a1f0 <__imp_VirtualProtect>
   14000202b:	ff d0                	call   rax
   14000202d:	85 c0                	test   eax,eax
   14000202f:	75 1a                	jne    14000204b <mark_section_writable+0x2c6>
   140002031:	48 8b 05 70 81 00 00 	mov    rax,QWORD PTR [rip+0x8170]        # 14000a1a8 <__imp_GetLastError>
   140002038:	ff d0                	call   rax
   14000203a:	89 c2                	mov    edx,eax
   14000203c:	48 8d 05 05 32 00 00 	lea    rax,[rip+0x3205]        # 140005248 <.rdata+0x78>
   140002043:	48 89 c1             	mov    rcx,rax
   140002046:	e8 d5 fc ff ff       	call   140001d20 <__report_error>
   14000204b:	8b 05 97 70 00 00    	mov    eax,DWORD PTR [rip+0x7097]        # 1400090e8 <maxSections>
   140002051:	83 c0 01             	add    eax,0x1
   140002054:	89 05 8e 70 00 00    	mov    DWORD PTR [rip+0x708e],eax        # 1400090e8 <maxSections>
   14000205a:	eb 01                	jmp    14000205d <mark_section_writable+0x2d8>
   14000205c:	90                   	nop
   14000205d:	48 83 c4 60          	add    rsp,0x60
   140002061:	5d                   	pop    rbp
   140002062:	c3                   	ret

0000000140002063 <restore_modified_sections>:
   140002063:	55                   	push   rbp
   140002064:	48 89 e5             	mov    rbp,rsp
   140002067:	48 83 ec 30          	sub    rsp,0x30
   14000206b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002072:	e9 ad 00 00 00       	jmp    140002124 <restore_modified_sections+0xc1>
   140002077:	48 8b 0d 62 70 00 00 	mov    rcx,QWORD PTR [rip+0x7062]        # 1400090e0 <the_secs>
   14000207e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002081:	48 63 d0             	movsxd rdx,eax
   140002084:	48 89 d0             	mov    rax,rdx
   140002087:	48 c1 e0 02          	shl    rax,0x2
   14000208b:	48 01 d0             	add    rax,rdx
   14000208e:	48 c1 e0 03          	shl    rax,0x3
   140002092:	48 01 c8             	add    rax,rcx
   140002095:	8b 00                	mov    eax,DWORD PTR [rax]
   140002097:	85 c0                	test   eax,eax
   140002099:	0f 84 80 00 00 00    	je     14000211f <restore_modified_sections+0xbc>
   14000209f:	48 8b 0d 3a 70 00 00 	mov    rcx,QWORD PTR [rip+0x703a]        # 1400090e0 <the_secs>
   1400020a6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400020a9:	48 63 d0             	movsxd rdx,eax
   1400020ac:	48 89 d0             	mov    rax,rdx
   1400020af:	48 c1 e0 02          	shl    rax,0x2
   1400020b3:	48 01 d0             	add    rax,rdx
   1400020b6:	48 c1 e0 03          	shl    rax,0x3
   1400020ba:	48 01 c8             	add    rax,rcx
   1400020bd:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   1400020c0:	48 8b 0d 19 70 00 00 	mov    rcx,QWORD PTR [rip+0x7019]        # 1400090e0 <the_secs>
   1400020c7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400020ca:	48 63 d0             	movsxd rdx,eax
   1400020cd:	48 89 d0             	mov    rax,rdx
   1400020d0:	48 c1 e0 02          	shl    rax,0x2
   1400020d4:	48 01 d0             	add    rax,rdx
   1400020d7:	48 c1 e0 03          	shl    rax,0x3
   1400020db:	48 01 c8             	add    rax,rcx
   1400020de:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   1400020e2:	4c 8b 05 f7 6f 00 00 	mov    r8,QWORD PTR [rip+0x6ff7]        # 1400090e0 <the_secs>
   1400020e9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400020ec:	48 63 d0             	movsxd rdx,eax
   1400020ef:	48 89 d0             	mov    rax,rdx
   1400020f2:	48 c1 e0 02          	shl    rax,0x2
   1400020f6:	48 01 d0             	add    rax,rdx
   1400020f9:	48 c1 e0 03          	shl    rax,0x3
   1400020fd:	4c 01 c0             	add    rax,r8
   140002100:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140002104:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140002108:	49 89 d1             	mov    r9,rdx
   14000210b:	45 89 d0             	mov    r8d,r10d
   14000210e:	48 89 ca             	mov    rdx,rcx
   140002111:	48 89 c1             	mov    rcx,rax
   140002114:	48 8b 05 d5 80 00 00 	mov    rax,QWORD PTR [rip+0x80d5]        # 14000a1f0 <__imp_VirtualProtect>
   14000211b:	ff d0                	call   rax
   14000211d:	eb 01                	jmp    140002120 <restore_modified_sections+0xbd>
   14000211f:	90                   	nop
   140002120:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140002124:	8b 05 be 6f 00 00    	mov    eax,DWORD PTR [rip+0x6fbe]        # 1400090e8 <maxSections>
   14000212a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   14000212d:	0f 8c 44 ff ff ff    	jl     140002077 <restore_modified_sections+0x14>
   140002133:	90                   	nop
   140002134:	90                   	nop
   140002135:	48 83 c4 30          	add    rsp,0x30
   140002139:	5d                   	pop    rbp
   14000213a:	c3                   	ret

000000014000213b <__write_memory>:
   14000213b:	55                   	push   rbp
   14000213c:	48 89 e5             	mov    rbp,rsp
   14000213f:	48 83 ec 20          	sub    rsp,0x20
   140002143:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002147:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000214b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000214f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140002154:	74 25                	je     14000217b <__write_memory+0x40>
   140002156:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000215a:	48 89 c1             	mov    rcx,rax
   14000215d:	e8 23 fc ff ff       	call   140001d85 <mark_section_writable>
   140002162:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140002166:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000216a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000216e:	49 89 c8             	mov    r8,rcx
   140002171:	48 89 c1             	mov    rcx,rax
   140002174:	e8 37 13 00 00       	call   1400034b0 <memcpy>
   140002179:	eb 01                	jmp    14000217c <__write_memory+0x41>
   14000217b:	90                   	nop
   14000217c:	48 83 c4 20          	add    rsp,0x20
   140002180:	5d                   	pop    rbp
   140002181:	c3                   	ret

0000000140002182 <do_pseudo_reloc>:
   140002182:	55                   	push   rbp
   140002183:	48 89 e5             	mov    rbp,rsp
   140002186:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   14000218a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000218e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002192:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002196:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000219a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000219e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400021a2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400021a6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400021aa:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   1400021af:	0f 8e 44 03 00 00    	jle    1400024f9 <do_pseudo_reloc+0x377>
   1400021b5:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   1400021ba:	7e 25                	jle    1400021e1 <do_pseudo_reloc+0x5f>
   1400021bc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021c0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021c2:	85 c0                	test   eax,eax
   1400021c4:	75 1b                	jne    1400021e1 <do_pseudo_reloc+0x5f>
   1400021c6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021ca:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400021cd:	85 c0                	test   eax,eax
   1400021cf:	75 10                	jne    1400021e1 <do_pseudo_reloc+0x5f>
   1400021d1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021d5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021d8:	85 c0                	test   eax,eax
   1400021da:	75 05                	jne    1400021e1 <do_pseudo_reloc+0x5f>
   1400021dc:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   1400021e1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021e5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021e7:	85 c0                	test   eax,eax
   1400021e9:	75 0b                	jne    1400021f6 <do_pseudo_reloc+0x74>
   1400021eb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021ef:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400021f2:	85 c0                	test   eax,eax
   1400021f4:	74 59                	je     14000224f <do_pseudo_reloc+0xcd>
   1400021f6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400021fa:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400021fe:	eb 40                	jmp    140002240 <do_pseudo_reloc+0xbe>
   140002200:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002204:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002207:	89 c2                	mov    edx,eax
   140002209:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000220d:	48 01 d0             	add    rax,rdx
   140002210:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002214:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002218:	8b 10                	mov    edx,DWORD PTR [rax]
   14000221a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000221e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002220:	01 d0                	add    eax,edx
   140002222:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002225:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002229:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000222d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002233:	48 89 c1             	mov    rcx,rax
   140002236:	e8 00 ff ff ff       	call   14000213b <__write_memory>
   14000223b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002240:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002244:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002248:	72 b6                	jb     140002200 <do_pseudo_reloc+0x7e>
   14000224a:	e9 ab 02 00 00       	jmp    1400024fa <do_pseudo_reloc+0x378>
   14000224f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002253:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002256:	83 f8 01             	cmp    eax,0x1
   140002259:	74 18                	je     140002273 <do_pseudo_reloc+0xf1>
   14000225b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000225f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002262:	89 c2                	mov    edx,eax
   140002264:	48 8d 05 05 30 00 00 	lea    rax,[rip+0x3005]        # 140005270 <.rdata+0xa0>
   14000226b:	48 89 c1             	mov    rcx,rax
   14000226e:	e8 ad fa ff ff       	call   140001d20 <__report_error>
   140002273:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002277:	48 83 c0 0c          	add    rax,0xc
   14000227b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000227f:	e9 65 02 00 00       	jmp    1400024e9 <do_pseudo_reloc+0x367>
   140002284:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002288:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000228b:	89 c2                	mov    edx,eax
   14000228d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002291:	48 01 d0             	add    rax,rdx
   140002294:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002298:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000229c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000229e:	89 c2                	mov    edx,eax
   1400022a0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400022a4:	48 01 d0             	add    rax,rdx
   1400022a7:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400022ab:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400022af:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400022b2:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400022b6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022ba:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022bd:	0f b6 c0             	movzx  eax,al
   1400022c0:	83 f8 40             	cmp    eax,0x40
   1400022c3:	0f 84 b6 00 00 00    	je     14000237f <do_pseudo_reloc+0x1fd>
   1400022c9:	83 f8 40             	cmp    eax,0x40
   1400022cc:	0f 87 ba 00 00 00    	ja     14000238c <do_pseudo_reloc+0x20a>
   1400022d2:	83 f8 20             	cmp    eax,0x20
   1400022d5:	74 77                	je     14000234e <do_pseudo_reloc+0x1cc>
   1400022d7:	83 f8 20             	cmp    eax,0x20
   1400022da:	0f 87 ac 00 00 00    	ja     14000238c <do_pseudo_reloc+0x20a>
   1400022e0:	83 f8 08             	cmp    eax,0x8
   1400022e3:	74 0a                	je     1400022ef <do_pseudo_reloc+0x16d>
   1400022e5:	83 f8 10             	cmp    eax,0x10
   1400022e8:	74 38                	je     140002322 <do_pseudo_reloc+0x1a0>
   1400022ea:	e9 9d 00 00 00       	jmp    14000238c <do_pseudo_reloc+0x20a>
   1400022ef:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022f3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400022f6:	0f b6 c0             	movzx  eax,al
   1400022f9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022fd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002301:	25 80 00 00 00       	and    eax,0x80
   140002306:	48 85 c0             	test   rax,rax
   140002309:	0f 84 9d 00 00 00    	je     1400023ac <do_pseudo_reloc+0x22a>
   14000230f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002313:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002319:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000231d:	e9 8a 00 00 00       	jmp    1400023ac <do_pseudo_reloc+0x22a>
   140002322:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002326:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002329:	0f b7 c0             	movzx  eax,ax
   14000232c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002330:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002334:	25 00 80 00 00       	and    eax,0x8000
   140002339:	48 85 c0             	test   rax,rax
   14000233c:	74 71                	je     1400023af <do_pseudo_reloc+0x22d>
   14000233e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002342:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002348:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000234c:	eb 61                	jmp    1400023af <do_pseudo_reloc+0x22d>
   14000234e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002352:	8b 00                	mov    eax,DWORD PTR [rax]
   140002354:	89 c0                	mov    eax,eax
   140002356:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000235a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000235e:	25 00 00 00 80       	and    eax,0x80000000
   140002363:	48 85 c0             	test   rax,rax
   140002366:	74 4a                	je     1400023b2 <do_pseudo_reloc+0x230>
   140002368:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000236c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002373:	ff ff ff 
   140002376:	48 09 d0             	or     rax,rdx
   140002379:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000237d:	eb 33                	jmp    1400023b2 <do_pseudo_reloc+0x230>
   14000237f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002383:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002386:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000238a:	eb 27                	jmp    1400023b3 <do_pseudo_reloc+0x231>
   14000238c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002393:	00 
   140002394:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002398:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000239b:	0f b6 c0             	movzx  eax,al
   14000239e:	48 8d 0d 03 2f 00 00 	lea    rcx,[rip+0x2f03]        # 1400052a8 <.rdata+0xd8>
   1400023a5:	89 c2                	mov    edx,eax
   1400023a7:	e8 74 f9 ff ff       	call   140001d20 <__report_error>
   1400023ac:	90                   	nop
   1400023ad:	eb 04                	jmp    1400023b3 <do_pseudo_reloc+0x231>
   1400023af:	90                   	nop
   1400023b0:	eb 01                	jmp    1400023b3 <do_pseudo_reloc+0x231>
   1400023b2:	90                   	nop
   1400023b3:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   1400023b7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400023bb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400023bd:	89 c2                	mov    edx,eax
   1400023bf:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400023c3:	48 01 c2             	add    rdx,rax
   1400023c6:	48 89 c8             	mov    rax,rcx
   1400023c9:	48 29 d0             	sub    rax,rdx
   1400023cc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400023d0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400023d4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400023d8:	48 01 d0             	add    rax,rdx
   1400023db:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400023df:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400023e3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400023e6:	25 ff 00 00 00       	and    eax,0xff
   1400023eb:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400023ee:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400023f2:	77 67                	ja     14000245b <do_pseudo_reloc+0x2d9>
   1400023f4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400023f7:	ba 01 00 00 00       	mov    edx,0x1
   1400023fc:	89 c1                	mov    ecx,eax
   1400023fe:	48 d3 e2             	shl    rdx,cl
   140002401:	48 89 d0             	mov    rax,rdx
   140002404:	48 83 e8 01          	sub    rax,0x1
   140002408:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000240c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000240f:	83 e8 01             	sub    eax,0x1
   140002412:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002419:	89 c1                	mov    ecx,eax
   14000241b:	48 d3 e2             	shl    rdx,cl
   14000241e:	48 89 d0             	mov    rax,rdx
   140002421:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002425:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002429:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000242d:	7c 0a                	jl     140002439 <do_pseudo_reloc+0x2b7>
   14000242f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002433:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002437:	7e 22                	jle    14000245b <do_pseudo_reloc+0x2d9>
   140002439:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000243d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002441:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002445:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002448:	48 8d 0d 89 2e 00 00 	lea    rcx,[rip+0x2e89]        # 1400052d8 <.rdata+0x108>
   14000244f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002454:	89 c2                	mov    edx,eax
   140002456:	e8 c5 f8 ff ff       	call   140001d20 <__report_error>
   14000245b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000245f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002462:	0f b6 c0             	movzx  eax,al
   140002465:	83 f8 40             	cmp    eax,0x40
   140002468:	74 63                	je     1400024cd <do_pseudo_reloc+0x34b>
   14000246a:	83 f8 40             	cmp    eax,0x40
   14000246d:	77 75                	ja     1400024e4 <do_pseudo_reloc+0x362>
   14000246f:	83 f8 20             	cmp    eax,0x20
   140002472:	74 41                	je     1400024b5 <do_pseudo_reloc+0x333>
   140002474:	83 f8 20             	cmp    eax,0x20
   140002477:	77 6b                	ja     1400024e4 <do_pseudo_reloc+0x362>
   140002479:	83 f8 08             	cmp    eax,0x8
   14000247c:	74 07                	je     140002485 <do_pseudo_reloc+0x303>
   14000247e:	83 f8 10             	cmp    eax,0x10
   140002481:	74 1a                	je     14000249d <do_pseudo_reloc+0x31b>
   140002483:	eb 5f                	jmp    1400024e4 <do_pseudo_reloc+0x362>
   140002485:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002489:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000248d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002493:	48 89 c1             	mov    rcx,rax
   140002496:	e8 a0 fc ff ff       	call   14000213b <__write_memory>
   14000249b:	eb 47                	jmp    1400024e4 <do_pseudo_reloc+0x362>
   14000249d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400024a1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400024a5:	41 b8 02 00 00 00    	mov    r8d,0x2
   1400024ab:	48 89 c1             	mov    rcx,rax
   1400024ae:	e8 88 fc ff ff       	call   14000213b <__write_memory>
   1400024b3:	eb 2f                	jmp    1400024e4 <do_pseudo_reloc+0x362>
   1400024b5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400024b9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400024bd:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400024c3:	48 89 c1             	mov    rcx,rax
   1400024c6:	e8 70 fc ff ff       	call   14000213b <__write_memory>
   1400024cb:	eb 17                	jmp    1400024e4 <do_pseudo_reloc+0x362>
   1400024cd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400024d1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400024d5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400024db:	48 89 c1             	mov    rcx,rax
   1400024de:	e8 58 fc ff ff       	call   14000213b <__write_memory>
   1400024e3:	90                   	nop
   1400024e4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400024e9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400024ed:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400024f1:	0f 82 8d fd ff ff    	jb     140002284 <do_pseudo_reloc+0x102>
   1400024f7:	eb 01                	jmp    1400024fa <do_pseudo_reloc+0x378>
   1400024f9:	90                   	nop
   1400024fa:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400024fe:	5d                   	pop    rbp
   1400024ff:	c3                   	ret

0000000140002500 <_pei386_runtime_relocator>:
   140002500:	55                   	push   rbp
   140002501:	48 89 e5             	mov    rbp,rsp
   140002504:	48 83 ec 30          	sub    rsp,0x30
   140002508:	8b 05 de 6b 00 00    	mov    eax,DWORD PTR [rip+0x6bde]        # 1400090ec <was_init.0>
   14000250e:	85 c0                	test   eax,eax
   140002510:	0f 85 88 00 00 00    	jne    14000259e <_pei386_runtime_relocator+0x9e>
   140002516:	8b 05 d0 6b 00 00    	mov    eax,DWORD PTR [rip+0x6bd0]        # 1400090ec <was_init.0>
   14000251c:	83 c0 01             	add    eax,0x1
   14000251f:	89 05 c7 6b 00 00    	mov    DWORD PTR [rip+0x6bc7],eax        # 1400090ec <was_init.0>
   140002525:	e8 21 0b 00 00       	call   14000304b <__mingw_GetSectionCount>
   14000252a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000252d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002530:	48 63 d0             	movsxd rdx,eax
   140002533:	48 89 d0             	mov    rax,rdx
   140002536:	48 c1 e0 02          	shl    rax,0x2
   14000253a:	48 01 d0             	add    rax,rdx
   14000253d:	48 c1 e0 03          	shl    rax,0x3
   140002541:	48 83 c0 0f          	add    rax,0xf
   140002545:	48 c1 e8 04          	shr    rax,0x4
   140002549:	48 c1 e0 04          	shl    rax,0x4
   14000254d:	e8 7e 0d 00 00       	call   1400032d0 <___chkstk_ms>
   140002552:	48 29 c4             	sub    rsp,rax
   140002555:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000255a:	48 83 c0 0f          	add    rax,0xf
   14000255e:	48 c1 e8 04          	shr    rax,0x4
   140002562:	48 c1 e0 04          	shl    rax,0x4
   140002566:	48 89 05 73 6b 00 00 	mov    QWORD PTR [rip+0x6b73],rax        # 1400090e0 <the_secs>
   14000256d:	c7 05 71 6b 00 00 00 	mov    DWORD PTR [rip+0x6b71],0x0        # 1400090e8 <maxSections>
   140002574:	00 00 00 
   140002577:	48 8b 0d e2 2d 00 00 	mov    rcx,QWORD PTR [rip+0x2de2]        # 140005360 <.refptr.__ImageBase>
   14000257e:	48 8b 15 eb 2d 00 00 	mov    rdx,QWORD PTR [rip+0x2deb]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002585:	48 8b 05 f4 2d 00 00 	mov    rax,QWORD PTR [rip+0x2df4]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000258c:	49 89 c8             	mov    r8,rcx
   14000258f:	48 89 c1             	mov    rcx,rax
   140002592:	e8 eb fb ff ff       	call   140002182 <do_pseudo_reloc>
   140002597:	e8 c7 fa ff ff       	call   140002063 <restore_modified_sections>
   14000259c:	eb 01                	jmp    14000259f <_pei386_runtime_relocator+0x9f>
   14000259e:	90                   	nop
   14000259f:	48 89 ec             	mov    rsp,rbp
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

00000001400025b0 <__mingw_raise_matherr>:
   1400025b0:	55                   	push   rbp
   1400025b1:	48 89 e5             	mov    rbp,rsp
   1400025b4:	48 83 ec 50          	sub    rsp,0x50
   1400025b8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400025bb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400025bf:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   1400025c4:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   1400025c9:	48 8b 05 20 6b 00 00 	mov    rax,QWORD PTR [rip+0x6b20]        # 1400090f0 <stUserMathErr>
   1400025d0:	48 85 c0             	test   rax,rax
   1400025d3:	74 3e                	je     140002613 <__mingw_raise_matherr+0x63>
   1400025d5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400025d8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400025db:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400025df:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400025e3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400025e8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400025ed:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400025f2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400025f7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400025fc:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002601:	48 8b 15 e8 6a 00 00 	mov    rdx,QWORD PTR [rip+0x6ae8]        # 1400090f0 <stUserMathErr>
   140002608:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000260c:	48 89 c1             	mov    rcx,rax
   14000260f:	ff d2                	call   rdx
   140002611:	eb 01                	jmp    140002614 <__mingw_raise_matherr+0x64>
   140002613:	90                   	nop
   140002614:	48 83 c4 50          	add    rsp,0x50
   140002618:	5d                   	pop    rbp
   140002619:	c3                   	ret

000000014000261a <__mingw_setusermatherr>:
   14000261a:	55                   	push   rbp
   14000261b:	48 89 e5             	mov    rbp,rsp
   14000261e:	48 83 ec 20          	sub    rsp,0x20
   140002622:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002626:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000262a:	48 89 05 bf 6a 00 00 	mov    QWORD PTR [rip+0x6abf],rax        # 1400090f0 <stUserMathErr>
   140002631:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002635:	48 89 c1             	mov    rcx,rax
   140002638:	e8 13 0e 00 00       	call   140003450 <__setusermatherr>
   14000263d:	90                   	nop
   14000263e:	48 83 c4 20          	add    rsp,0x20
   140002642:	5d                   	pop    rbp
   140002643:	c3                   	ret
   140002644:	90                   	nop
   140002645:	90                   	nop
   140002646:	90                   	nop
   140002647:	90                   	nop
   140002648:	90                   	nop
   140002649:	90                   	nop
   14000264a:	90                   	nop
   14000264b:	90                   	nop
   14000264c:	90                   	nop
   14000264d:	90                   	nop
   14000264e:	90                   	nop
   14000264f:	90                   	nop

0000000140002650 <__mingw_SEH_error_handler>:
   140002650:	55                   	push   rbp
   140002651:	48 89 e5             	mov    rbp,rsp
   140002654:	48 83 ec 30          	sub    rsp,0x30
   140002658:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000265c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002660:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002664:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002668:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000266f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002676:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000267a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000267d:	83 e0 02             	and    eax,0x2
   140002680:	85 c0                	test   eax,eax
   140002682:	74 0a                	je     14000268e <__mingw_SEH_error_handler+0x3e>
   140002684:	b8 01 00 00 00       	mov    eax,0x1
   140002689:	e9 16 02 00 00       	jmp    1400028a4 <__mingw_SEH_error_handler+0x254>
   14000268e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002692:	8b 00                	mov    eax,DWORD PTR [rax]
   140002694:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002699:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000269e:	75 18                	jne    1400026b8 <__mingw_SEH_error_handler+0x68>
   1400026a0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026a4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400026a7:	83 e0 01             	and    eax,0x1
   1400026aa:	85 c0                	test   eax,eax
   1400026ac:	75 0a                	jne    1400026b8 <__mingw_SEH_error_handler+0x68>
   1400026ae:	b8 00 00 00 00       	mov    eax,0x0
   1400026b3:	e9 ec 01 00 00       	jmp    1400028a4 <__mingw_SEH_error_handler+0x254>
   1400026b8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026bc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026be:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026c3:	0f 84 12 01 00 00    	je     1400027db <__mingw_SEH_error_handler+0x18b>
   1400026c9:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026ce:	0f 87 c3 01 00 00    	ja     140002897 <__mingw_SEH_error_handler+0x247>
   1400026d4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400026d9:	0f 87 b8 01 00 00    	ja     140002897 <__mingw_SEH_error_handler+0x247>
   1400026df:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400026e4:	0f 83 4c 01 00 00    	jae    140002836 <__mingw_SEH_error_handler+0x1e6>
   1400026ea:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400026ef:	0f 84 3a 01 00 00    	je     14000282f <__mingw_SEH_error_handler+0x1df>
   1400026f5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400026fa:	0f 87 97 01 00 00    	ja     140002897 <__mingw_SEH_error_handler+0x247>
   140002700:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002705:	0f 84 83 01 00 00    	je     14000288e <__mingw_SEH_error_handler+0x23e>
   14000270b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002710:	0f 87 81 01 00 00    	ja     140002897 <__mingw_SEH_error_handler+0x247>
   140002716:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000271b:	0f 87 76 01 00 00    	ja     140002897 <__mingw_SEH_error_handler+0x247>
   140002721:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002726:	0f 83 03 01 00 00    	jae    14000282f <__mingw_SEH_error_handler+0x1df>
   14000272c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002731:	0f 84 57 01 00 00    	je     14000288e <__mingw_SEH_error_handler+0x23e>
   140002737:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000273c:	0f 87 55 01 00 00    	ja     140002897 <__mingw_SEH_error_handler+0x247>
   140002742:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002747:	0f 84 8e 00 00 00    	je     1400027db <__mingw_SEH_error_handler+0x18b>
   14000274d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002752:	0f 87 3f 01 00 00    	ja     140002897 <__mingw_SEH_error_handler+0x247>
   140002758:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000275d:	0f 84 2b 01 00 00    	je     14000288e <__mingw_SEH_error_handler+0x23e>
   140002763:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002768:	0f 87 29 01 00 00    	ja     140002897 <__mingw_SEH_error_handler+0x247>
   14000276e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002773:	0f 84 15 01 00 00    	je     14000288e <__mingw_SEH_error_handler+0x23e>
   140002779:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000277e:	0f 85 13 01 00 00    	jne    140002897 <__mingw_SEH_error_handler+0x247>
   140002784:	ba 00 00 00 00       	mov    edx,0x0
   140002789:	b9 0b 00 00 00       	mov    ecx,0xb
   14000278e:	e8 35 0d 00 00       	call   1400034c8 <signal>
   140002793:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002797:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000279c:	75 1b                	jne    1400027b9 <__mingw_SEH_error_handler+0x169>
   14000279e:	ba 01 00 00 00       	mov    edx,0x1
   1400027a3:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027a8:	e8 1b 0d 00 00       	call   1400034c8 <signal>
   1400027ad:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400027b4:	e9 e1 00 00 00       	jmp    14000289a <__mingw_SEH_error_handler+0x24a>
   1400027b9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027be:	0f 84 d6 00 00 00    	je     14000289a <__mingw_SEH_error_handler+0x24a>
   1400027c4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027c8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027cd:	ff d0                	call   rax
   1400027cf:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400027d6:	e9 bf 00 00 00       	jmp    14000289a <__mingw_SEH_error_handler+0x24a>
   1400027db:	ba 00 00 00 00       	mov    edx,0x0
   1400027e0:	b9 04 00 00 00       	mov    ecx,0x4
   1400027e5:	e8 de 0c 00 00       	call   1400034c8 <signal>
   1400027ea:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027ee:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027f3:	75 1b                	jne    140002810 <__mingw_SEH_error_handler+0x1c0>
   1400027f5:	ba 01 00 00 00       	mov    edx,0x1
   1400027fa:	b9 04 00 00 00       	mov    ecx,0x4
   1400027ff:	e8 c4 0c 00 00       	call   1400034c8 <signal>
   140002804:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000280b:	e9 8d 00 00 00       	jmp    14000289d <__mingw_SEH_error_handler+0x24d>
   140002810:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002815:	0f 84 82 00 00 00    	je     14000289d <__mingw_SEH_error_handler+0x24d>
   14000281b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000281f:	b9 04 00 00 00       	mov    ecx,0x4
   140002824:	ff d0                	call   rax
   140002826:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000282d:	eb 6e                	jmp    14000289d <__mingw_SEH_error_handler+0x24d>
   14000282f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002836:	ba 00 00 00 00       	mov    edx,0x0
   14000283b:	b9 08 00 00 00       	mov    ecx,0x8
   140002840:	e8 83 0c 00 00       	call   1400034c8 <signal>
   140002845:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002849:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000284e:	75 23                	jne    140002873 <__mingw_SEH_error_handler+0x223>
   140002850:	ba 01 00 00 00       	mov    edx,0x1
   140002855:	b9 08 00 00 00       	mov    ecx,0x8
   14000285a:	e8 69 0c 00 00       	call   1400034c8 <signal>
   14000285f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002863:	74 05                	je     14000286a <__mingw_SEH_error_handler+0x21a>
   140002865:	e8 a6 05 00 00       	call   140002e10 <_fpreset>
   14000286a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002871:	eb 2d                	jmp    1400028a0 <__mingw_SEH_error_handler+0x250>
   140002873:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002878:	74 26                	je     1400028a0 <__mingw_SEH_error_handler+0x250>
   14000287a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000287e:	b9 08 00 00 00       	mov    ecx,0x8
   140002883:	ff d0                	call   rax
   140002885:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000288c:	eb 12                	jmp    1400028a0 <__mingw_SEH_error_handler+0x250>
   14000288e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002895:	eb 0a                	jmp    1400028a1 <__mingw_SEH_error_handler+0x251>
   140002897:	90                   	nop
   140002898:	eb 07                	jmp    1400028a1 <__mingw_SEH_error_handler+0x251>
   14000289a:	90                   	nop
   14000289b:	eb 04                	jmp    1400028a1 <__mingw_SEH_error_handler+0x251>
   14000289d:	90                   	nop
   14000289e:	eb 01                	jmp    1400028a1 <__mingw_SEH_error_handler+0x251>
   1400028a0:	90                   	nop
   1400028a1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400028a4:	48 83 c4 30          	add    rsp,0x30
   1400028a8:	5d                   	pop    rbp
   1400028a9:	c3                   	ret

00000001400028aa <_gnu_exception_handler>:
   1400028aa:	55                   	push   rbp
   1400028ab:	48 89 e5             	mov    rbp,rsp
   1400028ae:	48 83 ec 30          	sub    rsp,0x30
   1400028b2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400028b6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400028bd:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400028c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028c8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400028cb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400028cd:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400028d2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400028d7:	75 1b                	jne    1400028f4 <_gnu_exception_handler+0x4a>
   1400028d9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028dd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400028e0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400028e3:	83 e0 01             	and    eax,0x1
   1400028e6:	85 c0                	test   eax,eax
   1400028e8:	75 0a                	jne    1400028f4 <_gnu_exception_handler+0x4a>
   1400028ea:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400028ef:	e9 14 02 00 00       	jmp    140002b08 <_gnu_exception_handler+0x25e>
   1400028f4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028f8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400028fb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400028fd:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002902:	0f 84 12 01 00 00    	je     140002a1a <_gnu_exception_handler+0x170>
   140002908:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000290d:	0f 87 c3 01 00 00    	ja     140002ad6 <_gnu_exception_handler+0x22c>
   140002913:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002918:	0f 87 b8 01 00 00    	ja     140002ad6 <_gnu_exception_handler+0x22c>
   14000291e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002923:	0f 83 4c 01 00 00    	jae    140002a75 <_gnu_exception_handler+0x1cb>
   140002929:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000292e:	0f 84 3a 01 00 00    	je     140002a6e <_gnu_exception_handler+0x1c4>
   140002934:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002939:	0f 87 97 01 00 00    	ja     140002ad6 <_gnu_exception_handler+0x22c>
   14000293f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002944:	0f 84 83 01 00 00    	je     140002acd <_gnu_exception_handler+0x223>
   14000294a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000294f:	0f 87 81 01 00 00    	ja     140002ad6 <_gnu_exception_handler+0x22c>
   140002955:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000295a:	0f 87 76 01 00 00    	ja     140002ad6 <_gnu_exception_handler+0x22c>
   140002960:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002965:	0f 83 03 01 00 00    	jae    140002a6e <_gnu_exception_handler+0x1c4>
   14000296b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002970:	0f 84 57 01 00 00    	je     140002acd <_gnu_exception_handler+0x223>
   140002976:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000297b:	0f 87 55 01 00 00    	ja     140002ad6 <_gnu_exception_handler+0x22c>
   140002981:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002986:	0f 84 8e 00 00 00    	je     140002a1a <_gnu_exception_handler+0x170>
   14000298c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002991:	0f 87 3f 01 00 00    	ja     140002ad6 <_gnu_exception_handler+0x22c>
   140002997:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000299c:	0f 84 2b 01 00 00    	je     140002acd <_gnu_exception_handler+0x223>
   1400029a2:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400029a7:	0f 87 29 01 00 00    	ja     140002ad6 <_gnu_exception_handler+0x22c>
   1400029ad:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400029b2:	0f 84 15 01 00 00    	je     140002acd <_gnu_exception_handler+0x223>
   1400029b8:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400029bd:	0f 85 13 01 00 00    	jne    140002ad6 <_gnu_exception_handler+0x22c>
   1400029c3:	ba 00 00 00 00       	mov    edx,0x0
   1400029c8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400029cd:	e8 f6 0a 00 00       	call   1400034c8 <signal>
   1400029d2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029d6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400029db:	75 1b                	jne    1400029f8 <_gnu_exception_handler+0x14e>
   1400029dd:	ba 01 00 00 00       	mov    edx,0x1
   1400029e2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400029e7:	e8 dc 0a 00 00       	call   1400034c8 <signal>
   1400029ec:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400029f3:	e9 e1 00 00 00       	jmp    140002ad9 <_gnu_exception_handler+0x22f>
   1400029f8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400029fd:	0f 84 d6 00 00 00    	je     140002ad9 <_gnu_exception_handler+0x22f>
   140002a03:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a07:	b9 0b 00 00 00       	mov    ecx,0xb
   140002a0c:	ff d0                	call   rax
   140002a0e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a15:	e9 bf 00 00 00       	jmp    140002ad9 <_gnu_exception_handler+0x22f>
   140002a1a:	ba 00 00 00 00       	mov    edx,0x0
   140002a1f:	b9 04 00 00 00       	mov    ecx,0x4
   140002a24:	e8 9f 0a 00 00       	call   1400034c8 <signal>
   140002a29:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a2d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002a32:	75 1b                	jne    140002a4f <_gnu_exception_handler+0x1a5>
   140002a34:	ba 01 00 00 00       	mov    edx,0x1
   140002a39:	b9 04 00 00 00       	mov    ecx,0x4
   140002a3e:	e8 85 0a 00 00       	call   1400034c8 <signal>
   140002a43:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a4a:	e9 8d 00 00 00       	jmp    140002adc <_gnu_exception_handler+0x232>
   140002a4f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a54:	0f 84 82 00 00 00    	je     140002adc <_gnu_exception_handler+0x232>
   140002a5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a5e:	b9 04 00 00 00       	mov    ecx,0x4
   140002a63:	ff d0                	call   rax
   140002a65:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002a6c:	eb 6e                	jmp    140002adc <_gnu_exception_handler+0x232>
   140002a6e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002a75:	ba 00 00 00 00       	mov    edx,0x0
   140002a7a:	b9 08 00 00 00       	mov    ecx,0x8
   140002a7f:	e8 44 0a 00 00       	call   1400034c8 <signal>
   140002a84:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a88:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002a8d:	75 23                	jne    140002ab2 <_gnu_exception_handler+0x208>
   140002a8f:	ba 01 00 00 00       	mov    edx,0x1
   140002a94:	b9 08 00 00 00       	mov    ecx,0x8
   140002a99:	e8 2a 0a 00 00       	call   1400034c8 <signal>
   140002a9e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002aa2:	74 05                	je     140002aa9 <_gnu_exception_handler+0x1ff>
   140002aa4:	e8 67 03 00 00       	call   140002e10 <_fpreset>
   140002aa9:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002ab0:	eb 2d                	jmp    140002adf <_gnu_exception_handler+0x235>
   140002ab2:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002ab7:	74 26                	je     140002adf <_gnu_exception_handler+0x235>
   140002ab9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002abd:	b9 08 00 00 00       	mov    ecx,0x8
   140002ac2:	ff d0                	call   rax
   140002ac4:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002acb:	eb 12                	jmp    140002adf <_gnu_exception_handler+0x235>
   140002acd:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002ad4:	eb 0a                	jmp    140002ae0 <_gnu_exception_handler+0x236>
   140002ad6:	90                   	nop
   140002ad7:	eb 07                	jmp    140002ae0 <_gnu_exception_handler+0x236>
   140002ad9:	90                   	nop
   140002ada:	eb 04                	jmp    140002ae0 <_gnu_exception_handler+0x236>
   140002adc:	90                   	nop
   140002add:	eb 01                	jmp    140002ae0 <_gnu_exception_handler+0x236>
   140002adf:	90                   	nop
   140002ae0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002ae4:	75 1f                	jne    140002b05 <_gnu_exception_handler+0x25b>
   140002ae6:	48 8b 05 23 66 00 00 	mov    rax,QWORD PTR [rip+0x6623]        # 140009110 <__mingw_oldexcpt_handler>
   140002aed:	48 85 c0             	test   rax,rax
   140002af0:	74 13                	je     140002b05 <_gnu_exception_handler+0x25b>
   140002af2:	48 8b 15 17 66 00 00 	mov    rdx,QWORD PTR [rip+0x6617]        # 140009110 <__mingw_oldexcpt_handler>
   140002af9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002afd:	48 89 c1             	mov    rcx,rax
   140002b00:	ff d2                	call   rdx
   140002b02:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002b05:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002b08:	48 83 c4 30          	add    rsp,0x30
   140002b0c:	5d                   	pop    rbp
   140002b0d:	c3                   	ret
   140002b0e:	90                   	nop
   140002b0f:	90                   	nop

0000000140002b10 <___w64_mingwthr_add_key_dtor>:
   140002b10:	55                   	push   rbp
   140002b11:	48 89 e5             	mov    rbp,rsp
   140002b14:	48 83 ec 30          	sub    rsp,0x30
   140002b18:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002b1b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002b1f:	8b 05 23 66 00 00    	mov    eax,DWORD PTR [rip+0x6623]        # 140009148 <__mingwthr_cs_init>
   140002b25:	85 c0                	test   eax,eax
   140002b27:	75 07                	jne    140002b30 <___w64_mingwthr_add_key_dtor+0x20>
   140002b29:	b8 00 00 00 00       	mov    eax,0x0
   140002b2e:	eb 7b                	jmp    140002bab <___w64_mingwthr_add_key_dtor+0x9b>
   140002b30:	ba 18 00 00 00       	mov    edx,0x18
   140002b35:	b9 01 00 00 00       	mov    ecx,0x1
   140002b3a:	e8 41 09 00 00       	call   140003480 <calloc>
   140002b3f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b43:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b48:	75 07                	jne    140002b51 <___w64_mingwthr_add_key_dtor+0x41>
   140002b4a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140002b4f:	eb 5a                	jmp    140002bab <___w64_mingwthr_add_key_dtor+0x9b>
   140002b51:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b55:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002b58:	89 10                	mov    DWORD PTR [rax],edx
   140002b5a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b5e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002b62:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002b66:	48 8d 05 b3 65 00 00 	lea    rax,[rip+0x65b3]        # 140009120 <__mingwthr_cs>
   140002b6d:	48 89 c1             	mov    rcx,rax
   140002b70:	48 8b 05 21 76 00 00 	mov    rax,QWORD PTR [rip+0x7621]        # 14000a198 <__imp_EnterCriticalSection>
   140002b77:	ff d0                	call   rax
   140002b79:	48 8b 15 d0 65 00 00 	mov    rdx,QWORD PTR [rip+0x65d0]        # 140009150 <key_dtor_list>
   140002b80:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b84:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002b88:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b8c:	48 89 05 bd 65 00 00 	mov    QWORD PTR [rip+0x65bd],rax        # 140009150 <key_dtor_list>
   140002b93:	48 8d 05 86 65 00 00 	lea    rax,[rip+0x6586]        # 140009120 <__mingwthr_cs>
   140002b9a:	48 89 c1             	mov    rcx,rax
   140002b9d:	48 8b 05 24 76 00 00 	mov    rax,QWORD PTR [rip+0x7624]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002ba4:	ff d0                	call   rax
   140002ba6:	b8 00 00 00 00       	mov    eax,0x0
   140002bab:	48 83 c4 30          	add    rsp,0x30
   140002baf:	5d                   	pop    rbp
   140002bb0:	c3                   	ret

0000000140002bb1 <___w64_mingwthr_remove_key_dtor>:
   140002bb1:	55                   	push   rbp
   140002bb2:	48 89 e5             	mov    rbp,rsp
   140002bb5:	48 83 ec 30          	sub    rsp,0x30
   140002bb9:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002bbc:	8b 05 86 65 00 00    	mov    eax,DWORD PTR [rip+0x6586]        # 140009148 <__mingwthr_cs_init>
   140002bc2:	85 c0                	test   eax,eax
   140002bc4:	75 0a                	jne    140002bd0 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002bc6:	b8 00 00 00 00       	mov    eax,0x0
   140002bcb:	e9 9c 00 00 00       	jmp    140002c6c <___w64_mingwthr_remove_key_dtor+0xbb>
   140002bd0:	48 8d 05 49 65 00 00 	lea    rax,[rip+0x6549]        # 140009120 <__mingwthr_cs>
   140002bd7:	48 89 c1             	mov    rcx,rax
   140002bda:	48 8b 05 b7 75 00 00 	mov    rax,QWORD PTR [rip+0x75b7]        # 14000a198 <__imp_EnterCriticalSection>
   140002be1:	ff d0                	call   rax
   140002be3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002bea:	00 
   140002beb:	48 8b 05 5e 65 00 00 	mov    rax,QWORD PTR [rip+0x655e]        # 140009150 <key_dtor_list>
   140002bf2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002bf6:	eb 55                	jmp    140002c4d <___w64_mingwthr_remove_key_dtor+0x9c>
   140002bf8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bfc:	8b 00                	mov    eax,DWORD PTR [rax]
   140002bfe:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002c01:	75 36                	jne    140002c39 <___w64_mingwthr_remove_key_dtor+0x88>
   140002c03:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c08:	75 11                	jne    140002c1b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002c0a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c0e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c12:	48 89 05 37 65 00 00 	mov    QWORD PTR [rip+0x6537],rax        # 140009150 <key_dtor_list>
   140002c19:	eb 10                	jmp    140002c2b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002c1b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c1f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002c23:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c27:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002c2b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c2f:	48 89 c1             	mov    rcx,rax
   140002c32:	e8 69 08 00 00       	call   1400034a0 <free>
   140002c37:	eb 1b                	jmp    140002c54 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002c39:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c3d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c41:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c45:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c49:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c4d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002c52:	75 a4                	jne    140002bf8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002c54:	48 8d 05 c5 64 00 00 	lea    rax,[rip+0x64c5]        # 140009120 <__mingwthr_cs>
   140002c5b:	48 89 c1             	mov    rcx,rax
   140002c5e:	48 8b 05 63 75 00 00 	mov    rax,QWORD PTR [rip+0x7563]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002c65:	ff d0                	call   rax
   140002c67:	b8 00 00 00 00       	mov    eax,0x0
   140002c6c:	48 83 c4 30          	add    rsp,0x30
   140002c70:	5d                   	pop    rbp
   140002c71:	c3                   	ret

0000000140002c72 <__mingwthr_run_key_dtors>:
   140002c72:	55                   	push   rbp
   140002c73:	48 89 e5             	mov    rbp,rsp
   140002c76:	48 83 ec 30          	sub    rsp,0x30
   140002c7a:	8b 05 c8 64 00 00    	mov    eax,DWORD PTR [rip+0x64c8]        # 140009148 <__mingwthr_cs_init>
   140002c80:	85 c0                	test   eax,eax
   140002c82:	0f 84 82 00 00 00    	je     140002d0a <__mingwthr_run_key_dtors+0x98>
   140002c88:	48 8d 05 91 64 00 00 	lea    rax,[rip+0x6491]        # 140009120 <__mingwthr_cs>
   140002c8f:	48 89 c1             	mov    rcx,rax
   140002c92:	48 8b 05 ff 74 00 00 	mov    rax,QWORD PTR [rip+0x74ff]        # 14000a198 <__imp_EnterCriticalSection>
   140002c99:	ff d0                	call   rax
   140002c9b:	48 8b 05 ae 64 00 00 	mov    rax,QWORD PTR [rip+0x64ae]        # 140009150 <key_dtor_list>
   140002ca2:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ca6:	eb 46                	jmp    140002cee <__mingwthr_run_key_dtors+0x7c>
   140002ca8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cac:	8b 00                	mov    eax,DWORD PTR [rax]
   140002cae:	89 c1                	mov    ecx,eax
   140002cb0:	48 8b 05 31 75 00 00 	mov    rax,QWORD PTR [rip+0x7531]        # 14000a1e8 <__imp_TlsGetValue>
   140002cb7:	ff d0                	call   rax
   140002cb9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002cbd:	48 8b 05 e4 74 00 00 	mov    rax,QWORD PTR [rip+0x74e4]        # 14000a1a8 <__imp_GetLastError>
   140002cc4:	ff d0                	call   rax
   140002cc6:	85 c0                	test   eax,eax
   140002cc8:	75 18                	jne    140002ce2 <__mingwthr_run_key_dtors+0x70>
   140002cca:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002ccf:	74 11                	je     140002ce2 <__mingwthr_run_key_dtors+0x70>
   140002cd1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cd5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002cd9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002cdd:	48 89 c1             	mov    rcx,rax
   140002ce0:	ff d2                	call   rdx
   140002ce2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ce6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002cea:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cee:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002cf3:	75 b3                	jne    140002ca8 <__mingwthr_run_key_dtors+0x36>
   140002cf5:	48 8d 05 24 64 00 00 	lea    rax,[rip+0x6424]        # 140009120 <__mingwthr_cs>
   140002cfc:	48 89 c1             	mov    rcx,rax
   140002cff:	48 8b 05 c2 74 00 00 	mov    rax,QWORD PTR [rip+0x74c2]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002d06:	ff d0                	call   rax
   140002d08:	eb 01                	jmp    140002d0b <__mingwthr_run_key_dtors+0x99>
   140002d0a:	90                   	nop
   140002d0b:	48 83 c4 30          	add    rsp,0x30
   140002d0f:	5d                   	pop    rbp
   140002d10:	c3                   	ret

0000000140002d11 <__mingw_TLScallback>:
   140002d11:	55                   	push   rbp
   140002d12:	48 89 e5             	mov    rbp,rsp
   140002d15:	48 83 ec 30          	sub    rsp,0x30
   140002d19:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d1d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002d20:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002d24:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002d28:	0f 84 cc 00 00 00    	je     140002dfa <__mingw_TLScallback+0xe9>
   140002d2e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002d32:	0f 87 ca 00 00 00    	ja     140002e02 <__mingw_TLScallback+0xf1>
   140002d38:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002d3c:	0f 84 b1 00 00 00    	je     140002df3 <__mingw_TLScallback+0xe2>
   140002d42:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002d46:	0f 87 b6 00 00 00    	ja     140002e02 <__mingw_TLScallback+0xf1>
   140002d4c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002d50:	74 33                	je     140002d85 <__mingw_TLScallback+0x74>
   140002d52:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002d56:	0f 85 a6 00 00 00    	jne    140002e02 <__mingw_TLScallback+0xf1>
   140002d5c:	8b 05 e6 63 00 00    	mov    eax,DWORD PTR [rip+0x63e6]        # 140009148 <__mingwthr_cs_init>
   140002d62:	85 c0                	test   eax,eax
   140002d64:	75 13                	jne    140002d79 <__mingw_TLScallback+0x68>
   140002d66:	48 8d 05 b3 63 00 00 	lea    rax,[rip+0x63b3]        # 140009120 <__mingwthr_cs>
   140002d6d:	48 89 c1             	mov    rcx,rax
   140002d70:	48 8b 05 49 74 00 00 	mov    rax,QWORD PTR [rip+0x7449]        # 14000a1c0 <__imp_InitializeCriticalSection>
   140002d77:	ff d0                	call   rax
   140002d79:	c7 05 c5 63 00 00 01 	mov    DWORD PTR [rip+0x63c5],0x1        # 140009148 <__mingwthr_cs_init>
   140002d80:	00 00 00 
   140002d83:	eb 7d                	jmp    140002e02 <__mingw_TLScallback+0xf1>
   140002d85:	e8 e8 fe ff ff       	call   140002c72 <__mingwthr_run_key_dtors>
   140002d8a:	8b 05 b8 63 00 00    	mov    eax,DWORD PTR [rip+0x63b8]        # 140009148 <__mingwthr_cs_init>
   140002d90:	83 f8 01             	cmp    eax,0x1
   140002d93:	75 6c                	jne    140002e01 <__mingw_TLScallback+0xf0>
   140002d95:	48 8b 05 b4 63 00 00 	mov    rax,QWORD PTR [rip+0x63b4]        # 140009150 <key_dtor_list>
   140002d9c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002da0:	eb 20                	jmp    140002dc2 <__mingw_TLScallback+0xb1>
   140002da2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002da6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002daa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002dae:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002db2:	48 89 c1             	mov    rcx,rax
   140002db5:	e8 e6 06 00 00       	call   1400034a0 <free>
   140002dba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002dbe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002dc2:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002dc7:	75 d9                	jne    140002da2 <__mingw_TLScallback+0x91>
   140002dc9:	48 c7 05 7c 63 00 00 	mov    QWORD PTR [rip+0x637c],0x0        # 140009150 <key_dtor_list>
   140002dd0:	00 00 00 00 
   140002dd4:	c7 05 6a 63 00 00 00 	mov    DWORD PTR [rip+0x636a],0x0        # 140009148 <__mingwthr_cs_init>
   140002ddb:	00 00 00 
   140002dde:	48 8d 05 3b 63 00 00 	lea    rax,[rip+0x633b]        # 140009120 <__mingwthr_cs>
   140002de5:	48 89 c1             	mov    rcx,rax
   140002de8:	48 8b 05 a1 73 00 00 	mov    rax,QWORD PTR [rip+0x73a1]        # 14000a190 <__IAT_start__>
   140002def:	ff d0                	call   rax
   140002df1:	eb 0e                	jmp    140002e01 <__mingw_TLScallback+0xf0>
   140002df3:	e8 18 00 00 00       	call   140002e10 <_fpreset>
   140002df8:	eb 08                	jmp    140002e02 <__mingw_TLScallback+0xf1>
   140002dfa:	e8 73 fe ff ff       	call   140002c72 <__mingwthr_run_key_dtors>
   140002dff:	eb 01                	jmp    140002e02 <__mingw_TLScallback+0xf1>
   140002e01:	90                   	nop
   140002e02:	b8 01 00 00 00       	mov    eax,0x1
   140002e07:	48 83 c4 30          	add    rsp,0x30
   140002e0b:	5d                   	pop    rbp
   140002e0c:	c3                   	ret
   140002e0d:	90                   	nop
   140002e0e:	90                   	nop
   140002e0f:	90                   	nop

0000000140002e10 <_fpreset>:
   140002e10:	55                   	push   rbp
   140002e11:	48 89 e5             	mov    rbp,rsp
   140002e14:	db e3                	fninit
   140002e16:	90                   	nop
   140002e17:	5d                   	pop    rbp
   140002e18:	c3                   	ret
   140002e19:	90                   	nop
   140002e1a:	90                   	nop
   140002e1b:	90                   	nop
   140002e1c:	90                   	nop
   140002e1d:	90                   	nop
   140002e1e:	90                   	nop
   140002e1f:	90                   	nop

0000000140002e20 <_ValidateImageBase>:
   140002e20:	55                   	push   rbp
   140002e21:	48 89 e5             	mov    rbp,rsp
   140002e24:	48 83 ec 20          	sub    rsp,0x20
   140002e28:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e2c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e30:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e34:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e38:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002e3b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002e3f:	74 07                	je     140002e48 <_ValidateImageBase+0x28>
   140002e41:	b8 00 00 00 00       	mov    eax,0x0
   140002e46:	eb 4e                	jmp    140002e96 <_ValidateImageBase+0x76>
   140002e48:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e4c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e4f:	48 63 d0             	movsxd rdx,eax
   140002e52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e56:	48 01 d0             	add    rax,rdx
   140002e59:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e5d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e61:	8b 00                	mov    eax,DWORD PTR [rax]
   140002e63:	3d 50 45 00 00       	cmp    eax,0x4550
   140002e68:	74 07                	je     140002e71 <_ValidateImageBase+0x51>
   140002e6a:	b8 00 00 00 00       	mov    eax,0x0
   140002e6f:	eb 25                	jmp    140002e96 <_ValidateImageBase+0x76>
   140002e71:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e75:	48 83 c0 18          	add    rax,0x18
   140002e79:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e7d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e81:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002e84:	66 3d 0b 02          	cmp    ax,0x20b
   140002e88:	74 07                	je     140002e91 <_ValidateImageBase+0x71>
   140002e8a:	b8 00 00 00 00       	mov    eax,0x0
   140002e8f:	eb 05                	jmp    140002e96 <_ValidateImageBase+0x76>
   140002e91:	b8 01 00 00 00       	mov    eax,0x1
   140002e96:	48 83 c4 20          	add    rsp,0x20
   140002e9a:	5d                   	pop    rbp
   140002e9b:	c3                   	ret

0000000140002e9c <_FindPESection>:
   140002e9c:	55                   	push   rbp
   140002e9d:	48 89 e5             	mov    rbp,rsp
   140002ea0:	48 83 ec 20          	sub    rsp,0x20
   140002ea4:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ea8:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002eac:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002eb0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002eb3:	48 63 d0             	movsxd rdx,eax
   140002eb6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002eba:	48 01 d0             	add    rax,rdx
   140002ebd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ec1:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ec8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ecc:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002ed0:	0f b7 d0             	movzx  edx,ax
   140002ed3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ed7:	48 01 d0             	add    rax,rdx
   140002eda:	48 83 c0 18          	add    rax,0x18
   140002ede:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ee2:	eb 36                	jmp    140002f1a <_FindPESection+0x7e>
   140002ee4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ee8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002eeb:	89 c0                	mov    eax,eax
   140002eed:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002ef1:	72 1e                	jb     140002f11 <_FindPESection+0x75>
   140002ef3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ef7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002efa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002efe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002f01:	01 d0                	add    eax,edx
   140002f03:	89 c0                	mov    eax,eax
   140002f05:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002f09:	73 06                	jae    140002f11 <_FindPESection+0x75>
   140002f0b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f0f:	eb 1e                	jmp    140002f2f <_FindPESection+0x93>
   140002f11:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f15:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f1a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f1e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f22:	0f b7 c0             	movzx  eax,ax
   140002f25:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f28:	72 ba                	jb     140002ee4 <_FindPESection+0x48>
   140002f2a:	b8 00 00 00 00       	mov    eax,0x0
   140002f2f:	48 83 c4 20          	add    rsp,0x20
   140002f33:	5d                   	pop    rbp
   140002f34:	c3                   	ret

0000000140002f35 <_FindPESectionByName>:
   140002f35:	55                   	push   rbp
   140002f36:	48 89 e5             	mov    rbp,rsp
   140002f39:	48 83 ec 40          	sub    rsp,0x40
   140002f3d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f41:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f45:	48 89 c1             	mov    rcx,rax
   140002f48:	e8 83 05 00 00       	call   1400034d0 <strlen>
   140002f4d:	48 83 f8 08          	cmp    rax,0x8
   140002f51:	76 0a                	jbe    140002f5d <_FindPESectionByName+0x28>
   140002f53:	b8 00 00 00 00       	mov    eax,0x0
   140002f58:	e9 98 00 00 00       	jmp    140002ff5 <_FindPESectionByName+0xc0>
   140002f5d:	48 8b 05 fc 23 00 00 	mov    rax,QWORD PTR [rip+0x23fc]        # 140005360 <.refptr.__ImageBase>
   140002f64:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f68:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f6c:	48 89 c1             	mov    rcx,rax
   140002f6f:	e8 ac fe ff ff       	call   140002e20 <_ValidateImageBase>
   140002f74:	85 c0                	test   eax,eax
   140002f76:	75 07                	jne    140002f7f <_FindPESectionByName+0x4a>
   140002f78:	b8 00 00 00 00       	mov    eax,0x0
   140002f7d:	eb 76                	jmp    140002ff5 <_FindPESectionByName+0xc0>
   140002f7f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f83:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f86:	48 63 d0             	movsxd rdx,eax
   140002f89:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f8d:	48 01 d0             	add    rax,rdx
   140002f90:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f94:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f9b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f9f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002fa3:	0f b7 d0             	movzx  edx,ax
   140002fa6:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002faa:	48 01 d0             	add    rax,rdx
   140002fad:	48 83 c0 18          	add    rax,0x18
   140002fb1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fb5:	eb 29                	jmp    140002fe0 <_FindPESectionByName+0xab>
   140002fb7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fbb:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002fbf:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002fc5:	48 89 c1             	mov    rcx,rax
   140002fc8:	e8 0b 05 00 00       	call   1400034d8 <strncmp>
   140002fcd:	85 c0                	test   eax,eax
   140002fcf:	75 06                	jne    140002fd7 <_FindPESectionByName+0xa2>
   140002fd1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fd5:	eb 1e                	jmp    140002ff5 <_FindPESectionByName+0xc0>
   140002fd7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002fdb:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002fe0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fe4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002fe8:	0f b7 c0             	movzx  eax,ax
   140002feb:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002fee:	72 c7                	jb     140002fb7 <_FindPESectionByName+0x82>
   140002ff0:	b8 00 00 00 00       	mov    eax,0x0
   140002ff5:	48 83 c4 40          	add    rsp,0x40
   140002ff9:	5d                   	pop    rbp
   140002ffa:	c3                   	ret

0000000140002ffb <__mingw_GetSectionForAddress>:
   140002ffb:	55                   	push   rbp
   140002ffc:	48 89 e5             	mov    rbp,rsp
   140002fff:	48 83 ec 30          	sub    rsp,0x30
   140003003:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003007:	48 8b 05 52 23 00 00 	mov    rax,QWORD PTR [rip+0x2352]        # 140005360 <.refptr.__ImageBase>
   14000300e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003012:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003016:	48 89 c1             	mov    rcx,rax
   140003019:	e8 02 fe ff ff       	call   140002e20 <_ValidateImageBase>
   14000301e:	85 c0                	test   eax,eax
   140003020:	75 07                	jne    140003029 <__mingw_GetSectionForAddress+0x2e>
   140003022:	b8 00 00 00 00       	mov    eax,0x0
   140003027:	eb 1c                	jmp    140003045 <__mingw_GetSectionForAddress+0x4a>
   140003029:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000302d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003031:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003035:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003039:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000303d:	48 89 c1             	mov    rcx,rax
   140003040:	e8 57 fe ff ff       	call   140002e9c <_FindPESection>
   140003045:	48 83 c4 30          	add    rsp,0x30
   140003049:	5d                   	pop    rbp
   14000304a:	c3                   	ret

000000014000304b <__mingw_GetSectionCount>:
   14000304b:	55                   	push   rbp
   14000304c:	48 89 e5             	mov    rbp,rsp
   14000304f:	48 83 ec 30          	sub    rsp,0x30
   140003053:	48 8b 05 06 23 00 00 	mov    rax,QWORD PTR [rip+0x2306]        # 140005360 <.refptr.__ImageBase>
   14000305a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000305e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003062:	48 89 c1             	mov    rcx,rax
   140003065:	e8 b6 fd ff ff       	call   140002e20 <_ValidateImageBase>
   14000306a:	85 c0                	test   eax,eax
   14000306c:	75 07                	jne    140003075 <__mingw_GetSectionCount+0x2a>
   14000306e:	b8 00 00 00 00       	mov    eax,0x0
   140003073:	eb 20                	jmp    140003095 <__mingw_GetSectionCount+0x4a>
   140003075:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003079:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   14000307c:	48 63 d0             	movsxd rdx,eax
   14000307f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003083:	48 01 d0             	add    rax,rdx
   140003086:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000308a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000308e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140003092:	0f b7 c0             	movzx  eax,ax
   140003095:	48 83 c4 30          	add    rsp,0x30
   140003099:	5d                   	pop    rbp
   14000309a:	c3                   	ret

000000014000309b <_FindPESectionExec>:
   14000309b:	55                   	push   rbp
   14000309c:	48 89 e5             	mov    rbp,rsp
   14000309f:	48 83 ec 40          	sub    rsp,0x40
   1400030a3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400030a7:	48 8b 05 b2 22 00 00 	mov    rax,QWORD PTR [rip+0x22b2]        # 140005360 <.refptr.__ImageBase>
   1400030ae:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400030b2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030b6:	48 89 c1             	mov    rcx,rax
   1400030b9:	e8 62 fd ff ff       	call   140002e20 <_ValidateImageBase>
   1400030be:	85 c0                	test   eax,eax
   1400030c0:	75 07                	jne    1400030c9 <_FindPESectionExec+0x2e>
   1400030c2:	b8 00 00 00 00       	mov    eax,0x0
   1400030c7:	eb 78                	jmp    140003141 <_FindPESectionExec+0xa6>
   1400030c9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030cd:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   1400030d0:	48 63 d0             	movsxd rdx,eax
   1400030d3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030d7:	48 01 d0             	add    rax,rdx
   1400030da:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400030de:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400030e5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400030e9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   1400030ed:	0f b7 d0             	movzx  edx,ax
   1400030f0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400030f4:	48 01 d0             	add    rax,rdx
   1400030f7:	48 83 c0 18          	add    rax,0x18
   1400030fb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030ff:	eb 2b                	jmp    14000312c <_FindPESectionExec+0x91>
   140003101:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003105:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003108:	25 00 00 00 20       	and    eax,0x20000000
   14000310d:	85 c0                	test   eax,eax
   14000310f:	74 12                	je     140003123 <_FindPESectionExec+0x88>
   140003111:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140003116:	75 06                	jne    14000311e <_FindPESectionExec+0x83>
   140003118:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000311c:	eb 23                	jmp    140003141 <_FindPESectionExec+0xa6>
   14000311e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140003123:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140003127:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   14000312c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003130:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140003134:	0f b7 c0             	movzx  eax,ax
   140003137:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   14000313a:	72 c5                	jb     140003101 <_FindPESectionExec+0x66>
   14000313c:	b8 00 00 00 00       	mov    eax,0x0
   140003141:	48 83 c4 40          	add    rsp,0x40
   140003145:	5d                   	pop    rbp
   140003146:	c3                   	ret

0000000140003147 <_GetPEImageBase>:
   140003147:	55                   	push   rbp
   140003148:	48 89 e5             	mov    rbp,rsp
   14000314b:	48 83 ec 30          	sub    rsp,0x30
   14000314f:	48 8b 05 0a 22 00 00 	mov    rax,QWORD PTR [rip+0x220a]        # 140005360 <.refptr.__ImageBase>
   140003156:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000315a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000315e:	48 89 c1             	mov    rcx,rax
   140003161:	e8 ba fc ff ff       	call   140002e20 <_ValidateImageBase>
   140003166:	85 c0                	test   eax,eax
   140003168:	75 07                	jne    140003171 <_GetPEImageBase+0x2a>
   14000316a:	b8 00 00 00 00       	mov    eax,0x0
   14000316f:	eb 04                	jmp    140003175 <_GetPEImageBase+0x2e>
   140003171:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003175:	48 83 c4 30          	add    rsp,0x30
   140003179:	5d                   	pop    rbp
   14000317a:	c3                   	ret

000000014000317b <_IsNonwritableInCurrentImage>:
   14000317b:	55                   	push   rbp
   14000317c:	48 89 e5             	mov    rbp,rsp
   14000317f:	48 83 ec 40          	sub    rsp,0x40
   140003183:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003187:	48 8b 05 d2 21 00 00 	mov    rax,QWORD PTR [rip+0x21d2]        # 140005360 <.refptr.__ImageBase>
   14000318e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003192:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003196:	48 89 c1             	mov    rcx,rax
   140003199:	e8 82 fc ff ff       	call   140002e20 <_ValidateImageBase>
   14000319e:	85 c0                	test   eax,eax
   1400031a0:	75 07                	jne    1400031a9 <_IsNonwritableInCurrentImage+0x2e>
   1400031a2:	b8 00 00 00 00       	mov    eax,0x0
   1400031a7:	eb 3d                	jmp    1400031e6 <_IsNonwritableInCurrentImage+0x6b>
   1400031a9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400031ad:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   1400031b1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400031b5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400031b9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400031bd:	48 89 c1             	mov    rcx,rax
   1400031c0:	e8 d7 fc ff ff       	call   140002e9c <_FindPESection>
   1400031c5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400031c9:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   1400031ce:	75 07                	jne    1400031d7 <_IsNonwritableInCurrentImage+0x5c>
   1400031d0:	b8 00 00 00 00       	mov    eax,0x0
   1400031d5:	eb 0f                	jmp    1400031e6 <_IsNonwritableInCurrentImage+0x6b>
   1400031d7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400031db:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031de:	f7 d0                	not    eax
   1400031e0:	c1 e8 1f             	shr    eax,0x1f
   1400031e3:	0f b6 c0             	movzx  eax,al
   1400031e6:	48 83 c4 40          	add    rsp,0x40
   1400031ea:	5d                   	pop    rbp
   1400031eb:	c3                   	ret

00000001400031ec <__mingw_enum_import_library_names>:
   1400031ec:	55                   	push   rbp
   1400031ed:	48 89 e5             	mov    rbp,rsp
   1400031f0:	48 83 ec 50          	sub    rsp,0x50
   1400031f4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031f7:	48 8b 05 62 21 00 00 	mov    rax,QWORD PTR [rip+0x2162]        # 140005360 <.refptr.__ImageBase>
   1400031fe:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003202:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003206:	48 89 c1             	mov    rcx,rax
   140003209:	e8 12 fc ff ff       	call   140002e20 <_ValidateImageBase>
   14000320e:	85 c0                	test   eax,eax
   140003210:	75 0a                	jne    14000321c <__mingw_enum_import_library_names+0x30>
   140003212:	b8 00 00 00 00       	mov    eax,0x0
   140003217:	e9 ab 00 00 00       	jmp    1400032c7 <__mingw_enum_import_library_names+0xdb>
   14000321c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003220:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003223:	48 63 d0             	movsxd rdx,eax
   140003226:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000322a:	48 01 d0             	add    rax,rdx
   14000322d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003231:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003235:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000323b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000323e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003242:	75 07                	jne    14000324b <__mingw_enum_import_library_names+0x5f>
   140003244:	b8 00 00 00 00       	mov    eax,0x0
   140003249:	eb 7c                	jmp    1400032c7 <__mingw_enum_import_library_names+0xdb>
   14000324b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000324e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003252:	48 89 c1             	mov    rcx,rax
   140003255:	e8 42 fc ff ff       	call   140002e9c <_FindPESection>
   14000325a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000325e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003263:	75 07                	jne    14000326c <__mingw_enum_import_library_names+0x80>
   140003265:	b8 00 00 00 00       	mov    eax,0x0
   14000326a:	eb 5b                	jmp    1400032c7 <__mingw_enum_import_library_names+0xdb>
   14000326c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000326f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003273:	48 01 d0             	add    rax,rdx
   140003276:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000327a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000327f:	75 07                	jne    140003288 <__mingw_enum_import_library_names+0x9c>
   140003281:	b8 00 00 00 00       	mov    eax,0x0
   140003286:	eb 3f                	jmp    1400032c7 <__mingw_enum_import_library_names+0xdb>
   140003288:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000328c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000328f:	85 c0                	test   eax,eax
   140003291:	75 0b                	jne    14000329e <__mingw_enum_import_library_names+0xb2>
   140003293:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003297:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000329a:	85 c0                	test   eax,eax
   14000329c:	74 23                	je     1400032c1 <__mingw_enum_import_library_names+0xd5>
   14000329e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400032a2:	7f 12                	jg     1400032b6 <__mingw_enum_import_library_names+0xca>
   1400032a4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400032a8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032ab:	89 c2                	mov    edx,eax
   1400032ad:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400032b1:	48 01 d0             	add    rax,rdx
   1400032b4:	eb 11                	jmp    1400032c7 <__mingw_enum_import_library_names+0xdb>
   1400032b6:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   1400032ba:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   1400032bf:	eb c7                	jmp    140003288 <__mingw_enum_import_library_names+0x9c>
   1400032c1:	90                   	nop
   1400032c2:	b8 00 00 00 00       	mov    eax,0x0
   1400032c7:	48 83 c4 50          	add    rsp,0x50
   1400032cb:	5d                   	pop    rbp
   1400032cc:	c3                   	ret
   1400032cd:	90                   	nop
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <___chkstk_ms>:
   1400032d0:	51                   	push   rcx
   1400032d1:	50                   	push   rax
   1400032d2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400032d8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400032dd:	72 19                	jb     1400032f8 <___chkstk_ms+0x28>
   1400032df:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400032e6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400032ea:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400032f0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400032f6:	77 e7                	ja     1400032df <___chkstk_ms+0xf>
   1400032f8:	48 29 c1             	sub    rcx,rax
   1400032fb:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400032ff:	58                   	pop    rax
   140003300:	59                   	pop    rcx
   140003301:	c3                   	ret
   140003302:	90                   	nop
   140003303:	90                   	nop
   140003304:	90                   	nop
   140003305:	90                   	nop
   140003306:	90                   	nop
   140003307:	90                   	nop
   140003308:	90                   	nop
   140003309:	90                   	nop
   14000330a:	90                   	nop
   14000330b:	90                   	nop
   14000330c:	90                   	nop
   14000330d:	90                   	nop
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <_initterm_e>:
   140003310:	55                   	push   rbp
   140003311:	48 89 e5             	mov    rbp,rsp
   140003314:	48 83 ec 30          	sub    rsp,0x30
   140003318:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000331c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003320:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003324:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003328:	eb 29                	jmp    140003353 <_initterm_e+0x43>
   14000332a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000332e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140003331:	48 85 c0             	test   rax,rax
   140003334:	74 17                	je     14000334d <_initterm_e+0x3d>
   140003336:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000333a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000333d:	ff d0                	call   rax
   14000333f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003342:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003346:	74 06                	je     14000334e <_initterm_e+0x3e>
   140003348:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000334b:	eb 15                	jmp    140003362 <_initterm_e+0x52>
   14000334d:	90                   	nop
   14000334e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140003353:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003357:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   14000335b:	72 cd                	jb     14000332a <_initterm_e+0x1a>
   14000335d:	b8 00 00 00 00       	mov    eax,0x0
   140003362:	48 83 c4 30          	add    rsp,0x30
   140003366:	5d                   	pop    rbp
   140003367:	c3                   	ret
   140003368:	90                   	nop
   140003369:	90                   	nop
   14000336a:	90                   	nop
   14000336b:	90                   	nop
   14000336c:	90                   	nop
   14000336d:	90                   	nop
   14000336e:	90                   	nop
   14000336f:	90                   	nop

0000000140003370 <__p__fmode>:
   140003370:	55                   	push   rbp
   140003371:	48 89 e5             	mov    rbp,rsp
   140003374:	48 8b 05 55 20 00 00 	mov    rax,QWORD PTR [rip+0x2055]        # 1400053d0 <.refptr.__imp__fmode>
   14000337b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000337e:	5d                   	pop    rbp
   14000337f:	c3                   	ret

0000000140003380 <__p__commode>:
   140003380:	55                   	push   rbp
   140003381:	48 89 e5             	mov    rbp,rsp
   140003384:	48 8b 05 35 20 00 00 	mov    rax,QWORD PTR [rip+0x2035]        # 1400053c0 <.refptr.__imp__commode>
   14000338b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000338e:	5d                   	pop    rbp
   14000338f:	c3                   	ret

0000000140003390 <__p___initenv>:
   140003390:	55                   	push   rbp
   140003391:	48 89 e5             	mov    rbp,rsp
   140003394:	48 8b 05 15 20 00 00 	mov    rax,QWORD PTR [rip+0x2015]        # 1400053b0 <.refptr.__imp___initenv>
   14000339b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000339e:	5d                   	pop    rbp
   14000339f:	c3                   	ret

00000001400033a0 <_set_invalid_parameter_handler>:
   1400033a0:	55                   	push   rbp
   1400033a1:	48 89 e5             	mov    rbp,rsp
   1400033a4:	48 83 ec 10          	sub    rsp,0x10
   1400033a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400033ac:	48 8d 05 dd 5d 00 00 	lea    rax,[rip+0x5ddd]        # 140009190 <handler>
   1400033b3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400033b7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033bb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400033bf:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400033c3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400033c7:	48 87 10             	xchg   QWORD PTR [rax],rdx
   1400033ca:	48 89 d0             	mov    rax,rdx
   1400033cd:	48 83 c4 10          	add    rsp,0x10
   1400033d1:	5d                   	pop    rbp
   1400033d2:	c3                   	ret

00000001400033d3 <_get_invalid_parameter_handler>:
   1400033d3:	55                   	push   rbp
   1400033d4:	48 89 e5             	mov    rbp,rsp
   1400033d7:	48 8b 05 b2 5d 00 00 	mov    rax,QWORD PTR [rip+0x5db2]        # 140009190 <handler>
   1400033de:	5d                   	pop    rbp
   1400033df:	c3                   	ret

00000001400033e0 <_configthreadlocale>:
   1400033e0:	55                   	push   rbp
   1400033e1:	48 89 e5             	mov    rbp,rsp
   1400033e4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400033e7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   1400033eb:	75 07                	jne    1400033f4 <_configthreadlocale+0x14>
   1400033ed:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400033f2:	eb 05                	jmp    1400033f9 <_configthreadlocale+0x19>
   1400033f4:	b8 02 00 00 00       	mov    eax,0x2
   1400033f9:	5d                   	pop    rbp
   1400033fa:	c3                   	ret
   1400033fb:	90                   	nop
   1400033fc:	90                   	nop
   1400033fd:	90                   	nop
   1400033fe:	90                   	nop
   1400033ff:	90                   	nop

0000000140003400 <__acrt_iob_func>:
   140003400:	55                   	push   rbp
   140003401:	48 89 e5             	mov    rbp,rsp
   140003404:	48 83 ec 20          	sub    rsp,0x20
   140003408:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000340b:	e8 30 00 00 00       	call   140003440 <__iob_func>
   140003410:	48 89 c1             	mov    rcx,rax
   140003413:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003416:	48 89 d0             	mov    rax,rdx
   140003419:	48 01 c0             	add    rax,rax
   14000341c:	48 01 d0             	add    rax,rdx
   14000341f:	48 c1 e0 04          	shl    rax,0x4
   140003423:	48 01 c8             	add    rax,rcx
   140003426:	48 83 c4 20          	add    rsp,0x20
   14000342a:	5d                   	pop    rbp
   14000342b:	c3                   	ret
   14000342c:	90                   	nop
   14000342d:	90                   	nop
   14000342e:	90                   	nop
   14000342f:	90                   	nop

0000000140003430 <__C_specific_handler>:
   140003430:	ff 25 d2 6d 00 00    	jmp    QWORD PTR [rip+0x6dd2]        # 14000a208 <__imp___C_specific_handler>
   140003436:	90                   	nop
   140003437:	90                   	nop

0000000140003438 <__getmainargs>:
   140003438:	ff 25 d2 6d 00 00    	jmp    QWORD PTR [rip+0x6dd2]        # 14000a210 <__imp___getmainargs>
   14000343e:	90                   	nop
   14000343f:	90                   	nop

0000000140003440 <__iob_func>:
   140003440:	ff 25 da 6d 00 00    	jmp    QWORD PTR [rip+0x6dda]        # 14000a220 <__imp___iob_func>
   140003446:	90                   	nop
   140003447:	90                   	nop

0000000140003448 <__set_app_type>:
   140003448:	ff 25 da 6d 00 00    	jmp    QWORD PTR [rip+0x6dda]        # 14000a228 <__imp___set_app_type>
   14000344e:	90                   	nop
   14000344f:	90                   	nop

0000000140003450 <__setusermatherr>:
   140003450:	ff 25 da 6d 00 00    	jmp    QWORD PTR [rip+0x6dda]        # 14000a230 <__imp___setusermatherr>
   140003456:	90                   	nop
   140003457:	90                   	nop

0000000140003458 <_amsg_exit>:
   140003458:	ff 25 da 6d 00 00    	jmp    QWORD PTR [rip+0x6dda]        # 14000a238 <__imp__amsg_exit>
   14000345e:	90                   	nop
   14000345f:	90                   	nop

0000000140003460 <_cexit>:
   140003460:	ff 25 da 6d 00 00    	jmp    QWORD PTR [rip+0x6dda]        # 14000a240 <__imp__cexit>
   140003466:	90                   	nop
   140003467:	90                   	nop

0000000140003468 <_initterm>:
   140003468:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a258 <__imp__initterm>
   14000346e:	90                   	nop
   14000346f:	90                   	nop

0000000140003470 <_crt_atexit>:
   140003470:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a260 <__imp__crt_atexit>
   140003476:	90                   	nop
   140003477:	90                   	nop

0000000140003478 <abort>:
   140003478:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a268 <__imp_abort>
   14000347e:	90                   	nop
   14000347f:	90                   	nop

0000000140003480 <calloc>:
   140003480:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a270 <__imp_calloc>
   140003486:	90                   	nop
   140003487:	90                   	nop

0000000140003488 <exit>:
   140003488:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a278 <__imp_exit>
   14000348e:	90                   	nop
   14000348f:	90                   	nop

0000000140003490 <fflush>:
   140003490:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a280 <__imp_fflush>
   140003496:	90                   	nop
   140003497:	90                   	nop

0000000140003498 <fprintf>:
   140003498:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a288 <__imp_fprintf>
   14000349e:	90                   	nop
   14000349f:	90                   	nop

00000001400034a0 <free>:
   1400034a0:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a290 <__imp_free>
   1400034a6:	90                   	nop
   1400034a7:	90                   	nop

00000001400034a8 <malloc>:
   1400034a8:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a298 <__imp_malloc>
   1400034ae:	90                   	nop
   1400034af:	90                   	nop

00000001400034b0 <memcpy>:
   1400034b0:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a2a0 <__imp_memcpy>
   1400034b6:	90                   	nop
   1400034b7:	90                   	nop

00000001400034b8 <memset>:
   1400034b8:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a2a8 <__imp_memset>
   1400034be:	90                   	nop
   1400034bf:	90                   	nop

00000001400034c0 <setvbuf>:
   1400034c0:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a2b0 <__imp_setvbuf>
   1400034c6:	90                   	nop
   1400034c7:	90                   	nop

00000001400034c8 <signal>:
   1400034c8:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a2b8 <__imp_signal>
   1400034ce:	90                   	nop
   1400034cf:	90                   	nop

00000001400034d0 <strlen>:
   1400034d0:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a2c0 <__imp_strlen>
   1400034d6:	90                   	nop
   1400034d7:	90                   	nop

00000001400034d8 <strncmp>:
   1400034d8:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a2c8 <__imp_strncmp>
   1400034de:	90                   	nop
   1400034df:	90                   	nop

00000001400034e0 <vfprintf>:
   1400034e0:	ff 25 ea 6d 00 00    	jmp    QWORD PTR [rip+0x6dea]        # 14000a2d0 <__imp_vfprintf>
   1400034e6:	90                   	nop
   1400034e7:	90                   	nop
   1400034e8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   1400034ef:	00 

00000001400034f0 <VirtualQuery>:
   1400034f0:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 14000a1f8 <__imp_VirtualQuery>
   1400034f6:	90                   	nop
   1400034f7:	90                   	nop

00000001400034f8 <VirtualProtect>:
   1400034f8:	ff 25 f2 6c 00 00    	jmp    QWORD PTR [rip+0x6cf2]        # 14000a1f0 <__imp_VirtualProtect>
   1400034fe:	90                   	nop
   1400034ff:	90                   	nop

0000000140003500 <TlsGetValue>:
   140003500:	ff 25 e2 6c 00 00    	jmp    QWORD PTR [rip+0x6ce2]        # 14000a1e8 <__imp_TlsGetValue>
   140003506:	90                   	nop
   140003507:	90                   	nop

0000000140003508 <Sleep>:
   140003508:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 14000a1e0 <__imp_Sleep>
   14000350e:	90                   	nop
   14000350f:	90                   	nop

0000000140003510 <SetUnhandledExceptionFilter>:
   140003510:	ff 25 c2 6c 00 00    	jmp    QWORD PTR [rip+0x6cc2]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   140003516:	90                   	nop
   140003517:	90                   	nop

0000000140003518 <LoadLibraryA>:
   140003518:	ff 25 b2 6c 00 00    	jmp    QWORD PTR [rip+0x6cb2]        # 14000a1d0 <__imp_LoadLibraryA>
   14000351e:	90                   	nop
   14000351f:	90                   	nop

0000000140003520 <LeaveCriticalSection>:
   140003520:	ff 25 a2 6c 00 00    	jmp    QWORD PTR [rip+0x6ca2]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140003526:	90                   	nop
   140003527:	90                   	nop

0000000140003528 <InitializeCriticalSection>:
   140003528:	ff 25 92 6c 00 00    	jmp    QWORD PTR [rip+0x6c92]        # 14000a1c0 <__imp_InitializeCriticalSection>
   14000352e:	90                   	nop
   14000352f:	90                   	nop

0000000140003530 <GetProcAddress>:
   140003530:	ff 25 82 6c 00 00    	jmp    QWORD PTR [rip+0x6c82]        # 14000a1b8 <__imp_GetProcAddress>
   140003536:	90                   	nop
   140003537:	90                   	nop

0000000140003538 <GetModuleHandleA>:
   140003538:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 14000a1b0 <__imp_GetModuleHandleA>
   14000353e:	90                   	nop
   14000353f:	90                   	nop

0000000140003540 <GetLastError>:
   140003540:	ff 25 62 6c 00 00    	jmp    QWORD PTR [rip+0x6c62]        # 14000a1a8 <__imp_GetLastError>
   140003546:	90                   	nop
   140003547:	90                   	nop

0000000140003548 <FreeLibrary>:
   140003548:	ff 25 52 6c 00 00    	jmp    QWORD PTR [rip+0x6c52]        # 14000a1a0 <__imp_FreeLibrary>
   14000354e:	90                   	nop
   14000354f:	90                   	nop

0000000140003550 <EnterCriticalSection>:
   140003550:	ff 25 42 6c 00 00    	jmp    QWORD PTR [rip+0x6c42]        # 14000a198 <__imp_EnterCriticalSection>
   140003556:	90                   	nop
   140003557:	90                   	nop

0000000140003558 <DeleteCriticalSection>:
   140003558:	ff 25 32 6c 00 00    	jmp    QWORD PTR [rip+0x6c32]        # 14000a190 <__IAT_start__>
   14000355e:	90                   	nop
   14000355f:	90                   	nop

0000000140003560 <register_frame_ctor>:
   140003560:	e9 0b e1 ff ff       	jmp    140001670 <__gcc_register_frame>
   140003565:	90                   	nop
   140003566:	90                   	nop
   140003567:	90                   	nop
   140003568:	90                   	nop
   140003569:	90                   	nop
   14000356a:	90                   	nop
   14000356b:	90                   	nop
   14000356c:	90                   	nop
   14000356d:	90                   	nop
   14000356e:	90                   	nop
   14000356f:	90                   	nop
