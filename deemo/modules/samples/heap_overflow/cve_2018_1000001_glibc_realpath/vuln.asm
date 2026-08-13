
C:\Users\Administrator\Desktop\BinMind\deemo\modules\samples\heap_overflow\cve_2018_1000001_glibc_realpath\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 a7 22 00 00       	call   1400032d0 <fflush>
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
   14000113b:	e8 58 21 00 00       	call   140003298 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 d8 20 00 00       	call   140003240 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 7f 21 00 00       	call   140003300 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 1f 21 00 00       	call   1400032b8 <abort>
   140001199:	e8 a2 11 00 00       	call   140002340 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 29 90 00 00 	mov    rax,QWORD PTR [rip+0x9029]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 16 20 00 00       	call   1400031e0 <_set_invalid_parameter_handler>
   1400011ca:	e8 81 1a 00 00       	call   140002c50 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 97 20 00 00       	call   140003288 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 8b 20 00 00       	call   140003288 <__set_app_type>
   1400011fd:	e8 ae 1f 00 00       	call   1400031b0 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 ae 1f 00 00       	call   1400031c0 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 fe 06 00 00       	call   140001920 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 63 20 00 00       	call   140003298 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 08 12 00 00       	call   14000245a <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 b6 1f 00 00       	call   140003220 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 d0 1e 00 00       	call   140003150 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 0a 20 00 00       	call   140003298 <_amsg_exit>
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
   1400012cb:	e8 a8 1f 00 00       	call   140003278 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 b5 1f 00 00       	call   140003298 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 8e 1f 00 00       	call   140003298 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 88 1f 00 00       	call   1400032a8 <_initterm>
   140001320:	e8 d2 05 00 00       	call   1400018f7 <__main>
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
   14000138d:	e8 3e 1e 00 00       	call   1400031d0 <__p___initenv>
   140001392:	48 8b 15 77 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c77]        # 140009010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d 7c 00 00 	mov    rcx,QWORD PTR [rip+0x7c6d]        # 140009010 <envp>
   1400013a3:	48 8b 15 5e 7c 00 00 	mov    rdx,QWORD PTR [rip+0x7c5e]        # 140009008 <argv>
   1400013aa:	8b 05 54 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c54]        # 140009004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 03 04 00 00       	call   1400017bd <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c55]        # 140009018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 f7 1e 00 00       	call   1400032c8 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 c0 1e 00 00       	call   1400032a0 <_cexit>
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
   140001511:	e8 d2 1d 00 00       	call   1400032e8 <malloc>
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
   14000155c:	e8 af 1d 00 00       	call   140003310 <strlen>
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
   140001585:	e8 5e 1d 00 00       	call   1400032e8 <malloc>
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
   1400015e8:	e8 03 1d 00 00       	call   1400032f0 <memcpy>
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
   140001642:	e8 69 1c 00 00       	call   1400032b0 <_crt_atexit>
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

0000000140001760 <resolve>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 30          	sub    rsp,0x30
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	b9 20 00 00 00       	mov    ecx,0x20
   140001771:	e8 72 1b 00 00       	call   1400032e8 <malloc>
   140001776:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000177a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000177f:	75 07                	jne    140001788 <resolve+0x28>
   140001781:	b8 00 00 00 00       	mov    eax,0x0
   140001786:	eb 2f                	jmp    1400017b7 <resolve+0x57>
   140001788:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000178c:	48 89 c1             	mov    rcx,rax
   14000178f:	e8 7c 1b 00 00       	call   140003310 <strlen>
   140001794:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001798:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000179c:	48 8d 48 01          	lea    rcx,[rax+0x1]
   1400017a0:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400017a4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017a8:	49 89 c8             	mov    r8,rcx
   1400017ab:	48 89 c1             	mov    rcx,rax
   1400017ae:	e8 3d 1b 00 00       	call   1400032f0 <memcpy>
   1400017b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017b7:	48 83 c4 30          	add    rsp,0x30
   1400017bb:	5d                   	pop    rbp
   1400017bc:	c3                   	ret

00000001400017bd <main>:
   1400017bd:	55                   	push   rbp
   1400017be:	48 81 ec 30 01 00 00 	sub    rsp,0x130
   1400017c5:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   1400017cc:	00 
   1400017cd:	89 8d c0 00 00 00    	mov    DWORD PTR [rbp+0xc0],ecx
   1400017d3:	48 89 95 c8 00 00 00 	mov    QWORD PTR [rbp+0xc8],rdx
   1400017da:	e8 18 01 00 00       	call   1400018f7 <__main>
   1400017df:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400017e3:	41 b8 00 01 00 00    	mov    r8d,0x100
   1400017e9:	ba 2f 00 00 00       	mov    edx,0x2f
   1400017ee:	48 89 c1             	mov    rcx,rax
   1400017f1:	e8 02 1b 00 00       	call   1400032f8 <memset>
   1400017f6:	c6 85 9f 00 00 00 00 	mov    BYTE PTR [rbp+0x9f],0x0
   1400017fd:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140001801:	48 89 c1             	mov    rcx,rax
   140001804:	e8 57 ff ff ff       	call   140001760 <resolve>
   140001809:	48 89 85 a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],rax
   140001810:	48 83 bd a8 00 00 00 	cmp    QWORD PTR [rbp+0xa8],0x0
   140001817:	00 
   140001818:	74 0f                	je     140001829 <main+0x6c>
   14000181a:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140001821:	48 89 c1             	mov    rcx,rax
   140001824:	e8 b7 1a 00 00       	call   1400032e0 <free>
   140001829:	b8 00 00 00 00       	mov    eax,0x0
   14000182e:	48 81 c4 30 01 00 00 	add    rsp,0x130
   140001835:	5d                   	pop    rbp
   140001836:	c3                   	ret
   140001837:	90                   	nop
   140001838:	90                   	nop
   140001839:	90                   	nop
   14000183a:	90                   	nop
   14000183b:	90                   	nop
   14000183c:	90                   	nop
   14000183d:	90                   	nop
   14000183e:	90                   	nop
   14000183f:	90                   	nop

0000000140001840 <__do_global_dtors>:
   140001840:	55                   	push   rbp
   140001841:	48 89 e5             	mov    rbp,rsp
   140001844:	48 83 ec 20          	sub    rsp,0x20
   140001848:	eb 1e                	jmp    140001868 <__do_global_dtors+0x28>
   14000184a:	48 8b 05 bf 27 00 00 	mov    rax,QWORD PTR [rip+0x27bf]        # 140004010 <p.0>
   140001851:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001854:	ff d0                	call   rax
   140001856:	48 8b 05 b3 27 00 00 	mov    rax,QWORD PTR [rip+0x27b3]        # 140004010 <p.0>
   14000185d:	48 83 c0 08          	add    rax,0x8
   140001861:	48 89 05 a8 27 00 00 	mov    QWORD PTR [rip+0x27a8],rax        # 140004010 <p.0>
   140001868:	48 8b 05 a1 27 00 00 	mov    rax,QWORD PTR [rip+0x27a1]        # 140004010 <p.0>
   14000186f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001872:	48 85 c0             	test   rax,rax
   140001875:	75 d3                	jne    14000184a <__do_global_dtors+0xa>
   140001877:	90                   	nop
   140001878:	90                   	nop
   140001879:	48 83 c4 20          	add    rsp,0x20
   14000187d:	5d                   	pop    rbp
   14000187e:	c3                   	ret

000000014000187f <__do_global_ctors>:
   14000187f:	55                   	push   rbp
   140001880:	48 89 e5             	mov    rbp,rsp
   140001883:	48 83 ec 30          	sub    rsp,0x30
   140001887:	48 8b 05 c2 3a 00 00 	mov    rax,QWORD PTR [rip+0x3ac2]        # 140005350 <.refptr.__CTOR_LIST__>
   14000188e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001891:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001894:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001898:	75 25                	jne    1400018bf <__do_global_ctors+0x40>
   14000189a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400018a1:	eb 04                	jmp    1400018a7 <__do_global_ctors+0x28>
   1400018a3:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400018a7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018aa:	8d 50 01             	lea    edx,[rax+0x1]
   1400018ad:	48 8b 05 9c 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a9c]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018b4:	89 d2                	mov    edx,edx
   1400018b6:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018ba:	48 85 c0             	test   rax,rax
   1400018bd:	75 e4                	jne    1400018a3 <__do_global_ctors+0x24>
   1400018bf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018c2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400018c5:	eb 14                	jmp    1400018db <__do_global_ctors+0x5c>
   1400018c7:	48 8b 05 82 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a82]        # 140005350 <.refptr.__CTOR_LIST__>
   1400018ce:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400018d1:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018d5:	ff d0                	call   rax
   1400018d7:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400018db:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400018df:	75 e6                	jne    1400018c7 <__do_global_ctors+0x48>
   1400018e1:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001840 <__do_global_dtors>
   1400018e8:	48 89 c1             	mov    rcx,rax
   1400018eb:	e8 3f fd ff ff       	call   14000162f <atexit>
   1400018f0:	90                   	nop
   1400018f1:	48 83 c4 30          	add    rsp,0x30
   1400018f5:	5d                   	pop    rbp
   1400018f6:	c3                   	ret

00000001400018f7 <__main>:
   1400018f7:	55                   	push   rbp
   1400018f8:	48 89 e5             	mov    rbp,rsp
   1400018fb:	48 83 ec 20          	sub    rsp,0x20
   1400018ff:	8b 05 7b 77 00 00    	mov    eax,DWORD PTR [rip+0x777b]        # 140009080 <initialized>
   140001905:	85 c0                	test   eax,eax
   140001907:	75 0f                	jne    140001918 <__main+0x21>
   140001909:	c7 05 6d 77 00 00 01 	mov    DWORD PTR [rip+0x776d],0x1        # 140009080 <initialized>
   140001910:	00 00 00 
   140001913:	e8 67 ff ff ff       	call   14000187f <__do_global_ctors>
   140001918:	90                   	nop
   140001919:	48 83 c4 20          	add    rsp,0x20
   14000191d:	5d                   	pop    rbp
   14000191e:	c3                   	ret
   14000191f:	90                   	nop

0000000140001920 <_setargv>:
   140001920:	55                   	push   rbp
   140001921:	48 89 e5             	mov    rbp,rsp
   140001924:	b8 00 00 00 00       	mov    eax,0x0
   140001929:	5d                   	pop    rbp
   14000192a:	c3                   	ret
   14000192b:	90                   	nop
   14000192c:	90                   	nop
   14000192d:	90                   	nop
   14000192e:	90                   	nop
   14000192f:	90                   	nop

0000000140001930 <__dyn_tls_init>:
   140001930:	55                   	push   rbp
   140001931:	48 89 e5             	mov    rbp,rsp
   140001934:	48 83 ec 30          	sub    rsp,0x30
   140001938:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000193c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000193f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001943:	48 8b 05 e6 39 00 00 	mov    rax,QWORD PTR [rip+0x39e6]        # 140005330 <.refptr._CRT_MT>
   14000194a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000194c:	83 f8 02             	cmp    eax,0x2
   14000194f:	74 0d                	je     14000195e <__dyn_tls_init+0x2e>
   140001951:	48 8b 05 d8 39 00 00 	mov    rax,QWORD PTR [rip+0x39d8]        # 140005330 <.refptr._CRT_MT>
   140001958:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000195e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001962:	74 1e                	je     140001982 <__dyn_tls_init+0x52>
   140001964:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001968:	75 5b                	jne    1400019c5 <__dyn_tls_init+0x95>
   14000196a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000196e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001971:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001975:	49 89 c8             	mov    r8,rcx
   140001978:	48 89 c1             	mov    rcx,rax
   14000197b:	e8 d1 11 00 00       	call   140002b51 <__mingw_TLScallback>
   140001980:	eb 43                	jmp    1400019c5 <__dyn_tls_init+0x95>
   140001982:	48 8d 05 0f 3d 00 00 	lea    rax,[rip+0x3d0f]        # 140005698 <___crt_xd_start__>
   140001989:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000198d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001992:	eb 22                	jmp    1400019b6 <__dyn_tls_init+0x86>
   140001994:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001998:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000199c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019a0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019a3:	48 85 c0             	test   rax,rax
   1400019a6:	74 09                	je     1400019b1 <__dyn_tls_init+0x81>
   1400019a8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019ac:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019af:	ff d0                	call   rax
   1400019b1:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019b6:	48 8d 05 e3 3c 00 00 	lea    rax,[rip+0x3ce3]        # 1400056a0 <__xd_z>
   1400019bd:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   1400019c1:	75 d1                	jne    140001994 <__dyn_tls_init+0x64>
   1400019c3:	eb 01                	jmp    1400019c6 <__dyn_tls_init+0x96>
   1400019c5:	90                   	nop
   1400019c6:	48 83 c4 30          	add    rsp,0x30
   1400019ca:	5d                   	pop    rbp
   1400019cb:	c3                   	ret

00000001400019cc <__tlregdtor>:
   1400019cc:	55                   	push   rbp
   1400019cd:	48 89 e5             	mov    rbp,rsp
   1400019d0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019d4:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400019d9:	75 07                	jne    1400019e2 <__tlregdtor+0x16>
   1400019db:	b8 00 00 00 00       	mov    eax,0x0
   1400019e0:	eb 05                	jmp    1400019e7 <__tlregdtor+0x1b>
   1400019e2:	b8 00 00 00 00       	mov    eax,0x0
   1400019e7:	5d                   	pop    rbp
   1400019e8:	c3                   	ret

00000001400019e9 <__dyn_tls_dtor>:
   1400019e9:	55                   	push   rbp
   1400019ea:	48 89 e5             	mov    rbp,rsp
   1400019ed:	48 83 ec 20          	sub    rsp,0x20
   1400019f1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019f5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019f8:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019fc:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a00:	74 06                	je     140001a08 <__dyn_tls_dtor+0x1f>
   140001a02:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a06:	75 18                	jne    140001a20 <__dyn_tls_dtor+0x37>
   140001a08:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a0c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a0f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a13:	49 89 c8             	mov    r8,rcx
   140001a16:	48 89 c1             	mov    rcx,rax
   140001a19:	e8 33 11 00 00       	call   140002b51 <__mingw_TLScallback>
   140001a1e:	eb 01                	jmp    140001a21 <__dyn_tls_dtor+0x38>
   140001a20:	90                   	nop
   140001a21:	48 83 c4 20          	add    rsp,0x20
   140001a25:	5d                   	pop    rbp
   140001a26:	c3                   	ret
   140001a27:	90                   	nop
   140001a28:	90                   	nop
   140001a29:	90                   	nop
   140001a2a:	90                   	nop
   140001a2b:	90                   	nop
   140001a2c:	90                   	nop
   140001a2d:	90                   	nop
   140001a2e:	90                   	nop
   140001a2f:	90                   	nop

0000000140001a30 <_matherr>:
   140001a30:	55                   	push   rbp
   140001a31:	53                   	push   rbx
   140001a32:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a39:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a3e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a42:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a46:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a4b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a4f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a53:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a55:	83 f8 06             	cmp    eax,0x6
   140001a58:	74 56                	je     140001ab0 <_matherr+0x80>
   140001a5a:	83 f8 06             	cmp    eax,0x6
   140001a5d:	7f 78                	jg     140001ad7 <_matherr+0xa7>
   140001a5f:	83 f8 05             	cmp    eax,0x5
   140001a62:	74 59                	je     140001abd <_matherr+0x8d>
   140001a64:	83 f8 05             	cmp    eax,0x5
   140001a67:	7f 6e                	jg     140001ad7 <_matherr+0xa7>
   140001a69:	83 f8 04             	cmp    eax,0x4
   140001a6c:	74 5c                	je     140001aca <_matherr+0x9a>
   140001a6e:	83 f8 04             	cmp    eax,0x4
   140001a71:	7f 64                	jg     140001ad7 <_matherr+0xa7>
   140001a73:	83 f8 03             	cmp    eax,0x3
   140001a76:	74 2b                	je     140001aa3 <_matherr+0x73>
   140001a78:	83 f8 03             	cmp    eax,0x3
   140001a7b:	7f 5a                	jg     140001ad7 <_matherr+0xa7>
   140001a7d:	83 f8 01             	cmp    eax,0x1
   140001a80:	74 07                	je     140001a89 <_matherr+0x59>
   140001a82:	83 f8 02             	cmp    eax,0x2
   140001a85:	74 0f                	je     140001a96 <_matherr+0x66>
   140001a87:	eb 4e                	jmp    140001ad7 <_matherr+0xa7>
   140001a89:	48 8d 05 10 36 00 00 	lea    rax,[rip+0x3610]        # 1400050a0 <.rdata>
   140001a90:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a94:	eb 4d                	jmp    140001ae3 <_matherr+0xb3>
   140001a96:	48 8d 05 22 36 00 00 	lea    rax,[rip+0x3622]        # 1400050bf <.rdata+0x1f>
   140001a9d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001aa1:	eb 40                	jmp    140001ae3 <_matherr+0xb3>
   140001aa3:	48 8d 05 36 36 00 00 	lea    rax,[rip+0x3636]        # 1400050e0 <.rdata+0x40>
   140001aaa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001aae:	eb 33                	jmp    140001ae3 <_matherr+0xb3>
   140001ab0:	48 8d 05 49 36 00 00 	lea    rax,[rip+0x3649]        # 140005100 <.rdata+0x60>
   140001ab7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001abb:	eb 26                	jmp    140001ae3 <_matherr+0xb3>
   140001abd:	48 8d 05 64 36 00 00 	lea    rax,[rip+0x3664]        # 140005128 <.rdata+0x88>
   140001ac4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ac8:	eb 19                	jmp    140001ae3 <_matherr+0xb3>
   140001aca:	48 8d 05 7f 36 00 00 	lea    rax,[rip+0x367f]        # 140005150 <.rdata+0xb0>
   140001ad1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ad5:	eb 0c                	jmp    140001ae3 <_matherr+0xb3>
   140001ad7:	48 8d 05 a8 36 00 00 	lea    rax,[rip+0x36a8]        # 140005186 <.rdata+0xe6>
   140001ade:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ae2:	90                   	nop
   140001ae3:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ae7:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001aed:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001af1:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001af6:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001afa:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001aff:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b03:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b07:	b9 02 00 00 00       	mov    ecx,0x2
   140001b0c:	e8 2f 17 00 00       	call   140003240 <__acrt_iob_func>
   140001b11:	48 89 c1             	mov    rcx,rax
   140001b14:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b18:	48 8d 05 79 36 00 00 	lea    rax,[rip+0x3679]        # 140005198 <.rdata+0xf8>
   140001b1f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b26:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b2c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b32:	49 89 d9             	mov    r9,rbx
   140001b35:	49 89 d0             	mov    r8,rdx
   140001b38:	48 89 c2             	mov    rdx,rax
   140001b3b:	e8 98 17 00 00       	call   1400032d8 <fprintf>
   140001b40:	b8 00 00 00 00       	mov    eax,0x0
   140001b45:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b49:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b4d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b52:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b59:	5b                   	pop    rbx
   140001b5a:	5d                   	pop    rbp
   140001b5b:	c3                   	ret
   140001b5c:	90                   	nop
   140001b5d:	90                   	nop
   140001b5e:	90                   	nop
   140001b5f:	90                   	nop

0000000140001b60 <__report_error>:
   140001b60:	55                   	push   rbp
   140001b61:	53                   	push   rbx
   140001b62:	48 83 ec 38          	sub    rsp,0x38
   140001b66:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b6b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b6f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b73:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b77:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b7b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b7f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b83:	b9 02 00 00 00       	mov    ecx,0x2
   140001b88:	e8 b3 16 00 00       	call   140003240 <__acrt_iob_func>
   140001b8d:	48 89 c1             	mov    rcx,rax
   140001b90:	48 8d 05 39 36 00 00 	lea    rax,[rip+0x3639]        # 1400051d0 <.rdata>
   140001b97:	48 89 c2             	mov    rdx,rax
   140001b9a:	e8 39 17 00 00       	call   1400032d8 <fprintf>
   140001b9f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001ba3:	b9 02 00 00 00       	mov    ecx,0x2
   140001ba8:	e8 93 16 00 00       	call   140003240 <__acrt_iob_func>
   140001bad:	48 89 c1             	mov    rcx,rax
   140001bb0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001bb4:	49 89 d8             	mov    r8,rbx
   140001bb7:	48 89 c2             	mov    rdx,rax
   140001bba:	e8 61 17 00 00       	call   140003320 <vfprintf>
   140001bbf:	e8 f4 16 00 00       	call   1400032b8 <abort>
   140001bc4:	90                   	nop

0000000140001bc5 <mark_section_writable>:
   140001bc5:	55                   	push   rbp
   140001bc6:	48 89 e5             	mov    rbp,rsp
   140001bc9:	48 83 ec 60          	sub    rsp,0x60
   140001bcd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001bd1:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001bd8:	e9 82 00 00 00       	jmp    140001c5f <mark_section_writable+0x9a>
   140001bdd:	48 8b 0d fc 74 00 00 	mov    rcx,QWORD PTR [rip+0x74fc]        # 1400090e0 <the_secs>
   140001be4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001be7:	48 63 d0             	movsxd rdx,eax
   140001bea:	48 89 d0             	mov    rax,rdx
   140001bed:	48 c1 e0 02          	shl    rax,0x2
   140001bf1:	48 01 d0             	add    rax,rdx
   140001bf4:	48 c1 e0 03          	shl    rax,0x3
   140001bf8:	48 01 c8             	add    rax,rcx
   140001bfb:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001bff:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c03:	72 56                	jb     140001c5b <mark_section_writable+0x96>
   140001c05:	48 8b 0d d4 74 00 00 	mov    rcx,QWORD PTR [rip+0x74d4]        # 1400090e0 <the_secs>
   140001c0c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c0f:	48 63 d0             	movsxd rdx,eax
   140001c12:	48 89 d0             	mov    rax,rdx
   140001c15:	48 c1 e0 02          	shl    rax,0x2
   140001c19:	48 01 d0             	add    rax,rdx
   140001c1c:	48 c1 e0 03          	shl    rax,0x3
   140001c20:	48 01 c8             	add    rax,rcx
   140001c23:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c27:	4c 8b 05 b2 74 00 00 	mov    r8,QWORD PTR [rip+0x74b2]        # 1400090e0 <the_secs>
   140001c2e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c31:	48 63 d0             	movsxd rdx,eax
   140001c34:	48 89 d0             	mov    rax,rdx
   140001c37:	48 c1 e0 02          	shl    rax,0x2
   140001c3b:	48 01 d0             	add    rax,rdx
   140001c3e:	48 c1 e0 03          	shl    rax,0x3
   140001c42:	4c 01 c0             	add    rax,r8
   140001c45:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c49:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c4c:	89 c0                	mov    eax,eax
   140001c4e:	48 01 c8             	add    rax,rcx
   140001c51:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c55:	0f 82 41 02 00 00    	jb     140001e9c <mark_section_writable+0x2d7>
   140001c5b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c5f:	8b 05 83 74 00 00    	mov    eax,DWORD PTR [rip+0x7483]        # 1400090e8 <maxSections>
   140001c65:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c68:	0f 8c 6f ff ff ff    	jl     140001bdd <mark_section_writable+0x18>
   140001c6e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c72:	48 89 c1             	mov    rcx,rax
   140001c75:	e8 c1 11 00 00       	call   140002e3b <__mingw_GetSectionForAddress>
   140001c7a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c7e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c83:	75 13                	jne    140001c98 <mark_section_writable+0xd3>
   140001c85:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c89:	48 8d 0d 60 35 00 00 	lea    rcx,[rip+0x3560]        # 1400051f0 <.rdata+0x20>
   140001c90:	48 89 c2             	mov    rdx,rax
   140001c93:	e8 c8 fe ff ff       	call   140001b60 <__report_error>
   140001c98:	48 8b 0d 41 74 00 00 	mov    rcx,QWORD PTR [rip+0x7441]        # 1400090e0 <the_secs>
   140001c9f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ca2:	48 63 d0             	movsxd rdx,eax
   140001ca5:	48 89 d0             	mov    rax,rdx
   140001ca8:	48 c1 e0 02          	shl    rax,0x2
   140001cac:	48 01 d0             	add    rax,rdx
   140001caf:	48 c1 e0 03          	shl    rax,0x3
   140001cb3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001cb7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001cbb:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001cbf:	48 8b 0d 1a 74 00 00 	mov    rcx,QWORD PTR [rip+0x741a]        # 1400090e0 <the_secs>
   140001cc6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cc9:	48 63 d0             	movsxd rdx,eax
   140001ccc:	48 89 d0             	mov    rax,rdx
   140001ccf:	48 c1 e0 02          	shl    rax,0x2
   140001cd3:	48 01 d0             	add    rax,rdx
   140001cd6:	48 c1 e0 03          	shl    rax,0x3
   140001cda:	48 01 c8             	add    rax,rcx
   140001cdd:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001ce3:	e8 9f 12 00 00       	call   140002f87 <_GetPEImageBase>
   140001ce8:	48 89 c1             	mov    rcx,rax
   140001ceb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001cef:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001cf2:	41 89 c1             	mov    r9d,eax
   140001cf5:	4c 8b 05 e4 73 00 00 	mov    r8,QWORD PTR [rip+0x73e4]        # 1400090e0 <the_secs>
   140001cfc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cff:	48 63 d0             	movsxd rdx,eax
   140001d02:	48 89 d0             	mov    rax,rdx
   140001d05:	48 c1 e0 02          	shl    rax,0x2
   140001d09:	48 01 d0             	add    rax,rdx
   140001d0c:	48 c1 e0 03          	shl    rax,0x3
   140001d10:	4c 01 c0             	add    rax,r8
   140001d13:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d17:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d1b:	48 8b 0d be 73 00 00 	mov    rcx,QWORD PTR [rip+0x73be]        # 1400090e0 <the_secs>
   140001d22:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d25:	48 63 d0             	movsxd rdx,eax
   140001d28:	48 89 d0             	mov    rax,rdx
   140001d2b:	48 c1 e0 02          	shl    rax,0x2
   140001d2f:	48 01 d0             	add    rax,rdx
   140001d32:	48 c1 e0 03          	shl    rax,0x3
   140001d36:	48 01 c8             	add    rax,rcx
   140001d39:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d3d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d41:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d47:	48 89 c1             	mov    rcx,rax
   140001d4a:	48 8b 05 a7 84 00 00 	mov    rax,QWORD PTR [rip+0x84a7]        # 14000a1f8 <__imp_VirtualQuery>
   140001d51:	ff d0                	call   rax
   140001d53:	48 85 c0             	test   rax,rax
   140001d56:	75 3f                	jne    140001d97 <mark_section_writable+0x1d2>
   140001d58:	48 8b 0d 81 73 00 00 	mov    rcx,QWORD PTR [rip+0x7381]        # 1400090e0 <the_secs>
   140001d5f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d62:	48 63 d0             	movsxd rdx,eax
   140001d65:	48 89 d0             	mov    rax,rdx
   140001d68:	48 c1 e0 02          	shl    rax,0x2
   140001d6c:	48 01 d0             	add    rax,rdx
   140001d6f:	48 c1 e0 03          	shl    rax,0x3
   140001d73:	48 01 c8             	add    rax,rcx
   140001d76:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d7a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d7e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d81:	89 c1                	mov    ecx,eax
   140001d83:	48 8d 05 86 34 00 00 	lea    rax,[rip+0x3486]        # 140005210 <.rdata+0x40>
   140001d8a:	49 89 d0             	mov    r8,rdx
   140001d8d:	89 ca                	mov    edx,ecx
   140001d8f:	48 89 c1             	mov    rcx,rax
   140001d92:	e8 c9 fd ff ff       	call   140001b60 <__report_error>
   140001d97:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d9a:	83 f8 40             	cmp    eax,0x40
   140001d9d:	0f 84 e8 00 00 00    	je     140001e8b <mark_section_writable+0x2c6>
   140001da3:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001da6:	83 f8 04             	cmp    eax,0x4
   140001da9:	0f 84 dc 00 00 00    	je     140001e8b <mark_section_writable+0x2c6>
   140001daf:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001db2:	3d 80 00 00 00       	cmp    eax,0x80
   140001db7:	0f 84 ce 00 00 00    	je     140001e8b <mark_section_writable+0x2c6>
   140001dbd:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dc0:	83 f8 08             	cmp    eax,0x8
   140001dc3:	0f 84 c2 00 00 00    	je     140001e8b <mark_section_writable+0x2c6>
   140001dc9:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dcc:	83 f8 02             	cmp    eax,0x2
   140001dcf:	75 09                	jne    140001dda <mark_section_writable+0x215>
   140001dd1:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001dd8:	eb 07                	jmp    140001de1 <mark_section_writable+0x21c>
   140001dda:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001de1:	48 8b 0d f8 72 00 00 	mov    rcx,QWORD PTR [rip+0x72f8]        # 1400090e0 <the_secs>
   140001de8:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001deb:	48 63 d0             	movsxd rdx,eax
   140001dee:	48 89 d0             	mov    rax,rdx
   140001df1:	48 c1 e0 02          	shl    rax,0x2
   140001df5:	48 01 d0             	add    rax,rdx
   140001df8:	48 c1 e0 03          	shl    rax,0x3
   140001dfc:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e00:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e04:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e08:	48 8b 0d d1 72 00 00 	mov    rcx,QWORD PTR [rip+0x72d1]        # 1400090e0 <the_secs>
   140001e0f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e12:	48 63 d0             	movsxd rdx,eax
   140001e15:	48 89 d0             	mov    rax,rdx
   140001e18:	48 c1 e0 02          	shl    rax,0x2
   140001e1c:	48 01 d0             	add    rax,rdx
   140001e1f:	48 c1 e0 03          	shl    rax,0x3
   140001e23:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e27:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e2b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e2f:	48 8b 0d aa 72 00 00 	mov    rcx,QWORD PTR [rip+0x72aa]        # 1400090e0 <the_secs>
   140001e36:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e39:	48 63 d0             	movsxd rdx,eax
   140001e3c:	48 89 d0             	mov    rax,rdx
   140001e3f:	48 c1 e0 02          	shl    rax,0x2
   140001e43:	48 01 d0             	add    rax,rdx
   140001e46:	48 c1 e0 03          	shl    rax,0x3
   140001e4a:	48 01 c8             	add    rax,rcx
   140001e4d:	49 89 c0             	mov    r8,rax
   140001e50:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e54:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e58:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e5b:	4d 89 c1             	mov    r9,r8
   140001e5e:	41 89 c8             	mov    r8d,ecx
   140001e61:	48 89 c1             	mov    rcx,rax
   140001e64:	48 8b 05 85 83 00 00 	mov    rax,QWORD PTR [rip+0x8385]        # 14000a1f0 <__imp_VirtualProtect>
   140001e6b:	ff d0                	call   rax
   140001e6d:	85 c0                	test   eax,eax
   140001e6f:	75 1a                	jne    140001e8b <mark_section_writable+0x2c6>
   140001e71:	48 8b 05 30 83 00 00 	mov    rax,QWORD PTR [rip+0x8330]        # 14000a1a8 <__imp_GetLastError>
   140001e78:	ff d0                	call   rax
   140001e7a:	89 c2                	mov    edx,eax
   140001e7c:	48 8d 05 c5 33 00 00 	lea    rax,[rip+0x33c5]        # 140005248 <.rdata+0x78>
   140001e83:	48 89 c1             	mov    rcx,rax
   140001e86:	e8 d5 fc ff ff       	call   140001b60 <__report_error>
   140001e8b:	8b 05 57 72 00 00    	mov    eax,DWORD PTR [rip+0x7257]        # 1400090e8 <maxSections>
   140001e91:	83 c0 01             	add    eax,0x1
   140001e94:	89 05 4e 72 00 00    	mov    DWORD PTR [rip+0x724e],eax        # 1400090e8 <maxSections>
   140001e9a:	eb 01                	jmp    140001e9d <mark_section_writable+0x2d8>
   140001e9c:	90                   	nop
   140001e9d:	48 83 c4 60          	add    rsp,0x60
   140001ea1:	5d                   	pop    rbp
   140001ea2:	c3                   	ret

0000000140001ea3 <restore_modified_sections>:
   140001ea3:	55                   	push   rbp
   140001ea4:	48 89 e5             	mov    rbp,rsp
   140001ea7:	48 83 ec 30          	sub    rsp,0x30
   140001eab:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001eb2:	e9 ad 00 00 00       	jmp    140001f64 <restore_modified_sections+0xc1>
   140001eb7:	48 8b 0d 22 72 00 00 	mov    rcx,QWORD PTR [rip+0x7222]        # 1400090e0 <the_secs>
   140001ebe:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ec1:	48 63 d0             	movsxd rdx,eax
   140001ec4:	48 89 d0             	mov    rax,rdx
   140001ec7:	48 c1 e0 02          	shl    rax,0x2
   140001ecb:	48 01 d0             	add    rax,rdx
   140001ece:	48 c1 e0 03          	shl    rax,0x3
   140001ed2:	48 01 c8             	add    rax,rcx
   140001ed5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ed7:	85 c0                	test   eax,eax
   140001ed9:	0f 84 80 00 00 00    	je     140001f5f <restore_modified_sections+0xbc>
   140001edf:	48 8b 0d fa 71 00 00 	mov    rcx,QWORD PTR [rip+0x71fa]        # 1400090e0 <the_secs>
   140001ee6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ee9:	48 63 d0             	movsxd rdx,eax
   140001eec:	48 89 d0             	mov    rax,rdx
   140001eef:	48 c1 e0 02          	shl    rax,0x2
   140001ef3:	48 01 d0             	add    rax,rdx
   140001ef6:	48 c1 e0 03          	shl    rax,0x3
   140001efa:	48 01 c8             	add    rax,rcx
   140001efd:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f00:	48 8b 0d d9 71 00 00 	mov    rcx,QWORD PTR [rip+0x71d9]        # 1400090e0 <the_secs>
   140001f07:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f0a:	48 63 d0             	movsxd rdx,eax
   140001f0d:	48 89 d0             	mov    rax,rdx
   140001f10:	48 c1 e0 02          	shl    rax,0x2
   140001f14:	48 01 d0             	add    rax,rdx
   140001f17:	48 c1 e0 03          	shl    rax,0x3
   140001f1b:	48 01 c8             	add    rax,rcx
   140001f1e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f22:	4c 8b 05 b7 71 00 00 	mov    r8,QWORD PTR [rip+0x71b7]        # 1400090e0 <the_secs>
   140001f29:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f2c:	48 63 d0             	movsxd rdx,eax
   140001f2f:	48 89 d0             	mov    rax,rdx
   140001f32:	48 c1 e0 02          	shl    rax,0x2
   140001f36:	48 01 d0             	add    rax,rdx
   140001f39:	48 c1 e0 03          	shl    rax,0x3
   140001f3d:	4c 01 c0             	add    rax,r8
   140001f40:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f44:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f48:	49 89 d1             	mov    r9,rdx
   140001f4b:	45 89 d0             	mov    r8d,r10d
   140001f4e:	48 89 ca             	mov    rdx,rcx
   140001f51:	48 89 c1             	mov    rcx,rax
   140001f54:	48 8b 05 95 82 00 00 	mov    rax,QWORD PTR [rip+0x8295]        # 14000a1f0 <__imp_VirtualProtect>
   140001f5b:	ff d0                	call   rax
   140001f5d:	eb 01                	jmp    140001f60 <restore_modified_sections+0xbd>
   140001f5f:	90                   	nop
   140001f60:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f64:	8b 05 7e 71 00 00    	mov    eax,DWORD PTR [rip+0x717e]        # 1400090e8 <maxSections>
   140001f6a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f6d:	0f 8c 44 ff ff ff    	jl     140001eb7 <restore_modified_sections+0x14>
   140001f73:	90                   	nop
   140001f74:	90                   	nop
   140001f75:	48 83 c4 30          	add    rsp,0x30
   140001f79:	5d                   	pop    rbp
   140001f7a:	c3                   	ret

0000000140001f7b <__write_memory>:
   140001f7b:	55                   	push   rbp
   140001f7c:	48 89 e5             	mov    rbp,rsp
   140001f7f:	48 83 ec 20          	sub    rsp,0x20
   140001f83:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f87:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f8b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f8f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f94:	74 25                	je     140001fbb <__write_memory+0x40>
   140001f96:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f9a:	48 89 c1             	mov    rcx,rax
   140001f9d:	e8 23 fc ff ff       	call   140001bc5 <mark_section_writable>
   140001fa2:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001fa6:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001faa:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fae:	49 89 c8             	mov    r8,rcx
   140001fb1:	48 89 c1             	mov    rcx,rax
   140001fb4:	e8 37 13 00 00       	call   1400032f0 <memcpy>
   140001fb9:	eb 01                	jmp    140001fbc <__write_memory+0x41>
   140001fbb:	90                   	nop
   140001fbc:	48 83 c4 20          	add    rsp,0x20
   140001fc0:	5d                   	pop    rbp
   140001fc1:	c3                   	ret

0000000140001fc2 <do_pseudo_reloc>:
   140001fc2:	55                   	push   rbp
   140001fc3:	48 89 e5             	mov    rbp,rsp
   140001fc6:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001fca:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fce:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001fd2:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001fd6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001fda:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001fde:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001fe2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fe6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001fea:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001fef:	0f 8e 44 03 00 00    	jle    140002339 <do_pseudo_reloc+0x377>
   140001ff5:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001ffa:	7e 25                	jle    140002021 <do_pseudo_reloc+0x5f>
   140001ffc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002000:	8b 00                	mov    eax,DWORD PTR [rax]
   140002002:	85 c0                	test   eax,eax
   140002004:	75 1b                	jne    140002021 <do_pseudo_reloc+0x5f>
   140002006:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000200a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000200d:	85 c0                	test   eax,eax
   14000200f:	75 10                	jne    140002021 <do_pseudo_reloc+0x5f>
   140002011:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002015:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002018:	85 c0                	test   eax,eax
   14000201a:	75 05                	jne    140002021 <do_pseudo_reloc+0x5f>
   14000201c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002021:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002025:	8b 00                	mov    eax,DWORD PTR [rax]
   140002027:	85 c0                	test   eax,eax
   140002029:	75 0b                	jne    140002036 <do_pseudo_reloc+0x74>
   14000202b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000202f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002032:	85 c0                	test   eax,eax
   140002034:	74 59                	je     14000208f <do_pseudo_reloc+0xcd>
   140002036:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000203a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000203e:	eb 40                	jmp    140002080 <do_pseudo_reloc+0xbe>
   140002040:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002044:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002047:	89 c2                	mov    edx,eax
   140002049:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000204d:	48 01 d0             	add    rax,rdx
   140002050:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002054:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002058:	8b 10                	mov    edx,DWORD PTR [rax]
   14000205a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000205e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002060:	01 d0                	add    eax,edx
   140002062:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002065:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002069:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000206d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002073:	48 89 c1             	mov    rcx,rax
   140002076:	e8 00 ff ff ff       	call   140001f7b <__write_memory>
   14000207b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002080:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002084:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002088:	72 b6                	jb     140002040 <do_pseudo_reloc+0x7e>
   14000208a:	e9 ab 02 00 00       	jmp    14000233a <do_pseudo_reloc+0x378>
   14000208f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002093:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002096:	83 f8 01             	cmp    eax,0x1
   140002099:	74 18                	je     1400020b3 <do_pseudo_reloc+0xf1>
   14000209b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000209f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020a2:	89 c2                	mov    edx,eax
   1400020a4:	48 8d 05 c5 31 00 00 	lea    rax,[rip+0x31c5]        # 140005270 <.rdata+0xa0>
   1400020ab:	48 89 c1             	mov    rcx,rax
   1400020ae:	e8 ad fa ff ff       	call   140001b60 <__report_error>
   1400020b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020b7:	48 83 c0 0c          	add    rax,0xc
   1400020bb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400020bf:	e9 65 02 00 00       	jmp    140002329 <do_pseudo_reloc+0x367>
   1400020c4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020c8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020cb:	89 c2                	mov    edx,eax
   1400020cd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020d1:	48 01 d0             	add    rax,rdx
   1400020d4:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020d8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020dc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020de:	89 c2                	mov    edx,eax
   1400020e0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020e4:	48 01 d0             	add    rax,rdx
   1400020e7:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020eb:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400020ef:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400020f2:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020f6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020fa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020fd:	0f b6 c0             	movzx  eax,al
   140002100:	83 f8 40             	cmp    eax,0x40
   140002103:	0f 84 b6 00 00 00    	je     1400021bf <do_pseudo_reloc+0x1fd>
   140002109:	83 f8 40             	cmp    eax,0x40
   14000210c:	0f 87 ba 00 00 00    	ja     1400021cc <do_pseudo_reloc+0x20a>
   140002112:	83 f8 20             	cmp    eax,0x20
   140002115:	74 77                	je     14000218e <do_pseudo_reloc+0x1cc>
   140002117:	83 f8 20             	cmp    eax,0x20
   14000211a:	0f 87 ac 00 00 00    	ja     1400021cc <do_pseudo_reloc+0x20a>
   140002120:	83 f8 08             	cmp    eax,0x8
   140002123:	74 0a                	je     14000212f <do_pseudo_reloc+0x16d>
   140002125:	83 f8 10             	cmp    eax,0x10
   140002128:	74 38                	je     140002162 <do_pseudo_reloc+0x1a0>
   14000212a:	e9 9d 00 00 00       	jmp    1400021cc <do_pseudo_reloc+0x20a>
   14000212f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002133:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002136:	0f b6 c0             	movzx  eax,al
   140002139:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000213d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002141:	25 80 00 00 00       	and    eax,0x80
   140002146:	48 85 c0             	test   rax,rax
   140002149:	0f 84 9d 00 00 00    	je     1400021ec <do_pseudo_reloc+0x22a>
   14000214f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002153:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002159:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000215d:	e9 8a 00 00 00       	jmp    1400021ec <do_pseudo_reloc+0x22a>
   140002162:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002166:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002169:	0f b7 c0             	movzx  eax,ax
   14000216c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002170:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002174:	25 00 80 00 00       	and    eax,0x8000
   140002179:	48 85 c0             	test   rax,rax
   14000217c:	74 71                	je     1400021ef <do_pseudo_reloc+0x22d>
   14000217e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002182:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002188:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000218c:	eb 61                	jmp    1400021ef <do_pseudo_reloc+0x22d>
   14000218e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002192:	8b 00                	mov    eax,DWORD PTR [rax]
   140002194:	89 c0                	mov    eax,eax
   140002196:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000219a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000219e:	25 00 00 00 80       	and    eax,0x80000000
   1400021a3:	48 85 c0             	test   rax,rax
   1400021a6:	74 4a                	je     1400021f2 <do_pseudo_reloc+0x230>
   1400021a8:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021ac:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   1400021b3:	ff ff ff 
   1400021b6:	48 09 d0             	or     rax,rdx
   1400021b9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021bd:	eb 33                	jmp    1400021f2 <do_pseudo_reloc+0x230>
   1400021bf:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021c3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400021c6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ca:	eb 27                	jmp    1400021f3 <do_pseudo_reloc+0x231>
   1400021cc:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   1400021d3:	00 
   1400021d4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021d8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021db:	0f b6 c0             	movzx  eax,al
   1400021de:	48 8d 0d c3 30 00 00 	lea    rcx,[rip+0x30c3]        # 1400052a8 <.rdata+0xd8>
   1400021e5:	89 c2                	mov    edx,eax
   1400021e7:	e8 74 f9 ff ff       	call   140001b60 <__report_error>
   1400021ec:	90                   	nop
   1400021ed:	eb 04                	jmp    1400021f3 <do_pseudo_reloc+0x231>
   1400021ef:	90                   	nop
   1400021f0:	eb 01                	jmp    1400021f3 <do_pseudo_reloc+0x231>
   1400021f2:	90                   	nop
   1400021f3:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   1400021f7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021fb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021fd:	89 c2                	mov    edx,eax
   1400021ff:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002203:	48 01 c2             	add    rdx,rax
   140002206:	48 89 c8             	mov    rax,rcx
   140002209:	48 29 d0             	sub    rax,rdx
   14000220c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002210:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002214:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002218:	48 01 d0             	add    rax,rdx
   14000221b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000221f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002223:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002226:	25 ff 00 00 00       	and    eax,0xff
   14000222b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000222e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002232:	77 67                	ja     14000229b <do_pseudo_reloc+0x2d9>
   140002234:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002237:	ba 01 00 00 00       	mov    edx,0x1
   14000223c:	89 c1                	mov    ecx,eax
   14000223e:	48 d3 e2             	shl    rdx,cl
   140002241:	48 89 d0             	mov    rax,rdx
   140002244:	48 83 e8 01          	sub    rax,0x1
   140002248:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000224c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000224f:	83 e8 01             	sub    eax,0x1
   140002252:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002259:	89 c1                	mov    ecx,eax
   14000225b:	48 d3 e2             	shl    rdx,cl
   14000225e:	48 89 d0             	mov    rax,rdx
   140002261:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002265:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002269:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000226d:	7c 0a                	jl     140002279 <do_pseudo_reloc+0x2b7>
   14000226f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002273:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002277:	7e 22                	jle    14000229b <do_pseudo_reloc+0x2d9>
   140002279:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000227d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002281:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002285:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002288:	48 8d 0d 49 30 00 00 	lea    rcx,[rip+0x3049]        # 1400052d8 <.rdata+0x108>
   14000228f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002294:	89 c2                	mov    edx,eax
   140002296:	e8 c5 f8 ff ff       	call   140001b60 <__report_error>
   14000229b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000229f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022a2:	0f b6 c0             	movzx  eax,al
   1400022a5:	83 f8 40             	cmp    eax,0x40
   1400022a8:	74 63                	je     14000230d <do_pseudo_reloc+0x34b>
   1400022aa:	83 f8 40             	cmp    eax,0x40
   1400022ad:	77 75                	ja     140002324 <do_pseudo_reloc+0x362>
   1400022af:	83 f8 20             	cmp    eax,0x20
   1400022b2:	74 41                	je     1400022f5 <do_pseudo_reloc+0x333>
   1400022b4:	83 f8 20             	cmp    eax,0x20
   1400022b7:	77 6b                	ja     140002324 <do_pseudo_reloc+0x362>
   1400022b9:	83 f8 08             	cmp    eax,0x8
   1400022bc:	74 07                	je     1400022c5 <do_pseudo_reloc+0x303>
   1400022be:	83 f8 10             	cmp    eax,0x10
   1400022c1:	74 1a                	je     1400022dd <do_pseudo_reloc+0x31b>
   1400022c3:	eb 5f                	jmp    140002324 <do_pseudo_reloc+0x362>
   1400022c5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022c9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022cd:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400022d3:	48 89 c1             	mov    rcx,rax
   1400022d6:	e8 a0 fc ff ff       	call   140001f7b <__write_memory>
   1400022db:	eb 47                	jmp    140002324 <do_pseudo_reloc+0x362>
   1400022dd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022e1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022e5:	41 b8 02 00 00 00    	mov    r8d,0x2
   1400022eb:	48 89 c1             	mov    rcx,rax
   1400022ee:	e8 88 fc ff ff       	call   140001f7b <__write_memory>
   1400022f3:	eb 2f                	jmp    140002324 <do_pseudo_reloc+0x362>
   1400022f5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022f9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022fd:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002303:	48 89 c1             	mov    rcx,rax
   140002306:	e8 70 fc ff ff       	call   140001f7b <__write_memory>
   14000230b:	eb 17                	jmp    140002324 <do_pseudo_reloc+0x362>
   14000230d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002311:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002315:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000231b:	48 89 c1             	mov    rcx,rax
   14000231e:	e8 58 fc ff ff       	call   140001f7b <__write_memory>
   140002323:	90                   	nop
   140002324:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002329:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000232d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002331:	0f 82 8d fd ff ff    	jb     1400020c4 <do_pseudo_reloc+0x102>
   140002337:	eb 01                	jmp    14000233a <do_pseudo_reloc+0x378>
   140002339:	90                   	nop
   14000233a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000233e:	5d                   	pop    rbp
   14000233f:	c3                   	ret

0000000140002340 <_pei386_runtime_relocator>:
   140002340:	55                   	push   rbp
   140002341:	48 89 e5             	mov    rbp,rsp
   140002344:	48 83 ec 30          	sub    rsp,0x30
   140002348:	8b 05 9e 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d9e]        # 1400090ec <was_init.0>
   14000234e:	85 c0                	test   eax,eax
   140002350:	0f 85 88 00 00 00    	jne    1400023de <_pei386_runtime_relocator+0x9e>
   140002356:	8b 05 90 6d 00 00    	mov    eax,DWORD PTR [rip+0x6d90]        # 1400090ec <was_init.0>
   14000235c:	83 c0 01             	add    eax,0x1
   14000235f:	89 05 87 6d 00 00    	mov    DWORD PTR [rip+0x6d87],eax        # 1400090ec <was_init.0>
   140002365:	e8 21 0b 00 00       	call   140002e8b <__mingw_GetSectionCount>
   14000236a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000236d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002370:	48 63 d0             	movsxd rdx,eax
   140002373:	48 89 d0             	mov    rax,rdx
   140002376:	48 c1 e0 02          	shl    rax,0x2
   14000237a:	48 01 d0             	add    rax,rdx
   14000237d:	48 c1 e0 03          	shl    rax,0x3
   140002381:	48 83 c0 0f          	add    rax,0xf
   140002385:	48 c1 e8 04          	shr    rax,0x4
   140002389:	48 c1 e0 04          	shl    rax,0x4
   14000238d:	e8 7e 0d 00 00       	call   140003110 <___chkstk_ms>
   140002392:	48 29 c4             	sub    rsp,rax
   140002395:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000239a:	48 83 c0 0f          	add    rax,0xf
   14000239e:	48 c1 e8 04          	shr    rax,0x4
   1400023a2:	48 c1 e0 04          	shl    rax,0x4
   1400023a6:	48 89 05 33 6d 00 00 	mov    QWORD PTR [rip+0x6d33],rax        # 1400090e0 <the_secs>
   1400023ad:	c7 05 31 6d 00 00 00 	mov    DWORD PTR [rip+0x6d31],0x0        # 1400090e8 <maxSections>
   1400023b4:	00 00 00 
   1400023b7:	48 8b 0d a2 2f 00 00 	mov    rcx,QWORD PTR [rip+0x2fa2]        # 140005360 <.refptr.__ImageBase>
   1400023be:	48 8b 15 ab 2f 00 00 	mov    rdx,QWORD PTR [rip+0x2fab]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   1400023c5:	48 8b 05 b4 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fb4]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   1400023cc:	49 89 c8             	mov    r8,rcx
   1400023cf:	48 89 c1             	mov    rcx,rax
   1400023d2:	e8 eb fb ff ff       	call   140001fc2 <do_pseudo_reloc>
   1400023d7:	e8 c7 fa ff ff       	call   140001ea3 <restore_modified_sections>
   1400023dc:	eb 01                	jmp    1400023df <_pei386_runtime_relocator+0x9f>
   1400023de:	90                   	nop
   1400023df:	48 89 ec             	mov    rsp,rbp
   1400023e2:	5d                   	pop    rbp
   1400023e3:	c3                   	ret
   1400023e4:	90                   	nop
   1400023e5:	90                   	nop
   1400023e6:	90                   	nop
   1400023e7:	90                   	nop
   1400023e8:	90                   	nop
   1400023e9:	90                   	nop
   1400023ea:	90                   	nop
   1400023eb:	90                   	nop
   1400023ec:	90                   	nop
   1400023ed:	90                   	nop
   1400023ee:	90                   	nop
   1400023ef:	90                   	nop

00000001400023f0 <__mingw_raise_matherr>:
   1400023f0:	55                   	push   rbp
   1400023f1:	48 89 e5             	mov    rbp,rsp
   1400023f4:	48 83 ec 50          	sub    rsp,0x50
   1400023f8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400023fb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400023ff:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002404:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002409:	48 8b 05 e0 6c 00 00 	mov    rax,QWORD PTR [rip+0x6ce0]        # 1400090f0 <stUserMathErr>
   140002410:	48 85 c0             	test   rax,rax
   140002413:	74 3e                	je     140002453 <__mingw_raise_matherr+0x63>
   140002415:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002418:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000241b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000241f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002423:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002428:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000242d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002432:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002437:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000243c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002441:	48 8b 15 a8 6c 00 00 	mov    rdx,QWORD PTR [rip+0x6ca8]        # 1400090f0 <stUserMathErr>
   140002448:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000244c:	48 89 c1             	mov    rcx,rax
   14000244f:	ff d2                	call   rdx
   140002451:	eb 01                	jmp    140002454 <__mingw_raise_matherr+0x64>
   140002453:	90                   	nop
   140002454:	48 83 c4 50          	add    rsp,0x50
   140002458:	5d                   	pop    rbp
   140002459:	c3                   	ret

000000014000245a <__mingw_setusermatherr>:
   14000245a:	55                   	push   rbp
   14000245b:	48 89 e5             	mov    rbp,rsp
   14000245e:	48 83 ec 20          	sub    rsp,0x20
   140002462:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002466:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000246a:	48 89 05 7f 6c 00 00 	mov    QWORD PTR [rip+0x6c7f],rax        # 1400090f0 <stUserMathErr>
   140002471:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002475:	48 89 c1             	mov    rcx,rax
   140002478:	e8 13 0e 00 00       	call   140003290 <__setusermatherr>
   14000247d:	90                   	nop
   14000247e:	48 83 c4 20          	add    rsp,0x20
   140002482:	5d                   	pop    rbp
   140002483:	c3                   	ret
   140002484:	90                   	nop
   140002485:	90                   	nop
   140002486:	90                   	nop
   140002487:	90                   	nop
   140002488:	90                   	nop
   140002489:	90                   	nop
   14000248a:	90                   	nop
   14000248b:	90                   	nop
   14000248c:	90                   	nop
   14000248d:	90                   	nop
   14000248e:	90                   	nop
   14000248f:	90                   	nop

0000000140002490 <__mingw_SEH_error_handler>:
   140002490:	55                   	push   rbp
   140002491:	48 89 e5             	mov    rbp,rsp
   140002494:	48 83 ec 30          	sub    rsp,0x30
   140002498:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000249c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400024a0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400024a4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400024a8:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400024af:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400024b6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024ba:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024bd:	83 e0 02             	and    eax,0x2
   1400024c0:	85 c0                	test   eax,eax
   1400024c2:	74 0a                	je     1400024ce <__mingw_SEH_error_handler+0x3e>
   1400024c4:	b8 01 00 00 00       	mov    eax,0x1
   1400024c9:	e9 16 02 00 00       	jmp    1400026e4 <__mingw_SEH_error_handler+0x254>
   1400024ce:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024d2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024d4:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400024d9:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400024de:	75 18                	jne    1400024f8 <__mingw_SEH_error_handler+0x68>
   1400024e0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024e4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024e7:	83 e0 01             	and    eax,0x1
   1400024ea:	85 c0                	test   eax,eax
   1400024ec:	75 0a                	jne    1400024f8 <__mingw_SEH_error_handler+0x68>
   1400024ee:	b8 00 00 00 00       	mov    eax,0x0
   1400024f3:	e9 ec 01 00 00       	jmp    1400026e4 <__mingw_SEH_error_handler+0x254>
   1400024f8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024fc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024fe:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002503:	0f 84 12 01 00 00    	je     14000261b <__mingw_SEH_error_handler+0x18b>
   140002509:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000250e:	0f 87 c3 01 00 00    	ja     1400026d7 <__mingw_SEH_error_handler+0x247>
   140002514:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002519:	0f 87 b8 01 00 00    	ja     1400026d7 <__mingw_SEH_error_handler+0x247>
   14000251f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002524:	0f 83 4c 01 00 00    	jae    140002676 <__mingw_SEH_error_handler+0x1e6>
   14000252a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000252f:	0f 84 3a 01 00 00    	je     14000266f <__mingw_SEH_error_handler+0x1df>
   140002535:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000253a:	0f 87 97 01 00 00    	ja     1400026d7 <__mingw_SEH_error_handler+0x247>
   140002540:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002545:	0f 84 83 01 00 00    	je     1400026ce <__mingw_SEH_error_handler+0x23e>
   14000254b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002550:	0f 87 81 01 00 00    	ja     1400026d7 <__mingw_SEH_error_handler+0x247>
   140002556:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000255b:	0f 87 76 01 00 00    	ja     1400026d7 <__mingw_SEH_error_handler+0x247>
   140002561:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002566:	0f 83 03 01 00 00    	jae    14000266f <__mingw_SEH_error_handler+0x1df>
   14000256c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002571:	0f 84 57 01 00 00    	je     1400026ce <__mingw_SEH_error_handler+0x23e>
   140002577:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000257c:	0f 87 55 01 00 00    	ja     1400026d7 <__mingw_SEH_error_handler+0x247>
   140002582:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002587:	0f 84 8e 00 00 00    	je     14000261b <__mingw_SEH_error_handler+0x18b>
   14000258d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002592:	0f 87 3f 01 00 00    	ja     1400026d7 <__mingw_SEH_error_handler+0x247>
   140002598:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000259d:	0f 84 2b 01 00 00    	je     1400026ce <__mingw_SEH_error_handler+0x23e>
   1400025a3:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025a8:	0f 87 29 01 00 00    	ja     1400026d7 <__mingw_SEH_error_handler+0x247>
   1400025ae:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400025b3:	0f 84 15 01 00 00    	je     1400026ce <__mingw_SEH_error_handler+0x23e>
   1400025b9:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400025be:	0f 85 13 01 00 00    	jne    1400026d7 <__mingw_SEH_error_handler+0x247>
   1400025c4:	ba 00 00 00 00       	mov    edx,0x0
   1400025c9:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025ce:	e8 35 0d 00 00       	call   140003308 <signal>
   1400025d3:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025d7:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025dc:	75 1b                	jne    1400025f9 <__mingw_SEH_error_handler+0x169>
   1400025de:	ba 01 00 00 00       	mov    edx,0x1
   1400025e3:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025e8:	e8 1b 0d 00 00       	call   140003308 <signal>
   1400025ed:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025f4:	e9 e1 00 00 00       	jmp    1400026da <__mingw_SEH_error_handler+0x24a>
   1400025f9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025fe:	0f 84 d6 00 00 00    	je     1400026da <__mingw_SEH_error_handler+0x24a>
   140002604:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002608:	b9 0b 00 00 00       	mov    ecx,0xb
   14000260d:	ff d0                	call   rax
   14000260f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002616:	e9 bf 00 00 00       	jmp    1400026da <__mingw_SEH_error_handler+0x24a>
   14000261b:	ba 00 00 00 00       	mov    edx,0x0
   140002620:	b9 04 00 00 00       	mov    ecx,0x4
   140002625:	e8 de 0c 00 00       	call   140003308 <signal>
   14000262a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000262e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002633:	75 1b                	jne    140002650 <__mingw_SEH_error_handler+0x1c0>
   140002635:	ba 01 00 00 00       	mov    edx,0x1
   14000263a:	b9 04 00 00 00       	mov    ecx,0x4
   14000263f:	e8 c4 0c 00 00       	call   140003308 <signal>
   140002644:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000264b:	e9 8d 00 00 00       	jmp    1400026dd <__mingw_SEH_error_handler+0x24d>
   140002650:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002655:	0f 84 82 00 00 00    	je     1400026dd <__mingw_SEH_error_handler+0x24d>
   14000265b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000265f:	b9 04 00 00 00       	mov    ecx,0x4
   140002664:	ff d0                	call   rax
   140002666:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000266d:	eb 6e                	jmp    1400026dd <__mingw_SEH_error_handler+0x24d>
   14000266f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002676:	ba 00 00 00 00       	mov    edx,0x0
   14000267b:	b9 08 00 00 00       	mov    ecx,0x8
   140002680:	e8 83 0c 00 00       	call   140003308 <signal>
   140002685:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002689:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000268e:	75 23                	jne    1400026b3 <__mingw_SEH_error_handler+0x223>
   140002690:	ba 01 00 00 00       	mov    edx,0x1
   140002695:	b9 08 00 00 00       	mov    ecx,0x8
   14000269a:	e8 69 0c 00 00       	call   140003308 <signal>
   14000269f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400026a3:	74 05                	je     1400026aa <__mingw_SEH_error_handler+0x21a>
   1400026a5:	e8 a6 05 00 00       	call   140002c50 <_fpreset>
   1400026aa:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026b1:	eb 2d                	jmp    1400026e0 <__mingw_SEH_error_handler+0x250>
   1400026b3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026b8:	74 26                	je     1400026e0 <__mingw_SEH_error_handler+0x250>
   1400026ba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026be:	b9 08 00 00 00       	mov    ecx,0x8
   1400026c3:	ff d0                	call   rax
   1400026c5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026cc:	eb 12                	jmp    1400026e0 <__mingw_SEH_error_handler+0x250>
   1400026ce:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026d5:	eb 0a                	jmp    1400026e1 <__mingw_SEH_error_handler+0x251>
   1400026d7:	90                   	nop
   1400026d8:	eb 07                	jmp    1400026e1 <__mingw_SEH_error_handler+0x251>
   1400026da:	90                   	nop
   1400026db:	eb 04                	jmp    1400026e1 <__mingw_SEH_error_handler+0x251>
   1400026dd:	90                   	nop
   1400026de:	eb 01                	jmp    1400026e1 <__mingw_SEH_error_handler+0x251>
   1400026e0:	90                   	nop
   1400026e1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400026e4:	48 83 c4 30          	add    rsp,0x30
   1400026e8:	5d                   	pop    rbp
   1400026e9:	c3                   	ret

00000001400026ea <_gnu_exception_handler>:
   1400026ea:	55                   	push   rbp
   1400026eb:	48 89 e5             	mov    rbp,rsp
   1400026ee:	48 83 ec 30          	sub    rsp,0x30
   1400026f2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400026f6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026fd:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002704:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002708:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000270b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000270d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002712:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002717:	75 1b                	jne    140002734 <_gnu_exception_handler+0x4a>
   140002719:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000271d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002720:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002723:	83 e0 01             	and    eax,0x1
   140002726:	85 c0                	test   eax,eax
   140002728:	75 0a                	jne    140002734 <_gnu_exception_handler+0x4a>
   14000272a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000272f:	e9 14 02 00 00       	jmp    140002948 <_gnu_exception_handler+0x25e>
   140002734:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002738:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000273b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000273d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002742:	0f 84 12 01 00 00    	je     14000285a <_gnu_exception_handler+0x170>
   140002748:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000274d:	0f 87 c3 01 00 00    	ja     140002916 <_gnu_exception_handler+0x22c>
   140002753:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002758:	0f 87 b8 01 00 00    	ja     140002916 <_gnu_exception_handler+0x22c>
   14000275e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002763:	0f 83 4c 01 00 00    	jae    1400028b5 <_gnu_exception_handler+0x1cb>
   140002769:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000276e:	0f 84 3a 01 00 00    	je     1400028ae <_gnu_exception_handler+0x1c4>
   140002774:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002779:	0f 87 97 01 00 00    	ja     140002916 <_gnu_exception_handler+0x22c>
   14000277f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002784:	0f 84 83 01 00 00    	je     14000290d <_gnu_exception_handler+0x223>
   14000278a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000278f:	0f 87 81 01 00 00    	ja     140002916 <_gnu_exception_handler+0x22c>
   140002795:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000279a:	0f 87 76 01 00 00    	ja     140002916 <_gnu_exception_handler+0x22c>
   1400027a0:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400027a5:	0f 83 03 01 00 00    	jae    1400028ae <_gnu_exception_handler+0x1c4>
   1400027ab:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027b0:	0f 84 57 01 00 00    	je     14000290d <_gnu_exception_handler+0x223>
   1400027b6:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027bb:	0f 87 55 01 00 00    	ja     140002916 <_gnu_exception_handler+0x22c>
   1400027c1:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027c6:	0f 84 8e 00 00 00    	je     14000285a <_gnu_exception_handler+0x170>
   1400027cc:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027d1:	0f 87 3f 01 00 00    	ja     140002916 <_gnu_exception_handler+0x22c>
   1400027d7:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027dc:	0f 84 2b 01 00 00    	je     14000290d <_gnu_exception_handler+0x223>
   1400027e2:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027e7:	0f 87 29 01 00 00    	ja     140002916 <_gnu_exception_handler+0x22c>
   1400027ed:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400027f2:	0f 84 15 01 00 00    	je     14000290d <_gnu_exception_handler+0x223>
   1400027f8:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400027fd:	0f 85 13 01 00 00    	jne    140002916 <_gnu_exception_handler+0x22c>
   140002803:	ba 00 00 00 00       	mov    edx,0x0
   140002808:	b9 0b 00 00 00       	mov    ecx,0xb
   14000280d:	e8 f6 0a 00 00       	call   140003308 <signal>
   140002812:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002816:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000281b:	75 1b                	jne    140002838 <_gnu_exception_handler+0x14e>
   14000281d:	ba 01 00 00 00       	mov    edx,0x1
   140002822:	b9 0b 00 00 00       	mov    ecx,0xb
   140002827:	e8 dc 0a 00 00       	call   140003308 <signal>
   14000282c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002833:	e9 e1 00 00 00       	jmp    140002919 <_gnu_exception_handler+0x22f>
   140002838:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000283d:	0f 84 d6 00 00 00    	je     140002919 <_gnu_exception_handler+0x22f>
   140002843:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002847:	b9 0b 00 00 00       	mov    ecx,0xb
   14000284c:	ff d0                	call   rax
   14000284e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002855:	e9 bf 00 00 00       	jmp    140002919 <_gnu_exception_handler+0x22f>
   14000285a:	ba 00 00 00 00       	mov    edx,0x0
   14000285f:	b9 04 00 00 00       	mov    ecx,0x4
   140002864:	e8 9f 0a 00 00       	call   140003308 <signal>
   140002869:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000286d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002872:	75 1b                	jne    14000288f <_gnu_exception_handler+0x1a5>
   140002874:	ba 01 00 00 00       	mov    edx,0x1
   140002879:	b9 04 00 00 00       	mov    ecx,0x4
   14000287e:	e8 85 0a 00 00       	call   140003308 <signal>
   140002883:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000288a:	e9 8d 00 00 00       	jmp    14000291c <_gnu_exception_handler+0x232>
   14000288f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002894:	0f 84 82 00 00 00    	je     14000291c <_gnu_exception_handler+0x232>
   14000289a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000289e:	b9 04 00 00 00       	mov    ecx,0x4
   1400028a3:	ff d0                	call   rax
   1400028a5:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028ac:	eb 6e                	jmp    14000291c <_gnu_exception_handler+0x232>
   1400028ae:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400028b5:	ba 00 00 00 00       	mov    edx,0x0
   1400028ba:	b9 08 00 00 00       	mov    ecx,0x8
   1400028bf:	e8 44 0a 00 00       	call   140003308 <signal>
   1400028c4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028c8:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028cd:	75 23                	jne    1400028f2 <_gnu_exception_handler+0x208>
   1400028cf:	ba 01 00 00 00       	mov    edx,0x1
   1400028d4:	b9 08 00 00 00       	mov    ecx,0x8
   1400028d9:	e8 2a 0a 00 00       	call   140003308 <signal>
   1400028de:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400028e2:	74 05                	je     1400028e9 <_gnu_exception_handler+0x1ff>
   1400028e4:	e8 67 03 00 00       	call   140002c50 <_fpreset>
   1400028e9:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028f0:	eb 2d                	jmp    14000291f <_gnu_exception_handler+0x235>
   1400028f2:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028f7:	74 26                	je     14000291f <_gnu_exception_handler+0x235>
   1400028f9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028fd:	b9 08 00 00 00       	mov    ecx,0x8
   140002902:	ff d0                	call   rax
   140002904:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000290b:	eb 12                	jmp    14000291f <_gnu_exception_handler+0x235>
   14000290d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002914:	eb 0a                	jmp    140002920 <_gnu_exception_handler+0x236>
   140002916:	90                   	nop
   140002917:	eb 07                	jmp    140002920 <_gnu_exception_handler+0x236>
   140002919:	90                   	nop
   14000291a:	eb 04                	jmp    140002920 <_gnu_exception_handler+0x236>
   14000291c:	90                   	nop
   14000291d:	eb 01                	jmp    140002920 <_gnu_exception_handler+0x236>
   14000291f:	90                   	nop
   140002920:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002924:	75 1f                	jne    140002945 <_gnu_exception_handler+0x25b>
   140002926:	48 8b 05 e3 67 00 00 	mov    rax,QWORD PTR [rip+0x67e3]        # 140009110 <__mingw_oldexcpt_handler>
   14000292d:	48 85 c0             	test   rax,rax
   140002930:	74 13                	je     140002945 <_gnu_exception_handler+0x25b>
   140002932:	48 8b 15 d7 67 00 00 	mov    rdx,QWORD PTR [rip+0x67d7]        # 140009110 <__mingw_oldexcpt_handler>
   140002939:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000293d:	48 89 c1             	mov    rcx,rax
   140002940:	ff d2                	call   rdx
   140002942:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002945:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002948:	48 83 c4 30          	add    rsp,0x30
   14000294c:	5d                   	pop    rbp
   14000294d:	c3                   	ret
   14000294e:	90                   	nop
   14000294f:	90                   	nop

0000000140002950 <___w64_mingwthr_add_key_dtor>:
   140002950:	55                   	push   rbp
   140002951:	48 89 e5             	mov    rbp,rsp
   140002954:	48 83 ec 30          	sub    rsp,0x30
   140002958:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000295b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000295f:	8b 05 e3 67 00 00    	mov    eax,DWORD PTR [rip+0x67e3]        # 140009148 <__mingwthr_cs_init>
   140002965:	85 c0                	test   eax,eax
   140002967:	75 07                	jne    140002970 <___w64_mingwthr_add_key_dtor+0x20>
   140002969:	b8 00 00 00 00       	mov    eax,0x0
   14000296e:	eb 7b                	jmp    1400029eb <___w64_mingwthr_add_key_dtor+0x9b>
   140002970:	ba 18 00 00 00       	mov    edx,0x18
   140002975:	b9 01 00 00 00       	mov    ecx,0x1
   14000297a:	e8 41 09 00 00       	call   1400032c0 <calloc>
   14000297f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002983:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002988:	75 07                	jne    140002991 <___w64_mingwthr_add_key_dtor+0x41>
   14000298a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000298f:	eb 5a                	jmp    1400029eb <___w64_mingwthr_add_key_dtor+0x9b>
   140002991:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002995:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002998:	89 10                	mov    DWORD PTR [rax],edx
   14000299a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000299e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400029a2:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   1400029a6:	48 8d 05 73 67 00 00 	lea    rax,[rip+0x6773]        # 140009120 <__mingwthr_cs>
   1400029ad:	48 89 c1             	mov    rcx,rax
   1400029b0:	48 8b 05 e1 77 00 00 	mov    rax,QWORD PTR [rip+0x77e1]        # 14000a198 <__imp_EnterCriticalSection>
   1400029b7:	ff d0                	call   rax
   1400029b9:	48 8b 15 90 67 00 00 	mov    rdx,QWORD PTR [rip+0x6790]        # 140009150 <key_dtor_list>
   1400029c0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029c4:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029c8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029cc:	48 89 05 7d 67 00 00 	mov    QWORD PTR [rip+0x677d],rax        # 140009150 <key_dtor_list>
   1400029d3:	48 8d 05 46 67 00 00 	lea    rax,[rip+0x6746]        # 140009120 <__mingwthr_cs>
   1400029da:	48 89 c1             	mov    rcx,rax
   1400029dd:	48 8b 05 e4 77 00 00 	mov    rax,QWORD PTR [rip+0x77e4]        # 14000a1c8 <__imp_LeaveCriticalSection>
   1400029e4:	ff d0                	call   rax
   1400029e6:	b8 00 00 00 00       	mov    eax,0x0
   1400029eb:	48 83 c4 30          	add    rsp,0x30
   1400029ef:	5d                   	pop    rbp
   1400029f0:	c3                   	ret

00000001400029f1 <___w64_mingwthr_remove_key_dtor>:
   1400029f1:	55                   	push   rbp
   1400029f2:	48 89 e5             	mov    rbp,rsp
   1400029f5:	48 83 ec 30          	sub    rsp,0x30
   1400029f9:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029fc:	8b 05 46 67 00 00    	mov    eax,DWORD PTR [rip+0x6746]        # 140009148 <__mingwthr_cs_init>
   140002a02:	85 c0                	test   eax,eax
   140002a04:	75 0a                	jne    140002a10 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a06:	b8 00 00 00 00       	mov    eax,0x0
   140002a0b:	e9 9c 00 00 00       	jmp    140002aac <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a10:	48 8d 05 09 67 00 00 	lea    rax,[rip+0x6709]        # 140009120 <__mingwthr_cs>
   140002a17:	48 89 c1             	mov    rcx,rax
   140002a1a:	48 8b 05 77 77 00 00 	mov    rax,QWORD PTR [rip+0x7777]        # 14000a198 <__imp_EnterCriticalSection>
   140002a21:	ff d0                	call   rax
   140002a23:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a2a:	00 
   140002a2b:	48 8b 05 1e 67 00 00 	mov    rax,QWORD PTR [rip+0x671e]        # 140009150 <key_dtor_list>
   140002a32:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a36:	eb 55                	jmp    140002a8d <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a38:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a3c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a3e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a41:	75 36                	jne    140002a79 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a43:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a48:	75 11                	jne    140002a5b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a4a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a4e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a52:	48 89 05 f7 66 00 00 	mov    QWORD PTR [rip+0x66f7],rax        # 140009150 <key_dtor_list>
   140002a59:	eb 10                	jmp    140002a6b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a5b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a5f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a63:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a67:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a6b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a6f:	48 89 c1             	mov    rcx,rax
   140002a72:	e8 69 08 00 00       	call   1400032e0 <free>
   140002a77:	eb 1b                	jmp    140002a94 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a79:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a7d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a81:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a85:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a89:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a8d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a92:	75 a4                	jne    140002a38 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a94:	48 8d 05 85 66 00 00 	lea    rax,[rip+0x6685]        # 140009120 <__mingwthr_cs>
   140002a9b:	48 89 c1             	mov    rcx,rax
   140002a9e:	48 8b 05 23 77 00 00 	mov    rax,QWORD PTR [rip+0x7723]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002aa5:	ff d0                	call   rax
   140002aa7:	b8 00 00 00 00       	mov    eax,0x0
   140002aac:	48 83 c4 30          	add    rsp,0x30
   140002ab0:	5d                   	pop    rbp
   140002ab1:	c3                   	ret

0000000140002ab2 <__mingwthr_run_key_dtors>:
   140002ab2:	55                   	push   rbp
   140002ab3:	48 89 e5             	mov    rbp,rsp
   140002ab6:	48 83 ec 30          	sub    rsp,0x30
   140002aba:	8b 05 88 66 00 00    	mov    eax,DWORD PTR [rip+0x6688]        # 140009148 <__mingwthr_cs_init>
   140002ac0:	85 c0                	test   eax,eax
   140002ac2:	0f 84 82 00 00 00    	je     140002b4a <__mingwthr_run_key_dtors+0x98>
   140002ac8:	48 8d 05 51 66 00 00 	lea    rax,[rip+0x6651]        # 140009120 <__mingwthr_cs>
   140002acf:	48 89 c1             	mov    rcx,rax
   140002ad2:	48 8b 05 bf 76 00 00 	mov    rax,QWORD PTR [rip+0x76bf]        # 14000a198 <__imp_EnterCriticalSection>
   140002ad9:	ff d0                	call   rax
   140002adb:	48 8b 05 6e 66 00 00 	mov    rax,QWORD PTR [rip+0x666e]        # 140009150 <key_dtor_list>
   140002ae2:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ae6:	eb 46                	jmp    140002b2e <__mingwthr_run_key_dtors+0x7c>
   140002ae8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002aec:	8b 00                	mov    eax,DWORD PTR [rax]
   140002aee:	89 c1                	mov    ecx,eax
   140002af0:	48 8b 05 f1 76 00 00 	mov    rax,QWORD PTR [rip+0x76f1]        # 14000a1e8 <__imp_TlsGetValue>
   140002af7:	ff d0                	call   rax
   140002af9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002afd:	48 8b 05 a4 76 00 00 	mov    rax,QWORD PTR [rip+0x76a4]        # 14000a1a8 <__imp_GetLastError>
   140002b04:	ff d0                	call   rax
   140002b06:	85 c0                	test   eax,eax
   140002b08:	75 18                	jne    140002b22 <__mingwthr_run_key_dtors+0x70>
   140002b0a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b0f:	74 11                	je     140002b22 <__mingwthr_run_key_dtors+0x70>
   140002b11:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b15:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002b19:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b1d:	48 89 c1             	mov    rcx,rax
   140002b20:	ff d2                	call   rdx
   140002b22:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b26:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b2a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b2e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b33:	75 b3                	jne    140002ae8 <__mingwthr_run_key_dtors+0x36>
   140002b35:	48 8d 05 e4 65 00 00 	lea    rax,[rip+0x65e4]        # 140009120 <__mingwthr_cs>
   140002b3c:	48 89 c1             	mov    rcx,rax
   140002b3f:	48 8b 05 82 76 00 00 	mov    rax,QWORD PTR [rip+0x7682]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002b46:	ff d0                	call   rax
   140002b48:	eb 01                	jmp    140002b4b <__mingwthr_run_key_dtors+0x99>
   140002b4a:	90                   	nop
   140002b4b:	48 83 c4 30          	add    rsp,0x30
   140002b4f:	5d                   	pop    rbp
   140002b50:	c3                   	ret

0000000140002b51 <__mingw_TLScallback>:
   140002b51:	55                   	push   rbp
   140002b52:	48 89 e5             	mov    rbp,rsp
   140002b55:	48 83 ec 30          	sub    rsp,0x30
   140002b59:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b5d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b60:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b64:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b68:	0f 84 cc 00 00 00    	je     140002c3a <__mingw_TLScallback+0xe9>
   140002b6e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b72:	0f 87 ca 00 00 00    	ja     140002c42 <__mingw_TLScallback+0xf1>
   140002b78:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b7c:	0f 84 b1 00 00 00    	je     140002c33 <__mingw_TLScallback+0xe2>
   140002b82:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b86:	0f 87 b6 00 00 00    	ja     140002c42 <__mingw_TLScallback+0xf1>
   140002b8c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b90:	74 33                	je     140002bc5 <__mingw_TLScallback+0x74>
   140002b92:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b96:	0f 85 a6 00 00 00    	jne    140002c42 <__mingw_TLScallback+0xf1>
   140002b9c:	8b 05 a6 65 00 00    	mov    eax,DWORD PTR [rip+0x65a6]        # 140009148 <__mingwthr_cs_init>
   140002ba2:	85 c0                	test   eax,eax
   140002ba4:	75 13                	jne    140002bb9 <__mingw_TLScallback+0x68>
   140002ba6:	48 8d 05 73 65 00 00 	lea    rax,[rip+0x6573]        # 140009120 <__mingwthr_cs>
   140002bad:	48 89 c1             	mov    rcx,rax
   140002bb0:	48 8b 05 09 76 00 00 	mov    rax,QWORD PTR [rip+0x7609]        # 14000a1c0 <__imp_InitializeCriticalSection>
   140002bb7:	ff d0                	call   rax
   140002bb9:	c7 05 85 65 00 00 01 	mov    DWORD PTR [rip+0x6585],0x1        # 140009148 <__mingwthr_cs_init>
   140002bc0:	00 00 00 
   140002bc3:	eb 7d                	jmp    140002c42 <__mingw_TLScallback+0xf1>
   140002bc5:	e8 e8 fe ff ff       	call   140002ab2 <__mingwthr_run_key_dtors>
   140002bca:	8b 05 78 65 00 00    	mov    eax,DWORD PTR [rip+0x6578]        # 140009148 <__mingwthr_cs_init>
   140002bd0:	83 f8 01             	cmp    eax,0x1
   140002bd3:	75 6c                	jne    140002c41 <__mingw_TLScallback+0xf0>
   140002bd5:	48 8b 05 74 65 00 00 	mov    rax,QWORD PTR [rip+0x6574]        # 140009150 <key_dtor_list>
   140002bdc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002be0:	eb 20                	jmp    140002c02 <__mingw_TLScallback+0xb1>
   140002be2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002be6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002bea:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002bee:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bf2:	48 89 c1             	mov    rcx,rax
   140002bf5:	e8 e6 06 00 00       	call   1400032e0 <free>
   140002bfa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bfe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c02:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c07:	75 d9                	jne    140002be2 <__mingw_TLScallback+0x91>
   140002c09:	48 c7 05 3c 65 00 00 	mov    QWORD PTR [rip+0x653c],0x0        # 140009150 <key_dtor_list>
   140002c10:	00 00 00 00 
   140002c14:	c7 05 2a 65 00 00 00 	mov    DWORD PTR [rip+0x652a],0x0        # 140009148 <__mingwthr_cs_init>
   140002c1b:	00 00 00 
   140002c1e:	48 8d 05 fb 64 00 00 	lea    rax,[rip+0x64fb]        # 140009120 <__mingwthr_cs>
   140002c25:	48 89 c1             	mov    rcx,rax
   140002c28:	48 8b 05 61 75 00 00 	mov    rax,QWORD PTR [rip+0x7561]        # 14000a190 <__IAT_start__>
   140002c2f:	ff d0                	call   rax
   140002c31:	eb 0e                	jmp    140002c41 <__mingw_TLScallback+0xf0>
   140002c33:	e8 18 00 00 00       	call   140002c50 <_fpreset>
   140002c38:	eb 08                	jmp    140002c42 <__mingw_TLScallback+0xf1>
   140002c3a:	e8 73 fe ff ff       	call   140002ab2 <__mingwthr_run_key_dtors>
   140002c3f:	eb 01                	jmp    140002c42 <__mingw_TLScallback+0xf1>
   140002c41:	90                   	nop
   140002c42:	b8 01 00 00 00       	mov    eax,0x1
   140002c47:	48 83 c4 30          	add    rsp,0x30
   140002c4b:	5d                   	pop    rbp
   140002c4c:	c3                   	ret
   140002c4d:	90                   	nop
   140002c4e:	90                   	nop
   140002c4f:	90                   	nop

0000000140002c50 <_fpreset>:
   140002c50:	55                   	push   rbp
   140002c51:	48 89 e5             	mov    rbp,rsp
   140002c54:	db e3                	fninit
   140002c56:	90                   	nop
   140002c57:	5d                   	pop    rbp
   140002c58:	c3                   	ret
   140002c59:	90                   	nop
   140002c5a:	90                   	nop
   140002c5b:	90                   	nop
   140002c5c:	90                   	nop
   140002c5d:	90                   	nop
   140002c5e:	90                   	nop
   140002c5f:	90                   	nop

0000000140002c60 <_ValidateImageBase>:
   140002c60:	55                   	push   rbp
   140002c61:	48 89 e5             	mov    rbp,rsp
   140002c64:	48 83 ec 20          	sub    rsp,0x20
   140002c68:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c6c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c70:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c74:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c78:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c7b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c7f:	74 07                	je     140002c88 <_ValidateImageBase+0x28>
   140002c81:	b8 00 00 00 00       	mov    eax,0x0
   140002c86:	eb 4e                	jmp    140002cd6 <_ValidateImageBase+0x76>
   140002c88:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c8c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c8f:	48 63 d0             	movsxd rdx,eax
   140002c92:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c96:	48 01 d0             	add    rax,rdx
   140002c99:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c9d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ca1:	8b 00                	mov    eax,DWORD PTR [rax]
   140002ca3:	3d 50 45 00 00       	cmp    eax,0x4550
   140002ca8:	74 07                	je     140002cb1 <_ValidateImageBase+0x51>
   140002caa:	b8 00 00 00 00       	mov    eax,0x0
   140002caf:	eb 25                	jmp    140002cd6 <_ValidateImageBase+0x76>
   140002cb1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002cb5:	48 83 c0 18          	add    rax,0x18
   140002cb9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002cbd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cc1:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002cc4:	66 3d 0b 02          	cmp    ax,0x20b
   140002cc8:	74 07                	je     140002cd1 <_ValidateImageBase+0x71>
   140002cca:	b8 00 00 00 00       	mov    eax,0x0
   140002ccf:	eb 05                	jmp    140002cd6 <_ValidateImageBase+0x76>
   140002cd1:	b8 01 00 00 00       	mov    eax,0x1
   140002cd6:	48 83 c4 20          	add    rsp,0x20
   140002cda:	5d                   	pop    rbp
   140002cdb:	c3                   	ret

0000000140002cdc <_FindPESection>:
   140002cdc:	55                   	push   rbp
   140002cdd:	48 89 e5             	mov    rbp,rsp
   140002ce0:	48 83 ec 20          	sub    rsp,0x20
   140002ce4:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ce8:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002cec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cf0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002cf3:	48 63 d0             	movsxd rdx,eax
   140002cf6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cfa:	48 01 d0             	add    rax,rdx
   140002cfd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d01:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d08:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d0c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d10:	0f b7 d0             	movzx  edx,ax
   140002d13:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d17:	48 01 d0             	add    rax,rdx
   140002d1a:	48 83 c0 18          	add    rax,0x18
   140002d1e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d22:	eb 36                	jmp    140002d5a <_FindPESection+0x7e>
   140002d24:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d28:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d2b:	89 c0                	mov    eax,eax
   140002d2d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d31:	72 1e                	jb     140002d51 <_FindPESection+0x75>
   140002d33:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d37:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d3a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d3e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d41:	01 d0                	add    eax,edx
   140002d43:	89 c0                	mov    eax,eax
   140002d45:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d49:	73 06                	jae    140002d51 <_FindPESection+0x75>
   140002d4b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d4f:	eb 1e                	jmp    140002d6f <_FindPESection+0x93>
   140002d51:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d55:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d5a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d5e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d62:	0f b7 c0             	movzx  eax,ax
   140002d65:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d68:	72 ba                	jb     140002d24 <_FindPESection+0x48>
   140002d6a:	b8 00 00 00 00       	mov    eax,0x0
   140002d6f:	48 83 c4 20          	add    rsp,0x20
   140002d73:	5d                   	pop    rbp
   140002d74:	c3                   	ret

0000000140002d75 <_FindPESectionByName>:
   140002d75:	55                   	push   rbp
   140002d76:	48 89 e5             	mov    rbp,rsp
   140002d79:	48 83 ec 40          	sub    rsp,0x40
   140002d7d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d81:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d85:	48 89 c1             	mov    rcx,rax
   140002d88:	e8 83 05 00 00       	call   140003310 <strlen>
   140002d8d:	48 83 f8 08          	cmp    rax,0x8
   140002d91:	76 0a                	jbe    140002d9d <_FindPESectionByName+0x28>
   140002d93:	b8 00 00 00 00       	mov    eax,0x0
   140002d98:	e9 98 00 00 00       	jmp    140002e35 <_FindPESectionByName+0xc0>
   140002d9d:	48 8b 05 bc 25 00 00 	mov    rax,QWORD PTR [rip+0x25bc]        # 140005360 <.refptr.__ImageBase>
   140002da4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002da8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dac:	48 89 c1             	mov    rcx,rax
   140002daf:	e8 ac fe ff ff       	call   140002c60 <_ValidateImageBase>
   140002db4:	85 c0                	test   eax,eax
   140002db6:	75 07                	jne    140002dbf <_FindPESectionByName+0x4a>
   140002db8:	b8 00 00 00 00       	mov    eax,0x0
   140002dbd:	eb 76                	jmp    140002e35 <_FindPESectionByName+0xc0>
   140002dbf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dc3:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002dc6:	48 63 d0             	movsxd rdx,eax
   140002dc9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dcd:	48 01 d0             	add    rax,rdx
   140002dd0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002dd4:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ddb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ddf:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002de3:	0f b7 d0             	movzx  edx,ax
   140002de6:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dea:	48 01 d0             	add    rax,rdx
   140002ded:	48 83 c0 18          	add    rax,0x18
   140002df1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002df5:	eb 29                	jmp    140002e20 <_FindPESectionByName+0xab>
   140002df7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dfb:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002dff:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e05:	48 89 c1             	mov    rcx,rax
   140002e08:	e8 0b 05 00 00       	call   140003318 <strncmp>
   140002e0d:	85 c0                	test   eax,eax
   140002e0f:	75 06                	jne    140002e17 <_FindPESectionByName+0xa2>
   140002e11:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e15:	eb 1e                	jmp    140002e35 <_FindPESectionByName+0xc0>
   140002e17:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e1b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e20:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e24:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e28:	0f b7 c0             	movzx  eax,ax
   140002e2b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e2e:	72 c7                	jb     140002df7 <_FindPESectionByName+0x82>
   140002e30:	b8 00 00 00 00       	mov    eax,0x0
   140002e35:	48 83 c4 40          	add    rsp,0x40
   140002e39:	5d                   	pop    rbp
   140002e3a:	c3                   	ret

0000000140002e3b <__mingw_GetSectionForAddress>:
   140002e3b:	55                   	push   rbp
   140002e3c:	48 89 e5             	mov    rbp,rsp
   140002e3f:	48 83 ec 30          	sub    rsp,0x30
   140002e43:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e47:	48 8b 05 12 25 00 00 	mov    rax,QWORD PTR [rip+0x2512]        # 140005360 <.refptr.__ImageBase>
   140002e4e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e56:	48 89 c1             	mov    rcx,rax
   140002e59:	e8 02 fe ff ff       	call   140002c60 <_ValidateImageBase>
   140002e5e:	85 c0                	test   eax,eax
   140002e60:	75 07                	jne    140002e69 <__mingw_GetSectionForAddress+0x2e>
   140002e62:	b8 00 00 00 00       	mov    eax,0x0
   140002e67:	eb 1c                	jmp    140002e85 <__mingw_GetSectionForAddress+0x4a>
   140002e69:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e6d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e71:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e75:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e79:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e7d:	48 89 c1             	mov    rcx,rax
   140002e80:	e8 57 fe ff ff       	call   140002cdc <_FindPESection>
   140002e85:	48 83 c4 30          	add    rsp,0x30
   140002e89:	5d                   	pop    rbp
   140002e8a:	c3                   	ret

0000000140002e8b <__mingw_GetSectionCount>:
   140002e8b:	55                   	push   rbp
   140002e8c:	48 89 e5             	mov    rbp,rsp
   140002e8f:	48 83 ec 30          	sub    rsp,0x30
   140002e93:	48 8b 05 c6 24 00 00 	mov    rax,QWORD PTR [rip+0x24c6]        # 140005360 <.refptr.__ImageBase>
   140002e9a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e9e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ea2:	48 89 c1             	mov    rcx,rax
   140002ea5:	e8 b6 fd ff ff       	call   140002c60 <_ValidateImageBase>
   140002eaa:	85 c0                	test   eax,eax
   140002eac:	75 07                	jne    140002eb5 <__mingw_GetSectionCount+0x2a>
   140002eae:	b8 00 00 00 00       	mov    eax,0x0
   140002eb3:	eb 20                	jmp    140002ed5 <__mingw_GetSectionCount+0x4a>
   140002eb5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002eb9:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ebc:	48 63 d0             	movsxd rdx,eax
   140002ebf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ec3:	48 01 d0             	add    rax,rdx
   140002ec6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002eca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ece:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ed2:	0f b7 c0             	movzx  eax,ax
   140002ed5:	48 83 c4 30          	add    rsp,0x30
   140002ed9:	5d                   	pop    rbp
   140002eda:	c3                   	ret

0000000140002edb <_FindPESectionExec>:
   140002edb:	55                   	push   rbp
   140002edc:	48 89 e5             	mov    rbp,rsp
   140002edf:	48 83 ec 40          	sub    rsp,0x40
   140002ee3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ee7:	48 8b 05 72 24 00 00 	mov    rax,QWORD PTR [rip+0x2472]        # 140005360 <.refptr.__ImageBase>
   140002eee:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ef2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ef6:	48 89 c1             	mov    rcx,rax
   140002ef9:	e8 62 fd ff ff       	call   140002c60 <_ValidateImageBase>
   140002efe:	85 c0                	test   eax,eax
   140002f00:	75 07                	jne    140002f09 <_FindPESectionExec+0x2e>
   140002f02:	b8 00 00 00 00       	mov    eax,0x0
   140002f07:	eb 78                	jmp    140002f81 <_FindPESectionExec+0xa6>
   140002f09:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f0d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f10:	48 63 d0             	movsxd rdx,eax
   140002f13:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f17:	48 01 d0             	add    rax,rdx
   140002f1a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f1e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f25:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f29:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f2d:	0f b7 d0             	movzx  edx,ax
   140002f30:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f34:	48 01 d0             	add    rax,rdx
   140002f37:	48 83 c0 18          	add    rax,0x18
   140002f3b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f3f:	eb 2b                	jmp    140002f6c <_FindPESectionExec+0x91>
   140002f41:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f45:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f48:	25 00 00 00 20       	and    eax,0x20000000
   140002f4d:	85 c0                	test   eax,eax
   140002f4f:	74 12                	je     140002f63 <_FindPESectionExec+0x88>
   140002f51:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f56:	75 06                	jne    140002f5e <_FindPESectionExec+0x83>
   140002f58:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f5c:	eb 23                	jmp    140002f81 <_FindPESectionExec+0xa6>
   140002f5e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f63:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f67:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f6c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f70:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f74:	0f b7 c0             	movzx  eax,ax
   140002f77:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f7a:	72 c5                	jb     140002f41 <_FindPESectionExec+0x66>
   140002f7c:	b8 00 00 00 00       	mov    eax,0x0
   140002f81:	48 83 c4 40          	add    rsp,0x40
   140002f85:	5d                   	pop    rbp
   140002f86:	c3                   	ret

0000000140002f87 <_GetPEImageBase>:
   140002f87:	55                   	push   rbp
   140002f88:	48 89 e5             	mov    rbp,rsp
   140002f8b:	48 83 ec 30          	sub    rsp,0x30
   140002f8f:	48 8b 05 ca 23 00 00 	mov    rax,QWORD PTR [rip+0x23ca]        # 140005360 <.refptr.__ImageBase>
   140002f96:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f9a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f9e:	48 89 c1             	mov    rcx,rax
   140002fa1:	e8 ba fc ff ff       	call   140002c60 <_ValidateImageBase>
   140002fa6:	85 c0                	test   eax,eax
   140002fa8:	75 07                	jne    140002fb1 <_GetPEImageBase+0x2a>
   140002faa:	b8 00 00 00 00       	mov    eax,0x0
   140002faf:	eb 04                	jmp    140002fb5 <_GetPEImageBase+0x2e>
   140002fb1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fb5:	48 83 c4 30          	add    rsp,0x30
   140002fb9:	5d                   	pop    rbp
   140002fba:	c3                   	ret

0000000140002fbb <_IsNonwritableInCurrentImage>:
   140002fbb:	55                   	push   rbp
   140002fbc:	48 89 e5             	mov    rbp,rsp
   140002fbf:	48 83 ec 40          	sub    rsp,0x40
   140002fc3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002fc7:	48 8b 05 92 23 00 00 	mov    rax,QWORD PTR [rip+0x2392]        # 140005360 <.refptr.__ImageBase>
   140002fce:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fd2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fd6:	48 89 c1             	mov    rcx,rax
   140002fd9:	e8 82 fc ff ff       	call   140002c60 <_ValidateImageBase>
   140002fde:	85 c0                	test   eax,eax
   140002fe0:	75 07                	jne    140002fe9 <_IsNonwritableInCurrentImage+0x2e>
   140002fe2:	b8 00 00 00 00       	mov    eax,0x0
   140002fe7:	eb 3d                	jmp    140003026 <_IsNonwritableInCurrentImage+0x6b>
   140002fe9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002fed:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002ff1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ff5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002ff9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ffd:	48 89 c1             	mov    rcx,rax
   140003000:	e8 d7 fc ff ff       	call   140002cdc <_FindPESection>
   140003005:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003009:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000300e:	75 07                	jne    140003017 <_IsNonwritableInCurrentImage+0x5c>
   140003010:	b8 00 00 00 00       	mov    eax,0x0
   140003015:	eb 0f                	jmp    140003026 <_IsNonwritableInCurrentImage+0x6b>
   140003017:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000301b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000301e:	f7 d0                	not    eax
   140003020:	c1 e8 1f             	shr    eax,0x1f
   140003023:	0f b6 c0             	movzx  eax,al
   140003026:	48 83 c4 40          	add    rsp,0x40
   14000302a:	5d                   	pop    rbp
   14000302b:	c3                   	ret

000000014000302c <__mingw_enum_import_library_names>:
   14000302c:	55                   	push   rbp
   14000302d:	48 89 e5             	mov    rbp,rsp
   140003030:	48 83 ec 50          	sub    rsp,0x50
   140003034:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003037:	48 8b 05 22 23 00 00 	mov    rax,QWORD PTR [rip+0x2322]        # 140005360 <.refptr.__ImageBase>
   14000303e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003042:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003046:	48 89 c1             	mov    rcx,rax
   140003049:	e8 12 fc ff ff       	call   140002c60 <_ValidateImageBase>
   14000304e:	85 c0                	test   eax,eax
   140003050:	75 0a                	jne    14000305c <__mingw_enum_import_library_names+0x30>
   140003052:	b8 00 00 00 00       	mov    eax,0x0
   140003057:	e9 ab 00 00 00       	jmp    140003107 <__mingw_enum_import_library_names+0xdb>
   14000305c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003060:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003063:	48 63 d0             	movsxd rdx,eax
   140003066:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000306a:	48 01 d0             	add    rax,rdx
   14000306d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003071:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003075:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000307b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000307e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003082:	75 07                	jne    14000308b <__mingw_enum_import_library_names+0x5f>
   140003084:	b8 00 00 00 00       	mov    eax,0x0
   140003089:	eb 7c                	jmp    140003107 <__mingw_enum_import_library_names+0xdb>
   14000308b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000308e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003092:	48 89 c1             	mov    rcx,rax
   140003095:	e8 42 fc ff ff       	call   140002cdc <_FindPESection>
   14000309a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000309e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   1400030a3:	75 07                	jne    1400030ac <__mingw_enum_import_library_names+0x80>
   1400030a5:	b8 00 00 00 00       	mov    eax,0x0
   1400030aa:	eb 5b                	jmp    140003107 <__mingw_enum_import_library_names+0xdb>
   1400030ac:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030af:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030b3:	48 01 d0             	add    rax,rdx
   1400030b6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030ba:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400030bf:	75 07                	jne    1400030c8 <__mingw_enum_import_library_names+0x9c>
   1400030c1:	b8 00 00 00 00       	mov    eax,0x0
   1400030c6:	eb 3f                	jmp    140003107 <__mingw_enum_import_library_names+0xdb>
   1400030c8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030cc:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400030cf:	85 c0                	test   eax,eax
   1400030d1:	75 0b                	jne    1400030de <__mingw_enum_import_library_names+0xb2>
   1400030d3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030d7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030da:	85 c0                	test   eax,eax
   1400030dc:	74 23                	je     140003101 <__mingw_enum_import_library_names+0xd5>
   1400030de:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400030e2:	7f 12                	jg     1400030f6 <__mingw_enum_import_library_names+0xca>
   1400030e4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030e8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030eb:	89 c2                	mov    edx,eax
   1400030ed:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030f1:	48 01 d0             	add    rax,rdx
   1400030f4:	eb 11                	jmp    140003107 <__mingw_enum_import_library_names+0xdb>
   1400030f6:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   1400030fa:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   1400030ff:	eb c7                	jmp    1400030c8 <__mingw_enum_import_library_names+0x9c>
   140003101:	90                   	nop
   140003102:	b8 00 00 00 00       	mov    eax,0x0
   140003107:	48 83 c4 50          	add    rsp,0x50
   14000310b:	5d                   	pop    rbp
   14000310c:	c3                   	ret
   14000310d:	90                   	nop
   14000310e:	90                   	nop
   14000310f:	90                   	nop

0000000140003110 <___chkstk_ms>:
   140003110:	51                   	push   rcx
   140003111:	50                   	push   rax
   140003112:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003118:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000311d:	72 19                	jb     140003138 <___chkstk_ms+0x28>
   14000311f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003126:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000312a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003130:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003136:	77 e7                	ja     14000311f <___chkstk_ms+0xf>
   140003138:	48 29 c1             	sub    rcx,rax
   14000313b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000313f:	58                   	pop    rax
   140003140:	59                   	pop    rcx
   140003141:	c3                   	ret
   140003142:	90                   	nop
   140003143:	90                   	nop
   140003144:	90                   	nop
   140003145:	90                   	nop
   140003146:	90                   	nop
   140003147:	90                   	nop
   140003148:	90                   	nop
   140003149:	90                   	nop
   14000314a:	90                   	nop
   14000314b:	90                   	nop
   14000314c:	90                   	nop
   14000314d:	90                   	nop
   14000314e:	90                   	nop
   14000314f:	90                   	nop

0000000140003150 <_initterm_e>:
   140003150:	55                   	push   rbp
   140003151:	48 89 e5             	mov    rbp,rsp
   140003154:	48 83 ec 30          	sub    rsp,0x30
   140003158:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000315c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003160:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003164:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003168:	eb 29                	jmp    140003193 <_initterm_e+0x43>
   14000316a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000316e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140003171:	48 85 c0             	test   rax,rax
   140003174:	74 17                	je     14000318d <_initterm_e+0x3d>
   140003176:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000317a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000317d:	ff d0                	call   rax
   14000317f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003182:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003186:	74 06                	je     14000318e <_initterm_e+0x3e>
   140003188:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000318b:	eb 15                	jmp    1400031a2 <_initterm_e+0x52>
   14000318d:	90                   	nop
   14000318e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140003193:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003197:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   14000319b:	72 cd                	jb     14000316a <_initterm_e+0x1a>
   14000319d:	b8 00 00 00 00       	mov    eax,0x0
   1400031a2:	48 83 c4 30          	add    rsp,0x30
   1400031a6:	5d                   	pop    rbp
   1400031a7:	c3                   	ret
   1400031a8:	90                   	nop
   1400031a9:	90                   	nop
   1400031aa:	90                   	nop
   1400031ab:	90                   	nop
   1400031ac:	90                   	nop
   1400031ad:	90                   	nop
   1400031ae:	90                   	nop
   1400031af:	90                   	nop

00000001400031b0 <__p__fmode>:
   1400031b0:	55                   	push   rbp
   1400031b1:	48 89 e5             	mov    rbp,rsp
   1400031b4:	48 8b 05 15 22 00 00 	mov    rax,QWORD PTR [rip+0x2215]        # 1400053d0 <.refptr.__imp__fmode>
   1400031bb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031be:	5d                   	pop    rbp
   1400031bf:	c3                   	ret

00000001400031c0 <__p__commode>:
   1400031c0:	55                   	push   rbp
   1400031c1:	48 89 e5             	mov    rbp,rsp
   1400031c4:	48 8b 05 f5 21 00 00 	mov    rax,QWORD PTR [rip+0x21f5]        # 1400053c0 <.refptr.__imp__commode>
   1400031cb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031ce:	5d                   	pop    rbp
   1400031cf:	c3                   	ret

00000001400031d0 <__p___initenv>:
   1400031d0:	55                   	push   rbp
   1400031d1:	48 89 e5             	mov    rbp,rsp
   1400031d4:	48 8b 05 d5 21 00 00 	mov    rax,QWORD PTR [rip+0x21d5]        # 1400053b0 <.refptr.__imp___initenv>
   1400031db:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400031de:	5d                   	pop    rbp
   1400031df:	c3                   	ret

00000001400031e0 <_set_invalid_parameter_handler>:
   1400031e0:	55                   	push   rbp
   1400031e1:	48 89 e5             	mov    rbp,rsp
   1400031e4:	48 83 ec 10          	sub    rsp,0x10
   1400031e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400031ec:	48 8d 05 9d 5f 00 00 	lea    rax,[rip+0x5f9d]        # 140009190 <handler>
   1400031f3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031f7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400031fb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400031ff:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003203:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003207:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000320a:	48 89 d0             	mov    rax,rdx
   14000320d:	48 83 c4 10          	add    rsp,0x10
   140003211:	5d                   	pop    rbp
   140003212:	c3                   	ret

0000000140003213 <_get_invalid_parameter_handler>:
   140003213:	55                   	push   rbp
   140003214:	48 89 e5             	mov    rbp,rsp
   140003217:	48 8b 05 72 5f 00 00 	mov    rax,QWORD PTR [rip+0x5f72]        # 140009190 <handler>
   14000321e:	5d                   	pop    rbp
   14000321f:	c3                   	ret

0000000140003220 <_configthreadlocale>:
   140003220:	55                   	push   rbp
   140003221:	48 89 e5             	mov    rbp,rsp
   140003224:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003227:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000322b:	75 07                	jne    140003234 <_configthreadlocale+0x14>
   14000322d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140003232:	eb 05                	jmp    140003239 <_configthreadlocale+0x19>
   140003234:	b8 02 00 00 00       	mov    eax,0x2
   140003239:	5d                   	pop    rbp
   14000323a:	c3                   	ret
   14000323b:	90                   	nop
   14000323c:	90                   	nop
   14000323d:	90                   	nop
   14000323e:	90                   	nop
   14000323f:	90                   	nop

0000000140003240 <__acrt_iob_func>:
   140003240:	55                   	push   rbp
   140003241:	48 89 e5             	mov    rbp,rsp
   140003244:	48 83 ec 20          	sub    rsp,0x20
   140003248:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000324b:	e8 30 00 00 00       	call   140003280 <__iob_func>
   140003250:	48 89 c1             	mov    rcx,rax
   140003253:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140003256:	48 89 d0             	mov    rax,rdx
   140003259:	48 01 c0             	add    rax,rax
   14000325c:	48 01 d0             	add    rax,rdx
   14000325f:	48 c1 e0 04          	shl    rax,0x4
   140003263:	48 01 c8             	add    rax,rcx
   140003266:	48 83 c4 20          	add    rsp,0x20
   14000326a:	5d                   	pop    rbp
   14000326b:	c3                   	ret
   14000326c:	90                   	nop
   14000326d:	90                   	nop
   14000326e:	90                   	nop
   14000326f:	90                   	nop

0000000140003270 <__C_specific_handler>:
   140003270:	ff 25 92 6f 00 00    	jmp    QWORD PTR [rip+0x6f92]        # 14000a208 <__imp___C_specific_handler>
   140003276:	90                   	nop
   140003277:	90                   	nop

0000000140003278 <__getmainargs>:
   140003278:	ff 25 92 6f 00 00    	jmp    QWORD PTR [rip+0x6f92]        # 14000a210 <__imp___getmainargs>
   14000327e:	90                   	nop
   14000327f:	90                   	nop

0000000140003280 <__iob_func>:
   140003280:	ff 25 9a 6f 00 00    	jmp    QWORD PTR [rip+0x6f9a]        # 14000a220 <__imp___iob_func>
   140003286:	90                   	nop
   140003287:	90                   	nop

0000000140003288 <__set_app_type>:
   140003288:	ff 25 9a 6f 00 00    	jmp    QWORD PTR [rip+0x6f9a]        # 14000a228 <__imp___set_app_type>
   14000328e:	90                   	nop
   14000328f:	90                   	nop

0000000140003290 <__setusermatherr>:
   140003290:	ff 25 9a 6f 00 00    	jmp    QWORD PTR [rip+0x6f9a]        # 14000a230 <__imp___setusermatherr>
   140003296:	90                   	nop
   140003297:	90                   	nop

0000000140003298 <_amsg_exit>:
   140003298:	ff 25 9a 6f 00 00    	jmp    QWORD PTR [rip+0x6f9a]        # 14000a238 <__imp__amsg_exit>
   14000329e:	90                   	nop
   14000329f:	90                   	nop

00000001400032a0 <_cexit>:
   1400032a0:	ff 25 9a 6f 00 00    	jmp    QWORD PTR [rip+0x6f9a]        # 14000a240 <__imp__cexit>
   1400032a6:	90                   	nop
   1400032a7:	90                   	nop

00000001400032a8 <_initterm>:
   1400032a8:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a258 <__imp__initterm>
   1400032ae:	90                   	nop
   1400032af:	90                   	nop

00000001400032b0 <_crt_atexit>:
   1400032b0:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a260 <__imp__crt_atexit>
   1400032b6:	90                   	nop
   1400032b7:	90                   	nop

00000001400032b8 <abort>:
   1400032b8:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a268 <__imp_abort>
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <calloc>:
   1400032c0:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a270 <__imp_calloc>
   1400032c6:	90                   	nop
   1400032c7:	90                   	nop

00000001400032c8 <exit>:
   1400032c8:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a278 <__imp_exit>
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <fflush>:
   1400032d0:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a280 <__imp_fflush>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop

00000001400032d8 <fprintf>:
   1400032d8:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a288 <__imp_fprintf>
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <free>:
   1400032e0:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a290 <__imp_free>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <malloc>:
   1400032e8:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a298 <__imp_malloc>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <memcpy>:
   1400032f0:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a2a0 <__imp_memcpy>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <memset>:
   1400032f8:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a2a8 <__imp_memset>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <setvbuf>:
   140003300:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a2b0 <__imp_setvbuf>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <signal>:
   140003308:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a2b8 <__imp_signal>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <strlen>:
   140003310:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a2c0 <__imp_strlen>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <strncmp>:
   140003318:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a2c8 <__imp_strncmp>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <vfprintf>:
   140003320:	ff 25 aa 6f 00 00    	jmp    QWORD PTR [rip+0x6faa]        # 14000a2d0 <__imp_vfprintf>
   140003326:	90                   	nop
   140003327:	90                   	nop
   140003328:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000332f:	00 

0000000140003330 <VirtualQuery>:
   140003330:	ff 25 c2 6e 00 00    	jmp    QWORD PTR [rip+0x6ec2]        # 14000a1f8 <__imp_VirtualQuery>
   140003336:	90                   	nop
   140003337:	90                   	nop

0000000140003338 <VirtualProtect>:
   140003338:	ff 25 b2 6e 00 00    	jmp    QWORD PTR [rip+0x6eb2]        # 14000a1f0 <__imp_VirtualProtect>
   14000333e:	90                   	nop
   14000333f:	90                   	nop

0000000140003340 <TlsGetValue>:
   140003340:	ff 25 a2 6e 00 00    	jmp    QWORD PTR [rip+0x6ea2]        # 14000a1e8 <__imp_TlsGetValue>
   140003346:	90                   	nop
   140003347:	90                   	nop

0000000140003348 <Sleep>:
   140003348:	ff 25 92 6e 00 00    	jmp    QWORD PTR [rip+0x6e92]        # 14000a1e0 <__imp_Sleep>
   14000334e:	90                   	nop
   14000334f:	90                   	nop

0000000140003350 <SetUnhandledExceptionFilter>:
   140003350:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   140003356:	90                   	nop
   140003357:	90                   	nop

0000000140003358 <LoadLibraryA>:
   140003358:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a1d0 <__imp_LoadLibraryA>
   14000335e:	90                   	nop
   14000335f:	90                   	nop

0000000140003360 <LeaveCriticalSection>:
   140003360:	ff 25 62 6e 00 00    	jmp    QWORD PTR [rip+0x6e62]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140003366:	90                   	nop
   140003367:	90                   	nop

0000000140003368 <InitializeCriticalSection>:
   140003368:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 14000a1c0 <__imp_InitializeCriticalSection>
   14000336e:	90                   	nop
   14000336f:	90                   	nop

0000000140003370 <GetProcAddress>:
   140003370:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 14000a1b8 <__imp_GetProcAddress>
   140003376:	90                   	nop
   140003377:	90                   	nop

0000000140003378 <GetModuleHandleA>:
   140003378:	ff 25 32 6e 00 00    	jmp    QWORD PTR [rip+0x6e32]        # 14000a1b0 <__imp_GetModuleHandleA>
   14000337e:	90                   	nop
   14000337f:	90                   	nop

0000000140003380 <GetLastError>:
   140003380:	ff 25 22 6e 00 00    	jmp    QWORD PTR [rip+0x6e22]        # 14000a1a8 <__imp_GetLastError>
   140003386:	90                   	nop
   140003387:	90                   	nop

0000000140003388 <FreeLibrary>:
   140003388:	ff 25 12 6e 00 00    	jmp    QWORD PTR [rip+0x6e12]        # 14000a1a0 <__imp_FreeLibrary>
   14000338e:	90                   	nop
   14000338f:	90                   	nop

0000000140003390 <EnterCriticalSection>:
   140003390:	ff 25 02 6e 00 00    	jmp    QWORD PTR [rip+0x6e02]        # 14000a198 <__imp_EnterCriticalSection>
   140003396:	90                   	nop
   140003397:	90                   	nop

0000000140003398 <DeleteCriticalSection>:
   140003398:	ff 25 f2 6d 00 00    	jmp    QWORD PTR [rip+0x6df2]        # 14000a190 <__IAT_start__>
   14000339e:	90                   	nop
   14000339f:	90                   	nop

00000001400033a0 <register_frame_ctor>:
   1400033a0:	e9 cb e2 ff ff       	jmp    140001670 <__gcc_register_frame>
   1400033a5:	90                   	nop
   1400033a6:	90                   	nop
   1400033a7:	90                   	nop
   1400033a8:	90                   	nop
   1400033a9:	90                   	nop
   1400033aa:	90                   	nop
   1400033ab:	90                   	nop
   1400033ac:	90                   	nop
   1400033ad:	90                   	nop
   1400033ae:	90                   	nop
   1400033af:	90                   	nop
