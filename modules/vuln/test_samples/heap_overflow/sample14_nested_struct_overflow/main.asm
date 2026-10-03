
C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\test_samples\heap_overflow\sample14_nested_struct_overflow\main.exe:     file format pei-x86-64


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
   140001024:	e8 37 22 00 00       	call   140003260 <fflush>
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
   14000113b:	e8 e8 20 00 00       	call   140003228 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 68 20 00 00       	call   1400031d0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 0f 21 00 00       	call   140003290 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 af 20 00 00       	call   140003248 <abort>
   140001199:	e8 32 11 00 00       	call   1400022d0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 29 90 00 00 	mov    rax,QWORD PTR [rip+0x9029]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 a6 1f 00 00       	call   140003170 <_set_invalid_parameter_handler>
   1400011ca:	e8 11 1a 00 00       	call   140002be0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 27 20 00 00       	call   140003218 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 1b 20 00 00       	call   140003218 <__set_app_type>
   1400011fd:	e8 3e 1f 00 00       	call   140003140 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 3e 1f 00 00       	call   140003150 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 8e 06 00 00       	call   1400018b0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 f3 1f 00 00       	call   140003228 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 98 11 00 00       	call   1400023ea <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 46 1f 00 00       	call   1400031b0 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 60 1e 00 00       	call   1400030e0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 9a 1f 00 00       	call   140003228 <_amsg_exit>
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
   1400012cb:	e8 38 1f 00 00       	call   140003208 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 45 1f 00 00       	call   140003228 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 1e 1f 00 00       	call   140003228 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 18 1f 00 00       	call   140003238 <_initterm>
   140001320:	e8 62 05 00 00       	call   140001887 <__main>
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
   14000138d:	e8 ce 1d 00 00       	call   140003160 <__p___initenv>
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
   1400013cc:	e8 87 1e 00 00       	call   140003258 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 50 1e 00 00       	call   140003230 <_cexit>
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
   140001511:	e8 62 1d 00 00       	call   140003278 <malloc>
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
   14000155c:	e8 3f 1d 00 00       	call   1400032a0 <strlen>
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
   140001585:	e8 ee 1c 00 00       	call   140003278 <malloc>
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
   1400015e8:	e8 93 1c 00 00       	call   140003280 <memcpy>
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
   140001642:	e8 f9 1b 00 00       	call   140003240 <_crt_atexit>
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
   140001768:	e8 1a 01 00 00       	call   140001887 <__main>
   14000176d:	b9 60 01 00 00       	mov    ecx,0x160
   140001772:	e8 01 1b 00 00       	call   140003278 <malloc>
   140001777:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000177b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140001780:	75 07                	jne    140001789 <main+0x29>
   140001782:	b8 01 00 00 00       	mov    eax,0x1
   140001787:	eb 32                	jmp    1400017bb <main+0x5b>
   140001789:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000178d:	48 83 c0 60          	add    rax,0x60
   140001791:	48 05 00 01 00 00    	add    rax,0x100
   140001797:	41 b8 10 00 00 00    	mov    r8d,0x10
   14000179d:	ba 00 00 00 00       	mov    edx,0x0
   1400017a2:	48 89 c1             	mov    rcx,rax
   1400017a5:	e8 de 1a 00 00       	call   140003288 <memset>
   1400017aa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017ae:	48 89 c1             	mov    rcx,rax
   1400017b1:	e8 ba 1a 00 00       	call   140003270 <free>
   1400017b6:	b8 00 00 00 00       	mov    eax,0x0
   1400017bb:	48 83 c4 30          	add    rsp,0x30
   1400017bf:	5d                   	pop    rbp
   1400017c0:	c3                   	ret
   1400017c1:	90                   	nop
   1400017c2:	90                   	nop
   1400017c3:	90                   	nop
   1400017c4:	90                   	nop
   1400017c5:	90                   	nop
   1400017c6:	90                   	nop
   1400017c7:	90                   	nop
   1400017c8:	90                   	nop
   1400017c9:	90                   	nop
   1400017ca:	90                   	nop
   1400017cb:	90                   	nop
   1400017cc:	90                   	nop
   1400017cd:	90                   	nop
   1400017ce:	90                   	nop
   1400017cf:	90                   	nop

00000001400017d0 <__do_global_dtors>:
   1400017d0:	55                   	push   rbp
   1400017d1:	48 89 e5             	mov    rbp,rsp
   1400017d4:	48 83 ec 20          	sub    rsp,0x20
   1400017d8:	eb 1e                	jmp    1400017f8 <__do_global_dtors+0x28>
   1400017da:	48 8b 05 2f 28 00 00 	mov    rax,QWORD PTR [rip+0x282f]        # 140004010 <p.0>
   1400017e1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017e4:	ff d0                	call   rax
   1400017e6:	48 8b 05 23 28 00 00 	mov    rax,QWORD PTR [rip+0x2823]        # 140004010 <p.0>
   1400017ed:	48 83 c0 08          	add    rax,0x8
   1400017f1:	48 89 05 18 28 00 00 	mov    QWORD PTR [rip+0x2818],rax        # 140004010 <p.0>
   1400017f8:	48 8b 05 11 28 00 00 	mov    rax,QWORD PTR [rip+0x2811]        # 140004010 <p.0>
   1400017ff:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001802:	48 85 c0             	test   rax,rax
   140001805:	75 d3                	jne    1400017da <__do_global_dtors+0xa>
   140001807:	90                   	nop
   140001808:	90                   	nop
   140001809:	48 83 c4 20          	add    rsp,0x20
   14000180d:	5d                   	pop    rbp
   14000180e:	c3                   	ret

000000014000180f <__do_global_ctors>:
   14000180f:	55                   	push   rbp
   140001810:	48 89 e5             	mov    rbp,rsp
   140001813:	48 83 ec 30          	sub    rsp,0x30
   140001817:	48 8b 05 32 3b 00 00 	mov    rax,QWORD PTR [rip+0x3b32]        # 140005350 <.refptr.__CTOR_LIST__>
   14000181e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001821:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001824:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001828:	75 25                	jne    14000184f <__do_global_ctors+0x40>
   14000182a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001831:	eb 04                	jmp    140001837 <__do_global_ctors+0x28>
   140001833:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001837:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000183a:	8d 50 01             	lea    edx,[rax+0x1]
   14000183d:	48 8b 05 0c 3b 00 00 	mov    rax,QWORD PTR [rip+0x3b0c]        # 140005350 <.refptr.__CTOR_LIST__>
   140001844:	89 d2                	mov    edx,edx
   140001846:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000184a:	48 85 c0             	test   rax,rax
   14000184d:	75 e4                	jne    140001833 <__do_global_ctors+0x24>
   14000184f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001852:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001855:	eb 14                	jmp    14000186b <__do_global_ctors+0x5c>
   140001857:	48 8b 05 f2 3a 00 00 	mov    rax,QWORD PTR [rip+0x3af2]        # 140005350 <.refptr.__CTOR_LIST__>
   14000185e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001861:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001865:	ff d0                	call   rax
   140001867:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000186b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000186f:	75 e6                	jne    140001857 <__do_global_ctors+0x48>
   140001871:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400017d0 <__do_global_dtors>
   140001878:	48 89 c1             	mov    rcx,rax
   14000187b:	e8 af fd ff ff       	call   14000162f <atexit>
   140001880:	90                   	nop
   140001881:	48 83 c4 30          	add    rsp,0x30
   140001885:	5d                   	pop    rbp
   140001886:	c3                   	ret

0000000140001887 <__main>:
   140001887:	55                   	push   rbp
   140001888:	48 89 e5             	mov    rbp,rsp
   14000188b:	48 83 ec 20          	sub    rsp,0x20
   14000188f:	8b 05 eb 77 00 00    	mov    eax,DWORD PTR [rip+0x77eb]        # 140009080 <initialized>
   140001895:	85 c0                	test   eax,eax
   140001897:	75 0f                	jne    1400018a8 <__main+0x21>
   140001899:	c7 05 dd 77 00 00 01 	mov    DWORD PTR [rip+0x77dd],0x1        # 140009080 <initialized>
   1400018a0:	00 00 00 
   1400018a3:	e8 67 ff ff ff       	call   14000180f <__do_global_ctors>
   1400018a8:	90                   	nop
   1400018a9:	48 83 c4 20          	add    rsp,0x20
   1400018ad:	5d                   	pop    rbp
   1400018ae:	c3                   	ret
   1400018af:	90                   	nop

00000001400018b0 <_setargv>:
   1400018b0:	55                   	push   rbp
   1400018b1:	48 89 e5             	mov    rbp,rsp
   1400018b4:	b8 00 00 00 00       	mov    eax,0x0
   1400018b9:	5d                   	pop    rbp
   1400018ba:	c3                   	ret
   1400018bb:	90                   	nop
   1400018bc:	90                   	nop
   1400018bd:	90                   	nop
   1400018be:	90                   	nop
   1400018bf:	90                   	nop

00000001400018c0 <__dyn_tls_init>:
   1400018c0:	55                   	push   rbp
   1400018c1:	48 89 e5             	mov    rbp,rsp
   1400018c4:	48 83 ec 30          	sub    rsp,0x30
   1400018c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400018cc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400018cf:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400018d3:	48 8b 05 56 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a56]        # 140005330 <.refptr._CRT_MT>
   1400018da:	8b 00                	mov    eax,DWORD PTR [rax]
   1400018dc:	83 f8 02             	cmp    eax,0x2
   1400018df:	74 0d                	je     1400018ee <__dyn_tls_init+0x2e>
   1400018e1:	48 8b 05 48 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a48]        # 140005330 <.refptr._CRT_MT>
   1400018e8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400018ee:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   1400018f2:	74 1e                	je     140001912 <__dyn_tls_init+0x52>
   1400018f4:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   1400018f8:	75 5b                	jne    140001955 <__dyn_tls_init+0x95>
   1400018fa:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400018fe:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001901:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001905:	49 89 c8             	mov    r8,rcx
   140001908:	48 89 c1             	mov    rcx,rax
   14000190b:	e8 d1 11 00 00       	call   140002ae1 <__mingw_TLScallback>
   140001910:	eb 43                	jmp    140001955 <__dyn_tls_init+0x95>
   140001912:	48 8d 05 7f 3d 00 00 	lea    rax,[rip+0x3d7f]        # 140005698 <___crt_xd_start__>
   140001919:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000191d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001922:	eb 22                	jmp    140001946 <__dyn_tls_init+0x86>
   140001924:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001928:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000192c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001930:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001933:	48 85 c0             	test   rax,rax
   140001936:	74 09                	je     140001941 <__dyn_tls_init+0x81>
   140001938:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000193c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000193f:	ff d0                	call   rax
   140001941:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001946:	48 8d 05 53 3d 00 00 	lea    rax,[rip+0x3d53]        # 1400056a0 <__xd_z>
   14000194d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001951:	75 d1                	jne    140001924 <__dyn_tls_init+0x64>
   140001953:	eb 01                	jmp    140001956 <__dyn_tls_init+0x96>
   140001955:	90                   	nop
   140001956:	48 83 c4 30          	add    rsp,0x30
   14000195a:	5d                   	pop    rbp
   14000195b:	c3                   	ret

000000014000195c <__tlregdtor>:
   14000195c:	55                   	push   rbp
   14000195d:	48 89 e5             	mov    rbp,rsp
   140001960:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001964:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001969:	75 07                	jne    140001972 <__tlregdtor+0x16>
   14000196b:	b8 00 00 00 00       	mov    eax,0x0
   140001970:	eb 05                	jmp    140001977 <__tlregdtor+0x1b>
   140001972:	b8 00 00 00 00       	mov    eax,0x0
   140001977:	5d                   	pop    rbp
   140001978:	c3                   	ret

0000000140001979 <__dyn_tls_dtor>:
   140001979:	55                   	push   rbp
   14000197a:	48 89 e5             	mov    rbp,rsp
   14000197d:	48 83 ec 20          	sub    rsp,0x20
   140001981:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001985:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001988:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000198c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001990:	74 06                	je     140001998 <__dyn_tls_dtor+0x1f>
   140001992:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001996:	75 18                	jne    1400019b0 <__dyn_tls_dtor+0x37>
   140001998:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000199c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   14000199f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019a3:	49 89 c8             	mov    r8,rcx
   1400019a6:	48 89 c1             	mov    rcx,rax
   1400019a9:	e8 33 11 00 00       	call   140002ae1 <__mingw_TLScallback>
   1400019ae:	eb 01                	jmp    1400019b1 <__dyn_tls_dtor+0x38>
   1400019b0:	90                   	nop
   1400019b1:	48 83 c4 20          	add    rsp,0x20
   1400019b5:	5d                   	pop    rbp
   1400019b6:	c3                   	ret
   1400019b7:	90                   	nop
   1400019b8:	90                   	nop
   1400019b9:	90                   	nop
   1400019ba:	90                   	nop
   1400019bb:	90                   	nop
   1400019bc:	90                   	nop
   1400019bd:	90                   	nop
   1400019be:	90                   	nop
   1400019bf:	90                   	nop

00000001400019c0 <_matherr>:
   1400019c0:	55                   	push   rbp
   1400019c1:	53                   	push   rbx
   1400019c2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400019c9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400019ce:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   1400019d2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   1400019d6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   1400019db:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   1400019df:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   1400019e3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019e5:	83 f8 06             	cmp    eax,0x6
   1400019e8:	74 56                	je     140001a40 <_matherr+0x80>
   1400019ea:	83 f8 06             	cmp    eax,0x6
   1400019ed:	7f 78                	jg     140001a67 <_matherr+0xa7>
   1400019ef:	83 f8 05             	cmp    eax,0x5
   1400019f2:	74 59                	je     140001a4d <_matherr+0x8d>
   1400019f4:	83 f8 05             	cmp    eax,0x5
   1400019f7:	7f 6e                	jg     140001a67 <_matherr+0xa7>
   1400019f9:	83 f8 04             	cmp    eax,0x4
   1400019fc:	74 5c                	je     140001a5a <_matherr+0x9a>
   1400019fe:	83 f8 04             	cmp    eax,0x4
   140001a01:	7f 64                	jg     140001a67 <_matherr+0xa7>
   140001a03:	83 f8 03             	cmp    eax,0x3
   140001a06:	74 2b                	je     140001a33 <_matherr+0x73>
   140001a08:	83 f8 03             	cmp    eax,0x3
   140001a0b:	7f 5a                	jg     140001a67 <_matherr+0xa7>
   140001a0d:	83 f8 01             	cmp    eax,0x1
   140001a10:	74 07                	je     140001a19 <_matherr+0x59>
   140001a12:	83 f8 02             	cmp    eax,0x2
   140001a15:	74 0f                	je     140001a26 <_matherr+0x66>
   140001a17:	eb 4e                	jmp    140001a67 <_matherr+0xa7>
   140001a19:	48 8d 05 80 36 00 00 	lea    rax,[rip+0x3680]        # 1400050a0 <.rdata>
   140001a20:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a24:	eb 4d                	jmp    140001a73 <_matherr+0xb3>
   140001a26:	48 8d 05 92 36 00 00 	lea    rax,[rip+0x3692]        # 1400050bf <.rdata+0x1f>
   140001a2d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a31:	eb 40                	jmp    140001a73 <_matherr+0xb3>
   140001a33:	48 8d 05 a6 36 00 00 	lea    rax,[rip+0x36a6]        # 1400050e0 <.rdata+0x40>
   140001a3a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a3e:	eb 33                	jmp    140001a73 <_matherr+0xb3>
   140001a40:	48 8d 05 b9 36 00 00 	lea    rax,[rip+0x36b9]        # 140005100 <.rdata+0x60>
   140001a47:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a4b:	eb 26                	jmp    140001a73 <_matherr+0xb3>
   140001a4d:	48 8d 05 d4 36 00 00 	lea    rax,[rip+0x36d4]        # 140005128 <.rdata+0x88>
   140001a54:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a58:	eb 19                	jmp    140001a73 <_matherr+0xb3>
   140001a5a:	48 8d 05 ef 36 00 00 	lea    rax,[rip+0x36ef]        # 140005150 <.rdata+0xb0>
   140001a61:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a65:	eb 0c                	jmp    140001a73 <_matherr+0xb3>
   140001a67:	48 8d 05 18 37 00 00 	lea    rax,[rip+0x3718]        # 140005186 <.rdata+0xe6>
   140001a6e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a72:	90                   	nop
   140001a73:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a77:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001a7d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a81:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001a86:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a8a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001a8f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a93:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001a97:	b9 02 00 00 00       	mov    ecx,0x2
   140001a9c:	e8 2f 17 00 00       	call   1400031d0 <__acrt_iob_func>
   140001aa1:	48 89 c1             	mov    rcx,rax
   140001aa4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001aa8:	48 8d 05 e9 36 00 00 	lea    rax,[rip+0x36e9]        # 140005198 <.rdata+0xf8>
   140001aaf:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001ab6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001abc:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001ac2:	49 89 d9             	mov    r9,rbx
   140001ac5:	49 89 d0             	mov    r8,rdx
   140001ac8:	48 89 c2             	mov    rdx,rax
   140001acb:	e8 98 17 00 00       	call   140003268 <fprintf>
   140001ad0:	b8 00 00 00 00       	mov    eax,0x0
   140001ad5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001ad9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001add:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001ae2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001ae9:	5b                   	pop    rbx
   140001aea:	5d                   	pop    rbp
   140001aeb:	c3                   	ret
   140001aec:	90                   	nop
   140001aed:	90                   	nop
   140001aee:	90                   	nop
   140001aef:	90                   	nop

0000000140001af0 <__report_error>:
   140001af0:	55                   	push   rbp
   140001af1:	53                   	push   rbx
   140001af2:	48 83 ec 38          	sub    rsp,0x38
   140001af6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001afb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001aff:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b03:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b07:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b0b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b0f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b13:	b9 02 00 00 00       	mov    ecx,0x2
   140001b18:	e8 b3 16 00 00       	call   1400031d0 <__acrt_iob_func>
   140001b1d:	48 89 c1             	mov    rcx,rax
   140001b20:	48 8d 05 a9 36 00 00 	lea    rax,[rip+0x36a9]        # 1400051d0 <.rdata>
   140001b27:	48 89 c2             	mov    rdx,rax
   140001b2a:	e8 39 17 00 00       	call   140003268 <fprintf>
   140001b2f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b33:	b9 02 00 00 00       	mov    ecx,0x2
   140001b38:	e8 93 16 00 00       	call   1400031d0 <__acrt_iob_func>
   140001b3d:	48 89 c1             	mov    rcx,rax
   140001b40:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b44:	49 89 d8             	mov    r8,rbx
   140001b47:	48 89 c2             	mov    rdx,rax
   140001b4a:	e8 61 17 00 00       	call   1400032b0 <vfprintf>
   140001b4f:	e8 f4 16 00 00       	call   140003248 <abort>
   140001b54:	90                   	nop

0000000140001b55 <mark_section_writable>:
   140001b55:	55                   	push   rbp
   140001b56:	48 89 e5             	mov    rbp,rsp
   140001b59:	48 83 ec 60          	sub    rsp,0x60
   140001b5d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b61:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001b68:	e9 82 00 00 00       	jmp    140001bef <mark_section_writable+0x9a>
   140001b6d:	48 8b 0d 6c 75 00 00 	mov    rcx,QWORD PTR [rip+0x756c]        # 1400090e0 <the_secs>
   140001b74:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b77:	48 63 d0             	movsxd rdx,eax
   140001b7a:	48 89 d0             	mov    rax,rdx
   140001b7d:	48 c1 e0 02          	shl    rax,0x2
   140001b81:	48 01 d0             	add    rax,rdx
   140001b84:	48 c1 e0 03          	shl    rax,0x3
   140001b88:	48 01 c8             	add    rax,rcx
   140001b8b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001b8f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001b93:	72 56                	jb     140001beb <mark_section_writable+0x96>
   140001b95:	48 8b 0d 44 75 00 00 	mov    rcx,QWORD PTR [rip+0x7544]        # 1400090e0 <the_secs>
   140001b9c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b9f:	48 63 d0             	movsxd rdx,eax
   140001ba2:	48 89 d0             	mov    rax,rdx
   140001ba5:	48 c1 e0 02          	shl    rax,0x2
   140001ba9:	48 01 d0             	add    rax,rdx
   140001bac:	48 c1 e0 03          	shl    rax,0x3
   140001bb0:	48 01 c8             	add    rax,rcx
   140001bb3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001bb7:	4c 8b 05 22 75 00 00 	mov    r8,QWORD PTR [rip+0x7522]        # 1400090e0 <the_secs>
   140001bbe:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bc1:	48 63 d0             	movsxd rdx,eax
   140001bc4:	48 89 d0             	mov    rax,rdx
   140001bc7:	48 c1 e0 02          	shl    rax,0x2
   140001bcb:	48 01 d0             	add    rax,rdx
   140001bce:	48 c1 e0 03          	shl    rax,0x3
   140001bd2:	4c 01 c0             	add    rax,r8
   140001bd5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001bd9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001bdc:	89 c0                	mov    eax,eax
   140001bde:	48 01 c8             	add    rax,rcx
   140001be1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001be5:	0f 82 41 02 00 00    	jb     140001e2c <mark_section_writable+0x2d7>
   140001beb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001bef:	8b 05 f3 74 00 00    	mov    eax,DWORD PTR [rip+0x74f3]        # 1400090e8 <maxSections>
   140001bf5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001bf8:	0f 8c 6f ff ff ff    	jl     140001b6d <mark_section_writable+0x18>
   140001bfe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c02:	48 89 c1             	mov    rcx,rax
   140001c05:	e8 c1 11 00 00       	call   140002dcb <__mingw_GetSectionForAddress>
   140001c0a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c0e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c13:	75 13                	jne    140001c28 <mark_section_writable+0xd3>
   140001c15:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c19:	48 8d 0d d0 35 00 00 	lea    rcx,[rip+0x35d0]        # 1400051f0 <.rdata+0x20>
   140001c20:	48 89 c2             	mov    rdx,rax
   140001c23:	e8 c8 fe ff ff       	call   140001af0 <__report_error>
   140001c28:	48 8b 0d b1 74 00 00 	mov    rcx,QWORD PTR [rip+0x74b1]        # 1400090e0 <the_secs>
   140001c2f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c32:	48 63 d0             	movsxd rdx,eax
   140001c35:	48 89 d0             	mov    rax,rdx
   140001c38:	48 c1 e0 02          	shl    rax,0x2
   140001c3c:	48 01 d0             	add    rax,rdx
   140001c3f:	48 c1 e0 03          	shl    rax,0x3
   140001c43:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c47:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c4b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c4f:	48 8b 0d 8a 74 00 00 	mov    rcx,QWORD PTR [rip+0x748a]        # 1400090e0 <the_secs>
   140001c56:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c59:	48 63 d0             	movsxd rdx,eax
   140001c5c:	48 89 d0             	mov    rax,rdx
   140001c5f:	48 c1 e0 02          	shl    rax,0x2
   140001c63:	48 01 d0             	add    rax,rdx
   140001c66:	48 c1 e0 03          	shl    rax,0x3
   140001c6a:	48 01 c8             	add    rax,rcx
   140001c6d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001c73:	e8 9f 12 00 00       	call   140002f17 <_GetPEImageBase>
   140001c78:	48 89 c1             	mov    rcx,rax
   140001c7b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c7f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001c82:	41 89 c1             	mov    r9d,eax
   140001c85:	4c 8b 05 54 74 00 00 	mov    r8,QWORD PTR [rip+0x7454]        # 1400090e0 <the_secs>
   140001c8c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c8f:	48 63 d0             	movsxd rdx,eax
   140001c92:	48 89 d0             	mov    rax,rdx
   140001c95:	48 c1 e0 02          	shl    rax,0x2
   140001c99:	48 01 d0             	add    rax,rdx
   140001c9c:	48 c1 e0 03          	shl    rax,0x3
   140001ca0:	4c 01 c0             	add    rax,r8
   140001ca3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001ca7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001cab:	48 8b 0d 2e 74 00 00 	mov    rcx,QWORD PTR [rip+0x742e]        # 1400090e0 <the_secs>
   140001cb2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cb5:	48 63 d0             	movsxd rdx,eax
   140001cb8:	48 89 d0             	mov    rax,rdx
   140001cbb:	48 c1 e0 02          	shl    rax,0x2
   140001cbf:	48 01 d0             	add    rax,rdx
   140001cc2:	48 c1 e0 03          	shl    rax,0x3
   140001cc6:	48 01 c8             	add    rax,rcx
   140001cc9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001ccd:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001cd1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001cd7:	48 89 c1             	mov    rcx,rax
   140001cda:	48 8b 05 17 85 00 00 	mov    rax,QWORD PTR [rip+0x8517]        # 14000a1f8 <__imp_VirtualQuery>
   140001ce1:	ff d0                	call   rax
   140001ce3:	48 85 c0             	test   rax,rax
   140001ce6:	75 3f                	jne    140001d27 <mark_section_writable+0x1d2>
   140001ce8:	48 8b 0d f1 73 00 00 	mov    rcx,QWORD PTR [rip+0x73f1]        # 1400090e0 <the_secs>
   140001cef:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cf2:	48 63 d0             	movsxd rdx,eax
   140001cf5:	48 89 d0             	mov    rax,rdx
   140001cf8:	48 c1 e0 02          	shl    rax,0x2
   140001cfc:	48 01 d0             	add    rax,rdx
   140001cff:	48 c1 e0 03          	shl    rax,0x3
   140001d03:	48 01 c8             	add    rax,rcx
   140001d06:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d0a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d0e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d11:	89 c1                	mov    ecx,eax
   140001d13:	48 8d 05 f6 34 00 00 	lea    rax,[rip+0x34f6]        # 140005210 <.rdata+0x40>
   140001d1a:	49 89 d0             	mov    r8,rdx
   140001d1d:	89 ca                	mov    edx,ecx
   140001d1f:	48 89 c1             	mov    rcx,rax
   140001d22:	e8 c9 fd ff ff       	call   140001af0 <__report_error>
   140001d27:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d2a:	83 f8 40             	cmp    eax,0x40
   140001d2d:	0f 84 e8 00 00 00    	je     140001e1b <mark_section_writable+0x2c6>
   140001d33:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d36:	83 f8 04             	cmp    eax,0x4
   140001d39:	0f 84 dc 00 00 00    	je     140001e1b <mark_section_writable+0x2c6>
   140001d3f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d42:	3d 80 00 00 00       	cmp    eax,0x80
   140001d47:	0f 84 ce 00 00 00    	je     140001e1b <mark_section_writable+0x2c6>
   140001d4d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d50:	83 f8 08             	cmp    eax,0x8
   140001d53:	0f 84 c2 00 00 00    	je     140001e1b <mark_section_writable+0x2c6>
   140001d59:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d5c:	83 f8 02             	cmp    eax,0x2
   140001d5f:	75 09                	jne    140001d6a <mark_section_writable+0x215>
   140001d61:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001d68:	eb 07                	jmp    140001d71 <mark_section_writable+0x21c>
   140001d6a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001d71:	48 8b 0d 68 73 00 00 	mov    rcx,QWORD PTR [rip+0x7368]        # 1400090e0 <the_secs>
   140001d78:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d7b:	48 63 d0             	movsxd rdx,eax
   140001d7e:	48 89 d0             	mov    rax,rdx
   140001d81:	48 c1 e0 02          	shl    rax,0x2
   140001d85:	48 01 d0             	add    rax,rdx
   140001d88:	48 c1 e0 03          	shl    rax,0x3
   140001d8c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d90:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001d94:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001d98:	48 8b 0d 41 73 00 00 	mov    rcx,QWORD PTR [rip+0x7341]        # 1400090e0 <the_secs>
   140001d9f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001da2:	48 63 d0             	movsxd rdx,eax
   140001da5:	48 89 d0             	mov    rax,rdx
   140001da8:	48 c1 e0 02          	shl    rax,0x2
   140001dac:	48 01 d0             	add    rax,rdx
   140001daf:	48 c1 e0 03          	shl    rax,0x3
   140001db3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001db7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001dbb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001dbf:	48 8b 0d 1a 73 00 00 	mov    rcx,QWORD PTR [rip+0x731a]        # 1400090e0 <the_secs>
   140001dc6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dc9:	48 63 d0             	movsxd rdx,eax
   140001dcc:	48 89 d0             	mov    rax,rdx
   140001dcf:	48 c1 e0 02          	shl    rax,0x2
   140001dd3:	48 01 d0             	add    rax,rdx
   140001dd6:	48 c1 e0 03          	shl    rax,0x3
   140001dda:	48 01 c8             	add    rax,rcx
   140001ddd:	49 89 c0             	mov    r8,rax
   140001de0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001de4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001de8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001deb:	4d 89 c1             	mov    r9,r8
   140001dee:	41 89 c8             	mov    r8d,ecx
   140001df1:	48 89 c1             	mov    rcx,rax
   140001df4:	48 8b 05 f5 83 00 00 	mov    rax,QWORD PTR [rip+0x83f5]        # 14000a1f0 <__imp_VirtualProtect>
   140001dfb:	ff d0                	call   rax
   140001dfd:	85 c0                	test   eax,eax
   140001dff:	75 1a                	jne    140001e1b <mark_section_writable+0x2c6>
   140001e01:	48 8b 05 a0 83 00 00 	mov    rax,QWORD PTR [rip+0x83a0]        # 14000a1a8 <__imp_GetLastError>
   140001e08:	ff d0                	call   rax
   140001e0a:	89 c2                	mov    edx,eax
   140001e0c:	48 8d 05 35 34 00 00 	lea    rax,[rip+0x3435]        # 140005248 <.rdata+0x78>
   140001e13:	48 89 c1             	mov    rcx,rax
   140001e16:	e8 d5 fc ff ff       	call   140001af0 <__report_error>
   140001e1b:	8b 05 c7 72 00 00    	mov    eax,DWORD PTR [rip+0x72c7]        # 1400090e8 <maxSections>
   140001e21:	83 c0 01             	add    eax,0x1
   140001e24:	89 05 be 72 00 00    	mov    DWORD PTR [rip+0x72be],eax        # 1400090e8 <maxSections>
   140001e2a:	eb 01                	jmp    140001e2d <mark_section_writable+0x2d8>
   140001e2c:	90                   	nop
   140001e2d:	48 83 c4 60          	add    rsp,0x60
   140001e31:	5d                   	pop    rbp
   140001e32:	c3                   	ret

0000000140001e33 <restore_modified_sections>:
   140001e33:	55                   	push   rbp
   140001e34:	48 89 e5             	mov    rbp,rsp
   140001e37:	48 83 ec 30          	sub    rsp,0x30
   140001e3b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e42:	e9 ad 00 00 00       	jmp    140001ef4 <restore_modified_sections+0xc1>
   140001e47:	48 8b 0d 92 72 00 00 	mov    rcx,QWORD PTR [rip+0x7292]        # 1400090e0 <the_secs>
   140001e4e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e51:	48 63 d0             	movsxd rdx,eax
   140001e54:	48 89 d0             	mov    rax,rdx
   140001e57:	48 c1 e0 02          	shl    rax,0x2
   140001e5b:	48 01 d0             	add    rax,rdx
   140001e5e:	48 c1 e0 03          	shl    rax,0x3
   140001e62:	48 01 c8             	add    rax,rcx
   140001e65:	8b 00                	mov    eax,DWORD PTR [rax]
   140001e67:	85 c0                	test   eax,eax
   140001e69:	0f 84 80 00 00 00    	je     140001eef <restore_modified_sections+0xbc>
   140001e6f:	48 8b 0d 6a 72 00 00 	mov    rcx,QWORD PTR [rip+0x726a]        # 1400090e0 <the_secs>
   140001e76:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e79:	48 63 d0             	movsxd rdx,eax
   140001e7c:	48 89 d0             	mov    rax,rdx
   140001e7f:	48 c1 e0 02          	shl    rax,0x2
   140001e83:	48 01 d0             	add    rax,rdx
   140001e86:	48 c1 e0 03          	shl    rax,0x3
   140001e8a:	48 01 c8             	add    rax,rcx
   140001e8d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001e90:	48 8b 0d 49 72 00 00 	mov    rcx,QWORD PTR [rip+0x7249]        # 1400090e0 <the_secs>
   140001e97:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e9a:	48 63 d0             	movsxd rdx,eax
   140001e9d:	48 89 d0             	mov    rax,rdx
   140001ea0:	48 c1 e0 02          	shl    rax,0x2
   140001ea4:	48 01 d0             	add    rax,rdx
   140001ea7:	48 c1 e0 03          	shl    rax,0x3
   140001eab:	48 01 c8             	add    rax,rcx
   140001eae:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001eb2:	4c 8b 05 27 72 00 00 	mov    r8,QWORD PTR [rip+0x7227]        # 1400090e0 <the_secs>
   140001eb9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ebc:	48 63 d0             	movsxd rdx,eax
   140001ebf:	48 89 d0             	mov    rax,rdx
   140001ec2:	48 c1 e0 02          	shl    rax,0x2
   140001ec6:	48 01 d0             	add    rax,rdx
   140001ec9:	48 c1 e0 03          	shl    rax,0x3
   140001ecd:	4c 01 c0             	add    rax,r8
   140001ed0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001ed4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001ed8:	49 89 d1             	mov    r9,rdx
   140001edb:	45 89 d0             	mov    r8d,r10d
   140001ede:	48 89 ca             	mov    rdx,rcx
   140001ee1:	48 89 c1             	mov    rcx,rax
   140001ee4:	48 8b 05 05 83 00 00 	mov    rax,QWORD PTR [rip+0x8305]        # 14000a1f0 <__imp_VirtualProtect>
   140001eeb:	ff d0                	call   rax
   140001eed:	eb 01                	jmp    140001ef0 <restore_modified_sections+0xbd>
   140001eef:	90                   	nop
   140001ef0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001ef4:	8b 05 ee 71 00 00    	mov    eax,DWORD PTR [rip+0x71ee]        # 1400090e8 <maxSections>
   140001efa:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001efd:	0f 8c 44 ff ff ff    	jl     140001e47 <restore_modified_sections+0x14>
   140001f03:	90                   	nop
   140001f04:	90                   	nop
   140001f05:	48 83 c4 30          	add    rsp,0x30
   140001f09:	5d                   	pop    rbp
   140001f0a:	c3                   	ret

0000000140001f0b <__write_memory>:
   140001f0b:	55                   	push   rbp
   140001f0c:	48 89 e5             	mov    rbp,rsp
   140001f0f:	48 83 ec 20          	sub    rsp,0x20
   140001f13:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f17:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f1b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f1f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f24:	74 25                	je     140001f4b <__write_memory+0x40>
   140001f26:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f2a:	48 89 c1             	mov    rcx,rax
   140001f2d:	e8 23 fc ff ff       	call   140001b55 <mark_section_writable>
   140001f32:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f36:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f3a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f3e:	49 89 c8             	mov    r8,rcx
   140001f41:	48 89 c1             	mov    rcx,rax
   140001f44:	e8 37 13 00 00       	call   140003280 <memcpy>
   140001f49:	eb 01                	jmp    140001f4c <__write_memory+0x41>
   140001f4b:	90                   	nop
   140001f4c:	48 83 c4 20          	add    rsp,0x20
   140001f50:	5d                   	pop    rbp
   140001f51:	c3                   	ret

0000000140001f52 <do_pseudo_reloc>:
   140001f52:	55                   	push   rbp
   140001f53:	48 89 e5             	mov    rbp,rsp
   140001f56:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001f5a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f5e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f62:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f66:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001f6a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001f6e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001f72:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f76:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001f7a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001f7f:	0f 8e 44 03 00 00    	jle    1400022c9 <do_pseudo_reloc+0x377>
   140001f85:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001f8a:	7e 25                	jle    140001fb1 <do_pseudo_reloc+0x5f>
   140001f8c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f90:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f92:	85 c0                	test   eax,eax
   140001f94:	75 1b                	jne    140001fb1 <do_pseudo_reloc+0x5f>
   140001f96:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f9a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001f9d:	85 c0                	test   eax,eax
   140001f9f:	75 10                	jne    140001fb1 <do_pseudo_reloc+0x5f>
   140001fa1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fa5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001fa8:	85 c0                	test   eax,eax
   140001faa:	75 05                	jne    140001fb1 <do_pseudo_reloc+0x5f>
   140001fac:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140001fb1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fb5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fb7:	85 c0                	test   eax,eax
   140001fb9:	75 0b                	jne    140001fc6 <do_pseudo_reloc+0x74>
   140001fbb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fbf:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fc2:	85 c0                	test   eax,eax
   140001fc4:	74 59                	je     14000201f <do_pseudo_reloc+0xcd>
   140001fc6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fca:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001fce:	eb 40                	jmp    140002010 <do_pseudo_reloc+0xbe>
   140001fd0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001fd4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fd7:	89 c2                	mov    edx,eax
   140001fd9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001fdd:	48 01 d0             	add    rax,rdx
   140001fe0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001fe4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001fe8:	8b 10                	mov    edx,DWORD PTR [rax]
   140001fea:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001fee:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ff0:	01 d0                	add    eax,edx
   140001ff2:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140001ff5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001ff9:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   140001ffd:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002003:	48 89 c1             	mov    rcx,rax
   140002006:	e8 00 ff ff ff       	call   140001f0b <__write_memory>
   14000200b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002010:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002014:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002018:	72 b6                	jb     140001fd0 <do_pseudo_reloc+0x7e>
   14000201a:	e9 ab 02 00 00       	jmp    1400022ca <do_pseudo_reloc+0x378>
   14000201f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002023:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002026:	83 f8 01             	cmp    eax,0x1
   140002029:	74 18                	je     140002043 <do_pseudo_reloc+0xf1>
   14000202b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000202f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002032:	89 c2                	mov    edx,eax
   140002034:	48 8d 05 35 32 00 00 	lea    rax,[rip+0x3235]        # 140005270 <.rdata+0xa0>
   14000203b:	48 89 c1             	mov    rcx,rax
   14000203e:	e8 ad fa ff ff       	call   140001af0 <__report_error>
   140002043:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002047:	48 83 c0 0c          	add    rax,0xc
   14000204b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000204f:	e9 65 02 00 00       	jmp    1400022b9 <do_pseudo_reloc+0x367>
   140002054:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002058:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000205b:	89 c2                	mov    edx,eax
   14000205d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002061:	48 01 d0             	add    rax,rdx
   140002064:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002068:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000206c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000206e:	89 c2                	mov    edx,eax
   140002070:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002074:	48 01 d0             	add    rax,rdx
   140002077:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000207b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000207f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002082:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002086:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000208a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000208d:	0f b6 c0             	movzx  eax,al
   140002090:	83 f8 40             	cmp    eax,0x40
   140002093:	0f 84 b6 00 00 00    	je     14000214f <do_pseudo_reloc+0x1fd>
   140002099:	83 f8 40             	cmp    eax,0x40
   14000209c:	0f 87 ba 00 00 00    	ja     14000215c <do_pseudo_reloc+0x20a>
   1400020a2:	83 f8 20             	cmp    eax,0x20
   1400020a5:	74 77                	je     14000211e <do_pseudo_reloc+0x1cc>
   1400020a7:	83 f8 20             	cmp    eax,0x20
   1400020aa:	0f 87 ac 00 00 00    	ja     14000215c <do_pseudo_reloc+0x20a>
   1400020b0:	83 f8 08             	cmp    eax,0x8
   1400020b3:	74 0a                	je     1400020bf <do_pseudo_reloc+0x16d>
   1400020b5:	83 f8 10             	cmp    eax,0x10
   1400020b8:	74 38                	je     1400020f2 <do_pseudo_reloc+0x1a0>
   1400020ba:	e9 9d 00 00 00       	jmp    14000215c <do_pseudo_reloc+0x20a>
   1400020bf:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020c3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400020c6:	0f b6 c0             	movzx  eax,al
   1400020c9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020cd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020d1:	25 80 00 00 00       	and    eax,0x80
   1400020d6:	48 85 c0             	test   rax,rax
   1400020d9:	0f 84 9d 00 00 00    	je     14000217c <do_pseudo_reloc+0x22a>
   1400020df:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020e3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400020e9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020ed:	e9 8a 00 00 00       	jmp    14000217c <do_pseudo_reloc+0x22a>
   1400020f2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020f6:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400020f9:	0f b7 c0             	movzx  eax,ax
   1400020fc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002100:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002104:	25 00 80 00 00       	and    eax,0x8000
   140002109:	48 85 c0             	test   rax,rax
   14000210c:	74 71                	je     14000217f <do_pseudo_reloc+0x22d>
   14000210e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002112:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002118:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000211c:	eb 61                	jmp    14000217f <do_pseudo_reloc+0x22d>
   14000211e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002122:	8b 00                	mov    eax,DWORD PTR [rax]
   140002124:	89 c0                	mov    eax,eax
   140002126:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000212a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000212e:	25 00 00 00 80       	and    eax,0x80000000
   140002133:	48 85 c0             	test   rax,rax
   140002136:	74 4a                	je     140002182 <do_pseudo_reloc+0x230>
   140002138:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000213c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002143:	ff ff ff 
   140002146:	48 09 d0             	or     rax,rdx
   140002149:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000214d:	eb 33                	jmp    140002182 <do_pseudo_reloc+0x230>
   14000214f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002153:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002156:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000215a:	eb 27                	jmp    140002183 <do_pseudo_reloc+0x231>
   14000215c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002163:	00 
   140002164:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002168:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000216b:	0f b6 c0             	movzx  eax,al
   14000216e:	48 8d 0d 33 31 00 00 	lea    rcx,[rip+0x3133]        # 1400052a8 <.rdata+0xd8>
   140002175:	89 c2                	mov    edx,eax
   140002177:	e8 74 f9 ff ff       	call   140001af0 <__report_error>
   14000217c:	90                   	nop
   14000217d:	eb 04                	jmp    140002183 <do_pseudo_reloc+0x231>
   14000217f:	90                   	nop
   140002180:	eb 01                	jmp    140002183 <do_pseudo_reloc+0x231>
   140002182:	90                   	nop
   140002183:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002187:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000218b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000218d:	89 c2                	mov    edx,eax
   14000218f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002193:	48 01 c2             	add    rdx,rax
   140002196:	48 89 c8             	mov    rax,rcx
   140002199:	48 29 d0             	sub    rax,rdx
   14000219c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021a0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021a4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400021a8:	48 01 d0             	add    rax,rdx
   1400021ab:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021af:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021b3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021b6:	25 ff 00 00 00       	and    eax,0xff
   1400021bb:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400021be:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400021c2:	77 67                	ja     14000222b <do_pseudo_reloc+0x2d9>
   1400021c4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021c7:	ba 01 00 00 00       	mov    edx,0x1
   1400021cc:	89 c1                	mov    ecx,eax
   1400021ce:	48 d3 e2             	shl    rdx,cl
   1400021d1:	48 89 d0             	mov    rax,rdx
   1400021d4:	48 83 e8 01          	sub    rax,0x1
   1400021d8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400021dc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021df:	83 e8 01             	sub    eax,0x1
   1400021e2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400021e9:	89 c1                	mov    ecx,eax
   1400021eb:	48 d3 e2             	shl    rdx,cl
   1400021ee:	48 89 d0             	mov    rax,rdx
   1400021f1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400021f5:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021f9:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   1400021fd:	7c 0a                	jl     140002209 <do_pseudo_reloc+0x2b7>
   1400021ff:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002203:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002207:	7e 22                	jle    14000222b <do_pseudo_reloc+0x2d9>
   140002209:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000220d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002211:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002215:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002218:	48 8d 0d b9 30 00 00 	lea    rcx,[rip+0x30b9]        # 1400052d8 <.rdata+0x108>
   14000221f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002224:	89 c2                	mov    edx,eax
   140002226:	e8 c5 f8 ff ff       	call   140001af0 <__report_error>
   14000222b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000222f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002232:	0f b6 c0             	movzx  eax,al
   140002235:	83 f8 40             	cmp    eax,0x40
   140002238:	74 63                	je     14000229d <do_pseudo_reloc+0x34b>
   14000223a:	83 f8 40             	cmp    eax,0x40
   14000223d:	77 75                	ja     1400022b4 <do_pseudo_reloc+0x362>
   14000223f:	83 f8 20             	cmp    eax,0x20
   140002242:	74 41                	je     140002285 <do_pseudo_reloc+0x333>
   140002244:	83 f8 20             	cmp    eax,0x20
   140002247:	77 6b                	ja     1400022b4 <do_pseudo_reloc+0x362>
   140002249:	83 f8 08             	cmp    eax,0x8
   14000224c:	74 07                	je     140002255 <do_pseudo_reloc+0x303>
   14000224e:	83 f8 10             	cmp    eax,0x10
   140002251:	74 1a                	je     14000226d <do_pseudo_reloc+0x31b>
   140002253:	eb 5f                	jmp    1400022b4 <do_pseudo_reloc+0x362>
   140002255:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002259:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000225d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002263:	48 89 c1             	mov    rcx,rax
   140002266:	e8 a0 fc ff ff       	call   140001f0b <__write_memory>
   14000226b:	eb 47                	jmp    1400022b4 <do_pseudo_reloc+0x362>
   14000226d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002271:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002275:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000227b:	48 89 c1             	mov    rcx,rax
   14000227e:	e8 88 fc ff ff       	call   140001f0b <__write_memory>
   140002283:	eb 2f                	jmp    1400022b4 <do_pseudo_reloc+0x362>
   140002285:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002289:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000228d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002293:	48 89 c1             	mov    rcx,rax
   140002296:	e8 70 fc ff ff       	call   140001f0b <__write_memory>
   14000229b:	eb 17                	jmp    1400022b4 <do_pseudo_reloc+0x362>
   14000229d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022a1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022a5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400022ab:	48 89 c1             	mov    rcx,rax
   1400022ae:	e8 58 fc ff ff       	call   140001f0b <__write_memory>
   1400022b3:	90                   	nop
   1400022b4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400022b9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022bd:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400022c1:	0f 82 8d fd ff ff    	jb     140002054 <do_pseudo_reloc+0x102>
   1400022c7:	eb 01                	jmp    1400022ca <do_pseudo_reloc+0x378>
   1400022c9:	90                   	nop
   1400022ca:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400022ce:	5d                   	pop    rbp
   1400022cf:	c3                   	ret

00000001400022d0 <_pei386_runtime_relocator>:
   1400022d0:	55                   	push   rbp
   1400022d1:	48 89 e5             	mov    rbp,rsp
   1400022d4:	48 83 ec 30          	sub    rsp,0x30
   1400022d8:	8b 05 0e 6e 00 00    	mov    eax,DWORD PTR [rip+0x6e0e]        # 1400090ec <was_init.0>
   1400022de:	85 c0                	test   eax,eax
   1400022e0:	0f 85 88 00 00 00    	jne    14000236e <_pei386_runtime_relocator+0x9e>
   1400022e6:	8b 05 00 6e 00 00    	mov    eax,DWORD PTR [rip+0x6e00]        # 1400090ec <was_init.0>
   1400022ec:	83 c0 01             	add    eax,0x1
   1400022ef:	89 05 f7 6d 00 00    	mov    DWORD PTR [rip+0x6df7],eax        # 1400090ec <was_init.0>
   1400022f5:	e8 21 0b 00 00       	call   140002e1b <__mingw_GetSectionCount>
   1400022fa:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400022fd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002300:	48 63 d0             	movsxd rdx,eax
   140002303:	48 89 d0             	mov    rax,rdx
   140002306:	48 c1 e0 02          	shl    rax,0x2
   14000230a:	48 01 d0             	add    rax,rdx
   14000230d:	48 c1 e0 03          	shl    rax,0x3
   140002311:	48 83 c0 0f          	add    rax,0xf
   140002315:	48 c1 e8 04          	shr    rax,0x4
   140002319:	48 c1 e0 04          	shl    rax,0x4
   14000231d:	e8 7e 0d 00 00       	call   1400030a0 <___chkstk_ms>
   140002322:	48 29 c4             	sub    rsp,rax
   140002325:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000232a:	48 83 c0 0f          	add    rax,0xf
   14000232e:	48 c1 e8 04          	shr    rax,0x4
   140002332:	48 c1 e0 04          	shl    rax,0x4
   140002336:	48 89 05 a3 6d 00 00 	mov    QWORD PTR [rip+0x6da3],rax        # 1400090e0 <the_secs>
   14000233d:	c7 05 a1 6d 00 00 00 	mov    DWORD PTR [rip+0x6da1],0x0        # 1400090e8 <maxSections>
   140002344:	00 00 00 
   140002347:	48 8b 0d 12 30 00 00 	mov    rcx,QWORD PTR [rip+0x3012]        # 140005360 <.refptr.__ImageBase>
   14000234e:	48 8b 15 1b 30 00 00 	mov    rdx,QWORD PTR [rip+0x301b]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002355:	48 8b 05 24 30 00 00 	mov    rax,QWORD PTR [rip+0x3024]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000235c:	49 89 c8             	mov    r8,rcx
   14000235f:	48 89 c1             	mov    rcx,rax
   140002362:	e8 eb fb ff ff       	call   140001f52 <do_pseudo_reloc>
   140002367:	e8 c7 fa ff ff       	call   140001e33 <restore_modified_sections>
   14000236c:	eb 01                	jmp    14000236f <_pei386_runtime_relocator+0x9f>
   14000236e:	90                   	nop
   14000236f:	48 89 ec             	mov    rsp,rbp
   140002372:	5d                   	pop    rbp
   140002373:	c3                   	ret
   140002374:	90                   	nop
   140002375:	90                   	nop
   140002376:	90                   	nop
   140002377:	90                   	nop
   140002378:	90                   	nop
   140002379:	90                   	nop
   14000237a:	90                   	nop
   14000237b:	90                   	nop
   14000237c:	90                   	nop
   14000237d:	90                   	nop
   14000237e:	90                   	nop
   14000237f:	90                   	nop

0000000140002380 <__mingw_raise_matherr>:
   140002380:	55                   	push   rbp
   140002381:	48 89 e5             	mov    rbp,rsp
   140002384:	48 83 ec 50          	sub    rsp,0x50
   140002388:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000238b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000238f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002394:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002399:	48 8b 05 50 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d50]        # 1400090f0 <stUserMathErr>
   1400023a0:	48 85 c0             	test   rax,rax
   1400023a3:	74 3e                	je     1400023e3 <__mingw_raise_matherr+0x63>
   1400023a5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400023a8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400023ab:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400023af:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400023b3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400023b8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400023bd:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400023c2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400023c7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400023cc:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400023d1:	48 8b 15 18 6d 00 00 	mov    rdx,QWORD PTR [rip+0x6d18]        # 1400090f0 <stUserMathErr>
   1400023d8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400023dc:	48 89 c1             	mov    rcx,rax
   1400023df:	ff d2                	call   rdx
   1400023e1:	eb 01                	jmp    1400023e4 <__mingw_raise_matherr+0x64>
   1400023e3:	90                   	nop
   1400023e4:	48 83 c4 50          	add    rsp,0x50
   1400023e8:	5d                   	pop    rbp
   1400023e9:	c3                   	ret

00000001400023ea <__mingw_setusermatherr>:
   1400023ea:	55                   	push   rbp
   1400023eb:	48 89 e5             	mov    rbp,rsp
   1400023ee:	48 83 ec 20          	sub    rsp,0x20
   1400023f2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400023f6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400023fa:	48 89 05 ef 6c 00 00 	mov    QWORD PTR [rip+0x6cef],rax        # 1400090f0 <stUserMathErr>
   140002401:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002405:	48 89 c1             	mov    rcx,rax
   140002408:	e8 13 0e 00 00       	call   140003220 <__setusermatherr>
   14000240d:	90                   	nop
   14000240e:	48 83 c4 20          	add    rsp,0x20
   140002412:	5d                   	pop    rbp
   140002413:	c3                   	ret
   140002414:	90                   	nop
   140002415:	90                   	nop
   140002416:	90                   	nop
   140002417:	90                   	nop
   140002418:	90                   	nop
   140002419:	90                   	nop
   14000241a:	90                   	nop
   14000241b:	90                   	nop
   14000241c:	90                   	nop
   14000241d:	90                   	nop
   14000241e:	90                   	nop
   14000241f:	90                   	nop

0000000140002420 <__mingw_SEH_error_handler>:
   140002420:	55                   	push   rbp
   140002421:	48 89 e5             	mov    rbp,rsp
   140002424:	48 83 ec 30          	sub    rsp,0x30
   140002428:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000242c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002430:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002434:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002438:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000243f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002446:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000244a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000244d:	83 e0 02             	and    eax,0x2
   140002450:	85 c0                	test   eax,eax
   140002452:	74 0a                	je     14000245e <__mingw_SEH_error_handler+0x3e>
   140002454:	b8 01 00 00 00       	mov    eax,0x1
   140002459:	e9 16 02 00 00       	jmp    140002674 <__mingw_SEH_error_handler+0x254>
   14000245e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002462:	8b 00                	mov    eax,DWORD PTR [rax]
   140002464:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002469:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000246e:	75 18                	jne    140002488 <__mingw_SEH_error_handler+0x68>
   140002470:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002474:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002477:	83 e0 01             	and    eax,0x1
   14000247a:	85 c0                	test   eax,eax
   14000247c:	75 0a                	jne    140002488 <__mingw_SEH_error_handler+0x68>
   14000247e:	b8 00 00 00 00       	mov    eax,0x0
   140002483:	e9 ec 01 00 00       	jmp    140002674 <__mingw_SEH_error_handler+0x254>
   140002488:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000248c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000248e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002493:	0f 84 12 01 00 00    	je     1400025ab <__mingw_SEH_error_handler+0x18b>
   140002499:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000249e:	0f 87 c3 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   1400024a4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400024a9:	0f 87 b8 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   1400024af:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400024b4:	0f 83 4c 01 00 00    	jae    140002606 <__mingw_SEH_error_handler+0x1e6>
   1400024ba:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024bf:	0f 84 3a 01 00 00    	je     1400025ff <__mingw_SEH_error_handler+0x1df>
   1400024c5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024ca:	0f 87 97 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   1400024d0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024d5:	0f 84 83 01 00 00    	je     14000265e <__mingw_SEH_error_handler+0x23e>
   1400024db:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024e0:	0f 87 81 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   1400024e6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400024eb:	0f 87 76 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   1400024f1:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400024f6:	0f 83 03 01 00 00    	jae    1400025ff <__mingw_SEH_error_handler+0x1df>
   1400024fc:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002501:	0f 84 57 01 00 00    	je     14000265e <__mingw_SEH_error_handler+0x23e>
   140002507:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000250c:	0f 87 55 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   140002512:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002517:	0f 84 8e 00 00 00    	je     1400025ab <__mingw_SEH_error_handler+0x18b>
   14000251d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002522:	0f 87 3f 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   140002528:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000252d:	0f 84 2b 01 00 00    	je     14000265e <__mingw_SEH_error_handler+0x23e>
   140002533:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002538:	0f 87 29 01 00 00    	ja     140002667 <__mingw_SEH_error_handler+0x247>
   14000253e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002543:	0f 84 15 01 00 00    	je     14000265e <__mingw_SEH_error_handler+0x23e>
   140002549:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000254e:	0f 85 13 01 00 00    	jne    140002667 <__mingw_SEH_error_handler+0x247>
   140002554:	ba 00 00 00 00       	mov    edx,0x0
   140002559:	b9 0b 00 00 00       	mov    ecx,0xb
   14000255e:	e8 35 0d 00 00       	call   140003298 <signal>
   140002563:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002567:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000256c:	75 1b                	jne    140002589 <__mingw_SEH_error_handler+0x169>
   14000256e:	ba 01 00 00 00       	mov    edx,0x1
   140002573:	b9 0b 00 00 00       	mov    ecx,0xb
   140002578:	e8 1b 0d 00 00       	call   140003298 <signal>
   14000257d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002584:	e9 e1 00 00 00       	jmp    14000266a <__mingw_SEH_error_handler+0x24a>
   140002589:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000258e:	0f 84 d6 00 00 00    	je     14000266a <__mingw_SEH_error_handler+0x24a>
   140002594:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002598:	b9 0b 00 00 00       	mov    ecx,0xb
   14000259d:	ff d0                	call   rax
   14000259f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025a6:	e9 bf 00 00 00       	jmp    14000266a <__mingw_SEH_error_handler+0x24a>
   1400025ab:	ba 00 00 00 00       	mov    edx,0x0
   1400025b0:	b9 04 00 00 00       	mov    ecx,0x4
   1400025b5:	e8 de 0c 00 00       	call   140003298 <signal>
   1400025ba:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025be:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025c3:	75 1b                	jne    1400025e0 <__mingw_SEH_error_handler+0x1c0>
   1400025c5:	ba 01 00 00 00       	mov    edx,0x1
   1400025ca:	b9 04 00 00 00       	mov    ecx,0x4
   1400025cf:	e8 c4 0c 00 00       	call   140003298 <signal>
   1400025d4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025db:	e9 8d 00 00 00       	jmp    14000266d <__mingw_SEH_error_handler+0x24d>
   1400025e0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025e5:	0f 84 82 00 00 00    	je     14000266d <__mingw_SEH_error_handler+0x24d>
   1400025eb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025ef:	b9 04 00 00 00       	mov    ecx,0x4
   1400025f4:	ff d0                	call   rax
   1400025f6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025fd:	eb 6e                	jmp    14000266d <__mingw_SEH_error_handler+0x24d>
   1400025ff:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002606:	ba 00 00 00 00       	mov    edx,0x0
   14000260b:	b9 08 00 00 00       	mov    ecx,0x8
   140002610:	e8 83 0c 00 00       	call   140003298 <signal>
   140002615:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002619:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000261e:	75 23                	jne    140002643 <__mingw_SEH_error_handler+0x223>
   140002620:	ba 01 00 00 00       	mov    edx,0x1
   140002625:	b9 08 00 00 00       	mov    ecx,0x8
   14000262a:	e8 69 0c 00 00       	call   140003298 <signal>
   14000262f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002633:	74 05                	je     14000263a <__mingw_SEH_error_handler+0x21a>
   140002635:	e8 a6 05 00 00       	call   140002be0 <_fpreset>
   14000263a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002641:	eb 2d                	jmp    140002670 <__mingw_SEH_error_handler+0x250>
   140002643:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002648:	74 26                	je     140002670 <__mingw_SEH_error_handler+0x250>
   14000264a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000264e:	b9 08 00 00 00       	mov    ecx,0x8
   140002653:	ff d0                	call   rax
   140002655:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000265c:	eb 12                	jmp    140002670 <__mingw_SEH_error_handler+0x250>
   14000265e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002665:	eb 0a                	jmp    140002671 <__mingw_SEH_error_handler+0x251>
   140002667:	90                   	nop
   140002668:	eb 07                	jmp    140002671 <__mingw_SEH_error_handler+0x251>
   14000266a:	90                   	nop
   14000266b:	eb 04                	jmp    140002671 <__mingw_SEH_error_handler+0x251>
   14000266d:	90                   	nop
   14000266e:	eb 01                	jmp    140002671 <__mingw_SEH_error_handler+0x251>
   140002670:	90                   	nop
   140002671:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002674:	48 83 c4 30          	add    rsp,0x30
   140002678:	5d                   	pop    rbp
   140002679:	c3                   	ret

000000014000267a <_gnu_exception_handler>:
   14000267a:	55                   	push   rbp
   14000267b:	48 89 e5             	mov    rbp,rsp
   14000267e:	48 83 ec 30          	sub    rsp,0x30
   140002682:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002686:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000268d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002694:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002698:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000269b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000269d:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400026a2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400026a7:	75 1b                	jne    1400026c4 <_gnu_exception_handler+0x4a>
   1400026a9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026ad:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026b0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400026b3:	83 e0 01             	and    eax,0x1
   1400026b6:	85 c0                	test   eax,eax
   1400026b8:	75 0a                	jne    1400026c4 <_gnu_exception_handler+0x4a>
   1400026ba:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400026bf:	e9 14 02 00 00       	jmp    1400028d8 <_gnu_exception_handler+0x25e>
   1400026c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026c8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026cb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026cd:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026d2:	0f 84 12 01 00 00    	je     1400027ea <_gnu_exception_handler+0x170>
   1400026d8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026dd:	0f 87 c3 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   1400026e3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400026e8:	0f 87 b8 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   1400026ee:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400026f3:	0f 83 4c 01 00 00    	jae    140002845 <_gnu_exception_handler+0x1cb>
   1400026f9:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400026fe:	0f 84 3a 01 00 00    	je     14000283e <_gnu_exception_handler+0x1c4>
   140002704:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002709:	0f 87 97 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   14000270f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002714:	0f 84 83 01 00 00    	je     14000289d <_gnu_exception_handler+0x223>
   14000271a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000271f:	0f 87 81 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   140002725:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000272a:	0f 87 76 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   140002730:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002735:	0f 83 03 01 00 00    	jae    14000283e <_gnu_exception_handler+0x1c4>
   14000273b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002740:	0f 84 57 01 00 00    	je     14000289d <_gnu_exception_handler+0x223>
   140002746:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000274b:	0f 87 55 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   140002751:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002756:	0f 84 8e 00 00 00    	je     1400027ea <_gnu_exception_handler+0x170>
   14000275c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002761:	0f 87 3f 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   140002767:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000276c:	0f 84 2b 01 00 00    	je     14000289d <_gnu_exception_handler+0x223>
   140002772:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002777:	0f 87 29 01 00 00    	ja     1400028a6 <_gnu_exception_handler+0x22c>
   14000277d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002782:	0f 84 15 01 00 00    	je     14000289d <_gnu_exception_handler+0x223>
   140002788:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000278d:	0f 85 13 01 00 00    	jne    1400028a6 <_gnu_exception_handler+0x22c>
   140002793:	ba 00 00 00 00       	mov    edx,0x0
   140002798:	b9 0b 00 00 00       	mov    ecx,0xb
   14000279d:	e8 f6 0a 00 00       	call   140003298 <signal>
   1400027a2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027a6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027ab:	75 1b                	jne    1400027c8 <_gnu_exception_handler+0x14e>
   1400027ad:	ba 01 00 00 00       	mov    edx,0x1
   1400027b2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027b7:	e8 dc 0a 00 00       	call   140003298 <signal>
   1400027bc:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027c3:	e9 e1 00 00 00       	jmp    1400028a9 <_gnu_exception_handler+0x22f>
   1400027c8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027cd:	0f 84 d6 00 00 00    	je     1400028a9 <_gnu_exception_handler+0x22f>
   1400027d3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027d7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027dc:	ff d0                	call   rax
   1400027de:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027e5:	e9 bf 00 00 00       	jmp    1400028a9 <_gnu_exception_handler+0x22f>
   1400027ea:	ba 00 00 00 00       	mov    edx,0x0
   1400027ef:	b9 04 00 00 00       	mov    ecx,0x4
   1400027f4:	e8 9f 0a 00 00       	call   140003298 <signal>
   1400027f9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027fd:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002802:	75 1b                	jne    14000281f <_gnu_exception_handler+0x1a5>
   140002804:	ba 01 00 00 00       	mov    edx,0x1
   140002809:	b9 04 00 00 00       	mov    ecx,0x4
   14000280e:	e8 85 0a 00 00       	call   140003298 <signal>
   140002813:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000281a:	e9 8d 00 00 00       	jmp    1400028ac <_gnu_exception_handler+0x232>
   14000281f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002824:	0f 84 82 00 00 00    	je     1400028ac <_gnu_exception_handler+0x232>
   14000282a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000282e:	b9 04 00 00 00       	mov    ecx,0x4
   140002833:	ff d0                	call   rax
   140002835:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000283c:	eb 6e                	jmp    1400028ac <_gnu_exception_handler+0x232>
   14000283e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002845:	ba 00 00 00 00       	mov    edx,0x0
   14000284a:	b9 08 00 00 00       	mov    ecx,0x8
   14000284f:	e8 44 0a 00 00       	call   140003298 <signal>
   140002854:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002858:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000285d:	75 23                	jne    140002882 <_gnu_exception_handler+0x208>
   14000285f:	ba 01 00 00 00       	mov    edx,0x1
   140002864:	b9 08 00 00 00       	mov    ecx,0x8
   140002869:	e8 2a 0a 00 00       	call   140003298 <signal>
   14000286e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002872:	74 05                	je     140002879 <_gnu_exception_handler+0x1ff>
   140002874:	e8 67 03 00 00       	call   140002be0 <_fpreset>
   140002879:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002880:	eb 2d                	jmp    1400028af <_gnu_exception_handler+0x235>
   140002882:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002887:	74 26                	je     1400028af <_gnu_exception_handler+0x235>
   140002889:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000288d:	b9 08 00 00 00       	mov    ecx,0x8
   140002892:	ff d0                	call   rax
   140002894:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000289b:	eb 12                	jmp    1400028af <_gnu_exception_handler+0x235>
   14000289d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028a4:	eb 0a                	jmp    1400028b0 <_gnu_exception_handler+0x236>
   1400028a6:	90                   	nop
   1400028a7:	eb 07                	jmp    1400028b0 <_gnu_exception_handler+0x236>
   1400028a9:	90                   	nop
   1400028aa:	eb 04                	jmp    1400028b0 <_gnu_exception_handler+0x236>
   1400028ac:	90                   	nop
   1400028ad:	eb 01                	jmp    1400028b0 <_gnu_exception_handler+0x236>
   1400028af:	90                   	nop
   1400028b0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400028b4:	75 1f                	jne    1400028d5 <_gnu_exception_handler+0x25b>
   1400028b6:	48 8b 05 53 68 00 00 	mov    rax,QWORD PTR [rip+0x6853]        # 140009110 <__mingw_oldexcpt_handler>
   1400028bd:	48 85 c0             	test   rax,rax
   1400028c0:	74 13                	je     1400028d5 <_gnu_exception_handler+0x25b>
   1400028c2:	48 8b 15 47 68 00 00 	mov    rdx,QWORD PTR [rip+0x6847]        # 140009110 <__mingw_oldexcpt_handler>
   1400028c9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028cd:	48 89 c1             	mov    rcx,rax
   1400028d0:	ff d2                	call   rdx
   1400028d2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400028d5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400028d8:	48 83 c4 30          	add    rsp,0x30
   1400028dc:	5d                   	pop    rbp
   1400028dd:	c3                   	ret
   1400028de:	90                   	nop
   1400028df:	90                   	nop

00000001400028e0 <___w64_mingwthr_add_key_dtor>:
   1400028e0:	55                   	push   rbp
   1400028e1:	48 89 e5             	mov    rbp,rsp
   1400028e4:	48 83 ec 30          	sub    rsp,0x30
   1400028e8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400028eb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400028ef:	8b 05 53 68 00 00    	mov    eax,DWORD PTR [rip+0x6853]        # 140009148 <__mingwthr_cs_init>
   1400028f5:	85 c0                	test   eax,eax
   1400028f7:	75 07                	jne    140002900 <___w64_mingwthr_add_key_dtor+0x20>
   1400028f9:	b8 00 00 00 00       	mov    eax,0x0
   1400028fe:	eb 7b                	jmp    14000297b <___w64_mingwthr_add_key_dtor+0x9b>
   140002900:	ba 18 00 00 00       	mov    edx,0x18
   140002905:	b9 01 00 00 00       	mov    ecx,0x1
   14000290a:	e8 41 09 00 00       	call   140003250 <calloc>
   14000290f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002913:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002918:	75 07                	jne    140002921 <___w64_mingwthr_add_key_dtor+0x41>
   14000291a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000291f:	eb 5a                	jmp    14000297b <___w64_mingwthr_add_key_dtor+0x9b>
   140002921:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002925:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002928:	89 10                	mov    DWORD PTR [rax],edx
   14000292a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000292e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002932:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002936:	48 8d 05 e3 67 00 00 	lea    rax,[rip+0x67e3]        # 140009120 <__mingwthr_cs>
   14000293d:	48 89 c1             	mov    rcx,rax
   140002940:	48 8b 05 51 78 00 00 	mov    rax,QWORD PTR [rip+0x7851]        # 14000a198 <__imp_EnterCriticalSection>
   140002947:	ff d0                	call   rax
   140002949:	48 8b 15 00 68 00 00 	mov    rdx,QWORD PTR [rip+0x6800]        # 140009150 <key_dtor_list>
   140002950:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002954:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002958:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000295c:	48 89 05 ed 67 00 00 	mov    QWORD PTR [rip+0x67ed],rax        # 140009150 <key_dtor_list>
   140002963:	48 8d 05 b6 67 00 00 	lea    rax,[rip+0x67b6]        # 140009120 <__mingwthr_cs>
   14000296a:	48 89 c1             	mov    rcx,rax
   14000296d:	48 8b 05 54 78 00 00 	mov    rax,QWORD PTR [rip+0x7854]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002974:	ff d0                	call   rax
   140002976:	b8 00 00 00 00       	mov    eax,0x0
   14000297b:	48 83 c4 30          	add    rsp,0x30
   14000297f:	5d                   	pop    rbp
   140002980:	c3                   	ret

0000000140002981 <___w64_mingwthr_remove_key_dtor>:
   140002981:	55                   	push   rbp
   140002982:	48 89 e5             	mov    rbp,rsp
   140002985:	48 83 ec 30          	sub    rsp,0x30
   140002989:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000298c:	8b 05 b6 67 00 00    	mov    eax,DWORD PTR [rip+0x67b6]        # 140009148 <__mingwthr_cs_init>
   140002992:	85 c0                	test   eax,eax
   140002994:	75 0a                	jne    1400029a0 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002996:	b8 00 00 00 00       	mov    eax,0x0
   14000299b:	e9 9c 00 00 00       	jmp    140002a3c <___w64_mingwthr_remove_key_dtor+0xbb>
   1400029a0:	48 8d 05 79 67 00 00 	lea    rax,[rip+0x6779]        # 140009120 <__mingwthr_cs>
   1400029a7:	48 89 c1             	mov    rcx,rax
   1400029aa:	48 8b 05 e7 77 00 00 	mov    rax,QWORD PTR [rip+0x77e7]        # 14000a198 <__imp_EnterCriticalSection>
   1400029b1:	ff d0                	call   rax
   1400029b3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400029ba:	00 
   1400029bb:	48 8b 05 8e 67 00 00 	mov    rax,QWORD PTR [rip+0x678e]        # 140009150 <key_dtor_list>
   1400029c2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029c6:	eb 55                	jmp    140002a1d <___w64_mingwthr_remove_key_dtor+0x9c>
   1400029c8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029cc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400029ce:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   1400029d1:	75 36                	jne    140002a09 <___w64_mingwthr_remove_key_dtor+0x88>
   1400029d3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029d8:	75 11                	jne    1400029eb <___w64_mingwthr_remove_key_dtor+0x6a>
   1400029da:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029de:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   1400029e2:	48 89 05 67 67 00 00 	mov    QWORD PTR [rip+0x6767],rax        # 140009150 <key_dtor_list>
   1400029e9:	eb 10                	jmp    1400029fb <___w64_mingwthr_remove_key_dtor+0x7a>
   1400029eb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ef:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   1400029f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029f7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029fb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ff:	48 89 c1             	mov    rcx,rax
   140002a02:	e8 69 08 00 00       	call   140003270 <free>
   140002a07:	eb 1b                	jmp    140002a24 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a09:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a0d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a11:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a15:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a19:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a1d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a22:	75 a4                	jne    1400029c8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a24:	48 8d 05 f5 66 00 00 	lea    rax,[rip+0x66f5]        # 140009120 <__mingwthr_cs>
   140002a2b:	48 89 c1             	mov    rcx,rax
   140002a2e:	48 8b 05 93 77 00 00 	mov    rax,QWORD PTR [rip+0x7793]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002a35:	ff d0                	call   rax
   140002a37:	b8 00 00 00 00       	mov    eax,0x0
   140002a3c:	48 83 c4 30          	add    rsp,0x30
   140002a40:	5d                   	pop    rbp
   140002a41:	c3                   	ret

0000000140002a42 <__mingwthr_run_key_dtors>:
   140002a42:	55                   	push   rbp
   140002a43:	48 89 e5             	mov    rbp,rsp
   140002a46:	48 83 ec 30          	sub    rsp,0x30
   140002a4a:	8b 05 f8 66 00 00    	mov    eax,DWORD PTR [rip+0x66f8]        # 140009148 <__mingwthr_cs_init>
   140002a50:	85 c0                	test   eax,eax
   140002a52:	0f 84 82 00 00 00    	je     140002ada <__mingwthr_run_key_dtors+0x98>
   140002a58:	48 8d 05 c1 66 00 00 	lea    rax,[rip+0x66c1]        # 140009120 <__mingwthr_cs>
   140002a5f:	48 89 c1             	mov    rcx,rax
   140002a62:	48 8b 05 2f 77 00 00 	mov    rax,QWORD PTR [rip+0x772f]        # 14000a198 <__imp_EnterCriticalSection>
   140002a69:	ff d0                	call   rax
   140002a6b:	48 8b 05 de 66 00 00 	mov    rax,QWORD PTR [rip+0x66de]        # 140009150 <key_dtor_list>
   140002a72:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a76:	eb 46                	jmp    140002abe <__mingwthr_run_key_dtors+0x7c>
   140002a78:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a7c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a7e:	89 c1                	mov    ecx,eax
   140002a80:	48 8b 05 61 77 00 00 	mov    rax,QWORD PTR [rip+0x7761]        # 14000a1e8 <__imp_TlsGetValue>
   140002a87:	ff d0                	call   rax
   140002a89:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a8d:	48 8b 05 14 77 00 00 	mov    rax,QWORD PTR [rip+0x7714]        # 14000a1a8 <__imp_GetLastError>
   140002a94:	ff d0                	call   rax
   140002a96:	85 c0                	test   eax,eax
   140002a98:	75 18                	jne    140002ab2 <__mingwthr_run_key_dtors+0x70>
   140002a9a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a9f:	74 11                	je     140002ab2 <__mingwthr_run_key_dtors+0x70>
   140002aa1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002aa5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002aa9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aad:	48 89 c1             	mov    rcx,rax
   140002ab0:	ff d2                	call   rdx
   140002ab2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ab6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002aba:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002abe:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ac3:	75 b3                	jne    140002a78 <__mingwthr_run_key_dtors+0x36>
   140002ac5:	48 8d 05 54 66 00 00 	lea    rax,[rip+0x6654]        # 140009120 <__mingwthr_cs>
   140002acc:	48 89 c1             	mov    rcx,rax
   140002acf:	48 8b 05 f2 76 00 00 	mov    rax,QWORD PTR [rip+0x76f2]        # 14000a1c8 <__imp_LeaveCriticalSection>
   140002ad6:	ff d0                	call   rax
   140002ad8:	eb 01                	jmp    140002adb <__mingwthr_run_key_dtors+0x99>
   140002ada:	90                   	nop
   140002adb:	48 83 c4 30          	add    rsp,0x30
   140002adf:	5d                   	pop    rbp
   140002ae0:	c3                   	ret

0000000140002ae1 <__mingw_TLScallback>:
   140002ae1:	55                   	push   rbp
   140002ae2:	48 89 e5             	mov    rbp,rsp
   140002ae5:	48 83 ec 30          	sub    rsp,0x30
   140002ae9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002aed:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002af0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002af4:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002af8:	0f 84 cc 00 00 00    	je     140002bca <__mingw_TLScallback+0xe9>
   140002afe:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b02:	0f 87 ca 00 00 00    	ja     140002bd2 <__mingw_TLScallback+0xf1>
   140002b08:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b0c:	0f 84 b1 00 00 00    	je     140002bc3 <__mingw_TLScallback+0xe2>
   140002b12:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b16:	0f 87 b6 00 00 00    	ja     140002bd2 <__mingw_TLScallback+0xf1>
   140002b1c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b20:	74 33                	je     140002b55 <__mingw_TLScallback+0x74>
   140002b22:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b26:	0f 85 a6 00 00 00    	jne    140002bd2 <__mingw_TLScallback+0xf1>
   140002b2c:	8b 05 16 66 00 00    	mov    eax,DWORD PTR [rip+0x6616]        # 140009148 <__mingwthr_cs_init>
   140002b32:	85 c0                	test   eax,eax
   140002b34:	75 13                	jne    140002b49 <__mingw_TLScallback+0x68>
   140002b36:	48 8d 05 e3 65 00 00 	lea    rax,[rip+0x65e3]        # 140009120 <__mingwthr_cs>
   140002b3d:	48 89 c1             	mov    rcx,rax
   140002b40:	48 8b 05 79 76 00 00 	mov    rax,QWORD PTR [rip+0x7679]        # 14000a1c0 <__imp_InitializeCriticalSection>
   140002b47:	ff d0                	call   rax
   140002b49:	c7 05 f5 65 00 00 01 	mov    DWORD PTR [rip+0x65f5],0x1        # 140009148 <__mingwthr_cs_init>
   140002b50:	00 00 00 
   140002b53:	eb 7d                	jmp    140002bd2 <__mingw_TLScallback+0xf1>
   140002b55:	e8 e8 fe ff ff       	call   140002a42 <__mingwthr_run_key_dtors>
   140002b5a:	8b 05 e8 65 00 00    	mov    eax,DWORD PTR [rip+0x65e8]        # 140009148 <__mingwthr_cs_init>
   140002b60:	83 f8 01             	cmp    eax,0x1
   140002b63:	75 6c                	jne    140002bd1 <__mingw_TLScallback+0xf0>
   140002b65:	48 8b 05 e4 65 00 00 	mov    rax,QWORD PTR [rip+0x65e4]        # 140009150 <key_dtor_list>
   140002b6c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b70:	eb 20                	jmp    140002b92 <__mingw_TLScallback+0xb1>
   140002b72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b76:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b7a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b7e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b82:	48 89 c1             	mov    rcx,rax
   140002b85:	e8 e6 06 00 00       	call   140003270 <free>
   140002b8a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b8e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b92:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b97:	75 d9                	jne    140002b72 <__mingw_TLScallback+0x91>
   140002b99:	48 c7 05 ac 65 00 00 	mov    QWORD PTR [rip+0x65ac],0x0        # 140009150 <key_dtor_list>
   140002ba0:	00 00 00 00 
   140002ba4:	c7 05 9a 65 00 00 00 	mov    DWORD PTR [rip+0x659a],0x0        # 140009148 <__mingwthr_cs_init>
   140002bab:	00 00 00 
   140002bae:	48 8d 05 6b 65 00 00 	lea    rax,[rip+0x656b]        # 140009120 <__mingwthr_cs>
   140002bb5:	48 89 c1             	mov    rcx,rax
   140002bb8:	48 8b 05 d1 75 00 00 	mov    rax,QWORD PTR [rip+0x75d1]        # 14000a190 <__IAT_start__>
   140002bbf:	ff d0                	call   rax
   140002bc1:	eb 0e                	jmp    140002bd1 <__mingw_TLScallback+0xf0>
   140002bc3:	e8 18 00 00 00       	call   140002be0 <_fpreset>
   140002bc8:	eb 08                	jmp    140002bd2 <__mingw_TLScallback+0xf1>
   140002bca:	e8 73 fe ff ff       	call   140002a42 <__mingwthr_run_key_dtors>
   140002bcf:	eb 01                	jmp    140002bd2 <__mingw_TLScallback+0xf1>
   140002bd1:	90                   	nop
   140002bd2:	b8 01 00 00 00       	mov    eax,0x1
   140002bd7:	48 83 c4 30          	add    rsp,0x30
   140002bdb:	5d                   	pop    rbp
   140002bdc:	c3                   	ret
   140002bdd:	90                   	nop
   140002bde:	90                   	nop
   140002bdf:	90                   	nop

0000000140002be0 <_fpreset>:
   140002be0:	55                   	push   rbp
   140002be1:	48 89 e5             	mov    rbp,rsp
   140002be4:	db e3                	fninit
   140002be6:	90                   	nop
   140002be7:	5d                   	pop    rbp
   140002be8:	c3                   	ret
   140002be9:	90                   	nop
   140002bea:	90                   	nop
   140002beb:	90                   	nop
   140002bec:	90                   	nop
   140002bed:	90                   	nop
   140002bee:	90                   	nop
   140002bef:	90                   	nop

0000000140002bf0 <_ValidateImageBase>:
   140002bf0:	55                   	push   rbp
   140002bf1:	48 89 e5             	mov    rbp,rsp
   140002bf4:	48 83 ec 20          	sub    rsp,0x20
   140002bf8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002bfc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c00:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c04:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c08:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c0b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c0f:	74 07                	je     140002c18 <_ValidateImageBase+0x28>
   140002c11:	b8 00 00 00 00       	mov    eax,0x0
   140002c16:	eb 4e                	jmp    140002c66 <_ValidateImageBase+0x76>
   140002c18:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c1c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c1f:	48 63 d0             	movsxd rdx,eax
   140002c22:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c26:	48 01 d0             	add    rax,rdx
   140002c29:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c2d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c31:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c33:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c38:	74 07                	je     140002c41 <_ValidateImageBase+0x51>
   140002c3a:	b8 00 00 00 00       	mov    eax,0x0
   140002c3f:	eb 25                	jmp    140002c66 <_ValidateImageBase+0x76>
   140002c41:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c45:	48 83 c0 18          	add    rax,0x18
   140002c49:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c4d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c51:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c54:	66 3d 0b 02          	cmp    ax,0x20b
   140002c58:	74 07                	je     140002c61 <_ValidateImageBase+0x71>
   140002c5a:	b8 00 00 00 00       	mov    eax,0x0
   140002c5f:	eb 05                	jmp    140002c66 <_ValidateImageBase+0x76>
   140002c61:	b8 01 00 00 00       	mov    eax,0x1
   140002c66:	48 83 c4 20          	add    rsp,0x20
   140002c6a:	5d                   	pop    rbp
   140002c6b:	c3                   	ret

0000000140002c6c <_FindPESection>:
   140002c6c:	55                   	push   rbp
   140002c6d:	48 89 e5             	mov    rbp,rsp
   140002c70:	48 83 ec 20          	sub    rsp,0x20
   140002c74:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c78:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002c7c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c80:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c83:	48 63 d0             	movsxd rdx,eax
   140002c86:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c8a:	48 01 d0             	add    rax,rdx
   140002c8d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c91:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002c98:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c9c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002ca0:	0f b7 d0             	movzx  edx,ax
   140002ca3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ca7:	48 01 d0             	add    rax,rdx
   140002caa:	48 83 c0 18          	add    rax,0x18
   140002cae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cb2:	eb 36                	jmp    140002cea <_FindPESection+0x7e>
   140002cb4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cb8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002cbb:	89 c0                	mov    eax,eax
   140002cbd:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cc1:	72 1e                	jb     140002ce1 <_FindPESection+0x75>
   140002cc3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cc7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002cca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cce:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002cd1:	01 d0                	add    eax,edx
   140002cd3:	89 c0                	mov    eax,eax
   140002cd5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cd9:	73 06                	jae    140002ce1 <_FindPESection+0x75>
   140002cdb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cdf:	eb 1e                	jmp    140002cff <_FindPESection+0x93>
   140002ce1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002ce5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002cea:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cee:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002cf2:	0f b7 c0             	movzx  eax,ax
   140002cf5:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002cf8:	72 ba                	jb     140002cb4 <_FindPESection+0x48>
   140002cfa:	b8 00 00 00 00       	mov    eax,0x0
   140002cff:	48 83 c4 20          	add    rsp,0x20
   140002d03:	5d                   	pop    rbp
   140002d04:	c3                   	ret

0000000140002d05 <_FindPESectionByName>:
   140002d05:	55                   	push   rbp
   140002d06:	48 89 e5             	mov    rbp,rsp
   140002d09:	48 83 ec 40          	sub    rsp,0x40
   140002d0d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d11:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d15:	48 89 c1             	mov    rcx,rax
   140002d18:	e8 83 05 00 00       	call   1400032a0 <strlen>
   140002d1d:	48 83 f8 08          	cmp    rax,0x8
   140002d21:	76 0a                	jbe    140002d2d <_FindPESectionByName+0x28>
   140002d23:	b8 00 00 00 00       	mov    eax,0x0
   140002d28:	e9 98 00 00 00       	jmp    140002dc5 <_FindPESectionByName+0xc0>
   140002d2d:	48 8b 05 2c 26 00 00 	mov    rax,QWORD PTR [rip+0x262c]        # 140005360 <.refptr.__ImageBase>
   140002d34:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d38:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d3c:	48 89 c1             	mov    rcx,rax
   140002d3f:	e8 ac fe ff ff       	call   140002bf0 <_ValidateImageBase>
   140002d44:	85 c0                	test   eax,eax
   140002d46:	75 07                	jne    140002d4f <_FindPESectionByName+0x4a>
   140002d48:	b8 00 00 00 00       	mov    eax,0x0
   140002d4d:	eb 76                	jmp    140002dc5 <_FindPESectionByName+0xc0>
   140002d4f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d53:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d56:	48 63 d0             	movsxd rdx,eax
   140002d59:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d5d:	48 01 d0             	add    rax,rdx
   140002d60:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002d64:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d6b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d6f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d73:	0f b7 d0             	movzx  edx,ax
   140002d76:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d7a:	48 01 d0             	add    rax,rdx
   140002d7d:	48 83 c0 18          	add    rax,0x18
   140002d81:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d85:	eb 29                	jmp    140002db0 <_FindPESectionByName+0xab>
   140002d87:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d8b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002d8f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002d95:	48 89 c1             	mov    rcx,rax
   140002d98:	e8 0b 05 00 00       	call   1400032a8 <strncmp>
   140002d9d:	85 c0                	test   eax,eax
   140002d9f:	75 06                	jne    140002da7 <_FindPESectionByName+0xa2>
   140002da1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002da5:	eb 1e                	jmp    140002dc5 <_FindPESectionByName+0xc0>
   140002da7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002dab:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002db0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002db4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002db8:	0f b7 c0             	movzx  eax,ax
   140002dbb:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002dbe:	72 c7                	jb     140002d87 <_FindPESectionByName+0x82>
   140002dc0:	b8 00 00 00 00       	mov    eax,0x0
   140002dc5:	48 83 c4 40          	add    rsp,0x40
   140002dc9:	5d                   	pop    rbp
   140002dca:	c3                   	ret

0000000140002dcb <__mingw_GetSectionForAddress>:
   140002dcb:	55                   	push   rbp
   140002dcc:	48 89 e5             	mov    rbp,rsp
   140002dcf:	48 83 ec 30          	sub    rsp,0x30
   140002dd3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002dd7:	48 8b 05 82 25 00 00 	mov    rax,QWORD PTR [rip+0x2582]        # 140005360 <.refptr.__ImageBase>
   140002dde:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002de2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002de6:	48 89 c1             	mov    rcx,rax
   140002de9:	e8 02 fe ff ff       	call   140002bf0 <_ValidateImageBase>
   140002dee:	85 c0                	test   eax,eax
   140002df0:	75 07                	jne    140002df9 <__mingw_GetSectionForAddress+0x2e>
   140002df2:	b8 00 00 00 00       	mov    eax,0x0
   140002df7:	eb 1c                	jmp    140002e15 <__mingw_GetSectionForAddress+0x4a>
   140002df9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002dfd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e01:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e05:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e09:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e0d:	48 89 c1             	mov    rcx,rax
   140002e10:	e8 57 fe ff ff       	call   140002c6c <_FindPESection>
   140002e15:	48 83 c4 30          	add    rsp,0x30
   140002e19:	5d                   	pop    rbp
   140002e1a:	c3                   	ret

0000000140002e1b <__mingw_GetSectionCount>:
   140002e1b:	55                   	push   rbp
   140002e1c:	48 89 e5             	mov    rbp,rsp
   140002e1f:	48 83 ec 30          	sub    rsp,0x30
   140002e23:	48 8b 05 36 25 00 00 	mov    rax,QWORD PTR [rip+0x2536]        # 140005360 <.refptr.__ImageBase>
   140002e2a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e2e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e32:	48 89 c1             	mov    rcx,rax
   140002e35:	e8 b6 fd ff ff       	call   140002bf0 <_ValidateImageBase>
   140002e3a:	85 c0                	test   eax,eax
   140002e3c:	75 07                	jne    140002e45 <__mingw_GetSectionCount+0x2a>
   140002e3e:	b8 00 00 00 00       	mov    eax,0x0
   140002e43:	eb 20                	jmp    140002e65 <__mingw_GetSectionCount+0x4a>
   140002e45:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e49:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e4c:	48 63 d0             	movsxd rdx,eax
   140002e4f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e53:	48 01 d0             	add    rax,rdx
   140002e56:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e5e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e62:	0f b7 c0             	movzx  eax,ax
   140002e65:	48 83 c4 30          	add    rsp,0x30
   140002e69:	5d                   	pop    rbp
   140002e6a:	c3                   	ret

0000000140002e6b <_FindPESectionExec>:
   140002e6b:	55                   	push   rbp
   140002e6c:	48 89 e5             	mov    rbp,rsp
   140002e6f:	48 83 ec 40          	sub    rsp,0x40
   140002e73:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e77:	48 8b 05 e2 24 00 00 	mov    rax,QWORD PTR [rip+0x24e2]        # 140005360 <.refptr.__ImageBase>
   140002e7e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e82:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e86:	48 89 c1             	mov    rcx,rax
   140002e89:	e8 62 fd ff ff       	call   140002bf0 <_ValidateImageBase>
   140002e8e:	85 c0                	test   eax,eax
   140002e90:	75 07                	jne    140002e99 <_FindPESectionExec+0x2e>
   140002e92:	b8 00 00 00 00       	mov    eax,0x0
   140002e97:	eb 78                	jmp    140002f11 <_FindPESectionExec+0xa6>
   140002e99:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e9d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ea0:	48 63 d0             	movsxd rdx,eax
   140002ea3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ea7:	48 01 d0             	add    rax,rdx
   140002eaa:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002eae:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002eb5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002eb9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002ebd:	0f b7 d0             	movzx  edx,ax
   140002ec0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ec4:	48 01 d0             	add    rax,rdx
   140002ec7:	48 83 c0 18          	add    rax,0x18
   140002ecb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ecf:	eb 2b                	jmp    140002efc <_FindPESectionExec+0x91>
   140002ed1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ed5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002ed8:	25 00 00 00 20       	and    eax,0x20000000
   140002edd:	85 c0                	test   eax,eax
   140002edf:	74 12                	je     140002ef3 <_FindPESectionExec+0x88>
   140002ee1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002ee6:	75 06                	jne    140002eee <_FindPESectionExec+0x83>
   140002ee8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002eec:	eb 23                	jmp    140002f11 <_FindPESectionExec+0xa6>
   140002eee:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002ef3:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002ef7:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002efc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f00:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f04:	0f b7 c0             	movzx  eax,ax
   140002f07:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f0a:	72 c5                	jb     140002ed1 <_FindPESectionExec+0x66>
   140002f0c:	b8 00 00 00 00       	mov    eax,0x0
   140002f11:	48 83 c4 40          	add    rsp,0x40
   140002f15:	5d                   	pop    rbp
   140002f16:	c3                   	ret

0000000140002f17 <_GetPEImageBase>:
   140002f17:	55                   	push   rbp
   140002f18:	48 89 e5             	mov    rbp,rsp
   140002f1b:	48 83 ec 30          	sub    rsp,0x30
   140002f1f:	48 8b 05 3a 24 00 00 	mov    rax,QWORD PTR [rip+0x243a]        # 140005360 <.refptr.__ImageBase>
   140002f26:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f2a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f2e:	48 89 c1             	mov    rcx,rax
   140002f31:	e8 ba fc ff ff       	call   140002bf0 <_ValidateImageBase>
   140002f36:	85 c0                	test   eax,eax
   140002f38:	75 07                	jne    140002f41 <_GetPEImageBase+0x2a>
   140002f3a:	b8 00 00 00 00       	mov    eax,0x0
   140002f3f:	eb 04                	jmp    140002f45 <_GetPEImageBase+0x2e>
   140002f41:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f45:	48 83 c4 30          	add    rsp,0x30
   140002f49:	5d                   	pop    rbp
   140002f4a:	c3                   	ret

0000000140002f4b <_IsNonwritableInCurrentImage>:
   140002f4b:	55                   	push   rbp
   140002f4c:	48 89 e5             	mov    rbp,rsp
   140002f4f:	48 83 ec 40          	sub    rsp,0x40
   140002f53:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f57:	48 8b 05 02 24 00 00 	mov    rax,QWORD PTR [rip+0x2402]        # 140005360 <.refptr.__ImageBase>
   140002f5e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f62:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f66:	48 89 c1             	mov    rcx,rax
   140002f69:	e8 82 fc ff ff       	call   140002bf0 <_ValidateImageBase>
   140002f6e:	85 c0                	test   eax,eax
   140002f70:	75 07                	jne    140002f79 <_IsNonwritableInCurrentImage+0x2e>
   140002f72:	b8 00 00 00 00       	mov    eax,0x0
   140002f77:	eb 3d                	jmp    140002fb6 <_IsNonwritableInCurrentImage+0x6b>
   140002f79:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f7d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002f81:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f85:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002f89:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f8d:	48 89 c1             	mov    rcx,rax
   140002f90:	e8 d7 fc ff ff       	call   140002c6c <_FindPESection>
   140002f95:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f99:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002f9e:	75 07                	jne    140002fa7 <_IsNonwritableInCurrentImage+0x5c>
   140002fa0:	b8 00 00 00 00       	mov    eax,0x0
   140002fa5:	eb 0f                	jmp    140002fb6 <_IsNonwritableInCurrentImage+0x6b>
   140002fa7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002fab:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fae:	f7 d0                	not    eax
   140002fb0:	c1 e8 1f             	shr    eax,0x1f
   140002fb3:	0f b6 c0             	movzx  eax,al
   140002fb6:	48 83 c4 40          	add    rsp,0x40
   140002fba:	5d                   	pop    rbp
   140002fbb:	c3                   	ret

0000000140002fbc <__mingw_enum_import_library_names>:
   140002fbc:	55                   	push   rbp
   140002fbd:	48 89 e5             	mov    rbp,rsp
   140002fc0:	48 83 ec 50          	sub    rsp,0x50
   140002fc4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002fc7:	48 8b 05 92 23 00 00 	mov    rax,QWORD PTR [rip+0x2392]        # 140005360 <.refptr.__ImageBase>
   140002fce:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fd2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fd6:	48 89 c1             	mov    rcx,rax
   140002fd9:	e8 12 fc ff ff       	call   140002bf0 <_ValidateImageBase>
   140002fde:	85 c0                	test   eax,eax
   140002fe0:	75 0a                	jne    140002fec <__mingw_enum_import_library_names+0x30>
   140002fe2:	b8 00 00 00 00       	mov    eax,0x0
   140002fe7:	e9 ab 00 00 00       	jmp    140003097 <__mingw_enum_import_library_names+0xdb>
   140002fec:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ff0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ff3:	48 63 d0             	movsxd rdx,eax
   140002ff6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ffa:	48 01 d0             	add    rax,rdx
   140002ffd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003001:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003005:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000300b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000300e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003012:	75 07                	jne    14000301b <__mingw_enum_import_library_names+0x5f>
   140003014:	b8 00 00 00 00       	mov    eax,0x0
   140003019:	eb 7c                	jmp    140003097 <__mingw_enum_import_library_names+0xdb>
   14000301b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000301e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003022:	48 89 c1             	mov    rcx,rax
   140003025:	e8 42 fc ff ff       	call   140002c6c <_FindPESection>
   14000302a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000302e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003033:	75 07                	jne    14000303c <__mingw_enum_import_library_names+0x80>
   140003035:	b8 00 00 00 00       	mov    eax,0x0
   14000303a:	eb 5b                	jmp    140003097 <__mingw_enum_import_library_names+0xdb>
   14000303c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000303f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003043:	48 01 d0             	add    rax,rdx
   140003046:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000304a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000304f:	75 07                	jne    140003058 <__mingw_enum_import_library_names+0x9c>
   140003051:	b8 00 00 00 00       	mov    eax,0x0
   140003056:	eb 3f                	jmp    140003097 <__mingw_enum_import_library_names+0xdb>
   140003058:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000305c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000305f:	85 c0                	test   eax,eax
   140003061:	75 0b                	jne    14000306e <__mingw_enum_import_library_names+0xb2>
   140003063:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003067:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000306a:	85 c0                	test   eax,eax
   14000306c:	74 23                	je     140003091 <__mingw_enum_import_library_names+0xd5>
   14000306e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003072:	7f 12                	jg     140003086 <__mingw_enum_import_library_names+0xca>
   140003074:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003078:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000307b:	89 c2                	mov    edx,eax
   14000307d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003081:	48 01 d0             	add    rax,rdx
   140003084:	eb 11                	jmp    140003097 <__mingw_enum_import_library_names+0xdb>
   140003086:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000308a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000308f:	eb c7                	jmp    140003058 <__mingw_enum_import_library_names+0x9c>
   140003091:	90                   	nop
   140003092:	b8 00 00 00 00       	mov    eax,0x0
   140003097:	48 83 c4 50          	add    rsp,0x50
   14000309b:	5d                   	pop    rbp
   14000309c:	c3                   	ret
   14000309d:	90                   	nop
   14000309e:	90                   	nop
   14000309f:	90                   	nop

00000001400030a0 <___chkstk_ms>:
   1400030a0:	51                   	push   rcx
   1400030a1:	50                   	push   rax
   1400030a2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030a8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400030ad:	72 19                	jb     1400030c8 <___chkstk_ms+0x28>
   1400030af:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400030b6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030ba:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400030c0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030c6:	77 e7                	ja     1400030af <___chkstk_ms+0xf>
   1400030c8:	48 29 c1             	sub    rcx,rax
   1400030cb:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030cf:	58                   	pop    rax
   1400030d0:	59                   	pop    rcx
   1400030d1:	c3                   	ret
   1400030d2:	90                   	nop
   1400030d3:	90                   	nop
   1400030d4:	90                   	nop
   1400030d5:	90                   	nop
   1400030d6:	90                   	nop
   1400030d7:	90                   	nop
   1400030d8:	90                   	nop
   1400030d9:	90                   	nop
   1400030da:	90                   	nop
   1400030db:	90                   	nop
   1400030dc:	90                   	nop
   1400030dd:	90                   	nop
   1400030de:	90                   	nop
   1400030df:	90                   	nop

00000001400030e0 <_initterm_e>:
   1400030e0:	55                   	push   rbp
   1400030e1:	48 89 e5             	mov    rbp,rsp
   1400030e4:	48 83 ec 30          	sub    rsp,0x30
   1400030e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400030ec:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400030f0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400030f4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030f8:	eb 29                	jmp    140003123 <_initterm_e+0x43>
   1400030fa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030fe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140003101:	48 85 c0             	test   rax,rax
   140003104:	74 17                	je     14000311d <_initterm_e+0x3d>
   140003106:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000310a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000310d:	ff d0                	call   rax
   14000310f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003112:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003116:	74 06                	je     14000311e <_initterm_e+0x3e>
   140003118:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000311b:	eb 15                	jmp    140003132 <_initterm_e+0x52>
   14000311d:	90                   	nop
   14000311e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140003123:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003127:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   14000312b:	72 cd                	jb     1400030fa <_initterm_e+0x1a>
   14000312d:	b8 00 00 00 00       	mov    eax,0x0
   140003132:	48 83 c4 30          	add    rsp,0x30
   140003136:	5d                   	pop    rbp
   140003137:	c3                   	ret
   140003138:	90                   	nop
   140003139:	90                   	nop
   14000313a:	90                   	nop
   14000313b:	90                   	nop
   14000313c:	90                   	nop
   14000313d:	90                   	nop
   14000313e:	90                   	nop
   14000313f:	90                   	nop

0000000140003140 <__p__fmode>:
   140003140:	55                   	push   rbp
   140003141:	48 89 e5             	mov    rbp,rsp
   140003144:	48 8b 05 85 22 00 00 	mov    rax,QWORD PTR [rip+0x2285]        # 1400053d0 <.refptr.__imp__fmode>
   14000314b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000314e:	5d                   	pop    rbp
   14000314f:	c3                   	ret

0000000140003150 <__p__commode>:
   140003150:	55                   	push   rbp
   140003151:	48 89 e5             	mov    rbp,rsp
   140003154:	48 8b 05 65 22 00 00 	mov    rax,QWORD PTR [rip+0x2265]        # 1400053c0 <.refptr.__imp__commode>
   14000315b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000315e:	5d                   	pop    rbp
   14000315f:	c3                   	ret

0000000140003160 <__p___initenv>:
   140003160:	55                   	push   rbp
   140003161:	48 89 e5             	mov    rbp,rsp
   140003164:	48 8b 05 45 22 00 00 	mov    rax,QWORD PTR [rip+0x2245]        # 1400053b0 <.refptr.__imp___initenv>
   14000316b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000316e:	5d                   	pop    rbp
   14000316f:	c3                   	ret

0000000140003170 <_set_invalid_parameter_handler>:
   140003170:	55                   	push   rbp
   140003171:	48 89 e5             	mov    rbp,rsp
   140003174:	48 83 ec 10          	sub    rsp,0x10
   140003178:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000317c:	48 8d 05 0d 60 00 00 	lea    rax,[rip+0x600d]        # 140009190 <handler>
   140003183:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003187:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000318b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000318f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003193:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003197:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000319a:	48 89 d0             	mov    rax,rdx
   14000319d:	48 83 c4 10          	add    rsp,0x10
   1400031a1:	5d                   	pop    rbp
   1400031a2:	c3                   	ret

00000001400031a3 <_get_invalid_parameter_handler>:
   1400031a3:	55                   	push   rbp
   1400031a4:	48 89 e5             	mov    rbp,rsp
   1400031a7:	48 8b 05 e2 5f 00 00 	mov    rax,QWORD PTR [rip+0x5fe2]        # 140009190 <handler>
   1400031ae:	5d                   	pop    rbp
   1400031af:	c3                   	ret

00000001400031b0 <_configthreadlocale>:
   1400031b0:	55                   	push   rbp
   1400031b1:	48 89 e5             	mov    rbp,rsp
   1400031b4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031b7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   1400031bb:	75 07                	jne    1400031c4 <_configthreadlocale+0x14>
   1400031bd:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400031c2:	eb 05                	jmp    1400031c9 <_configthreadlocale+0x19>
   1400031c4:	b8 02 00 00 00       	mov    eax,0x2
   1400031c9:	5d                   	pop    rbp
   1400031ca:	c3                   	ret
   1400031cb:	90                   	nop
   1400031cc:	90                   	nop
   1400031cd:	90                   	nop
   1400031ce:	90                   	nop
   1400031cf:	90                   	nop

00000001400031d0 <__acrt_iob_func>:
   1400031d0:	55                   	push   rbp
   1400031d1:	48 89 e5             	mov    rbp,rsp
   1400031d4:	48 83 ec 20          	sub    rsp,0x20
   1400031d8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031db:	e8 30 00 00 00       	call   140003210 <__iob_func>
   1400031e0:	48 89 c1             	mov    rcx,rax
   1400031e3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400031e6:	48 89 d0             	mov    rax,rdx
   1400031e9:	48 01 c0             	add    rax,rax
   1400031ec:	48 01 d0             	add    rax,rdx
   1400031ef:	48 c1 e0 04          	shl    rax,0x4
   1400031f3:	48 01 c8             	add    rax,rcx
   1400031f6:	48 83 c4 20          	add    rsp,0x20
   1400031fa:	5d                   	pop    rbp
   1400031fb:	c3                   	ret
   1400031fc:	90                   	nop
   1400031fd:	90                   	nop
   1400031fe:	90                   	nop
   1400031ff:	90                   	nop

0000000140003200 <__C_specific_handler>:
   140003200:	ff 25 02 70 00 00    	jmp    QWORD PTR [rip+0x7002]        # 14000a208 <__imp___C_specific_handler>
   140003206:	90                   	nop
   140003207:	90                   	nop

0000000140003208 <__getmainargs>:
   140003208:	ff 25 02 70 00 00    	jmp    QWORD PTR [rip+0x7002]        # 14000a210 <__imp___getmainargs>
   14000320e:	90                   	nop
   14000320f:	90                   	nop

0000000140003210 <__iob_func>:
   140003210:	ff 25 0a 70 00 00    	jmp    QWORD PTR [rip+0x700a]        # 14000a220 <__imp___iob_func>
   140003216:	90                   	nop
   140003217:	90                   	nop

0000000140003218 <__set_app_type>:
   140003218:	ff 25 0a 70 00 00    	jmp    QWORD PTR [rip+0x700a]        # 14000a228 <__imp___set_app_type>
   14000321e:	90                   	nop
   14000321f:	90                   	nop

0000000140003220 <__setusermatherr>:
   140003220:	ff 25 0a 70 00 00    	jmp    QWORD PTR [rip+0x700a]        # 14000a230 <__imp___setusermatherr>
   140003226:	90                   	nop
   140003227:	90                   	nop

0000000140003228 <_amsg_exit>:
   140003228:	ff 25 0a 70 00 00    	jmp    QWORD PTR [rip+0x700a]        # 14000a238 <__imp__amsg_exit>
   14000322e:	90                   	nop
   14000322f:	90                   	nop

0000000140003230 <_cexit>:
   140003230:	ff 25 0a 70 00 00    	jmp    QWORD PTR [rip+0x700a]        # 14000a240 <__imp__cexit>
   140003236:	90                   	nop
   140003237:	90                   	nop

0000000140003238 <_initterm>:
   140003238:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a258 <__imp__initterm>
   14000323e:	90                   	nop
   14000323f:	90                   	nop

0000000140003240 <_crt_atexit>:
   140003240:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a260 <__imp__crt_atexit>
   140003246:	90                   	nop
   140003247:	90                   	nop

0000000140003248 <abort>:
   140003248:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a268 <__imp_abort>
   14000324e:	90                   	nop
   14000324f:	90                   	nop

0000000140003250 <calloc>:
   140003250:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a270 <__imp_calloc>
   140003256:	90                   	nop
   140003257:	90                   	nop

0000000140003258 <exit>:
   140003258:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a278 <__imp_exit>
   14000325e:	90                   	nop
   14000325f:	90                   	nop

0000000140003260 <fflush>:
   140003260:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a280 <__imp_fflush>
   140003266:	90                   	nop
   140003267:	90                   	nop

0000000140003268 <fprintf>:
   140003268:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a288 <__imp_fprintf>
   14000326e:	90                   	nop
   14000326f:	90                   	nop

0000000140003270 <free>:
   140003270:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a290 <__imp_free>
   140003276:	90                   	nop
   140003277:	90                   	nop

0000000140003278 <malloc>:
   140003278:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a298 <__imp_malloc>
   14000327e:	90                   	nop
   14000327f:	90                   	nop

0000000140003280 <memcpy>:
   140003280:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a2a0 <__imp_memcpy>
   140003286:	90                   	nop
   140003287:	90                   	nop

0000000140003288 <memset>:
   140003288:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a2a8 <__imp_memset>
   14000328e:	90                   	nop
   14000328f:	90                   	nop

0000000140003290 <setvbuf>:
   140003290:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a2b0 <__imp_setvbuf>
   140003296:	90                   	nop
   140003297:	90                   	nop

0000000140003298 <signal>:
   140003298:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a2b8 <__imp_signal>
   14000329e:	90                   	nop
   14000329f:	90                   	nop

00000001400032a0 <strlen>:
   1400032a0:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a2c0 <__imp_strlen>
   1400032a6:	90                   	nop
   1400032a7:	90                   	nop

00000001400032a8 <strncmp>:
   1400032a8:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a2c8 <__imp_strncmp>
   1400032ae:	90                   	nop
   1400032af:	90                   	nop

00000001400032b0 <vfprintf>:
   1400032b0:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a2d0 <__imp_vfprintf>
   1400032b6:	90                   	nop
   1400032b7:	90                   	nop
   1400032b8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   1400032bf:	00 

00000001400032c0 <VirtualQuery>:
   1400032c0:	ff 25 32 6f 00 00    	jmp    QWORD PTR [rip+0x6f32]        # 14000a1f8 <__imp_VirtualQuery>
   1400032c6:	90                   	nop
   1400032c7:	90                   	nop

00000001400032c8 <VirtualProtect>:
   1400032c8:	ff 25 22 6f 00 00    	jmp    QWORD PTR [rip+0x6f22]        # 14000a1f0 <__imp_VirtualProtect>
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <TlsGetValue>:
   1400032d0:	ff 25 12 6f 00 00    	jmp    QWORD PTR [rip+0x6f12]        # 14000a1e8 <__imp_TlsGetValue>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop

00000001400032d8 <Sleep>:
   1400032d8:	ff 25 02 6f 00 00    	jmp    QWORD PTR [rip+0x6f02]        # 14000a1e0 <__imp_Sleep>
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <SetUnhandledExceptionFilter>:
   1400032e0:	ff 25 f2 6e 00 00    	jmp    QWORD PTR [rip+0x6ef2]        # 14000a1d8 <__imp_SetUnhandledExceptionFilter>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <LoadLibraryA>:
   1400032e8:	ff 25 e2 6e 00 00    	jmp    QWORD PTR [rip+0x6ee2]        # 14000a1d0 <__imp_LoadLibraryA>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <LeaveCriticalSection>:
   1400032f0:	ff 25 d2 6e 00 00    	jmp    QWORD PTR [rip+0x6ed2]        # 14000a1c8 <__imp_LeaveCriticalSection>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <InitializeCriticalSection>:
   1400032f8:	ff 25 c2 6e 00 00    	jmp    QWORD PTR [rip+0x6ec2]        # 14000a1c0 <__imp_InitializeCriticalSection>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <GetProcAddress>:
   140003300:	ff 25 b2 6e 00 00    	jmp    QWORD PTR [rip+0x6eb2]        # 14000a1b8 <__imp_GetProcAddress>
   140003306:	90                   	nop
   140003307:	90                   	nop

0000000140003308 <GetModuleHandleA>:
   140003308:	ff 25 a2 6e 00 00    	jmp    QWORD PTR [rip+0x6ea2]        # 14000a1b0 <__imp_GetModuleHandleA>
   14000330e:	90                   	nop
   14000330f:	90                   	nop

0000000140003310 <GetLastError>:
   140003310:	ff 25 92 6e 00 00    	jmp    QWORD PTR [rip+0x6e92]        # 14000a1a8 <__imp_GetLastError>
   140003316:	90                   	nop
   140003317:	90                   	nop

0000000140003318 <FreeLibrary>:
   140003318:	ff 25 82 6e 00 00    	jmp    QWORD PTR [rip+0x6e82]        # 14000a1a0 <__imp_FreeLibrary>
   14000331e:	90                   	nop
   14000331f:	90                   	nop

0000000140003320 <EnterCriticalSection>:
   140003320:	ff 25 72 6e 00 00    	jmp    QWORD PTR [rip+0x6e72]        # 14000a198 <__imp_EnterCriticalSection>
   140003326:	90                   	nop
   140003327:	90                   	nop

0000000140003328 <DeleteCriticalSection>:
   140003328:	ff 25 62 6e 00 00    	jmp    QWORD PTR [rip+0x6e62]        # 14000a190 <__IAT_start__>
   14000332e:	90                   	nop
   14000332f:	90                   	nop

0000000140003330 <register_frame_ctor>:
   140003330:	e9 3b e3 ff ff       	jmp    140001670 <__gcc_register_frame>
   140003335:	90                   	nop
   140003336:	90                   	nop
   140003337:	90                   	nop
   140003338:	90                   	nop
   140003339:	90                   	nop
   14000333a:	90                   	nop
   14000333b:	90                   	nop
   14000333c:	90                   	nop
   14000333d:	90                   	nop
   14000333e:	90                   	nop
   14000333f:	90                   	nop
