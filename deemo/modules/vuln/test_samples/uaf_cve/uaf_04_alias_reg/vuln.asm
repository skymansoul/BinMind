
C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\test_samples\uaf_cve\uaf_04_alias_reg\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 17 22 00 00       	call   140003240 <fflush>
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
   14000113b:	e8 c8 20 00 00       	call   140003208 <_amsg_exit>
   140001140:	48 8b 05 f9 42 00 00 	mov    rax,QWORD PTR [rip+0x42f9]        # 140005440 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 e8 42 00 00 	mov    rax,QWORD PTR [rip+0x42e8]        # 140005440 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 48 20 00 00       	call   1400031b0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 e7 20 00 00       	call   140003268 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 8f 20 00 00       	call   140003228 <abort>
   140001199:	e8 12 11 00 00       	call   1400022b0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 1b 43 00 00 	mov    rax,QWORD PTR [rip+0x431b]        # 1400054c0 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 21 90 00 00 	mov    rax,QWORD PTR [rip+0x9021]        # 14000a1d0 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 68 42 00 00 	mov    rdx,QWORD PTR [rip+0x4268]        # 140005420 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 86 1f 00 00       	call   140003150 <_set_invalid_parameter_handler>
   1400011ca:	e8 f1 19 00 00       	call   140002bc0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e 7e 00 00    	mov    DWORD PTR [rip+0x7e3e],eax        # 140009018 <managedapp>
   1400011da:	48 8b 05 ff 41 00 00 	mov    rax,QWORD PTR [rip+0x41ff]        # 1400053e0 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 07 20 00 00       	call   1400031f8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 fb 1f 00 00       	call   1400031f8 <__set_app_type>
   1400011fd:	e8 1e 1f 00 00       	call   140003120 <__p__fmode>
   140001202:	48 8b 15 a7 42 00 00 	mov    rdx,QWORD PTR [rip+0x42a7]        # 1400054b0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 1e 1f 00 00       	call   140003130 <__p__commode>
   140001212:	48 8b 15 77 42 00 00 	mov    rdx,QWORD PTR [rip+0x4277]        # 140005490 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 6e 06 00 00       	call   140001890 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 d3 1f 00 00       	call   140003208 <_amsg_exit>
   140001235:	48 8b 05 04 41 00 00 	mov    rax,QWORD PTR [rip+0x4104]        # 140005340 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 86 42 00 00 	mov    rax,QWORD PTR [rip+0x4286]        # 1400054d0 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 78 11 00 00       	call   1400023ca <__mingw_setusermatherr>
   140001252:	48 8b 05 47 41 00 00 	mov    rax,QWORD PTR [rip+0x4147]        # 1400053a0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 26 1f 00 00       	call   140003190 <_configthreadlocale>
   14000126a:	48 8b 15 0f 42 00 00 	mov    rdx,QWORD PTR [rip+0x420f]        # 140005480 <.refptr.__xi_z>
   140001271:	48 8b 05 f8 41 00 00 	mov    rax,QWORD PTR [rip+0x41f8]        # 140005470 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 40 1e 00 00       	call   1400030c0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 7a 1f 00 00       	call   140003208 <_amsg_exit>
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
   1400012cb:	e8 18 1f 00 00       	call   1400031e8 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 25 1f 00 00       	call   140003208 <_amsg_exit>
   1400012e3:	8b 05 1b 7d 00 00    	mov    eax,DWORD PTR [rip+0x7d1b]        # 140009004 <argc>
   1400012e9:	48 8d 15 18 7d 00 00 	lea    rdx,[rip+0x7d18]        # 140009008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 fe 1e 00 00       	call   140003208 <_amsg_exit>
   14000130a:	48 8b 15 4f 41 00 00 	mov    rdx,QWORD PTR [rip+0x414f]        # 140005460 <.refptr.__xc_z>
   140001311:	48 8b 05 38 41 00 00 	mov    rax,QWORD PTR [rip+0x4138]        # 140005450 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 f8 1e 00 00       	call   140003218 <_initterm>
   140001320:	e8 42 05 00 00       	call   140001867 <__main>
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
   14000138d:	e8 ae 1d 00 00       	call   140003140 <__p___initenv>
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
   1400013cc:	e8 67 1e 00 00       	call   140003238 <exit>
   1400013d1:	8b 05 45 7c 00 00    	mov    eax,DWORD PTR [rip+0x7c45]        # 14000901c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 30 1e 00 00       	call   140003210 <_cexit>
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
   140001511:	e8 42 1d 00 00       	call   140003258 <malloc>
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
   14000155c:	e8 17 1d 00 00       	call   140003278 <strlen>
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
   140001585:	e8 ce 1c 00 00       	call   140003258 <malloc>
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
   1400015e8:	e8 73 1c 00 00       	call   140003260 <memcpy>
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
   140001642:	e8 d9 1b 00 00       	call   140003220 <_crt_atexit>
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
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 30          	sub    rsp,0x30
   140001768:	e8 fa 00 00 00       	call   140001867 <__main>
   14000176d:	b9 40 00 00 00       	mov    ecx,0x40
   140001772:	e8 e1 1a 00 00       	call   140003258 <malloc>
   140001777:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000177b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140001780:	75 07                	jne    140001789 <main+0x29>
   140001782:	b8 01 00 00 00       	mov    eax,0x1
   140001787:	eb 1a                	jmp    1400017a3 <main+0x43>
   140001789:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000178d:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001791:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001795:	48 89 c1             	mov    rcx,rax
   140001798:	e8 b3 1a 00 00       	call   140003250 <free>
   14000179d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017a1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400017a3:	48 83 c4 30          	add    rsp,0x30
   1400017a7:	5d                   	pop    rbp
   1400017a8:	c3                   	ret
   1400017a9:	90                   	nop
   1400017aa:	90                   	nop
   1400017ab:	90                   	nop
   1400017ac:	90                   	nop
   1400017ad:	90                   	nop
   1400017ae:	90                   	nop
   1400017af:	90                   	nop

00000001400017b0 <__do_global_dtors>:
   1400017b0:	55                   	push   rbp
   1400017b1:	48 89 e5             	mov    rbp,rsp
   1400017b4:	48 83 ec 20          	sub    rsp,0x20
   1400017b8:	eb 1e                	jmp    1400017d8 <__do_global_dtors+0x28>
   1400017ba:	48 8b 05 4f 28 00 00 	mov    rax,QWORD PTR [rip+0x284f]        # 140004010 <p.0>
   1400017c1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017c4:	ff d0                	call   rax
   1400017c6:	48 8b 05 43 28 00 00 	mov    rax,QWORD PTR [rip+0x2843]        # 140004010 <p.0>
   1400017cd:	48 83 c0 08          	add    rax,0x8
   1400017d1:	48 89 05 38 28 00 00 	mov    QWORD PTR [rip+0x2838],rax        # 140004010 <p.0>
   1400017d8:	48 8b 05 31 28 00 00 	mov    rax,QWORD PTR [rip+0x2831]        # 140004010 <p.0>
   1400017df:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017e2:	48 85 c0             	test   rax,rax
   1400017e5:	75 d3                	jne    1400017ba <__do_global_dtors+0xa>
   1400017e7:	90                   	nop
   1400017e8:	90                   	nop
   1400017e9:	48 83 c4 20          	add    rsp,0x20
   1400017ed:	5d                   	pop    rbp
   1400017ee:	c3                   	ret

00000001400017ef <__do_global_ctors>:
   1400017ef:	55                   	push   rbp
   1400017f0:	48 89 e5             	mov    rbp,rsp
   1400017f3:	48 83 ec 30          	sub    rsp,0x30
   1400017f7:	48 8b 05 52 3b 00 00 	mov    rax,QWORD PTR [rip+0x3b52]        # 140005350 <.refptr.__CTOR_LIST__>
   1400017fe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001801:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001804:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001808:	75 25                	jne    14000182f <__do_global_ctors+0x40>
   14000180a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001811:	eb 04                	jmp    140001817 <__do_global_ctors+0x28>
   140001813:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001817:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000181a:	8d 50 01             	lea    edx,[rax+0x1]
   14000181d:	48 8b 05 2c 3b 00 00 	mov    rax,QWORD PTR [rip+0x3b2c]        # 140005350 <.refptr.__CTOR_LIST__>
   140001824:	89 d2                	mov    edx,edx
   140001826:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000182a:	48 85 c0             	test   rax,rax
   14000182d:	75 e4                	jne    140001813 <__do_global_ctors+0x24>
   14000182f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001832:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001835:	eb 14                	jmp    14000184b <__do_global_ctors+0x5c>
   140001837:	48 8b 05 12 3b 00 00 	mov    rax,QWORD PTR [rip+0x3b12]        # 140005350 <.refptr.__CTOR_LIST__>
   14000183e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001841:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001845:	ff d0                	call   rax
   140001847:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000184b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000184f:	75 e6                	jne    140001837 <__do_global_ctors+0x48>
   140001851:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400017b0 <__do_global_dtors>
   140001858:	48 89 c1             	mov    rcx,rax
   14000185b:	e8 cf fd ff ff       	call   14000162f <atexit>
   140001860:	90                   	nop
   140001861:	48 83 c4 30          	add    rsp,0x30
   140001865:	5d                   	pop    rbp
   140001866:	c3                   	ret

0000000140001867 <__main>:
   140001867:	55                   	push   rbp
   140001868:	48 89 e5             	mov    rbp,rsp
   14000186b:	48 83 ec 20          	sub    rsp,0x20
   14000186f:	8b 05 0b 78 00 00    	mov    eax,DWORD PTR [rip+0x780b]        # 140009080 <initialized>
   140001875:	85 c0                	test   eax,eax
   140001877:	75 0f                	jne    140001888 <__main+0x21>
   140001879:	c7 05 fd 77 00 00 01 	mov    DWORD PTR [rip+0x77fd],0x1        # 140009080 <initialized>
   140001880:	00 00 00 
   140001883:	e8 67 ff ff ff       	call   1400017ef <__do_global_ctors>
   140001888:	90                   	nop
   140001889:	48 83 c4 20          	add    rsp,0x20
   14000188d:	5d                   	pop    rbp
   14000188e:	c3                   	ret
   14000188f:	90                   	nop

0000000140001890 <_setargv>:
   140001890:	55                   	push   rbp
   140001891:	48 89 e5             	mov    rbp,rsp
   140001894:	b8 00 00 00 00       	mov    eax,0x0
   140001899:	5d                   	pop    rbp
   14000189a:	c3                   	ret
   14000189b:	90                   	nop
   14000189c:	90                   	nop
   14000189d:	90                   	nop
   14000189e:	90                   	nop
   14000189f:	90                   	nop

00000001400018a0 <__dyn_tls_init>:
   1400018a0:	55                   	push   rbp
   1400018a1:	48 89 e5             	mov    rbp,rsp
   1400018a4:	48 83 ec 30          	sub    rsp,0x30
   1400018a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400018ac:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400018af:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400018b3:	48 8b 05 76 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a76]        # 140005330 <.refptr._CRT_MT>
   1400018ba:	8b 00                	mov    eax,DWORD PTR [rax]
   1400018bc:	83 f8 02             	cmp    eax,0x2
   1400018bf:	74 0d                	je     1400018ce <__dyn_tls_init+0x2e>
   1400018c1:	48 8b 05 68 3a 00 00 	mov    rax,QWORD PTR [rip+0x3a68]        # 140005330 <.refptr._CRT_MT>
   1400018c8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400018ce:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   1400018d2:	74 1e                	je     1400018f2 <__dyn_tls_init+0x52>
   1400018d4:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   1400018d8:	75 5b                	jne    140001935 <__dyn_tls_init+0x95>
   1400018da:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400018de:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400018e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400018e5:	49 89 c8             	mov    r8,rcx
   1400018e8:	48 89 c1             	mov    rcx,rax
   1400018eb:	e8 d1 11 00 00       	call   140002ac1 <__mingw_TLScallback>
   1400018f0:	eb 43                	jmp    140001935 <__dyn_tls_init+0x95>
   1400018f2:	48 8d 05 9f 3d 00 00 	lea    rax,[rip+0x3d9f]        # 140005698 <___crt_xd_start__>
   1400018f9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400018fd:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001902:	eb 22                	jmp    140001926 <__dyn_tls_init+0x86>
   140001904:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001908:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000190c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001910:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001913:	48 85 c0             	test   rax,rax
   140001916:	74 09                	je     140001921 <__dyn_tls_init+0x81>
   140001918:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000191c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000191f:	ff d0                	call   rax
   140001921:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001926:	48 8d 05 73 3d 00 00 	lea    rax,[rip+0x3d73]        # 1400056a0 <__xd_z>
   14000192d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001931:	75 d1                	jne    140001904 <__dyn_tls_init+0x64>
   140001933:	eb 01                	jmp    140001936 <__dyn_tls_init+0x96>
   140001935:	90                   	nop
   140001936:	48 83 c4 30          	add    rsp,0x30
   14000193a:	5d                   	pop    rbp
   14000193b:	c3                   	ret

000000014000193c <__tlregdtor>:
   14000193c:	55                   	push   rbp
   14000193d:	48 89 e5             	mov    rbp,rsp
   140001940:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001944:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001949:	75 07                	jne    140001952 <__tlregdtor+0x16>
   14000194b:	b8 00 00 00 00       	mov    eax,0x0
   140001950:	eb 05                	jmp    140001957 <__tlregdtor+0x1b>
   140001952:	b8 00 00 00 00       	mov    eax,0x0
   140001957:	5d                   	pop    rbp
   140001958:	c3                   	ret

0000000140001959 <__dyn_tls_dtor>:
   140001959:	55                   	push   rbp
   14000195a:	48 89 e5             	mov    rbp,rsp
   14000195d:	48 83 ec 20          	sub    rsp,0x20
   140001961:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001965:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001968:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000196c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001970:	74 06                	je     140001978 <__dyn_tls_dtor+0x1f>
   140001972:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001976:	75 18                	jne    140001990 <__dyn_tls_dtor+0x37>
   140001978:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000197c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   14000197f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001983:	49 89 c8             	mov    r8,rcx
   140001986:	48 89 c1             	mov    rcx,rax
   140001989:	e8 33 11 00 00       	call   140002ac1 <__mingw_TLScallback>
   14000198e:	eb 01                	jmp    140001991 <__dyn_tls_dtor+0x38>
   140001990:	90                   	nop
   140001991:	48 83 c4 20          	add    rsp,0x20
   140001995:	5d                   	pop    rbp
   140001996:	c3                   	ret
   140001997:	90                   	nop
   140001998:	90                   	nop
   140001999:	90                   	nop
   14000199a:	90                   	nop
   14000199b:	90                   	nop
   14000199c:	90                   	nop
   14000199d:	90                   	nop
   14000199e:	90                   	nop
   14000199f:	90                   	nop

00000001400019a0 <_matherr>:
   1400019a0:	55                   	push   rbp
   1400019a1:	53                   	push   rbx
   1400019a2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400019a9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400019ae:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   1400019b2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   1400019b6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   1400019bb:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   1400019bf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   1400019c3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019c5:	83 f8 06             	cmp    eax,0x6
   1400019c8:	74 56                	je     140001a20 <_matherr+0x80>
   1400019ca:	83 f8 06             	cmp    eax,0x6
   1400019cd:	7f 78                	jg     140001a47 <_matherr+0xa7>
   1400019cf:	83 f8 05             	cmp    eax,0x5
   1400019d2:	74 59                	je     140001a2d <_matherr+0x8d>
   1400019d4:	83 f8 05             	cmp    eax,0x5
   1400019d7:	7f 6e                	jg     140001a47 <_matherr+0xa7>
   1400019d9:	83 f8 04             	cmp    eax,0x4
   1400019dc:	74 5c                	je     140001a3a <_matherr+0x9a>
   1400019de:	83 f8 04             	cmp    eax,0x4
   1400019e1:	7f 64                	jg     140001a47 <_matherr+0xa7>
   1400019e3:	83 f8 03             	cmp    eax,0x3
   1400019e6:	74 2b                	je     140001a13 <_matherr+0x73>
   1400019e8:	83 f8 03             	cmp    eax,0x3
   1400019eb:	7f 5a                	jg     140001a47 <_matherr+0xa7>
   1400019ed:	83 f8 01             	cmp    eax,0x1
   1400019f0:	74 07                	je     1400019f9 <_matherr+0x59>
   1400019f2:	83 f8 02             	cmp    eax,0x2
   1400019f5:	74 0f                	je     140001a06 <_matherr+0x66>
   1400019f7:	eb 4e                	jmp    140001a47 <_matherr+0xa7>
   1400019f9:	48 8d 05 a0 36 00 00 	lea    rax,[rip+0x36a0]        # 1400050a0 <.rdata>
   140001a00:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a04:	eb 4d                	jmp    140001a53 <_matherr+0xb3>
   140001a06:	48 8d 05 b2 36 00 00 	lea    rax,[rip+0x36b2]        # 1400050bf <.rdata+0x1f>
   140001a0d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a11:	eb 40                	jmp    140001a53 <_matherr+0xb3>
   140001a13:	48 8d 05 c6 36 00 00 	lea    rax,[rip+0x36c6]        # 1400050e0 <.rdata+0x40>
   140001a1a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a1e:	eb 33                	jmp    140001a53 <_matherr+0xb3>
   140001a20:	48 8d 05 d9 36 00 00 	lea    rax,[rip+0x36d9]        # 140005100 <.rdata+0x60>
   140001a27:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a2b:	eb 26                	jmp    140001a53 <_matherr+0xb3>
   140001a2d:	48 8d 05 f4 36 00 00 	lea    rax,[rip+0x36f4]        # 140005128 <.rdata+0x88>
   140001a34:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a38:	eb 19                	jmp    140001a53 <_matherr+0xb3>
   140001a3a:	48 8d 05 0f 37 00 00 	lea    rax,[rip+0x370f]        # 140005150 <.rdata+0xb0>
   140001a41:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a45:	eb 0c                	jmp    140001a53 <_matherr+0xb3>
   140001a47:	48 8d 05 38 37 00 00 	lea    rax,[rip+0x3738]        # 140005186 <.rdata+0xe6>
   140001a4e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a52:	90                   	nop
   140001a53:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a57:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001a5d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a61:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001a66:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a6a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001a6f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a73:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001a77:	b9 02 00 00 00       	mov    ecx,0x2
   140001a7c:	e8 2f 17 00 00       	call   1400031b0 <__acrt_iob_func>
   140001a81:	48 89 c1             	mov    rcx,rax
   140001a84:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001a88:	48 8d 05 09 37 00 00 	lea    rax,[rip+0x3709]        # 140005198 <.rdata+0xf8>
   140001a8f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001a96:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001a9c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001aa2:	49 89 d9             	mov    r9,rbx
   140001aa5:	49 89 d0             	mov    r8,rdx
   140001aa8:	48 89 c2             	mov    rdx,rax
   140001aab:	e8 98 17 00 00       	call   140003248 <fprintf>
   140001ab0:	b8 00 00 00 00       	mov    eax,0x0
   140001ab5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001ab9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001abd:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001ac2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001ac9:	5b                   	pop    rbx
   140001aca:	5d                   	pop    rbp
   140001acb:	c3                   	ret
   140001acc:	90                   	nop
   140001acd:	90                   	nop
   140001ace:	90                   	nop
   140001acf:	90                   	nop

0000000140001ad0 <__report_error>:
   140001ad0:	55                   	push   rbp
   140001ad1:	53                   	push   rbx
   140001ad2:	48 83 ec 38          	sub    rsp,0x38
   140001ad6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001adb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001adf:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001ae3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001ae7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001aeb:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001aef:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001af3:	b9 02 00 00 00       	mov    ecx,0x2
   140001af8:	e8 b3 16 00 00       	call   1400031b0 <__acrt_iob_func>
   140001afd:	48 89 c1             	mov    rcx,rax
   140001b00:	48 8d 05 c9 36 00 00 	lea    rax,[rip+0x36c9]        # 1400051d0 <.rdata>
   140001b07:	48 89 c2             	mov    rdx,rax
   140001b0a:	e8 39 17 00 00       	call   140003248 <fprintf>
   140001b0f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b13:	b9 02 00 00 00       	mov    ecx,0x2
   140001b18:	e8 93 16 00 00       	call   1400031b0 <__acrt_iob_func>
   140001b1d:	48 89 c1             	mov    rcx,rax
   140001b20:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b24:	49 89 d8             	mov    r8,rbx
   140001b27:	48 89 c2             	mov    rdx,rax
   140001b2a:	e8 59 17 00 00       	call   140003288 <vfprintf>
   140001b2f:	e8 f4 16 00 00       	call   140003228 <abort>
   140001b34:	90                   	nop

0000000140001b35 <mark_section_writable>:
   140001b35:	55                   	push   rbp
   140001b36:	48 89 e5             	mov    rbp,rsp
   140001b39:	48 83 ec 60          	sub    rsp,0x60
   140001b3d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b41:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001b48:	e9 82 00 00 00       	jmp    140001bcf <mark_section_writable+0x9a>
   140001b4d:	48 8b 0d 8c 75 00 00 	mov    rcx,QWORD PTR [rip+0x758c]        # 1400090e0 <the_secs>
   140001b54:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b57:	48 63 d0             	movsxd rdx,eax
   140001b5a:	48 89 d0             	mov    rax,rdx
   140001b5d:	48 c1 e0 02          	shl    rax,0x2
   140001b61:	48 01 d0             	add    rax,rdx
   140001b64:	48 c1 e0 03          	shl    rax,0x3
   140001b68:	48 01 c8             	add    rax,rcx
   140001b6b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001b6f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001b73:	72 56                	jb     140001bcb <mark_section_writable+0x96>
   140001b75:	48 8b 0d 64 75 00 00 	mov    rcx,QWORD PTR [rip+0x7564]        # 1400090e0 <the_secs>
   140001b7c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b7f:	48 63 d0             	movsxd rdx,eax
   140001b82:	48 89 d0             	mov    rax,rdx
   140001b85:	48 c1 e0 02          	shl    rax,0x2
   140001b89:	48 01 d0             	add    rax,rdx
   140001b8c:	48 c1 e0 03          	shl    rax,0x3
   140001b90:	48 01 c8             	add    rax,rcx
   140001b93:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001b97:	4c 8b 05 42 75 00 00 	mov    r8,QWORD PTR [rip+0x7542]        # 1400090e0 <the_secs>
   140001b9e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ba1:	48 63 d0             	movsxd rdx,eax
   140001ba4:	48 89 d0             	mov    rax,rdx
   140001ba7:	48 c1 e0 02          	shl    rax,0x2
   140001bab:	48 01 d0             	add    rax,rdx
   140001bae:	48 c1 e0 03          	shl    rax,0x3
   140001bb2:	4c 01 c0             	add    rax,r8
   140001bb5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001bb9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001bbc:	89 c0                	mov    eax,eax
   140001bbe:	48 01 c8             	add    rax,rcx
   140001bc1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001bc5:	0f 82 41 02 00 00    	jb     140001e0c <mark_section_writable+0x2d7>
   140001bcb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001bcf:	8b 05 13 75 00 00    	mov    eax,DWORD PTR [rip+0x7513]        # 1400090e8 <maxSections>
   140001bd5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001bd8:	0f 8c 6f ff ff ff    	jl     140001b4d <mark_section_writable+0x18>
   140001bde:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001be2:	48 89 c1             	mov    rcx,rax
   140001be5:	e8 c1 11 00 00       	call   140002dab <__mingw_GetSectionForAddress>
   140001bea:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001bee:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001bf3:	75 13                	jne    140001c08 <mark_section_writable+0xd3>
   140001bf5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001bf9:	48 8d 0d f0 35 00 00 	lea    rcx,[rip+0x35f0]        # 1400051f0 <.rdata+0x20>
   140001c00:	48 89 c2             	mov    rdx,rax
   140001c03:	e8 c8 fe ff ff       	call   140001ad0 <__report_error>
   140001c08:	48 8b 0d d1 74 00 00 	mov    rcx,QWORD PTR [rip+0x74d1]        # 1400090e0 <the_secs>
   140001c0f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c12:	48 63 d0             	movsxd rdx,eax
   140001c15:	48 89 d0             	mov    rax,rdx
   140001c18:	48 c1 e0 02          	shl    rax,0x2
   140001c1c:	48 01 d0             	add    rax,rdx
   140001c1f:	48 c1 e0 03          	shl    rax,0x3
   140001c23:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c27:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c2b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c2f:	48 8b 0d aa 74 00 00 	mov    rcx,QWORD PTR [rip+0x74aa]        # 1400090e0 <the_secs>
   140001c36:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c39:	48 63 d0             	movsxd rdx,eax
   140001c3c:	48 89 d0             	mov    rax,rdx
   140001c3f:	48 c1 e0 02          	shl    rax,0x2
   140001c43:	48 01 d0             	add    rax,rdx
   140001c46:	48 c1 e0 03          	shl    rax,0x3
   140001c4a:	48 01 c8             	add    rax,rcx
   140001c4d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001c53:	e8 9f 12 00 00       	call   140002ef7 <_GetPEImageBase>
   140001c58:	48 89 c1             	mov    rcx,rax
   140001c5b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c5f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001c62:	41 89 c1             	mov    r9d,eax
   140001c65:	4c 8b 05 74 74 00 00 	mov    r8,QWORD PTR [rip+0x7474]        # 1400090e0 <the_secs>
   140001c6c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c6f:	48 63 d0             	movsxd rdx,eax
   140001c72:	48 89 d0             	mov    rax,rdx
   140001c75:	48 c1 e0 02          	shl    rax,0x2
   140001c79:	48 01 d0             	add    rax,rdx
   140001c7c:	48 c1 e0 03          	shl    rax,0x3
   140001c80:	4c 01 c0             	add    rax,r8
   140001c83:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001c87:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001c8b:	48 8b 0d 4e 74 00 00 	mov    rcx,QWORD PTR [rip+0x744e]        # 1400090e0 <the_secs>
   140001c92:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c95:	48 63 d0             	movsxd rdx,eax
   140001c98:	48 89 d0             	mov    rax,rdx
   140001c9b:	48 c1 e0 02          	shl    rax,0x2
   140001c9f:	48 01 d0             	add    rax,rdx
   140001ca2:	48 c1 e0 03          	shl    rax,0x3
   140001ca6:	48 01 c8             	add    rax,rcx
   140001ca9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001cad:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001cb1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001cb7:	48 89 c1             	mov    rcx,rax
   140001cba:	48 8b 05 2f 85 00 00 	mov    rax,QWORD PTR [rip+0x852f]        # 14000a1f0 <__imp_VirtualQuery>
   140001cc1:	ff d0                	call   rax
   140001cc3:	48 85 c0             	test   rax,rax
   140001cc6:	75 3f                	jne    140001d07 <mark_section_writable+0x1d2>
   140001cc8:	48 8b 0d 11 74 00 00 	mov    rcx,QWORD PTR [rip+0x7411]        # 1400090e0 <the_secs>
   140001ccf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cd2:	48 63 d0             	movsxd rdx,eax
   140001cd5:	48 89 d0             	mov    rax,rdx
   140001cd8:	48 c1 e0 02          	shl    rax,0x2
   140001cdc:	48 01 d0             	add    rax,rdx
   140001cdf:	48 c1 e0 03          	shl    rax,0x3
   140001ce3:	48 01 c8             	add    rax,rcx
   140001ce6:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001cea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001cee:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001cf1:	89 c1                	mov    ecx,eax
   140001cf3:	48 8d 05 16 35 00 00 	lea    rax,[rip+0x3516]        # 140005210 <.rdata+0x40>
   140001cfa:	49 89 d0             	mov    r8,rdx
   140001cfd:	89 ca                	mov    edx,ecx
   140001cff:	48 89 c1             	mov    rcx,rax
   140001d02:	e8 c9 fd ff ff       	call   140001ad0 <__report_error>
   140001d07:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d0a:	83 f8 40             	cmp    eax,0x40
   140001d0d:	0f 84 e8 00 00 00    	je     140001dfb <mark_section_writable+0x2c6>
   140001d13:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d16:	83 f8 04             	cmp    eax,0x4
   140001d19:	0f 84 dc 00 00 00    	je     140001dfb <mark_section_writable+0x2c6>
   140001d1f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d22:	3d 80 00 00 00       	cmp    eax,0x80
   140001d27:	0f 84 ce 00 00 00    	je     140001dfb <mark_section_writable+0x2c6>
   140001d2d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d30:	83 f8 08             	cmp    eax,0x8
   140001d33:	0f 84 c2 00 00 00    	je     140001dfb <mark_section_writable+0x2c6>
   140001d39:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d3c:	83 f8 02             	cmp    eax,0x2
   140001d3f:	75 09                	jne    140001d4a <mark_section_writable+0x215>
   140001d41:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001d48:	eb 07                	jmp    140001d51 <mark_section_writable+0x21c>
   140001d4a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001d51:	48 8b 0d 88 73 00 00 	mov    rcx,QWORD PTR [rip+0x7388]        # 1400090e0 <the_secs>
   140001d58:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d5b:	48 63 d0             	movsxd rdx,eax
   140001d5e:	48 89 d0             	mov    rax,rdx
   140001d61:	48 c1 e0 02          	shl    rax,0x2
   140001d65:	48 01 d0             	add    rax,rdx
   140001d68:	48 c1 e0 03          	shl    rax,0x3
   140001d6c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d70:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001d74:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001d78:	48 8b 0d 61 73 00 00 	mov    rcx,QWORD PTR [rip+0x7361]        # 1400090e0 <the_secs>
   140001d7f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d82:	48 63 d0             	movsxd rdx,eax
   140001d85:	48 89 d0             	mov    rax,rdx
   140001d88:	48 c1 e0 02          	shl    rax,0x2
   140001d8c:	48 01 d0             	add    rax,rdx
   140001d8f:	48 c1 e0 03          	shl    rax,0x3
   140001d93:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d97:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001d9b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001d9f:	48 8b 0d 3a 73 00 00 	mov    rcx,QWORD PTR [rip+0x733a]        # 1400090e0 <the_secs>
   140001da6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001da9:	48 63 d0             	movsxd rdx,eax
   140001dac:	48 89 d0             	mov    rax,rdx
   140001daf:	48 c1 e0 02          	shl    rax,0x2
   140001db3:	48 01 d0             	add    rax,rdx
   140001db6:	48 c1 e0 03          	shl    rax,0x3
   140001dba:	48 01 c8             	add    rax,rcx
   140001dbd:	49 89 c0             	mov    r8,rax
   140001dc0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001dc4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001dc8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001dcb:	4d 89 c1             	mov    r9,r8
   140001dce:	41 89 c8             	mov    r8d,ecx
   140001dd1:	48 89 c1             	mov    rcx,rax
   140001dd4:	48 8b 05 0d 84 00 00 	mov    rax,QWORD PTR [rip+0x840d]        # 14000a1e8 <__imp_VirtualProtect>
   140001ddb:	ff d0                	call   rax
   140001ddd:	85 c0                	test   eax,eax
   140001ddf:	75 1a                	jne    140001dfb <mark_section_writable+0x2c6>
   140001de1:	48 8b 05 b8 83 00 00 	mov    rax,QWORD PTR [rip+0x83b8]        # 14000a1a0 <__imp_GetLastError>
   140001de8:	ff d0                	call   rax
   140001dea:	89 c2                	mov    edx,eax
   140001dec:	48 8d 05 55 34 00 00 	lea    rax,[rip+0x3455]        # 140005248 <.rdata+0x78>
   140001df3:	48 89 c1             	mov    rcx,rax
   140001df6:	e8 d5 fc ff ff       	call   140001ad0 <__report_error>
   140001dfb:	8b 05 e7 72 00 00    	mov    eax,DWORD PTR [rip+0x72e7]        # 1400090e8 <maxSections>
   140001e01:	83 c0 01             	add    eax,0x1
   140001e04:	89 05 de 72 00 00    	mov    DWORD PTR [rip+0x72de],eax        # 1400090e8 <maxSections>
   140001e0a:	eb 01                	jmp    140001e0d <mark_section_writable+0x2d8>
   140001e0c:	90                   	nop
   140001e0d:	48 83 c4 60          	add    rsp,0x60
   140001e11:	5d                   	pop    rbp
   140001e12:	c3                   	ret

0000000140001e13 <restore_modified_sections>:
   140001e13:	55                   	push   rbp
   140001e14:	48 89 e5             	mov    rbp,rsp
   140001e17:	48 83 ec 30          	sub    rsp,0x30
   140001e1b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e22:	e9 ad 00 00 00       	jmp    140001ed4 <restore_modified_sections+0xc1>
   140001e27:	48 8b 0d b2 72 00 00 	mov    rcx,QWORD PTR [rip+0x72b2]        # 1400090e0 <the_secs>
   140001e2e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e31:	48 63 d0             	movsxd rdx,eax
   140001e34:	48 89 d0             	mov    rax,rdx
   140001e37:	48 c1 e0 02          	shl    rax,0x2
   140001e3b:	48 01 d0             	add    rax,rdx
   140001e3e:	48 c1 e0 03          	shl    rax,0x3
   140001e42:	48 01 c8             	add    rax,rcx
   140001e45:	8b 00                	mov    eax,DWORD PTR [rax]
   140001e47:	85 c0                	test   eax,eax
   140001e49:	0f 84 80 00 00 00    	je     140001ecf <restore_modified_sections+0xbc>
   140001e4f:	48 8b 0d 8a 72 00 00 	mov    rcx,QWORD PTR [rip+0x728a]        # 1400090e0 <the_secs>
   140001e56:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e59:	48 63 d0             	movsxd rdx,eax
   140001e5c:	48 89 d0             	mov    rax,rdx
   140001e5f:	48 c1 e0 02          	shl    rax,0x2
   140001e63:	48 01 d0             	add    rax,rdx
   140001e66:	48 c1 e0 03          	shl    rax,0x3
   140001e6a:	48 01 c8             	add    rax,rcx
   140001e6d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001e70:	48 8b 0d 69 72 00 00 	mov    rcx,QWORD PTR [rip+0x7269]        # 1400090e0 <the_secs>
   140001e77:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e7a:	48 63 d0             	movsxd rdx,eax
   140001e7d:	48 89 d0             	mov    rax,rdx
   140001e80:	48 c1 e0 02          	shl    rax,0x2
   140001e84:	48 01 d0             	add    rax,rdx
   140001e87:	48 c1 e0 03          	shl    rax,0x3
   140001e8b:	48 01 c8             	add    rax,rcx
   140001e8e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001e92:	4c 8b 05 47 72 00 00 	mov    r8,QWORD PTR [rip+0x7247]        # 1400090e0 <the_secs>
   140001e99:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e9c:	48 63 d0             	movsxd rdx,eax
   140001e9f:	48 89 d0             	mov    rax,rdx
   140001ea2:	48 c1 e0 02          	shl    rax,0x2
   140001ea6:	48 01 d0             	add    rax,rdx
   140001ea9:	48 c1 e0 03          	shl    rax,0x3
   140001ead:	4c 01 c0             	add    rax,r8
   140001eb0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001eb4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001eb8:	49 89 d1             	mov    r9,rdx
   140001ebb:	45 89 d0             	mov    r8d,r10d
   140001ebe:	48 89 ca             	mov    rdx,rcx
   140001ec1:	48 89 c1             	mov    rcx,rax
   140001ec4:	48 8b 05 1d 83 00 00 	mov    rax,QWORD PTR [rip+0x831d]        # 14000a1e8 <__imp_VirtualProtect>
   140001ecb:	ff d0                	call   rax
   140001ecd:	eb 01                	jmp    140001ed0 <restore_modified_sections+0xbd>
   140001ecf:	90                   	nop
   140001ed0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001ed4:	8b 05 0e 72 00 00    	mov    eax,DWORD PTR [rip+0x720e]        # 1400090e8 <maxSections>
   140001eda:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001edd:	0f 8c 44 ff ff ff    	jl     140001e27 <restore_modified_sections+0x14>
   140001ee3:	90                   	nop
   140001ee4:	90                   	nop
   140001ee5:	48 83 c4 30          	add    rsp,0x30
   140001ee9:	5d                   	pop    rbp
   140001eea:	c3                   	ret

0000000140001eeb <__write_memory>:
   140001eeb:	55                   	push   rbp
   140001eec:	48 89 e5             	mov    rbp,rsp
   140001eef:	48 83 ec 20          	sub    rsp,0x20
   140001ef3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001ef7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001efb:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001eff:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f04:	74 25                	je     140001f2b <__write_memory+0x40>
   140001f06:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f0a:	48 89 c1             	mov    rcx,rax
   140001f0d:	e8 23 fc ff ff       	call   140001b35 <mark_section_writable>
   140001f12:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f16:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f1a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f1e:	49 89 c8             	mov    r8,rcx
   140001f21:	48 89 c1             	mov    rcx,rax
   140001f24:	e8 37 13 00 00       	call   140003260 <memcpy>
   140001f29:	eb 01                	jmp    140001f2c <__write_memory+0x41>
   140001f2b:	90                   	nop
   140001f2c:	48 83 c4 20          	add    rsp,0x20
   140001f30:	5d                   	pop    rbp
   140001f31:	c3                   	ret

0000000140001f32 <do_pseudo_reloc>:
   140001f32:	55                   	push   rbp
   140001f33:	48 89 e5             	mov    rbp,rsp
   140001f36:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001f3a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f3e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f42:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f46:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001f4a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001f4e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001f52:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f56:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001f5a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001f5f:	0f 8e 44 03 00 00    	jle    1400022a9 <do_pseudo_reloc+0x377>
   140001f65:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001f6a:	7e 25                	jle    140001f91 <do_pseudo_reloc+0x5f>
   140001f6c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f70:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f72:	85 c0                	test   eax,eax
   140001f74:	75 1b                	jne    140001f91 <do_pseudo_reloc+0x5f>
   140001f76:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f7a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001f7d:	85 c0                	test   eax,eax
   140001f7f:	75 10                	jne    140001f91 <do_pseudo_reloc+0x5f>
   140001f81:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f85:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001f88:	85 c0                	test   eax,eax
   140001f8a:	75 05                	jne    140001f91 <do_pseudo_reloc+0x5f>
   140001f8c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140001f91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f95:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f97:	85 c0                	test   eax,eax
   140001f99:	75 0b                	jne    140001fa6 <do_pseudo_reloc+0x74>
   140001f9b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f9f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fa2:	85 c0                	test   eax,eax
   140001fa4:	74 59                	je     140001fff <do_pseudo_reloc+0xcd>
   140001fa6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001faa:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001fae:	eb 40                	jmp    140001ff0 <do_pseudo_reloc+0xbe>
   140001fb0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001fb4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fb7:	89 c2                	mov    edx,eax
   140001fb9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001fbd:	48 01 d0             	add    rax,rdx
   140001fc0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001fc4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001fc8:	8b 10                	mov    edx,DWORD PTR [rax]
   140001fca:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001fce:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fd0:	01 d0                	add    eax,edx
   140001fd2:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140001fd5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001fd9:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   140001fdd:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001fe3:	48 89 c1             	mov    rcx,rax
   140001fe6:	e8 00 ff ff ff       	call   140001eeb <__write_memory>
   140001feb:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140001ff0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001ff4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140001ff8:	72 b6                	jb     140001fb0 <do_pseudo_reloc+0x7e>
   140001ffa:	e9 ab 02 00 00       	jmp    1400022aa <do_pseudo_reloc+0x378>
   140001fff:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002003:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002006:	83 f8 01             	cmp    eax,0x1
   140002009:	74 18                	je     140002023 <do_pseudo_reloc+0xf1>
   14000200b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000200f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002012:	89 c2                	mov    edx,eax
   140002014:	48 8d 05 55 32 00 00 	lea    rax,[rip+0x3255]        # 140005270 <.rdata+0xa0>
   14000201b:	48 89 c1             	mov    rcx,rax
   14000201e:	e8 ad fa ff ff       	call   140001ad0 <__report_error>
   140002023:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002027:	48 83 c0 0c          	add    rax,0xc
   14000202b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000202f:	e9 65 02 00 00       	jmp    140002299 <do_pseudo_reloc+0x367>
   140002034:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002038:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000203b:	89 c2                	mov    edx,eax
   14000203d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002041:	48 01 d0             	add    rax,rdx
   140002044:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002048:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000204c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000204e:	89 c2                	mov    edx,eax
   140002050:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002054:	48 01 d0             	add    rax,rdx
   140002057:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000205b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000205f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002062:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002066:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000206a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000206d:	0f b6 c0             	movzx  eax,al
   140002070:	83 f8 40             	cmp    eax,0x40
   140002073:	0f 84 b6 00 00 00    	je     14000212f <do_pseudo_reloc+0x1fd>
   140002079:	83 f8 40             	cmp    eax,0x40
   14000207c:	0f 87 ba 00 00 00    	ja     14000213c <do_pseudo_reloc+0x20a>
   140002082:	83 f8 20             	cmp    eax,0x20
   140002085:	74 77                	je     1400020fe <do_pseudo_reloc+0x1cc>
   140002087:	83 f8 20             	cmp    eax,0x20
   14000208a:	0f 87 ac 00 00 00    	ja     14000213c <do_pseudo_reloc+0x20a>
   140002090:	83 f8 08             	cmp    eax,0x8
   140002093:	74 0a                	je     14000209f <do_pseudo_reloc+0x16d>
   140002095:	83 f8 10             	cmp    eax,0x10
   140002098:	74 38                	je     1400020d2 <do_pseudo_reloc+0x1a0>
   14000209a:	e9 9d 00 00 00       	jmp    14000213c <do_pseudo_reloc+0x20a>
   14000209f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020a3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400020a6:	0f b6 c0             	movzx  eax,al
   1400020a9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020ad:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020b1:	25 80 00 00 00       	and    eax,0x80
   1400020b6:	48 85 c0             	test   rax,rax
   1400020b9:	0f 84 9d 00 00 00    	je     14000215c <do_pseudo_reloc+0x22a>
   1400020bf:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020c3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400020c9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020cd:	e9 8a 00 00 00       	jmp    14000215c <do_pseudo_reloc+0x22a>
   1400020d2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020d6:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400020d9:	0f b7 c0             	movzx  eax,ax
   1400020dc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020e0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020e4:	25 00 80 00 00       	and    eax,0x8000
   1400020e9:	48 85 c0             	test   rax,rax
   1400020ec:	74 71                	je     14000215f <do_pseudo_reloc+0x22d>
   1400020ee:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020f2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400020f8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020fc:	eb 61                	jmp    14000215f <do_pseudo_reloc+0x22d>
   1400020fe:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002102:	8b 00                	mov    eax,DWORD PTR [rax]
   140002104:	89 c0                	mov    eax,eax
   140002106:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000210a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000210e:	25 00 00 00 80       	and    eax,0x80000000
   140002113:	48 85 c0             	test   rax,rax
   140002116:	74 4a                	je     140002162 <do_pseudo_reloc+0x230>
   140002118:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000211c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002123:	ff ff ff 
   140002126:	48 09 d0             	or     rax,rdx
   140002129:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000212d:	eb 33                	jmp    140002162 <do_pseudo_reloc+0x230>
   14000212f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002133:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002136:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000213a:	eb 27                	jmp    140002163 <do_pseudo_reloc+0x231>
   14000213c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002143:	00 
   140002144:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002148:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000214b:	0f b6 c0             	movzx  eax,al
   14000214e:	48 8d 0d 53 31 00 00 	lea    rcx,[rip+0x3153]        # 1400052a8 <.rdata+0xd8>
   140002155:	89 c2                	mov    edx,eax
   140002157:	e8 74 f9 ff ff       	call   140001ad0 <__report_error>
   14000215c:	90                   	nop
   14000215d:	eb 04                	jmp    140002163 <do_pseudo_reloc+0x231>
   14000215f:	90                   	nop
   140002160:	eb 01                	jmp    140002163 <do_pseudo_reloc+0x231>
   140002162:	90                   	nop
   140002163:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002167:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000216b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000216d:	89 c2                	mov    edx,eax
   14000216f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002173:	48 01 c2             	add    rdx,rax
   140002176:	48 89 c8             	mov    rax,rcx
   140002179:	48 29 d0             	sub    rax,rdx
   14000217c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002180:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002184:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002188:	48 01 d0             	add    rax,rdx
   14000218b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000218f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002193:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002196:	25 ff 00 00 00       	and    eax,0xff
   14000219b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000219e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400021a2:	77 67                	ja     14000220b <do_pseudo_reloc+0x2d9>
   1400021a4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021a7:	ba 01 00 00 00       	mov    edx,0x1
   1400021ac:	89 c1                	mov    ecx,eax
   1400021ae:	48 d3 e2             	shl    rdx,cl
   1400021b1:	48 89 d0             	mov    rax,rdx
   1400021b4:	48 83 e8 01          	sub    rax,0x1
   1400021b8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400021bc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021bf:	83 e8 01             	sub    eax,0x1
   1400021c2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400021c9:	89 c1                	mov    ecx,eax
   1400021cb:	48 d3 e2             	shl    rdx,cl
   1400021ce:	48 89 d0             	mov    rax,rdx
   1400021d1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400021d5:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021d9:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   1400021dd:	7c 0a                	jl     1400021e9 <do_pseudo_reloc+0x2b7>
   1400021df:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021e3:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400021e7:	7e 22                	jle    14000220b <do_pseudo_reloc+0x2d9>
   1400021e9:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021ed:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400021f1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400021f5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021f8:	48 8d 0d d9 30 00 00 	lea    rcx,[rip+0x30d9]        # 1400052d8 <.rdata+0x108>
   1400021ff:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002204:	89 c2                	mov    edx,eax
   140002206:	e8 c5 f8 ff ff       	call   140001ad0 <__report_error>
   14000220b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000220f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002212:	0f b6 c0             	movzx  eax,al
   140002215:	83 f8 40             	cmp    eax,0x40
   140002218:	74 63                	je     14000227d <do_pseudo_reloc+0x34b>
   14000221a:	83 f8 40             	cmp    eax,0x40
   14000221d:	77 75                	ja     140002294 <do_pseudo_reloc+0x362>
   14000221f:	83 f8 20             	cmp    eax,0x20
   140002222:	74 41                	je     140002265 <do_pseudo_reloc+0x333>
   140002224:	83 f8 20             	cmp    eax,0x20
   140002227:	77 6b                	ja     140002294 <do_pseudo_reloc+0x362>
   140002229:	83 f8 08             	cmp    eax,0x8
   14000222c:	74 07                	je     140002235 <do_pseudo_reloc+0x303>
   14000222e:	83 f8 10             	cmp    eax,0x10
   140002231:	74 1a                	je     14000224d <do_pseudo_reloc+0x31b>
   140002233:	eb 5f                	jmp    140002294 <do_pseudo_reloc+0x362>
   140002235:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002239:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000223d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002243:	48 89 c1             	mov    rcx,rax
   140002246:	e8 a0 fc ff ff       	call   140001eeb <__write_memory>
   14000224b:	eb 47                	jmp    140002294 <do_pseudo_reloc+0x362>
   14000224d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002251:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002255:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000225b:	48 89 c1             	mov    rcx,rax
   14000225e:	e8 88 fc ff ff       	call   140001eeb <__write_memory>
   140002263:	eb 2f                	jmp    140002294 <do_pseudo_reloc+0x362>
   140002265:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002269:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000226d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002273:	48 89 c1             	mov    rcx,rax
   140002276:	e8 70 fc ff ff       	call   140001eeb <__write_memory>
   14000227b:	eb 17                	jmp    140002294 <do_pseudo_reloc+0x362>
   14000227d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002281:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002285:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000228b:	48 89 c1             	mov    rcx,rax
   14000228e:	e8 58 fc ff ff       	call   140001eeb <__write_memory>
   140002293:	90                   	nop
   140002294:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002299:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000229d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400022a1:	0f 82 8d fd ff ff    	jb     140002034 <do_pseudo_reloc+0x102>
   1400022a7:	eb 01                	jmp    1400022aa <do_pseudo_reloc+0x378>
   1400022a9:	90                   	nop
   1400022aa:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400022ae:	5d                   	pop    rbp
   1400022af:	c3                   	ret

00000001400022b0 <_pei386_runtime_relocator>:
   1400022b0:	55                   	push   rbp
   1400022b1:	48 89 e5             	mov    rbp,rsp
   1400022b4:	48 83 ec 30          	sub    rsp,0x30
   1400022b8:	8b 05 2e 6e 00 00    	mov    eax,DWORD PTR [rip+0x6e2e]        # 1400090ec <was_init.0>
   1400022be:	85 c0                	test   eax,eax
   1400022c0:	0f 85 88 00 00 00    	jne    14000234e <_pei386_runtime_relocator+0x9e>
   1400022c6:	8b 05 20 6e 00 00    	mov    eax,DWORD PTR [rip+0x6e20]        # 1400090ec <was_init.0>
   1400022cc:	83 c0 01             	add    eax,0x1
   1400022cf:	89 05 17 6e 00 00    	mov    DWORD PTR [rip+0x6e17],eax        # 1400090ec <was_init.0>
   1400022d5:	e8 21 0b 00 00       	call   140002dfb <__mingw_GetSectionCount>
   1400022da:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400022dd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400022e0:	48 63 d0             	movsxd rdx,eax
   1400022e3:	48 89 d0             	mov    rax,rdx
   1400022e6:	48 c1 e0 02          	shl    rax,0x2
   1400022ea:	48 01 d0             	add    rax,rdx
   1400022ed:	48 c1 e0 03          	shl    rax,0x3
   1400022f1:	48 83 c0 0f          	add    rax,0xf
   1400022f5:	48 c1 e8 04          	shr    rax,0x4
   1400022f9:	48 c1 e0 04          	shl    rax,0x4
   1400022fd:	e8 7e 0d 00 00       	call   140003080 <___chkstk_ms>
   140002302:	48 29 c4             	sub    rsp,rax
   140002305:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000230a:	48 83 c0 0f          	add    rax,0xf
   14000230e:	48 c1 e8 04          	shr    rax,0x4
   140002312:	48 c1 e0 04          	shl    rax,0x4
   140002316:	48 89 05 c3 6d 00 00 	mov    QWORD PTR [rip+0x6dc3],rax        # 1400090e0 <the_secs>
   14000231d:	c7 05 c1 6d 00 00 00 	mov    DWORD PTR [rip+0x6dc1],0x0        # 1400090e8 <maxSections>
   140002324:	00 00 00 
   140002327:	48 8b 0d 32 30 00 00 	mov    rcx,QWORD PTR [rip+0x3032]        # 140005360 <.refptr.__ImageBase>
   14000232e:	48 8b 15 3b 30 00 00 	mov    rdx,QWORD PTR [rip+0x303b]        # 140005370 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002335:	48 8b 05 44 30 00 00 	mov    rax,QWORD PTR [rip+0x3044]        # 140005380 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000233c:	49 89 c8             	mov    r8,rcx
   14000233f:	48 89 c1             	mov    rcx,rax
   140002342:	e8 eb fb ff ff       	call   140001f32 <do_pseudo_reloc>
   140002347:	e8 c7 fa ff ff       	call   140001e13 <restore_modified_sections>
   14000234c:	eb 01                	jmp    14000234f <_pei386_runtime_relocator+0x9f>
   14000234e:	90                   	nop
   14000234f:	48 89 ec             	mov    rsp,rbp
   140002352:	5d                   	pop    rbp
   140002353:	c3                   	ret
   140002354:	90                   	nop
   140002355:	90                   	nop
   140002356:	90                   	nop
   140002357:	90                   	nop
   140002358:	90                   	nop
   140002359:	90                   	nop
   14000235a:	90                   	nop
   14000235b:	90                   	nop
   14000235c:	90                   	nop
   14000235d:	90                   	nop
   14000235e:	90                   	nop
   14000235f:	90                   	nop

0000000140002360 <__mingw_raise_matherr>:
   140002360:	55                   	push   rbp
   140002361:	48 89 e5             	mov    rbp,rsp
   140002364:	48 83 ec 50          	sub    rsp,0x50
   140002368:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000236b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000236f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002374:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002379:	48 8b 05 70 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d70]        # 1400090f0 <stUserMathErr>
   140002380:	48 85 c0             	test   rax,rax
   140002383:	74 3e                	je     1400023c3 <__mingw_raise_matherr+0x63>
   140002385:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002388:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000238b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000238f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002393:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002398:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000239d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400023a2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400023a7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400023ac:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400023b1:	48 8b 15 38 6d 00 00 	mov    rdx,QWORD PTR [rip+0x6d38]        # 1400090f0 <stUserMathErr>
   1400023b8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400023bc:	48 89 c1             	mov    rcx,rax
   1400023bf:	ff d2                	call   rdx
   1400023c1:	eb 01                	jmp    1400023c4 <__mingw_raise_matherr+0x64>
   1400023c3:	90                   	nop
   1400023c4:	48 83 c4 50          	add    rsp,0x50
   1400023c8:	5d                   	pop    rbp
   1400023c9:	c3                   	ret

00000001400023ca <__mingw_setusermatherr>:
   1400023ca:	55                   	push   rbp
   1400023cb:	48 89 e5             	mov    rbp,rsp
   1400023ce:	48 83 ec 20          	sub    rsp,0x20
   1400023d2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400023d6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400023da:	48 89 05 0f 6d 00 00 	mov    QWORD PTR [rip+0x6d0f],rax        # 1400090f0 <stUserMathErr>
   1400023e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400023e5:	48 89 c1             	mov    rcx,rax
   1400023e8:	e8 13 0e 00 00       	call   140003200 <__setusermatherr>
   1400023ed:	90                   	nop
   1400023ee:	48 83 c4 20          	add    rsp,0x20
   1400023f2:	5d                   	pop    rbp
   1400023f3:	c3                   	ret
   1400023f4:	90                   	nop
   1400023f5:	90                   	nop
   1400023f6:	90                   	nop
   1400023f7:	90                   	nop
   1400023f8:	90                   	nop
   1400023f9:	90                   	nop
   1400023fa:	90                   	nop
   1400023fb:	90                   	nop
   1400023fc:	90                   	nop
   1400023fd:	90                   	nop
   1400023fe:	90                   	nop
   1400023ff:	90                   	nop

0000000140002400 <__mingw_SEH_error_handler>:
   140002400:	55                   	push   rbp
   140002401:	48 89 e5             	mov    rbp,rsp
   140002404:	48 83 ec 30          	sub    rsp,0x30
   140002408:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000240c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002410:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002414:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002418:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000241f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002426:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000242a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000242d:	83 e0 02             	and    eax,0x2
   140002430:	85 c0                	test   eax,eax
   140002432:	74 0a                	je     14000243e <__mingw_SEH_error_handler+0x3e>
   140002434:	b8 01 00 00 00       	mov    eax,0x1
   140002439:	e9 16 02 00 00       	jmp    140002654 <__mingw_SEH_error_handler+0x254>
   14000243e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002442:	8b 00                	mov    eax,DWORD PTR [rax]
   140002444:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002449:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000244e:	75 18                	jne    140002468 <__mingw_SEH_error_handler+0x68>
   140002450:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002454:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002457:	83 e0 01             	and    eax,0x1
   14000245a:	85 c0                	test   eax,eax
   14000245c:	75 0a                	jne    140002468 <__mingw_SEH_error_handler+0x68>
   14000245e:	b8 00 00 00 00       	mov    eax,0x0
   140002463:	e9 ec 01 00 00       	jmp    140002654 <__mingw_SEH_error_handler+0x254>
   140002468:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000246c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000246e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002473:	0f 84 12 01 00 00    	je     14000258b <__mingw_SEH_error_handler+0x18b>
   140002479:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000247e:	0f 87 c3 01 00 00    	ja     140002647 <__mingw_SEH_error_handler+0x247>
   140002484:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002489:	0f 87 b8 01 00 00    	ja     140002647 <__mingw_SEH_error_handler+0x247>
   14000248f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002494:	0f 83 4c 01 00 00    	jae    1400025e6 <__mingw_SEH_error_handler+0x1e6>
   14000249a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000249f:	0f 84 3a 01 00 00    	je     1400025df <__mingw_SEH_error_handler+0x1df>
   1400024a5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024aa:	0f 87 97 01 00 00    	ja     140002647 <__mingw_SEH_error_handler+0x247>
   1400024b0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024b5:	0f 84 83 01 00 00    	je     14000263e <__mingw_SEH_error_handler+0x23e>
   1400024bb:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024c0:	0f 87 81 01 00 00    	ja     140002647 <__mingw_SEH_error_handler+0x247>
   1400024c6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400024cb:	0f 87 76 01 00 00    	ja     140002647 <__mingw_SEH_error_handler+0x247>
   1400024d1:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400024d6:	0f 83 03 01 00 00    	jae    1400025df <__mingw_SEH_error_handler+0x1df>
   1400024dc:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400024e1:	0f 84 57 01 00 00    	je     14000263e <__mingw_SEH_error_handler+0x23e>
   1400024e7:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400024ec:	0f 87 55 01 00 00    	ja     140002647 <__mingw_SEH_error_handler+0x247>
   1400024f2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400024f7:	0f 84 8e 00 00 00    	je     14000258b <__mingw_SEH_error_handler+0x18b>
   1400024fd:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002502:	0f 87 3f 01 00 00    	ja     140002647 <__mingw_SEH_error_handler+0x247>
   140002508:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000250d:	0f 84 2b 01 00 00    	je     14000263e <__mingw_SEH_error_handler+0x23e>
   140002513:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002518:	0f 87 29 01 00 00    	ja     140002647 <__mingw_SEH_error_handler+0x247>
   14000251e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002523:	0f 84 15 01 00 00    	je     14000263e <__mingw_SEH_error_handler+0x23e>
   140002529:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000252e:	0f 85 13 01 00 00    	jne    140002647 <__mingw_SEH_error_handler+0x247>
   140002534:	ba 00 00 00 00       	mov    edx,0x0
   140002539:	b9 0b 00 00 00       	mov    ecx,0xb
   14000253e:	e8 2d 0d 00 00       	call   140003270 <signal>
   140002543:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002547:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000254c:	75 1b                	jne    140002569 <__mingw_SEH_error_handler+0x169>
   14000254e:	ba 01 00 00 00       	mov    edx,0x1
   140002553:	b9 0b 00 00 00       	mov    ecx,0xb
   140002558:	e8 13 0d 00 00       	call   140003270 <signal>
   14000255d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002564:	e9 e1 00 00 00       	jmp    14000264a <__mingw_SEH_error_handler+0x24a>
   140002569:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000256e:	0f 84 d6 00 00 00    	je     14000264a <__mingw_SEH_error_handler+0x24a>
   140002574:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002578:	b9 0b 00 00 00       	mov    ecx,0xb
   14000257d:	ff d0                	call   rax
   14000257f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002586:	e9 bf 00 00 00       	jmp    14000264a <__mingw_SEH_error_handler+0x24a>
   14000258b:	ba 00 00 00 00       	mov    edx,0x0
   140002590:	b9 04 00 00 00       	mov    ecx,0x4
   140002595:	e8 d6 0c 00 00       	call   140003270 <signal>
   14000259a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000259e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025a3:	75 1b                	jne    1400025c0 <__mingw_SEH_error_handler+0x1c0>
   1400025a5:	ba 01 00 00 00       	mov    edx,0x1
   1400025aa:	b9 04 00 00 00       	mov    ecx,0x4
   1400025af:	e8 bc 0c 00 00       	call   140003270 <signal>
   1400025b4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025bb:	e9 8d 00 00 00       	jmp    14000264d <__mingw_SEH_error_handler+0x24d>
   1400025c0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025c5:	0f 84 82 00 00 00    	je     14000264d <__mingw_SEH_error_handler+0x24d>
   1400025cb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025cf:	b9 04 00 00 00       	mov    ecx,0x4
   1400025d4:	ff d0                	call   rax
   1400025d6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025dd:	eb 6e                	jmp    14000264d <__mingw_SEH_error_handler+0x24d>
   1400025df:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400025e6:	ba 00 00 00 00       	mov    edx,0x0
   1400025eb:	b9 08 00 00 00       	mov    ecx,0x8
   1400025f0:	e8 7b 0c 00 00       	call   140003270 <signal>
   1400025f5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025f9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025fe:	75 23                	jne    140002623 <__mingw_SEH_error_handler+0x223>
   140002600:	ba 01 00 00 00       	mov    edx,0x1
   140002605:	b9 08 00 00 00       	mov    ecx,0x8
   14000260a:	e8 61 0c 00 00       	call   140003270 <signal>
   14000260f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002613:	74 05                	je     14000261a <__mingw_SEH_error_handler+0x21a>
   140002615:	e8 a6 05 00 00       	call   140002bc0 <_fpreset>
   14000261a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002621:	eb 2d                	jmp    140002650 <__mingw_SEH_error_handler+0x250>
   140002623:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002628:	74 26                	je     140002650 <__mingw_SEH_error_handler+0x250>
   14000262a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000262e:	b9 08 00 00 00       	mov    ecx,0x8
   140002633:	ff d0                	call   rax
   140002635:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000263c:	eb 12                	jmp    140002650 <__mingw_SEH_error_handler+0x250>
   14000263e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002645:	eb 0a                	jmp    140002651 <__mingw_SEH_error_handler+0x251>
   140002647:	90                   	nop
   140002648:	eb 07                	jmp    140002651 <__mingw_SEH_error_handler+0x251>
   14000264a:	90                   	nop
   14000264b:	eb 04                	jmp    140002651 <__mingw_SEH_error_handler+0x251>
   14000264d:	90                   	nop
   14000264e:	eb 01                	jmp    140002651 <__mingw_SEH_error_handler+0x251>
   140002650:	90                   	nop
   140002651:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002654:	48 83 c4 30          	add    rsp,0x30
   140002658:	5d                   	pop    rbp
   140002659:	c3                   	ret

000000014000265a <_gnu_exception_handler>:
   14000265a:	55                   	push   rbp
   14000265b:	48 89 e5             	mov    rbp,rsp
   14000265e:	48 83 ec 30          	sub    rsp,0x30
   140002662:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002666:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000266d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002674:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002678:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000267b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000267d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002682:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002687:	75 1b                	jne    1400026a4 <_gnu_exception_handler+0x4a>
   140002689:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000268d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002690:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002693:	83 e0 01             	and    eax,0x1
   140002696:	85 c0                	test   eax,eax
   140002698:	75 0a                	jne    1400026a4 <_gnu_exception_handler+0x4a>
   14000269a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000269f:	e9 14 02 00 00       	jmp    1400028b8 <_gnu_exception_handler+0x25e>
   1400026a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026a8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026ad:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026b2:	0f 84 12 01 00 00    	je     1400027ca <_gnu_exception_handler+0x170>
   1400026b8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026bd:	0f 87 c3 01 00 00    	ja     140002886 <_gnu_exception_handler+0x22c>
   1400026c3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400026c8:	0f 87 b8 01 00 00    	ja     140002886 <_gnu_exception_handler+0x22c>
   1400026ce:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400026d3:	0f 83 4c 01 00 00    	jae    140002825 <_gnu_exception_handler+0x1cb>
   1400026d9:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400026de:	0f 84 3a 01 00 00    	je     14000281e <_gnu_exception_handler+0x1c4>
   1400026e4:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400026e9:	0f 87 97 01 00 00    	ja     140002886 <_gnu_exception_handler+0x22c>
   1400026ef:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400026f4:	0f 84 83 01 00 00    	je     14000287d <_gnu_exception_handler+0x223>
   1400026fa:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400026ff:	0f 87 81 01 00 00    	ja     140002886 <_gnu_exception_handler+0x22c>
   140002705:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000270a:	0f 87 76 01 00 00    	ja     140002886 <_gnu_exception_handler+0x22c>
   140002710:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002715:	0f 83 03 01 00 00    	jae    14000281e <_gnu_exception_handler+0x1c4>
   14000271b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002720:	0f 84 57 01 00 00    	je     14000287d <_gnu_exception_handler+0x223>
   140002726:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000272b:	0f 87 55 01 00 00    	ja     140002886 <_gnu_exception_handler+0x22c>
   140002731:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002736:	0f 84 8e 00 00 00    	je     1400027ca <_gnu_exception_handler+0x170>
   14000273c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002741:	0f 87 3f 01 00 00    	ja     140002886 <_gnu_exception_handler+0x22c>
   140002747:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000274c:	0f 84 2b 01 00 00    	je     14000287d <_gnu_exception_handler+0x223>
   140002752:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002757:	0f 87 29 01 00 00    	ja     140002886 <_gnu_exception_handler+0x22c>
   14000275d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002762:	0f 84 15 01 00 00    	je     14000287d <_gnu_exception_handler+0x223>
   140002768:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000276d:	0f 85 13 01 00 00    	jne    140002886 <_gnu_exception_handler+0x22c>
   140002773:	ba 00 00 00 00       	mov    edx,0x0
   140002778:	b9 0b 00 00 00       	mov    ecx,0xb
   14000277d:	e8 ee 0a 00 00       	call   140003270 <signal>
   140002782:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002786:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000278b:	75 1b                	jne    1400027a8 <_gnu_exception_handler+0x14e>
   14000278d:	ba 01 00 00 00       	mov    edx,0x1
   140002792:	b9 0b 00 00 00       	mov    ecx,0xb
   140002797:	e8 d4 0a 00 00       	call   140003270 <signal>
   14000279c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027a3:	e9 e1 00 00 00       	jmp    140002889 <_gnu_exception_handler+0x22f>
   1400027a8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027ad:	0f 84 d6 00 00 00    	je     140002889 <_gnu_exception_handler+0x22f>
   1400027b3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027b7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027bc:	ff d0                	call   rax
   1400027be:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027c5:	e9 bf 00 00 00       	jmp    140002889 <_gnu_exception_handler+0x22f>
   1400027ca:	ba 00 00 00 00       	mov    edx,0x0
   1400027cf:	b9 04 00 00 00       	mov    ecx,0x4
   1400027d4:	e8 97 0a 00 00       	call   140003270 <signal>
   1400027d9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027dd:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027e2:	75 1b                	jne    1400027ff <_gnu_exception_handler+0x1a5>
   1400027e4:	ba 01 00 00 00       	mov    edx,0x1
   1400027e9:	b9 04 00 00 00       	mov    ecx,0x4
   1400027ee:	e8 7d 0a 00 00       	call   140003270 <signal>
   1400027f3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027fa:	e9 8d 00 00 00       	jmp    14000288c <_gnu_exception_handler+0x232>
   1400027ff:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002804:	0f 84 82 00 00 00    	je     14000288c <_gnu_exception_handler+0x232>
   14000280a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000280e:	b9 04 00 00 00       	mov    ecx,0x4
   140002813:	ff d0                	call   rax
   140002815:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000281c:	eb 6e                	jmp    14000288c <_gnu_exception_handler+0x232>
   14000281e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002825:	ba 00 00 00 00       	mov    edx,0x0
   14000282a:	b9 08 00 00 00       	mov    ecx,0x8
   14000282f:	e8 3c 0a 00 00       	call   140003270 <signal>
   140002834:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002838:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000283d:	75 23                	jne    140002862 <_gnu_exception_handler+0x208>
   14000283f:	ba 01 00 00 00       	mov    edx,0x1
   140002844:	b9 08 00 00 00       	mov    ecx,0x8
   140002849:	e8 22 0a 00 00       	call   140003270 <signal>
   14000284e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002852:	74 05                	je     140002859 <_gnu_exception_handler+0x1ff>
   140002854:	e8 67 03 00 00       	call   140002bc0 <_fpreset>
   140002859:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002860:	eb 2d                	jmp    14000288f <_gnu_exception_handler+0x235>
   140002862:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002867:	74 26                	je     14000288f <_gnu_exception_handler+0x235>
   140002869:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000286d:	b9 08 00 00 00       	mov    ecx,0x8
   140002872:	ff d0                	call   rax
   140002874:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000287b:	eb 12                	jmp    14000288f <_gnu_exception_handler+0x235>
   14000287d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002884:	eb 0a                	jmp    140002890 <_gnu_exception_handler+0x236>
   140002886:	90                   	nop
   140002887:	eb 07                	jmp    140002890 <_gnu_exception_handler+0x236>
   140002889:	90                   	nop
   14000288a:	eb 04                	jmp    140002890 <_gnu_exception_handler+0x236>
   14000288c:	90                   	nop
   14000288d:	eb 01                	jmp    140002890 <_gnu_exception_handler+0x236>
   14000288f:	90                   	nop
   140002890:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002894:	75 1f                	jne    1400028b5 <_gnu_exception_handler+0x25b>
   140002896:	48 8b 05 73 68 00 00 	mov    rax,QWORD PTR [rip+0x6873]        # 140009110 <__mingw_oldexcpt_handler>
   14000289d:	48 85 c0             	test   rax,rax
   1400028a0:	74 13                	je     1400028b5 <_gnu_exception_handler+0x25b>
   1400028a2:	48 8b 15 67 68 00 00 	mov    rdx,QWORD PTR [rip+0x6867]        # 140009110 <__mingw_oldexcpt_handler>
   1400028a9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028ad:	48 89 c1             	mov    rcx,rax
   1400028b0:	ff d2                	call   rdx
   1400028b2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400028b5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400028b8:	48 83 c4 30          	add    rsp,0x30
   1400028bc:	5d                   	pop    rbp
   1400028bd:	c3                   	ret
   1400028be:	90                   	nop
   1400028bf:	90                   	nop

00000001400028c0 <___w64_mingwthr_add_key_dtor>:
   1400028c0:	55                   	push   rbp
   1400028c1:	48 89 e5             	mov    rbp,rsp
   1400028c4:	48 83 ec 30          	sub    rsp,0x30
   1400028c8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400028cb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400028cf:	8b 05 73 68 00 00    	mov    eax,DWORD PTR [rip+0x6873]        # 140009148 <__mingwthr_cs_init>
   1400028d5:	85 c0                	test   eax,eax
   1400028d7:	75 07                	jne    1400028e0 <___w64_mingwthr_add_key_dtor+0x20>
   1400028d9:	b8 00 00 00 00       	mov    eax,0x0
   1400028de:	eb 7b                	jmp    14000295b <___w64_mingwthr_add_key_dtor+0x9b>
   1400028e0:	ba 18 00 00 00       	mov    edx,0x18
   1400028e5:	b9 01 00 00 00       	mov    ecx,0x1
   1400028ea:	e8 41 09 00 00       	call   140003230 <calloc>
   1400028ef:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400028f3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400028f8:	75 07                	jne    140002901 <___w64_mingwthr_add_key_dtor+0x41>
   1400028fa:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400028ff:	eb 5a                	jmp    14000295b <___w64_mingwthr_add_key_dtor+0x9b>
   140002901:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002905:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002908:	89 10                	mov    DWORD PTR [rax],edx
   14000290a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000290e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002912:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002916:	48 8d 05 03 68 00 00 	lea    rax,[rip+0x6803]        # 140009120 <__mingwthr_cs>
   14000291d:	48 89 c1             	mov    rcx,rax
   140002920:	48 8b 05 69 78 00 00 	mov    rax,QWORD PTR [rip+0x7869]        # 14000a190 <__imp_EnterCriticalSection>
   140002927:	ff d0                	call   rax
   140002929:	48 8b 15 20 68 00 00 	mov    rdx,QWORD PTR [rip+0x6820]        # 140009150 <key_dtor_list>
   140002930:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002934:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002938:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000293c:	48 89 05 0d 68 00 00 	mov    QWORD PTR [rip+0x680d],rax        # 140009150 <key_dtor_list>
   140002943:	48 8d 05 d6 67 00 00 	lea    rax,[rip+0x67d6]        # 140009120 <__mingwthr_cs>
   14000294a:	48 89 c1             	mov    rcx,rax
   14000294d:	48 8b 05 6c 78 00 00 	mov    rax,QWORD PTR [rip+0x786c]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002954:	ff d0                	call   rax
   140002956:	b8 00 00 00 00       	mov    eax,0x0
   14000295b:	48 83 c4 30          	add    rsp,0x30
   14000295f:	5d                   	pop    rbp
   140002960:	c3                   	ret

0000000140002961 <___w64_mingwthr_remove_key_dtor>:
   140002961:	55                   	push   rbp
   140002962:	48 89 e5             	mov    rbp,rsp
   140002965:	48 83 ec 30          	sub    rsp,0x30
   140002969:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000296c:	8b 05 d6 67 00 00    	mov    eax,DWORD PTR [rip+0x67d6]        # 140009148 <__mingwthr_cs_init>
   140002972:	85 c0                	test   eax,eax
   140002974:	75 0a                	jne    140002980 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002976:	b8 00 00 00 00       	mov    eax,0x0
   14000297b:	e9 9c 00 00 00       	jmp    140002a1c <___w64_mingwthr_remove_key_dtor+0xbb>
   140002980:	48 8d 05 99 67 00 00 	lea    rax,[rip+0x6799]        # 140009120 <__mingwthr_cs>
   140002987:	48 89 c1             	mov    rcx,rax
   14000298a:	48 8b 05 ff 77 00 00 	mov    rax,QWORD PTR [rip+0x77ff]        # 14000a190 <__imp_EnterCriticalSection>
   140002991:	ff d0                	call   rax
   140002993:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   14000299a:	00 
   14000299b:	48 8b 05 ae 67 00 00 	mov    rax,QWORD PTR [rip+0x67ae]        # 140009150 <key_dtor_list>
   1400029a2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029a6:	eb 55                	jmp    1400029fd <___w64_mingwthr_remove_key_dtor+0x9c>
   1400029a8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ac:	8b 00                	mov    eax,DWORD PTR [rax]
   1400029ae:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   1400029b1:	75 36                	jne    1400029e9 <___w64_mingwthr_remove_key_dtor+0x88>
   1400029b3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029b8:	75 11                	jne    1400029cb <___w64_mingwthr_remove_key_dtor+0x6a>
   1400029ba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029be:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   1400029c2:	48 89 05 87 67 00 00 	mov    QWORD PTR [rip+0x6787],rax        # 140009150 <key_dtor_list>
   1400029c9:	eb 10                	jmp    1400029db <___w64_mingwthr_remove_key_dtor+0x7a>
   1400029cb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029cf:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   1400029d3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029d7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029db:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029df:	48 89 c1             	mov    rcx,rax
   1400029e2:	e8 69 08 00 00       	call   140003250 <free>
   1400029e7:	eb 1b                	jmp    140002a04 <___w64_mingwthr_remove_key_dtor+0xa3>
   1400029e9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ed:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400029f1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029f5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   1400029f9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029fd:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a02:	75 a4                	jne    1400029a8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a04:	48 8d 05 15 67 00 00 	lea    rax,[rip+0x6715]        # 140009120 <__mingwthr_cs>
   140002a0b:	48 89 c1             	mov    rcx,rax
   140002a0e:	48 8b 05 ab 77 00 00 	mov    rax,QWORD PTR [rip+0x77ab]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002a15:	ff d0                	call   rax
   140002a17:	b8 00 00 00 00       	mov    eax,0x0
   140002a1c:	48 83 c4 30          	add    rsp,0x30
   140002a20:	5d                   	pop    rbp
   140002a21:	c3                   	ret

0000000140002a22 <__mingwthr_run_key_dtors>:
   140002a22:	55                   	push   rbp
   140002a23:	48 89 e5             	mov    rbp,rsp
   140002a26:	48 83 ec 30          	sub    rsp,0x30
   140002a2a:	8b 05 18 67 00 00    	mov    eax,DWORD PTR [rip+0x6718]        # 140009148 <__mingwthr_cs_init>
   140002a30:	85 c0                	test   eax,eax
   140002a32:	0f 84 82 00 00 00    	je     140002aba <__mingwthr_run_key_dtors+0x98>
   140002a38:	48 8d 05 e1 66 00 00 	lea    rax,[rip+0x66e1]        # 140009120 <__mingwthr_cs>
   140002a3f:	48 89 c1             	mov    rcx,rax
   140002a42:	48 8b 05 47 77 00 00 	mov    rax,QWORD PTR [rip+0x7747]        # 14000a190 <__imp_EnterCriticalSection>
   140002a49:	ff d0                	call   rax
   140002a4b:	48 8b 05 fe 66 00 00 	mov    rax,QWORD PTR [rip+0x66fe]        # 140009150 <key_dtor_list>
   140002a52:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a56:	eb 46                	jmp    140002a9e <__mingwthr_run_key_dtors+0x7c>
   140002a58:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a5c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a5e:	89 c1                	mov    ecx,eax
   140002a60:	48 8b 05 79 77 00 00 	mov    rax,QWORD PTR [rip+0x7779]        # 14000a1e0 <__imp_TlsGetValue>
   140002a67:	ff d0                	call   rax
   140002a69:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a6d:	48 8b 05 2c 77 00 00 	mov    rax,QWORD PTR [rip+0x772c]        # 14000a1a0 <__imp_GetLastError>
   140002a74:	ff d0                	call   rax
   140002a76:	85 c0                	test   eax,eax
   140002a78:	75 18                	jne    140002a92 <__mingwthr_run_key_dtors+0x70>
   140002a7a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a7f:	74 11                	je     140002a92 <__mingwthr_run_key_dtors+0x70>
   140002a81:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a85:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002a89:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a8d:	48 89 c1             	mov    rcx,rax
   140002a90:	ff d2                	call   rdx
   140002a92:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a96:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a9a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a9e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002aa3:	75 b3                	jne    140002a58 <__mingwthr_run_key_dtors+0x36>
   140002aa5:	48 8d 05 74 66 00 00 	lea    rax,[rip+0x6674]        # 140009120 <__mingwthr_cs>
   140002aac:	48 89 c1             	mov    rcx,rax
   140002aaf:	48 8b 05 0a 77 00 00 	mov    rax,QWORD PTR [rip+0x770a]        # 14000a1c0 <__imp_LeaveCriticalSection>
   140002ab6:	ff d0                	call   rax
   140002ab8:	eb 01                	jmp    140002abb <__mingwthr_run_key_dtors+0x99>
   140002aba:	90                   	nop
   140002abb:	48 83 c4 30          	add    rsp,0x30
   140002abf:	5d                   	pop    rbp
   140002ac0:	c3                   	ret

0000000140002ac1 <__mingw_TLScallback>:
   140002ac1:	55                   	push   rbp
   140002ac2:	48 89 e5             	mov    rbp,rsp
   140002ac5:	48 83 ec 30          	sub    rsp,0x30
   140002ac9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002acd:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002ad0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002ad4:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002ad8:	0f 84 cc 00 00 00    	je     140002baa <__mingw_TLScallback+0xe9>
   140002ade:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002ae2:	0f 87 ca 00 00 00    	ja     140002bb2 <__mingw_TLScallback+0xf1>
   140002ae8:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002aec:	0f 84 b1 00 00 00    	je     140002ba3 <__mingw_TLScallback+0xe2>
   140002af2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002af6:	0f 87 b6 00 00 00    	ja     140002bb2 <__mingw_TLScallback+0xf1>
   140002afc:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b00:	74 33                	je     140002b35 <__mingw_TLScallback+0x74>
   140002b02:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b06:	0f 85 a6 00 00 00    	jne    140002bb2 <__mingw_TLScallback+0xf1>
   140002b0c:	8b 05 36 66 00 00    	mov    eax,DWORD PTR [rip+0x6636]        # 140009148 <__mingwthr_cs_init>
   140002b12:	85 c0                	test   eax,eax
   140002b14:	75 13                	jne    140002b29 <__mingw_TLScallback+0x68>
   140002b16:	48 8d 05 03 66 00 00 	lea    rax,[rip+0x6603]        # 140009120 <__mingwthr_cs>
   140002b1d:	48 89 c1             	mov    rcx,rax
   140002b20:	48 8b 05 91 76 00 00 	mov    rax,QWORD PTR [rip+0x7691]        # 14000a1b8 <__imp_InitializeCriticalSection>
   140002b27:	ff d0                	call   rax
   140002b29:	c7 05 15 66 00 00 01 	mov    DWORD PTR [rip+0x6615],0x1        # 140009148 <__mingwthr_cs_init>
   140002b30:	00 00 00 
   140002b33:	eb 7d                	jmp    140002bb2 <__mingw_TLScallback+0xf1>
   140002b35:	e8 e8 fe ff ff       	call   140002a22 <__mingwthr_run_key_dtors>
   140002b3a:	8b 05 08 66 00 00    	mov    eax,DWORD PTR [rip+0x6608]        # 140009148 <__mingwthr_cs_init>
   140002b40:	83 f8 01             	cmp    eax,0x1
   140002b43:	75 6c                	jne    140002bb1 <__mingw_TLScallback+0xf0>
   140002b45:	48 8b 05 04 66 00 00 	mov    rax,QWORD PTR [rip+0x6604]        # 140009150 <key_dtor_list>
   140002b4c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b50:	eb 20                	jmp    140002b72 <__mingw_TLScallback+0xb1>
   140002b52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b56:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b5a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b5e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b62:	48 89 c1             	mov    rcx,rax
   140002b65:	e8 e6 06 00 00       	call   140003250 <free>
   140002b6a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b6e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b72:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b77:	75 d9                	jne    140002b52 <__mingw_TLScallback+0x91>
   140002b79:	48 c7 05 cc 65 00 00 	mov    QWORD PTR [rip+0x65cc],0x0        # 140009150 <key_dtor_list>
   140002b80:	00 00 00 00 
   140002b84:	c7 05 ba 65 00 00 00 	mov    DWORD PTR [rip+0x65ba],0x0        # 140009148 <__mingwthr_cs_init>
   140002b8b:	00 00 00 
   140002b8e:	48 8d 05 8b 65 00 00 	lea    rax,[rip+0x658b]        # 140009120 <__mingwthr_cs>
   140002b95:	48 89 c1             	mov    rcx,rax
   140002b98:	48 8b 05 e9 75 00 00 	mov    rax,QWORD PTR [rip+0x75e9]        # 14000a188 <__IAT_start__>
   140002b9f:	ff d0                	call   rax
   140002ba1:	eb 0e                	jmp    140002bb1 <__mingw_TLScallback+0xf0>
   140002ba3:	e8 18 00 00 00       	call   140002bc0 <_fpreset>
   140002ba8:	eb 08                	jmp    140002bb2 <__mingw_TLScallback+0xf1>
   140002baa:	e8 73 fe ff ff       	call   140002a22 <__mingwthr_run_key_dtors>
   140002baf:	eb 01                	jmp    140002bb2 <__mingw_TLScallback+0xf1>
   140002bb1:	90                   	nop
   140002bb2:	b8 01 00 00 00       	mov    eax,0x1
   140002bb7:	48 83 c4 30          	add    rsp,0x30
   140002bbb:	5d                   	pop    rbp
   140002bbc:	c3                   	ret
   140002bbd:	90                   	nop
   140002bbe:	90                   	nop
   140002bbf:	90                   	nop

0000000140002bc0 <_fpreset>:
   140002bc0:	55                   	push   rbp
   140002bc1:	48 89 e5             	mov    rbp,rsp
   140002bc4:	db e3                	fninit
   140002bc6:	90                   	nop
   140002bc7:	5d                   	pop    rbp
   140002bc8:	c3                   	ret
   140002bc9:	90                   	nop
   140002bca:	90                   	nop
   140002bcb:	90                   	nop
   140002bcc:	90                   	nop
   140002bcd:	90                   	nop
   140002bce:	90                   	nop
   140002bcf:	90                   	nop

0000000140002bd0 <_ValidateImageBase>:
   140002bd0:	55                   	push   rbp
   140002bd1:	48 89 e5             	mov    rbp,rsp
   140002bd4:	48 83 ec 20          	sub    rsp,0x20
   140002bd8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002bdc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002be0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002be4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002be8:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002beb:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002bef:	74 07                	je     140002bf8 <_ValidateImageBase+0x28>
   140002bf1:	b8 00 00 00 00       	mov    eax,0x0
   140002bf6:	eb 4e                	jmp    140002c46 <_ValidateImageBase+0x76>
   140002bf8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bfc:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002bff:	48 63 d0             	movsxd rdx,eax
   140002c02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c06:	48 01 d0             	add    rax,rdx
   140002c09:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c0d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c11:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c13:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c18:	74 07                	je     140002c21 <_ValidateImageBase+0x51>
   140002c1a:	b8 00 00 00 00       	mov    eax,0x0
   140002c1f:	eb 25                	jmp    140002c46 <_ValidateImageBase+0x76>
   140002c21:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c25:	48 83 c0 18          	add    rax,0x18
   140002c29:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c2d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c31:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c34:	66 3d 0b 02          	cmp    ax,0x20b
   140002c38:	74 07                	je     140002c41 <_ValidateImageBase+0x71>
   140002c3a:	b8 00 00 00 00       	mov    eax,0x0
   140002c3f:	eb 05                	jmp    140002c46 <_ValidateImageBase+0x76>
   140002c41:	b8 01 00 00 00       	mov    eax,0x1
   140002c46:	48 83 c4 20          	add    rsp,0x20
   140002c4a:	5d                   	pop    rbp
   140002c4b:	c3                   	ret

0000000140002c4c <_FindPESection>:
   140002c4c:	55                   	push   rbp
   140002c4d:	48 89 e5             	mov    rbp,rsp
   140002c50:	48 83 ec 20          	sub    rsp,0x20
   140002c54:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c58:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002c5c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c60:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c63:	48 63 d0             	movsxd rdx,eax
   140002c66:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c6a:	48 01 d0             	add    rax,rdx
   140002c6d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c71:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002c78:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c7c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002c80:	0f b7 d0             	movzx  edx,ax
   140002c83:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c87:	48 01 d0             	add    rax,rdx
   140002c8a:	48 83 c0 18          	add    rax,0x18
   140002c8e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c92:	eb 36                	jmp    140002cca <_FindPESection+0x7e>
   140002c94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c98:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002c9b:	89 c0                	mov    eax,eax
   140002c9d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002ca1:	72 1e                	jb     140002cc1 <_FindPESection+0x75>
   140002ca3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ca7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002caa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cae:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002cb1:	01 d0                	add    eax,edx
   140002cb3:	89 c0                	mov    eax,eax
   140002cb5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cb9:	73 06                	jae    140002cc1 <_FindPESection+0x75>
   140002cbb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cbf:	eb 1e                	jmp    140002cdf <_FindPESection+0x93>
   140002cc1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002cc5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002cca:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cce:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002cd2:	0f b7 c0             	movzx  eax,ax
   140002cd5:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002cd8:	72 ba                	jb     140002c94 <_FindPESection+0x48>
   140002cda:	b8 00 00 00 00       	mov    eax,0x0
   140002cdf:	48 83 c4 20          	add    rsp,0x20
   140002ce3:	5d                   	pop    rbp
   140002ce4:	c3                   	ret

0000000140002ce5 <_FindPESectionByName>:
   140002ce5:	55                   	push   rbp
   140002ce6:	48 89 e5             	mov    rbp,rsp
   140002ce9:	48 83 ec 40          	sub    rsp,0x40
   140002ced:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002cf1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cf5:	48 89 c1             	mov    rcx,rax
   140002cf8:	e8 7b 05 00 00       	call   140003278 <strlen>
   140002cfd:	48 83 f8 08          	cmp    rax,0x8
   140002d01:	76 0a                	jbe    140002d0d <_FindPESectionByName+0x28>
   140002d03:	b8 00 00 00 00       	mov    eax,0x0
   140002d08:	e9 98 00 00 00       	jmp    140002da5 <_FindPESectionByName+0xc0>
   140002d0d:	48 8b 05 4c 26 00 00 	mov    rax,QWORD PTR [rip+0x264c]        # 140005360 <.refptr.__ImageBase>
   140002d14:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d18:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d1c:	48 89 c1             	mov    rcx,rax
   140002d1f:	e8 ac fe ff ff       	call   140002bd0 <_ValidateImageBase>
   140002d24:	85 c0                	test   eax,eax
   140002d26:	75 07                	jne    140002d2f <_FindPESectionByName+0x4a>
   140002d28:	b8 00 00 00 00       	mov    eax,0x0
   140002d2d:	eb 76                	jmp    140002da5 <_FindPESectionByName+0xc0>
   140002d2f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d33:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d36:	48 63 d0             	movsxd rdx,eax
   140002d39:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d3d:	48 01 d0             	add    rax,rdx
   140002d40:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002d44:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d4b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d4f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d53:	0f b7 d0             	movzx  edx,ax
   140002d56:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d5a:	48 01 d0             	add    rax,rdx
   140002d5d:	48 83 c0 18          	add    rax,0x18
   140002d61:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d65:	eb 29                	jmp    140002d90 <_FindPESectionByName+0xab>
   140002d67:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d6b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002d6f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002d75:	48 89 c1             	mov    rcx,rax
   140002d78:	e8 03 05 00 00       	call   140003280 <strncmp>
   140002d7d:	85 c0                	test   eax,eax
   140002d7f:	75 06                	jne    140002d87 <_FindPESectionByName+0xa2>
   140002d81:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d85:	eb 1e                	jmp    140002da5 <_FindPESectionByName+0xc0>
   140002d87:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d8b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d90:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d94:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d98:	0f b7 c0             	movzx  eax,ax
   140002d9b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d9e:	72 c7                	jb     140002d67 <_FindPESectionByName+0x82>
   140002da0:	b8 00 00 00 00       	mov    eax,0x0
   140002da5:	48 83 c4 40          	add    rsp,0x40
   140002da9:	5d                   	pop    rbp
   140002daa:	c3                   	ret

0000000140002dab <__mingw_GetSectionForAddress>:
   140002dab:	55                   	push   rbp
   140002dac:	48 89 e5             	mov    rbp,rsp
   140002daf:	48 83 ec 30          	sub    rsp,0x30
   140002db3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002db7:	48 8b 05 a2 25 00 00 	mov    rax,QWORD PTR [rip+0x25a2]        # 140005360 <.refptr.__ImageBase>
   140002dbe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002dc2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dc6:	48 89 c1             	mov    rcx,rax
   140002dc9:	e8 02 fe ff ff       	call   140002bd0 <_ValidateImageBase>
   140002dce:	85 c0                	test   eax,eax
   140002dd0:	75 07                	jne    140002dd9 <__mingw_GetSectionForAddress+0x2e>
   140002dd2:	b8 00 00 00 00       	mov    eax,0x0
   140002dd7:	eb 1c                	jmp    140002df5 <__mingw_GetSectionForAddress+0x4a>
   140002dd9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ddd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002de1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002de5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002de9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ded:	48 89 c1             	mov    rcx,rax
   140002df0:	e8 57 fe ff ff       	call   140002c4c <_FindPESection>
   140002df5:	48 83 c4 30          	add    rsp,0x30
   140002df9:	5d                   	pop    rbp
   140002dfa:	c3                   	ret

0000000140002dfb <__mingw_GetSectionCount>:
   140002dfb:	55                   	push   rbp
   140002dfc:	48 89 e5             	mov    rbp,rsp
   140002dff:	48 83 ec 30          	sub    rsp,0x30
   140002e03:	48 8b 05 56 25 00 00 	mov    rax,QWORD PTR [rip+0x2556]        # 140005360 <.refptr.__ImageBase>
   140002e0a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e0e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e12:	48 89 c1             	mov    rcx,rax
   140002e15:	e8 b6 fd ff ff       	call   140002bd0 <_ValidateImageBase>
   140002e1a:	85 c0                	test   eax,eax
   140002e1c:	75 07                	jne    140002e25 <__mingw_GetSectionCount+0x2a>
   140002e1e:	b8 00 00 00 00       	mov    eax,0x0
   140002e23:	eb 20                	jmp    140002e45 <__mingw_GetSectionCount+0x4a>
   140002e25:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e29:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e2c:	48 63 d0             	movsxd rdx,eax
   140002e2f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e33:	48 01 d0             	add    rax,rdx
   140002e36:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e3a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e3e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e42:	0f b7 c0             	movzx  eax,ax
   140002e45:	48 83 c4 30          	add    rsp,0x30
   140002e49:	5d                   	pop    rbp
   140002e4a:	c3                   	ret

0000000140002e4b <_FindPESectionExec>:
   140002e4b:	55                   	push   rbp
   140002e4c:	48 89 e5             	mov    rbp,rsp
   140002e4f:	48 83 ec 40          	sub    rsp,0x40
   140002e53:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e57:	48 8b 05 02 25 00 00 	mov    rax,QWORD PTR [rip+0x2502]        # 140005360 <.refptr.__ImageBase>
   140002e5e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e62:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e66:	48 89 c1             	mov    rcx,rax
   140002e69:	e8 62 fd ff ff       	call   140002bd0 <_ValidateImageBase>
   140002e6e:	85 c0                	test   eax,eax
   140002e70:	75 07                	jne    140002e79 <_FindPESectionExec+0x2e>
   140002e72:	b8 00 00 00 00       	mov    eax,0x0
   140002e77:	eb 78                	jmp    140002ef1 <_FindPESectionExec+0xa6>
   140002e79:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e7d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e80:	48 63 d0             	movsxd rdx,eax
   140002e83:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e87:	48 01 d0             	add    rax,rdx
   140002e8a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e8e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e95:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e99:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e9d:	0f b7 d0             	movzx  edx,ax
   140002ea0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ea4:	48 01 d0             	add    rax,rdx
   140002ea7:	48 83 c0 18          	add    rax,0x18
   140002eab:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002eaf:	eb 2b                	jmp    140002edc <_FindPESectionExec+0x91>
   140002eb1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002eb5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002eb8:	25 00 00 00 20       	and    eax,0x20000000
   140002ebd:	85 c0                	test   eax,eax
   140002ebf:	74 12                	je     140002ed3 <_FindPESectionExec+0x88>
   140002ec1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002ec6:	75 06                	jne    140002ece <_FindPESectionExec+0x83>
   140002ec8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ecc:	eb 23                	jmp    140002ef1 <_FindPESectionExec+0xa6>
   140002ece:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002ed3:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002ed7:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002edc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ee0:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ee4:	0f b7 c0             	movzx  eax,ax
   140002ee7:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002eea:	72 c5                	jb     140002eb1 <_FindPESectionExec+0x66>
   140002eec:	b8 00 00 00 00       	mov    eax,0x0
   140002ef1:	48 83 c4 40          	add    rsp,0x40
   140002ef5:	5d                   	pop    rbp
   140002ef6:	c3                   	ret

0000000140002ef7 <_GetPEImageBase>:
   140002ef7:	55                   	push   rbp
   140002ef8:	48 89 e5             	mov    rbp,rsp
   140002efb:	48 83 ec 30          	sub    rsp,0x30
   140002eff:	48 8b 05 5a 24 00 00 	mov    rax,QWORD PTR [rip+0x245a]        # 140005360 <.refptr.__ImageBase>
   140002f06:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f0a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f0e:	48 89 c1             	mov    rcx,rax
   140002f11:	e8 ba fc ff ff       	call   140002bd0 <_ValidateImageBase>
   140002f16:	85 c0                	test   eax,eax
   140002f18:	75 07                	jne    140002f21 <_GetPEImageBase+0x2a>
   140002f1a:	b8 00 00 00 00       	mov    eax,0x0
   140002f1f:	eb 04                	jmp    140002f25 <_GetPEImageBase+0x2e>
   140002f21:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f25:	48 83 c4 30          	add    rsp,0x30
   140002f29:	5d                   	pop    rbp
   140002f2a:	c3                   	ret

0000000140002f2b <_IsNonwritableInCurrentImage>:
   140002f2b:	55                   	push   rbp
   140002f2c:	48 89 e5             	mov    rbp,rsp
   140002f2f:	48 83 ec 40          	sub    rsp,0x40
   140002f33:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f37:	48 8b 05 22 24 00 00 	mov    rax,QWORD PTR [rip+0x2422]        # 140005360 <.refptr.__ImageBase>
   140002f3e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f46:	48 89 c1             	mov    rcx,rax
   140002f49:	e8 82 fc ff ff       	call   140002bd0 <_ValidateImageBase>
   140002f4e:	85 c0                	test   eax,eax
   140002f50:	75 07                	jne    140002f59 <_IsNonwritableInCurrentImage+0x2e>
   140002f52:	b8 00 00 00 00       	mov    eax,0x0
   140002f57:	eb 3d                	jmp    140002f96 <_IsNonwritableInCurrentImage+0x6b>
   140002f59:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f5d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002f61:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f65:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002f69:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f6d:	48 89 c1             	mov    rcx,rax
   140002f70:	e8 d7 fc ff ff       	call   140002c4c <_FindPESection>
   140002f75:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f79:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002f7e:	75 07                	jne    140002f87 <_IsNonwritableInCurrentImage+0x5c>
   140002f80:	b8 00 00 00 00       	mov    eax,0x0
   140002f85:	eb 0f                	jmp    140002f96 <_IsNonwritableInCurrentImage+0x6b>
   140002f87:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f8b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f8e:	f7 d0                	not    eax
   140002f90:	c1 e8 1f             	shr    eax,0x1f
   140002f93:	0f b6 c0             	movzx  eax,al
   140002f96:	48 83 c4 40          	add    rsp,0x40
   140002f9a:	5d                   	pop    rbp
   140002f9b:	c3                   	ret

0000000140002f9c <__mingw_enum_import_library_names>:
   140002f9c:	55                   	push   rbp
   140002f9d:	48 89 e5             	mov    rbp,rsp
   140002fa0:	48 83 ec 50          	sub    rsp,0x50
   140002fa4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002fa7:	48 8b 05 b2 23 00 00 	mov    rax,QWORD PTR [rip+0x23b2]        # 140005360 <.refptr.__ImageBase>
   140002fae:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fb2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fb6:	48 89 c1             	mov    rcx,rax
   140002fb9:	e8 12 fc ff ff       	call   140002bd0 <_ValidateImageBase>
   140002fbe:	85 c0                	test   eax,eax
   140002fc0:	75 0a                	jne    140002fcc <__mingw_enum_import_library_names+0x30>
   140002fc2:	b8 00 00 00 00       	mov    eax,0x0
   140002fc7:	e9 ab 00 00 00       	jmp    140003077 <__mingw_enum_import_library_names+0xdb>
   140002fcc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fd0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002fd3:	48 63 d0             	movsxd rdx,eax
   140002fd6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fda:	48 01 d0             	add    rax,rdx
   140002fdd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002fe1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002fe5:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   140002feb:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140002fee:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140002ff2:	75 07                	jne    140002ffb <__mingw_enum_import_library_names+0x5f>
   140002ff4:	b8 00 00 00 00       	mov    eax,0x0
   140002ff9:	eb 7c                	jmp    140003077 <__mingw_enum_import_library_names+0xdb>
   140002ffb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140002ffe:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003002:	48 89 c1             	mov    rcx,rax
   140003005:	e8 42 fc ff ff       	call   140002c4c <_FindPESection>
   14000300a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000300e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003013:	75 07                	jne    14000301c <__mingw_enum_import_library_names+0x80>
   140003015:	b8 00 00 00 00       	mov    eax,0x0
   14000301a:	eb 5b                	jmp    140003077 <__mingw_enum_import_library_names+0xdb>
   14000301c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000301f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003023:	48 01 d0             	add    rax,rdx
   140003026:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000302a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000302f:	75 07                	jne    140003038 <__mingw_enum_import_library_names+0x9c>
   140003031:	b8 00 00 00 00       	mov    eax,0x0
   140003036:	eb 3f                	jmp    140003077 <__mingw_enum_import_library_names+0xdb>
   140003038:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000303c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000303f:	85 c0                	test   eax,eax
   140003041:	75 0b                	jne    14000304e <__mingw_enum_import_library_names+0xb2>
   140003043:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003047:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000304a:	85 c0                	test   eax,eax
   14000304c:	74 23                	je     140003071 <__mingw_enum_import_library_names+0xd5>
   14000304e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003052:	7f 12                	jg     140003066 <__mingw_enum_import_library_names+0xca>
   140003054:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003058:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000305b:	89 c2                	mov    edx,eax
   14000305d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003061:	48 01 d0             	add    rax,rdx
   140003064:	eb 11                	jmp    140003077 <__mingw_enum_import_library_names+0xdb>
   140003066:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000306a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000306f:	eb c7                	jmp    140003038 <__mingw_enum_import_library_names+0x9c>
   140003071:	90                   	nop
   140003072:	b8 00 00 00 00       	mov    eax,0x0
   140003077:	48 83 c4 50          	add    rsp,0x50
   14000307b:	5d                   	pop    rbp
   14000307c:	c3                   	ret
   14000307d:	90                   	nop
   14000307e:	90                   	nop
   14000307f:	90                   	nop

0000000140003080 <___chkstk_ms>:
   140003080:	51                   	push   rcx
   140003081:	50                   	push   rax
   140003082:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003088:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000308d:	72 19                	jb     1400030a8 <___chkstk_ms+0x28>
   14000308f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003096:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000309a:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400030a0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030a6:	77 e7                	ja     14000308f <___chkstk_ms+0xf>
   1400030a8:	48 29 c1             	sub    rcx,rax
   1400030ab:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030af:	58                   	pop    rax
   1400030b0:	59                   	pop    rcx
   1400030b1:	c3                   	ret
   1400030b2:	90                   	nop
   1400030b3:	90                   	nop
   1400030b4:	90                   	nop
   1400030b5:	90                   	nop
   1400030b6:	90                   	nop
   1400030b7:	90                   	nop
   1400030b8:	90                   	nop
   1400030b9:	90                   	nop
   1400030ba:	90                   	nop
   1400030bb:	90                   	nop
   1400030bc:	90                   	nop
   1400030bd:	90                   	nop
   1400030be:	90                   	nop
   1400030bf:	90                   	nop

00000001400030c0 <_initterm_e>:
   1400030c0:	55                   	push   rbp
   1400030c1:	48 89 e5             	mov    rbp,rsp
   1400030c4:	48 83 ec 30          	sub    rsp,0x30
   1400030c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400030cc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400030d0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400030d4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030d8:	eb 29                	jmp    140003103 <_initterm_e+0x43>
   1400030da:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030de:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400030e1:	48 85 c0             	test   rax,rax
   1400030e4:	74 17                	je     1400030fd <_initterm_e+0x3d>
   1400030e6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030ea:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400030ed:	ff d0                	call   rax
   1400030ef:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400030f2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   1400030f6:	74 06                	je     1400030fe <_initterm_e+0x3e>
   1400030f8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400030fb:	eb 15                	jmp    140003112 <_initterm_e+0x52>
   1400030fd:	90                   	nop
   1400030fe:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140003103:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003107:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   14000310b:	72 cd                	jb     1400030da <_initterm_e+0x1a>
   14000310d:	b8 00 00 00 00       	mov    eax,0x0
   140003112:	48 83 c4 30          	add    rsp,0x30
   140003116:	5d                   	pop    rbp
   140003117:	c3                   	ret
   140003118:	90                   	nop
   140003119:	90                   	nop
   14000311a:	90                   	nop
   14000311b:	90                   	nop
   14000311c:	90                   	nop
   14000311d:	90                   	nop
   14000311e:	90                   	nop
   14000311f:	90                   	nop

0000000140003120 <__p__fmode>:
   140003120:	55                   	push   rbp
   140003121:	48 89 e5             	mov    rbp,rsp
   140003124:	48 8b 05 a5 22 00 00 	mov    rax,QWORD PTR [rip+0x22a5]        # 1400053d0 <.refptr.__imp__fmode>
   14000312b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000312e:	5d                   	pop    rbp
   14000312f:	c3                   	ret

0000000140003130 <__p__commode>:
   140003130:	55                   	push   rbp
   140003131:	48 89 e5             	mov    rbp,rsp
   140003134:	48 8b 05 85 22 00 00 	mov    rax,QWORD PTR [rip+0x2285]        # 1400053c0 <.refptr.__imp__commode>
   14000313b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000313e:	5d                   	pop    rbp
   14000313f:	c3                   	ret

0000000140003140 <__p___initenv>:
   140003140:	55                   	push   rbp
   140003141:	48 89 e5             	mov    rbp,rsp
   140003144:	48 8b 05 65 22 00 00 	mov    rax,QWORD PTR [rip+0x2265]        # 1400053b0 <.refptr.__imp___initenv>
   14000314b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000314e:	5d                   	pop    rbp
   14000314f:	c3                   	ret

0000000140003150 <_set_invalid_parameter_handler>:
   140003150:	55                   	push   rbp
   140003151:	48 89 e5             	mov    rbp,rsp
   140003154:	48 83 ec 10          	sub    rsp,0x10
   140003158:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000315c:	48 8d 05 2d 60 00 00 	lea    rax,[rip+0x602d]        # 140009190 <handler>
   140003163:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003167:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000316b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000316f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003173:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003177:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000317a:	48 89 d0             	mov    rax,rdx
   14000317d:	48 83 c4 10          	add    rsp,0x10
   140003181:	5d                   	pop    rbp
   140003182:	c3                   	ret

0000000140003183 <_get_invalid_parameter_handler>:
   140003183:	55                   	push   rbp
   140003184:	48 89 e5             	mov    rbp,rsp
   140003187:	48 8b 05 02 60 00 00 	mov    rax,QWORD PTR [rip+0x6002]        # 140009190 <handler>
   14000318e:	5d                   	pop    rbp
   14000318f:	c3                   	ret

0000000140003190 <_configthreadlocale>:
   140003190:	55                   	push   rbp
   140003191:	48 89 e5             	mov    rbp,rsp
   140003194:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003197:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000319b:	75 07                	jne    1400031a4 <_configthreadlocale+0x14>
   14000319d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400031a2:	eb 05                	jmp    1400031a9 <_configthreadlocale+0x19>
   1400031a4:	b8 02 00 00 00       	mov    eax,0x2
   1400031a9:	5d                   	pop    rbp
   1400031aa:	c3                   	ret
   1400031ab:	90                   	nop
   1400031ac:	90                   	nop
   1400031ad:	90                   	nop
   1400031ae:	90                   	nop
   1400031af:	90                   	nop

00000001400031b0 <__acrt_iob_func>:
   1400031b0:	55                   	push   rbp
   1400031b1:	48 89 e5             	mov    rbp,rsp
   1400031b4:	48 83 ec 20          	sub    rsp,0x20
   1400031b8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031bb:	e8 30 00 00 00       	call   1400031f0 <__iob_func>
   1400031c0:	48 89 c1             	mov    rcx,rax
   1400031c3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400031c6:	48 89 d0             	mov    rax,rdx
   1400031c9:	48 01 c0             	add    rax,rax
   1400031cc:	48 01 d0             	add    rax,rdx
   1400031cf:	48 c1 e0 04          	shl    rax,0x4
   1400031d3:	48 01 c8             	add    rax,rcx
   1400031d6:	48 83 c4 20          	add    rsp,0x20
   1400031da:	5d                   	pop    rbp
   1400031db:	c3                   	ret
   1400031dc:	90                   	nop
   1400031dd:	90                   	nop
   1400031de:	90                   	nop
   1400031df:	90                   	nop

00000001400031e0 <__C_specific_handler>:
   1400031e0:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a200 <__imp___C_specific_handler>
   1400031e6:	90                   	nop
   1400031e7:	90                   	nop

00000001400031e8 <__getmainargs>:
   1400031e8:	ff 25 1a 70 00 00    	jmp    QWORD PTR [rip+0x701a]        # 14000a208 <__imp___getmainargs>
   1400031ee:	90                   	nop
   1400031ef:	90                   	nop

00000001400031f0 <__iob_func>:
   1400031f0:	ff 25 22 70 00 00    	jmp    QWORD PTR [rip+0x7022]        # 14000a218 <__imp___iob_func>
   1400031f6:	90                   	nop
   1400031f7:	90                   	nop

00000001400031f8 <__set_app_type>:
   1400031f8:	ff 25 22 70 00 00    	jmp    QWORD PTR [rip+0x7022]        # 14000a220 <__imp___set_app_type>
   1400031fe:	90                   	nop
   1400031ff:	90                   	nop

0000000140003200 <__setusermatherr>:
   140003200:	ff 25 22 70 00 00    	jmp    QWORD PTR [rip+0x7022]        # 14000a228 <__imp___setusermatherr>
   140003206:	90                   	nop
   140003207:	90                   	nop

0000000140003208 <_amsg_exit>:
   140003208:	ff 25 22 70 00 00    	jmp    QWORD PTR [rip+0x7022]        # 14000a230 <__imp__amsg_exit>
   14000320e:	90                   	nop
   14000320f:	90                   	nop

0000000140003210 <_cexit>:
   140003210:	ff 25 22 70 00 00    	jmp    QWORD PTR [rip+0x7022]        # 14000a238 <__imp__cexit>
   140003216:	90                   	nop
   140003217:	90                   	nop

0000000140003218 <_initterm>:
   140003218:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a250 <__imp__initterm>
   14000321e:	90                   	nop
   14000321f:	90                   	nop

0000000140003220 <_crt_atexit>:
   140003220:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a258 <__imp__crt_atexit>
   140003226:	90                   	nop
   140003227:	90                   	nop

0000000140003228 <abort>:
   140003228:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a260 <__imp_abort>
   14000322e:	90                   	nop
   14000322f:	90                   	nop

0000000140003230 <calloc>:
   140003230:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a268 <__imp_calloc>
   140003236:	90                   	nop
   140003237:	90                   	nop

0000000140003238 <exit>:
   140003238:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a270 <__imp_exit>
   14000323e:	90                   	nop
   14000323f:	90                   	nop

0000000140003240 <fflush>:
   140003240:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a278 <__imp_fflush>
   140003246:	90                   	nop
   140003247:	90                   	nop

0000000140003248 <fprintf>:
   140003248:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a280 <__imp_fprintf>
   14000324e:	90                   	nop
   14000324f:	90                   	nop

0000000140003250 <free>:
   140003250:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a288 <__imp_free>
   140003256:	90                   	nop
   140003257:	90                   	nop

0000000140003258 <malloc>:
   140003258:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a290 <__imp_malloc>
   14000325e:	90                   	nop
   14000325f:	90                   	nop

0000000140003260 <memcpy>:
   140003260:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a298 <__imp_memcpy>
   140003266:	90                   	nop
   140003267:	90                   	nop

0000000140003268 <setvbuf>:
   140003268:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a2a0 <__imp_setvbuf>
   14000326e:	90                   	nop
   14000326f:	90                   	nop

0000000140003270 <signal>:
   140003270:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a2a8 <__imp_signal>
   140003276:	90                   	nop
   140003277:	90                   	nop

0000000140003278 <strlen>:
   140003278:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a2b0 <__imp_strlen>
   14000327e:	90                   	nop
   14000327f:	90                   	nop

0000000140003280 <strncmp>:
   140003280:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a2b8 <__imp_strncmp>
   140003286:	90                   	nop
   140003287:	90                   	nop

0000000140003288 <vfprintf>:
   140003288:	ff 25 32 70 00 00    	jmp    QWORD PTR [rip+0x7032]        # 14000a2c0 <__imp_vfprintf>
   14000328e:	90                   	nop
   14000328f:	90                   	nop

0000000140003290 <VirtualQuery>:
   140003290:	ff 25 5a 6f 00 00    	jmp    QWORD PTR [rip+0x6f5a]        # 14000a1f0 <__imp_VirtualQuery>
   140003296:	90                   	nop
   140003297:	90                   	nop

0000000140003298 <VirtualProtect>:
   140003298:	ff 25 4a 6f 00 00    	jmp    QWORD PTR [rip+0x6f4a]        # 14000a1e8 <__imp_VirtualProtect>
   14000329e:	90                   	nop
   14000329f:	90                   	nop

00000001400032a0 <TlsGetValue>:
   1400032a0:	ff 25 3a 6f 00 00    	jmp    QWORD PTR [rip+0x6f3a]        # 14000a1e0 <__imp_TlsGetValue>
   1400032a6:	90                   	nop
   1400032a7:	90                   	nop

00000001400032a8 <Sleep>:
   1400032a8:	ff 25 2a 6f 00 00    	jmp    QWORD PTR [rip+0x6f2a]        # 14000a1d8 <__imp_Sleep>
   1400032ae:	90                   	nop
   1400032af:	90                   	nop

00000001400032b0 <SetUnhandledExceptionFilter>:
   1400032b0:	ff 25 1a 6f 00 00    	jmp    QWORD PTR [rip+0x6f1a]        # 14000a1d0 <__imp_SetUnhandledExceptionFilter>
   1400032b6:	90                   	nop
   1400032b7:	90                   	nop

00000001400032b8 <LoadLibraryA>:
   1400032b8:	ff 25 0a 6f 00 00    	jmp    QWORD PTR [rip+0x6f0a]        # 14000a1c8 <__imp_LoadLibraryA>
   1400032be:	90                   	nop
   1400032bf:	90                   	nop

00000001400032c0 <LeaveCriticalSection>:
   1400032c0:	ff 25 fa 6e 00 00    	jmp    QWORD PTR [rip+0x6efa]        # 14000a1c0 <__imp_LeaveCriticalSection>
   1400032c6:	90                   	nop
   1400032c7:	90                   	nop

00000001400032c8 <InitializeCriticalSection>:
   1400032c8:	ff 25 ea 6e 00 00    	jmp    QWORD PTR [rip+0x6eea]        # 14000a1b8 <__imp_InitializeCriticalSection>
   1400032ce:	90                   	nop
   1400032cf:	90                   	nop

00000001400032d0 <GetProcAddress>:
   1400032d0:	ff 25 da 6e 00 00    	jmp    QWORD PTR [rip+0x6eda]        # 14000a1b0 <__imp_GetProcAddress>
   1400032d6:	90                   	nop
   1400032d7:	90                   	nop

00000001400032d8 <GetModuleHandleA>:
   1400032d8:	ff 25 ca 6e 00 00    	jmp    QWORD PTR [rip+0x6eca]        # 14000a1a8 <__imp_GetModuleHandleA>
   1400032de:	90                   	nop
   1400032df:	90                   	nop

00000001400032e0 <GetLastError>:
   1400032e0:	ff 25 ba 6e 00 00    	jmp    QWORD PTR [rip+0x6eba]        # 14000a1a0 <__imp_GetLastError>
   1400032e6:	90                   	nop
   1400032e7:	90                   	nop

00000001400032e8 <FreeLibrary>:
   1400032e8:	ff 25 aa 6e 00 00    	jmp    QWORD PTR [rip+0x6eaa]        # 14000a198 <__imp_FreeLibrary>
   1400032ee:	90                   	nop
   1400032ef:	90                   	nop

00000001400032f0 <EnterCriticalSection>:
   1400032f0:	ff 25 9a 6e 00 00    	jmp    QWORD PTR [rip+0x6e9a]        # 14000a190 <__imp_EnterCriticalSection>
   1400032f6:	90                   	nop
   1400032f7:	90                   	nop

00000001400032f8 <DeleteCriticalSection>:
   1400032f8:	ff 25 8a 6e 00 00    	jmp    QWORD PTR [rip+0x6e8a]        # 14000a188 <__IAT_start__>
   1400032fe:	90                   	nop
   1400032ff:	90                   	nop

0000000140003300 <register_frame_ctor>:
   140003300:	e9 6b e3 ff ff       	jmp    140001670 <__gcc_register_frame>
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
