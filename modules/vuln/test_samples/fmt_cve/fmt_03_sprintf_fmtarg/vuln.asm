
C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\test_samples\fmt_cve\fmt_03_sprintf_fmtarg\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 7f 84 00 00       	call   1400094a8 <fflush>
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
   14000103f:	48 8b 05 ca a5 00 00 	mov    rax,QWORD PTR [rip+0xa5ca]        # 14000b610 <.refptr.__mingw_app_type>
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
   14000106e:	48 8b 05 9b a5 00 00 	mov    rax,QWORD PTR [rip+0xa59b]        # 14000b610 <.refptr.__mingw_app_type>
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
   1400010e8:	48 8b 05 51 f1 00 00 	mov    rax,QWORD PTR [rip+0xf151]        # 140010240 <__imp_Sleep>
   1400010ef:	ff d0                	call   rax
   1400010f1:	48 8b 05 68 a5 00 00 	mov    rax,QWORD PTR [rip+0xa568]        # 14000b660 <.refptr.__native_startup_lock>
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
   140001128:	48 8b 05 41 a5 00 00 	mov    rax,QWORD PTR [rip+0xa541]        # 14000b670 <.refptr.__native_startup_state>
   14000112f:	8b 00                	mov    eax,DWORD PTR [rax]
   140001131:	83 f8 01             	cmp    eax,0x1
   140001134:	75 0a                	jne    140001140 <__tmainCRTStartup+0xb2>
   140001136:	b9 1f 00 00 00       	mov    ecx,0x1f
   14000113b:	e8 28 83 00 00       	call   140009468 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 28 7d 00 00       	call   140008e90 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 67 83 00 00       	call   1400094e8 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 f7 82 00 00       	call   140009490 <abort>
   140001199:	e8 22 11 00 00       	call   1400022c0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 89 f0 00 00 	mov    rax,QWORD PTR [rip+0xf089]        # 140010238 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 66 7c 00 00       	call   140008e30 <_set_invalid_parameter_handler>
   1400011ca:	e8 01 1a 00 00       	call   140002bd0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 67 82 00 00       	call   140009458 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 5b 82 00 00       	call   140009458 <__set_app_type>
   1400011fd:	e8 fe 7b 00 00       	call   140008e00 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 fe 7b 00 00       	call   140008e10 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 7e 06 00 00       	call   1400018a0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 33 82 00 00       	call   140009468 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 88 11 00 00       	call   1400023da <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 06 7c 00 00       	call   140008e70 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 20 7b 00 00       	call   140008da0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 da 81 00 00       	call   140009468 <_amsg_exit>
   14000128e:	48 8b 05 8b a4 00 00 	mov    rax,QWORD PTR [rip+0xa48b]        # 14000b720 <.refptr._newmode>
   140001295:	8b 00                	mov    eax,DWORD PTR [rax]
   140001297:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000129a:	48 8b 05 3f a4 00 00 	mov    rax,QWORD PTR [rip+0xa43f]        # 14000b6e0 <.refptr._dowildcard>
   1400012a1:	44 8b 00             	mov    r8d,DWORD PTR [rax]
   1400012a4:	4c 8d 15 65 dd 00 00 	lea    r10,[rip+0xdd65]        # 14000f010 <envp>
   1400012ab:	48 8d 15 56 dd 00 00 	lea    rdx,[rip+0xdd56]        # 14000f008 <argv>
   1400012b2:	48 8d 05 4b dd 00 00 	lea    rax,[rip+0xdd4b]        # 14000f004 <argc>
   1400012b9:	48 8d 4d ac          	lea    rcx,[rbp-0x54]
   1400012bd:	48 89 4c 24 20       	mov    QWORD PTR [rsp+0x20],rcx
   1400012c2:	45 89 c1             	mov    r9d,r8d
   1400012c5:	4d 89 d0             	mov    r8,r10
   1400012c8:	48 89 c1             	mov    rcx,rax
   1400012cb:	e8 78 81 00 00       	call   140009448 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 85 81 00 00       	call   140009468 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 5e 81 00 00       	call   140009468 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 60 81 00 00       	call   140009480 <_initterm>
   140001320:	e8 52 05 00 00       	call   140001877 <__main>
   140001325:	48 8b 05 44 a3 00 00 	mov    rax,QWORD PTR [rip+0xa344]        # 14000b670 <.refptr.__native_startup_state>
   14000132c:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   140001332:	eb 0a                	jmp    14000133e <__tmainCRTStartup+0x2b0>
   140001334:	c7 05 de dc 00 00 01 	mov    DWORD PTR [rip+0xdcde],0x1        # 14000f01c <has_cctor>
   14000133b:	00 00 00 
   14000133e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140001342:	75 1e                	jne    140001362 <__tmainCRTStartup+0x2d4>
   140001344:	48 8b 05 15 a3 00 00 	mov    rax,QWORD PTR [rip+0xa315]        # 14000b660 <.refptr.__native_startup_lock>
   14000134b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000134f:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
   140001356:	00 
   140001357:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000135b:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000135f:	48 87 10             	xchg   QWORD PTR [rax],rdx
   140001362:	48 8b 05 57 a2 00 00 	mov    rax,QWORD PTR [rip+0xa257]        # 14000b5c0 <.refptr.__dyn_tls_init_callback>
   140001369:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000136c:	48 85 c0             	test   rax,rax
   14000136f:	74 1c                	je     14000138d <__tmainCRTStartup+0x2ff>
   140001371:	48 8b 05 48 a2 00 00 	mov    rax,QWORD PTR [rip+0xa248]        # 14000b5c0 <.refptr.__dyn_tls_init_callback>
   140001378:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000137b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140001381:	ba 02 00 00 00       	mov    edx,0x2
   140001386:	b9 00 00 00 00       	mov    ecx,0x0
   14000138b:	ff d0                	call   rax
   14000138d:	e8 8e 7a 00 00       	call   140008e20 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 a6 03 00 00       	call   140001760 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 cf 80 00 00       	call   1400094a0 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 90 80 00 00       	call   140009470 <_cexit>
   1400013e0:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013e3:	48 81 c4 90 00 00 00 	add    rsp,0x90
   1400013ea:	5d                   	pop    rbp
   1400013eb:	c3                   	ret

00000001400013ec <check_managed_app>:
   1400013ec:	55                   	push   rbp
   1400013ed:	48 89 e5             	mov    rbp,rsp
   1400013f0:	48 83 ec 20          	sub    rsp,0x20
   1400013f4:	48 8b 05 25 a2 00 00 	mov    rax,QWORD PTR [rip+0xa225]        # 14000b620 <.refptr.__mingw_initltsdrot_force>
   1400013fb:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140001401:	48 8b 05 28 a2 00 00 	mov    rax,QWORD PTR [rip+0xa228]        # 14000b630 <.refptr.__mingw_initltsdyn_force>
   140001408:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000140e:	48 8b 05 2b a2 00 00 	mov    rax,QWORD PTR [rip+0xa22b]        # 14000b640 <.refptr.__mingw_initltssuo_force>
   140001415:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000141b:	48 8b 05 5e a1 00 00 	mov    rax,QWORD PTR [rip+0xa15e]        # 14000b580 <.refptr.__ImageBase>
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
   140001511:	e8 ba 7f 00 00       	call   1400094d0 <malloc>
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
   14000155c:	e8 9f 7f 00 00       	call   140009500 <strlen>
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
   140001585:	e8 46 7f 00 00       	call   1400094d0 <malloc>
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
   1400015e8:	e8 eb 7e 00 00       	call   1400094d8 <memcpy>
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
   140001642:	e8 41 7e 00 00       	call   140009488 <_crt_atexit>
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
   14000167b:	48 8d 0d 7e 99 00 00 	lea    rcx,[rip+0x997e]        # 14000b000 <.rdata>
   140001682:	ff 15 80 eb 00 00    	call   QWORD PTR [rip+0xeb80]        # 140010208 <__imp_GetModuleHandleA>
   140001688:	48 89 c3             	mov    rbx,rax
   14000168b:	48 85 c0             	test   rax,rax
   14000168e:	74 70                	je     140001700 <__gcc_register_frame+0x90>
   140001690:	48 8d 0d 69 99 00 00 	lea    rcx,[rip+0x9969]        # 14000b000 <.rdata>
   140001697:	ff 15 8b eb 00 00    	call   QWORD PTR [rip+0xeb8b]        # 140010228 <__imp_LoadLibraryA>
   14000169d:	4c 8b 0d 6c eb 00 00 	mov    r9,QWORD PTR [rip+0xeb6c]        # 140010210 <__imp_GetProcAddress>
   1400016a4:	48 8d 15 68 99 00 00 	lea    rdx,[rip+0x9968]        # 14000b013 <.rdata+0x13>
   1400016ab:	48 89 d9             	mov    rcx,rbx
   1400016ae:	48 89 05 6b d9 00 00 	mov    QWORD PTR [rip+0xd96b],rax        # 14000f020 <hmod_libgcc>
   1400016b5:	4c 89 4d f0          	mov    QWORD PTR [rbp-0x10],r9
   1400016b9:	41 ff d1             	call   r9
   1400016bc:	48 8d 15 66 99 00 00 	lea    rdx,[rip+0x9966]        # 14000b029 <.rdata+0x29>
   1400016c3:	48 89 d9             	mov    rcx,rbx
   1400016c6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400016ca:	ff 55 f0             	call   QWORD PTR [rbp-0x10]
   1400016cd:	4c 8b 45 f8          	mov    r8,QWORD PTR [rbp-0x8]
   1400016d1:	48 89 05 28 89 00 00 	mov    QWORD PTR [rip+0x8928],rax        # 14000a000 <__data_start__>
   1400016d8:	4d 85 c0             	test   r8,r8
   1400016db:	74 11                	je     1400016ee <__gcc_register_frame+0x7e>
   1400016dd:	48 8d 15 5c d9 00 00 	lea    rdx,[rip+0xd95c]        # 14000f040 <obj>
   1400016e4:	48 8d 0d 15 a9 00 00 	lea    rcx,[rip+0xa915]        # 14000c000 <__EH_FRAME_BEGIN__>
   1400016eb:	41 ff d0             	call   r8
   1400016ee:	48 8d 0d 2b 00 00 00 	lea    rcx,[rip+0x2b]        # 140001720 <__gcc_deregister_frame>
   1400016f5:	48 83 c4 38          	add    rsp,0x38
   1400016f9:	5b                   	pop    rbx
   1400016fa:	5d                   	pop    rbp
   1400016fb:	e9 2f ff ff ff       	jmp    14000162f <atexit>
   140001700:	48 8d 05 59 ff ff ff 	lea    rax,[rip+0xffffffffffffff59]        # 140001660 <.weak.__deregister_frame_info.hmod_libgcc>
   140001707:	4c 8d 05 42 ff ff ff 	lea    r8,[rip+0xffffffffffffff42]        # 140001650 <.weak.__register_frame_info.hmod_libgcc>
   14000170e:	48 89 05 eb 88 00 00 	mov    QWORD PTR [rip+0x88eb],rax        # 14000a000 <__data_start__>
   140001715:	eb c6                	jmp    1400016dd <__gcc_register_frame+0x6d>
   140001717:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
   14000171e:	00 00 

0000000140001720 <__gcc_deregister_frame>:
   140001720:	55                   	push   rbp
   140001721:	48 89 e5             	mov    rbp,rsp
   140001724:	48 83 ec 20          	sub    rsp,0x20
   140001728:	48 8b 05 d1 88 00 00 	mov    rax,QWORD PTR [rip+0x88d1]        # 14000a000 <__data_start__>
   14000172f:	48 85 c0             	test   rax,rax
   140001732:	74 09                	je     14000173d <__gcc_deregister_frame+0x1d>
   140001734:	48 8d 0d c5 a8 00 00 	lea    rcx,[rip+0xa8c5]        # 14000c000 <__EH_FRAME_BEGIN__>
   14000173b:	ff d0                	call   rax
   14000173d:	48 8b 0d dc d8 00 00 	mov    rcx,QWORD PTR [rip+0xd8dc]        # 14000f020 <hmod_libgcc>
   140001744:	48 85 c9             	test   rcx,rcx
   140001747:	74 0f                	je     140001758 <__gcc_deregister_frame+0x38>
   140001749:	48 83 c4 20          	add    rsp,0x20
   14000174d:	5d                   	pop    rbp
   14000174e:	48 ff 25 9b ea 00 00 	rex.W jmp QWORD PTR [rip+0xea9b]        # 1400101f0 <__imp_FreeLibrary>
   140001755:	0f 1f 00             	nop    DWORD PTR [rax]
   140001758:	48 83 c4 20          	add    rsp,0x20
   14000175c:	5d                   	pop    rbp
   14000175d:	c3                   	ret
   14000175e:	90                   	nop
   14000175f:	90                   	nop

0000000140001760 <main>:
   140001760:	55                   	push   rbp
   140001761:	48 81 ec 20 01 00 00 	sub    rsp,0x120
   140001768:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   14000176f:	00 
   140001770:	89 8d b0 00 00 00    	mov    DWORD PTR [rbp+0xb0],ecx
   140001776:	48 89 95 b8 00 00 00 	mov    QWORD PTR [rbp+0xb8],rdx
   14000177d:	e8 f5 00 00 00       	call   140001877 <__main>
   140001782:	48 8b 85 b8 00 00 00 	mov    rax,QWORD PTR [rbp+0xb8]
   140001789:	48 83 c0 08          	add    rax,0x8
   14000178d:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140001790:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140001794:	41 b8 2a 00 00 00    	mov    r8d,0x2a
   14000179a:	48 89 c1             	mov    rcx,rax
   14000179d:	e8 2e 19 00 00       	call   1400030d0 <__mingw_sprintf>
   1400017a2:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400017a6:	48 89 c1             	mov    rcx,rax
   1400017a9:	e8 32 7d 00 00       	call   1400094e0 <puts>
   1400017ae:	b8 00 00 00 00       	mov    eax,0x0
   1400017b3:	48 81 c4 20 01 00 00 	add    rsp,0x120
   1400017ba:	5d                   	pop    rbp
   1400017bb:	c3                   	ret
   1400017bc:	90                   	nop
   1400017bd:	90                   	nop
   1400017be:	90                   	nop
   1400017bf:	90                   	nop

00000001400017c0 <__do_global_dtors>:
   1400017c0:	55                   	push   rbp
   1400017c1:	48 89 e5             	mov    rbp,rsp
   1400017c4:	48 83 ec 20          	sub    rsp,0x20
   1400017c8:	eb 1e                	jmp    1400017e8 <__do_global_dtors+0x28>
   1400017ca:	48 8b 05 3f 88 00 00 	mov    rax,QWORD PTR [rip+0x883f]        # 14000a010 <p.0>
   1400017d1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017d4:	ff d0                	call   rax
   1400017d6:	48 8b 05 33 88 00 00 	mov    rax,QWORD PTR [rip+0x8833]        # 14000a010 <p.0>
   1400017dd:	48 83 c0 08          	add    rax,0x8
   1400017e1:	48 89 05 28 88 00 00 	mov    QWORD PTR [rip+0x8828],rax        # 14000a010 <p.0>
   1400017e8:	48 8b 05 21 88 00 00 	mov    rax,QWORD PTR [rip+0x8821]        # 14000a010 <p.0>
   1400017ef:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017f2:	48 85 c0             	test   rax,rax
   1400017f5:	75 d3                	jne    1400017ca <__do_global_dtors+0xa>
   1400017f7:	90                   	nop
   1400017f8:	90                   	nop
   1400017f9:	48 83 c4 20          	add    rsp,0x20
   1400017fd:	5d                   	pop    rbp
   1400017fe:	c3                   	ret

00000001400017ff <__do_global_ctors>:
   1400017ff:	55                   	push   rbp
   140001800:	48 89 e5             	mov    rbp,rsp
   140001803:	48 83 ec 30          	sub    rsp,0x30
   140001807:	48 8b 05 62 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d62]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000180e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001811:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001814:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001818:	75 25                	jne    14000183f <__do_global_ctors+0x40>
   14000181a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001821:	eb 04                	jmp    140001827 <__do_global_ctors+0x28>
   140001823:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001827:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000182a:	8d 50 01             	lea    edx,[rax+0x1]
   14000182d:	48 8b 05 3c 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d3c]        # 14000b570 <.refptr.__CTOR_LIST__>
   140001834:	89 d2                	mov    edx,edx
   140001836:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000183a:	48 85 c0             	test   rax,rax
   14000183d:	75 e4                	jne    140001823 <__do_global_ctors+0x24>
   14000183f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001842:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001845:	eb 14                	jmp    14000185b <__do_global_ctors+0x5c>
   140001847:	48 8b 05 22 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d22]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000184e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001851:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001855:	ff d0                	call   rax
   140001857:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000185b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000185f:	75 e6                	jne    140001847 <__do_global_ctors+0x48>
   140001861:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400017c0 <__do_global_dtors>
   140001868:	48 89 c1             	mov    rcx,rax
   14000186b:	e8 bf fd ff ff       	call   14000162f <atexit>
   140001870:	90                   	nop
   140001871:	48 83 c4 30          	add    rsp,0x30
   140001875:	5d                   	pop    rbp
   140001876:	c3                   	ret

0000000140001877 <__main>:
   140001877:	55                   	push   rbp
   140001878:	48 89 e5             	mov    rbp,rsp
   14000187b:	48 83 ec 20          	sub    rsp,0x20
   14000187f:	8b 05 fb d7 00 00    	mov    eax,DWORD PTR [rip+0xd7fb]        # 14000f080 <initialized>
   140001885:	85 c0                	test   eax,eax
   140001887:	75 0f                	jne    140001898 <__main+0x21>
   140001889:	c7 05 ed d7 00 00 01 	mov    DWORD PTR [rip+0xd7ed],0x1        # 14000f080 <initialized>
   140001890:	00 00 00 
   140001893:	e8 67 ff ff ff       	call   1400017ff <__do_global_ctors>
   140001898:	90                   	nop
   140001899:	48 83 c4 20          	add    rsp,0x20
   14000189d:	5d                   	pop    rbp
   14000189e:	c3                   	ret
   14000189f:	90                   	nop

00000001400018a0 <_setargv>:
   1400018a0:	55                   	push   rbp
   1400018a1:	48 89 e5             	mov    rbp,rsp
   1400018a4:	b8 00 00 00 00       	mov    eax,0x0
   1400018a9:	5d                   	pop    rbp
   1400018aa:	c3                   	ret
   1400018ab:	90                   	nop
   1400018ac:	90                   	nop
   1400018ad:	90                   	nop
   1400018ae:	90                   	nop
   1400018af:	90                   	nop

00000001400018b0 <__dyn_tls_init>:
   1400018b0:	55                   	push   rbp
   1400018b1:	48 89 e5             	mov    rbp,rsp
   1400018b4:	48 83 ec 30          	sub    rsp,0x30
   1400018b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400018bc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400018bf:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400018c3:	48 8b 05 86 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c86]        # 14000b550 <.refptr._CRT_MT>
   1400018ca:	8b 00                	mov    eax,DWORD PTR [rax]
   1400018cc:	83 f8 02             	cmp    eax,0x2
   1400018cf:	74 0d                	je     1400018de <__dyn_tls_init+0x2e>
   1400018d1:	48 8b 05 78 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c78]        # 14000b550 <.refptr._CRT_MT>
   1400018d8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400018de:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   1400018e2:	74 1e                	je     140001902 <__dyn_tls_init+0x52>
   1400018e4:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   1400018e8:	75 5b                	jne    140001945 <__dyn_tls_init+0x95>
   1400018ea:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400018ee:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400018f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400018f5:	49 89 c8             	mov    r8,rcx
   1400018f8:	48 89 c1             	mov    rcx,rax
   1400018fb:	e8 d1 11 00 00       	call   140002ad1 <__mingw_TLScallback>
   140001900:	eb 43                	jmp    140001945 <__dyn_tls_init+0x95>
   140001902:	48 8d 05 cf 9f 00 00 	lea    rax,[rip+0x9fcf]        # 14000b8d8 <___crt_xd_start__>
   140001909:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000190d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001912:	eb 22                	jmp    140001936 <__dyn_tls_init+0x86>
   140001914:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001918:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000191c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001920:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001923:	48 85 c0             	test   rax,rax
   140001926:	74 09                	je     140001931 <__dyn_tls_init+0x81>
   140001928:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000192c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000192f:	ff d0                	call   rax
   140001931:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001936:	48 8d 05 a3 9f 00 00 	lea    rax,[rip+0x9fa3]        # 14000b8e0 <__xd_z>
   14000193d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001941:	75 d1                	jne    140001914 <__dyn_tls_init+0x64>
   140001943:	eb 01                	jmp    140001946 <__dyn_tls_init+0x96>
   140001945:	90                   	nop
   140001946:	48 83 c4 30          	add    rsp,0x30
   14000194a:	5d                   	pop    rbp
   14000194b:	c3                   	ret

000000014000194c <__tlregdtor>:
   14000194c:	55                   	push   rbp
   14000194d:	48 89 e5             	mov    rbp,rsp
   140001950:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001954:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001959:	75 07                	jne    140001962 <__tlregdtor+0x16>
   14000195b:	b8 00 00 00 00       	mov    eax,0x0
   140001960:	eb 05                	jmp    140001967 <__tlregdtor+0x1b>
   140001962:	b8 00 00 00 00       	mov    eax,0x0
   140001967:	5d                   	pop    rbp
   140001968:	c3                   	ret

0000000140001969 <__dyn_tls_dtor>:
   140001969:	55                   	push   rbp
   14000196a:	48 89 e5             	mov    rbp,rsp
   14000196d:	48 83 ec 20          	sub    rsp,0x20
   140001971:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001975:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001978:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000197c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001980:	74 06                	je     140001988 <__dyn_tls_dtor+0x1f>
   140001982:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001986:	75 18                	jne    1400019a0 <__dyn_tls_dtor+0x37>
   140001988:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000198c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   14000198f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001993:	49 89 c8             	mov    r8,rcx
   140001996:	48 89 c1             	mov    rcx,rax
   140001999:	e8 33 11 00 00       	call   140002ad1 <__mingw_TLScallback>
   14000199e:	eb 01                	jmp    1400019a1 <__dyn_tls_dtor+0x38>
   1400019a0:	90                   	nop
   1400019a1:	48 83 c4 20          	add    rsp,0x20
   1400019a5:	5d                   	pop    rbp
   1400019a6:	c3                   	ret
   1400019a7:	90                   	nop
   1400019a8:	90                   	nop
   1400019a9:	90                   	nop
   1400019aa:	90                   	nop
   1400019ab:	90                   	nop
   1400019ac:	90                   	nop
   1400019ad:	90                   	nop
   1400019ae:	90                   	nop
   1400019af:	90                   	nop

00000001400019b0 <_matherr>:
   1400019b0:	55                   	push   rbp
   1400019b1:	53                   	push   rbx
   1400019b2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400019b9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400019be:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   1400019c2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   1400019c6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   1400019cb:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   1400019cf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   1400019d3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019d5:	83 f8 06             	cmp    eax,0x6
   1400019d8:	74 56                	je     140001a30 <_matherr+0x80>
   1400019da:	83 f8 06             	cmp    eax,0x6
   1400019dd:	7f 78                	jg     140001a57 <_matherr+0xa7>
   1400019df:	83 f8 05             	cmp    eax,0x5
   1400019e2:	74 59                	je     140001a3d <_matherr+0x8d>
   1400019e4:	83 f8 05             	cmp    eax,0x5
   1400019e7:	7f 6e                	jg     140001a57 <_matherr+0xa7>
   1400019e9:	83 f8 04             	cmp    eax,0x4
   1400019ec:	74 5c                	je     140001a4a <_matherr+0x9a>
   1400019ee:	83 f8 04             	cmp    eax,0x4
   1400019f1:	7f 64                	jg     140001a57 <_matherr+0xa7>
   1400019f3:	83 f8 03             	cmp    eax,0x3
   1400019f6:	74 2b                	je     140001a23 <_matherr+0x73>
   1400019f8:	83 f8 03             	cmp    eax,0x3
   1400019fb:	7f 5a                	jg     140001a57 <_matherr+0xa7>
   1400019fd:	83 f8 01             	cmp    eax,0x1
   140001a00:	74 07                	je     140001a09 <_matherr+0x59>
   140001a02:	83 f8 02             	cmp    eax,0x2
   140001a05:	74 0f                	je     140001a16 <_matherr+0x66>
   140001a07:	eb 4e                	jmp    140001a57 <_matherr+0xa7>
   140001a09:	48 8d 05 90 96 00 00 	lea    rax,[rip+0x9690]        # 14000b0a0 <.rdata>
   140001a10:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a14:	eb 4d                	jmp    140001a63 <_matherr+0xb3>
   140001a16:	48 8d 05 a2 96 00 00 	lea    rax,[rip+0x96a2]        # 14000b0bf <.rdata+0x1f>
   140001a1d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a21:	eb 40                	jmp    140001a63 <_matherr+0xb3>
   140001a23:	48 8d 05 b6 96 00 00 	lea    rax,[rip+0x96b6]        # 14000b0e0 <.rdata+0x40>
   140001a2a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a2e:	eb 33                	jmp    140001a63 <_matherr+0xb3>
   140001a30:	48 8d 05 c9 96 00 00 	lea    rax,[rip+0x96c9]        # 14000b100 <.rdata+0x60>
   140001a37:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a3b:	eb 26                	jmp    140001a63 <_matherr+0xb3>
   140001a3d:	48 8d 05 e4 96 00 00 	lea    rax,[rip+0x96e4]        # 14000b128 <.rdata+0x88>
   140001a44:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a48:	eb 19                	jmp    140001a63 <_matherr+0xb3>
   140001a4a:	48 8d 05 ff 96 00 00 	lea    rax,[rip+0x96ff]        # 14000b150 <.rdata+0xb0>
   140001a51:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a55:	eb 0c                	jmp    140001a63 <_matherr+0xb3>
   140001a57:	48 8d 05 28 97 00 00 	lea    rax,[rip+0x9728]        # 14000b186 <.rdata+0xe6>
   140001a5e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a62:	90                   	nop
   140001a63:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a67:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001a6d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a71:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001a76:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a7a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001a7f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a83:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001a87:	b9 02 00 00 00       	mov    ecx,0x2
   140001a8c:	e8 ff 73 00 00       	call   140008e90 <__acrt_iob_func>
   140001a91:	48 89 c1             	mov    rcx,rax
   140001a94:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001a98:	48 8d 05 f9 96 00 00 	lea    rax,[rip+0x96f9]        # 14000b198 <.rdata+0xf8>
   140001a9f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001aa6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001aac:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001ab2:	49 89 d9             	mov    r9,rbx
   140001ab5:	49 89 d0             	mov    r8,rdx
   140001ab8:	48 89 c2             	mov    rdx,rax
   140001abb:	e8 f0 79 00 00       	call   1400094b0 <fprintf>
   140001ac0:	b8 00 00 00 00       	mov    eax,0x0
   140001ac5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001ac9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001acd:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001ad2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001ad9:	5b                   	pop    rbx
   140001ada:	5d                   	pop    rbp
   140001adb:	c3                   	ret
   140001adc:	90                   	nop
   140001add:	90                   	nop
   140001ade:	90                   	nop
   140001adf:	90                   	nop

0000000140001ae0 <__report_error>:
   140001ae0:	55                   	push   rbp
   140001ae1:	53                   	push   rbx
   140001ae2:	48 83 ec 38          	sub    rsp,0x38
   140001ae6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001aeb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001aef:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001af3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001af7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001afb:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001aff:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b03:	b9 02 00 00 00       	mov    ecx,0x2
   140001b08:	e8 83 73 00 00       	call   140008e90 <__acrt_iob_func>
   140001b0d:	48 89 c1             	mov    rcx,rax
   140001b10:	48 8d 05 b9 96 00 00 	lea    rax,[rip+0x96b9]        # 14000b1d0 <.rdata>
   140001b17:	48 89 c2             	mov    rdx,rax
   140001b1a:	e8 91 79 00 00       	call   1400094b0 <fprintf>
   140001b1f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b23:	b9 02 00 00 00       	mov    ecx,0x2
   140001b28:	e8 63 73 00 00       	call   140008e90 <__acrt_iob_func>
   140001b2d:	48 89 c1             	mov    rcx,rax
   140001b30:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b34:	49 89 d8             	mov    r8,rbx
   140001b37:	48 89 c2             	mov    rdx,rax
   140001b3a:	e8 d1 79 00 00       	call   140009510 <vfprintf>
   140001b3f:	e8 4c 79 00 00       	call   140009490 <abort>
   140001b44:	90                   	nop

0000000140001b45 <mark_section_writable>:
   140001b45:	55                   	push   rbp
   140001b46:	48 89 e5             	mov    rbp,rsp
   140001b49:	48 83 ec 60          	sub    rsp,0x60
   140001b4d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b51:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001b58:	e9 82 00 00 00       	jmp    140001bdf <mark_section_writable+0x9a>
   140001b5d:	48 8b 0d 7c d5 00 00 	mov    rcx,QWORD PTR [rip+0xd57c]        # 14000f0e0 <the_secs>
   140001b64:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b67:	48 63 d0             	movsxd rdx,eax
   140001b6a:	48 89 d0             	mov    rax,rdx
   140001b6d:	48 c1 e0 02          	shl    rax,0x2
   140001b71:	48 01 d0             	add    rax,rdx
   140001b74:	48 c1 e0 03          	shl    rax,0x3
   140001b78:	48 01 c8             	add    rax,rcx
   140001b7b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001b7f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001b83:	72 56                	jb     140001bdb <mark_section_writable+0x96>
   140001b85:	48 8b 0d 54 d5 00 00 	mov    rcx,QWORD PTR [rip+0xd554]        # 14000f0e0 <the_secs>
   140001b8c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b8f:	48 63 d0             	movsxd rdx,eax
   140001b92:	48 89 d0             	mov    rax,rdx
   140001b95:	48 c1 e0 02          	shl    rax,0x2
   140001b99:	48 01 d0             	add    rax,rdx
   140001b9c:	48 c1 e0 03          	shl    rax,0x3
   140001ba0:	48 01 c8             	add    rax,rcx
   140001ba3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001ba7:	4c 8b 05 32 d5 00 00 	mov    r8,QWORD PTR [rip+0xd532]        # 14000f0e0 <the_secs>
   140001bae:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bb1:	48 63 d0             	movsxd rdx,eax
   140001bb4:	48 89 d0             	mov    rax,rdx
   140001bb7:	48 c1 e0 02          	shl    rax,0x2
   140001bbb:	48 01 d0             	add    rax,rdx
   140001bbe:	48 c1 e0 03          	shl    rax,0x3
   140001bc2:	4c 01 c0             	add    rax,r8
   140001bc5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001bc9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001bcc:	89 c0                	mov    eax,eax
   140001bce:	48 01 c8             	add    rax,rcx
   140001bd1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001bd5:	0f 82 41 02 00 00    	jb     140001e1c <mark_section_writable+0x2d7>
   140001bdb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001bdf:	8b 05 03 d5 00 00    	mov    eax,DWORD PTR [rip+0xd503]        # 14000f0e8 <maxSections>
   140001be5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001be8:	0f 8c 6f ff ff ff    	jl     140001b5d <mark_section_writable+0x18>
   140001bee:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001bf2:	48 89 c1             	mov    rcx,rax
   140001bf5:	e8 c1 11 00 00       	call   140002dbb <__mingw_GetSectionForAddress>
   140001bfa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001bfe:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c03:	75 13                	jne    140001c18 <mark_section_writable+0xd3>
   140001c05:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c09:	48 8d 0d e0 95 00 00 	lea    rcx,[rip+0x95e0]        # 14000b1f0 <.rdata+0x20>
   140001c10:	48 89 c2             	mov    rdx,rax
   140001c13:	e8 c8 fe ff ff       	call   140001ae0 <__report_error>
   140001c18:	48 8b 0d c1 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd4c1]        # 14000f0e0 <the_secs>
   140001c1f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c22:	48 63 d0             	movsxd rdx,eax
   140001c25:	48 89 d0             	mov    rax,rdx
   140001c28:	48 c1 e0 02          	shl    rax,0x2
   140001c2c:	48 01 d0             	add    rax,rdx
   140001c2f:	48 c1 e0 03          	shl    rax,0x3
   140001c33:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c37:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c3b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c3f:	48 8b 0d 9a d4 00 00 	mov    rcx,QWORD PTR [rip+0xd49a]        # 14000f0e0 <the_secs>
   140001c46:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c49:	48 63 d0             	movsxd rdx,eax
   140001c4c:	48 89 d0             	mov    rax,rdx
   140001c4f:	48 c1 e0 02          	shl    rax,0x2
   140001c53:	48 01 d0             	add    rax,rdx
   140001c56:	48 c1 e0 03          	shl    rax,0x3
   140001c5a:	48 01 c8             	add    rax,rcx
   140001c5d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001c63:	e8 9f 12 00 00       	call   140002f07 <_GetPEImageBase>
   140001c68:	48 89 c1             	mov    rcx,rax
   140001c6b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c6f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001c72:	41 89 c1             	mov    r9d,eax
   140001c75:	4c 8b 05 64 d4 00 00 	mov    r8,QWORD PTR [rip+0xd464]        # 14000f0e0 <the_secs>
   140001c7c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c7f:	48 63 d0             	movsxd rdx,eax
   140001c82:	48 89 d0             	mov    rax,rdx
   140001c85:	48 c1 e0 02          	shl    rax,0x2
   140001c89:	48 01 d0             	add    rax,rdx
   140001c8c:	48 c1 e0 03          	shl    rax,0x3
   140001c90:	4c 01 c0             	add    rax,r8
   140001c93:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001c97:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001c9b:	48 8b 0d 3e d4 00 00 	mov    rcx,QWORD PTR [rip+0xd43e]        # 14000f0e0 <the_secs>
   140001ca2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ca5:	48 63 d0             	movsxd rdx,eax
   140001ca8:	48 89 d0             	mov    rax,rdx
   140001cab:	48 c1 e0 02          	shl    rax,0x2
   140001caf:	48 01 d0             	add    rax,rdx
   140001cb2:	48 c1 e0 03          	shl    rax,0x3
   140001cb6:	48 01 c8             	add    rax,rcx
   140001cb9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001cbd:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001cc1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001cc7:	48 89 c1             	mov    rcx,rax
   140001cca:	48 8b 05 87 e5 00 00 	mov    rax,QWORD PTR [rip+0xe587]        # 140010258 <__imp_VirtualQuery>
   140001cd1:	ff d0                	call   rax
   140001cd3:	48 85 c0             	test   rax,rax
   140001cd6:	75 3f                	jne    140001d17 <mark_section_writable+0x1d2>
   140001cd8:	48 8b 0d 01 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd401]        # 14000f0e0 <the_secs>
   140001cdf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ce2:	48 63 d0             	movsxd rdx,eax
   140001ce5:	48 89 d0             	mov    rax,rdx
   140001ce8:	48 c1 e0 02          	shl    rax,0x2
   140001cec:	48 01 d0             	add    rax,rdx
   140001cef:	48 c1 e0 03          	shl    rax,0x3
   140001cf3:	48 01 c8             	add    rax,rcx
   140001cf6:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001cfa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001cfe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d01:	89 c1                	mov    ecx,eax
   140001d03:	48 8d 05 06 95 00 00 	lea    rax,[rip+0x9506]        # 14000b210 <.rdata+0x40>
   140001d0a:	49 89 d0             	mov    r8,rdx
   140001d0d:	89 ca                	mov    edx,ecx
   140001d0f:	48 89 c1             	mov    rcx,rax
   140001d12:	e8 c9 fd ff ff       	call   140001ae0 <__report_error>
   140001d17:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d1a:	83 f8 40             	cmp    eax,0x40
   140001d1d:	0f 84 e8 00 00 00    	je     140001e0b <mark_section_writable+0x2c6>
   140001d23:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d26:	83 f8 04             	cmp    eax,0x4
   140001d29:	0f 84 dc 00 00 00    	je     140001e0b <mark_section_writable+0x2c6>
   140001d2f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d32:	3d 80 00 00 00       	cmp    eax,0x80
   140001d37:	0f 84 ce 00 00 00    	je     140001e0b <mark_section_writable+0x2c6>
   140001d3d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d40:	83 f8 08             	cmp    eax,0x8
   140001d43:	0f 84 c2 00 00 00    	je     140001e0b <mark_section_writable+0x2c6>
   140001d49:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d4c:	83 f8 02             	cmp    eax,0x2
   140001d4f:	75 09                	jne    140001d5a <mark_section_writable+0x215>
   140001d51:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001d58:	eb 07                	jmp    140001d61 <mark_section_writable+0x21c>
   140001d5a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001d61:	48 8b 0d 78 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd378]        # 14000f0e0 <the_secs>
   140001d68:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d6b:	48 63 d0             	movsxd rdx,eax
   140001d6e:	48 89 d0             	mov    rax,rdx
   140001d71:	48 c1 e0 02          	shl    rax,0x2
   140001d75:	48 01 d0             	add    rax,rdx
   140001d78:	48 c1 e0 03          	shl    rax,0x3
   140001d7c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d80:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001d84:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001d88:	48 8b 0d 51 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd351]        # 14000f0e0 <the_secs>
   140001d8f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d92:	48 63 d0             	movsxd rdx,eax
   140001d95:	48 89 d0             	mov    rax,rdx
   140001d98:	48 c1 e0 02          	shl    rax,0x2
   140001d9c:	48 01 d0             	add    rax,rdx
   140001d9f:	48 c1 e0 03          	shl    rax,0x3
   140001da3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001da7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001dab:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001daf:	48 8b 0d 2a d3 00 00 	mov    rcx,QWORD PTR [rip+0xd32a]        # 14000f0e0 <the_secs>
   140001db6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001db9:	48 63 d0             	movsxd rdx,eax
   140001dbc:	48 89 d0             	mov    rax,rdx
   140001dbf:	48 c1 e0 02          	shl    rax,0x2
   140001dc3:	48 01 d0             	add    rax,rdx
   140001dc6:	48 c1 e0 03          	shl    rax,0x3
   140001dca:	48 01 c8             	add    rax,rcx
   140001dcd:	49 89 c0             	mov    r8,rax
   140001dd0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001dd4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001dd8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001ddb:	4d 89 c1             	mov    r9,r8
   140001dde:	41 89 c8             	mov    r8d,ecx
   140001de1:	48 89 c1             	mov    rcx,rax
   140001de4:	48 8b 05 65 e4 00 00 	mov    rax,QWORD PTR [rip+0xe465]        # 140010250 <__imp_VirtualProtect>
   140001deb:	ff d0                	call   rax
   140001ded:	85 c0                	test   eax,eax
   140001def:	75 1a                	jne    140001e0b <mark_section_writable+0x2c6>
   140001df1:	48 8b 05 08 e4 00 00 	mov    rax,QWORD PTR [rip+0xe408]        # 140010200 <__imp_GetLastError>
   140001df8:	ff d0                	call   rax
   140001dfa:	89 c2                	mov    edx,eax
   140001dfc:	48 8d 05 45 94 00 00 	lea    rax,[rip+0x9445]        # 14000b248 <.rdata+0x78>
   140001e03:	48 89 c1             	mov    rcx,rax
   140001e06:	e8 d5 fc ff ff       	call   140001ae0 <__report_error>
   140001e0b:	8b 05 d7 d2 00 00    	mov    eax,DWORD PTR [rip+0xd2d7]        # 14000f0e8 <maxSections>
   140001e11:	83 c0 01             	add    eax,0x1
   140001e14:	89 05 ce d2 00 00    	mov    DWORD PTR [rip+0xd2ce],eax        # 14000f0e8 <maxSections>
   140001e1a:	eb 01                	jmp    140001e1d <mark_section_writable+0x2d8>
   140001e1c:	90                   	nop
   140001e1d:	48 83 c4 60          	add    rsp,0x60
   140001e21:	5d                   	pop    rbp
   140001e22:	c3                   	ret

0000000140001e23 <restore_modified_sections>:
   140001e23:	55                   	push   rbp
   140001e24:	48 89 e5             	mov    rbp,rsp
   140001e27:	48 83 ec 30          	sub    rsp,0x30
   140001e2b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e32:	e9 ad 00 00 00       	jmp    140001ee4 <restore_modified_sections+0xc1>
   140001e37:	48 8b 0d a2 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2a2]        # 14000f0e0 <the_secs>
   140001e3e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e41:	48 63 d0             	movsxd rdx,eax
   140001e44:	48 89 d0             	mov    rax,rdx
   140001e47:	48 c1 e0 02          	shl    rax,0x2
   140001e4b:	48 01 d0             	add    rax,rdx
   140001e4e:	48 c1 e0 03          	shl    rax,0x3
   140001e52:	48 01 c8             	add    rax,rcx
   140001e55:	8b 00                	mov    eax,DWORD PTR [rax]
   140001e57:	85 c0                	test   eax,eax
   140001e59:	0f 84 80 00 00 00    	je     140001edf <restore_modified_sections+0xbc>
   140001e5f:	48 8b 0d 7a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd27a]        # 14000f0e0 <the_secs>
   140001e66:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e69:	48 63 d0             	movsxd rdx,eax
   140001e6c:	48 89 d0             	mov    rax,rdx
   140001e6f:	48 c1 e0 02          	shl    rax,0x2
   140001e73:	48 01 d0             	add    rax,rdx
   140001e76:	48 c1 e0 03          	shl    rax,0x3
   140001e7a:	48 01 c8             	add    rax,rcx
   140001e7d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001e80:	48 8b 0d 59 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd259]        # 14000f0e0 <the_secs>
   140001e87:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e8a:	48 63 d0             	movsxd rdx,eax
   140001e8d:	48 89 d0             	mov    rax,rdx
   140001e90:	48 c1 e0 02          	shl    rax,0x2
   140001e94:	48 01 d0             	add    rax,rdx
   140001e97:	48 c1 e0 03          	shl    rax,0x3
   140001e9b:	48 01 c8             	add    rax,rcx
   140001e9e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001ea2:	4c 8b 05 37 d2 00 00 	mov    r8,QWORD PTR [rip+0xd237]        # 14000f0e0 <the_secs>
   140001ea9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eac:	48 63 d0             	movsxd rdx,eax
   140001eaf:	48 89 d0             	mov    rax,rdx
   140001eb2:	48 c1 e0 02          	shl    rax,0x2
   140001eb6:	48 01 d0             	add    rax,rdx
   140001eb9:	48 c1 e0 03          	shl    rax,0x3
   140001ebd:	4c 01 c0             	add    rax,r8
   140001ec0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001ec4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001ec8:	49 89 d1             	mov    r9,rdx
   140001ecb:	45 89 d0             	mov    r8d,r10d
   140001ece:	48 89 ca             	mov    rdx,rcx
   140001ed1:	48 89 c1             	mov    rcx,rax
   140001ed4:	48 8b 05 75 e3 00 00 	mov    rax,QWORD PTR [rip+0xe375]        # 140010250 <__imp_VirtualProtect>
   140001edb:	ff d0                	call   rax
   140001edd:	eb 01                	jmp    140001ee0 <restore_modified_sections+0xbd>
   140001edf:	90                   	nop
   140001ee0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001ee4:	8b 05 fe d1 00 00    	mov    eax,DWORD PTR [rip+0xd1fe]        # 14000f0e8 <maxSections>
   140001eea:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001eed:	0f 8c 44 ff ff ff    	jl     140001e37 <restore_modified_sections+0x14>
   140001ef3:	90                   	nop
   140001ef4:	90                   	nop
   140001ef5:	48 83 c4 30          	add    rsp,0x30
   140001ef9:	5d                   	pop    rbp
   140001efa:	c3                   	ret

0000000140001efb <__write_memory>:
   140001efb:	55                   	push   rbp
   140001efc:	48 89 e5             	mov    rbp,rsp
   140001eff:	48 83 ec 20          	sub    rsp,0x20
   140001f03:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f07:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f0b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f0f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f14:	74 25                	je     140001f3b <__write_memory+0x40>
   140001f16:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f1a:	48 89 c1             	mov    rcx,rax
   140001f1d:	e8 23 fc ff ff       	call   140001b45 <mark_section_writable>
   140001f22:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f26:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f2a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f2e:	49 89 c8             	mov    r8,rcx
   140001f31:	48 89 c1             	mov    rcx,rax
   140001f34:	e8 9f 75 00 00       	call   1400094d8 <memcpy>
   140001f39:	eb 01                	jmp    140001f3c <__write_memory+0x41>
   140001f3b:	90                   	nop
   140001f3c:	48 83 c4 20          	add    rsp,0x20
   140001f40:	5d                   	pop    rbp
   140001f41:	c3                   	ret

0000000140001f42 <do_pseudo_reloc>:
   140001f42:	55                   	push   rbp
   140001f43:	48 89 e5             	mov    rbp,rsp
   140001f46:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001f4a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f4e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f52:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f56:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001f5a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001f5e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001f62:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f66:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001f6a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001f6f:	0f 8e 44 03 00 00    	jle    1400022b9 <do_pseudo_reloc+0x377>
   140001f75:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001f7a:	7e 25                	jle    140001fa1 <do_pseudo_reloc+0x5f>
   140001f7c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f80:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f82:	85 c0                	test   eax,eax
   140001f84:	75 1b                	jne    140001fa1 <do_pseudo_reloc+0x5f>
   140001f86:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f8a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001f8d:	85 c0                	test   eax,eax
   140001f8f:	75 10                	jne    140001fa1 <do_pseudo_reloc+0x5f>
   140001f91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001f95:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001f98:	85 c0                	test   eax,eax
   140001f9a:	75 05                	jne    140001fa1 <do_pseudo_reloc+0x5f>
   140001f9c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140001fa1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fa5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fa7:	85 c0                	test   eax,eax
   140001fa9:	75 0b                	jne    140001fb6 <do_pseudo_reloc+0x74>
   140001fab:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001faf:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fb2:	85 c0                	test   eax,eax
   140001fb4:	74 59                	je     14000200f <do_pseudo_reloc+0xcd>
   140001fb6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fba:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001fbe:	eb 40                	jmp    140002000 <do_pseudo_reloc+0xbe>
   140001fc0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001fc4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fc7:	89 c2                	mov    edx,eax
   140001fc9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001fcd:	48 01 d0             	add    rax,rdx
   140001fd0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001fd4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001fd8:	8b 10                	mov    edx,DWORD PTR [rax]
   140001fda:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001fde:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fe0:	01 d0                	add    eax,edx
   140001fe2:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140001fe5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001fe9:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   140001fed:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001ff3:	48 89 c1             	mov    rcx,rax
   140001ff6:	e8 00 ff ff ff       	call   140001efb <__write_memory>
   140001ffb:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002000:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002004:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002008:	72 b6                	jb     140001fc0 <do_pseudo_reloc+0x7e>
   14000200a:	e9 ab 02 00 00       	jmp    1400022ba <do_pseudo_reloc+0x378>
   14000200f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002013:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002016:	83 f8 01             	cmp    eax,0x1
   140002019:	74 18                	je     140002033 <do_pseudo_reloc+0xf1>
   14000201b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000201f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002022:	89 c2                	mov    edx,eax
   140002024:	48 8d 05 45 92 00 00 	lea    rax,[rip+0x9245]        # 14000b270 <.rdata+0xa0>
   14000202b:	48 89 c1             	mov    rcx,rax
   14000202e:	e8 ad fa ff ff       	call   140001ae0 <__report_error>
   140002033:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002037:	48 83 c0 0c          	add    rax,0xc
   14000203b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000203f:	e9 65 02 00 00       	jmp    1400022a9 <do_pseudo_reloc+0x367>
   140002044:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002048:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000204b:	89 c2                	mov    edx,eax
   14000204d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002051:	48 01 d0             	add    rax,rdx
   140002054:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002058:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000205c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000205e:	89 c2                	mov    edx,eax
   140002060:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002064:	48 01 d0             	add    rax,rdx
   140002067:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000206b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000206f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002072:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002076:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000207a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000207d:	0f b6 c0             	movzx  eax,al
   140002080:	83 f8 40             	cmp    eax,0x40
   140002083:	0f 84 b6 00 00 00    	je     14000213f <do_pseudo_reloc+0x1fd>
   140002089:	83 f8 40             	cmp    eax,0x40
   14000208c:	0f 87 ba 00 00 00    	ja     14000214c <do_pseudo_reloc+0x20a>
   140002092:	83 f8 20             	cmp    eax,0x20
   140002095:	74 77                	je     14000210e <do_pseudo_reloc+0x1cc>
   140002097:	83 f8 20             	cmp    eax,0x20
   14000209a:	0f 87 ac 00 00 00    	ja     14000214c <do_pseudo_reloc+0x20a>
   1400020a0:	83 f8 08             	cmp    eax,0x8
   1400020a3:	74 0a                	je     1400020af <do_pseudo_reloc+0x16d>
   1400020a5:	83 f8 10             	cmp    eax,0x10
   1400020a8:	74 38                	je     1400020e2 <do_pseudo_reloc+0x1a0>
   1400020aa:	e9 9d 00 00 00       	jmp    14000214c <do_pseudo_reloc+0x20a>
   1400020af:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020b3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400020b6:	0f b6 c0             	movzx  eax,al
   1400020b9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020bd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020c1:	25 80 00 00 00       	and    eax,0x80
   1400020c6:	48 85 c0             	test   rax,rax
   1400020c9:	0f 84 9d 00 00 00    	je     14000216c <do_pseudo_reloc+0x22a>
   1400020cf:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020d3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400020d9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020dd:	e9 8a 00 00 00       	jmp    14000216c <do_pseudo_reloc+0x22a>
   1400020e2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020e6:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400020e9:	0f b7 c0             	movzx  eax,ax
   1400020ec:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020f0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020f4:	25 00 80 00 00       	and    eax,0x8000
   1400020f9:	48 85 c0             	test   rax,rax
   1400020fc:	74 71                	je     14000216f <do_pseudo_reloc+0x22d>
   1400020fe:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002102:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002108:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000210c:	eb 61                	jmp    14000216f <do_pseudo_reloc+0x22d>
   14000210e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002112:	8b 00                	mov    eax,DWORD PTR [rax]
   140002114:	89 c0                	mov    eax,eax
   140002116:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000211a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000211e:	25 00 00 00 80       	and    eax,0x80000000
   140002123:	48 85 c0             	test   rax,rax
   140002126:	74 4a                	je     140002172 <do_pseudo_reloc+0x230>
   140002128:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000212c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002133:	ff ff ff 
   140002136:	48 09 d0             	or     rax,rdx
   140002139:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000213d:	eb 33                	jmp    140002172 <do_pseudo_reloc+0x230>
   14000213f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002143:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002146:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000214a:	eb 27                	jmp    140002173 <do_pseudo_reloc+0x231>
   14000214c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002153:	00 
   140002154:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002158:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000215b:	0f b6 c0             	movzx  eax,al
   14000215e:	48 8d 0d 43 91 00 00 	lea    rcx,[rip+0x9143]        # 14000b2a8 <.rdata+0xd8>
   140002165:	89 c2                	mov    edx,eax
   140002167:	e8 74 f9 ff ff       	call   140001ae0 <__report_error>
   14000216c:	90                   	nop
   14000216d:	eb 04                	jmp    140002173 <do_pseudo_reloc+0x231>
   14000216f:	90                   	nop
   140002170:	eb 01                	jmp    140002173 <do_pseudo_reloc+0x231>
   140002172:	90                   	nop
   140002173:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002177:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000217b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000217d:	89 c2                	mov    edx,eax
   14000217f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002183:	48 01 c2             	add    rdx,rax
   140002186:	48 89 c8             	mov    rax,rcx
   140002189:	48 29 d0             	sub    rax,rdx
   14000218c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002190:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002194:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002198:	48 01 d0             	add    rax,rdx
   14000219b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000219f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021a3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021a6:	25 ff 00 00 00       	and    eax,0xff
   1400021ab:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400021ae:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400021b2:	77 67                	ja     14000221b <do_pseudo_reloc+0x2d9>
   1400021b4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021b7:	ba 01 00 00 00       	mov    edx,0x1
   1400021bc:	89 c1                	mov    ecx,eax
   1400021be:	48 d3 e2             	shl    rdx,cl
   1400021c1:	48 89 d0             	mov    rax,rdx
   1400021c4:	48 83 e8 01          	sub    rax,0x1
   1400021c8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400021cc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021cf:	83 e8 01             	sub    eax,0x1
   1400021d2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400021d9:	89 c1                	mov    ecx,eax
   1400021db:	48 d3 e2             	shl    rdx,cl
   1400021de:	48 89 d0             	mov    rax,rdx
   1400021e1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400021e5:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021e9:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   1400021ed:	7c 0a                	jl     1400021f9 <do_pseudo_reloc+0x2b7>
   1400021ef:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021f3:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400021f7:	7e 22                	jle    14000221b <do_pseudo_reloc+0x2d9>
   1400021f9:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021fd:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002201:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002205:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002208:	48 8d 0d c9 90 00 00 	lea    rcx,[rip+0x90c9]        # 14000b2d8 <.rdata+0x108>
   14000220f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002214:	89 c2                	mov    edx,eax
   140002216:	e8 c5 f8 ff ff       	call   140001ae0 <__report_error>
   14000221b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000221f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002222:	0f b6 c0             	movzx  eax,al
   140002225:	83 f8 40             	cmp    eax,0x40
   140002228:	74 63                	je     14000228d <do_pseudo_reloc+0x34b>
   14000222a:	83 f8 40             	cmp    eax,0x40
   14000222d:	77 75                	ja     1400022a4 <do_pseudo_reloc+0x362>
   14000222f:	83 f8 20             	cmp    eax,0x20
   140002232:	74 41                	je     140002275 <do_pseudo_reloc+0x333>
   140002234:	83 f8 20             	cmp    eax,0x20
   140002237:	77 6b                	ja     1400022a4 <do_pseudo_reloc+0x362>
   140002239:	83 f8 08             	cmp    eax,0x8
   14000223c:	74 07                	je     140002245 <do_pseudo_reloc+0x303>
   14000223e:	83 f8 10             	cmp    eax,0x10
   140002241:	74 1a                	je     14000225d <do_pseudo_reloc+0x31b>
   140002243:	eb 5f                	jmp    1400022a4 <do_pseudo_reloc+0x362>
   140002245:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002249:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000224d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002253:	48 89 c1             	mov    rcx,rax
   140002256:	e8 a0 fc ff ff       	call   140001efb <__write_memory>
   14000225b:	eb 47                	jmp    1400022a4 <do_pseudo_reloc+0x362>
   14000225d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002261:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002265:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000226b:	48 89 c1             	mov    rcx,rax
   14000226e:	e8 88 fc ff ff       	call   140001efb <__write_memory>
   140002273:	eb 2f                	jmp    1400022a4 <do_pseudo_reloc+0x362>
   140002275:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002279:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000227d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002283:	48 89 c1             	mov    rcx,rax
   140002286:	e8 70 fc ff ff       	call   140001efb <__write_memory>
   14000228b:	eb 17                	jmp    1400022a4 <do_pseudo_reloc+0x362>
   14000228d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002291:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002295:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000229b:	48 89 c1             	mov    rcx,rax
   14000229e:	e8 58 fc ff ff       	call   140001efb <__write_memory>
   1400022a3:	90                   	nop
   1400022a4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400022a9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022ad:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400022b1:	0f 82 8d fd ff ff    	jb     140002044 <do_pseudo_reloc+0x102>
   1400022b7:	eb 01                	jmp    1400022ba <do_pseudo_reloc+0x378>
   1400022b9:	90                   	nop
   1400022ba:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400022be:	5d                   	pop    rbp
   1400022bf:	c3                   	ret

00000001400022c0 <_pei386_runtime_relocator>:
   1400022c0:	55                   	push   rbp
   1400022c1:	48 89 e5             	mov    rbp,rsp
   1400022c4:	48 83 ec 30          	sub    rsp,0x30
   1400022c8:	8b 05 1e ce 00 00    	mov    eax,DWORD PTR [rip+0xce1e]        # 14000f0ec <was_init.0>
   1400022ce:	85 c0                	test   eax,eax
   1400022d0:	0f 85 88 00 00 00    	jne    14000235e <_pei386_runtime_relocator+0x9e>
   1400022d6:	8b 05 10 ce 00 00    	mov    eax,DWORD PTR [rip+0xce10]        # 14000f0ec <was_init.0>
   1400022dc:	83 c0 01             	add    eax,0x1
   1400022df:	89 05 07 ce 00 00    	mov    DWORD PTR [rip+0xce07],eax        # 14000f0ec <was_init.0>
   1400022e5:	e8 21 0b 00 00       	call   140002e0b <__mingw_GetSectionCount>
   1400022ea:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400022ed:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400022f0:	48 63 d0             	movsxd rdx,eax
   1400022f3:	48 89 d0             	mov    rax,rdx
   1400022f6:	48 c1 e0 02          	shl    rax,0x2
   1400022fa:	48 01 d0             	add    rax,rdx
   1400022fd:	48 c1 e0 03          	shl    rax,0x3
   140002301:	48 83 c0 0f          	add    rax,0xf
   140002305:	48 c1 e8 04          	shr    rax,0x4
   140002309:	48 c1 e0 04          	shl    rax,0x4
   14000230d:	e8 7e 0d 00 00       	call   140003090 <___chkstk_ms>
   140002312:	48 29 c4             	sub    rsp,rax
   140002315:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000231a:	48 83 c0 0f          	add    rax,0xf
   14000231e:	48 c1 e8 04          	shr    rax,0x4
   140002322:	48 c1 e0 04          	shl    rax,0x4
   140002326:	48 89 05 b3 cd 00 00 	mov    QWORD PTR [rip+0xcdb3],rax        # 14000f0e0 <the_secs>
   14000232d:	c7 05 b1 cd 00 00 00 	mov    DWORD PTR [rip+0xcdb1],0x0        # 14000f0e8 <maxSections>
   140002334:	00 00 00 
   140002337:	48 8b 0d 42 92 00 00 	mov    rcx,QWORD PTR [rip+0x9242]        # 14000b580 <.refptr.__ImageBase>
   14000233e:	48 8b 15 4b 92 00 00 	mov    rdx,QWORD PTR [rip+0x924b]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002345:	48 8b 05 54 92 00 00 	mov    rax,QWORD PTR [rip+0x9254]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000234c:	49 89 c8             	mov    r8,rcx
   14000234f:	48 89 c1             	mov    rcx,rax
   140002352:	e8 eb fb ff ff       	call   140001f42 <do_pseudo_reloc>
   140002357:	e8 c7 fa ff ff       	call   140001e23 <restore_modified_sections>
   14000235c:	eb 01                	jmp    14000235f <_pei386_runtime_relocator+0x9f>
   14000235e:	90                   	nop
   14000235f:	48 89 ec             	mov    rsp,rbp
   140002362:	5d                   	pop    rbp
   140002363:	c3                   	ret
   140002364:	90                   	nop
   140002365:	90                   	nop
   140002366:	90                   	nop
   140002367:	90                   	nop
   140002368:	90                   	nop
   140002369:	90                   	nop
   14000236a:	90                   	nop
   14000236b:	90                   	nop
   14000236c:	90                   	nop
   14000236d:	90                   	nop
   14000236e:	90                   	nop
   14000236f:	90                   	nop

0000000140002370 <__mingw_raise_matherr>:
   140002370:	55                   	push   rbp
   140002371:	48 89 e5             	mov    rbp,rsp
   140002374:	48 83 ec 50          	sub    rsp,0x50
   140002378:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000237b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000237f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002384:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002389:	48 8b 05 60 cd 00 00 	mov    rax,QWORD PTR [rip+0xcd60]        # 14000f0f0 <stUserMathErr>
   140002390:	48 85 c0             	test   rax,rax
   140002393:	74 3e                	je     1400023d3 <__mingw_raise_matherr+0x63>
   140002395:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002398:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000239b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000239f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400023a3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400023a8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400023ad:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400023b2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400023b7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400023bc:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400023c1:	48 8b 15 28 cd 00 00 	mov    rdx,QWORD PTR [rip+0xcd28]        # 14000f0f0 <stUserMathErr>
   1400023c8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400023cc:	48 89 c1             	mov    rcx,rax
   1400023cf:	ff d2                	call   rdx
   1400023d1:	eb 01                	jmp    1400023d4 <__mingw_raise_matherr+0x64>
   1400023d3:	90                   	nop
   1400023d4:	48 83 c4 50          	add    rsp,0x50
   1400023d8:	5d                   	pop    rbp
   1400023d9:	c3                   	ret

00000001400023da <__mingw_setusermatherr>:
   1400023da:	55                   	push   rbp
   1400023db:	48 89 e5             	mov    rbp,rsp
   1400023de:	48 83 ec 20          	sub    rsp,0x20
   1400023e2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400023e6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400023ea:	48 89 05 ff cc 00 00 	mov    QWORD PTR [rip+0xccff],rax        # 14000f0f0 <stUserMathErr>
   1400023f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400023f5:	48 89 c1             	mov    rcx,rax
   1400023f8:	e8 63 70 00 00       	call   140009460 <__setusermatherr>
   1400023fd:	90                   	nop
   1400023fe:	48 83 c4 20          	add    rsp,0x20
   140002402:	5d                   	pop    rbp
   140002403:	c3                   	ret
   140002404:	90                   	nop
   140002405:	90                   	nop
   140002406:	90                   	nop
   140002407:	90                   	nop
   140002408:	90                   	nop
   140002409:	90                   	nop
   14000240a:	90                   	nop
   14000240b:	90                   	nop
   14000240c:	90                   	nop
   14000240d:	90                   	nop
   14000240e:	90                   	nop
   14000240f:	90                   	nop

0000000140002410 <__mingw_SEH_error_handler>:
   140002410:	55                   	push   rbp
   140002411:	48 89 e5             	mov    rbp,rsp
   140002414:	48 83 ec 30          	sub    rsp,0x30
   140002418:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000241c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002420:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002424:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002428:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000242f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002436:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000243a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000243d:	83 e0 02             	and    eax,0x2
   140002440:	85 c0                	test   eax,eax
   140002442:	74 0a                	je     14000244e <__mingw_SEH_error_handler+0x3e>
   140002444:	b8 01 00 00 00       	mov    eax,0x1
   140002449:	e9 16 02 00 00       	jmp    140002664 <__mingw_SEH_error_handler+0x254>
   14000244e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002452:	8b 00                	mov    eax,DWORD PTR [rax]
   140002454:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002459:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000245e:	75 18                	jne    140002478 <__mingw_SEH_error_handler+0x68>
   140002460:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002464:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002467:	83 e0 01             	and    eax,0x1
   14000246a:	85 c0                	test   eax,eax
   14000246c:	75 0a                	jne    140002478 <__mingw_SEH_error_handler+0x68>
   14000246e:	b8 00 00 00 00       	mov    eax,0x0
   140002473:	e9 ec 01 00 00       	jmp    140002664 <__mingw_SEH_error_handler+0x254>
   140002478:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000247c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000247e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002483:	0f 84 12 01 00 00    	je     14000259b <__mingw_SEH_error_handler+0x18b>
   140002489:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000248e:	0f 87 c3 01 00 00    	ja     140002657 <__mingw_SEH_error_handler+0x247>
   140002494:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002499:	0f 87 b8 01 00 00    	ja     140002657 <__mingw_SEH_error_handler+0x247>
   14000249f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400024a4:	0f 83 4c 01 00 00    	jae    1400025f6 <__mingw_SEH_error_handler+0x1e6>
   1400024aa:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024af:	0f 84 3a 01 00 00    	je     1400025ef <__mingw_SEH_error_handler+0x1df>
   1400024b5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024ba:	0f 87 97 01 00 00    	ja     140002657 <__mingw_SEH_error_handler+0x247>
   1400024c0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024c5:	0f 84 83 01 00 00    	je     14000264e <__mingw_SEH_error_handler+0x23e>
   1400024cb:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024d0:	0f 87 81 01 00 00    	ja     140002657 <__mingw_SEH_error_handler+0x247>
   1400024d6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400024db:	0f 87 76 01 00 00    	ja     140002657 <__mingw_SEH_error_handler+0x247>
   1400024e1:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400024e6:	0f 83 03 01 00 00    	jae    1400025ef <__mingw_SEH_error_handler+0x1df>
   1400024ec:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400024f1:	0f 84 57 01 00 00    	je     14000264e <__mingw_SEH_error_handler+0x23e>
   1400024f7:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400024fc:	0f 87 55 01 00 00    	ja     140002657 <__mingw_SEH_error_handler+0x247>
   140002502:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002507:	0f 84 8e 00 00 00    	je     14000259b <__mingw_SEH_error_handler+0x18b>
   14000250d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002512:	0f 87 3f 01 00 00    	ja     140002657 <__mingw_SEH_error_handler+0x247>
   140002518:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000251d:	0f 84 2b 01 00 00    	je     14000264e <__mingw_SEH_error_handler+0x23e>
   140002523:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002528:	0f 87 29 01 00 00    	ja     140002657 <__mingw_SEH_error_handler+0x247>
   14000252e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002533:	0f 84 15 01 00 00    	je     14000264e <__mingw_SEH_error_handler+0x23e>
   140002539:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000253e:	0f 85 13 01 00 00    	jne    140002657 <__mingw_SEH_error_handler+0x247>
   140002544:	ba 00 00 00 00       	mov    edx,0x0
   140002549:	b9 0b 00 00 00       	mov    ecx,0xb
   14000254e:	e8 9d 6f 00 00       	call   1400094f0 <signal>
   140002553:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002557:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000255c:	75 1b                	jne    140002579 <__mingw_SEH_error_handler+0x169>
   14000255e:	ba 01 00 00 00       	mov    edx,0x1
   140002563:	b9 0b 00 00 00       	mov    ecx,0xb
   140002568:	e8 83 6f 00 00       	call   1400094f0 <signal>
   14000256d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002574:	e9 e1 00 00 00       	jmp    14000265a <__mingw_SEH_error_handler+0x24a>
   140002579:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000257e:	0f 84 d6 00 00 00    	je     14000265a <__mingw_SEH_error_handler+0x24a>
   140002584:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002588:	b9 0b 00 00 00       	mov    ecx,0xb
   14000258d:	ff d0                	call   rax
   14000258f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002596:	e9 bf 00 00 00       	jmp    14000265a <__mingw_SEH_error_handler+0x24a>
   14000259b:	ba 00 00 00 00       	mov    edx,0x0
   1400025a0:	b9 04 00 00 00       	mov    ecx,0x4
   1400025a5:	e8 46 6f 00 00       	call   1400094f0 <signal>
   1400025aa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025ae:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025b3:	75 1b                	jne    1400025d0 <__mingw_SEH_error_handler+0x1c0>
   1400025b5:	ba 01 00 00 00       	mov    edx,0x1
   1400025ba:	b9 04 00 00 00       	mov    ecx,0x4
   1400025bf:	e8 2c 6f 00 00       	call   1400094f0 <signal>
   1400025c4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025cb:	e9 8d 00 00 00       	jmp    14000265d <__mingw_SEH_error_handler+0x24d>
   1400025d0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025d5:	0f 84 82 00 00 00    	je     14000265d <__mingw_SEH_error_handler+0x24d>
   1400025db:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025df:	b9 04 00 00 00       	mov    ecx,0x4
   1400025e4:	ff d0                	call   rax
   1400025e6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025ed:	eb 6e                	jmp    14000265d <__mingw_SEH_error_handler+0x24d>
   1400025ef:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400025f6:	ba 00 00 00 00       	mov    edx,0x0
   1400025fb:	b9 08 00 00 00       	mov    ecx,0x8
   140002600:	e8 eb 6e 00 00       	call   1400094f0 <signal>
   140002605:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002609:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000260e:	75 23                	jne    140002633 <__mingw_SEH_error_handler+0x223>
   140002610:	ba 01 00 00 00       	mov    edx,0x1
   140002615:	b9 08 00 00 00       	mov    ecx,0x8
   14000261a:	e8 d1 6e 00 00       	call   1400094f0 <signal>
   14000261f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002623:	74 05                	je     14000262a <__mingw_SEH_error_handler+0x21a>
   140002625:	e8 a6 05 00 00       	call   140002bd0 <_fpreset>
   14000262a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002631:	eb 2d                	jmp    140002660 <__mingw_SEH_error_handler+0x250>
   140002633:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002638:	74 26                	je     140002660 <__mingw_SEH_error_handler+0x250>
   14000263a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000263e:	b9 08 00 00 00       	mov    ecx,0x8
   140002643:	ff d0                	call   rax
   140002645:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000264c:	eb 12                	jmp    140002660 <__mingw_SEH_error_handler+0x250>
   14000264e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002655:	eb 0a                	jmp    140002661 <__mingw_SEH_error_handler+0x251>
   140002657:	90                   	nop
   140002658:	eb 07                	jmp    140002661 <__mingw_SEH_error_handler+0x251>
   14000265a:	90                   	nop
   14000265b:	eb 04                	jmp    140002661 <__mingw_SEH_error_handler+0x251>
   14000265d:	90                   	nop
   14000265e:	eb 01                	jmp    140002661 <__mingw_SEH_error_handler+0x251>
   140002660:	90                   	nop
   140002661:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002664:	48 83 c4 30          	add    rsp,0x30
   140002668:	5d                   	pop    rbp
   140002669:	c3                   	ret

000000014000266a <_gnu_exception_handler>:
   14000266a:	55                   	push   rbp
   14000266b:	48 89 e5             	mov    rbp,rsp
   14000266e:	48 83 ec 30          	sub    rsp,0x30
   140002672:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002676:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000267d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002684:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002688:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000268b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000268d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002692:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002697:	75 1b                	jne    1400026b4 <_gnu_exception_handler+0x4a>
   140002699:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000269d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026a0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400026a3:	83 e0 01             	and    eax,0x1
   1400026a6:	85 c0                	test   eax,eax
   1400026a8:	75 0a                	jne    1400026b4 <_gnu_exception_handler+0x4a>
   1400026aa:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400026af:	e9 14 02 00 00       	jmp    1400028c8 <_gnu_exception_handler+0x25e>
   1400026b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026b8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026bb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026bd:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026c2:	0f 84 12 01 00 00    	je     1400027da <_gnu_exception_handler+0x170>
   1400026c8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026cd:	0f 87 c3 01 00 00    	ja     140002896 <_gnu_exception_handler+0x22c>
   1400026d3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400026d8:	0f 87 b8 01 00 00    	ja     140002896 <_gnu_exception_handler+0x22c>
   1400026de:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400026e3:	0f 83 4c 01 00 00    	jae    140002835 <_gnu_exception_handler+0x1cb>
   1400026e9:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400026ee:	0f 84 3a 01 00 00    	je     14000282e <_gnu_exception_handler+0x1c4>
   1400026f4:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400026f9:	0f 87 97 01 00 00    	ja     140002896 <_gnu_exception_handler+0x22c>
   1400026ff:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002704:	0f 84 83 01 00 00    	je     14000288d <_gnu_exception_handler+0x223>
   14000270a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000270f:	0f 87 81 01 00 00    	ja     140002896 <_gnu_exception_handler+0x22c>
   140002715:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000271a:	0f 87 76 01 00 00    	ja     140002896 <_gnu_exception_handler+0x22c>
   140002720:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002725:	0f 83 03 01 00 00    	jae    14000282e <_gnu_exception_handler+0x1c4>
   14000272b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002730:	0f 84 57 01 00 00    	je     14000288d <_gnu_exception_handler+0x223>
   140002736:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000273b:	0f 87 55 01 00 00    	ja     140002896 <_gnu_exception_handler+0x22c>
   140002741:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002746:	0f 84 8e 00 00 00    	je     1400027da <_gnu_exception_handler+0x170>
   14000274c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002751:	0f 87 3f 01 00 00    	ja     140002896 <_gnu_exception_handler+0x22c>
   140002757:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000275c:	0f 84 2b 01 00 00    	je     14000288d <_gnu_exception_handler+0x223>
   140002762:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002767:	0f 87 29 01 00 00    	ja     140002896 <_gnu_exception_handler+0x22c>
   14000276d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002772:	0f 84 15 01 00 00    	je     14000288d <_gnu_exception_handler+0x223>
   140002778:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000277d:	0f 85 13 01 00 00    	jne    140002896 <_gnu_exception_handler+0x22c>
   140002783:	ba 00 00 00 00       	mov    edx,0x0
   140002788:	b9 0b 00 00 00       	mov    ecx,0xb
   14000278d:	e8 5e 6d 00 00       	call   1400094f0 <signal>
   140002792:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002796:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000279b:	75 1b                	jne    1400027b8 <_gnu_exception_handler+0x14e>
   14000279d:	ba 01 00 00 00       	mov    edx,0x1
   1400027a2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027a7:	e8 44 6d 00 00       	call   1400094f0 <signal>
   1400027ac:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027b3:	e9 e1 00 00 00       	jmp    140002899 <_gnu_exception_handler+0x22f>
   1400027b8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027bd:	0f 84 d6 00 00 00    	je     140002899 <_gnu_exception_handler+0x22f>
   1400027c3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027c7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027cc:	ff d0                	call   rax
   1400027ce:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027d5:	e9 bf 00 00 00       	jmp    140002899 <_gnu_exception_handler+0x22f>
   1400027da:	ba 00 00 00 00       	mov    edx,0x0
   1400027df:	b9 04 00 00 00       	mov    ecx,0x4
   1400027e4:	e8 07 6d 00 00       	call   1400094f0 <signal>
   1400027e9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027ed:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027f2:	75 1b                	jne    14000280f <_gnu_exception_handler+0x1a5>
   1400027f4:	ba 01 00 00 00       	mov    edx,0x1
   1400027f9:	b9 04 00 00 00       	mov    ecx,0x4
   1400027fe:	e8 ed 6c 00 00       	call   1400094f0 <signal>
   140002803:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000280a:	e9 8d 00 00 00       	jmp    14000289c <_gnu_exception_handler+0x232>
   14000280f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002814:	0f 84 82 00 00 00    	je     14000289c <_gnu_exception_handler+0x232>
   14000281a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000281e:	b9 04 00 00 00       	mov    ecx,0x4
   140002823:	ff d0                	call   rax
   140002825:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000282c:	eb 6e                	jmp    14000289c <_gnu_exception_handler+0x232>
   14000282e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002835:	ba 00 00 00 00       	mov    edx,0x0
   14000283a:	b9 08 00 00 00       	mov    ecx,0x8
   14000283f:	e8 ac 6c 00 00       	call   1400094f0 <signal>
   140002844:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002848:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000284d:	75 23                	jne    140002872 <_gnu_exception_handler+0x208>
   14000284f:	ba 01 00 00 00       	mov    edx,0x1
   140002854:	b9 08 00 00 00       	mov    ecx,0x8
   140002859:	e8 92 6c 00 00       	call   1400094f0 <signal>
   14000285e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002862:	74 05                	je     140002869 <_gnu_exception_handler+0x1ff>
   140002864:	e8 67 03 00 00       	call   140002bd0 <_fpreset>
   140002869:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002870:	eb 2d                	jmp    14000289f <_gnu_exception_handler+0x235>
   140002872:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002877:	74 26                	je     14000289f <_gnu_exception_handler+0x235>
   140002879:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000287d:	b9 08 00 00 00       	mov    ecx,0x8
   140002882:	ff d0                	call   rax
   140002884:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000288b:	eb 12                	jmp    14000289f <_gnu_exception_handler+0x235>
   14000288d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002894:	eb 0a                	jmp    1400028a0 <_gnu_exception_handler+0x236>
   140002896:	90                   	nop
   140002897:	eb 07                	jmp    1400028a0 <_gnu_exception_handler+0x236>
   140002899:	90                   	nop
   14000289a:	eb 04                	jmp    1400028a0 <_gnu_exception_handler+0x236>
   14000289c:	90                   	nop
   14000289d:	eb 01                	jmp    1400028a0 <_gnu_exception_handler+0x236>
   14000289f:	90                   	nop
   1400028a0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400028a4:	75 1f                	jne    1400028c5 <_gnu_exception_handler+0x25b>
   1400028a6:	48 8b 05 63 c8 00 00 	mov    rax,QWORD PTR [rip+0xc863]        # 14000f110 <__mingw_oldexcpt_handler>
   1400028ad:	48 85 c0             	test   rax,rax
   1400028b0:	74 13                	je     1400028c5 <_gnu_exception_handler+0x25b>
   1400028b2:	48 8b 15 57 c8 00 00 	mov    rdx,QWORD PTR [rip+0xc857]        # 14000f110 <__mingw_oldexcpt_handler>
   1400028b9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028bd:	48 89 c1             	mov    rcx,rax
   1400028c0:	ff d2                	call   rdx
   1400028c2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400028c5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400028c8:	48 83 c4 30          	add    rsp,0x30
   1400028cc:	5d                   	pop    rbp
   1400028cd:	c3                   	ret
   1400028ce:	90                   	nop
   1400028cf:	90                   	nop

00000001400028d0 <___w64_mingwthr_add_key_dtor>:
   1400028d0:	55                   	push   rbp
   1400028d1:	48 89 e5             	mov    rbp,rsp
   1400028d4:	48 83 ec 30          	sub    rsp,0x30
   1400028d8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400028db:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400028df:	8b 05 63 c8 00 00    	mov    eax,DWORD PTR [rip+0xc863]        # 14000f148 <__mingwthr_cs_init>
   1400028e5:	85 c0                	test   eax,eax
   1400028e7:	75 07                	jne    1400028f0 <___w64_mingwthr_add_key_dtor+0x20>
   1400028e9:	b8 00 00 00 00       	mov    eax,0x0
   1400028ee:	eb 7b                	jmp    14000296b <___w64_mingwthr_add_key_dtor+0x9b>
   1400028f0:	ba 18 00 00 00       	mov    edx,0x18
   1400028f5:	b9 01 00 00 00       	mov    ecx,0x1
   1400028fa:	e8 99 6b 00 00       	call   140009498 <calloc>
   1400028ff:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002903:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002908:	75 07                	jne    140002911 <___w64_mingwthr_add_key_dtor+0x41>
   14000290a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000290f:	eb 5a                	jmp    14000296b <___w64_mingwthr_add_key_dtor+0x9b>
   140002911:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002915:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002918:	89 10                	mov    DWORD PTR [rax],edx
   14000291a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000291e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002922:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002926:	48 8d 05 f3 c7 00 00 	lea    rax,[rip+0xc7f3]        # 14000f120 <__mingwthr_cs>
   14000292d:	48 89 c1             	mov    rcx,rax
   140002930:	48 8b 05 b1 d8 00 00 	mov    rax,QWORD PTR [rip+0xd8b1]        # 1400101e8 <__imp_EnterCriticalSection>
   140002937:	ff d0                	call   rax
   140002939:	48 8b 15 10 c8 00 00 	mov    rdx,QWORD PTR [rip+0xc810]        # 14000f150 <key_dtor_list>
   140002940:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002944:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002948:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000294c:	48 89 05 fd c7 00 00 	mov    QWORD PTR [rip+0xc7fd],rax        # 14000f150 <key_dtor_list>
   140002953:	48 8d 05 c6 c7 00 00 	lea    rax,[rip+0xc7c6]        # 14000f120 <__mingwthr_cs>
   14000295a:	48 89 c1             	mov    rcx,rax
   14000295d:	48 8b 05 bc d8 00 00 	mov    rax,QWORD PTR [rip+0xd8bc]        # 140010220 <__imp_LeaveCriticalSection>
   140002964:	ff d0                	call   rax
   140002966:	b8 00 00 00 00       	mov    eax,0x0
   14000296b:	48 83 c4 30          	add    rsp,0x30
   14000296f:	5d                   	pop    rbp
   140002970:	c3                   	ret

0000000140002971 <___w64_mingwthr_remove_key_dtor>:
   140002971:	55                   	push   rbp
   140002972:	48 89 e5             	mov    rbp,rsp
   140002975:	48 83 ec 30          	sub    rsp,0x30
   140002979:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000297c:	8b 05 c6 c7 00 00    	mov    eax,DWORD PTR [rip+0xc7c6]        # 14000f148 <__mingwthr_cs_init>
   140002982:	85 c0                	test   eax,eax
   140002984:	75 0a                	jne    140002990 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002986:	b8 00 00 00 00       	mov    eax,0x0
   14000298b:	e9 9c 00 00 00       	jmp    140002a2c <___w64_mingwthr_remove_key_dtor+0xbb>
   140002990:	48 8d 05 89 c7 00 00 	lea    rax,[rip+0xc789]        # 14000f120 <__mingwthr_cs>
   140002997:	48 89 c1             	mov    rcx,rax
   14000299a:	48 8b 05 47 d8 00 00 	mov    rax,QWORD PTR [rip+0xd847]        # 1400101e8 <__imp_EnterCriticalSection>
   1400029a1:	ff d0                	call   rax
   1400029a3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400029aa:	00 
   1400029ab:	48 8b 05 9e c7 00 00 	mov    rax,QWORD PTR [rip+0xc79e]        # 14000f150 <key_dtor_list>
   1400029b2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029b6:	eb 55                	jmp    140002a0d <___w64_mingwthr_remove_key_dtor+0x9c>
   1400029b8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029bc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400029be:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   1400029c1:	75 36                	jne    1400029f9 <___w64_mingwthr_remove_key_dtor+0x88>
   1400029c3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029c8:	75 11                	jne    1400029db <___w64_mingwthr_remove_key_dtor+0x6a>
   1400029ca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ce:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   1400029d2:	48 89 05 77 c7 00 00 	mov    QWORD PTR [rip+0xc777],rax        # 14000f150 <key_dtor_list>
   1400029d9:	eb 10                	jmp    1400029eb <___w64_mingwthr_remove_key_dtor+0x7a>
   1400029db:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029df:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   1400029e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029e7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029eb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ef:	48 89 c1             	mov    rcx,rax
   1400029f2:	e8 c9 6a 00 00       	call   1400094c0 <free>
   1400029f7:	eb 1b                	jmp    140002a14 <___w64_mingwthr_remove_key_dtor+0xa3>
   1400029f9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029fd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a01:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a05:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a09:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a0d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a12:	75 a4                	jne    1400029b8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a14:	48 8d 05 05 c7 00 00 	lea    rax,[rip+0xc705]        # 14000f120 <__mingwthr_cs>
   140002a1b:	48 89 c1             	mov    rcx,rax
   140002a1e:	48 8b 05 fb d7 00 00 	mov    rax,QWORD PTR [rip+0xd7fb]        # 140010220 <__imp_LeaveCriticalSection>
   140002a25:	ff d0                	call   rax
   140002a27:	b8 00 00 00 00       	mov    eax,0x0
   140002a2c:	48 83 c4 30          	add    rsp,0x30
   140002a30:	5d                   	pop    rbp
   140002a31:	c3                   	ret

0000000140002a32 <__mingwthr_run_key_dtors>:
   140002a32:	55                   	push   rbp
   140002a33:	48 89 e5             	mov    rbp,rsp
   140002a36:	48 83 ec 30          	sub    rsp,0x30
   140002a3a:	8b 05 08 c7 00 00    	mov    eax,DWORD PTR [rip+0xc708]        # 14000f148 <__mingwthr_cs_init>
   140002a40:	85 c0                	test   eax,eax
   140002a42:	0f 84 82 00 00 00    	je     140002aca <__mingwthr_run_key_dtors+0x98>
   140002a48:	48 8d 05 d1 c6 00 00 	lea    rax,[rip+0xc6d1]        # 14000f120 <__mingwthr_cs>
   140002a4f:	48 89 c1             	mov    rcx,rax
   140002a52:	48 8b 05 8f d7 00 00 	mov    rax,QWORD PTR [rip+0xd78f]        # 1400101e8 <__imp_EnterCriticalSection>
   140002a59:	ff d0                	call   rax
   140002a5b:	48 8b 05 ee c6 00 00 	mov    rax,QWORD PTR [rip+0xc6ee]        # 14000f150 <key_dtor_list>
   140002a62:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a66:	eb 46                	jmp    140002aae <__mingwthr_run_key_dtors+0x7c>
   140002a68:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a6c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a6e:	89 c1                	mov    ecx,eax
   140002a70:	48 8b 05 d1 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7d1]        # 140010248 <__imp_TlsGetValue>
   140002a77:	ff d0                	call   rax
   140002a79:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a7d:	48 8b 05 7c d7 00 00 	mov    rax,QWORD PTR [rip+0xd77c]        # 140010200 <__imp_GetLastError>
   140002a84:	ff d0                	call   rax
   140002a86:	85 c0                	test   eax,eax
   140002a88:	75 18                	jne    140002aa2 <__mingwthr_run_key_dtors+0x70>
   140002a8a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a8f:	74 11                	je     140002aa2 <__mingwthr_run_key_dtors+0x70>
   140002a91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a95:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002a99:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a9d:	48 89 c1             	mov    rcx,rax
   140002aa0:	ff d2                	call   rdx
   140002aa2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002aa6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002aaa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002aae:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ab3:	75 b3                	jne    140002a68 <__mingwthr_run_key_dtors+0x36>
   140002ab5:	48 8d 05 64 c6 00 00 	lea    rax,[rip+0xc664]        # 14000f120 <__mingwthr_cs>
   140002abc:	48 89 c1             	mov    rcx,rax
   140002abf:	48 8b 05 5a d7 00 00 	mov    rax,QWORD PTR [rip+0xd75a]        # 140010220 <__imp_LeaveCriticalSection>
   140002ac6:	ff d0                	call   rax
   140002ac8:	eb 01                	jmp    140002acb <__mingwthr_run_key_dtors+0x99>
   140002aca:	90                   	nop
   140002acb:	48 83 c4 30          	add    rsp,0x30
   140002acf:	5d                   	pop    rbp
   140002ad0:	c3                   	ret

0000000140002ad1 <__mingw_TLScallback>:
   140002ad1:	55                   	push   rbp
   140002ad2:	48 89 e5             	mov    rbp,rsp
   140002ad5:	48 83 ec 30          	sub    rsp,0x30
   140002ad9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002add:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002ae0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002ae4:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002ae8:	0f 84 cc 00 00 00    	je     140002bba <__mingw_TLScallback+0xe9>
   140002aee:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002af2:	0f 87 ca 00 00 00    	ja     140002bc2 <__mingw_TLScallback+0xf1>
   140002af8:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002afc:	0f 84 b1 00 00 00    	je     140002bb3 <__mingw_TLScallback+0xe2>
   140002b02:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b06:	0f 87 b6 00 00 00    	ja     140002bc2 <__mingw_TLScallback+0xf1>
   140002b0c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b10:	74 33                	je     140002b45 <__mingw_TLScallback+0x74>
   140002b12:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b16:	0f 85 a6 00 00 00    	jne    140002bc2 <__mingw_TLScallback+0xf1>
   140002b1c:	8b 05 26 c6 00 00    	mov    eax,DWORD PTR [rip+0xc626]        # 14000f148 <__mingwthr_cs_init>
   140002b22:	85 c0                	test   eax,eax
   140002b24:	75 13                	jne    140002b39 <__mingw_TLScallback+0x68>
   140002b26:	48 8d 05 f3 c5 00 00 	lea    rax,[rip+0xc5f3]        # 14000f120 <__mingwthr_cs>
   140002b2d:	48 89 c1             	mov    rcx,rax
   140002b30:	48 8b 05 e1 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6e1]        # 140010218 <__imp_InitializeCriticalSection>
   140002b37:	ff d0                	call   rax
   140002b39:	c7 05 05 c6 00 00 01 	mov    DWORD PTR [rip+0xc605],0x1        # 14000f148 <__mingwthr_cs_init>
   140002b40:	00 00 00 
   140002b43:	eb 7d                	jmp    140002bc2 <__mingw_TLScallback+0xf1>
   140002b45:	e8 e8 fe ff ff       	call   140002a32 <__mingwthr_run_key_dtors>
   140002b4a:	8b 05 f8 c5 00 00    	mov    eax,DWORD PTR [rip+0xc5f8]        # 14000f148 <__mingwthr_cs_init>
   140002b50:	83 f8 01             	cmp    eax,0x1
   140002b53:	75 6c                	jne    140002bc1 <__mingw_TLScallback+0xf0>
   140002b55:	48 8b 05 f4 c5 00 00 	mov    rax,QWORD PTR [rip+0xc5f4]        # 14000f150 <key_dtor_list>
   140002b5c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b60:	eb 20                	jmp    140002b82 <__mingw_TLScallback+0xb1>
   140002b62:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b66:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b6a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b6e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b72:	48 89 c1             	mov    rcx,rax
   140002b75:	e8 46 69 00 00       	call   1400094c0 <free>
   140002b7a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b82:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b87:	75 d9                	jne    140002b62 <__mingw_TLScallback+0x91>
   140002b89:	48 c7 05 bc c5 00 00 	mov    QWORD PTR [rip+0xc5bc],0x0        # 14000f150 <key_dtor_list>
   140002b90:	00 00 00 00 
   140002b94:	c7 05 aa c5 00 00 00 	mov    DWORD PTR [rip+0xc5aa],0x0        # 14000f148 <__mingwthr_cs_init>
   140002b9b:	00 00 00 
   140002b9e:	48 8d 05 7b c5 00 00 	lea    rax,[rip+0xc57b]        # 14000f120 <__mingwthr_cs>
   140002ba5:	48 89 c1             	mov    rcx,rax
   140002ba8:	48 8b 05 31 d6 00 00 	mov    rax,QWORD PTR [rip+0xd631]        # 1400101e0 <__IAT_start__>
   140002baf:	ff d0                	call   rax
   140002bb1:	eb 0e                	jmp    140002bc1 <__mingw_TLScallback+0xf0>
   140002bb3:	e8 18 00 00 00       	call   140002bd0 <_fpreset>
   140002bb8:	eb 08                	jmp    140002bc2 <__mingw_TLScallback+0xf1>
   140002bba:	e8 73 fe ff ff       	call   140002a32 <__mingwthr_run_key_dtors>
   140002bbf:	eb 01                	jmp    140002bc2 <__mingw_TLScallback+0xf1>
   140002bc1:	90                   	nop
   140002bc2:	b8 01 00 00 00       	mov    eax,0x1
   140002bc7:	48 83 c4 30          	add    rsp,0x30
   140002bcb:	5d                   	pop    rbp
   140002bcc:	c3                   	ret
   140002bcd:	90                   	nop
   140002bce:	90                   	nop
   140002bcf:	90                   	nop

0000000140002bd0 <_fpreset>:
   140002bd0:	55                   	push   rbp
   140002bd1:	48 89 e5             	mov    rbp,rsp
   140002bd4:	db e3                	fninit
   140002bd6:	90                   	nop
   140002bd7:	5d                   	pop    rbp
   140002bd8:	c3                   	ret
   140002bd9:	90                   	nop
   140002bda:	90                   	nop
   140002bdb:	90                   	nop
   140002bdc:	90                   	nop
   140002bdd:	90                   	nop
   140002bde:	90                   	nop
   140002bdf:	90                   	nop

0000000140002be0 <_ValidateImageBase>:
   140002be0:	55                   	push   rbp
   140002be1:	48 89 e5             	mov    rbp,rsp
   140002be4:	48 83 ec 20          	sub    rsp,0x20
   140002be8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002bec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002bf0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bf4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bf8:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002bfb:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002bff:	74 07                	je     140002c08 <_ValidateImageBase+0x28>
   140002c01:	b8 00 00 00 00       	mov    eax,0x0
   140002c06:	eb 4e                	jmp    140002c56 <_ValidateImageBase+0x76>
   140002c08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c0c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c0f:	48 63 d0             	movsxd rdx,eax
   140002c12:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c16:	48 01 d0             	add    rax,rdx
   140002c19:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c1d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c21:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c23:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c28:	74 07                	je     140002c31 <_ValidateImageBase+0x51>
   140002c2a:	b8 00 00 00 00       	mov    eax,0x0
   140002c2f:	eb 25                	jmp    140002c56 <_ValidateImageBase+0x76>
   140002c31:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c35:	48 83 c0 18          	add    rax,0x18
   140002c39:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c3d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c41:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c44:	66 3d 0b 02          	cmp    ax,0x20b
   140002c48:	74 07                	je     140002c51 <_ValidateImageBase+0x71>
   140002c4a:	b8 00 00 00 00       	mov    eax,0x0
   140002c4f:	eb 05                	jmp    140002c56 <_ValidateImageBase+0x76>
   140002c51:	b8 01 00 00 00       	mov    eax,0x1
   140002c56:	48 83 c4 20          	add    rsp,0x20
   140002c5a:	5d                   	pop    rbp
   140002c5b:	c3                   	ret

0000000140002c5c <_FindPESection>:
   140002c5c:	55                   	push   rbp
   140002c5d:	48 89 e5             	mov    rbp,rsp
   140002c60:	48 83 ec 20          	sub    rsp,0x20
   140002c64:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c68:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002c6c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c70:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c73:	48 63 d0             	movsxd rdx,eax
   140002c76:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c7a:	48 01 d0             	add    rax,rdx
   140002c7d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c81:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002c88:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c8c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002c90:	0f b7 d0             	movzx  edx,ax
   140002c93:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c97:	48 01 d0             	add    rax,rdx
   140002c9a:	48 83 c0 18          	add    rax,0x18
   140002c9e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ca2:	eb 36                	jmp    140002cda <_FindPESection+0x7e>
   140002ca4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ca8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002cab:	89 c0                	mov    eax,eax
   140002cad:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cb1:	72 1e                	jb     140002cd1 <_FindPESection+0x75>
   140002cb3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cb7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002cba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cbe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002cc1:	01 d0                	add    eax,edx
   140002cc3:	89 c0                	mov    eax,eax
   140002cc5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cc9:	73 06                	jae    140002cd1 <_FindPESection+0x75>
   140002ccb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ccf:	eb 1e                	jmp    140002cef <_FindPESection+0x93>
   140002cd1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002cd5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002cda:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cde:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ce2:	0f b7 c0             	movzx  eax,ax
   140002ce5:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002ce8:	72 ba                	jb     140002ca4 <_FindPESection+0x48>
   140002cea:	b8 00 00 00 00       	mov    eax,0x0
   140002cef:	48 83 c4 20          	add    rsp,0x20
   140002cf3:	5d                   	pop    rbp
   140002cf4:	c3                   	ret

0000000140002cf5 <_FindPESectionByName>:
   140002cf5:	55                   	push   rbp
   140002cf6:	48 89 e5             	mov    rbp,rsp
   140002cf9:	48 83 ec 40          	sub    rsp,0x40
   140002cfd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d01:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d05:	48 89 c1             	mov    rcx,rax
   140002d08:	e8 f3 67 00 00       	call   140009500 <strlen>
   140002d0d:	48 83 f8 08          	cmp    rax,0x8
   140002d11:	76 0a                	jbe    140002d1d <_FindPESectionByName+0x28>
   140002d13:	b8 00 00 00 00       	mov    eax,0x0
   140002d18:	e9 98 00 00 00       	jmp    140002db5 <_FindPESectionByName+0xc0>
   140002d1d:	48 8b 05 5c 88 00 00 	mov    rax,QWORD PTR [rip+0x885c]        # 14000b580 <.refptr.__ImageBase>
   140002d24:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d28:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d2c:	48 89 c1             	mov    rcx,rax
   140002d2f:	e8 ac fe ff ff       	call   140002be0 <_ValidateImageBase>
   140002d34:	85 c0                	test   eax,eax
   140002d36:	75 07                	jne    140002d3f <_FindPESectionByName+0x4a>
   140002d38:	b8 00 00 00 00       	mov    eax,0x0
   140002d3d:	eb 76                	jmp    140002db5 <_FindPESectionByName+0xc0>
   140002d3f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d43:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d46:	48 63 d0             	movsxd rdx,eax
   140002d49:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d4d:	48 01 d0             	add    rax,rdx
   140002d50:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002d54:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d5b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d5f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d63:	0f b7 d0             	movzx  edx,ax
   140002d66:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d6a:	48 01 d0             	add    rax,rdx
   140002d6d:	48 83 c0 18          	add    rax,0x18
   140002d71:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d75:	eb 29                	jmp    140002da0 <_FindPESectionByName+0xab>
   140002d77:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d7b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002d7f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002d85:	48 89 c1             	mov    rcx,rax
   140002d88:	e8 7b 67 00 00       	call   140009508 <strncmp>
   140002d8d:	85 c0                	test   eax,eax
   140002d8f:	75 06                	jne    140002d97 <_FindPESectionByName+0xa2>
   140002d91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d95:	eb 1e                	jmp    140002db5 <_FindPESectionByName+0xc0>
   140002d97:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d9b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002da0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002da4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002da8:	0f b7 c0             	movzx  eax,ax
   140002dab:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002dae:	72 c7                	jb     140002d77 <_FindPESectionByName+0x82>
   140002db0:	b8 00 00 00 00       	mov    eax,0x0
   140002db5:	48 83 c4 40          	add    rsp,0x40
   140002db9:	5d                   	pop    rbp
   140002dba:	c3                   	ret

0000000140002dbb <__mingw_GetSectionForAddress>:
   140002dbb:	55                   	push   rbp
   140002dbc:	48 89 e5             	mov    rbp,rsp
   140002dbf:	48 83 ec 30          	sub    rsp,0x30
   140002dc3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002dc7:	48 8b 05 b2 87 00 00 	mov    rax,QWORD PTR [rip+0x87b2]        # 14000b580 <.refptr.__ImageBase>
   140002dce:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002dd2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dd6:	48 89 c1             	mov    rcx,rax
   140002dd9:	e8 02 fe ff ff       	call   140002be0 <_ValidateImageBase>
   140002dde:	85 c0                	test   eax,eax
   140002de0:	75 07                	jne    140002de9 <__mingw_GetSectionForAddress+0x2e>
   140002de2:	b8 00 00 00 00       	mov    eax,0x0
   140002de7:	eb 1c                	jmp    140002e05 <__mingw_GetSectionForAddress+0x4a>
   140002de9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ded:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002df1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002df5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002df9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dfd:	48 89 c1             	mov    rcx,rax
   140002e00:	e8 57 fe ff ff       	call   140002c5c <_FindPESection>
   140002e05:	48 83 c4 30          	add    rsp,0x30
   140002e09:	5d                   	pop    rbp
   140002e0a:	c3                   	ret

0000000140002e0b <__mingw_GetSectionCount>:
   140002e0b:	55                   	push   rbp
   140002e0c:	48 89 e5             	mov    rbp,rsp
   140002e0f:	48 83 ec 30          	sub    rsp,0x30
   140002e13:	48 8b 05 66 87 00 00 	mov    rax,QWORD PTR [rip+0x8766]        # 14000b580 <.refptr.__ImageBase>
   140002e1a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e1e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e22:	48 89 c1             	mov    rcx,rax
   140002e25:	e8 b6 fd ff ff       	call   140002be0 <_ValidateImageBase>
   140002e2a:	85 c0                	test   eax,eax
   140002e2c:	75 07                	jne    140002e35 <__mingw_GetSectionCount+0x2a>
   140002e2e:	b8 00 00 00 00       	mov    eax,0x0
   140002e33:	eb 20                	jmp    140002e55 <__mingw_GetSectionCount+0x4a>
   140002e35:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e39:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e3c:	48 63 d0             	movsxd rdx,eax
   140002e3f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e43:	48 01 d0             	add    rax,rdx
   140002e46:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e4a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e4e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e52:	0f b7 c0             	movzx  eax,ax
   140002e55:	48 83 c4 30          	add    rsp,0x30
   140002e59:	5d                   	pop    rbp
   140002e5a:	c3                   	ret

0000000140002e5b <_FindPESectionExec>:
   140002e5b:	55                   	push   rbp
   140002e5c:	48 89 e5             	mov    rbp,rsp
   140002e5f:	48 83 ec 40          	sub    rsp,0x40
   140002e63:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e67:	48 8b 05 12 87 00 00 	mov    rax,QWORD PTR [rip+0x8712]        # 14000b580 <.refptr.__ImageBase>
   140002e6e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e72:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e76:	48 89 c1             	mov    rcx,rax
   140002e79:	e8 62 fd ff ff       	call   140002be0 <_ValidateImageBase>
   140002e7e:	85 c0                	test   eax,eax
   140002e80:	75 07                	jne    140002e89 <_FindPESectionExec+0x2e>
   140002e82:	b8 00 00 00 00       	mov    eax,0x0
   140002e87:	eb 78                	jmp    140002f01 <_FindPESectionExec+0xa6>
   140002e89:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e8d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e90:	48 63 d0             	movsxd rdx,eax
   140002e93:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e97:	48 01 d0             	add    rax,rdx
   140002e9a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e9e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ea5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ea9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002ead:	0f b7 d0             	movzx  edx,ax
   140002eb0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002eb4:	48 01 d0             	add    rax,rdx
   140002eb7:	48 83 c0 18          	add    rax,0x18
   140002ebb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ebf:	eb 2b                	jmp    140002eec <_FindPESectionExec+0x91>
   140002ec1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ec5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002ec8:	25 00 00 00 20       	and    eax,0x20000000
   140002ecd:	85 c0                	test   eax,eax
   140002ecf:	74 12                	je     140002ee3 <_FindPESectionExec+0x88>
   140002ed1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002ed6:	75 06                	jne    140002ede <_FindPESectionExec+0x83>
   140002ed8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002edc:	eb 23                	jmp    140002f01 <_FindPESectionExec+0xa6>
   140002ede:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002ee3:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002ee7:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002eec:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ef0:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ef4:	0f b7 c0             	movzx  eax,ax
   140002ef7:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002efa:	72 c5                	jb     140002ec1 <_FindPESectionExec+0x66>
   140002efc:	b8 00 00 00 00       	mov    eax,0x0
   140002f01:	48 83 c4 40          	add    rsp,0x40
   140002f05:	5d                   	pop    rbp
   140002f06:	c3                   	ret

0000000140002f07 <_GetPEImageBase>:
   140002f07:	55                   	push   rbp
   140002f08:	48 89 e5             	mov    rbp,rsp
   140002f0b:	48 83 ec 30          	sub    rsp,0x30
   140002f0f:	48 8b 05 6a 86 00 00 	mov    rax,QWORD PTR [rip+0x866a]        # 14000b580 <.refptr.__ImageBase>
   140002f16:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f1a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f1e:	48 89 c1             	mov    rcx,rax
   140002f21:	e8 ba fc ff ff       	call   140002be0 <_ValidateImageBase>
   140002f26:	85 c0                	test   eax,eax
   140002f28:	75 07                	jne    140002f31 <_GetPEImageBase+0x2a>
   140002f2a:	b8 00 00 00 00       	mov    eax,0x0
   140002f2f:	eb 04                	jmp    140002f35 <_GetPEImageBase+0x2e>
   140002f31:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f35:	48 83 c4 30          	add    rsp,0x30
   140002f39:	5d                   	pop    rbp
   140002f3a:	c3                   	ret

0000000140002f3b <_IsNonwritableInCurrentImage>:
   140002f3b:	55                   	push   rbp
   140002f3c:	48 89 e5             	mov    rbp,rsp
   140002f3f:	48 83 ec 40          	sub    rsp,0x40
   140002f43:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f47:	48 8b 05 32 86 00 00 	mov    rax,QWORD PTR [rip+0x8632]        # 14000b580 <.refptr.__ImageBase>
   140002f4e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f56:	48 89 c1             	mov    rcx,rax
   140002f59:	e8 82 fc ff ff       	call   140002be0 <_ValidateImageBase>
   140002f5e:	85 c0                	test   eax,eax
   140002f60:	75 07                	jne    140002f69 <_IsNonwritableInCurrentImage+0x2e>
   140002f62:	b8 00 00 00 00       	mov    eax,0x0
   140002f67:	eb 3d                	jmp    140002fa6 <_IsNonwritableInCurrentImage+0x6b>
   140002f69:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f6d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002f71:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f75:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002f79:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f7d:	48 89 c1             	mov    rcx,rax
   140002f80:	e8 d7 fc ff ff       	call   140002c5c <_FindPESection>
   140002f85:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f89:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002f8e:	75 07                	jne    140002f97 <_IsNonwritableInCurrentImage+0x5c>
   140002f90:	b8 00 00 00 00       	mov    eax,0x0
   140002f95:	eb 0f                	jmp    140002fa6 <_IsNonwritableInCurrentImage+0x6b>
   140002f97:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f9b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f9e:	f7 d0                	not    eax
   140002fa0:	c1 e8 1f             	shr    eax,0x1f
   140002fa3:	0f b6 c0             	movzx  eax,al
   140002fa6:	48 83 c4 40          	add    rsp,0x40
   140002faa:	5d                   	pop    rbp
   140002fab:	c3                   	ret

0000000140002fac <__mingw_enum_import_library_names>:
   140002fac:	55                   	push   rbp
   140002fad:	48 89 e5             	mov    rbp,rsp
   140002fb0:	48 83 ec 50          	sub    rsp,0x50
   140002fb4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002fb7:	48 8b 05 c2 85 00 00 	mov    rax,QWORD PTR [rip+0x85c2]        # 14000b580 <.refptr.__ImageBase>
   140002fbe:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fc2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fc6:	48 89 c1             	mov    rcx,rax
   140002fc9:	e8 12 fc ff ff       	call   140002be0 <_ValidateImageBase>
   140002fce:	85 c0                	test   eax,eax
   140002fd0:	75 0a                	jne    140002fdc <__mingw_enum_import_library_names+0x30>
   140002fd2:	b8 00 00 00 00       	mov    eax,0x0
   140002fd7:	e9 ab 00 00 00       	jmp    140003087 <__mingw_enum_import_library_names+0xdb>
   140002fdc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fe0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002fe3:	48 63 d0             	movsxd rdx,eax
   140002fe6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fea:	48 01 d0             	add    rax,rdx
   140002fed:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ff1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ff5:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   140002ffb:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140002ffe:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003002:	75 07                	jne    14000300b <__mingw_enum_import_library_names+0x5f>
   140003004:	b8 00 00 00 00       	mov    eax,0x0
   140003009:	eb 7c                	jmp    140003087 <__mingw_enum_import_library_names+0xdb>
   14000300b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000300e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003012:	48 89 c1             	mov    rcx,rax
   140003015:	e8 42 fc ff ff       	call   140002c5c <_FindPESection>
   14000301a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000301e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003023:	75 07                	jne    14000302c <__mingw_enum_import_library_names+0x80>
   140003025:	b8 00 00 00 00       	mov    eax,0x0
   14000302a:	eb 5b                	jmp    140003087 <__mingw_enum_import_library_names+0xdb>
   14000302c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000302f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003033:	48 01 d0             	add    rax,rdx
   140003036:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000303a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000303f:	75 07                	jne    140003048 <__mingw_enum_import_library_names+0x9c>
   140003041:	b8 00 00 00 00       	mov    eax,0x0
   140003046:	eb 3f                	jmp    140003087 <__mingw_enum_import_library_names+0xdb>
   140003048:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000304c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000304f:	85 c0                	test   eax,eax
   140003051:	75 0b                	jne    14000305e <__mingw_enum_import_library_names+0xb2>
   140003053:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003057:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000305a:	85 c0                	test   eax,eax
   14000305c:	74 23                	je     140003081 <__mingw_enum_import_library_names+0xd5>
   14000305e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003062:	7f 12                	jg     140003076 <__mingw_enum_import_library_names+0xca>
   140003064:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003068:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000306b:	89 c2                	mov    edx,eax
   14000306d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003071:	48 01 d0             	add    rax,rdx
   140003074:	eb 11                	jmp    140003087 <__mingw_enum_import_library_names+0xdb>
   140003076:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000307a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000307f:	eb c7                	jmp    140003048 <__mingw_enum_import_library_names+0x9c>
   140003081:	90                   	nop
   140003082:	b8 00 00 00 00       	mov    eax,0x0
   140003087:	48 83 c4 50          	add    rsp,0x50
   14000308b:	5d                   	pop    rbp
   14000308c:	c3                   	ret
   14000308d:	90                   	nop
   14000308e:	90                   	nop
   14000308f:	90                   	nop

0000000140003090 <___chkstk_ms>:
   140003090:	51                   	push   rcx
   140003091:	50                   	push   rax
   140003092:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003098:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000309d:	72 19                	jb     1400030b8 <___chkstk_ms+0x28>
   14000309f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400030a6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030aa:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400030b0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030b6:	77 e7                	ja     14000309f <___chkstk_ms+0xf>
   1400030b8:	48 29 c1             	sub    rcx,rax
   1400030bb:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030bf:	58                   	pop    rax
   1400030c0:	59                   	pop    rcx
   1400030c1:	c3                   	ret
   1400030c2:	90                   	nop
   1400030c3:	90                   	nop
   1400030c4:	90                   	nop
   1400030c5:	90                   	nop
   1400030c6:	90                   	nop
   1400030c7:	90                   	nop
   1400030c8:	90                   	nop
   1400030c9:	90                   	nop
   1400030ca:	90                   	nop
   1400030cb:	90                   	nop
   1400030cc:	90                   	nop
   1400030cd:	90                   	nop
   1400030ce:	90                   	nop
   1400030cf:	90                   	nop

00000001400030d0 <__mingw_sprintf>:
   1400030d0:	55                   	push   rbp
   1400030d1:	53                   	push   rbx
   1400030d2:	48 83 ec 48          	sub    rsp,0x48
   1400030d6:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   1400030db:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400030df:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400030e3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400030e7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   1400030eb:	48 8d 45 30          	lea    rax,[rbp+0x30]
   1400030ef:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030f3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400030f7:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400030fb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400030ff:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003104:	49 89 c9             	mov    r9,rcx
   140003107:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000310d:	48 89 c2             	mov    rdx,rax
   140003110:	b9 00 40 00 00       	mov    ecx,0x4000
   140003115:	e8 b9 1f 00 00       	call   1400050d3 <__mingw_pformat>
   14000311a:	89 c3                	mov    ebx,eax
   14000311c:	48 63 d3             	movsxd rdx,ebx
   14000311f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003123:	48 01 d0             	add    rax,rdx
   140003126:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140003129:	89 d8                	mov    eax,ebx
   14000312b:	48 83 c4 48          	add    rsp,0x48
   14000312f:	5b                   	pop    rbx
   140003130:	5d                   	pop    rbp
   140003131:	c3                   	ret
   140003132:	90                   	nop
   140003133:	90                   	nop
   140003134:	90                   	nop
   140003135:	90                   	nop
   140003136:	90                   	nop
   140003137:	90                   	nop
   140003138:	90                   	nop
   140003139:	90                   	nop
   14000313a:	90                   	nop
   14000313b:	90                   	nop
   14000313c:	90                   	nop
   14000313d:	90                   	nop
   14000313e:	90                   	nop
   14000313f:	90                   	nop

0000000140003140 <__pformat_putc>:
   140003140:	55                   	push   rbp
   140003141:	48 89 e5             	mov    rbp,rsp
   140003144:	48 83 ec 20          	sub    rsp,0x20
   140003148:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000314b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000314f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003153:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003156:	25 00 40 00 00       	and    eax,0x4000
   14000315b:	85 c0                	test   eax,eax
   14000315d:	75 12                	jne    140003171 <__pformat_putc+0x31>
   14000315f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003163:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   140003166:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000316a:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000316d:	39 c2                	cmp    edx,eax
   14000316f:	7e 3b                	jle    1400031ac <__pformat_putc+0x6c>
   140003171:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003175:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003178:	25 00 20 00 00       	and    eax,0x2000
   14000317d:	85 c0                	test   eax,eax
   14000317f:	74 13                	je     140003194 <__pformat_putc+0x54>
   140003181:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003185:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003188:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000318b:	89 c1                	mov    ecx,eax
   14000318d:	e8 26 63 00 00       	call   1400094b8 <fputc>
   140003192:	eb 18                	jmp    1400031ac <__pformat_putc+0x6c>
   140003194:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003198:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   14000319b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000319f:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031a2:	48 98                	cdqe
   1400031a4:	48 01 d0             	add    rax,rdx
   1400031a7:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400031aa:	88 10                	mov    BYTE PTR [rax],dl
   1400031ac:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031b0:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031b3:	8d 50 01             	lea    edx,[rax+0x1]
   1400031b6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031ba:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   1400031bd:	90                   	nop
   1400031be:	48 83 c4 20          	add    rsp,0x20
   1400031c2:	5d                   	pop    rbp
   1400031c3:	c3                   	ret

00000001400031c4 <__pformat_putchars>:
   1400031c4:	55                   	push   rbp
   1400031c5:	48 89 e5             	mov    rbp,rsp
   1400031c8:	48 83 ec 20          	sub    rsp,0x20
   1400031cc:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400031d0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400031d3:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400031d7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400031db:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400031de:	85 c0                	test   eax,eax
   1400031e0:	78 16                	js     1400031f8 <__pformat_putchars+0x34>
   1400031e2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400031e6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400031e9:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400031ec:	7e 0a                	jle    1400031f8 <__pformat_putchars+0x34>
   1400031ee:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400031f2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400031f5:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400031f8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400031fc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400031ff:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003202:	7d 15                	jge    140003219 <__pformat_putchars+0x55>
   140003204:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003208:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000320b:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000320e:	89 c2                	mov    edx,eax
   140003210:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003214:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003217:	eb 0b                	jmp    140003224 <__pformat_putchars+0x60>
   140003219:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000321d:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003224:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003228:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000322b:	85 c0                	test   eax,eax
   14000322d:	7e 57                	jle    140003286 <__pformat_putchars+0xc2>
   14000322f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003233:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003236:	25 00 04 00 00       	and    eax,0x400
   14000323b:	85 c0                	test   eax,eax
   14000323d:	75 47                	jne    140003286 <__pformat_putchars+0xc2>
   14000323f:	eb 11                	jmp    140003252 <__pformat_putchars+0x8e>
   140003241:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003245:	48 89 c2             	mov    rdx,rax
   140003248:	b9 20 00 00 00       	mov    ecx,0x20
   14000324d:	e8 ee fe ff ff       	call   140003140 <__pformat_putc>
   140003252:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003256:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003259:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000325c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003260:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003263:	85 c0                	test   eax,eax
   140003265:	75 da                	jne    140003241 <__pformat_putchars+0x7d>
   140003267:	eb 1d                	jmp    140003286 <__pformat_putchars+0xc2>
   140003269:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000326d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003271:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003275:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003278:	0f be c0             	movsx  eax,al
   14000327b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000327f:	89 c1                	mov    ecx,eax
   140003281:	e8 ba fe ff ff       	call   140003140 <__pformat_putc>
   140003286:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003289:	8d 50 ff             	lea    edx,[rax-0x1]
   14000328c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000328f:	85 c0                	test   eax,eax
   140003291:	75 d6                	jne    140003269 <__pformat_putchars+0xa5>
   140003293:	eb 11                	jmp    1400032a6 <__pformat_putchars+0xe2>
   140003295:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003299:	48 89 c2             	mov    rdx,rax
   14000329c:	b9 20 00 00 00       	mov    ecx,0x20
   1400032a1:	e8 9a fe ff ff       	call   140003140 <__pformat_putc>
   1400032a6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032aa:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032ad:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400032b0:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400032b4:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400032b7:	85 c0                	test   eax,eax
   1400032b9:	7f da                	jg     140003295 <__pformat_putchars+0xd1>
   1400032bb:	90                   	nop
   1400032bc:	90                   	nop
   1400032bd:	48 83 c4 20          	add    rsp,0x20
   1400032c1:	5d                   	pop    rbp
   1400032c2:	c3                   	ret

00000001400032c3 <__pformat_puts>:
   1400032c3:	55                   	push   rbp
   1400032c4:	48 89 e5             	mov    rbp,rsp
   1400032c7:	48 83 ec 20          	sub    rsp,0x20
   1400032cb:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400032cf:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400032d3:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400032d8:	75 0b                	jne    1400032e5 <__pformat_puts+0x22>
   1400032da:	48 8d 05 4f 80 00 00 	lea    rax,[rip+0x804f]        # 14000b330 <.rdata>
   1400032e1:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400032e5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032e9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032ec:	85 c0                	test   eax,eax
   1400032ee:	78 2f                	js     14000331f <__pformat_puts+0x5c>
   1400032f0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032f4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032f7:	48 63 d0             	movsxd rdx,eax
   1400032fa:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400032fe:	48 89 c1             	mov    rcx,rax
   140003301:	e8 4a 5a 00 00       	call   140008d50 <strnlen>
   140003306:	89 c1                	mov    ecx,eax
   140003308:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000330c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003310:	49 89 d0             	mov    r8,rdx
   140003313:	89 ca                	mov    edx,ecx
   140003315:	48 89 c1             	mov    rcx,rax
   140003318:	e8 a7 fe ff ff       	call   1400031c4 <__pformat_putchars>
   14000331d:	eb 23                	jmp    140003342 <__pformat_puts+0x7f>
   14000331f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003323:	48 89 c1             	mov    rcx,rax
   140003326:	e8 d5 61 00 00       	call   140009500 <strlen>
   14000332b:	89 c1                	mov    ecx,eax
   14000332d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003331:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003335:	49 89 d0             	mov    r8,rdx
   140003338:	89 ca                	mov    edx,ecx
   14000333a:	48 89 c1             	mov    rcx,rax
   14000333d:	e8 82 fe ff ff       	call   1400031c4 <__pformat_putchars>
   140003342:	90                   	nop
   140003343:	48 83 c4 20          	add    rsp,0x20
   140003347:	5d                   	pop    rbp
   140003348:	c3                   	ret

0000000140003349 <__pformat_wputchars>:
   140003349:	55                   	push   rbp
   14000334a:	48 89 e5             	mov    rbp,rsp
   14000334d:	48 83 ec 50          	sub    rsp,0x50
   140003351:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003355:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003358:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000335c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   140003363:	00 
   140003364:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003368:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000336b:	85 c0                	test   eax,eax
   14000336d:	78 16                	js     140003385 <__pformat_wputchars+0x3c>
   14000336f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003373:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003376:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003379:	7e 0a                	jle    140003385 <__pformat_wputchars+0x3c>
   14000337b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000337f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003382:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003385:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003389:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000338c:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000338f:	7d 15                	jge    1400033a6 <__pformat_wputchars+0x5d>
   140003391:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003395:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003398:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000339b:	89 c2                	mov    edx,eax
   14000339d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033a1:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400033a4:	eb 0b                	jmp    1400033b1 <__pformat_wputchars+0x68>
   1400033a6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033aa:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400033b1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033b5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033b8:	85 c0                	test   eax,eax
   1400033ba:	7e 6e                	jle    14000342a <__pformat_wputchars+0xe1>
   1400033bc:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033c0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400033c3:	25 00 04 00 00       	and    eax,0x400
   1400033c8:	85 c0                	test   eax,eax
   1400033ca:	75 5e                	jne    14000342a <__pformat_wputchars+0xe1>
   1400033cc:	eb 11                	jmp    1400033df <__pformat_wputchars+0x96>
   1400033ce:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033d2:	48 89 c2             	mov    rdx,rax
   1400033d5:	b9 20 00 00 00       	mov    ecx,0x20
   1400033da:	e8 61 fd ff ff       	call   140003140 <__pformat_putc>
   1400033df:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033e3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033e6:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400033e9:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400033ed:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400033f0:	85 c0                	test   eax,eax
   1400033f2:	75 da                	jne    1400033ce <__pformat_wputchars+0x85>
   1400033f4:	eb 34                	jmp    14000342a <__pformat_wputchars+0xe1>
   1400033f6:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400033fa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400033fe:	eb 1d                	jmp    14000341d <__pformat_wputchars+0xd4>
   140003400:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003404:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003408:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000340c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000340f:	0f be c0             	movsx  eax,al
   140003412:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003416:	89 c1                	mov    ecx,eax
   140003418:	e8 23 fd ff ff       	call   140003140 <__pformat_putc>
   14000341d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003420:	8d 50 ff             	lea    edx,[rax-0x1]
   140003423:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003426:	85 c0                	test   eax,eax
   140003428:	7f d6                	jg     140003400 <__pformat_wputchars+0xb7>
   14000342a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000342d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003430:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003433:	85 c0                	test   eax,eax
   140003435:	7e 41                	jle    140003478 <__pformat_wputchars+0x12f>
   140003437:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000343b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000343f:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003443:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140003446:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   14000344a:	0f b7 d0             	movzx  edx,ax
   14000344d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003451:	49 89 c8             	mov    r8,rcx
   140003454:	48 89 c1             	mov    rcx,rax
   140003457:	e8 64 5a 00 00       	call   140008ec0 <wcrtomb>
   14000345c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000345f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003463:	7f 91                	jg     1400033f6 <__pformat_wputchars+0xad>
   140003465:	eb 11                	jmp    140003478 <__pformat_wputchars+0x12f>
   140003467:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000346b:	48 89 c2             	mov    rdx,rax
   14000346e:	b9 20 00 00 00       	mov    ecx,0x20
   140003473:	e8 c8 fc ff ff       	call   140003140 <__pformat_putc>
   140003478:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000347c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000347f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003482:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003486:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003489:	85 c0                	test   eax,eax
   14000348b:	7f da                	jg     140003467 <__pformat_wputchars+0x11e>
   14000348d:	90                   	nop
   14000348e:	90                   	nop
   14000348f:	48 83 c4 50          	add    rsp,0x50
   140003493:	5d                   	pop    rbp
   140003494:	c3                   	ret

0000000140003495 <__pformat_wcputs>:
   140003495:	55                   	push   rbp
   140003496:	48 89 e5             	mov    rbp,rsp
   140003499:	48 83 ec 20          	sub    rsp,0x20
   14000349d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400034a1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400034a5:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400034aa:	75 0b                	jne    1400034b7 <__pformat_wcputs+0x22>
   1400034ac:	48 8d 05 85 7e 00 00 	lea    rax,[rip+0x7e85]        # 14000b338 <.rdata+0x8>
   1400034b3:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400034b7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400034bb:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400034be:	85 c0                	test   eax,eax
   1400034c0:	78 2f                	js     1400034f1 <__pformat_wcputs+0x5c>
   1400034c2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400034c6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400034c9:	48 63 d0             	movsxd rdx,eax
   1400034cc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400034d0:	48 89 c1             	mov    rcx,rax
   1400034d3:	e8 28 58 00 00       	call   140008d00 <wcsnlen>
   1400034d8:	89 c1                	mov    ecx,eax
   1400034da:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400034de:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400034e2:	49 89 d0             	mov    r8,rdx
   1400034e5:	89 ca                	mov    edx,ecx
   1400034e7:	48 89 c1             	mov    rcx,rax
   1400034ea:	e8 5a fe ff ff       	call   140003349 <__pformat_wputchars>
   1400034ef:	eb 23                	jmp    140003514 <__pformat_wcputs+0x7f>
   1400034f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400034f5:	48 89 c1             	mov    rcx,rax
   1400034f8:	e8 1b 60 00 00       	call   140009518 <wcslen>
   1400034fd:	89 c1                	mov    ecx,eax
   1400034ff:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003503:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003507:	49 89 d0             	mov    r8,rdx
   14000350a:	89 ca                	mov    edx,ecx
   14000350c:	48 89 c1             	mov    rcx,rax
   14000350f:	e8 35 fe ff ff       	call   140003349 <__pformat_wputchars>
   140003514:	90                   	nop
   140003515:	48 83 c4 20          	add    rsp,0x20
   140003519:	5d                   	pop    rbp
   14000351a:	c3                   	ret

000000014000351b <__pformat_int_bufsiz>:
   14000351b:	55                   	push   rbp
   14000351c:	48 89 e5             	mov    rbp,rsp
   14000351f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003522:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003525:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003529:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000352c:	83 e8 01             	sub    eax,0x1
   14000352f:	48 98                	cdqe
   140003531:	48 83 c0 40          	add    rax,0x40
   140003535:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140003538:	48 63 ca             	movsxd rcx,edx
   14000353b:	ba 00 00 00 00       	mov    edx,0x0
   140003540:	48 f7 f1             	div    rcx
   140003543:	89 c2                	mov    edx,eax
   140003545:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140003548:	01 d0                	add    eax,edx
   14000354a:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   14000354d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003551:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003554:	ba 00 00 00 00       	mov    edx,0x0
   140003559:	85 c0                	test   eax,eax
   14000355b:	0f 48 c2             	cmovs  eax,edx
   14000355e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   140003561:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003565:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003568:	25 00 10 00 00       	and    eax,0x1000
   14000356d:	85 c0                	test   eax,eax
   14000356f:	74 29                	je     14000359a <__pformat_int_bufsiz+0x7f>
   140003571:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003575:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003579:	66 85 c0             	test   ax,ax
   14000357c:	74 1c                	je     14000359a <__pformat_int_bufsiz+0x7f>
   14000357e:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003581:	48 63 d0             	movsxd rdx,eax
   140003584:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   14000358b:	48 89 d1             	mov    rcx,rdx
   14000358e:	48 c1 e9 20          	shr    rcx,0x20
   140003592:	99                   	cdq
   140003593:	89 c8                	mov    eax,ecx
   140003595:	29 d0                	sub    eax,edx
   140003597:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   14000359a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000359e:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400035a1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035a4:	39 c2                	cmp    edx,eax
   1400035a6:	0f 4d c2             	cmovge eax,edx
   1400035a9:	5d                   	pop    rbp
   1400035aa:	c3                   	ret

00000001400035ab <__pformat_int>:
   1400035ab:	55                   	push   rbp
   1400035ac:	53                   	push   rbx
   1400035ad:	48 83 ec 58          	sub    rsp,0x58
   1400035b1:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400035b6:	48 89 cb             	mov    rbx,rcx
   1400035b9:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   1400035bc:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   1400035c0:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   1400035c4:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   1400035c8:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400035cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400035d0:	49 89 c0             	mov    r8,rax
   1400035d3:	ba 03 00 00 00       	mov    edx,0x3
   1400035d8:	b9 01 00 00 00       	mov    ecx,0x1
   1400035dd:	e8 39 ff ff ff       	call   14000351b <__pformat_int_bufsiz>
   1400035e2:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400035e5:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   1400035ec:	00 
   1400035ed:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400035f0:	48 98                	cdqe
   1400035f2:	48 83 c0 0f          	add    rax,0xf
   1400035f6:	48 c1 e8 04          	shr    rax,0x4
   1400035fa:	48 c1 e0 04          	shl    rax,0x4
   1400035fe:	e8 8d fa ff ff       	call   140003090 <___chkstk_ms>
   140003603:	48 29 c4             	sub    rsp,rax
   140003606:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000360b:	48 83 c0 0f          	add    rax,0xf
   14000360f:	48 c1 e8 04          	shr    rax,0x4
   140003613:	48 c1 e0 04          	shl    rax,0x4
   140003617:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000361b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000361f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003623:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003627:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000362a:	25 80 00 00 00       	and    eax,0x80
   14000362f:	85 c0                	test   eax,eax
   140003631:	0f 84 ea 00 00 00    	je     140003721 <__pformat_int+0x176>
   140003637:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000363b:	48 85 c0             	test   rax,rax
   14000363e:	79 10                	jns    140003650 <__pformat_int+0xa5>
   140003640:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003644:	48 f7 d8             	neg    rax
   140003647:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000364b:	e9 d1 00 00 00       	jmp    140003721 <__pformat_int+0x176>
   140003650:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003654:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003657:	24 7f                	and    al,0x7f
   140003659:	89 c2                	mov    edx,eax
   14000365b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000365f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003662:	e9 ba 00 00 00       	jmp    140003721 <__pformat_int+0x176>
   140003667:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000366b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000366f:	74 54                	je     1400036c5 <__pformat_int+0x11a>
   140003671:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003675:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003678:	25 00 10 00 00       	and    eax,0x1000
   14000367d:	85 c0                	test   eax,eax
   14000367f:	74 44                	je     1400036c5 <__pformat_int+0x11a>
   140003681:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003685:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003689:	66 85 c0             	test   ax,ax
   14000368c:	74 37                	je     1400036c5 <__pformat_int+0x11a>
   14000368e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003692:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   140003696:	48 89 c2             	mov    rdx,rax
   140003699:	48 89 d0             	mov    rax,rdx
   14000369c:	48 c1 f8 3f          	sar    rax,0x3f
   1400036a0:	48 c1 e8 3e          	shr    rax,0x3e
   1400036a4:	48 01 c2             	add    rdx,rax
   1400036a7:	83 e2 03             	and    edx,0x3
   1400036aa:	48 29 c2             	sub    rdx,rax
   1400036ad:	48 89 d0             	mov    rax,rdx
   1400036b0:	48 83 f8 03          	cmp    rax,0x3
   1400036b4:	75 0f                	jne    1400036c5 <__pformat_int+0x11a>
   1400036b6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036ba:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400036be:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400036c2:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   1400036c5:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   1400036c9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400036d0:	cc cc cc 
   1400036d3:	48 89 c8             	mov    rax,rcx
   1400036d6:	48 f7 e2             	mul    rdx
   1400036d9:	48 c1 ea 03          	shr    rdx,0x3
   1400036dd:	48 89 d0             	mov    rax,rdx
   1400036e0:	48 c1 e0 02          	shl    rax,0x2
   1400036e4:	48 01 d0             	add    rax,rdx
   1400036e7:	48 01 c0             	add    rax,rax
   1400036ea:	48 29 c1             	sub    rcx,rax
   1400036ed:	48 89 ca             	mov    rdx,rcx
   1400036f0:	89 d0                	mov    eax,edx
   1400036f2:	8d 48 30             	lea    ecx,[rax+0x30]
   1400036f5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036f9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400036fd:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003701:	89 ca                	mov    edx,ecx
   140003703:	88 10                	mov    BYTE PTR [rax],dl
   140003705:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003709:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003710:	cc cc cc 
   140003713:	48 f7 e2             	mul    rdx
   140003716:	48 89 d0             	mov    rax,rdx
   140003719:	48 c1 e8 03          	shr    rax,0x3
   14000371d:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140003721:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003725:	48 85 c0             	test   rax,rax
   140003728:	0f 85 39 ff ff ff    	jne    140003667 <__pformat_int+0xbc>
   14000372e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003732:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003735:	85 c0                	test   eax,eax
   140003737:	7e 3e                	jle    140003777 <__pformat_int+0x1cc>
   140003739:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000373d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003740:	89 c1                	mov    ecx,eax
   140003742:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003746:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000374a:	89 c2                	mov    edx,eax
   14000374c:	89 c8                	mov    eax,ecx
   14000374e:	29 d0                	sub    eax,edx
   140003750:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003753:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003757:	7e 1e                	jle    140003777 <__pformat_int+0x1cc>
   140003759:	eb 0f                	jmp    14000376a <__pformat_int+0x1bf>
   14000375b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000375f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003763:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003767:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000376a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000376d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003770:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   140003773:	85 c0                	test   eax,eax
   140003775:	7f e4                	jg     14000375b <__pformat_int+0x1b0>
   140003777:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000377b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000377f:	75 1a                	jne    14000379b <__pformat_int+0x1f0>
   140003781:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003785:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003788:	85 c0                	test   eax,eax
   14000378a:	74 0f                	je     14000379b <__pformat_int+0x1f0>
   14000378c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003790:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003794:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003798:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000379b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000379f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037a2:	85 c0                	test   eax,eax
   1400037a4:	0f 8e ce 00 00 00    	jle    140003878 <__pformat_int+0x2cd>
   1400037aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037ae:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037b1:	89 c1                	mov    ecx,eax
   1400037b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037b7:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400037bb:	89 c2                	mov    edx,eax
   1400037bd:	89 c8                	mov    eax,ecx
   1400037bf:	29 d0                	sub    eax,edx
   1400037c1:	89 c2                	mov    edx,eax
   1400037c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037c7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400037ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037ce:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037d1:	85 c0                	test   eax,eax
   1400037d3:	0f 8e 9f 00 00 00    	jle    140003878 <__pformat_int+0x2cd>
   1400037d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037dd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400037e0:	25 c0 01 00 00       	and    eax,0x1c0
   1400037e5:	85 c0                	test   eax,eax
   1400037e7:	74 11                	je     1400037fa <__pformat_int+0x24f>
   1400037e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037ed:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037f0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400037f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037f7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400037fa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037fe:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003801:	85 c0                	test   eax,eax
   140003803:	79 3b                	jns    140003840 <__pformat_int+0x295>
   140003805:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003809:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000380c:	25 00 06 00 00       	and    eax,0x600
   140003811:	3d 00 02 00 00       	cmp    eax,0x200
   140003816:	75 28                	jne    140003840 <__pformat_int+0x295>
   140003818:	eb 0f                	jmp    140003829 <__pformat_int+0x27e>
   14000381a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000381e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003822:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003826:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003829:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000382d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003830:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003833:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003837:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000383a:	85 c0                	test   eax,eax
   14000383c:	7f dc                	jg     14000381a <__pformat_int+0x26f>
   14000383e:	eb 38                	jmp    140003878 <__pformat_int+0x2cd>
   140003840:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003844:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003847:	25 00 04 00 00       	and    eax,0x400
   14000384c:	85 c0                	test   eax,eax
   14000384e:	75 28                	jne    140003878 <__pformat_int+0x2cd>
   140003850:	eb 11                	jmp    140003863 <__pformat_int+0x2b8>
   140003852:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003856:	48 89 c2             	mov    rdx,rax
   140003859:	b9 20 00 00 00       	mov    ecx,0x20
   14000385e:	e8 dd f8 ff ff       	call   140003140 <__pformat_putc>
   140003863:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003867:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000386a:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000386d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003871:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003874:	85 c0                	test   eax,eax
   140003876:	7f da                	jg     140003852 <__pformat_int+0x2a7>
   140003878:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000387c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000387f:	25 80 00 00 00       	and    eax,0x80
   140003884:	85 c0                	test   eax,eax
   140003886:	74 11                	je     140003899 <__pformat_int+0x2ee>
   140003888:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000388c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003890:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003894:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   140003897:	eb 5a                	jmp    1400038f3 <__pformat_int+0x348>
   140003899:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000389d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038a0:	25 00 01 00 00       	and    eax,0x100
   1400038a5:	85 c0                	test   eax,eax
   1400038a7:	74 11                	je     1400038ba <__pformat_int+0x30f>
   1400038a9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038ad:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038b1:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038b5:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400038b8:	eb 39                	jmp    1400038f3 <__pformat_int+0x348>
   1400038ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038be:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038c1:	83 e0 40             	and    eax,0x40
   1400038c4:	85 c0                	test   eax,eax
   1400038c6:	74 2b                	je     1400038f3 <__pformat_int+0x348>
   1400038c8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038cc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038d0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038d4:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400038d7:	eb 1a                	jmp    1400038f3 <__pformat_int+0x348>
   1400038d9:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   1400038de:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038e2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400038e5:	0f be c0             	movsx  eax,al
   1400038e8:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400038ec:	89 c1                	mov    ecx,eax
   1400038ee:	e8 4d f8 ff ff       	call   140003140 <__pformat_putc>
   1400038f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038f7:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   1400038fb:	72 dc                	jb     1400038d9 <__pformat_int+0x32e>
   1400038fd:	eb 11                	jmp    140003910 <__pformat_int+0x365>
   1400038ff:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003903:	48 89 c2             	mov    rdx,rax
   140003906:	b9 20 00 00 00       	mov    ecx,0x20
   14000390b:	e8 30 f8 ff ff       	call   140003140 <__pformat_putc>
   140003910:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003914:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003917:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000391a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000391e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003921:	85 c0                	test   eax,eax
   140003923:	7f da                	jg     1400038ff <__pformat_int+0x354>
   140003925:	90                   	nop
   140003926:	90                   	nop
   140003927:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   14000392b:	5b                   	pop    rbx
   14000392c:	5d                   	pop    rbp
   14000392d:	c3                   	ret

000000014000392e <__pformat_xint>:
   14000392e:	55                   	push   rbp
   14000392f:	53                   	push   rbx
   140003930:	48 83 ec 68          	sub    rsp,0x68
   140003934:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003939:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   14000393c:	48 89 d3             	mov    rbx,rdx
   14000393f:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140003942:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   140003946:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   14000394a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   14000394e:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003952:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003956:	74 1e                	je     140003976 <__pformat_xint+0x48>
   140003958:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   14000395c:	74 06                	je     140003964 <__pformat_xint+0x36>
   14000395e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003962:	75 09                	jne    14000396d <__pformat_xint+0x3f>
   140003964:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000396b:	eb 10                	jmp    14000397d <__pformat_xint+0x4f>
   14000396d:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003974:	eb 07                	jmp    14000397d <__pformat_xint+0x4f>
   140003976:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   14000397d:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003981:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003984:	49 89 d0             	mov    r8,rdx
   140003987:	89 c2                	mov    edx,eax
   140003989:	b9 02 00 00 00       	mov    ecx,0x2
   14000398e:	e8 88 fb ff ff       	call   14000351b <__pformat_int_bufsiz>
   140003993:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140003996:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   14000399d:	00 
   14000399e:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400039a1:	48 98                	cdqe
   1400039a3:	48 83 c0 0f          	add    rax,0xf
   1400039a7:	48 c1 e8 04          	shr    rax,0x4
   1400039ab:	48 c1 e0 04          	shl    rax,0x4
   1400039af:	e8 dc f6 ff ff       	call   140003090 <___chkstk_ms>
   1400039b4:	48 29 c4             	sub    rsp,rax
   1400039b7:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400039bc:	48 83 c0 0f          	add    rax,0xf
   1400039c0:	48 c1 e8 04          	shr    rax,0x4
   1400039c4:	48 c1 e0 04          	shl    rax,0x4
   1400039c8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400039cc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400039d0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400039d4:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   1400039d8:	74 1e                	je     1400039f8 <__pformat_xint+0xca>
   1400039da:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   1400039de:	74 06                	je     1400039e6 <__pformat_xint+0xb8>
   1400039e0:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   1400039e4:	75 09                	jne    1400039ef <__pformat_xint+0xc1>
   1400039e6:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   1400039ed:	eb 10                	jmp    1400039ff <__pformat_xint+0xd1>
   1400039ef:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   1400039f6:	eb 67                	jmp    140003a5f <__pformat_xint+0x131>
   1400039f8:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   1400039ff:	eb 5e                	jmp    140003a5f <__pformat_xint+0x131>
   140003a01:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003a05:	89 c2                	mov    edx,eax
   140003a07:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003a0a:	21 d0                	and    eax,edx
   140003a0c:	8d 48 30             	lea    ecx,[rax+0x30]
   140003a0f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003a13:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003a17:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003a1b:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003a1f:	89 ca                	mov    edx,ecx
   140003a21:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a25:	88 10                	mov    BYTE PTR [rax],dl
   140003a27:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a2b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a2e:	3c 39                	cmp    al,0x39
   140003a30:	7e 1a                	jle    140003a4c <__pformat_xint+0x11e>
   140003a32:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a36:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a39:	83 c0 07             	add    eax,0x7
   140003a3c:	89 c2                	mov    edx,eax
   140003a3e:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003a41:	83 e0 20             	and    eax,0x20
   140003a44:	09 c2                	or     edx,eax
   140003a46:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a4a:	88 10                	mov    BYTE PTR [rax],dl
   140003a4c:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003a50:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003a53:	89 c1                	mov    ecx,eax
   140003a55:	48 d3 ea             	shr    rdx,cl
   140003a58:	48 89 d0             	mov    rax,rdx
   140003a5b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003a5f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003a63:	48 85 c0             	test   rax,rax
   140003a66:	75 99                	jne    140003a01 <__pformat_xint+0xd3>
   140003a68:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003a6c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003a70:	75 13                	jne    140003a85 <__pformat_xint+0x157>
   140003a72:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003a76:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003a79:	80 e4 f7             	and    ah,0xf7
   140003a7c:	89 c2                	mov    edx,eax
   140003a7e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003a82:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003a85:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003a89:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003a8c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003a8f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003a93:	7e 3a                	jle    140003acf <__pformat_xint+0x1a1>
   140003a95:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003a98:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003a9c:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003aa0:	89 c1                	mov    ecx,eax
   140003aa2:	89 d0                	mov    eax,edx
   140003aa4:	29 c8                	sub    eax,ecx
   140003aa6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003aa9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003aad:	7e 20                	jle    140003acf <__pformat_xint+0x1a1>
   140003aaf:	eb 0f                	jmp    140003ac0 <__pformat_xint+0x192>
   140003ab1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ab5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ab9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003abd:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003ac0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ac3:	8d 50 ff             	lea    edx,[rax-0x1]
   140003ac6:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003ac9:	85 c0                	test   eax,eax
   140003acb:	7f e4                	jg     140003ab1 <__pformat_xint+0x183>
   140003acd:	eb 25                	jmp    140003af4 <__pformat_xint+0x1c6>
   140003acf:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003ad3:	75 1f                	jne    140003af4 <__pformat_xint+0x1c6>
   140003ad5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ad9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003adc:	25 00 08 00 00       	and    eax,0x800
   140003ae1:	85 c0                	test   eax,eax
   140003ae3:	74 0f                	je     140003af4 <__pformat_xint+0x1c6>
   140003ae5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ae9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003aed:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003af1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003af4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003af8:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003afc:	75 1a                	jne    140003b18 <__pformat_xint+0x1ea>
   140003afe:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b02:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b05:	85 c0                	test   eax,eax
   140003b07:	74 0f                	je     140003b18 <__pformat_xint+0x1ea>
   140003b09:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b0d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b11:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b15:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b18:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b1c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b1f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003b23:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003b27:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b2a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003b2d:	7d 15                	jge    140003b44 <__pformat_xint+0x216>
   140003b2f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b33:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b36:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003b39:	89 c2                	mov    edx,eax
   140003b3b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b3f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003b42:	eb 0b                	jmp    140003b4f <__pformat_xint+0x221>
   140003b44:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b48:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003b4f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b53:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b56:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b59:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b5d:	7e 1a                	jle    140003b79 <__pformat_xint+0x24b>
   140003b5f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003b63:	74 14                	je     140003b79 <__pformat_xint+0x24b>
   140003b65:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b69:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b6c:	25 00 08 00 00       	and    eax,0x800
   140003b71:	85 c0                	test   eax,eax
   140003b73:	74 04                	je     140003b79 <__pformat_xint+0x24b>
   140003b75:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003b79:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b7d:	7e 3c                	jle    140003bbb <__pformat_xint+0x28d>
   140003b7f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b83:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b86:	85 c0                	test   eax,eax
   140003b88:	79 31                	jns    140003bbb <__pformat_xint+0x28d>
   140003b8a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b8e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b91:	25 00 06 00 00       	and    eax,0x600
   140003b96:	3d 00 02 00 00       	cmp    eax,0x200
   140003b9b:	75 1e                	jne    140003bbb <__pformat_xint+0x28d>
   140003b9d:	eb 0f                	jmp    140003bae <__pformat_xint+0x280>
   140003b9f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ba3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ba7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bab:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bae:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003bb1:	8d 50 ff             	lea    edx,[rax-0x1]
   140003bb4:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bb7:	85 c0                	test   eax,eax
   140003bb9:	7f e4                	jg     140003b9f <__pformat_xint+0x271>
   140003bbb:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003bbf:	74 30                	je     140003bf1 <__pformat_xint+0x2c3>
   140003bc1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bc5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bc8:	25 00 08 00 00       	and    eax,0x800
   140003bcd:	85 c0                	test   eax,eax
   140003bcf:	74 20                	je     140003bf1 <__pformat_xint+0x2c3>
   140003bd1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bd5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bd9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bdd:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003be0:	88 10                	mov    BYTE PTR [rax],dl
   140003be2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003be6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bea:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bee:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bf1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003bf5:	7e 4c                	jle    140003c43 <__pformat_xint+0x315>
   140003bf7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bfb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bfe:	25 00 04 00 00       	and    eax,0x400
   140003c03:	85 c0                	test   eax,eax
   140003c05:	75 3c                	jne    140003c43 <__pformat_xint+0x315>
   140003c07:	eb 11                	jmp    140003c1a <__pformat_xint+0x2ec>
   140003c09:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c0d:	48 89 c2             	mov    rdx,rax
   140003c10:	b9 20 00 00 00       	mov    ecx,0x20
   140003c15:	e8 26 f5 ff ff       	call   140003140 <__pformat_putc>
   140003c1a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c1d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c20:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c23:	85 c0                	test   eax,eax
   140003c25:	7f e2                	jg     140003c09 <__pformat_xint+0x2db>
   140003c27:	eb 1a                	jmp    140003c43 <__pformat_xint+0x315>
   140003c29:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003c2e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c32:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003c35:	0f be c0             	movsx  eax,al
   140003c38:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003c3c:	89 c1                	mov    ecx,eax
   140003c3e:	e8 fd f4 ff ff       	call   140003140 <__pformat_putc>
   140003c43:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c47:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003c4b:	72 dc                	jb     140003c29 <__pformat_xint+0x2fb>
   140003c4d:	eb 11                	jmp    140003c60 <__pformat_xint+0x332>
   140003c4f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c53:	48 89 c2             	mov    rdx,rax
   140003c56:	b9 20 00 00 00       	mov    ecx,0x20
   140003c5b:	e8 e0 f4 ff ff       	call   140003140 <__pformat_putc>
   140003c60:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c63:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c66:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c69:	85 c0                	test   eax,eax
   140003c6b:	7f e2                	jg     140003c4f <__pformat_xint+0x321>
   140003c6d:	90                   	nop
   140003c6e:	90                   	nop
   140003c6f:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003c73:	5b                   	pop    rbx
   140003c74:	5d                   	pop    rbp
   140003c75:	c3                   	ret

0000000140003c76 <init_fpreg_ldouble>:
   140003c76:	55                   	push   rbp
   140003c77:	53                   	push   rbx
   140003c78:	48 83 ec 28          	sub    rsp,0x28
   140003c7c:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003c81:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003c85:	48 89 d3             	mov    rbx,rdx
   140003c88:	db 2b                	fld    TBYTE PTR [rbx]
   140003c8a:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003c8d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003c90:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003c93:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003c97:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c9b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003c9f:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003ca2:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003ca6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003caa:	48 83 c4 28          	add    rsp,0x28
   140003cae:	5b                   	pop    rbx
   140003caf:	5d                   	pop    rbp
   140003cb0:	c3                   	ret

0000000140003cb1 <__pformat_cvt>:
   140003cb1:	55                   	push   rbp
   140003cb2:	53                   	push   rbx
   140003cb3:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003cba:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003cc1:	00 
   140003cc2:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003cc5:	48 89 d3             	mov    rbx,rdx
   140003cc8:	db 2b                	fld    TBYTE PTR [rbx]
   140003cca:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003ccd:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003cd1:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003cd5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003cdc:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003ce0:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003ce3:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003ce6:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003cea:	48 89 c1             	mov    rcx,rax
   140003ced:	e8 84 ff ff ff       	call   140003c76 <init_fpreg_ldouble>
   140003cf2:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003cf5:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003cf8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003cfc:	48 89 c1             	mov    rcx,rax
   140003cff:	e8 9c 4e 00 00       	call   140008ba0 <__fpclassifyl>
   140003d04:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d07:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d0a:	25 00 01 00 00       	and    eax,0x100
   140003d0f:	85 c0                	test   eax,eax
   140003d11:	74 1d                	je     140003d30 <__pformat_cvt+0x7f>
   140003d13:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d16:	25 00 04 00 00       	and    eax,0x400
   140003d1b:	85 c0                	test   eax,eax
   140003d1d:	74 07                	je     140003d26 <__pformat_cvt+0x75>
   140003d1f:	b8 03 00 00 00       	mov    eax,0x3
   140003d24:	eb 05                	jmp    140003d2b <__pformat_cvt+0x7a>
   140003d26:	b8 04 00 00 00       	mov    eax,0x4
   140003d2b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d2e:	eb 4a                	jmp    140003d7a <__pformat_cvt+0xc9>
   140003d30:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d33:	25 00 04 00 00       	and    eax,0x400
   140003d38:	85 c0                	test   eax,eax
   140003d3a:	74 37                	je     140003d73 <__pformat_cvt+0xc2>
   140003d3c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d3f:	25 00 40 00 00       	and    eax,0x4000
   140003d44:	85 c0                	test   eax,eax
   140003d46:	74 10                	je     140003d58 <__pformat_cvt+0xa7>
   140003d48:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003d4f:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003d56:	eb 22                	jmp    140003d7a <__pformat_cvt+0xc9>
   140003d58:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003d5f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003d63:	98                   	cwde
   140003d64:	25 ff 7f 00 00       	and    eax,0x7fff
   140003d69:	2d 3e 40 00 00       	sub    eax,0x403e
   140003d6e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003d71:	eb 07                	jmp    140003d7a <__pformat_cvt+0xc9>
   140003d73:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003d7a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d7d:	83 f8 04             	cmp    eax,0x4
   140003d80:	74 0e                	je     140003d90 <__pformat_cvt+0xdf>
   140003d82:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003d86:	98                   	cwde
   140003d87:	25 00 80 00 00       	and    eax,0x8000
   140003d8c:	89 c2                	mov    edx,eax
   140003d8e:	eb 05                	jmp    140003d95 <__pformat_cvt+0xe4>
   140003d90:	ba 00 00 00 00       	mov    edx,0x0
   140003d95:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003d99:	89 10                	mov    DWORD PTR [rax],edx
   140003d9b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d9e:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003da2:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003da6:	48 8d 0d c3 62 00 00 	lea    rcx,[rip+0x62c3]        # 14000a070 <fpi.0>
   140003dad:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003db1:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003db6:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003dba:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003dbf:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003dc2:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003dc6:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003dc9:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003dcd:	89 c2                	mov    edx,eax
   140003dcf:	e8 96 24 00 00       	call   14000626a <__gdtoa>
   140003dd4:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003ddb:	5b                   	pop    rbx
   140003ddc:	5d                   	pop    rbp
   140003ddd:	c3                   	ret

0000000140003dde <__pformat_ecvt>:
   140003dde:	55                   	push   rbp
   140003ddf:	53                   	push   rbx
   140003de0:	48 83 ec 58          	sub    rsp,0x58
   140003de4:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003de9:	48 89 cb             	mov    rbx,rcx
   140003dec:	db 2b                	fld    TBYTE PTR [rbx]
   140003dee:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003df1:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003df4:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003df8:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003dfc:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003dff:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003e02:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003e06:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003e09:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e0d:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e11:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003e16:	4d 89 c1             	mov    r9,r8
   140003e19:	41 89 c8             	mov    r8d,ecx
   140003e1c:	48 89 c2             	mov    rdx,rax
   140003e1f:	b9 02 00 00 00       	mov    ecx,0x2
   140003e24:	e8 88 fe ff ff       	call   140003cb1 <__pformat_cvt>
   140003e29:	48 83 c4 58          	add    rsp,0x58
   140003e2d:	5b                   	pop    rbx
   140003e2e:	5d                   	pop    rbp
   140003e2f:	c3                   	ret

0000000140003e30 <__pformat_fcvt>:
   140003e30:	55                   	push   rbp
   140003e31:	53                   	push   rbx
   140003e32:	48 83 ec 58          	sub    rsp,0x58
   140003e36:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003e3b:	48 89 cb             	mov    rbx,rcx
   140003e3e:	db 2b                	fld    TBYTE PTR [rbx]
   140003e40:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003e43:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003e46:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003e4a:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003e4e:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003e51:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003e54:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003e58:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003e5b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e5f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e63:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003e68:	4d 89 c1             	mov    r9,r8
   140003e6b:	41 89 c8             	mov    r8d,ecx
   140003e6e:	48 89 c2             	mov    rdx,rax
   140003e71:	b9 03 00 00 00       	mov    ecx,0x3
   140003e76:	e8 36 fe ff ff       	call   140003cb1 <__pformat_cvt>
   140003e7b:	48 83 c4 58          	add    rsp,0x58
   140003e7f:	5b                   	pop    rbx
   140003e80:	5d                   	pop    rbp
   140003e81:	c3                   	ret

0000000140003e82 <__pformat_emit_radix_point>:
   140003e82:	55                   	push   rbp
   140003e83:	53                   	push   rbx
   140003e84:	48 83 ec 68          	sub    rsp,0x68
   140003e88:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003e8d:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003e91:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003e95:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003e98:	83 f8 fd             	cmp    eax,0xfffffffd
   140003e9b:	75 48                	jne    140003ee5 <__pformat_emit_radix_point+0x63>
   140003e9d:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003ea4:	00 
   140003ea5:	e8 1e 56 00 00       	call   1400094c8 <localeconv>
   140003eaa:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003ead:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003eb1:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003eb5:	49 89 c9             	mov    r9,rcx
   140003eb8:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003ebe:	48 89 c1             	mov    rcx,rax
   140003ec1:	e8 4a 50 00 00       	call   140008f10 <mbrtowc>
   140003ec6:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003ec9:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003ecd:	7e 0c                	jle    140003edb <__pformat_emit_radix_point+0x59>
   140003ecf:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003ed3:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003ed7:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003edb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003edf:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003ee2:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003ee5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003ee9:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003eed:	66 85 c0             	test   ax,ax
   140003ef0:	0f 84 b8 00 00 00    	je     140003fae <__pformat_emit_radix_point+0x12c>
   140003ef6:	48 89 e0             	mov    rax,rsp
   140003ef9:	48 89 c3             	mov    rbx,rax
   140003efc:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f00:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f03:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003f06:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003f09:	48 63 d0             	movsxd rdx,eax
   140003f0c:	48 83 ea 01          	sub    rdx,0x1
   140003f10:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140003f14:	48 98                	cdqe
   140003f16:	48 83 c0 0f          	add    rax,0xf
   140003f1a:	48 c1 e8 04          	shr    rax,0x4
   140003f1e:	48 c1 e0 04          	shl    rax,0x4
   140003f22:	e8 69 f1 ff ff       	call   140003090 <___chkstk_ms>
   140003f27:	48 29 c4             	sub    rsp,rax
   140003f2a:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003f2f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003f33:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   140003f3a:	00 
   140003f3b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f3f:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003f43:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140003f47:	0f b7 d0             	movzx  edx,ax
   140003f4a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003f4e:	49 89 c8             	mov    r8,rcx
   140003f51:	48 89 c1             	mov    rcx,rax
   140003f54:	e8 67 4f 00 00       	call   140008ec0 <wcrtomb>
   140003f59:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003f5c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003f60:	7e 36                	jle    140003f98 <__pformat_emit_radix_point+0x116>
   140003f62:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003f66:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003f6a:	eb 1d                	jmp    140003f89 <__pformat_emit_radix_point+0x107>
   140003f6c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003f70:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003f74:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003f78:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003f7b:	0f be c0             	movsx  eax,al
   140003f7e:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003f82:	89 c1                	mov    ecx,eax
   140003f84:	e8 b7 f1 ff ff       	call   140003140 <__pformat_putc>
   140003f89:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003f8c:	8d 50 ff             	lea    edx,[rax-0x1]
   140003f8f:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003f92:	85 c0                	test   eax,eax
   140003f94:	7f d6                	jg     140003f6c <__pformat_emit_radix_point+0xea>
   140003f96:	eb 11                	jmp    140003fa9 <__pformat_emit_radix_point+0x127>
   140003f98:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f9c:	48 89 c2             	mov    rdx,rax
   140003f9f:	b9 2e 00 00 00       	mov    ecx,0x2e
   140003fa4:	e8 97 f1 ff ff       	call   140003140 <__pformat_putc>
   140003fa9:	48 89 dc             	mov    rsp,rbx
   140003fac:	eb 11                	jmp    140003fbf <__pformat_emit_radix_point+0x13d>
   140003fae:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fb2:	48 89 c2             	mov    rdx,rax
   140003fb5:	b9 2e 00 00 00       	mov    ecx,0x2e
   140003fba:	e8 81 f1 ff ff       	call   140003140 <__pformat_putc>
   140003fbf:	90                   	nop
   140003fc0:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003fc4:	5b                   	pop    rbx
   140003fc5:	5d                   	pop    rbp
   140003fc6:	c3                   	ret

0000000140003fc7 <__pformat_emit_numeric_value>:
   140003fc7:	55                   	push   rbp
   140003fc8:	48 89 e5             	mov    rbp,rsp
   140003fcb:	48 83 ec 30          	sub    rsp,0x30
   140003fcf:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003fd2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003fd6:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   140003fda:	75 0e                	jne    140003fea <__pformat_emit_numeric_value+0x23>
   140003fdc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003fe0:	48 89 c1             	mov    rcx,rax
   140003fe3:	e8 9a fe ff ff       	call   140003e82 <__pformat_emit_radix_point>
   140003fe8:	eb 43                	jmp    14000402d <__pformat_emit_numeric_value+0x66>
   140003fea:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   140003fee:	75 2f                	jne    14000401f <__pformat_emit_numeric_value+0x58>
   140003ff0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003ff4:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003ff8:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   140003ffc:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   140004000:	66 85 c0             	test   ax,ax
   140004003:	74 28                	je     14000402d <__pformat_emit_numeric_value+0x66>
   140004005:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004009:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   14000400d:	49 89 d0             	mov    r8,rdx
   140004010:	ba 01 00 00 00       	mov    edx,0x1
   140004015:	48 89 c1             	mov    rcx,rax
   140004018:	e8 2c f3 ff ff       	call   140003349 <__pformat_wputchars>
   14000401d:	eb 0e                	jmp    14000402d <__pformat_emit_numeric_value+0x66>
   14000401f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004023:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140004026:	89 c1                	mov    ecx,eax
   140004028:	e8 13 f1 ff ff       	call   140003140 <__pformat_putc>
   14000402d:	90                   	nop
   14000402e:	48 83 c4 30          	add    rsp,0x30
   140004032:	5d                   	pop    rbp
   140004033:	c3                   	ret

0000000140004034 <__pformat_emit_inf_or_nan>:
   140004034:	55                   	push   rbp
   140004035:	48 89 e5             	mov    rbp,rsp
   140004038:	48 83 ec 40          	sub    rsp,0x40
   14000403c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000403f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004043:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140004047:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000404b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000404f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004053:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000405a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000405e:	74 11                	je     140004071 <__pformat_emit_inf_or_nan+0x3d>
   140004060:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004064:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004068:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000406c:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   14000406f:	eb 3e                	jmp    1400040af <__pformat_emit_inf_or_nan+0x7b>
   140004071:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004075:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004078:	25 00 01 00 00       	and    eax,0x100
   14000407d:	85 c0                	test   eax,eax
   14000407f:	74 11                	je     140004092 <__pformat_emit_inf_or_nan+0x5e>
   140004081:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004085:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004089:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000408d:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140004090:	eb 1d                	jmp    1400040af <__pformat_emit_inf_or_nan+0x7b>
   140004092:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004096:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004099:	83 e0 40             	and    eax,0x40
   14000409c:	85 c0                	test   eax,eax
   14000409e:	74 0f                	je     1400040af <__pformat_emit_inf_or_nan+0x7b>
   1400040a0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040a4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040a8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040ac:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400040af:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   1400040b6:	eb 38                	jmp    1400040f0 <__pformat_emit_inf_or_nan+0xbc>
   1400040b8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040bc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040c0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400040c4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400040c7:	83 e0 df             	and    eax,0xffffffdf
   1400040ca:	41 89 c0             	mov    r8d,eax
   1400040cd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040d1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400040d4:	83 e0 20             	and    eax,0x20
   1400040d7:	89 c1                	mov    ecx,eax
   1400040d9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040dd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040e1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040e5:	44 89 c2             	mov    edx,r8d
   1400040e8:	09 ca                	or     edx,ecx
   1400040ea:	88 10                	mov    BYTE PTR [rax],dl
   1400040ec:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400040f0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400040f4:	7f c2                	jg     1400040b8 <__pformat_emit_inf_or_nan+0x84>
   1400040f6:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400040fa:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400040fe:	48 29 c2             	sub    rdx,rax
   140004101:	89 d1                	mov    ecx,edx
   140004103:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004107:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000410b:	49 89 d0             	mov    r8,rdx
   14000410e:	89 ca                	mov    edx,ecx
   140004110:	48 89 c1             	mov    rcx,rax
   140004113:	e8 ac f0 ff ff       	call   1400031c4 <__pformat_putchars>
   140004118:	90                   	nop
   140004119:	48 83 c4 40          	add    rsp,0x40
   14000411d:	5d                   	pop    rbp
   14000411e:	c3                   	ret

000000014000411f <__pformat_emit_float>:
   14000411f:	55                   	push   rbp
   140004120:	48 89 e5             	mov    rbp,rsp
   140004123:	48 83 ec 30          	sub    rsp,0x30
   140004127:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000412a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000412e:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140004132:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004136:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000413a:	7e 2e                	jle    14000416a <__pformat_emit_float+0x4b>
   14000413c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004140:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004143:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   140004146:	7f 15                	jg     14000415d <__pformat_emit_float+0x3e>
   140004148:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000414c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000414f:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004152:	89 c2                	mov    edx,eax
   140004154:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004158:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000415b:	eb 29                	jmp    140004186 <__pformat_emit_float+0x67>
   14000415d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004161:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004168:	eb 1c                	jmp    140004186 <__pformat_emit_float+0x67>
   14000416a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000416e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004171:	85 c0                	test   eax,eax
   140004173:	7e 11                	jle    140004186 <__pformat_emit_float+0x67>
   140004175:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004179:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000417c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000417f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004183:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004186:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000418a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000418d:	85 c0                	test   eax,eax
   14000418f:	78 2b                	js     1400041bc <__pformat_emit_float+0x9d>
   140004191:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004195:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004198:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000419c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000419f:	39 c2                	cmp    edx,eax
   1400041a1:	7e 19                	jle    1400041bc <__pformat_emit_float+0x9d>
   1400041a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041a7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400041aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041ae:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400041b1:	29 c2                	sub    edx,eax
   1400041b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041b7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400041ba:	eb 0b                	jmp    1400041c7 <__pformat_emit_float+0xa8>
   1400041bc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041c0:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400041c7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041cb:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041ce:	85 c0                	test   eax,eax
   1400041d0:	7e 2c                	jle    1400041fe <__pformat_emit_float+0xdf>
   1400041d2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041d6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400041d9:	85 c0                	test   eax,eax
   1400041db:	7f 10                	jg     1400041ed <__pformat_emit_float+0xce>
   1400041dd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041e1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400041e4:	25 00 08 00 00       	and    eax,0x800
   1400041e9:	85 c0                	test   eax,eax
   1400041eb:	74 11                	je     1400041fe <__pformat_emit_float+0xdf>
   1400041ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041f1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041f4:	8d 50 ff             	lea    edx,[rax-0x1]
   1400041f7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041fb:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400041fe:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004202:	7e 64                	jle    140004268 <__pformat_emit_float+0x149>
   140004204:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004208:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000420b:	25 00 10 00 00       	and    eax,0x1000
   140004210:	85 c0                	test   eax,eax
   140004212:	74 54                	je     140004268 <__pformat_emit_float+0x149>
   140004214:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004218:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   14000421c:	66 85 c0             	test   ax,ax
   14000421f:	74 47                	je     140004268 <__pformat_emit_float+0x149>
   140004221:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004224:	83 c0 02             	add    eax,0x2
   140004227:	48 63 d0             	movsxd rdx,eax
   14000422a:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   140004231:	48 c1 ea 20          	shr    rdx,0x20
   140004235:	c1 f8 1f             	sar    eax,0x1f
   140004238:	29 c2                	sub    edx,eax
   14000423a:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000423d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004240:	eb 15                	jmp    140004257 <__pformat_emit_float+0x138>
   140004242:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004246:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000424a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000424d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004250:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004254:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004257:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000425b:	7e 0b                	jle    140004268 <__pformat_emit_float+0x149>
   14000425d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004261:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004264:	85 c0                	test   eax,eax
   140004266:	7f da                	jg     140004242 <__pformat_emit_float+0x123>
   140004268:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000426c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000426f:	85 c0                	test   eax,eax
   140004271:	7e 27                	jle    14000429a <__pformat_emit_float+0x17b>
   140004273:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004277:	75 10                	jne    140004289 <__pformat_emit_float+0x16a>
   140004279:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000427d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004280:	25 c0 01 00 00       	and    eax,0x1c0
   140004285:	85 c0                	test   eax,eax
   140004287:	74 11                	je     14000429a <__pformat_emit_float+0x17b>
   140004289:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000428d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004290:	8d 50 ff             	lea    edx,[rax-0x1]
   140004293:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004297:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000429a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000429e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042a1:	85 c0                	test   eax,eax
   1400042a3:	7e 38                	jle    1400042dd <__pformat_emit_float+0x1be>
   1400042a5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042ac:	25 00 06 00 00       	and    eax,0x600
   1400042b1:	85 c0                	test   eax,eax
   1400042b3:	75 28                	jne    1400042dd <__pformat_emit_float+0x1be>
   1400042b5:	eb 11                	jmp    1400042c8 <__pformat_emit_float+0x1a9>
   1400042b7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042bb:	48 89 c2             	mov    rdx,rax
   1400042be:	b9 20 00 00 00       	mov    ecx,0x20
   1400042c3:	e8 78 ee ff ff       	call   140003140 <__pformat_putc>
   1400042c8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042cc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042cf:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400042d2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400042d6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400042d9:	85 c0                	test   eax,eax
   1400042db:	7f da                	jg     1400042b7 <__pformat_emit_float+0x198>
   1400042dd:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400042e1:	74 13                	je     1400042f6 <__pformat_emit_float+0x1d7>
   1400042e3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042e7:	48 89 c2             	mov    rdx,rax
   1400042ea:	b9 2d 00 00 00       	mov    ecx,0x2d
   1400042ef:	e8 4c ee ff ff       	call   140003140 <__pformat_putc>
   1400042f4:	eb 42                	jmp    140004338 <__pformat_emit_float+0x219>
   1400042f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042fa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042fd:	25 00 01 00 00       	and    eax,0x100
   140004302:	85 c0                	test   eax,eax
   140004304:	74 13                	je     140004319 <__pformat_emit_float+0x1fa>
   140004306:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000430a:	48 89 c2             	mov    rdx,rax
   14000430d:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004312:	e8 29 ee ff ff       	call   140003140 <__pformat_putc>
   140004317:	eb 1f                	jmp    140004338 <__pformat_emit_float+0x219>
   140004319:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000431d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004320:	83 e0 40             	and    eax,0x40
   140004323:	85 c0                	test   eax,eax
   140004325:	74 11                	je     140004338 <__pformat_emit_float+0x219>
   140004327:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000432b:	48 89 c2             	mov    rdx,rax
   14000432e:	b9 20 00 00 00       	mov    ecx,0x20
   140004333:	e8 08 ee ff ff       	call   140003140 <__pformat_putc>
   140004338:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000433c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000433f:	85 c0                	test   eax,eax
   140004341:	7e 3b                	jle    14000437e <__pformat_emit_float+0x25f>
   140004343:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004347:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000434a:	25 00 06 00 00       	and    eax,0x600
   14000434f:	3d 00 02 00 00       	cmp    eax,0x200
   140004354:	75 28                	jne    14000437e <__pformat_emit_float+0x25f>
   140004356:	eb 11                	jmp    140004369 <__pformat_emit_float+0x24a>
   140004358:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000435c:	48 89 c2             	mov    rdx,rax
   14000435f:	b9 30 00 00 00       	mov    ecx,0x30
   140004364:	e8 d7 ed ff ff       	call   140003140 <__pformat_putc>
   140004369:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000436d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004370:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004373:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004377:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000437a:	85 c0                	test   eax,eax
   14000437c:	7f da                	jg     140004358 <__pformat_emit_float+0x239>
   14000437e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004382:	0f 8e a7 00 00 00    	jle    14000442f <__pformat_emit_float+0x310>
   140004388:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000438c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000438f:	84 c0                	test   al,al
   140004391:	74 14                	je     1400043a7 <__pformat_emit_float+0x288>
   140004393:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004397:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000439b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000439f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400043a2:	0f be c0             	movsx  eax,al
   1400043a5:	eb 05                	jmp    1400043ac <__pformat_emit_float+0x28d>
   1400043a7:	b8 30 00 00 00       	mov    eax,0x30
   1400043ac:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400043b0:	89 c1                	mov    ecx,eax
   1400043b2:	e8 89 ed ff ff       	call   140003140 <__pformat_putc>
   1400043b7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400043bb:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400043bf:	74 62                	je     140004423 <__pformat_emit_float+0x304>
   1400043c1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043c5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043c8:	25 00 10 00 00       	and    eax,0x1000
   1400043cd:	85 c0                	test   eax,eax
   1400043cf:	74 52                	je     140004423 <__pformat_emit_float+0x304>
   1400043d1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043d5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400043d9:	66 85 c0             	test   ax,ax
   1400043dc:	74 45                	je     140004423 <__pformat_emit_float+0x304>
   1400043de:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   1400043e1:	48 63 c1             	movsxd rax,ecx
   1400043e4:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   1400043eb:	48 c1 e8 20          	shr    rax,0x20
   1400043ef:	48 89 c2             	mov    rdx,rax
   1400043f2:	89 c8                	mov    eax,ecx
   1400043f4:	c1 f8 1f             	sar    eax,0x1f
   1400043f7:	29 c2                	sub    edx,eax
   1400043f9:	89 d0                	mov    eax,edx
   1400043fb:	01 c0                	add    eax,eax
   1400043fd:	01 d0                	add    eax,edx
   1400043ff:	29 c1                	sub    ecx,eax
   140004401:	89 ca                	mov    edx,ecx
   140004403:	85 d2                	test   edx,edx
   140004405:	75 1c                	jne    140004423 <__pformat_emit_float+0x304>
   140004407:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000440b:	48 83 c0 20          	add    rax,0x20
   14000440f:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004413:	49 89 d0             	mov    r8,rdx
   140004416:	ba 01 00 00 00       	mov    edx,0x1
   14000441b:	48 89 c1             	mov    rcx,rax
   14000441e:	e8 26 ef ff ff       	call   140003349 <__pformat_wputchars>
   140004423:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004427:	0f 8f 5b ff ff ff    	jg     140004388 <__pformat_emit_float+0x269>
   14000442d:	eb 11                	jmp    140004440 <__pformat_emit_float+0x321>
   14000442f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004433:	48 89 c2             	mov    rdx,rax
   140004436:	b9 30 00 00 00       	mov    ecx,0x30
   14000443b:	e8 00 ed ff ff       	call   140003140 <__pformat_putc>
   140004440:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004444:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004447:	85 c0                	test   eax,eax
   140004449:	7f 10                	jg     14000445b <__pformat_emit_float+0x33c>
   14000444b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000444f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004452:	25 00 08 00 00       	and    eax,0x800
   140004457:	85 c0                	test   eax,eax
   140004459:	74 0c                	je     140004467 <__pformat_emit_float+0x348>
   14000445b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000445f:	48 89 c1             	mov    rcx,rax
   140004462:	e8 1b fa ff ff       	call   140003e82 <__pformat_emit_radix_point>
   140004467:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000446b:	79 5f                	jns    1400044cc <__pformat_emit_float+0x3ad>
   14000446d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004471:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004474:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004477:	01 c2                	add    edx,eax
   140004479:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000447d:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004480:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004484:	48 89 c2             	mov    rdx,rax
   140004487:	b9 30 00 00 00       	mov    ecx,0x30
   14000448c:	e8 af ec ff ff       	call   140003140 <__pformat_putc>
   140004491:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   140004495:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004499:	78 e5                	js     140004480 <__pformat_emit_float+0x361>
   14000449b:	eb 2f                	jmp    1400044cc <__pformat_emit_float+0x3ad>
   14000449d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044a1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044a4:	84 c0                	test   al,al
   1400044a6:	74 14                	je     1400044bc <__pformat_emit_float+0x39d>
   1400044a8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044ac:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400044b0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400044b4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044b7:	0f be c0             	movsx  eax,al
   1400044ba:	eb 05                	jmp    1400044c1 <__pformat_emit_float+0x3a2>
   1400044bc:	b8 30 00 00 00       	mov    eax,0x30
   1400044c1:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044c5:	89 c1                	mov    ecx,eax
   1400044c7:	e8 74 ec ff ff       	call   140003140 <__pformat_putc>
   1400044cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044d0:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400044d3:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400044d6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044da:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   1400044dd:	85 c0                	test   eax,eax
   1400044df:	7f bc                	jg     14000449d <__pformat_emit_float+0x37e>
   1400044e1:	90                   	nop
   1400044e2:	90                   	nop
   1400044e3:	48 83 c4 30          	add    rsp,0x30
   1400044e7:	5d                   	pop    rbp
   1400044e8:	c3                   	ret

00000001400044e9 <__pformat_emit_efloat>:
   1400044e9:	55                   	push   rbp
   1400044ea:	48 89 e5             	mov    rbp,rsp
   1400044ed:	48 83 ec 50          	sub    rsp,0x50
   1400044f1:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400044f4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400044f8:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400044fc:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004500:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140004507:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000450b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000450f:	79 09                	jns    14000451a <__pformat_emit_efloat+0x31>
   140004511:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004518:	eb 05                	jmp    14000451f <__pformat_emit_efloat+0x36>
   14000451a:	b8 00 00 00 00       	mov    eax,0x0
   14000451f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140004523:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004526:	48 98                	cdqe
   140004528:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000452c:	eb 04                	jmp    140004532 <__pformat_emit_efloat+0x49>
   14000452e:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140004532:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004535:	48 63 d0             	movsxd rdx,eax
   140004538:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   14000453f:	48 c1 ea 20          	shr    rdx,0x20
   140004543:	89 d1                	mov    ecx,edx
   140004545:	c1 f9 02             	sar    ecx,0x2
   140004548:	99                   	cdq
   140004549:	89 c8                	mov    eax,ecx
   14000454b:	29 d0                	sub    eax,edx
   14000454d:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004550:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004554:	75 d8                	jne    14000452e <__pformat_emit_efloat+0x45>
   140004556:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000455a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000455d:	83 f8 ff             	cmp    eax,0xffffffff
   140004560:	75 0b                	jne    14000456d <__pformat_emit_efloat+0x84>
   140004562:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004566:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   14000456d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004571:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004574:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004577:	7d 0a                	jge    140004583 <__pformat_emit_efloat+0x9a>
   140004579:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000457d:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004580:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004583:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004587:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000458a:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   14000458e:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004591:	7d 15                	jge    1400045a8 <__pformat_emit_efloat+0xbf>
   140004593:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004597:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000459a:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   14000459d:	89 c2                	mov    edx,eax
   14000459f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045a3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400045a6:	eb 0b                	jmp    1400045b3 <__pformat_emit_efloat+0xca>
   1400045a8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045ac:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400045b3:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400045b7:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400045bb:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400045be:	49 89 c9             	mov    r9,rcx
   1400045c1:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400045c7:	89 c1                	mov    ecx,eax
   1400045c9:	e8 51 fb ff ff       	call   14000411f <__pformat_emit_float>
   1400045ce:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045d2:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   1400045d5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045d9:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400045dc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045e0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400045e3:	0d c0 01 00 00       	or     eax,0x1c0
   1400045e8:	89 c2                	mov    edx,eax
   1400045ea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045ee:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400045f1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045f5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400045f8:	83 e0 20             	and    eax,0x20
   1400045fb:	83 c8 45             	or     eax,0x45
   1400045fe:	89 c1                	mov    ecx,eax
   140004600:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004604:	48 89 c2             	mov    rdx,rax
   140004607:	e8 34 eb ff ff       	call   140003140 <__pformat_putc>
   14000460c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004610:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004613:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140004616:	83 ea 01             	sub    edx,0x1
   140004619:	01 c2                	add    edx,eax
   14000461b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000461f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004622:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004626:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   14000462a:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000462e:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140004632:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004636:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000463a:	48 89 c1             	mov    rcx,rax
   14000463d:	e8 69 ef ff ff       	call   1400035ab <__pformat_int>
   140004642:	90                   	nop
   140004643:	48 83 c4 50          	add    rsp,0x50
   140004647:	5d                   	pop    rbp
   140004648:	c3                   	ret

0000000140004649 <__pformat_float>:
   140004649:	55                   	push   rbp
   14000464a:	53                   	push   rbx
   14000464b:	48 83 ec 58          	sub    rsp,0x58
   14000464f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004654:	48 89 cb             	mov    rbx,rcx
   140004657:	db 2b                	fld    TBYTE PTR [rbx]
   140004659:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000465c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004660:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004664:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004667:	85 c0                	test   eax,eax
   140004669:	79 0b                	jns    140004676 <__pformat_float+0x2d>
   14000466b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000466f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004676:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000467a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000467d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004680:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004683:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   140004687:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000468b:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000468f:	4d 89 c1             	mov    r9,r8
   140004692:	49 89 c8             	mov    r8,rcx
   140004695:	48 89 c1             	mov    rcx,rax
   140004698:	e8 93 f7 ff ff       	call   140003e30 <__pformat_fcvt>
   14000469d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400046a1:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400046a4:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400046a9:	75 17                	jne    1400046c2 <__pformat_float+0x79>
   1400046ab:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400046ae:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400046b2:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400046b6:	49 89 c8             	mov    r8,rcx
   1400046b9:	89 c1                	mov    ecx,eax
   1400046bb:	e8 74 f9 ff ff       	call   140004034 <__pformat_emit_inf_or_nan>
   1400046c0:	eb 43                	jmp    140004705 <__pformat_float+0xbc>
   1400046c2:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400046c5:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400046c8:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400046cc:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400046d0:	4d 89 c1             	mov    r9,r8
   1400046d3:	41 89 c8             	mov    r8d,ecx
   1400046d6:	89 c1                	mov    ecx,eax
   1400046d8:	e8 42 fa ff ff       	call   14000411f <__pformat_emit_float>
   1400046dd:	eb 11                	jmp    1400046f0 <__pformat_float+0xa7>
   1400046df:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046e3:	48 89 c2             	mov    rdx,rax
   1400046e6:	b9 20 00 00 00       	mov    ecx,0x20
   1400046eb:	e8 50 ea ff ff       	call   140003140 <__pformat_putc>
   1400046f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046f4:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400046f7:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400046fa:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400046fe:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004701:	85 c0                	test   eax,eax
   140004703:	7f da                	jg     1400046df <__pformat_float+0x96>
   140004705:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004709:	48 89 c1             	mov    rcx,rax
   14000470c:	e8 4e 17 00 00       	call   140005e5f <__freedtoa>
   140004711:	90                   	nop
   140004712:	48 83 c4 58          	add    rsp,0x58
   140004716:	5b                   	pop    rbx
   140004717:	5d                   	pop    rbp
   140004718:	c3                   	ret

0000000140004719 <__pformat_efloat>:
   140004719:	55                   	push   rbp
   14000471a:	53                   	push   rbx
   14000471b:	48 83 ec 58          	sub    rsp,0x58
   14000471f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004724:	48 89 cb             	mov    rbx,rcx
   140004727:	db 2b                	fld    TBYTE PTR [rbx]
   140004729:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000472c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004730:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004734:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004737:	85 c0                	test   eax,eax
   140004739:	79 0b                	jns    140004746 <__pformat_efloat+0x2d>
   14000473b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000473f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004746:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000474a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000474d:	8d 50 01             	lea    edx,[rax+0x1]
   140004750:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004753:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004756:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000475a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000475e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004762:	4d 89 c1             	mov    r9,r8
   140004765:	49 89 c8             	mov    r8,rcx
   140004768:	48 89 c1             	mov    rcx,rax
   14000476b:	e8 6e f6 ff ff       	call   140003dde <__pformat_ecvt>
   140004770:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004774:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004777:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000477c:	75 17                	jne    140004795 <__pformat_efloat+0x7c>
   14000477e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004781:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004785:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004789:	49 89 c8             	mov    r8,rcx
   14000478c:	89 c1                	mov    ecx,eax
   14000478e:	e8 a1 f8 ff ff       	call   140004034 <__pformat_emit_inf_or_nan>
   140004793:	eb 1b                	jmp    1400047b0 <__pformat_efloat+0x97>
   140004795:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004798:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000479b:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000479f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047a3:	4d 89 c1             	mov    r9,r8
   1400047a6:	41 89 c8             	mov    r8d,ecx
   1400047a9:	89 c1                	mov    ecx,eax
   1400047ab:	e8 39 fd ff ff       	call   1400044e9 <__pformat_emit_efloat>
   1400047b0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400047b4:	48 89 c1             	mov    rcx,rax
   1400047b7:	e8 a3 16 00 00       	call   140005e5f <__freedtoa>
   1400047bc:	90                   	nop
   1400047bd:	48 83 c4 58          	add    rsp,0x58
   1400047c1:	5b                   	pop    rbx
   1400047c2:	5d                   	pop    rbp
   1400047c3:	c3                   	ret

00000001400047c4 <__pformat_gfloat>:
   1400047c4:	55                   	push   rbp
   1400047c5:	53                   	push   rbx
   1400047c6:	48 83 ec 58          	sub    rsp,0x58
   1400047ca:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400047cf:	48 89 cb             	mov    rbx,rcx
   1400047d2:	db 2b                	fld    TBYTE PTR [rbx]
   1400047d4:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400047d7:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400047db:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047df:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400047e2:	85 c0                	test   eax,eax
   1400047e4:	79 0d                	jns    1400047f3 <__pformat_gfloat+0x2f>
   1400047e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047ea:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400047f1:	eb 16                	jmp    140004809 <__pformat_gfloat+0x45>
   1400047f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047f7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400047fa:	85 c0                	test   eax,eax
   1400047fc:	75 0b                	jne    140004809 <__pformat_gfloat+0x45>
   1400047fe:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004802:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   140004809:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000480d:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004810:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004813:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004816:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000481a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000481e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004822:	4d 89 c1             	mov    r9,r8
   140004825:	49 89 c8             	mov    r8,rcx
   140004828:	48 89 c1             	mov    rcx,rax
   14000482b:	e8 ae f5 ff ff       	call   140003dde <__pformat_ecvt>
   140004830:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004834:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004837:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000483c:	75 1a                	jne    140004858 <__pformat_gfloat+0x94>
   14000483e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004841:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004845:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004849:	49 89 c8             	mov    r8,rcx
   14000484c:	89 c1                	mov    ecx,eax
   14000484e:	e8 e1 f7 ff ff       	call   140004034 <__pformat_emit_inf_or_nan>
   140004853:	e9 14 01 00 00       	jmp    14000496c <__pformat_gfloat+0x1a8>
   140004858:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000485b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000485e:	0f 8c b2 00 00 00    	jl     140004916 <__pformat_gfloat+0x152>
   140004864:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004868:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000486b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000486e:	39 c2                	cmp    edx,eax
   140004870:	0f 8c a0 00 00 00    	jl     140004916 <__pformat_gfloat+0x152>
   140004876:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000487a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000487d:	25 00 08 00 00       	and    eax,0x800
   140004882:	85 c0                	test   eax,eax
   140004884:	74 15                	je     14000489b <__pformat_gfloat+0xd7>
   140004886:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000488a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000488d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004890:	29 c2                	sub    edx,eax
   140004892:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004896:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004899:	eb 20                	jmp    1400048bb <__pformat_gfloat+0xf7>
   14000489b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000489f:	48 89 c1             	mov    rcx,rax
   1400048a2:	e8 59 4c 00 00       	call   140009500 <strlen>
   1400048a7:	89 c1                	mov    ecx,eax
   1400048a9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048ac:	89 c2                	mov    edx,eax
   1400048ae:	89 c8                	mov    eax,ecx
   1400048b0:	29 d0                	sub    eax,edx
   1400048b2:	89 c2                	mov    edx,eax
   1400048b4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048b8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400048bb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048bf:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048c2:	85 c0                	test   eax,eax
   1400048c4:	79 0b                	jns    1400048d1 <__pformat_gfloat+0x10d>
   1400048c6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048ca:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   1400048d1:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400048d4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400048d7:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400048db:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048df:	4d 89 c1             	mov    r9,r8
   1400048e2:	41 89 c8             	mov    r8d,ecx
   1400048e5:	89 c1                	mov    ecx,eax
   1400048e7:	e8 33 f8 ff ff       	call   14000411f <__pformat_emit_float>
   1400048ec:	eb 11                	jmp    1400048ff <__pformat_gfloat+0x13b>
   1400048ee:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048f2:	48 89 c2             	mov    rdx,rax
   1400048f5:	b9 20 00 00 00       	mov    ecx,0x20
   1400048fa:	e8 41 e8 ff ff       	call   140003140 <__pformat_putc>
   1400048ff:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004903:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004906:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004909:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000490d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004910:	85 c0                	test   eax,eax
   140004912:	7f da                	jg     1400048ee <__pformat_gfloat+0x12a>
   140004914:	eb 56                	jmp    14000496c <__pformat_gfloat+0x1a8>
   140004916:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000491a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000491d:	25 00 08 00 00       	and    eax,0x800
   140004922:	85 c0                	test   eax,eax
   140004924:	74 13                	je     140004939 <__pformat_gfloat+0x175>
   140004926:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000492a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000492d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004930:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004934:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004937:	eb 18                	jmp    140004951 <__pformat_gfloat+0x18d>
   140004939:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000493d:	48 89 c1             	mov    rcx,rax
   140004940:	e8 bb 4b 00 00       	call   140009500 <strlen>
   140004945:	83 e8 01             	sub    eax,0x1
   140004948:	89 c2                	mov    edx,eax
   14000494a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000494e:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004951:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004954:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004957:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000495b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   14000495f:	4d 89 c1             	mov    r9,r8
   140004962:	41 89 c8             	mov    r8d,ecx
   140004965:	89 c1                	mov    ecx,eax
   140004967:	e8 7d fb ff ff       	call   1400044e9 <__pformat_emit_efloat>
   14000496c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004970:	48 89 c1             	mov    rcx,rax
   140004973:	e8 e7 14 00 00       	call   140005e5f <__freedtoa>
   140004978:	90                   	nop
   140004979:	48 83 c4 58          	add    rsp,0x58
   14000497d:	5b                   	pop    rbx
   14000497e:	5d                   	pop    rbp
   14000497f:	c3                   	ret

0000000140004980 <__pformat_emit_xfloat>:
   140004980:	55                   	push   rbp
   140004981:	53                   	push   rbx
   140004982:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140004989:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140004990:	00 
   140004991:	48 89 cb             	mov    rbx,rcx
   140004994:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004998:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   14000499c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400049a0:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   1400049a6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   1400049a9:	48 85 c0             	test   rax,rax
   1400049ac:	75 09                	jne    1400049b7 <__pformat_emit_xfloat+0x37>
   1400049ae:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   1400049b2:	66 85 c0             	test   ax,ax
   1400049b5:	74 0b                	je     1400049c2 <__pformat_emit_xfloat+0x42>
   1400049b7:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   1400049bb:	83 e8 03             	sub    eax,0x3
   1400049be:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   1400049c2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049c6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049c9:	85 c0                	test   eax,eax
   1400049cb:	0f 88 90 00 00 00    	js     140004a61 <__pformat_emit_xfloat+0xe1>
   1400049d1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049d5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049d8:	83 f8 0e             	cmp    eax,0xe
   1400049db:	0f 8f 80 00 00 00    	jg     140004a61 <__pformat_emit_xfloat+0xe1>
   1400049e1:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   1400049e4:	48 d1 e8             	shr    rax,1
   1400049e7:	48 89 03             	mov    QWORD PTR [rbx],rax
   1400049ea:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   1400049ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049f1:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049f4:	b9 0e 00 00 00       	mov    ecx,0xe
   1400049f9:	29 c1                	sub    ecx,eax
   1400049fb:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004a02:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004a08:	89 c1                	mov    ecx,eax
   140004a0a:	49 d3 e0             	shl    r8,cl
   140004a0d:	4c 89 c0             	mov    rax,r8
   140004a10:	48 01 d0             	add    rax,rdx
   140004a13:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a16:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a19:	48 85 c0             	test   rax,rax
   140004a1c:	78 0b                	js     140004a29 <__pformat_emit_xfloat+0xa9>
   140004a1e:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a21:	48 01 c0             	add    rax,rax
   140004a24:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a27:	eb 15                	jmp    140004a3e <__pformat_emit_xfloat+0xbe>
   140004a29:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a2d:	83 c0 04             	add    eax,0x4
   140004a30:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004a34:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a37:	48 c1 e8 03          	shr    rax,0x3
   140004a3b:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a3e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004a41:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a45:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a48:	b9 0f 00 00 00       	mov    ecx,0xf
   140004a4d:	29 c1                	sub    ecx,eax
   140004a4f:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004a56:	89 c1                	mov    ecx,eax
   140004a58:	48 d3 ea             	shr    rdx,cl
   140004a5b:	48 89 d0             	mov    rax,rdx
   140004a5e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a61:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a64:	48 85 c0             	test   rax,rax
   140004a67:	75 0f                	jne    140004a78 <__pformat_emit_xfloat+0xf8>
   140004a69:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a6d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a70:	85 c0                	test   eax,eax
   140004a72:	0f 8e f8 00 00 00    	jle    140004b70 <__pformat_emit_xfloat+0x1f0>
   140004a78:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a7c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a7f:	83 f8 0e             	cmp    eax,0xe
   140004a82:	7f 1a                	jg     140004a9e <__pformat_emit_xfloat+0x11e>
   140004a84:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a88:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a8b:	85 c0                	test   eax,eax
   140004a8d:	78 0f                	js     140004a9e <__pformat_emit_xfloat+0x11e>
   140004a8f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a93:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a96:	83 c0 01             	add    eax,0x1
   140004a99:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004a9c:	eb 07                	jmp    140004aa5 <__pformat_emit_xfloat+0x125>
   140004a9e:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004aa5:	e9 bc 00 00 00       	jmp    140004b66 <__pformat_emit_xfloat+0x1e6>
   140004aaa:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004aad:	83 e0 0f             	and    eax,0xf
   140004ab0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004ab3:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004ab7:	75 36                	jne    140004aef <__pformat_emit_xfloat+0x16f>
   140004ab9:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004abd:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004ac1:	72 1b                	jb     140004ade <__pformat_emit_xfloat+0x15e>
   140004ac3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ac7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004aca:	25 00 08 00 00       	and    eax,0x800
   140004acf:	85 c0                	test   eax,eax
   140004ad1:	75 0b                	jne    140004ade <__pformat_emit_xfloat+0x15e>
   140004ad3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ad7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ada:	85 c0                	test   eax,eax
   140004adc:	7e 2d                	jle    140004b0b <__pformat_emit_xfloat+0x18b>
   140004ade:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004ae2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004ae6:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004aea:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004aed:	eb 1c                	jmp    140004b0b <__pformat_emit_xfloat+0x18b>
   140004aef:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004af3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004af6:	85 c0                	test   eax,eax
   140004af8:	7e 11                	jle    140004b0b <__pformat_emit_xfloat+0x18b>
   140004afa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004afe:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b01:	8d 50 ff             	lea    edx,[rax-0x1]
   140004b04:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b08:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004b0b:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004b0f:	75 15                	jne    140004b26 <__pformat_emit_xfloat+0x1a6>
   140004b11:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b15:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b19:	72 0b                	jb     140004b26 <__pformat_emit_xfloat+0x1a6>
   140004b1b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b1f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b22:	85 c0                	test   eax,eax
   140004b24:	78 32                	js     140004b58 <__pformat_emit_xfloat+0x1d8>
   140004b26:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004b2a:	76 16                	jbe    140004b42 <__pformat_emit_xfloat+0x1c2>
   140004b2c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004b2f:	8d 50 37             	lea    edx,[rax+0x37]
   140004b32:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b36:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b39:	83 e0 20             	and    eax,0x20
   140004b3c:	09 d0                	or     eax,edx
   140004b3e:	89 c1                	mov    ecx,eax
   140004b40:	eb 08                	jmp    140004b4a <__pformat_emit_xfloat+0x1ca>
   140004b42:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004b45:	83 c0 30             	add    eax,0x30
   140004b48:	89 c1                	mov    ecx,eax
   140004b4a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004b4e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004b52:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004b56:	88 08                	mov    BYTE PTR [rax],cl
   140004b58:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b5b:	48 c1 e8 04          	shr    rax,0x4
   140004b5f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b62:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004b66:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004b6a:	0f 8f 3a ff ff ff    	jg     140004aaa <__pformat_emit_xfloat+0x12a>
   140004b70:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b74:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004b78:	75 39                	jne    140004bb3 <__pformat_emit_xfloat+0x233>
   140004b7a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b7e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b81:	85 c0                	test   eax,eax
   140004b83:	7f 10                	jg     140004b95 <__pformat_emit_xfloat+0x215>
   140004b85:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b89:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b8c:	25 00 08 00 00       	and    eax,0x800
   140004b91:	85 c0                	test   eax,eax
   140004b93:	74 0f                	je     140004ba4 <__pformat_emit_xfloat+0x224>
   140004b95:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004b99:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004b9d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004ba1:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004ba4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004ba8:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004bac:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004bb0:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004bb3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bb7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004bba:	85 c0                	test   eax,eax
   140004bbc:	0f 8e e3 00 00 00    	jle    140004ca5 <__pformat_emit_xfloat+0x325>
   140004bc2:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004bc6:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004bca:	48 29 c2             	sub    rdx,rax
   140004bcd:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004bd0:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004bd4:	98                   	cwde
   140004bd5:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004bd8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bdc:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bdf:	85 c0                	test   eax,eax
   140004be1:	7e 0a                	jle    140004bed <__pformat_emit_xfloat+0x26d>
   140004be3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004be7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bea:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004bed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bf1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004bf4:	25 c0 01 00 00       	and    eax,0x1c0
   140004bf9:	85 c0                	test   eax,eax
   140004bfb:	74 07                	je     140004c04 <__pformat_emit_xfloat+0x284>
   140004bfd:	b8 06 00 00 00       	mov    eax,0x6
   140004c02:	eb 05                	jmp    140004c09 <__pformat_emit_xfloat+0x289>
   140004c04:	b8 05 00 00 00       	mov    eax,0x5
   140004c09:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c0c:	eb 0f                	jmp    140004c1d <__pformat_emit_xfloat+0x29d>
   140004c0e:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004c12:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004c16:	83 c0 01             	add    eax,0x1
   140004c19:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004c1d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004c20:	48 63 d0             	movsxd rdx,eax
   140004c23:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004c2a:	48 c1 ea 20          	shr    rdx,0x20
   140004c2e:	89 d1                	mov    ecx,edx
   140004c30:	c1 f9 02             	sar    ecx,0x2
   140004c33:	99                   	cdq
   140004c34:	89 c8                	mov    eax,ecx
   140004c36:	29 d0                	sub    eax,edx
   140004c38:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004c3b:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004c3f:	75 cd                	jne    140004c0e <__pformat_emit_xfloat+0x28e>
   140004c41:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c45:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c48:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004c4b:	7d 4d                	jge    140004c9a <__pformat_emit_xfloat+0x31a>
   140004c4d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c51:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c54:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004c57:	89 c2                	mov    edx,eax
   140004c59:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c5d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004c60:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c64:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c67:	25 00 06 00 00       	and    eax,0x600
   140004c6c:	85 c0                	test   eax,eax
   140004c6e:	75 35                	jne    140004ca5 <__pformat_emit_xfloat+0x325>
   140004c70:	eb 11                	jmp    140004c83 <__pformat_emit_xfloat+0x303>
   140004c72:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c76:	48 89 c2             	mov    rdx,rax
   140004c79:	b9 20 00 00 00       	mov    ecx,0x20
   140004c7e:	e8 bd e4 ff ff       	call   140003140 <__pformat_putc>
   140004c83:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c87:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c8a:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004c8d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004c91:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004c94:	85 c0                	test   eax,eax
   140004c96:	7f da                	jg     140004c72 <__pformat_emit_xfloat+0x2f2>
   140004c98:	eb 0b                	jmp    140004ca5 <__pformat_emit_xfloat+0x325>
   140004c9a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c9e:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004ca5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ca9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cac:	25 80 00 00 00       	and    eax,0x80
   140004cb1:	85 c0                	test   eax,eax
   140004cb3:	74 13                	je     140004cc8 <__pformat_emit_xfloat+0x348>
   140004cb5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cb9:	48 89 c2             	mov    rdx,rax
   140004cbc:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004cc1:	e8 7a e4 ff ff       	call   140003140 <__pformat_putc>
   140004cc6:	eb 42                	jmp    140004d0a <__pformat_emit_xfloat+0x38a>
   140004cc8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ccc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ccf:	25 00 01 00 00       	and    eax,0x100
   140004cd4:	85 c0                	test   eax,eax
   140004cd6:	74 13                	je     140004ceb <__pformat_emit_xfloat+0x36b>
   140004cd8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cdc:	48 89 c2             	mov    rdx,rax
   140004cdf:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004ce4:	e8 57 e4 ff ff       	call   140003140 <__pformat_putc>
   140004ce9:	eb 1f                	jmp    140004d0a <__pformat_emit_xfloat+0x38a>
   140004ceb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cef:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cf2:	83 e0 40             	and    eax,0x40
   140004cf5:	85 c0                	test   eax,eax
   140004cf7:	74 11                	je     140004d0a <__pformat_emit_xfloat+0x38a>
   140004cf9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cfd:	48 89 c2             	mov    rdx,rax
   140004d00:	b9 20 00 00 00       	mov    ecx,0x20
   140004d05:	e8 36 e4 ff ff       	call   140003140 <__pformat_putc>
   140004d0a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d0e:	48 89 c2             	mov    rdx,rax
   140004d11:	b9 30 00 00 00       	mov    ecx,0x30
   140004d16:	e8 25 e4 ff ff       	call   140003140 <__pformat_putc>
   140004d1b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d1f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d22:	83 e0 20             	and    eax,0x20
   140004d25:	83 c8 58             	or     eax,0x58
   140004d28:	89 c1                	mov    ecx,eax
   140004d2a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d2e:	48 89 c2             	mov    rdx,rax
   140004d31:	e8 0a e4 ff ff       	call   140003140 <__pformat_putc>
   140004d36:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d3a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d3d:	85 c0                	test   eax,eax
   140004d3f:	7e 54                	jle    140004d95 <__pformat_emit_xfloat+0x415>
   140004d41:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d45:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d48:	25 00 02 00 00       	and    eax,0x200
   140004d4d:	85 c0                	test   eax,eax
   140004d4f:	74 44                	je     140004d95 <__pformat_emit_xfloat+0x415>
   140004d51:	eb 11                	jmp    140004d64 <__pformat_emit_xfloat+0x3e4>
   140004d53:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d57:	48 89 c2             	mov    rdx,rax
   140004d5a:	b9 30 00 00 00       	mov    ecx,0x30
   140004d5f:	e8 dc e3 ff ff       	call   140003140 <__pformat_putc>
   140004d64:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d68:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d6b:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004d6e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d72:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004d75:	85 c0                	test   eax,eax
   140004d77:	7f da                	jg     140004d53 <__pformat_emit_xfloat+0x3d3>
   140004d79:	eb 1a                	jmp    140004d95 <__pformat_emit_xfloat+0x415>
   140004d7b:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004d80:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004d84:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004d87:	0f be c0             	movsx  eax,al
   140004d8a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d8e:	89 c1                	mov    ecx,eax
   140004d90:	e8 32 f2 ff ff       	call   140003fc7 <__pformat_emit_numeric_value>
   140004d95:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004d99:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004d9d:	72 dc                	jb     140004d7b <__pformat_emit_xfloat+0x3fb>
   140004d9f:	eb 11                	jmp    140004db2 <__pformat_emit_xfloat+0x432>
   140004da1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004da5:	48 89 c2             	mov    rdx,rax
   140004da8:	b9 30 00 00 00       	mov    ecx,0x30
   140004dad:	e8 8e e3 ff ff       	call   140003140 <__pformat_putc>
   140004db2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004db6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004db9:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004dbc:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004dc0:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004dc3:	85 c0                	test   eax,eax
   140004dc5:	7f da                	jg     140004da1 <__pformat_emit_xfloat+0x421>
   140004dc7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dcb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dce:	83 e0 20             	and    eax,0x20
   140004dd1:	83 c8 50             	or     eax,0x50
   140004dd4:	89 c1                	mov    ecx,eax
   140004dd6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dda:	48 89 c2             	mov    rdx,rax
   140004ddd:	e8 5e e3 ff ff       	call   140003140 <__pformat_putc>
   140004de2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004de6:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004de9:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004ded:	01 c2                	add    edx,eax
   140004def:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004df3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004df6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dfa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dfd:	0d c0 01 00 00       	or     eax,0x1c0
   140004e02:	89 c2                	mov    edx,eax
   140004e04:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e08:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004e0b:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e0f:	66 85 c0             	test   ax,ax
   140004e12:	79 09                	jns    140004e1d <__pformat_emit_xfloat+0x49d>
   140004e14:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004e1b:	eb 05                	jmp    140004e22 <__pformat_emit_xfloat+0x4a2>
   140004e1d:	b8 00 00 00 00       	mov    eax,0x0
   140004e22:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004e26:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e2a:	48 0f bf c0          	movsx  rax,ax
   140004e2e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004e32:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004e36:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004e3a:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004e3e:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004e42:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e46:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004e4a:	48 89 c1             	mov    rcx,rax
   140004e4d:	e8 59 e7 ff ff       	call   1400035ab <__pformat_int>
   140004e52:	90                   	nop
   140004e53:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004e5a:	5b                   	pop    rbx
   140004e5b:	5d                   	pop    rbp
   140004e5c:	c3                   	ret

0000000140004e5d <__pformat_xldouble>:
   140004e5d:	55                   	push   rbp
   140004e5e:	53                   	push   rbx
   140004e5f:	48 83 ec 78          	sub    rsp,0x78
   140004e63:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004e68:	48 89 cb             	mov    rbx,rcx
   140004e6b:	db 2b                	fld    TBYTE PTR [rbx]
   140004e6d:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004e70:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004e74:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004e7b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004e7f:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004e82:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004e85:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004e89:	48 89 c1             	mov    rcx,rax
   140004e8c:	e8 e5 ed ff ff       	call   140003c76 <init_fpreg_ldouble>
   140004e91:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004e94:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004e97:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004e9b:	48 89 c1             	mov    rcx,rax
   140004e9e:	e8 ed 3d 00 00       	call   140008c90 <__isnanl>
   140004ea3:	85 c0                	test   eax,eax
   140004ea5:	74 1d                	je     140004ec4 <__pformat_xldouble+0x67>
   140004ea7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004eaa:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004eae:	48 8d 15 91 64 00 00 	lea    rdx,[rip+0x6491]        # 14000b346 <.rdata+0x16>
   140004eb5:	49 89 c8             	mov    r8,rcx
   140004eb8:	89 c1                	mov    ecx,eax
   140004eba:	e8 75 f1 ff ff       	call   140004034 <__pformat_emit_inf_or_nan>
   140004ebf:	e9 aa 00 00 00       	jmp    140004f6e <__pformat_xldouble+0x111>
   140004ec4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004ec8:	98                   	cwde
   140004ec9:	25 00 80 00 00       	and    eax,0x8000
   140004ece:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004ed1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004ed5:	74 12                	je     140004ee9 <__pformat_xldouble+0x8c>
   140004ed7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004edb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ede:	0c 80                	or     al,0x80
   140004ee0:	89 c2                	mov    edx,eax
   140004ee2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ee6:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004ee9:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004eec:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004eef:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004ef3:	48 89 c1             	mov    rcx,rax
   140004ef6:	e8 a5 3c 00 00       	call   140008ba0 <__fpclassifyl>
   140004efb:	3d 00 05 00 00       	cmp    eax,0x500
   140004f00:	75 1a                	jne    140004f1c <__pformat_xldouble+0xbf>
   140004f02:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f05:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f09:	48 8d 15 3a 64 00 00 	lea    rdx,[rip+0x643a]        # 14000b34a <.rdata+0x1a>
   140004f10:	49 89 c8             	mov    r8,rcx
   140004f13:	89 c1                	mov    ecx,eax
   140004f15:	e8 1a f1 ff ff       	call   140004034 <__pformat_emit_inf_or_nan>
   140004f1a:	eb 52                	jmp    140004f6e <__pformat_xldouble+0x111>
   140004f1c:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f20:	66 25 ff 7f          	and    ax,0x7fff
   140004f24:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004f28:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f2c:	66 85 c0             	test   ax,ax
   140004f2f:	75 11                	jne    140004f42 <__pformat_xldouble+0xe5>
   140004f31:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004f35:	48 85 c0             	test   rax,rax
   140004f38:	74 14                	je     140004f4e <__pformat_xldouble+0xf1>
   140004f3a:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140004f40:	eb 0c                	jmp    140004f4e <__pformat_xldouble+0xf1>
   140004f42:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f46:	66 2d ff 3f          	sub    ax,0x3fff
   140004f4a:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004f4e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004f52:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140004f56:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004f5a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   140004f5e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004f62:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140004f66:	48 89 c1             	mov    rcx,rax
   140004f69:	e8 12 fa ff ff       	call   140004980 <__pformat_emit_xfloat>
   140004f6e:	90                   	nop
   140004f6f:	48 83 c4 78          	add    rsp,0x78
   140004f73:	5b                   	pop    rbx
   140004f74:	5d                   	pop    rbp
   140004f75:	c3                   	ret

0000000140004f76 <__pformat_xdouble>:
   140004f76:	55                   	push   rbp
   140004f77:	48 89 e5             	mov    rbp,rsp
   140004f7a:	48 83 ec 60          	sub    rsp,0x60
   140004f7e:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140004f83:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004f87:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004f8e:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140004f91:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004f95:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004f98:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   140004f9c:	48 89 c1             	mov    rcx,rax
   140004f9f:	e8 d2 ec ff ff       	call   140003c76 <init_fpreg_ldouble>
   140004fa4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140004fa8:	66 48 0f 6e c0       	movq   xmm0,rax
   140004fad:	e8 7e 3c 00 00       	call   140008c30 <__isnan>
   140004fb2:	85 c0                	test   eax,eax
   140004fb4:	74 1d                	je     140004fd3 <__pformat_xdouble+0x5d>
   140004fb6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004fb9:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140004fbd:	48 8d 15 82 63 00 00 	lea    rdx,[rip+0x6382]        # 14000b346 <.rdata+0x16>
   140004fc4:	49 89 c8             	mov    r8,rcx
   140004fc7:	89 c1                	mov    ecx,eax
   140004fc9:	e8 66 f0 ff ff       	call   140004034 <__pformat_emit_inf_or_nan>
   140004fce:	e9 f9 00 00 00       	jmp    1400050cc <__pformat_xdouble+0x156>
   140004fd3:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fd7:	98                   	cwde
   140004fd8:	25 00 80 00 00       	and    eax,0x8000
   140004fdd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004fe0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004fe4:	74 12                	je     140004ff8 <__pformat_xdouble+0x82>
   140004fe6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004fea:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004fed:	0c 80                	or     al,0x80
   140004fef:	89 c2                	mov    edx,eax
   140004ff1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004ff5:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004ff8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140004ffc:	66 48 0f 6e c0       	movq   xmm0,rax
   140005001:	e8 1a 3b 00 00       	call   140008b20 <__fpclassify>
   140005006:	3d 00 05 00 00       	cmp    eax,0x500
   14000500b:	75 1d                	jne    14000502a <__pformat_xdouble+0xb4>
   14000500d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005010:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140005014:	48 8d 15 2f 63 00 00 	lea    rdx,[rip+0x632f]        # 14000b34a <.rdata+0x1a>
   14000501b:	49 89 c8             	mov    r8,rcx
   14000501e:	89 c1                	mov    ecx,eax
   140005020:	e8 0f f0 ff ff       	call   140004034 <__pformat_emit_inf_or_nan>
   140005025:	e9 a2 00 00 00       	jmp    1400050cc <__pformat_xdouble+0x156>
   14000502a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000502e:	66 25 ff 7f          	and    ax,0x7fff
   140005032:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005036:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000503a:	66 85 c0             	test   ax,ax
   14000503d:	74 3b                	je     14000507a <__pformat_xdouble+0x104>
   14000503f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005043:	66 3d 00 3c          	cmp    ax,0x3c00
   140005047:	7f 31                	jg     14000507a <__pformat_xdouble+0x104>
   140005049:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000504d:	98                   	cwde
   14000504e:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005053:	29 c2                	sub    edx,eax
   140005055:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005058:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000505c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000505f:	89 c1                	mov    ecx,eax
   140005061:	48 d3 ea             	shr    rdx,cl
   140005064:	48 89 d0             	mov    rax,rdx
   140005067:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000506b:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000506f:	89 c2                	mov    edx,eax
   140005071:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005074:	01 d0                	add    eax,edx
   140005076:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000507a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000507e:	66 85 c0             	test   ax,ax
   140005081:	75 11                	jne    140005094 <__pformat_xdouble+0x11e>
   140005083:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005087:	48 85 c0             	test   rax,rax
   14000508a:	74 14                	je     1400050a0 <__pformat_xdouble+0x12a>
   14000508c:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   140005092:	eb 0c                	jmp    1400050a0 <__pformat_xdouble+0x12a>
   140005094:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005098:	66 2d fc 3f          	sub    ax,0x3ffc
   14000509c:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400050a0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050a4:	48 c1 e8 03          	shr    rax,0x3
   1400050a8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400050ac:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050b0:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400050b4:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400050b8:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400050bc:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400050c0:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   1400050c4:	48 89 c1             	mov    rcx,rax
   1400050c7:	e8 b4 f8 ff ff       	call   140004980 <__pformat_emit_xfloat>
   1400050cc:	90                   	nop
   1400050cd:	48 83 c4 60          	add    rsp,0x60
   1400050d1:	5d                   	pop    rbp
   1400050d2:	c3                   	ret

00000001400050d3 <__mingw_pformat>:
   1400050d3:	55                   	push   rbp
   1400050d4:	48 89 e5             	mov    rbp,rsp
   1400050d7:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   1400050de:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400050e1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400050e5:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400050e9:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400050ed:	e8 86 43 00 00       	call   140009478 <_errno>
   1400050f2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400050f4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400050f7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400050fb:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   1400050ff:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   140005106:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140005109:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000510c:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   140005113:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   14000511a:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   140005121:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   140005127:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   14000512e:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   140005134:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   14000513b:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   14000513e:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   140005141:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   140005148:	e9 27 0c 00 00       	jmp    140005d74 <__mingw_pformat+0xca1>
   14000514d:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005151:	0f 85 0f 0c 00 00    	jne    140005d66 <__mingw_pformat+0xc93>
   140005157:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000515e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005165:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005169:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000516d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005171:	48 83 c0 0c          	add    rax,0xc
   140005175:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005179:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000517c:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000517f:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005186:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140005189:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000518c:	e9 c4 0b 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005191:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005195:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005199:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000519d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400051a0:	0f be c0             	movsx  eax,al
   1400051a3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400051a6:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400051aa:	0f 84 94 09 00 00    	je     140005b44 <__mingw_pformat+0xa71>
   1400051b0:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400051b4:	0f 8f 02 0b 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400051ba:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400051be:	0f 84 eb 03 00 00    	je     1400055af <__mingw_pformat+0x4dc>
   1400051c4:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400051c8:	0f 8f ee 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400051ce:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400051d2:	0f 84 31 09 00 00    	je     140005b09 <__mingw_pformat+0xa36>
   1400051d8:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400051dc:	0f 8f da 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400051e2:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400051e6:	0f 84 c3 03 00 00    	je     1400055af <__mingw_pformat+0x4dc>
   1400051ec:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400051f0:	0f 8f c6 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400051f6:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   1400051fa:	0f 84 31 09 00 00    	je     140005b31 <__mingw_pformat+0xa5e>
   140005200:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   140005204:	0f 8f b2 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000520a:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   14000520e:	0f 84 31 03 00 00    	je     140005545 <__mingw_pformat+0x472>
   140005214:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   140005218:	0f 8f 9e 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000521e:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   140005222:	0f 84 28 05 00 00    	je     140005750 <__mingw_pformat+0x67d>
   140005228:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   14000522c:	0f 8f 8a 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005232:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005236:	0f 84 73 03 00 00    	je     1400055af <__mingw_pformat+0x4dc>
   14000523c:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005240:	0f 8f 76 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005246:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   14000524a:	0f 84 4d 07 00 00    	je     14000599d <__mingw_pformat+0x8ca>
   140005250:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005254:	0f 8f 62 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000525a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000525e:	0f 84 2d 03 00 00    	je     140005591 <__mingw_pformat+0x4be>
   140005264:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   140005268:	0f 8f 4e 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000526e:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   140005272:	0f 84 65 08 00 00    	je     140005add <__mingw_pformat+0xa0a>
   140005278:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   14000527c:	0f 8f 3a 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005282:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005286:	0f 84 db 07 00 00    	je     140005a67 <__mingw_pformat+0x994>
   14000528c:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005290:	0f 8f 26 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005296:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   14000529a:	0f 84 ee 03 00 00    	je     14000568e <__mingw_pformat+0x5bb>
   1400052a0:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400052a4:	0f 8f 12 0a 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400052aa:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400052ae:	0f 84 87 07 00 00    	je     140005a3b <__mingw_pformat+0x968>
   1400052b4:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400052b8:	0f 8f fe 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400052be:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400052c2:	0f 84 f3 05 00 00    	je     1400058bb <__mingw_pformat+0x7e8>
   1400052c8:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400052cc:	0f 8f ea 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400052d2:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400052d6:	0f 84 61 05 00 00    	je     14000583d <__mingw_pformat+0x76a>
   1400052dc:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400052e0:	0f 8f d6 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400052e6:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400052ea:	0f 84 cf 04 00 00    	je     1400057bf <__mingw_pformat+0x6ec>
   1400052f0:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400052f4:	0f 8f c2 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400052fa:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   1400052fe:	0f 84 8a 03 00 00    	je     14000568e <__mingw_pformat+0x5bb>
   140005304:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   140005308:	0f 8f ae 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000530e:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   140005312:	0f 84 b5 01 00 00    	je     1400054cd <__mingw_pformat+0x3fa>
   140005318:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   14000531c:	0f 8f 9a 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005322:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005326:	0f 84 83 02 00 00    	je     1400055af <__mingw_pformat+0x4dc>
   14000532c:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005330:	0f 8f 86 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005336:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   14000533a:	0f 84 f9 05 00 00    	je     140005939 <__mingw_pformat+0x866>
   140005340:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   140005344:	0f 8f 72 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000534a:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   14000534e:	0f 84 5b 02 00 00    	je     1400055af <__mingw_pformat+0x4dc>
   140005354:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005358:	0f 8f 5e 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000535e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   140005362:	0f 84 d6 01 00 00    	je     14000553e <__mingw_pformat+0x46b>
   140005368:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   14000536c:	0f 8f 4a 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005372:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005376:	0f 84 a0 07 00 00    	je     140005b1c <__mingw_pformat+0xa49>
   14000537c:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005380:	0f 8f 36 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005386:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   14000538a:	0f 84 ea 06 00 00    	je     140005a7a <__mingw_pformat+0x9a7>
   140005390:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   140005394:	0f 8f 22 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000539a:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   14000539e:	0f 84 20 05 00 00    	je     1400058c4 <__mingw_pformat+0x7f1>
   1400053a4:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400053a8:	0f 8f 0e 09 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400053ae:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400053b2:	0f 84 8e 04 00 00    	je     140005846 <__mingw_pformat+0x773>
   1400053b8:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400053bc:	0f 8f fa 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400053c2:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400053c6:	0f 84 fc 03 00 00    	je     1400057c8 <__mingw_pformat+0x6f5>
   1400053cc:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400053d0:	0f 8f e6 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400053d6:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400053da:	0f 84 e6 00 00 00    	je     1400054c6 <__mingw_pformat+0x3f3>
   1400053e0:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400053e4:	0f 8f d2 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400053ea:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400053ee:	0f 84 bb 01 00 00    	je     1400055af <__mingw_pformat+0x4dc>
   1400053f4:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400053f8:	0f 8f be 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   1400053fe:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   140005402:	0f 84 3a 05 00 00    	je     140005942 <__mingw_pformat+0x86f>
   140005408:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   14000540c:	0f 8f aa 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005412:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005416:	0f 84 8c 08 00 00    	je     140005ca8 <__mingw_pformat+0xbd5>
   14000541c:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005420:	0f 8f 96 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005426:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   14000542a:	0f 84 27 07 00 00    	je     140005b57 <__mingw_pformat+0xa84>
   140005430:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   140005434:	0f 8f 82 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000543a:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   14000543e:	0f 84 db 07 00 00    	je     140005c1f <__mingw_pformat+0xb4c>
   140005444:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   140005448:	0f 8f 6e 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000544e:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005452:	0f 84 af 07 00 00    	je     140005c07 <__mingw_pformat+0xb34>
   140005458:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000545c:	0f 8f 5a 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005462:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005466:	0f 84 1c 07 00 00    	je     140005b88 <__mingw_pformat+0xab5>
   14000546c:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005470:	0f 8f 46 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   140005476:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   14000547a:	0f 84 b7 07 00 00    	je     140005c37 <__mingw_pformat+0xb64>
   140005480:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   140005484:	0f 8f 32 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000548a:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   14000548e:	74 23                	je     1400054b3 <__mingw_pformat+0x3e0>
   140005490:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005494:	0f 8f 22 08 00 00    	jg     140005cbc <__mingw_pformat+0xbe9>
   14000549a:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   14000549e:	0f 84 ec 07 00 00    	je     140005c90 <__mingw_pformat+0xbbd>
   1400054a4:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   1400054a8:	0f 84 41 07 00 00    	je     140005bef <__mingw_pformat+0xb1c>
   1400054ae:	e9 09 08 00 00       	jmp    140005cbc <__mingw_pformat+0xbe9>
   1400054b3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400054b7:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400054ba:	89 c1                	mov    ecx,eax
   1400054bc:	e8 7f dc ff ff       	call   140003140 <__pformat_putc>
   1400054c1:	e9 82 fc ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   1400054c6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400054cd:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400054d4:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400054d8:	74 06                	je     1400054e0 <__mingw_pformat+0x40d>
   1400054da:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400054de:	75 30                	jne    140005510 <__mingw_pformat+0x43d>
   1400054e0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400054e4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400054e8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400054ec:	8b 00                	mov    eax,DWORD PTR [rax]
   1400054ee:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   1400054f2:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400054f6:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   1400054fa:	49 89 d0             	mov    r8,rdx
   1400054fd:	ba 01 00 00 00       	mov    edx,0x1
   140005502:	48 89 c1             	mov    rcx,rax
   140005505:	e8 3f de ff ff       	call   140003349 <__pformat_wputchars>
   14000550a:	90                   	nop
   14000550b:	e9 38 fc ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   140005510:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005514:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005518:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000551c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000551e:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   140005521:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005525:	48 8d 45 90          	lea    rax,[rbp-0x70]
   140005529:	49 89 d0             	mov    r8,rdx
   14000552c:	ba 01 00 00 00       	mov    edx,0x1
   140005531:	48 89 c1             	mov    rcx,rax
   140005534:	e8 8b dc ff ff       	call   1400031c4 <__pformat_putchars>
   140005539:	e9 0a fc ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   14000553e:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005545:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005549:	74 06                	je     140005551 <__mingw_pformat+0x47e>
   14000554b:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000554f:	75 20                	jne    140005571 <__mingw_pformat+0x49e>
   140005551:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005555:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005559:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000555d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005560:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005564:	48 89 c1             	mov    rcx,rax
   140005567:	e8 29 df ff ff       	call   140003495 <__pformat_wcputs>
   14000556c:	e9 d7 fb ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   140005571:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005575:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005579:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000557d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005580:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005584:	48 89 c1             	mov    rcx,rax
   140005587:	e8 37 dd ff ff       	call   1400032c3 <__pformat_puts>
   14000558c:	e9 b7 fb ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   140005591:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140005594:	89 c1                	mov    ecx,eax
   140005596:	e8 5d 3f 00 00       	call   1400094f8 <strerror>
   14000559b:	48 89 c1             	mov    rcx,rax
   14000559e:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400055a2:	48 89 c2             	mov    rdx,rax
   1400055a5:	e8 19 dd ff ff       	call   1400032c3 <__pformat_puts>
   1400055aa:	e9 99 fb ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   1400055af:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400055b2:	80 e4 fe             	and    ah,0xfe
   1400055b5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400055b8:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055bc:	75 15                	jne    1400055d3 <__mingw_pformat+0x500>
   1400055be:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055c2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055c6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055ca:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400055cd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400055d1:	eb 54                	jmp    140005627 <__mingw_pformat+0x554>
   1400055d3:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400055d7:	75 16                	jne    1400055ef <__mingw_pformat+0x51c>
   1400055d9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055dd:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055e1:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055e5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055e7:	89 c0                	mov    eax,eax
   1400055e9:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400055ed:	eb 38                	jmp    140005627 <__mingw_pformat+0x554>
   1400055ef:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055f3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055f7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055fb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055fd:	89 c0                	mov    eax,eax
   1400055ff:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005603:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005607:	75 0d                	jne    140005616 <__mingw_pformat+0x543>
   140005609:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000560d:	0f b7 c0             	movzx  eax,ax
   140005610:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005614:	eb 11                	jmp    140005627 <__mingw_pformat+0x554>
   140005616:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   14000561a:	75 0b                	jne    140005627 <__mingw_pformat+0x554>
   14000561c:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   140005620:	0f b6 c0             	movzx  eax,al
   140005623:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005627:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   14000562b:	75 2e                	jne    14000565b <__mingw_pformat+0x588>
   14000562d:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005631:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005635:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000563c:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005643:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005647:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000564e:	48 89 c1             	mov    rcx,rax
   140005651:	e8 55 df ff ff       	call   1400035ab <__pformat_int>
   140005656:	e9 ed fa ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   14000565b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000565f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005663:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000566a:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005671:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140005675:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   14000567c:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000567f:	49 89 c8             	mov    r8,rcx
   140005682:	89 c1                	mov    ecx,eax
   140005684:	e8 a5 e2 ff ff       	call   14000392e <__pformat_xint>
   140005689:	e9 ba fa ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   14000568e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005691:	0c 80                	or     al,0x80
   140005693:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005696:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000569a:	75 15                	jne    1400056b1 <__mingw_pformat+0x5de>
   14000569c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056a0:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056a4:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056a8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400056ab:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056af:	eb 56                	jmp    140005707 <__mingw_pformat+0x634>
   1400056b1:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400056b5:	75 16                	jne    1400056cd <__mingw_pformat+0x5fa>
   1400056b7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056bb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056bf:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056c3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056c5:	48 98                	cdqe
   1400056c7:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056cb:	eb 3a                	jmp    140005707 <__mingw_pformat+0x634>
   1400056cd:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056d1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056d5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056d9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056db:	48 98                	cdqe
   1400056dd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056e1:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400056e5:	75 0e                	jne    1400056f5 <__mingw_pformat+0x622>
   1400056e7:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   1400056eb:	48 0f bf c0          	movsx  rax,ax
   1400056ef:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056f3:	eb 12                	jmp    140005707 <__mingw_pformat+0x634>
   1400056f5:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400056f9:	75 0c                	jne    140005707 <__mingw_pformat+0x634>
   1400056fb:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   1400056ff:	48 0f be c0          	movsx  rax,al
   140005703:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005707:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000570b:	48 85 c0             	test   rax,rax
   14000570e:	79 09                	jns    140005719 <__mingw_pformat+0x646>
   140005710:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140005717:	eb 05                	jmp    14000571e <__mingw_pformat+0x64b>
   140005719:	b8 00 00 00 00       	mov    eax,0x0
   14000571e:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140005722:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005726:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   14000572a:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005731:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005738:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000573c:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   140005743:	48 89 c1             	mov    rcx,rax
   140005746:	e8 60 de ff ff       	call   1400035ab <__pformat_int>
   14000574b:	e9 f8 f9 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   140005750:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005754:	75 18                	jne    14000576e <__mingw_pformat+0x69b>
   140005756:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005759:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000575c:	75 10                	jne    14000576e <__mingw_pformat+0x69b>
   14000575e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005761:	80 cc 02             	or     ah,0x2
   140005764:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005767:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   14000576e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005772:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005776:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000577a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000577d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005781:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   140005788:	00 
   140005789:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000578d:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005791:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005798:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   14000579f:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400057a3:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400057aa:	49 89 d0             	mov    r8,rdx
   1400057ad:	48 89 c2             	mov    rdx,rax
   1400057b0:	b9 78 00 00 00       	mov    ecx,0x78
   1400057b5:	e8 74 e1 ff ff       	call   14000392e <__pformat_xint>
   1400057ba:	e9 89 f9 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   1400057bf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057c2:	83 c8 20             	or     eax,0x20
   1400057c5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400057c8:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057cb:	83 e0 04             	and    eax,0x4
   1400057ce:	85 c0                	test   eax,eax
   1400057d0:	74 2f                	je     140005801 <__mingw_pformat+0x72e>
   1400057d2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057d6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057da:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057de:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400057e1:	db 28                	fld    TBYTE PTR [rax]
   1400057e3:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400057e9:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400057ed:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400057f4:	48 89 c1             	mov    rcx,rax
   1400057f7:	e8 1d ef ff ff       	call   140004719 <__pformat_efloat>
   1400057fc:	e9 47 f9 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   140005801:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005805:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005809:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000580d:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   140005811:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   140005818:	ff 
   140005819:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000581f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005825:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005829:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005830:	48 89 c1             	mov    rcx,rax
   140005833:	e8 e1 ee ff ff       	call   140004719 <__pformat_efloat>
   140005838:	e9 0b f9 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   14000583d:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005840:	83 c8 20             	or     eax,0x20
   140005843:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005846:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005849:	83 e0 04             	and    eax,0x4
   14000584c:	85 c0                	test   eax,eax
   14000584e:	74 2f                	je     14000587f <__mingw_pformat+0x7ac>
   140005850:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005854:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005858:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000585c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000585f:	db 28                	fld    TBYTE PTR [rax]
   140005861:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005867:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000586b:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005872:	48 89 c1             	mov    rcx,rax
   140005875:	e8 cf ed ff ff       	call   140004649 <__pformat_float>
   14000587a:	e9 c9 f8 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   14000587f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005883:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005887:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000588b:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   14000588f:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   140005896:	ff 
   140005897:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000589d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058a3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058a7:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058ae:	48 89 c1             	mov    rcx,rax
   1400058b1:	e8 93 ed ff ff       	call   140004649 <__pformat_float>
   1400058b6:	e9 8d f8 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   1400058bb:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058be:	83 c8 20             	or     eax,0x20
   1400058c1:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400058c4:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058c7:	83 e0 04             	and    eax,0x4
   1400058ca:	85 c0                	test   eax,eax
   1400058cc:	74 2f                	je     1400058fd <__mingw_pformat+0x82a>
   1400058ce:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058d2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058d6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058da:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400058dd:	db 28                	fld    TBYTE PTR [rax]
   1400058df:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058e5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058e9:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058f0:	48 89 c1             	mov    rcx,rax
   1400058f3:	e8 cc ee ff ff       	call   1400047c4 <__pformat_gfloat>
   1400058f8:	e9 4b f8 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   1400058fd:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005901:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005905:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005909:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   14000590d:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   140005914:	ff 
   140005915:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000591b:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005921:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005925:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000592c:	48 89 c1             	mov    rcx,rax
   14000592f:	e8 90 ee ff ff       	call   1400047c4 <__pformat_gfloat>
   140005934:	e9 0f f8 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   140005939:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000593c:	83 c8 20             	or     eax,0x20
   14000593f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005942:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005945:	83 e0 04             	and    eax,0x4
   140005948:	85 c0                	test   eax,eax
   14000594a:	74 2f                	je     14000597b <__mingw_pformat+0x8a8>
   14000594c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005950:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005954:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005958:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000595b:	db 28                	fld    TBYTE PTR [rax]
   14000595d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005963:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005967:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000596e:	48 89 c1             	mov    rcx,rax
   140005971:	e8 e7 f4 ff ff       	call   140004e5d <__pformat_xldouble>
   140005976:	e9 cd f7 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   14000597b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000597f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005983:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005987:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000598a:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000598e:	66 48 0f 6e c0       	movq   xmm0,rax
   140005993:	e8 de f5 ff ff       	call   140004f76 <__pformat_xdouble>
   140005998:	e9 ab f7 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   14000599d:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400059a1:	75 1b                	jne    1400059be <__mingw_pformat+0x8eb>
   1400059a3:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   1400059a6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059aa:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059ae:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059b2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059b5:	89 ca                	mov    edx,ecx
   1400059b7:	88 10                	mov    BYTE PTR [rax],dl
   1400059b9:	e9 8a f7 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   1400059be:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400059c2:	75 1c                	jne    1400059e0 <__mingw_pformat+0x90d>
   1400059c4:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   1400059c7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059cb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059cf:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059d3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059d6:	89 ca                	mov    edx,ecx
   1400059d8:	66 89 10             	mov    WORD PTR [rax],dx
   1400059db:	e9 68 f7 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   1400059e0:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400059e4:	75 19                	jne    1400059ff <__mingw_pformat+0x92c>
   1400059e6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059ea:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059ee:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059f2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059f5:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   1400059f8:	89 10                	mov    DWORD PTR [rax],edx
   1400059fa:	e9 49 f7 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   1400059ff:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005a03:	75 1d                	jne    140005a22 <__mingw_pformat+0x94f>
   140005a05:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a08:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a0c:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a10:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a14:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a17:	48 63 d1             	movsxd rdx,ecx
   140005a1a:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005a1d:	e9 26 f7 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   140005a22:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a26:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a2a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a2e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a31:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005a34:	89 10                	mov    DWORD PTR [rax],edx
   140005a36:	e9 0d f7 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   140005a3b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005a3f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005a42:	3c 68                	cmp    al,0x68
   140005a44:	75 0e                	jne    140005a54 <__mingw_pformat+0x981>
   140005a46:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005a4b:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005a52:	eb 07                	jmp    140005a5b <__mingw_pformat+0x988>
   140005a54:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005a5b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005a62:	e9 ee 02 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005a67:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005a6e:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005a75:	e9 db 02 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005a7a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005a7e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005a81:	3c 36                	cmp    al,0x36
   140005a83:	75 1d                	jne    140005aa2 <__mingw_pformat+0x9cf>
   140005a85:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005a89:	48 83 c0 01          	add    rax,0x1
   140005a8d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005a90:	3c 34                	cmp    al,0x34
   140005a92:	75 0e                	jne    140005aa2 <__mingw_pformat+0x9cf>
   140005a94:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005a9b:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005aa0:	eb 2f                	jmp    140005ad1 <__mingw_pformat+0x9fe>
   140005aa2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005aa6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005aa9:	3c 33                	cmp    al,0x33
   140005aab:	75 1d                	jne    140005aca <__mingw_pformat+0x9f7>
   140005aad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ab1:	48 83 c0 01          	add    rax,0x1
   140005ab5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ab8:	3c 32                	cmp    al,0x32
   140005aba:	75 0e                	jne    140005aca <__mingw_pformat+0x9f7>
   140005abc:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005ac3:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005ac8:	eb 07                	jmp    140005ad1 <__mingw_pformat+0x9fe>
   140005aca:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005ad1:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ad8:	e9 78 02 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005add:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ae1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ae4:	3c 6c                	cmp    al,0x6c
   140005ae6:	75 0e                	jne    140005af6 <__mingw_pformat+0xa23>
   140005ae8:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005aed:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005af4:	eb 07                	jmp    140005afd <__mingw_pformat+0xa2a>
   140005af6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005afd:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b04:	e9 4c 02 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005b09:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b10:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b17:	e9 39 02 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005b1c:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005b1f:	83 c8 04             	or     eax,0x4
   140005b22:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005b25:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b2c:	e9 24 02 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005b31:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b38:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b3f:	e9 11 02 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005b44:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b4b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b52:	e9 fe 01 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005b57:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005b5b:	77 1f                	ja     140005b7c <__mingw_pformat+0xaa9>
   140005b5d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005b64:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005b68:	48 83 c0 10          	add    rax,0x10
   140005b6c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005b70:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005b77:	e9 d9 01 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005b7c:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b83:	e9 cd 01 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005b88:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005b8d:	74 4c                	je     140005bdb <__mingw_pformat+0xb08>
   140005b8f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005b93:	74 06                	je     140005b9b <__mingw_pformat+0xac8>
   140005b95:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005b99:	75 40                	jne    140005bdb <__mingw_pformat+0xb08>
   140005b9b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005b9f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005ba3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ba7:	8b 10                	mov    edx,DWORD PTR [rax]
   140005ba9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005bad:	89 10                	mov    DWORD PTR [rax],edx
   140005baf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005bb3:	8b 00                	mov    eax,DWORD PTR [rax]
   140005bb5:	85 c0                	test   eax,eax
   140005bb7:	79 29                	jns    140005be2 <__mingw_pformat+0xb0f>
   140005bb9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005bbd:	75 13                	jne    140005bd2 <__mingw_pformat+0xaff>
   140005bbf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005bc2:	80 cc 04             	or     ah,0x4
   140005bc5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005bc8:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005bcb:	f7 d8                	neg    eax
   140005bcd:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005bd0:	eb 10                	jmp    140005be2 <__mingw_pformat+0xb0f>
   140005bd2:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005bd9:	eb 07                	jmp    140005be2 <__mingw_pformat+0xb0f>
   140005bdb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005be2:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005be9:	00 
   140005bea:	e9 66 01 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005bef:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005bf3:	0f 85 4f 01 00 00    	jne    140005d48 <__mingw_pformat+0xc75>
   140005bf9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005bfc:	80 cc 08             	or     ah,0x8
   140005bff:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c02:	e9 41 01 00 00       	jmp    140005d48 <__mingw_pformat+0xc75>
   140005c07:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c0b:	0f 85 3a 01 00 00    	jne    140005d4b <__mingw_pformat+0xc78>
   140005c11:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c14:	80 cc 01             	or     ah,0x1
   140005c17:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c1a:	e9 2c 01 00 00       	jmp    140005d4b <__mingw_pformat+0xc78>
   140005c1f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c23:	0f 85 25 01 00 00    	jne    140005d4e <__mingw_pformat+0xc7b>
   140005c29:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c2c:	80 cc 04             	or     ah,0x4
   140005c2f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c32:	e9 17 01 00 00       	jmp    140005d4e <__mingw_pformat+0xc7b>
   140005c37:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c3b:	0f 85 10 01 00 00    	jne    140005d51 <__mingw_pformat+0xc7e>
   140005c41:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c44:	80 cc 10             	or     ah,0x10
   140005c47:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c4a:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005c51:	00 
   140005c52:	e8 71 38 00 00       	call   1400094c8 <localeconv>
   140005c57:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005c5b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005c5f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005c63:	49 89 c9             	mov    r9,rcx
   140005c66:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005c6c:	48 89 c1             	mov    rcx,rax
   140005c6f:	e8 9c 32 00 00       	call   140008f10 <mbrtowc>
   140005c74:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005c77:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005c7b:	7e 08                	jle    140005c85 <__mingw_pformat+0xbb2>
   140005c7d:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005c81:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005c85:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005c88:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005c8b:	e9 c1 00 00 00       	jmp    140005d51 <__mingw_pformat+0xc7e>
   140005c90:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c94:	0f 85 ba 00 00 00    	jne    140005d54 <__mingw_pformat+0xc81>
   140005c9a:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c9d:	83 c8 40             	or     eax,0x40
   140005ca0:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005ca3:	e9 ac 00 00 00       	jmp    140005d54 <__mingw_pformat+0xc81>
   140005ca8:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cac:	75 0e                	jne    140005cbc <__mingw_pformat+0xbe9>
   140005cae:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cb1:	80 cc 02             	or     ah,0x2
   140005cb4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cb7:	e9 99 00 00 00       	jmp    140005d55 <__mingw_pformat+0xc82>
   140005cbc:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005cc0:	77 68                	ja     140005d2a <__mingw_pformat+0xc57>
   140005cc2:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005cc6:	7f 62                	jg     140005d2a <__mingw_pformat+0xc57>
   140005cc8:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005ccc:	7e 5c                	jle    140005d2a <__mingw_pformat+0xc57>
   140005cce:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cd2:	75 09                	jne    140005cdd <__mingw_pformat+0xc0a>
   140005cd4:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005cdb:	eb 0d                	jmp    140005cea <__mingw_pformat+0xc17>
   140005cdd:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005ce1:	75 07                	jne    140005cea <__mingw_pformat+0xc17>
   140005ce3:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005cea:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005cef:	74 64                	je     140005d55 <__mingw_pformat+0xc82>
   140005cf1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005cf5:	8b 00                	mov    eax,DWORD PTR [rax]
   140005cf7:	85 c0                	test   eax,eax
   140005cf9:	79 0e                	jns    140005d09 <__mingw_pformat+0xc36>
   140005cfb:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005cfe:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d01:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d05:	89 10                	mov    DWORD PTR [rax],edx
   140005d07:	eb 4c                	jmp    140005d55 <__mingw_pformat+0xc82>
   140005d09:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d0d:	8b 10                	mov    edx,DWORD PTR [rax]
   140005d0f:	89 d0                	mov    eax,edx
   140005d11:	c1 e0 02             	shl    eax,0x2
   140005d14:	01 d0                	add    eax,edx
   140005d16:	01 c0                	add    eax,eax
   140005d18:	89 c2                	mov    edx,eax
   140005d1a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d1d:	01 d0                	add    eax,edx
   140005d1f:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d22:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d26:	89 10                	mov    DWORD PTR [rax],edx
   140005d28:	eb 2b                	jmp    140005d55 <__mingw_pformat+0xc82>
   140005d2a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005d2e:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005d32:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005d36:	48 89 c2             	mov    rdx,rax
   140005d39:	b9 25 00 00 00       	mov    ecx,0x25
   140005d3e:	e8 fd d3 ff ff       	call   140003140 <__pformat_putc>
   140005d43:	e9 00 f4 ff ff       	jmp    140005148 <__mingw_pformat+0x75>
   140005d48:	90                   	nop
   140005d49:	eb 0a                	jmp    140005d55 <__mingw_pformat+0xc82>
   140005d4b:	90                   	nop
   140005d4c:	eb 07                	jmp    140005d55 <__mingw_pformat+0xc82>
   140005d4e:	90                   	nop
   140005d4f:	eb 04                	jmp    140005d55 <__mingw_pformat+0xc82>
   140005d51:	90                   	nop
   140005d52:	eb 01                	jmp    140005d55 <__mingw_pformat+0xc82>
   140005d54:	90                   	nop
   140005d55:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005d59:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005d5c:	84 c0                	test   al,al
   140005d5e:	0f 85 2d f4 ff ff    	jne    140005191 <__mingw_pformat+0xbe>
   140005d64:	eb 0e                	jmp    140005d74 <__mingw_pformat+0xca1>
   140005d66:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005d6a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d6d:	89 c1                	mov    ecx,eax
   140005d6f:	e8 cc d3 ff ff       	call   140003140 <__pformat_putc>
   140005d74:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005d78:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005d7c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005d80:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005d83:	0f be c0             	movsx  eax,al
   140005d86:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005d89:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005d8d:	0f 85 ba f3 ff ff    	jne    14000514d <__mingw_pformat+0x7a>
   140005d93:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005d96:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005d9d:	5d                   	pop    rbp
   140005d9e:	c3                   	ret
   140005d9f:	90                   	nop

0000000140005da0 <__rv_alloc_D2A>:
   140005da0:	55                   	push   rbp
   140005da1:	48 89 e5             	mov    rbp,rsp
   140005da4:	48 83 ec 30          	sub    rsp,0x30
   140005da8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005dab:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005db2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005db9:	eb 07                	jmp    140005dc2 <__rv_alloc_D2A+0x22>
   140005dbb:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005dbf:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005dc2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005dc5:	83 c0 17             	add    eax,0x17
   140005dc8:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005dcb:	7f ee                	jg     140005dbb <__rv_alloc_D2A+0x1b>
   140005dcd:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005dd0:	89 c1                	mov    ecx,eax
   140005dd2:	e8 56 1e 00 00       	call   140007c2d <__Balloc_D2A>
   140005dd7:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005ddb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ddf:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005de2:	89 10                	mov    DWORD PTR [rax],edx
   140005de4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005de8:	48 83 c0 04          	add    rax,0x4
   140005dec:	48 83 c4 30          	add    rsp,0x30
   140005df0:	5d                   	pop    rbp
   140005df1:	c3                   	ret

0000000140005df2 <__nrv_alloc_D2A>:
   140005df2:	55                   	push   rbp
   140005df3:	48 89 e5             	mov    rbp,rsp
   140005df6:	48 83 ec 30          	sub    rsp,0x30
   140005dfa:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005dfe:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005e02:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005e06:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005e09:	89 c1                	mov    ecx,eax
   140005e0b:	e8 90 ff ff ff       	call   140005da0 <__rv_alloc_D2A>
   140005e10:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005e14:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e18:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005e1c:	eb 05                	jmp    140005e23 <__nrv_alloc_D2A+0x31>
   140005e1e:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005e23:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005e27:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e2b:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005e2f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005e32:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e36:	88 10                	mov    BYTE PTR [rax],dl
   140005e38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e3c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e3f:	84 c0                	test   al,al
   140005e41:	75 db                	jne    140005e1e <__nrv_alloc_D2A+0x2c>
   140005e43:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005e48:	74 0b                	je     140005e55 <__nrv_alloc_D2A+0x63>
   140005e4a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005e4e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005e52:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005e55:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e59:	48 83 c4 30          	add    rsp,0x30
   140005e5d:	5d                   	pop    rbp
   140005e5e:	c3                   	ret

0000000140005e5f <__freedtoa>:
   140005e5f:	55                   	push   rbp
   140005e60:	48 89 e5             	mov    rbp,rsp
   140005e63:	48 83 ec 30          	sub    rsp,0x30
   140005e67:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005e6b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005e6f:	48 83 e8 04          	sub    rax,0x4
   140005e73:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005e77:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e7b:	8b 10                	mov    edx,DWORD PTR [rax]
   140005e7d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e81:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005e84:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e88:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005e8b:	ba 01 00 00 00       	mov    edx,0x1
   140005e90:	89 c1                	mov    ecx,eax
   140005e92:	d3 e2                	shl    edx,cl
   140005e94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e98:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005e9b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e9f:	48 89 c1             	mov    rcx,rax
   140005ea2:	e8 c7 1e 00 00       	call   140007d6e <__Bfree_D2A>
   140005ea7:	90                   	nop
   140005ea8:	48 83 c4 30          	add    rsp,0x30
   140005eac:	5d                   	pop    rbp
   140005ead:	c3                   	ret

0000000140005eae <__quorem_D2A>:
   140005eae:	55                   	push   rbp
   140005eaf:	48 89 e5             	mov    rbp,rsp
   140005eb2:	48 83 ec 70          	sub    rsp,0x70
   140005eb6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005eba:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005ebe:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005ec2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005ec5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005ec8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005ecc:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005ecf:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005ed2:	7e 0a                	jle    140005ede <__quorem_D2A+0x30>
   140005ed4:	b8 00 00 00 00       	mov    eax,0x0
   140005ed9:	e9 3f 02 00 00       	jmp    14000611d <__quorem_D2A+0x26f>
   140005ede:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005ee2:	48 83 c0 18          	add    rax,0x18
   140005ee6:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005eea:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005eee:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005ef1:	48 98                	cdqe
   140005ef3:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005efa:	00 
   140005efb:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005eff:	48 01 d0             	add    rax,rdx
   140005f02:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005f06:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f0a:	48 83 c0 18          	add    rax,0x18
   140005f0e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005f12:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005f15:	48 98                	cdqe
   140005f17:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005f1e:	00 
   140005f1f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f23:	48 01 d0             	add    rax,rdx
   140005f26:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140005f2a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005f2e:	8b 00                	mov    eax,DWORD PTR [rax]
   140005f30:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140005f34:	8b 12                	mov    edx,DWORD PTR [rdx]
   140005f36:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140005f39:	ba 00 00 00 00       	mov    edx,0x0
   140005f3e:	f7 f1                	div    ecx
   140005f40:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140005f43:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140005f47:	0f 84 c4 00 00 00    	je     140006011 <__quorem_D2A+0x163>
   140005f4d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140005f54:	00 
   140005f55:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   140005f5c:	00 
   140005f5d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005f61:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140005f65:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140005f69:	8b 00                	mov    eax,DWORD PTR [rax]
   140005f6b:	89 c2                	mov    edx,eax
   140005f6d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140005f70:	48 0f af d0          	imul   rdx,rax
   140005f74:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140005f78:	48 01 d0             	add    rax,rdx
   140005f7b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140005f7f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140005f83:	48 c1 e8 20          	shr    rax,0x20
   140005f87:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140005f8b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f8f:	8b 00                	mov    eax,DWORD PTR [rax]
   140005f91:	89 c1                	mov    ecx,eax
   140005f93:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140005f97:	89 c2                	mov    edx,eax
   140005f99:	48 89 c8             	mov    rax,rcx
   140005f9c:	48 29 d0             	sub    rax,rdx
   140005f9f:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140005fa3:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140005fa7:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140005fab:	48 c1 e8 20          	shr    rax,0x20
   140005faf:	83 e0 01             	and    eax,0x1
   140005fb2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140005fb6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005fba:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140005fbe:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140005fc2:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140005fc6:	89 10                	mov    DWORD PTR [rax],edx
   140005fc8:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005fcc:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140005fd0:	73 8b                	jae    140005f5d <__quorem_D2A+0xaf>
   140005fd2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005fd6:	8b 00                	mov    eax,DWORD PTR [rax]
   140005fd8:	85 c0                	test   eax,eax
   140005fda:	75 35                	jne    140006011 <__quorem_D2A+0x163>
   140005fdc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005fe0:	48 83 c0 18          	add    rax,0x18
   140005fe4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005fe8:	eb 04                	jmp    140005fee <__quorem_D2A+0x140>
   140005fea:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005fee:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   140005ff3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005ff7:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   140005ffb:	73 0a                	jae    140006007 <__quorem_D2A+0x159>
   140005ffd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006001:	8b 00                	mov    eax,DWORD PTR [rax]
   140006003:	85 c0                	test   eax,eax
   140006005:	74 e3                	je     140005fea <__quorem_D2A+0x13c>
   140006007:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000600b:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000600e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006011:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140006015:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006019:	48 89 c1             	mov    rcx,rax
   14000601c:	e8 bc 24 00 00       	call   1400084dd <__cmp_D2A>
   140006021:	85 c0                	test   eax,eax
   140006023:	0f 88 f1 00 00 00    	js     14000611a <__quorem_D2A+0x26c>
   140006029:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   14000602d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006034:	00 
   140006035:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000603c:	00 
   14000603d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006041:	48 83 c0 18          	add    rax,0x18
   140006045:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006049:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000604d:	48 83 c0 18          	add    rax,0x18
   140006051:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006055:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006059:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000605d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006061:	8b 00                	mov    eax,DWORD PTR [rax]
   140006063:	89 c2                	mov    edx,eax
   140006065:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006069:	48 01 d0             	add    rax,rdx
   14000606c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140006070:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006074:	48 c1 e8 20          	shr    rax,0x20
   140006078:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000607c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006080:	8b 00                	mov    eax,DWORD PTR [rax]
   140006082:	89 c1                	mov    ecx,eax
   140006084:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006088:	89 c2                	mov    edx,eax
   14000608a:	48 89 c8             	mov    rax,rcx
   14000608d:	48 29 d0             	sub    rax,rdx
   140006090:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006094:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006098:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000609c:	48 c1 e8 20          	shr    rax,0x20
   1400060a0:	83 e0 01             	and    eax,0x1
   1400060a3:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400060a7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060ab:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400060af:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400060b3:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400060b7:	89 10                	mov    DWORD PTR [rax],edx
   1400060b9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400060bd:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400060c1:	73 92                	jae    140006055 <__quorem_D2A+0x1a7>
   1400060c3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060c7:	48 83 c0 18          	add    rax,0x18
   1400060cb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400060cf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400060d2:	48 98                	cdqe
   1400060d4:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400060db:	00 
   1400060dc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060e0:	48 01 d0             	add    rax,rdx
   1400060e3:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400060e7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060ed:	85 c0                	test   eax,eax
   1400060ef:	75 29                	jne    14000611a <__quorem_D2A+0x26c>
   1400060f1:	eb 04                	jmp    1400060f7 <__quorem_D2A+0x249>
   1400060f3:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400060f7:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400060fc:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006100:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   140006104:	73 0a                	jae    140006110 <__quorem_D2A+0x262>
   140006106:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000610a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000610c:	85 c0                	test   eax,eax
   14000610e:	74 e3                	je     1400060f3 <__quorem_D2A+0x245>
   140006110:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006114:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006117:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000611a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   14000611d:	48 83 c4 70          	add    rsp,0x70
   140006121:	5d                   	pop    rbp
   140006122:	c3                   	ret
   140006123:	90                   	nop
   140006124:	90                   	nop
   140006125:	90                   	nop
   140006126:	90                   	nop
   140006127:	90                   	nop
   140006128:	90                   	nop
   140006129:	90                   	nop
   14000612a:	90                   	nop
   14000612b:	90                   	nop
   14000612c:	90                   	nop
   14000612d:	90                   	nop
   14000612e:	90                   	nop
   14000612f:	90                   	nop

0000000140006130 <__hi0bits_D2A>:
   140006130:	55                   	push   rbp
   140006131:	48 89 e5             	mov    rbp,rsp
   140006134:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140006137:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   14000613b:	83 f0 1f             	xor    eax,0x1f
   14000613e:	5d                   	pop    rbp
   14000613f:	c3                   	ret

0000000140006140 <bitstob>:
   140006140:	55                   	push   rbp
   140006141:	53                   	push   rbx
   140006142:	48 83 ec 58          	sub    rsp,0x58
   140006146:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000614b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000614f:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006152:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006156:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000615d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140006164:	eb 07                	jmp    14000616d <bitstob+0x2d>
   140006166:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140006169:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   14000616d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006170:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   140006173:	7c f1                	jl     140006166 <bitstob+0x26>
   140006175:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140006178:	89 c1                	mov    ecx,eax
   14000617a:	e8 ae 1a 00 00       	call   140007c2d <__Balloc_D2A>
   14000617f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006183:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140006186:	83 e8 01             	sub    eax,0x1
   140006189:	c1 f8 05             	sar    eax,0x5
   14000618c:	48 98                	cdqe
   14000618e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006195:	00 
   140006196:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000619a:	48 01 d0             	add    rax,rdx
   14000619d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400061a1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061a5:	48 83 c0 18          	add    rax,0x18
   1400061a9:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400061ad:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400061b1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400061b5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061b9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400061bd:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400061c1:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400061c5:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400061c7:	89 10                	mov    DWORD PTR [rax],edx
   1400061c9:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   1400061ce:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400061d2:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400061d6:	73 dd                	jae    1400061b5 <bitstob+0x75>
   1400061d8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061dc:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400061e0:	48 c1 f8 02          	sar    rax,0x2
   1400061e4:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400061e7:	eb 1d                	jmp    140006206 <bitstob+0xc6>
   1400061e9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400061ed:	75 17                	jne    140006206 <bitstob+0xc6>
   1400061ef:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061f3:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   1400061fa:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400061fe:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140006204:	eb 59                	jmp    14000625f <bitstob+0x11f>
   140006206:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000620a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000620d:	48 98                	cdqe
   14000620f:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006216:	00 
   140006217:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000621b:	48 01 d0             	add    rax,rdx
   14000621e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006220:	85 c0                	test   eax,eax
   140006222:	74 c5                	je     1400061e9 <bitstob+0xa9>
   140006224:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006227:	8d 50 01             	lea    edx,[rax+0x1]
   14000622a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000622e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006231:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006234:	83 c0 01             	add    eax,0x1
   140006237:	c1 e0 05             	shl    eax,0x5
   14000623a:	89 c3                	mov    ebx,eax
   14000623c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006240:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006243:	48 63 d2             	movsxd rdx,edx
   140006246:	48 83 c2 04          	add    rdx,0x4
   14000624a:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   14000624e:	89 c1                	mov    ecx,eax
   140006250:	e8 db fe ff ff       	call   140006130 <__hi0bits_D2A>
   140006255:	29 c3                	sub    ebx,eax
   140006257:	89 da                	mov    edx,ebx
   140006259:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000625d:	89 10                	mov    DWORD PTR [rax],edx
   14000625f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006263:	48 83 c4 58          	add    rsp,0x58
   140006267:	5b                   	pop    rbx
   140006268:	5d                   	pop    rbp
   140006269:	c3                   	ret

000000014000626a <__gdtoa>:
   14000626a:	55                   	push   rbp
   14000626b:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   140006272:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140006279:	00 
   14000627a:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   140006281:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   140006287:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   14000628e:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   140006295:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   14000629c:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062a3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062a5:	83 e0 cf             	and    eax,0xffffffcf
   1400062a8:	89 c2                	mov    edx,eax
   1400062aa:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062b1:	89 10                	mov    DWORD PTR [rax],edx
   1400062b3:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062ba:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062bc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400062bf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062c2:	83 e0 07             	and    eax,0x7
   1400062c5:	83 f8 04             	cmp    eax,0x4
   1400062c8:	0f 84 b0 00 00 00    	je     14000637e <__gdtoa+0x114>
   1400062ce:	83 f8 04             	cmp    eax,0x4
   1400062d1:	0f 8f d5 00 00 00    	jg     1400063ac <__gdtoa+0x142>
   1400062d7:	83 f8 03             	cmp    eax,0x3
   1400062da:	74 74                	je     140006350 <__gdtoa+0xe6>
   1400062dc:	83 f8 03             	cmp    eax,0x3
   1400062df:	0f 8f c7 00 00 00    	jg     1400063ac <__gdtoa+0x142>
   1400062e5:	85 c0                	test   eax,eax
   1400062e7:	0f 84 05 01 00 00    	je     1400063f2 <__gdtoa+0x188>
   1400062ed:	85 c0                	test   eax,eax
   1400062ef:	0f 88 b7 00 00 00    	js     1400063ac <__gdtoa+0x142>
   1400062f5:	83 e8 01             	sub    eax,0x1
   1400062f8:	83 f8 01             	cmp    eax,0x1
   1400062fb:	0f 87 ab 00 00 00    	ja     1400063ac <__gdtoa+0x142>
   140006301:	90                   	nop
   140006302:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006309:	8b 00                	mov    eax,DWORD PTR [rax]
   14000630b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000630e:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   140006312:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006315:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   14000631c:	49 89 c8             	mov    r8,rcx
   14000631f:	48 89 c1             	mov    rcx,rax
   140006322:	e8 19 fe ff ff       	call   140006140 <bitstob>
   140006327:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000632b:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006331:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140006334:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006338:	48 89 c1             	mov    rcx,rax
   14000633b:	e8 31 16 00 00       	call   140007971 <__trailz_D2A>
   140006340:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006343:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006346:	85 c0                	test   eax,eax
   140006348:	0f 84 8b 00 00 00    	je     1400063d9 <__gdtoa+0x16f>
   14000634e:	eb 66                	jmp    1400063b6 <__gdtoa+0x14c>
   140006350:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006357:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000635d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006364:	48 8d 0d e5 4f 00 00 	lea    rcx,[rip+0x4fe5]        # 14000b350 <.rdata>
   14000636b:	41 b8 08 00 00 00    	mov    r8d,0x8
   140006371:	48 89 c2             	mov    rdx,rax
   140006374:	e8 79 fa ff ff       	call   140005df2 <__nrv_alloc_D2A>
   140006379:	e9 4d 14 00 00       	jmp    1400077cb <__gdtoa+0x1561>
   14000637e:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006385:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000638b:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006392:	48 8d 0d c0 4f 00 00 	lea    rcx,[rip+0x4fc0]        # 14000b359 <.rdata+0x9>
   140006399:	41 b8 03 00 00 00    	mov    r8d,0x3
   14000639f:	48 89 c2             	mov    rdx,rax
   1400063a2:	e8 4b fa ff ff       	call   140005df2 <__nrv_alloc_D2A>
   1400063a7:	e9 1f 14 00 00       	jmp    1400077cb <__gdtoa+0x1561>
   1400063ac:	b8 00 00 00 00       	mov    eax,0x0
   1400063b1:	e9 15 14 00 00       	jmp    1400077cb <__gdtoa+0x1561>
   1400063b6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400063b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063bd:	48 89 c1             	mov    rcx,rax
   1400063c0:	e8 50 14 00 00       	call   140007815 <__rshift_D2A>
   1400063c5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400063c8:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   1400063ce:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400063d1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400063d4:	29 c2                	sub    edx,eax
   1400063d6:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   1400063d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063dd:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400063e0:	85 c0                	test   eax,eax
   1400063e2:	75 3d                	jne    140006421 <__gdtoa+0x1b7>
   1400063e4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063e8:	48 89 c1             	mov    rcx,rax
   1400063eb:	e8 7e 19 00 00       	call   140007d6e <__Bfree_D2A>
   1400063f0:	eb 01                	jmp    1400063f3 <__gdtoa+0x189>
   1400063f2:	90                   	nop
   1400063f3:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400063fa:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140006400:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006407:	48 8d 0d 4f 4f 00 00 	lea    rcx,[rip+0x4f4f]        # 14000b35d <.rdata+0xd>
   14000640e:	41 b8 01 00 00 00    	mov    r8d,0x1
   140006414:	48 89 c2             	mov    rdx,rax
   140006417:	e8 d6 f9 ff ff       	call   140005df2 <__nrv_alloc_D2A>
   14000641c:	e9 aa 13 00 00       	jmp    1400077cb <__gdtoa+0x1561>
   140006421:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   140006425:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006429:	48 89 c1             	mov    rcx,rax
   14000642c:	e8 75 23 00 00       	call   1400087a6 <__b2d_D2A>
   140006431:	66 48 0f 7e c0       	movq   rax,xmm0
   140006436:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   14000643a:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   14000643d:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006443:	01 d0                	add    eax,edx
   140006445:	83 e8 01             	sub    eax,0x1
   140006448:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000644b:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   14000644e:	25 ff ff 0f 00       	and    eax,0xfffff
   140006453:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006456:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006459:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000645e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006461:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006466:	f2 0f 10 15 f2 4e 00 	movsd  xmm2,QWORD PTR [rip+0x4ef2]        # 14000b360 <.rdata+0x10>
   14000646d:	00 
   14000646e:	66 0f 28 c8          	movapd xmm1,xmm0
   140006472:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006476:	f2 0f 10 05 ea 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4eea]        # 14000b368 <.rdata+0x18>
   14000647d:	00 
   14000647e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006482:	f2 0f 10 05 e6 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4ee6]        # 14000b370 <.rdata+0x20>
   140006489:	00 
   14000648a:	f2 0f 58 c8          	addsd  xmm1,xmm0
   14000648e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006491:	66 0f ef d2          	pxor   xmm2,xmm2
   140006495:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   140006499:	f2 0f 10 05 d7 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4ed7]        # 14000b378 <.rdata+0x28>
   1400064a0:	00 
   1400064a1:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   1400064a5:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400064a9:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400064ae:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064b1:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400064b4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400064b8:	79 03                	jns    1400064bd <__gdtoa+0x253>
   1400064ba:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   1400064bd:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   1400064c4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400064c8:	7e 23                	jle    1400064ed <__gdtoa+0x283>
   1400064ca:	66 0f ef c9          	pxor   xmm1,xmm1
   1400064ce:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   1400064d3:	f2 0f 10 05 a5 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4ea5]        # 14000b380 <.rdata+0x30>
   1400064da:	00 
   1400064db:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400064df:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   1400064e4:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400064e8:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400064ed:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   1400064f2:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400064f6:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   1400064f9:	66 0f ef c0          	pxor   xmm0,xmm0
   1400064fd:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006502:	76 1b                	jbe    14000651f <__gdtoa+0x2b5>
   140006504:	66 0f ef c0          	pxor   xmm0,xmm0
   140006508:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   14000650d:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006512:	7a 07                	jp     14000651b <__gdtoa+0x2b1>
   140006514:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006519:	74 04                	je     14000651f <__gdtoa+0x2b5>
   14000651b:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000651f:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   140006526:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006529:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   14000652c:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006532:	01 ca                	add    edx,ecx
   140006534:	83 ea 01             	sub    edx,0x1
   140006537:	c1 e2 14             	shl    edx,0x14
   14000653a:	01 d0                	add    eax,edx
   14000653c:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000653f:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006543:	78 2e                	js     140006573 <__gdtoa+0x309>
   140006545:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   140006549:	7f 28                	jg     140006573 <__gdtoa+0x309>
   14000654b:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006550:	48 8b 05 29 51 00 00 	mov    rax,QWORD PTR [rip+0x5129]        # 14000b680 <.refptr.__tens_D2A>
   140006557:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000655a:	48 63 d2             	movsxd rdx,edx
   14000655d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006562:	66 0f 2f c1          	comisd xmm0,xmm1
   140006566:	76 04                	jbe    14000656c <__gdtoa+0x302>
   140006568:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000656c:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   140006573:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006576:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006579:	29 c2                	sub    edx,eax
   14000657b:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000657e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006581:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006585:	78 0f                	js     140006596 <__gdtoa+0x32c>
   140006587:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   14000658e:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006591:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   140006594:	eb 0f                	jmp    1400065a5 <__gdtoa+0x33b>
   140006596:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006599:	f7 d8                	neg    eax
   14000659b:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   14000659e:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   1400065a5:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400065a9:	78 15                	js     1400065c0 <__gdtoa+0x356>
   1400065ab:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   1400065b2:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065b5:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   1400065b8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065bb:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400065be:	eb 15                	jmp    1400065d5 <__gdtoa+0x36b>
   1400065c0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065c3:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   1400065c6:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065c9:	f7 d8                	neg    eax
   1400065cb:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   1400065ce:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   1400065d5:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400065dc:	78 09                	js     1400065e7 <__gdtoa+0x37d>
   1400065de:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   1400065e5:	7e 0a                	jle    1400065f1 <__gdtoa+0x387>
   1400065e7:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   1400065ee:	00 00 00 
   1400065f1:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   1400065f8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400065ff:	7e 10                	jle    140006611 <__gdtoa+0x3a7>
   140006601:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   140006608:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000660f:	eb 1b                	jmp    14000662c <__gdtoa+0x3c2>
   140006611:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006614:	3d f9 03 00 00       	cmp    eax,0x3f9
   140006619:	7f 0a                	jg     140006625 <__gdtoa+0x3bb>
   14000661b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000661e:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   140006623:	7d 07                	jge    14000662c <__gdtoa+0x3c2>
   140006625:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000662c:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   140006633:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   14000663a:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000663d:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006640:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006647:	0f 84 c5 00 00 00    	je     140006712 <__gdtoa+0x4a8>
   14000664d:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006654:	0f 8f e6 00 00 00    	jg     140006740 <__gdtoa+0x4d6>
   14000665a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   140006661:	74 7e                	je     1400066e1 <__gdtoa+0x477>
   140006663:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   14000666a:	0f 8f d0 00 00 00    	jg     140006740 <__gdtoa+0x4d6>
   140006670:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006677:	0f 84 8e 00 00 00    	je     14000670b <__gdtoa+0x4a1>
   14000667d:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006684:	0f 8f b6 00 00 00    	jg     140006740 <__gdtoa+0x4d6>
   14000668a:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006691:	7f 0e                	jg     1400066a1 <__gdtoa+0x437>
   140006693:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000669a:	79 13                	jns    1400066af <__gdtoa+0x445>
   14000669c:	e9 9f 00 00 00       	jmp    140006740 <__gdtoa+0x4d6>
   1400066a1:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400066a8:	74 30                	je     1400066da <__gdtoa+0x470>
   1400066aa:	e9 91 00 00 00       	jmp    140006740 <__gdtoa+0x4d6>
   1400066af:	66 0f ef c9          	pxor   xmm1,xmm1
   1400066b3:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   1400066b8:	f2 0f 10 05 c8 4c 00 	movsd  xmm0,QWORD PTR [rip+0x4cc8]        # 14000b388 <.rdata+0x38>
   1400066bf:	00 
   1400066c0:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400066c4:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400066c8:	83 c0 03             	add    eax,0x3
   1400066cb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400066ce:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   1400066d5:	00 00 00 
   1400066d8:	eb 66                	jmp    140006740 <__gdtoa+0x4d6>
   1400066da:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   1400066e1:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   1400066e8:	7f 0a                	jg     1400066f4 <__gdtoa+0x48a>
   1400066ea:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   1400066f1:	00 00 00 
   1400066f4:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   1400066fa:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400066fd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006700:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006703:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006706:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006709:	eb 35                	jmp    140006740 <__gdtoa+0x4d6>
   14000670b:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006712:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   140006718:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000671b:	01 d0                	add    eax,edx
   14000671d:	83 c0 01             	add    eax,0x1
   140006720:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006723:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006726:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006729:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000672c:	83 e8 01             	sub    eax,0x1
   14000672f:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006732:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006735:	85 c0                	test   eax,eax
   140006737:	7f 07                	jg     140006740 <__gdtoa+0x4d6>
   140006739:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006740:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006743:	89 c1                	mov    ecx,eax
   140006745:	e8 56 f6 ff ff       	call   140005da0 <__rv_alloc_D2A>
   14000674a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000674e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006752:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006756:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000675d:	7f 09                	jg     140006768 <__gdtoa+0x4fe>
   14000675f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   140006766:	eb 38                	jmp    1400067a0 <__gdtoa+0x536>
   140006768:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000676f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140006772:	83 e8 01             	sub    eax,0x1
   140006775:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006778:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000677c:	74 22                	je     1400067a0 <__gdtoa+0x536>
   14000677e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006782:	79 07                	jns    14000678b <__gdtoa+0x521>
   140006784:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   14000678b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000678e:	83 e0 08             	and    eax,0x8
   140006791:	85 c0                	test   eax,eax
   140006793:	74 0b                	je     1400067a0 <__gdtoa+0x536>
   140006795:	b8 03 00 00 00       	mov    eax,0x3
   14000679a:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   14000679d:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   1400067a0:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400067a4:	0f 88 b9 04 00 00    	js     140006c63 <__gdtoa+0x9f9>
   1400067aa:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   1400067ae:	0f 8f af 04 00 00    	jg     140006c63 <__gdtoa+0x9f9>
   1400067b4:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   1400067b8:	0f 84 a5 04 00 00    	je     140006c63 <__gdtoa+0x9f9>
   1400067be:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400067c2:	0f 85 9b 04 00 00    	jne    140006c63 <__gdtoa+0x9f9>
   1400067c8:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400067cc:	0f 85 91 04 00 00    	jne    140006c63 <__gdtoa+0x9f9>
   1400067d2:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   1400067d9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400067de:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400067e3:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400067e6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400067e9:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   1400067ec:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   1400067ef:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   1400067f6:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400067fa:	0f 8e 98 00 00 00    	jle    140006898 <__gdtoa+0x62e>
   140006800:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006803:	83 e0 0f             	and    eax,0xf
   140006806:	89 c2                	mov    edx,eax
   140006808:	48 8b 05 71 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e71]        # 14000b680 <.refptr.__tens_D2A>
   14000680f:	48 63 d2             	movsxd rdx,edx
   140006812:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006817:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000681c:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000681f:	c1 f8 04             	sar    eax,0x4
   140006822:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006825:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006828:	83 e0 10             	and    eax,0x10
   14000682b:	85 c0                	test   eax,eax
   14000682d:	74 5e                	je     14000688d <__gdtoa+0x623>
   14000682f:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   140006833:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006838:	48 8b 05 71 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d71]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000683f:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   140006844:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006848:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000684d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006851:	eb 3a                	jmp    14000688d <__gdtoa+0x623>
   140006853:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006856:	83 e0 01             	and    eax,0x1
   140006859:	85 c0                	test   eax,eax
   14000685b:	74 24                	je     140006881 <__gdtoa+0x617>
   14000685d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006861:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006864:	48 8b 05 45 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d45]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000686b:	48 63 d2             	movsxd rdx,edx
   14000686e:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006873:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006878:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000687c:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006881:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006884:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006887:	83 c0 01             	add    eax,0x1
   14000688a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000688d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006891:	75 c0                	jne    140006853 <__gdtoa+0x5e9>
   140006893:	e9 8b 00 00 00       	jmp    140006923 <__gdtoa+0x6b9>
   140006898:	f2 0f 10 05 f0 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4af0]        # 14000b390 <.rdata+0x40>
   14000689f:	00 
   1400068a0:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068a5:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068a8:	f7 d8                	neg    eax
   1400068aa:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400068ad:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400068b1:	74 70                	je     140006923 <__gdtoa+0x6b9>
   1400068b3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400068b8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400068bb:	83 e0 0f             	and    eax,0xf
   1400068be:	89 c2                	mov    edx,eax
   1400068c0:	48 8b 05 b9 4d 00 00 	mov    rax,QWORD PTR [rip+0x4db9]        # 14000b680 <.refptr.__tens_D2A>
   1400068c7:	48 63 d2             	movsxd rdx,edx
   1400068ca:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400068cf:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400068d3:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400068d8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400068db:	c1 f8 04             	sar    eax,0x4
   1400068de:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400068e1:	eb 3a                	jmp    14000691d <__gdtoa+0x6b3>
   1400068e3:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400068e6:	83 e0 01             	and    eax,0x1
   1400068e9:	85 c0                	test   eax,eax
   1400068eb:	74 24                	je     140006911 <__gdtoa+0x6a7>
   1400068ed:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400068f1:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400068f6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400068f9:	48 8b 05 b0 4c 00 00 	mov    rax,QWORD PTR [rip+0x4cb0]        # 14000b5b0 <.refptr.__bigtens_D2A>
   140006900:	48 63 d2             	movsxd rdx,edx
   140006903:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006908:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000690c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006911:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006914:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006917:	83 c0 01             	add    eax,0x1
   14000691a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000691d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006921:	75 c0                	jne    1400068e3 <__gdtoa+0x679>
   140006923:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140006927:	74 47                	je     140006970 <__gdtoa+0x706>
   140006929:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   14000692e:	f2 0f 10 05 5a 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a5a]        # 14000b390 <.rdata+0x40>
   140006935:	00 
   140006936:	66 0f 2f c1          	comisd xmm0,xmm1
   14000693a:	76 34                	jbe    140006970 <__gdtoa+0x706>
   14000693c:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006940:	7e 2e                	jle    140006970 <__gdtoa+0x706>
   140006942:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   140006946:	0f 8e f5 02 00 00    	jle    140006c41 <__gdtoa+0x9d7>
   14000694c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000694f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006952:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006956:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   14000695b:	f2 0f 10 05 35 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a35]        # 14000b398 <.rdata+0x48>
   140006962:	00 
   140006963:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006967:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000696c:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006970:	66 0f ef c9          	pxor   xmm1,xmm1
   140006974:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006979:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   14000697e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006982:	f2 0f 10 05 16 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a16]        # 14000b3a0 <.rdata+0x50>
   140006989:	00 
   14000698a:	f2 0f 58 c1          	addsd  xmm0,xmm1
   14000698e:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006993:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   140006996:	2d 00 00 40 03       	sub    eax,0x3400000
   14000699b:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   14000699e:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400069a2:	75 5f                	jne    140006a03 <__gdtoa+0x799>
   1400069a4:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   1400069ab:	00 
   1400069ac:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400069b0:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400069b4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400069b9:	f2 0f 10 0d e7 49 00 	movsd  xmm1,QWORD PTR [rip+0x49e7]        # 14000b3a8 <.rdata+0x58>
   1400069c0:	00 
   1400069c1:	f2 0f 5c c1          	subsd  xmm0,xmm1
   1400069c5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069ca:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400069cf:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   1400069d4:	66 0f 2f c1          	comisd xmm0,xmm1
   1400069d8:	0f 87 ac 07 00 00    	ja     14000718a <__gdtoa+0xf20>
   1400069de:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069e3:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   1400069e8:	f3 0f 7e 15 c0 49 00 	movq   xmm2,QWORD PTR [rip+0x49c0]        # 14000b3b0 <.rdata+0x60>
   1400069ef:	00 
   1400069f0:	66 0f 57 c2          	xorpd  xmm0,xmm2
   1400069f4:	66 0f 2f c1          	comisd xmm0,xmm1
   1400069f8:	0f 87 6e 07 00 00    	ja     14000716c <__gdtoa+0xf02>
   1400069fe:	e9 42 02 00 00       	jmp    140006c45 <__gdtoa+0x9db>
   140006a03:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006a07:	0f 84 22 01 00 00    	je     140006b2f <__gdtoa+0x8c5>
   140006a0d:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006a12:	f2 0f 10 05 a6 49 00 	movsd  xmm0,QWORD PTR [rip+0x49a6]        # 14000b3c0 <.rdata+0x70>
   140006a19:	00 
   140006a1a:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a1e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006a21:	8d 50 ff             	lea    edx,[rax-0x1]
   140006a24:	48 8b 05 55 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c55]        # 14000b680 <.refptr.__tens_D2A>
   140006a2b:	48 63 d2             	movsxd rdx,edx
   140006a2e:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006a33:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006a37:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006a3c:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a40:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a45:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006a4c:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a51:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006a56:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006a5a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006a5d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a62:	66 0f ef c9          	pxor   xmm1,xmm1
   140006a66:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006a6b:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006a70:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a74:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a79:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006a7c:	8d 48 30             	lea    ecx,[rax+0x30]
   140006a7f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006a83:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006a87:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006a8b:	89 ca                	mov    edx,ecx
   140006a8d:	88 10                	mov    BYTE PTR [rax],dl
   140006a8f:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a94:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006a99:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a9d:	76 29                	jbe    140006ac8 <__gdtoa+0x85e>
   140006a9f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006aa4:	66 0f ef c9          	pxor   xmm1,xmm1
   140006aa8:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006aac:	7a 0e                	jp     140006abc <__gdtoa+0x852>
   140006aae:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ab2:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006ab6:	0f 84 93 0c 00 00    	je     14000774f <__gdtoa+0x14e5>
   140006abc:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006ac3:	e9 87 0c 00 00       	jmp    14000774f <__gdtoa+0x14e5>
   140006ac8:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006acd:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006ad2:	66 0f 28 c8          	movapd xmm1,xmm0
   140006ad6:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006ada:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006adf:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ae3:	0f 87 c3 02 00 00    	ja     140006dac <__gdtoa+0xb42>
   140006ae9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006aec:	83 c0 01             	add    eax,0x1
   140006aef:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006af2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006af5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006af8:	0f 8e 46 01 00 00    	jle    140006c44 <__gdtoa+0x9da>
   140006afe:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b03:	f2 0f 10 05 8d 48 00 	movsd  xmm0,QWORD PTR [rip+0x488d]        # 14000b398 <.rdata+0x48>
   140006b0a:	00 
   140006b0b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b0f:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b14:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b19:	f2 0f 10 05 77 48 00 	movsd  xmm0,QWORD PTR [rip+0x4877]        # 14000b398 <.rdata+0x48>
   140006b20:	00 
   140006b21:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b25:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b2a:	e9 1d ff ff ff       	jmp    140006a4c <__gdtoa+0x7e2>
   140006b2f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b34:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006b37:	8d 50 ff             	lea    edx,[rax-0x1]
   140006b3a:	48 8b 05 3f 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b3f]        # 14000b680 <.refptr.__tens_D2A>
   140006b41:	48 63 d2             	movsxd rdx,edx
   140006b44:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006b49:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b4d:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b52:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006b59:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b5e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006b63:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006b67:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006b6a:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006b6e:	74 1c                	je     140006b8c <__gdtoa+0x922>
   140006b70:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b75:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b79:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006b7e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006b83:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b87:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b8c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006b8f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006b92:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006b96:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006b9a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006b9e:	89 ca                	mov    edx,ecx
   140006ba0:	88 10                	mov    BYTE PTR [rax],dl
   140006ba2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ba5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006ba8:	75 73                	jne    140006c1d <__gdtoa+0x9b3>
   140006baa:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006baf:	f2 0f 10 05 09 48 00 	movsd  xmm0,QWORD PTR [rip+0x4809]        # 14000b3c0 <.rdata+0x70>
   140006bb6:	00 
   140006bb7:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bbb:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006bc0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006bc5:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006bca:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006bcf:	66 0f 2f c1          	comisd xmm0,xmm1
   140006bd3:	0f 87 d6 01 00 00    	ja     140006daf <__gdtoa+0xb45>
   140006bd9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006bde:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006be3:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006be8:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006bec:	66 0f 2f c1          	comisd xmm0,xmm1
   140006bf0:	77 02                	ja     140006bf4 <__gdtoa+0x98a>
   140006bf2:	eb 51                	jmp    140006c45 <__gdtoa+0x9db>
   140006bf4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006bf9:	66 0f ef c9          	pxor   xmm1,xmm1
   140006bfd:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c01:	7a 0e                	jp     140006c11 <__gdtoa+0x9a7>
   140006c03:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c07:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c0b:	0f 84 41 0b 00 00    	je     140007752 <__gdtoa+0x14e8>
   140006c11:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006c18:	e9 35 0b 00 00       	jmp    140007752 <__gdtoa+0x14e8>
   140006c1d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c20:	83 c0 01             	add    eax,0x1
   140006c23:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006c26:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c2b:	f2 0f 10 05 65 47 00 	movsd  xmm0,QWORD PTR [rip+0x4765]        # 14000b398 <.rdata+0x48>
   140006c32:	00 
   140006c33:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c37:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c3c:	e9 18 ff ff ff       	jmp    140006b59 <__gdtoa+0x8ef>
   140006c41:	90                   	nop
   140006c42:	eb 01                	jmp    140006c45 <__gdtoa+0x9db>
   140006c44:	90                   	nop
   140006c45:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006c49:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006c4d:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006c52:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c57:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006c5a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006c5d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006c60:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006c63:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006c6a:	0f 88 bf 01 00 00    	js     140006e2f <__gdtoa+0xbc5>
   140006c70:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006c77:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006c7a:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006c7d:	0f 8f ac 01 00 00    	jg     140006e2f <__gdtoa+0xbc5>
   140006c83:	48 8b 05 f6 49 00 00 	mov    rax,QWORD PTR [rip+0x49f6]        # 14000b680 <.refptr.__tens_D2A>
   140006c8a:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006c8d:	48 63 d2             	movsxd rdx,edx
   140006c90:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006c95:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006c9a:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006ca1:	79 45                	jns    140006ce8 <__gdtoa+0xa7e>
   140006ca3:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006ca7:	7f 3f                	jg     140006ce8 <__gdtoa+0xa7e>
   140006ca9:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006cb0:	00 
   140006cb1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006cb5:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006cb9:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006cbd:	0f 88 ac 04 00 00    	js     14000716f <__gdtoa+0xf05>
   140006cc3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006cc8:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006ccd:	f2 0f 10 05 d3 46 00 	movsd  xmm0,QWORD PTR [rip+0x46d3]        # 14000b3a8 <.rdata+0x58>
   140006cd4:	00 
   140006cd5:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006cd9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006cdd:	0f 83 8c 04 00 00    	jae    14000716f <__gdtoa+0xf05>
   140006ce3:	e9 a6 04 00 00       	jmp    14000718e <__gdtoa+0xf24>
   140006ce8:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006cef:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006cf4:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006cf9:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006cfd:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006d00:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d05:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d09:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006d0e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006d13:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006d17:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d1c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006d1f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006d22:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006d26:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006d2a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006d2e:	89 ca                	mov    edx,ecx
   140006d30:	88 10                	mov    BYTE PTR [rax],dl
   140006d32:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d37:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d3b:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d3f:	7a 0e                	jp     140006d4f <__gdtoa+0xae5>
   140006d41:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d45:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d49:	0f 84 da 00 00 00    	je     140006e29 <__gdtoa+0xbbf>
   140006d4f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006d52:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006d55:	0f 85 aa 00 00 00    	jne    140006e05 <__gdtoa+0xb9b>
   140006d5b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006d5f:	74 12                	je     140006d73 <__gdtoa+0xb09>
   140006d61:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006d65:	74 4b                	je     140006db2 <__gdtoa+0xb48>
   140006d67:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006d6e:	e9 e3 09 00 00       	jmp    140007756 <__gdtoa+0x14ec>
   140006d73:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d78:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006d7c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d81:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d86:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006d8b:	77 28                	ja     140006db5 <__gdtoa+0xb4b>
   140006d8d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d92:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006d97:	7a 63                	jp     140006dfc <__gdtoa+0xb92>
   140006d99:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006d9e:	75 5c                	jne    140006dfc <__gdtoa+0xb92>
   140006da0:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006da3:	83 e0 01             	and    eax,0x1
   140006da6:	85 c0                	test   eax,eax
   140006da8:	74 52                	je     140006dfc <__gdtoa+0xb92>
   140006daa:	eb 0a                	jmp    140006db6 <__gdtoa+0xb4c>
   140006dac:	90                   	nop
   140006dad:	eb 07                	jmp    140006db6 <__gdtoa+0xb4c>
   140006daf:	90                   	nop
   140006db0:	eb 04                	jmp    140006db6 <__gdtoa+0xb4c>
   140006db2:	90                   	nop
   140006db3:	eb 01                	jmp    140006db6 <__gdtoa+0xb4c>
   140006db5:	90                   	nop
   140006db6:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006dbd:	eb 17                	jmp    140006dd6 <__gdtoa+0xb6c>
   140006dbf:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006dc3:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006dc7:	75 0d                	jne    140006dd6 <__gdtoa+0xb6c>
   140006dc9:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006dcd:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006dd1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006dd4:	eb 10                	jmp    140006de6 <__gdtoa+0xb7c>
   140006dd6:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006ddb:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ddf:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006de2:	3c 39                	cmp    al,0x39
   140006de4:	74 d9                	je     140006dbf <__gdtoa+0xb55>
   140006de6:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006dea:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006dee:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006df2:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006df5:	83 c2 01             	add    edx,0x1
   140006df8:	88 10                	mov    BYTE PTR [rax],dl
   140006dfa:	eb 2e                	jmp    140006e2a <__gdtoa+0xbc0>
   140006dfc:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e03:	eb 25                	jmp    140006e2a <__gdtoa+0xbc0>
   140006e05:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e08:	83 c0 01             	add    eax,0x1
   140006e0b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006e0e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006e13:	f2 0f 10 05 7d 45 00 	movsd  xmm0,QWORD PTR [rip+0x457d]        # 14000b398 <.rdata+0x48>
   140006e1a:	00 
   140006e1b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006e1f:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e24:	e9 c6 fe ff ff       	jmp    140006cef <__gdtoa+0xa85>
   140006e29:	90                   	nop
   140006e2a:	e9 27 09 00 00       	jmp    140007756 <__gdtoa+0x14ec>
   140006e2f:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006e32:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006e35:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006e38:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006e3b:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006e42:	00 
   140006e43:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006e47:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006e4b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006e4f:	0f 84 e0 00 00 00    	je     140006f35 <__gdtoa+0xccb>
   140006e55:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006e58:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006e5b:	29 c2                	sub    edx,eax
   140006e5d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006e60:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e63:	8d 50 01             	lea    edx,[rax+0x1]
   140006e66:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006e69:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006e6f:	29 c2                	sub    edx,eax
   140006e71:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006e78:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006e7b:	39 c2                	cmp    edx,eax
   140006e7d:	7d 43                	jge    140006ec2 <__gdtoa+0xc58>
   140006e7f:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006e86:	74 3a                	je     140006ec2 <__gdtoa+0xc58>
   140006e88:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006e8f:	74 31                	je     140006ec2 <__gdtoa+0xc58>
   140006e91:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006e98:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006e9b:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006ea1:	29 c2                	sub    edx,eax
   140006ea3:	8d 42 01             	lea    eax,[rdx+0x1]
   140006ea6:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006ea9:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006eb0:	7e 68                	jle    140006f1a <__gdtoa+0xcb0>
   140006eb2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006eb6:	7e 62                	jle    140006f1a <__gdtoa+0xcb0>
   140006eb8:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ebb:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006ebe:	7d 5a                	jge    140006f1a <__gdtoa+0xcb0>
   140006ec0:	eb 0a                	jmp    140006ecc <__gdtoa+0xc62>
   140006ec2:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006ec9:	7e 50                	jle    140006f1b <__gdtoa+0xcb1>
   140006ecb:	90                   	nop
   140006ecc:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006ecf:	83 e8 01             	sub    eax,0x1
   140006ed2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006ed5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006ed8:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006edb:	7c 08                	jl     140006ee5 <__gdtoa+0xc7b>
   140006edd:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006ee0:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006ee3:	eb 19                	jmp    140006efe <__gdtoa+0xc94>
   140006ee5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006ee8:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006eeb:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006eee:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006ef1:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006ef4:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006ef7:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006efe:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f01:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f04:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f07:	85 c0                	test   eax,eax
   140006f09:	79 10                	jns    140006f1b <__gdtoa+0xcb1>
   140006f0b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f0e:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006f11:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006f18:	eb 01                	jmp    140006f1b <__gdtoa+0xcb1>
   140006f1a:	90                   	nop
   140006f1b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f1e:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140006f21:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f24:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140006f27:	b9 01 00 00 00       	mov    ecx,0x1
   140006f2c:	e8 f6 0f 00 00       	call   140007f27 <__i2b_D2A>
   140006f31:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f35:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140006f39:	7e 26                	jle    140006f61 <__gdtoa+0xcf7>
   140006f3b:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   140006f3f:	7e 20                	jle    140006f61 <__gdtoa+0xcf7>
   140006f41:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140006f44:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140006f47:	39 c2                	cmp    edx,eax
   140006f49:	0f 4e c2             	cmovle eax,edx
   140006f4c:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f4f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f52:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006f55:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f58:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006f5b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f5e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140006f61:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140006f65:	7e 7e                	jle    140006fe5 <__gdtoa+0xd7b>
   140006f67:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006f6b:	74 65                	je     140006fd2 <__gdtoa+0xd68>
   140006f6d:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140006f71:	7e 3b                	jle    140006fae <__gdtoa+0xd44>
   140006f73:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140006f76:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006f7a:	48 89 c1             	mov    rcx,rax
   140006f7d:	e8 11 12 00 00       	call   140008193 <__pow5mult_D2A>
   140006f82:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f86:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140006f8a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006f8e:	48 89 c1             	mov    rcx,rax
   140006f91:	e8 d7 0f 00 00       	call   140007f6d <__mult_D2A>
   140006f96:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140006f9a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006f9e:	48 89 c1             	mov    rcx,rax
   140006fa1:	e8 c8 0d 00 00       	call   140007d6e <__Bfree_D2A>
   140006fa6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006faa:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140006fae:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006fb1:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   140006fb4:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006fb7:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006fbb:	74 28                	je     140006fe5 <__gdtoa+0xd7b>
   140006fbd:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   140006fc0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006fc4:	48 89 c1             	mov    rcx,rax
   140006fc7:	e8 c7 11 00 00       	call   140008193 <__pow5mult_D2A>
   140006fcc:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140006fd0:	eb 13                	jmp    140006fe5 <__gdtoa+0xd7b>
   140006fd2:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   140006fd5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006fd9:	48 89 c1             	mov    rcx,rax
   140006fdc:	e8 b2 11 00 00       	call   140008193 <__pow5mult_D2A>
   140006fe1:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140006fe5:	b9 01 00 00 00       	mov    ecx,0x1
   140006fea:	e8 38 0f 00 00       	call   140007f27 <__i2b_D2A>
   140006fef:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006ff3:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140006ff7:	7e 13                	jle    14000700c <__gdtoa+0xda2>
   140006ff9:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   140006ffc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007000:	48 89 c1             	mov    rcx,rax
   140007003:	e8 8b 11 00 00       	call   140008193 <__pow5mult_D2A>
   140007008:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000700c:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   140007013:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000701a:	7f 29                	jg     140007045 <__gdtoa+0xddb>
   14000701c:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   14000701f:	83 f8 01             	cmp    eax,0x1
   140007022:	75 21                	jne    140007045 <__gdtoa+0xddb>
   140007024:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000702b:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000702e:	83 c0 01             	add    eax,0x1
   140007031:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140007034:	7e 0f                	jle    140007045 <__gdtoa+0xddb>
   140007036:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   14000703a:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   14000703e:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   140007045:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007049:	74 22                	je     14000706d <__gdtoa+0xe03>
   14000704b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000704f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007052:	8d 50 ff             	lea    edx,[rax-0x1]
   140007055:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007059:	48 63 d2             	movsxd rdx,edx
   14000705c:	48 83 c2 04          	add    rdx,0x4
   140007060:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   140007064:	89 c1                	mov    ecx,eax
   140007066:	e8 c5 f0 ff ff       	call   140006130 <__hi0bits_D2A>
   14000706b:	eb 05                	jmp    140007072 <__gdtoa+0xe08>
   14000706d:	b8 1f 00 00 00       	mov    eax,0x1f
   140007072:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   140007075:	83 e8 04             	sub    eax,0x4
   140007078:	83 e0 1f             	and    eax,0x1f
   14000707b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000707e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007081:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   140007084:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007087:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   14000708a:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   14000708e:	7e 13                	jle    1400070a3 <__gdtoa+0xe39>
   140007090:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   140007093:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007097:	48 89 c1             	mov    rcx,rax
   14000709a:	e8 b1 12 00 00       	call   140008350 <__lshift_D2A>
   14000709f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070a3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400070a6:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400070a9:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   1400070ad:	7e 13                	jle    1400070c2 <__gdtoa+0xe58>
   1400070af:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   1400070b2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070b6:	48 89 c1             	mov    rcx,rax
   1400070b9:	e8 92 12 00 00       	call   140008350 <__lshift_D2A>
   1400070be:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070c2:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400070c6:	74 5a                	je     140007122 <__gdtoa+0xeb8>
   1400070c8:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400070cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070d0:	48 89 c1             	mov    rcx,rax
   1400070d3:	e8 05 14 00 00       	call   1400084dd <__cmp_D2A>
   1400070d8:	85 c0                	test   eax,eax
   1400070da:	79 46                	jns    140007122 <__gdtoa+0xeb8>
   1400070dc:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400070e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070e4:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400070ea:	ba 0a 00 00 00       	mov    edx,0xa
   1400070ef:	48 89 c1             	mov    rcx,rax
   1400070f2:	e8 02 0d 00 00       	call   140007df9 <__multadd_D2A>
   1400070f7:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070fb:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400070ff:	74 1b                	je     14000711c <__gdtoa+0xeb2>
   140007101:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007105:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000710b:	ba 0a 00 00 00       	mov    edx,0xa
   140007110:	48 89 c1             	mov    rcx,rax
   140007113:	e8 e1 0c 00 00       	call   140007df9 <__multadd_D2A>
   140007118:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000711c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000711f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140007122:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007126:	0f 8f 81 00 00 00    	jg     1400071ad <__gdtoa+0xf43>
   14000712c:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140007133:	7e 78                	jle    1400071ad <__gdtoa+0xf43>
   140007135:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007139:	78 37                	js     140007172 <__gdtoa+0xf08>
   14000713b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000713f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007145:	ba 05 00 00 00       	mov    edx,0x5
   14000714a:	48 89 c1             	mov    rcx,rax
   14000714d:	e8 a7 0c 00 00       	call   140007df9 <__multadd_D2A>
   140007152:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007156:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000715a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000715e:	48 89 c1             	mov    rcx,rax
   140007161:	e8 77 13 00 00       	call   1400084dd <__cmp_D2A>
   140007166:	85 c0                	test   eax,eax
   140007168:	7f 23                	jg     14000718d <__gdtoa+0xf23>
   14000716a:	eb 07                	jmp    140007173 <__gdtoa+0xf09>
   14000716c:	90                   	nop
   14000716d:	eb 04                	jmp    140007173 <__gdtoa+0xf09>
   14000716f:	90                   	nop
   140007170:	eb 01                	jmp    140007173 <__gdtoa+0xf09>
   140007172:	90                   	nop
   140007173:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   140007179:	f7 d0                	not    eax
   14000717b:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   14000717e:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007185:	e9 87 05 00 00       	jmp    140007711 <__gdtoa+0x14a7>
   14000718a:	90                   	nop
   14000718b:	eb 01                	jmp    14000718e <__gdtoa+0xf24>
   14000718d:	90                   	nop
   14000718e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007195:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007199:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000719d:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400071a1:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400071a4:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400071a8:	e9 64 05 00 00       	jmp    140007711 <__gdtoa+0x14a7>
   1400071ad:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400071b1:	0f 84 14 04 00 00    	je     1400075cb <__gdtoa+0x1361>
   1400071b7:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   1400071bb:	7e 13                	jle    1400071d0 <__gdtoa+0xf66>
   1400071bd:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   1400071c0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071c4:	48 89 c1             	mov    rcx,rax
   1400071c7:	e8 84 11 00 00       	call   140008350 <__lshift_D2A>
   1400071cc:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400071d0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071d4:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400071d8:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   1400071dc:	74 57                	je     140007235 <__gdtoa+0xfcb>
   1400071de:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071e2:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400071e5:	89 c1                	mov    ecx,eax
   1400071e7:	e8 41 0a 00 00       	call   140007c2d <__Balloc_D2A>
   1400071ec:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400071f0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400071f4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400071f7:	48 98                	cdqe
   1400071f9:	48 83 c0 02          	add    rax,0x2
   1400071fd:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007204:	00 
   140007205:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007209:	48 8d 50 10          	lea    rdx,[rax+0x10]
   14000720d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007211:	48 83 c0 10          	add    rax,0x10
   140007215:	49 89 c8             	mov    r8,rcx
   140007218:	48 89 c1             	mov    rcx,rax
   14000721b:	e8 b8 22 00 00       	call   1400094d8 <memcpy>
   140007220:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007224:	ba 01 00 00 00       	mov    edx,0x1
   140007229:	48 89 c1             	mov    rcx,rax
   14000722c:	e8 1f 11 00 00       	call   140008350 <__lshift_D2A>
   140007231:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007235:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   14000723c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007240:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007244:	48 89 c1             	mov    rcx,rax
   140007247:	e8 62 ec ff ff       	call   140005eae <__quorem_D2A>
   14000724c:	83 c0 30             	add    eax,0x30
   14000724f:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007252:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007256:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000725a:	48 89 c1             	mov    rcx,rax
   14000725d:	e8 7b 12 00 00       	call   1400084dd <__cmp_D2A>
   140007262:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007265:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007269:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000726d:	48 89 c1             	mov    rcx,rax
   140007270:	e8 38 13 00 00       	call   1400085ad <__diff_D2A>
   140007275:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140007279:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   14000727d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140007280:	85 c0                	test   eax,eax
   140007282:	75 15                	jne    140007299 <__gdtoa+0x102f>
   140007284:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140007288:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000728c:	48 89 c1             	mov    rcx,rax
   14000728f:	e8 49 12 00 00       	call   1400084dd <__cmp_D2A>
   140007294:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007297:	eb 07                	jmp    1400072a0 <__gdtoa+0x1036>
   140007299:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   1400072a0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   1400072a4:	48 89 c1             	mov    rcx,rax
   1400072a7:	e8 c2 0a 00 00       	call   140007d6e <__Bfree_D2A>
   1400072ac:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400072b0:	75 70                	jne    140007322 <__gdtoa+0x10b8>
   1400072b2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400072b9:	75 67                	jne    140007322 <__gdtoa+0x10b8>
   1400072bb:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400072c2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400072c4:	83 e0 01             	and    eax,0x1
   1400072c7:	85 c0                	test   eax,eax
   1400072c9:	75 57                	jne    140007322 <__gdtoa+0x10b8>
   1400072cb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400072cf:	75 51                	jne    140007322 <__gdtoa+0x10b8>
   1400072d1:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400072d5:	0f 84 01 02 00 00    	je     1400074dc <__gdtoa+0x1272>
   1400072db:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400072df:	7f 20                	jg     140007301 <__gdtoa+0x1097>
   1400072e1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072e5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400072e8:	83 f8 01             	cmp    eax,0x1
   1400072eb:	7f 0b                	jg     1400072f8 <__gdtoa+0x108e>
   1400072ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072f1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400072f4:	85 c0                	test   eax,eax
   1400072f6:	74 14                	je     14000730c <__gdtoa+0x10a2>
   1400072f8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400072ff:	eb 0b                	jmp    14000730c <__gdtoa+0x10a2>
   140007301:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   140007305:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   14000730c:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007310:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007314:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007318:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000731b:	88 10                	mov    BYTE PTR [rax],dl
   14000731d:	e9 ef 03 00 00       	jmp    140007711 <__gdtoa+0x14a7>
   140007322:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007326:	78 2b                	js     140007353 <__gdtoa+0x10e9>
   140007328:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000732c:	0f 85 96 01 00 00    	jne    1400074c8 <__gdtoa+0x125e>
   140007332:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007339:	0f 85 89 01 00 00    	jne    1400074c8 <__gdtoa+0x125e>
   14000733f:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007346:	8b 00                	mov    eax,DWORD PTR [rax]
   140007348:	83 e0 01             	and    eax,0x1
   14000734b:	85 c0                	test   eax,eax
   14000734d:	0f 85 75 01 00 00    	jne    1400074c8 <__gdtoa+0x125e>
   140007353:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007357:	0f 84 db 00 00 00    	je     140007438 <__gdtoa+0x11ce>
   14000735d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007361:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007364:	83 f8 01             	cmp    eax,0x1
   140007367:	7f 0f                	jg     140007378 <__gdtoa+0x110e>
   140007369:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000736d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007370:	85 c0                	test   eax,eax
   140007372:	0f 84 c0 00 00 00    	je     140007438 <__gdtoa+0x11ce>
   140007378:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   14000737c:	0f 85 83 00 00 00    	jne    140007405 <__gdtoa+0x119b>
   140007382:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007389:	e9 24 01 00 00       	jmp    1400074b2 <__gdtoa+0x1248>
   14000738e:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007392:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007396:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000739a:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000739d:	88 10                	mov    BYTE PTR [rax],dl
   14000739f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400073a3:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400073a9:	ba 0a 00 00 00       	mov    edx,0xa
   1400073ae:	48 89 c1             	mov    rcx,rax
   1400073b1:	e8 43 0a 00 00       	call   140007df9 <__multadd_D2A>
   1400073b6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400073ba:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400073be:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400073c2:	75 08                	jne    1400073cc <__gdtoa+0x1162>
   1400073c4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400073c8:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400073cc:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400073d0:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400073d4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073d8:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400073de:	ba 0a 00 00 00       	mov    edx,0xa
   1400073e3:	48 89 c1             	mov    rcx,rax
   1400073e6:	e8 0e 0a 00 00       	call   140007df9 <__multadd_D2A>
   1400073eb:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400073ef:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400073f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073f7:	48 89 c1             	mov    rcx,rax
   1400073fa:	e8 af ea ff ff       	call   140005eae <__quorem_D2A>
   1400073ff:	83 c0 30             	add    eax,0x30
   140007402:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007405:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007409:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000740d:	48 89 c1             	mov    rcx,rax
   140007410:	e8 c8 10 00 00       	call   1400084dd <__cmp_D2A>
   140007415:	85 c0                	test   eax,eax
   140007417:	0f 8f 71 ff ff ff    	jg     14000738e <__gdtoa+0x1124>
   14000741d:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007420:	8d 50 01             	lea    edx,[rax+0x1]
   140007423:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007426:	83 f8 39             	cmp    eax,0x39
   140007429:	0f 84 b0 00 00 00    	je     1400074df <__gdtoa+0x1275>
   14000742f:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007436:	eb 7a                	jmp    1400074b2 <__gdtoa+0x1248>
   140007438:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000743c:	7e 53                	jle    140007491 <__gdtoa+0x1227>
   14000743e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007442:	ba 01 00 00 00       	mov    edx,0x1
   140007447:	48 89 c1             	mov    rcx,rax
   14000744a:	e8 01 0f 00 00       	call   140008350 <__lshift_D2A>
   14000744f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007453:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007457:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000745b:	48 89 c1             	mov    rcx,rax
   14000745e:	e8 7a 10 00 00       	call   1400084dd <__cmp_D2A>
   140007463:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007466:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000746a:	7f 10                	jg     14000747c <__gdtoa+0x1212>
   14000746c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007470:	75 18                	jne    14000748a <__gdtoa+0x1220>
   140007472:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007475:	83 e0 01             	and    eax,0x1
   140007478:	85 c0                	test   eax,eax
   14000747a:	74 0e                	je     14000748a <__gdtoa+0x1220>
   14000747c:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000747f:	8d 50 01             	lea    edx,[rax+0x1]
   140007482:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007485:	83 f8 39             	cmp    eax,0x39
   140007488:	74 58                	je     1400074e2 <__gdtoa+0x1278>
   14000748a:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007491:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007495:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007498:	83 f8 01             	cmp    eax,0x1
   14000749b:	7f 0b                	jg     1400074a8 <__gdtoa+0x123e>
   14000749d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074a1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400074a4:	85 c0                	test   eax,eax
   1400074a6:	74 09                	je     1400074b1 <__gdtoa+0x1247>
   1400074a8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400074af:	eb 01                	jmp    1400074b2 <__gdtoa+0x1248>
   1400074b1:	90                   	nop
   1400074b2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400074b6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400074ba:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400074be:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400074c1:	88 10                	mov    BYTE PTR [rax],dl
   1400074c3:	e9 49 02 00 00       	jmp    140007711 <__gdtoa+0x14a7>
   1400074c8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074cc:	7e 52                	jle    140007520 <__gdtoa+0x12b6>
   1400074ce:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400074d2:	74 4c                	je     140007520 <__gdtoa+0x12b6>
   1400074d4:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400074d8:	75 24                	jne    1400074fe <__gdtoa+0x1294>
   1400074da:	eb 07                	jmp    1400074e3 <__gdtoa+0x1279>
   1400074dc:	90                   	nop
   1400074dd:	eb 04                	jmp    1400074e3 <__gdtoa+0x1279>
   1400074df:	90                   	nop
   1400074e0:	eb 01                	jmp    1400074e3 <__gdtoa+0x1279>
   1400074e2:	90                   	nop
   1400074e3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400074e7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400074eb:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400074ef:	c6 00 39             	mov    BYTE PTR [rax],0x39
   1400074f2:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400074f9:	e9 9d 01 00 00       	jmp    14000769b <__gdtoa+0x1431>
   1400074fe:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007505:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007508:	8d 48 01             	lea    ecx,[rax+0x1]
   14000750b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000750f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007513:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007517:	89 ca                	mov    edx,ecx
   140007519:	88 10                	mov    BYTE PTR [rax],dl
   14000751b:	e9 f1 01 00 00       	jmp    140007711 <__gdtoa+0x14a7>
   140007520:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007524:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007528:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000752c:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000752f:	88 10                	mov    BYTE PTR [rax],dl
   140007531:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007534:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140007537:	0f 84 ea 00 00 00    	je     140007627 <__gdtoa+0x13bd>
   14000753d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007541:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007547:	ba 0a 00 00 00       	mov    edx,0xa
   14000754c:	48 89 c1             	mov    rcx,rax
   14000754f:	e8 a5 08 00 00       	call   140007df9 <__multadd_D2A>
   140007554:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007558:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000755c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007560:	75 25                	jne    140007587 <__gdtoa+0x131d>
   140007562:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007566:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000756c:	ba 0a 00 00 00       	mov    edx,0xa
   140007571:	48 89 c1             	mov    rcx,rax
   140007574:	e8 80 08 00 00       	call   140007df9 <__multadd_D2A>
   140007579:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000757d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007581:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007585:	eb 36                	jmp    1400075bd <__gdtoa+0x1353>
   140007587:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000758b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007591:	ba 0a 00 00 00       	mov    edx,0xa
   140007596:	48 89 c1             	mov    rcx,rax
   140007599:	e8 5b 08 00 00       	call   140007df9 <__multadd_D2A>
   14000759e:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400075a2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400075a6:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075ac:	ba 0a 00 00 00       	mov    edx,0xa
   1400075b1:	48 89 c1             	mov    rcx,rax
   1400075b4:	e8 40 08 00 00       	call   140007df9 <__multadd_D2A>
   1400075b9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400075bd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400075c0:	83 c0 01             	add    eax,0x1
   1400075c3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400075c6:	e9 71 fc ff ff       	jmp    14000723c <__gdtoa+0xfd2>
   1400075cb:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400075d2:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400075d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075da:	48 89 c1             	mov    rcx,rax
   1400075dd:	e8 cc e8 ff ff       	call   140005eae <__quorem_D2A>
   1400075e2:	83 c0 30             	add    eax,0x30
   1400075e5:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400075e8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075ec:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075f0:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075f4:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400075f7:	88 10                	mov    BYTE PTR [rax],dl
   1400075f9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400075fc:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   1400075ff:	7e 29                	jle    14000762a <__gdtoa+0x13c0>
   140007601:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007605:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000760b:	ba 0a 00 00 00       	mov    edx,0xa
   140007610:	48 89 c1             	mov    rcx,rax
   140007613:	e8 e1 07 00 00       	call   140007df9 <__multadd_D2A>
   140007618:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000761c:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000761f:	83 c0 01             	add    eax,0x1
   140007622:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007625:	eb ab                	jmp    1400075d2 <__gdtoa+0x1368>
   140007627:	90                   	nop
   140007628:	eb 01                	jmp    14000762b <__gdtoa+0x13c1>
   14000762a:	90                   	nop
   14000762b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000762f:	74 26                	je     140007657 <__gdtoa+0x13ed>
   140007631:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007635:	0f 84 ae 00 00 00    	je     1400076e9 <__gdtoa+0x147f>
   14000763b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000763f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007642:	83 f8 01             	cmp    eax,0x1
   140007645:	7f 50                	jg     140007697 <__gdtoa+0x142d>
   140007647:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000764b:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000764e:	85 c0                	test   eax,eax
   140007650:	75 45                	jne    140007697 <__gdtoa+0x142d>
   140007652:	e9 92 00 00 00       	jmp    1400076e9 <__gdtoa+0x147f>
   140007657:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000765b:	ba 01 00 00 00       	mov    edx,0x1
   140007660:	48 89 c1             	mov    rcx,rax
   140007663:	e8 e8 0c 00 00       	call   140008350 <__lshift_D2A>
   140007668:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000766c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007670:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007674:	48 89 c1             	mov    rcx,rax
   140007677:	e8 61 0e 00 00       	call   1400084dd <__cmp_D2A>
   14000767c:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   14000767f:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007683:	7f 15                	jg     14000769a <__gdtoa+0x1430>
   140007685:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007689:	75 61                	jne    1400076ec <__gdtoa+0x1482>
   14000768b:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000768e:	83 e0 01             	and    eax,0x1
   140007691:	85 c0                	test   eax,eax
   140007693:	74 5a                	je     1400076ef <__gdtoa+0x1485>
   140007695:	eb 04                	jmp    14000769b <__gdtoa+0x1431>
   140007697:	90                   	nop
   140007698:	eb 01                	jmp    14000769b <__gdtoa+0x1431>
   14000769a:	90                   	nop
   14000769b:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400076a2:	eb 1f                	jmp    1400076c3 <__gdtoa+0x1459>
   1400076a4:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076a8:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400076ac:	75 15                	jne    1400076c3 <__gdtoa+0x1459>
   1400076ae:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400076b2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076b6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076ba:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076be:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400076c1:	eb 4e                	jmp    140007711 <__gdtoa+0x14a7>
   1400076c3:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   1400076c8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076cc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400076cf:	3c 39                	cmp    al,0x39
   1400076d1:	74 d1                	je     1400076a4 <__gdtoa+0x143a>
   1400076d3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076d7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076db:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076df:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   1400076e2:	83 c2 01             	add    edx,0x1
   1400076e5:	88 10                	mov    BYTE PTR [rax],dl
   1400076e7:	eb 28                	jmp    140007711 <__gdtoa+0x14a7>
   1400076e9:	90                   	nop
   1400076ea:	eb 04                	jmp    1400076f0 <__gdtoa+0x1486>
   1400076ec:	90                   	nop
   1400076ed:	eb 01                	jmp    1400076f0 <__gdtoa+0x1486>
   1400076ef:	90                   	nop
   1400076f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076f4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400076f7:	83 f8 01             	cmp    eax,0x1
   1400076fa:	7f 0b                	jg     140007707 <__gdtoa+0x149d>
   1400076fc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007700:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007703:	85 c0                	test   eax,eax
   140007705:	74 09                	je     140007710 <__gdtoa+0x14a6>
   140007707:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000770e:	eb 01                	jmp    140007711 <__gdtoa+0x14a7>
   140007710:	90                   	nop
   140007711:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007715:	48 89 c1             	mov    rcx,rax
   140007718:	e8 51 06 00 00       	call   140007d6e <__Bfree_D2A>
   14000771d:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140007722:	74 31                	je     140007755 <__gdtoa+0x14eb>
   140007724:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140007729:	74 16                	je     140007741 <__gdtoa+0x14d7>
   14000772b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000772f:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007733:	74 0c                	je     140007741 <__gdtoa+0x14d7>
   140007735:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007739:	48 89 c1             	mov    rcx,rax
   14000773c:	e8 2d 06 00 00       	call   140007d6e <__Bfree_D2A>
   140007741:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007745:	48 89 c1             	mov    rcx,rax
   140007748:	e8 21 06 00 00       	call   140007d6e <__Bfree_D2A>
   14000774d:	eb 0e                	jmp    14000775d <__gdtoa+0x14f3>
   14000774f:	90                   	nop
   140007750:	eb 0b                	jmp    14000775d <__gdtoa+0x14f3>
   140007752:	90                   	nop
   140007753:	eb 08                	jmp    14000775d <__gdtoa+0x14f3>
   140007755:	90                   	nop
   140007756:	eb 05                	jmp    14000775d <__gdtoa+0x14f3>
   140007758:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000775d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007761:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140007765:	73 0f                	jae    140007776 <__gdtoa+0x150c>
   140007767:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000776b:	48 83 e8 01          	sub    rax,0x1
   14000776f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140007772:	3c 30                	cmp    al,0x30
   140007774:	74 e2                	je     140007758 <__gdtoa+0x14ee>
   140007776:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000777a:	48 89 c1             	mov    rcx,rax
   14000777d:	e8 ec 05 00 00       	call   140007d6e <__Bfree_D2A>
   140007782:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007786:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140007789:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000778c:	8d 50 01             	lea    edx,[rax+0x1]
   14000778f:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140007796:	89 10                	mov    DWORD PTR [rax],edx
   140007798:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   14000779f:	00 
   1400077a0:	74 0e                	je     1400077b0 <__gdtoa+0x1546>
   1400077a2:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400077a9:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   1400077ad:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400077b0:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400077b7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400077b9:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   1400077bc:	89 c2                	mov    edx,eax
   1400077be:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400077c5:	89 10                	mov    DWORD PTR [rax],edx
   1400077c7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400077cb:	48 81 c4 00 01 00 00 	add    rsp,0x100
   1400077d2:	5d                   	pop    rbp
   1400077d3:	c3                   	ret
   1400077d4:	90                   	nop
   1400077d5:	90                   	nop
   1400077d6:	90                   	nop
   1400077d7:	90                   	nop
   1400077d8:	90                   	nop
   1400077d9:	90                   	nop
   1400077da:	90                   	nop
   1400077db:	90                   	nop
   1400077dc:	90                   	nop
   1400077dd:	90                   	nop
   1400077de:	90                   	nop
   1400077df:	90                   	nop

00000001400077e0 <__lo0bits_D2A>:
   1400077e0:	55                   	push   rbp
   1400077e1:	48 89 e5             	mov    rbp,rsp
   1400077e4:	48 83 ec 10          	sub    rsp,0x10
   1400077e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400077ec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400077f0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400077f2:	f3 0f bc c0          	tzcnt  eax,eax
   1400077f6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400077f9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400077fd:	8b 10                	mov    edx,DWORD PTR [rax]
   1400077ff:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007802:	89 c1                	mov    ecx,eax
   140007804:	d3 ea                	shr    edx,cl
   140007806:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000780a:	89 10                	mov    DWORD PTR [rax],edx
   14000780c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000780f:	48 83 c4 10          	add    rsp,0x10
   140007813:	5d                   	pop    rbp
   140007814:	c3                   	ret

0000000140007815 <__rshift_D2A>:
   140007815:	55                   	push   rbp
   140007816:	48 89 e5             	mov    rbp,rsp
   140007819:	48 83 ec 20          	sub    rsp,0x20
   14000781d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007821:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007824:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007828:	48 83 c0 18          	add    rax,0x18
   14000782c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007830:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007834:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007838:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000783b:	c1 f8 05             	sar    eax,0x5
   14000783e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007841:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007845:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007848:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   14000784b:	0f 8d e4 00 00 00    	jge    140007935 <__rshift_D2A+0x120>
   140007851:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007855:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007858:	48 98                	cdqe
   14000785a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007861:	00 
   140007862:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007866:	48 01 d0             	add    rax,rdx
   140007869:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000786d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007870:	48 98                	cdqe
   140007872:	48 c1 e0 02          	shl    rax,0x2
   140007876:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   14000787a:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000787e:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140007882:	0f 84 a3 00 00 00    	je     14000792b <__rshift_D2A+0x116>
   140007888:	b8 20 00 00 00       	mov    eax,0x20
   14000788d:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   140007890:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007893:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007897:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000789b:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000789f:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078a1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400078a4:	89 c1                	mov    ecx,eax
   1400078a6:	d3 ea                	shr    edx,cl
   1400078a8:	89 d0                	mov    eax,edx
   1400078aa:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400078ad:	eb 3c                	jmp    1400078eb <__rshift_D2A+0xd6>
   1400078af:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078b3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078b5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400078b8:	89 c1                	mov    ecx,eax
   1400078ba:	d3 e2                	shl    edx,cl
   1400078bc:	89 d1                	mov    ecx,edx
   1400078be:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400078c2:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400078c6:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400078ca:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   1400078cd:	89 ca                	mov    edx,ecx
   1400078cf:	89 10                	mov    DWORD PTR [rax],edx
   1400078d1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078d5:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400078d9:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400078dd:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078df:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400078e2:	89 c1                	mov    ecx,eax
   1400078e4:	d3 ea                	shr    edx,cl
   1400078e6:	89 d0                	mov    eax,edx
   1400078e8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400078eb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078ef:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   1400078f3:	72 ba                	jb     1400078af <__rshift_D2A+0x9a>
   1400078f5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400078f9:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400078fc:	89 10                	mov    DWORD PTR [rax],edx
   1400078fe:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007902:	8b 00                	mov    eax,DWORD PTR [rax]
   140007904:	85 c0                	test   eax,eax
   140007906:	74 2d                	je     140007935 <__rshift_D2A+0x120>
   140007908:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   14000790d:	eb 26                	jmp    140007935 <__rshift_D2A+0x120>
   14000790f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140007913:	48 8d 42 04          	lea    rax,[rdx+0x4]
   140007917:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000791b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000791f:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140007923:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   140007927:	8b 12                	mov    edx,DWORD PTR [rdx]
   140007929:	89 10                	mov    DWORD PTR [rax],edx
   14000792b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000792f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007933:	72 da                	jb     14000790f <__rshift_D2A+0xfa>
   140007935:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007939:	48 83 c0 18          	add    rax,0x18
   14000793d:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140007941:	48 29 c2             	sub    rdx,rax
   140007944:	48 89 d0             	mov    rax,rdx
   140007947:	48 c1 f8 02          	sar    rax,0x2
   14000794b:	89 c2                	mov    edx,eax
   14000794d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007951:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007954:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007958:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000795b:	85 c0                	test   eax,eax
   14000795d:	75 0b                	jne    14000796a <__rshift_D2A+0x155>
   14000795f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007963:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000796a:	90                   	nop
   14000796b:	48 83 c4 20          	add    rsp,0x20
   14000796f:	5d                   	pop    rbp
   140007970:	c3                   	ret

0000000140007971 <__trailz_D2A>:
   140007971:	55                   	push   rbp
   140007972:	48 89 e5             	mov    rbp,rsp
   140007975:	48 83 ec 40          	sub    rsp,0x40
   140007979:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000797d:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007984:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007988:	48 83 c0 18          	add    rax,0x18
   14000798c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007990:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007994:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007997:	48 98                	cdqe
   140007999:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400079a0:	00 
   1400079a1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079a5:	48 01 d0             	add    rax,rdx
   1400079a8:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400079ac:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400079b3:	eb 09                	jmp    1400079be <__trailz_D2A+0x4d>
   1400079b5:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   1400079b9:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   1400079be:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079c2:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400079c6:	73 0a                	jae    1400079d2 <__trailz_D2A+0x61>
   1400079c8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079cc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400079ce:	85 c0                	test   eax,eax
   1400079d0:	74 e3                	je     1400079b5 <__trailz_D2A+0x44>
   1400079d2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079d6:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400079da:	73 18                	jae    1400079f4 <__trailz_D2A+0x83>
   1400079dc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079e0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400079e2:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400079e5:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   1400079e9:	48 89 c1             	mov    rcx,rax
   1400079ec:	e8 ef fd ff ff       	call   1400077e0 <__lo0bits_D2A>
   1400079f1:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   1400079f4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400079f7:	48 83 c4 40          	add    rsp,0x40
   1400079fb:	5d                   	pop    rbp
   1400079fc:	c3                   	ret
   1400079fd:	90                   	nop
   1400079fe:	90                   	nop
   1400079ff:	90                   	nop

0000000140007a00 <dtoa_lock_cleanup>:
   140007a00:	55                   	push   rbp
   140007a01:	48 89 e5             	mov    rbp,rsp
   140007a04:	48 83 ec 40          	sub    rsp,0x40
   140007a08:	48 8d 05 e1 77 00 00 	lea    rax,[rip+0x77e1]        # 14000f1f0 <dtoa_CS_init>
   140007a0f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007a13:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007a1a:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007a1d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a21:	87 10                	xchg   DWORD PTR [rax],edx
   140007a23:	89 d0                	mov    eax,edx
   140007a25:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007a28:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007a2c:	75 3d                	jne    140007a6b <dtoa_lock_cleanup+0x6b>
   140007a2e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007a35:	eb 2e                	jmp    140007a65 <dtoa_lock_cleanup+0x65>
   140007a37:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007a3a:	48 63 d0             	movsxd rdx,eax
   140007a3d:	48 89 d0             	mov    rax,rdx
   140007a40:	48 c1 e0 02          	shl    rax,0x2
   140007a44:	48 01 d0             	add    rax,rdx
   140007a47:	48 c1 e0 03          	shl    rax,0x3
   140007a4b:	48 8d 15 4e 77 00 00 	lea    rdx,[rip+0x774e]        # 14000f1a0 <dtoa_CritSec>
   140007a52:	48 01 d0             	add    rax,rdx
   140007a55:	48 89 c1             	mov    rcx,rax
   140007a58:	48 8b 05 81 87 00 00 	mov    rax,QWORD PTR [rip+0x8781]        # 1400101e0 <__IAT_start__>
   140007a5f:	ff d0                	call   rax
   140007a61:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007a65:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007a69:	7e cc                	jle    140007a37 <dtoa_lock_cleanup+0x37>
   140007a6b:	90                   	nop
   140007a6c:	48 83 c4 40          	add    rsp,0x40
   140007a70:	5d                   	pop    rbp
   140007a71:	c3                   	ret

0000000140007a72 <dtoa_lock>:
   140007a72:	55                   	push   rbp
   140007a73:	48 89 e5             	mov    rbp,rsp
   140007a76:	48 83 ec 40          	sub    rsp,0x40
   140007a7a:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007a7d:	8b 05 6d 77 00 00    	mov    eax,DWORD PTR [rip+0x776d]        # 14000f1f0 <dtoa_CS_init>
   140007a83:	83 f8 02             	cmp    eax,0x2
   140007a86:	75 2c                	jne    140007ab4 <dtoa_lock+0x42>
   140007a88:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007a8b:	48 89 d0             	mov    rax,rdx
   140007a8e:	48 c1 e0 02          	shl    rax,0x2
   140007a92:	48 01 d0             	add    rax,rdx
   140007a95:	48 c1 e0 03          	shl    rax,0x3
   140007a99:	48 8d 15 00 77 00 00 	lea    rdx,[rip+0x7700]        # 14000f1a0 <dtoa_CritSec>
   140007aa0:	48 01 d0             	add    rax,rdx
   140007aa3:	48 89 c1             	mov    rcx,rax
   140007aa6:	48 8b 05 3b 87 00 00 	mov    rax,QWORD PTR [rip+0x873b]        # 1400101e8 <__imp_EnterCriticalSection>
   140007aad:	ff d0                	call   rax
   140007aaf:	e9 ea 00 00 00       	jmp    140007b9e <dtoa_lock+0x12c>
   140007ab4:	8b 05 36 77 00 00    	mov    eax,DWORD PTR [rip+0x7736]        # 14000f1f0 <dtoa_CS_init>
   140007aba:	85 c0                	test   eax,eax
   140007abc:	0f 85 9e 00 00 00    	jne    140007b60 <dtoa_lock+0xee>
   140007ac2:	48 8d 05 27 77 00 00 	lea    rax,[rip+0x7727]        # 14000f1f0 <dtoa_CS_init>
   140007ac9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007acd:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007ad4:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007ad7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007adb:	87 10                	xchg   DWORD PTR [rax],edx
   140007add:	89 d0                	mov    eax,edx
   140007adf:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007ae2:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007ae6:	75 58                	jne    140007b40 <dtoa_lock+0xce>
   140007ae8:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007aef:	eb 2e                	jmp    140007b1f <dtoa_lock+0xad>
   140007af1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007af4:	48 63 d0             	movsxd rdx,eax
   140007af7:	48 89 d0             	mov    rax,rdx
   140007afa:	48 c1 e0 02          	shl    rax,0x2
   140007afe:	48 01 d0             	add    rax,rdx
   140007b01:	48 c1 e0 03          	shl    rax,0x3
   140007b05:	48 8d 15 94 76 00 00 	lea    rdx,[rip+0x7694]        # 14000f1a0 <dtoa_CritSec>
   140007b0c:	48 01 d0             	add    rax,rdx
   140007b0f:	48 89 c1             	mov    rcx,rax
   140007b12:	48 8b 05 ff 86 00 00 	mov    rax,QWORD PTR [rip+0x86ff]        # 140010218 <__imp_InitializeCriticalSection>
   140007b19:	ff d0                	call   rax
   140007b1b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b1f:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b23:	7e cc                	jle    140007af1 <dtoa_lock+0x7f>
   140007b25:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007a00 <dtoa_lock_cleanup>
   140007b2c:	48 89 c1             	mov    rcx,rax
   140007b2f:	e8 fb 9a ff ff       	call   14000162f <atexit>
   140007b34:	c7 05 b2 76 00 00 02 	mov    DWORD PTR [rip+0x76b2],0x2        # 14000f1f0 <dtoa_CS_init>
   140007b3b:	00 00 00 
   140007b3e:	eb 20                	jmp    140007b60 <dtoa_lock+0xee>
   140007b40:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007b44:	75 1a                	jne    140007b60 <dtoa_lock+0xee>
   140007b46:	c7 05 a0 76 00 00 02 	mov    DWORD PTR [rip+0x76a0],0x2        # 14000f1f0 <dtoa_CS_init>
   140007b4d:	00 00 00 
   140007b50:	eb 0e                	jmp    140007b60 <dtoa_lock+0xee>
   140007b52:	b9 01 00 00 00       	mov    ecx,0x1
   140007b57:	48 8b 05 e2 86 00 00 	mov    rax,QWORD PTR [rip+0x86e2]        # 140010240 <__imp_Sleep>
   140007b5e:	ff d0                	call   rax
   140007b60:	8b 05 8a 76 00 00    	mov    eax,DWORD PTR [rip+0x768a]        # 14000f1f0 <dtoa_CS_init>
   140007b66:	83 f8 01             	cmp    eax,0x1
   140007b69:	74 e7                	je     140007b52 <dtoa_lock+0xe0>
   140007b6b:	8b 05 7f 76 00 00    	mov    eax,DWORD PTR [rip+0x767f]        # 14000f1f0 <dtoa_CS_init>
   140007b71:	83 f8 02             	cmp    eax,0x2
   140007b74:	75 28                	jne    140007b9e <dtoa_lock+0x12c>
   140007b76:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007b79:	48 89 d0             	mov    rax,rdx
   140007b7c:	48 c1 e0 02          	shl    rax,0x2
   140007b80:	48 01 d0             	add    rax,rdx
   140007b83:	48 c1 e0 03          	shl    rax,0x3
   140007b87:	48 8d 15 12 76 00 00 	lea    rdx,[rip+0x7612]        # 14000f1a0 <dtoa_CritSec>
   140007b8e:	48 01 d0             	add    rax,rdx
   140007b91:	48 89 c1             	mov    rcx,rax
   140007b94:	48 8b 05 4d 86 00 00 	mov    rax,QWORD PTR [rip+0x864d]        # 1400101e8 <__imp_EnterCriticalSection>
   140007b9b:	ff d0                	call   rax
   140007b9d:	90                   	nop
   140007b9e:	48 83 c4 40          	add    rsp,0x40
   140007ba2:	5d                   	pop    rbp
   140007ba3:	c3                   	ret

0000000140007ba4 <dtoa_unlock>:
   140007ba4:	55                   	push   rbp
   140007ba5:	48 89 e5             	mov    rbp,rsp
   140007ba8:	48 83 ec 20          	sub    rsp,0x20
   140007bac:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007baf:	8b 05 3b 76 00 00    	mov    eax,DWORD PTR [rip+0x763b]        # 14000f1f0 <dtoa_CS_init>
   140007bb5:	83 f8 02             	cmp    eax,0x2
   140007bb8:	75 27                	jne    140007be1 <dtoa_unlock+0x3d>
   140007bba:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007bbd:	48 89 d0             	mov    rax,rdx
   140007bc0:	48 c1 e0 02          	shl    rax,0x2
   140007bc4:	48 01 d0             	add    rax,rdx
   140007bc7:	48 c1 e0 03          	shl    rax,0x3
   140007bcb:	48 8d 15 ce 75 00 00 	lea    rdx,[rip+0x75ce]        # 14000f1a0 <dtoa_CritSec>
   140007bd2:	48 01 d0             	add    rax,rdx
   140007bd5:	48 89 c1             	mov    rcx,rax
   140007bd8:	48 8b 05 41 86 00 00 	mov    rax,QWORD PTR [rip+0x8641]        # 140010220 <__imp_LeaveCriticalSection>
   140007bdf:	ff d0                	call   rax
   140007be1:	90                   	nop
   140007be2:	48 83 c4 20          	add    rsp,0x20
   140007be6:	5d                   	pop    rbp
   140007be7:	c3                   	ret

0000000140007be8 <__lo0bits_D2A>:
   140007be8:	55                   	push   rbp
   140007be9:	48 89 e5             	mov    rbp,rsp
   140007bec:	48 83 ec 10          	sub    rsp,0x10
   140007bf0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007bf4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007bf8:	8b 00                	mov    eax,DWORD PTR [rax]
   140007bfa:	f3 0f bc c0          	tzcnt  eax,eax
   140007bfe:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007c01:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c05:	8b 10                	mov    edx,DWORD PTR [rax]
   140007c07:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c0a:	89 c1                	mov    ecx,eax
   140007c0c:	d3 ea                	shr    edx,cl
   140007c0e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c12:	89 10                	mov    DWORD PTR [rax],edx
   140007c14:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c17:	48 83 c4 10          	add    rsp,0x10
   140007c1b:	5d                   	pop    rbp
   140007c1c:	c3                   	ret

0000000140007c1d <__hi0bits_D2A>:
   140007c1d:	55                   	push   rbp
   140007c1e:	48 89 e5             	mov    rbp,rsp
   140007c21:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c24:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007c28:	83 f0 1f             	xor    eax,0x1f
   140007c2b:	5d                   	pop    rbp
   140007c2c:	c3                   	ret

0000000140007c2d <__Balloc_D2A>:
   140007c2d:	55                   	push   rbp
   140007c2e:	48 89 e5             	mov    rbp,rsp
   140007c31:	48 83 ec 30          	sub    rsp,0x30
   140007c35:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c38:	b9 00 00 00 00       	mov    ecx,0x0
   140007c3d:	e8 30 fe ff ff       	call   140007a72 <dtoa_lock>
   140007c42:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007c46:	7f 48                	jg     140007c90 <__Balloc_D2A+0x63>
   140007c48:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007c4b:	48 98                	cdqe
   140007c4d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007c54:	00 
   140007c55:	48 8d 05 a4 75 00 00 	lea    rax,[rip+0x75a4]        # 14000f200 <freelist>
   140007c5c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007c60:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007c64:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007c69:	74 25                	je     140007c90 <__Balloc_D2A+0x63>
   140007c6b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007c6f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007c72:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c75:	48 63 d2             	movsxd rdx,edx
   140007c78:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007c7f:	00 
   140007c80:	48 8d 15 79 75 00 00 	lea    rdx,[rip+0x7579]        # 14000f200 <freelist>
   140007c87:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007c8b:	e9 b1 00 00 00       	jmp    140007d41 <__Balloc_D2A+0x114>
   140007c90:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007c93:	ba 01 00 00 00       	mov    edx,0x1
   140007c98:	89 c1                	mov    ecx,eax
   140007c9a:	d3 e2                	shl    edx,cl
   140007c9c:	89 d0                	mov    eax,edx
   140007c9e:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007ca1:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007ca4:	83 e8 01             	sub    eax,0x1
   140007ca7:	48 98                	cdqe
   140007ca9:	48 c1 e0 02          	shl    rax,0x2
   140007cad:	48 83 c0 27          	add    rax,0x27
   140007cb1:	48 c1 e8 03          	shr    rax,0x3
   140007cb5:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007cb8:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007cbc:	7f 4e                	jg     140007d0c <__Balloc_D2A+0xdf>
   140007cbe:	48 8b 15 cb 23 00 00 	mov    rdx,QWORD PTR [rip+0x23cb]        # 14000a090 <pmem_next>
   140007cc5:	48 8d 05 94 75 00 00 	lea    rax,[rip+0x7594]        # 14000f260 <private_mem>
   140007ccc:	48 29 c2             	sub    rdx,rax
   140007ccf:	48 89 d0             	mov    rax,rdx
   140007cd2:	48 c1 f8 03          	sar    rax,0x3
   140007cd6:	48 89 c2             	mov    rdx,rax
   140007cd9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007cdc:	48 01 d0             	add    rax,rdx
   140007cdf:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007ce5:	77 25                	ja     140007d0c <__Balloc_D2A+0xdf>
   140007ce7:	48 8b 05 a2 23 00 00 	mov    rax,QWORD PTR [rip+0x23a2]        # 14000a090 <pmem_next>
   140007cee:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007cf2:	48 8b 05 97 23 00 00 	mov    rax,QWORD PTR [rip+0x2397]        # 14000a090 <pmem_next>
   140007cf9:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007cfc:	48 c1 e2 03          	shl    rdx,0x3
   140007d00:	48 01 d0             	add    rax,rdx
   140007d03:	48 89 05 86 23 00 00 	mov    QWORD PTR [rip+0x2386],rax        # 14000a090 <pmem_next>
   140007d0a:	eb 21                	jmp    140007d2d <__Balloc_D2A+0x100>
   140007d0c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d0f:	48 c1 e0 03          	shl    rax,0x3
   140007d13:	48 89 c1             	mov    rcx,rax
   140007d16:	e8 b5 17 00 00       	call   1400094d0 <malloc>
   140007d1b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d1f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d24:	75 07                	jne    140007d2d <__Balloc_D2A+0x100>
   140007d26:	b8 00 00 00 00       	mov    eax,0x0
   140007d2b:	eb 3b                	jmp    140007d68 <__Balloc_D2A+0x13b>
   140007d2d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d31:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d34:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007d37:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d3b:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007d3e:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007d41:	b9 00 00 00 00       	mov    ecx,0x0
   140007d46:	e8 59 fe ff ff       	call   140007ba4 <dtoa_unlock>
   140007d4b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d4f:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007d56:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d5a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007d5d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d61:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007d64:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d68:	48 83 c4 30          	add    rsp,0x30
   140007d6c:	5d                   	pop    rbp
   140007d6d:	c3                   	ret

0000000140007d6e <__Bfree_D2A>:
   140007d6e:	55                   	push   rbp
   140007d6f:	48 89 e5             	mov    rbp,rsp
   140007d72:	48 83 ec 20          	sub    rsp,0x20
   140007d76:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007d7a:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007d7f:	74 71                	je     140007df2 <__Bfree_D2A+0x84>
   140007d81:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d85:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007d88:	83 f8 09             	cmp    eax,0x9
   140007d8b:	7e 0e                	jle    140007d9b <__Bfree_D2A+0x2d>
   140007d8d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d91:	48 89 c1             	mov    rcx,rax
   140007d94:	e8 27 17 00 00       	call   1400094c0 <free>
   140007d99:	eb 57                	jmp    140007df2 <__Bfree_D2A+0x84>
   140007d9b:	b9 00 00 00 00       	mov    ecx,0x0
   140007da0:	e8 cd fc ff ff       	call   140007a72 <dtoa_lock>
   140007da5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007da9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007dac:	48 98                	cdqe
   140007dae:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007db5:	00 
   140007db6:	48 8d 05 43 74 00 00 	lea    rax,[rip+0x7443]        # 14000f200 <freelist>
   140007dbd:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007dc1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007dc5:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007dc8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007dcc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007dcf:	48 98                	cdqe
   140007dd1:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007dd8:	00 
   140007dd9:	48 8d 15 20 74 00 00 	lea    rdx,[rip+0x7420]        # 14000f200 <freelist>
   140007de0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007de4:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007de8:	b9 00 00 00 00       	mov    ecx,0x0
   140007ded:	e8 b2 fd ff ff       	call   140007ba4 <dtoa_unlock>
   140007df2:	90                   	nop
   140007df3:	48 83 c4 20          	add    rsp,0x20
   140007df7:	5d                   	pop    rbp
   140007df8:	c3                   	ret

0000000140007df9 <__multadd_D2A>:
   140007df9:	55                   	push   rbp
   140007dfa:	48 89 e5             	mov    rbp,rsp
   140007dfd:	48 83 ec 50          	sub    rsp,0x50
   140007e01:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e05:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007e08:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007e0c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e10:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007e13:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007e16:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e1a:	48 83 c0 18          	add    rax,0x18
   140007e1e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007e22:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007e29:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007e2c:	48 98                	cdqe
   140007e2e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007e32:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007e36:	8b 00                	mov    eax,DWORD PTR [rax]
   140007e38:	89 c2                	mov    edx,eax
   140007e3a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007e3d:	48 98                	cdqe
   140007e3f:	48 0f af d0          	imul   rdx,rax
   140007e43:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007e47:	48 01 d0             	add    rax,rdx
   140007e4a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007e4e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007e52:	48 c1 e8 20          	shr    rax,0x20
   140007e56:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007e5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007e5e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007e62:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007e66:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007e6a:	89 10                	mov    DWORD PTR [rax],edx
   140007e6c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007e70:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007e73:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007e76:	7c ba                	jl     140007e32 <__multadd_D2A+0x39>
   140007e78:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007e7d:	0f 84 9a 00 00 00    	je     140007f1d <__multadd_D2A+0x124>
   140007e83:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e87:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007e8a:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007e8d:	7c 67                	jl     140007ef6 <__multadd_D2A+0xfd>
   140007e8f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e93:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e96:	83 c0 01             	add    eax,0x1
   140007e99:	89 c1                	mov    ecx,eax
   140007e9b:	e8 8d fd ff ff       	call   140007c2d <__Balloc_D2A>
   140007ea0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007ea4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007ea9:	75 07                	jne    140007eb2 <__multadd_D2A+0xb9>
   140007eab:	b8 00 00 00 00       	mov    eax,0x0
   140007eb0:	eb 6f                	jmp    140007f21 <__multadd_D2A+0x128>
   140007eb2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eb6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007eb9:	48 98                	cdqe
   140007ebb:	48 83 c0 02          	add    rax,0x2
   140007ebf:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007ec6:	00 
   140007ec7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ecb:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007ecf:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007ed3:	48 83 c0 10          	add    rax,0x10
   140007ed7:	49 89 c8             	mov    r8,rcx
   140007eda:	48 89 c1             	mov    rcx,rax
   140007edd:	e8 f6 15 00 00       	call   1400094d8 <memcpy>
   140007ee2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ee6:	48 89 c1             	mov    rcx,rax
   140007ee9:	e8 80 fe ff ff       	call   140007d6e <__Bfree_D2A>
   140007eee:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007ef2:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007ef6:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007ef9:	8d 50 01             	lea    edx,[rax+0x1]
   140007efc:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007eff:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140007f03:	89 d1                	mov    ecx,edx
   140007f05:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007f09:	48 98                	cdqe
   140007f0b:	48 83 c0 04          	add    rax,0x4
   140007f0f:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140007f13:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f17:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140007f1a:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007f1d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f21:	48 83 c4 50          	add    rsp,0x50
   140007f25:	5d                   	pop    rbp
   140007f26:	c3                   	ret

0000000140007f27 <__i2b_D2A>:
   140007f27:	55                   	push   rbp
   140007f28:	48 89 e5             	mov    rbp,rsp
   140007f2b:	48 83 ec 30          	sub    rsp,0x30
   140007f2f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007f32:	b9 01 00 00 00       	mov    ecx,0x1
   140007f37:	e8 f1 fc ff ff       	call   140007c2d <__Balloc_D2A>
   140007f3c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007f40:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007f45:	75 07                	jne    140007f4e <__i2b_D2A+0x27>
   140007f47:	b8 00 00 00 00       	mov    eax,0x0
   140007f4c:	eb 19                	jmp    140007f67 <__i2b_D2A+0x40>
   140007f4e:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007f51:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f55:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140007f58:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f5c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140007f63:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f67:	48 83 c4 30          	add    rsp,0x30
   140007f6b:	5d                   	pop    rbp
   140007f6c:	c3                   	ret

0000000140007f6d <__mult_D2A>:
   140007f6d:	55                   	push   rbp
   140007f6e:	48 89 e5             	mov    rbp,rsp
   140007f71:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140007f78:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007f7c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140007f80:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f84:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007f87:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007f8b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f8e:	39 c2                	cmp    edx,eax
   140007f90:	7d 18                	jge    140007faa <__mult_D2A+0x3d>
   140007f92:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f96:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140007f9a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007f9e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007fa2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140007fa6:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007faa:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fae:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007fb1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007fb4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fb8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fbb:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   140007fbe:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007fc2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fc5:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   140007fc8:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140007fcb:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140007fce:	01 d0                	add    eax,edx
   140007fd0:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007fd3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fd7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007fda:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   140007fdd:	7e 04                	jle    140007fe3 <__mult_D2A+0x76>
   140007fdf:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007fe3:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007fe6:	89 c1                	mov    ecx,eax
   140007fe8:	e8 40 fc ff ff       	call   140007c2d <__Balloc_D2A>
   140007fed:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140007ff1:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   140007ff6:	75 0a                	jne    140008002 <__mult_D2A+0x95>
   140007ff8:	b8 00 00 00 00       	mov    eax,0x0
   140007ffd:	e9 88 01 00 00       	jmp    14000818a <__mult_D2A+0x21d>
   140008002:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008006:	48 83 c0 18          	add    rax,0x18
   14000800a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000800e:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008011:	48 98                	cdqe
   140008013:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000801a:	00 
   14000801b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000801f:	48 01 d0             	add    rax,rdx
   140008022:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140008026:	eb 0f                	jmp    140008037 <__mult_D2A+0xca>
   140008028:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000802c:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008032:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140008037:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000803b:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   14000803f:	72 e7                	jb     140008028 <__mult_D2A+0xbb>
   140008041:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008045:	48 83 c0 18          	add    rax,0x18
   140008049:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000804d:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008050:	48 98                	cdqe
   140008052:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008059:	00 
   14000805a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000805e:	48 01 d0             	add    rax,rdx
   140008061:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008065:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008069:	48 83 c0 18          	add    rax,0x18
   14000806d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008071:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140008074:	48 98                	cdqe
   140008076:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000807d:	00 
   14000807e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008082:	48 01 d0             	add    rax,rdx
   140008085:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   140008089:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000808d:	48 83 c0 18          	add    rax,0x18
   140008091:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008095:	e9 95 00 00 00       	jmp    14000812f <__mult_D2A+0x1c2>
   14000809a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000809e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400080a2:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400080a6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400080a8:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   1400080ab:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   1400080af:	74 79                	je     14000812a <__mult_D2A+0x1bd>
   1400080b1:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400080b5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400080b9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400080bd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400080c1:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400080c8:	00 
   1400080c9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080cd:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400080d1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400080d5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400080d7:	89 c2                	mov    edx,eax
   1400080d9:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   1400080dc:	48 0f af d0          	imul   rdx,rax
   1400080e0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400080e4:	8b 00                	mov    eax,DWORD PTR [rax]
   1400080e6:	89 c0                	mov    eax,eax
   1400080e8:	48 01 c2             	add    rdx,rax
   1400080eb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400080ef:	48 01 d0             	add    rax,rdx
   1400080f2:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   1400080f6:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   1400080fa:	48 c1 e8 20          	shr    rax,0x20
   1400080fe:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008102:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008106:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000810a:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000810e:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140008112:	89 10                	mov    DWORD PTR [rax],edx
   140008114:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008118:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   14000811c:	72 ab                	jb     1400080c9 <__mult_D2A+0x15c>
   14000811e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008122:	89 c2                	mov    edx,eax
   140008124:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008128:	89 10                	mov    DWORD PTR [rax],edx
   14000812a:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   14000812f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008133:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   140008137:	0f 82 5d ff ff ff    	jb     14000809a <__mult_D2A+0x12d>
   14000813d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008141:	48 83 c0 18          	add    rax,0x18
   140008145:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008149:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000814c:	48 98                	cdqe
   14000814e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008155:	00 
   140008156:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000815a:	48 01 d0             	add    rax,rdx
   14000815d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008161:	eb 04                	jmp    140008167 <__mult_D2A+0x1fa>
   140008163:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008167:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000816b:	7e 0f                	jle    14000817c <__mult_D2A+0x20f>
   14000816d:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008172:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008176:	8b 00                	mov    eax,DWORD PTR [rax]
   140008178:	85 c0                	test   eax,eax
   14000817a:	74 e7                	je     140008163 <__mult_D2A+0x1f6>
   14000817c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008180:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008183:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008186:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000818a:	48 81 c4 90 00 00 00 	add    rsp,0x90
   140008191:	5d                   	pop    rbp
   140008192:	c3                   	ret

0000000140008193 <__pow5mult_D2A>:
   140008193:	55                   	push   rbp
   140008194:	48 89 e5             	mov    rbp,rsp
   140008197:	48 83 ec 40          	sub    rsp,0x40
   14000819b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000819f:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400081a2:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400081a5:	83 e0 03             	and    eax,0x3
   1400081a8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400081ab:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400081af:	74 41                	je     1400081f2 <__pow5mult_D2A+0x5f>
   1400081b1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400081b4:	83 e8 01             	sub    eax,0x1
   1400081b7:	48 98                	cdqe
   1400081b9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400081c0:	00 
   1400081c1:	48 8d 05 d0 1e 00 00 	lea    rax,[rip+0x1ed0]        # 14000a098 <p05.0>
   1400081c8:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   1400081cb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400081cf:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400081d5:	48 89 c1             	mov    rcx,rax
   1400081d8:	e8 1c fc ff ff       	call   140007df9 <__multadd_D2A>
   1400081dd:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400081e1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400081e6:	75 0a                	jne    1400081f2 <__pow5mult_D2A+0x5f>
   1400081e8:	b8 00 00 00 00       	mov    eax,0x0
   1400081ed:	e9 58 01 00 00       	jmp    14000834a <__pow5mult_D2A+0x1b7>
   1400081f2:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   1400081f6:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400081fa:	75 09                	jne    140008205 <__pow5mult_D2A+0x72>
   1400081fc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008200:	e9 45 01 00 00       	jmp    14000834a <__pow5mult_D2A+0x1b7>
   140008205:	48 8b 05 54 79 00 00 	mov    rax,QWORD PTR [rip+0x7954]        # 14000fb60 <p5s>
   14000820c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008210:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008215:	75 5e                	jne    140008275 <__pow5mult_D2A+0xe2>
   140008217:	b9 01 00 00 00       	mov    ecx,0x1
   14000821c:	e8 51 f8 ff ff       	call   140007a72 <dtoa_lock>
   140008221:	48 8b 05 38 79 00 00 	mov    rax,QWORD PTR [rip+0x7938]        # 14000fb60 <p5s>
   140008228:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000822c:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008231:	75 38                	jne    14000826b <__pow5mult_D2A+0xd8>
   140008233:	b9 71 02 00 00       	mov    ecx,0x271
   140008238:	e8 ea fc ff ff       	call   140007f27 <__i2b_D2A>
   14000823d:	48 89 05 1c 79 00 00 	mov    QWORD PTR [rip+0x791c],rax        # 14000fb60 <p5s>
   140008244:	48 8b 05 15 79 00 00 	mov    rax,QWORD PTR [rip+0x7915]        # 14000fb60 <p5s>
   14000824b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000824f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008254:	75 0a                	jne    140008260 <__pow5mult_D2A+0xcd>
   140008256:	b8 00 00 00 00       	mov    eax,0x0
   14000825b:	e9 ea 00 00 00       	jmp    14000834a <__pow5mult_D2A+0x1b7>
   140008260:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008264:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000826b:	b9 01 00 00 00       	mov    ecx,0x1
   140008270:	e8 2f f9 ff ff       	call   140007ba4 <dtoa_unlock>
   140008275:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008278:	83 e0 01             	and    eax,0x1
   14000827b:	85 c0                	test   eax,eax
   14000827d:	74 39                	je     1400082b8 <__pow5mult_D2A+0x125>
   14000827f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008283:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008287:	48 89 c1             	mov    rcx,rax
   14000828a:	e8 de fc ff ff       	call   140007f6d <__mult_D2A>
   14000828f:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008293:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   140008298:	75 0a                	jne    1400082a4 <__pow5mult_D2A+0x111>
   14000829a:	b8 00 00 00 00       	mov    eax,0x0
   14000829f:	e9 a6 00 00 00       	jmp    14000834a <__pow5mult_D2A+0x1b7>
   1400082a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082a8:	48 89 c1             	mov    rcx,rax
   1400082ab:	e8 be fa ff ff       	call   140007d6e <__Bfree_D2A>
   1400082b0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400082b4:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400082b8:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   1400082bb:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400082bf:	0f 84 80 00 00 00    	je     140008345 <__pow5mult_D2A+0x1b2>
   1400082c5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400082c9:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400082cc:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400082d0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400082d5:	75 61                	jne    140008338 <__pow5mult_D2A+0x1a5>
   1400082d7:	b9 01 00 00 00       	mov    ecx,0x1
   1400082dc:	e8 91 f7 ff ff       	call   140007a72 <dtoa_lock>
   1400082e1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400082e5:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400082e8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400082ec:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400082f1:	75 3b                	jne    14000832e <__pow5mult_D2A+0x19b>
   1400082f3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400082f7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400082fb:	48 89 c1             	mov    rcx,rax
   1400082fe:	e8 6a fc ff ff       	call   140007f6d <__mult_D2A>
   140008303:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008307:	48 89 02             	mov    QWORD PTR [rdx],rax
   14000830a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000830e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008311:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008315:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000831a:	75 07                	jne    140008323 <__pow5mult_D2A+0x190>
   14000831c:	b8 00 00 00 00       	mov    eax,0x0
   140008321:	eb 27                	jmp    14000834a <__pow5mult_D2A+0x1b7>
   140008323:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008327:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000832e:	b9 01 00 00 00       	mov    ecx,0x1
   140008333:	e8 6c f8 ff ff       	call   140007ba4 <dtoa_unlock>
   140008338:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000833c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008340:	e9 30 ff ff ff       	jmp    140008275 <__pow5mult_D2A+0xe2>
   140008345:	90                   	nop
   140008346:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000834a:	48 83 c4 40          	add    rsp,0x40
   14000834e:	5d                   	pop    rbp
   14000834f:	c3                   	ret

0000000140008350 <__lshift_D2A>:
   140008350:	55                   	push   rbp
   140008351:	48 89 e5             	mov    rbp,rsp
   140008354:	48 83 ec 60          	sub    rsp,0x60
   140008358:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000835c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000835f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008362:	c1 f8 05             	sar    eax,0x5
   140008365:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   140008368:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000836c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000836f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008372:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008376:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008379:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   14000837c:	01 d0                	add    eax,edx
   14000837e:	83 c0 01             	add    eax,0x1
   140008381:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008384:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008388:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000838b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000838e:	eb 07                	jmp    140008397 <__lshift_D2A+0x47>
   140008390:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140008394:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140008397:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000839a:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   14000839d:	7f f1                	jg     140008390 <__lshift_D2A+0x40>
   14000839f:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400083a2:	89 c1                	mov    ecx,eax
   1400083a4:	e8 84 f8 ff ff       	call   140007c2d <__Balloc_D2A>
   1400083a9:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400083ad:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400083b2:	75 0a                	jne    1400083be <__lshift_D2A+0x6e>
   1400083b4:	b8 00 00 00 00       	mov    eax,0x0
   1400083b9:	e9 19 01 00 00       	jmp    1400084d7 <__lshift_D2A+0x187>
   1400083be:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400083c2:	48 83 c0 18          	add    rax,0x18
   1400083c6:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400083ca:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400083d1:	eb 16                	jmp    1400083e9 <__lshift_D2A+0x99>
   1400083d3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400083d7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400083db:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400083df:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400083e5:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400083e9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400083ec:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   1400083ef:	7c e2                	jl     1400083d3 <__lshift_D2A+0x83>
   1400083f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083f5:	48 83 c0 18          	add    rax,0x18
   1400083f9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400083fd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008401:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008404:	48 98                	cdqe
   140008406:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000840d:	00 
   14000840e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008412:	48 01 d0             	add    rax,rdx
   140008415:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008419:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000841d:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140008421:	74 71                	je     140008494 <__lshift_D2A+0x144>
   140008423:	b8 20 00 00 00       	mov    eax,0x20
   140008428:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000842b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000842e:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   140008435:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008439:	8b 10                	mov    edx,DWORD PTR [rax]
   14000843b:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000843e:	89 c1                	mov    ecx,eax
   140008440:	d3 e2                	shl    edx,cl
   140008442:	89 d1                	mov    ecx,edx
   140008444:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008448:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000844c:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008450:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008453:	89 ca                	mov    edx,ecx
   140008455:	89 10                	mov    DWORD PTR [rax],edx
   140008457:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000845b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000845f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008463:	8b 10                	mov    edx,DWORD PTR [rax]
   140008465:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008468:	89 c1                	mov    ecx,eax
   14000846a:	d3 ea                	shr    edx,cl
   14000846c:	89 d0                	mov    eax,edx
   14000846e:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008471:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008475:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008479:	72 ba                	jb     140008435 <__lshift_D2A+0xe5>
   14000847b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000847f:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   140008482:	89 10                	mov    DWORD PTR [rax],edx
   140008484:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008488:	8b 00                	mov    eax,DWORD PTR [rax]
   14000848a:	85 c0                	test   eax,eax
   14000848c:	74 2c                	je     1400084ba <__lshift_D2A+0x16a>
   14000848e:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140008492:	eb 26                	jmp    1400084ba <__lshift_D2A+0x16a>
   140008494:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008498:	48 8d 42 04          	lea    rax,[rdx+0x4]
   14000849c:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400084a0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084a4:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400084a8:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   1400084ac:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400084ae:	89 10                	mov    DWORD PTR [rax],edx
   1400084b0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084b4:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400084b8:	72 da                	jb     140008494 <__lshift_D2A+0x144>
   1400084ba:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400084bd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400084c0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400084c4:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400084c7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084cb:	48 89 c1             	mov    rcx,rax
   1400084ce:	e8 9b f8 ff ff       	call   140007d6e <__Bfree_D2A>
   1400084d3:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400084d7:	48 83 c4 60          	add    rsp,0x60
   1400084db:	5d                   	pop    rbp
   1400084dc:	c3                   	ret

00000001400084dd <__cmp_D2A>:
   1400084dd:	55                   	push   rbp
   1400084de:	48 89 e5             	mov    rbp,rsp
   1400084e1:	48 83 ec 30          	sub    rsp,0x30
   1400084e5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400084e9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400084ed:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084f1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400084f4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400084f7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400084fb:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400084fe:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140008501:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008504:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   140008507:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000850b:	74 08                	je     140008515 <__cmp_D2A+0x38>
   14000850d:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008510:	e9 92 00 00 00       	jmp    1400085a7 <__cmp_D2A+0xca>
   140008515:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008519:	48 83 c0 18          	add    rax,0x18
   14000851d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008521:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008524:	48 98                	cdqe
   140008526:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000852d:	00 
   14000852e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008532:	48 01 d0             	add    rax,rdx
   140008535:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008539:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000853d:	48 83 c0 18          	add    rax,0x18
   140008541:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008545:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008548:	48 98                	cdqe
   14000854a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008551:	00 
   140008552:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008556:	48 01 d0             	add    rax,rdx
   140008559:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000855d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008562:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008566:	8b 10                	mov    edx,DWORD PTR [rax]
   140008568:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   14000856d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008571:	8b 00                	mov    eax,DWORD PTR [rax]
   140008573:	39 c2                	cmp    edx,eax
   140008575:	74 1e                	je     140008595 <__cmp_D2A+0xb8>
   140008577:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000857b:	8b 10                	mov    edx,DWORD PTR [rax]
   14000857d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008581:	8b 00                	mov    eax,DWORD PTR [rax]
   140008583:	39 c2                	cmp    edx,eax
   140008585:	73 07                	jae    14000858e <__cmp_D2A+0xb1>
   140008587:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000858c:	eb 19                	jmp    1400085a7 <__cmp_D2A+0xca>
   14000858e:	b8 01 00 00 00       	mov    eax,0x1
   140008593:	eb 12                	jmp    1400085a7 <__cmp_D2A+0xca>
   140008595:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008599:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000859d:	73 02                	jae    1400085a1 <__cmp_D2A+0xc4>
   14000859f:	eb bc                	jmp    14000855d <__cmp_D2A+0x80>
   1400085a1:	90                   	nop
   1400085a2:	b8 00 00 00 00       	mov    eax,0x0
   1400085a7:	48 83 c4 30          	add    rsp,0x30
   1400085ab:	5d                   	pop    rbp
   1400085ac:	c3                   	ret

00000001400085ad <__diff_D2A>:
   1400085ad:	55                   	push   rbp
   1400085ae:	48 89 e5             	mov    rbp,rsp
   1400085b1:	48 83 ec 70          	sub    rsp,0x70
   1400085b5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400085b9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400085bd:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400085c1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085c5:	48 89 c1             	mov    rcx,rax
   1400085c8:	e8 10 ff ff ff       	call   1400084dd <__cmp_D2A>
   1400085cd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400085d0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400085d4:	75 3e                	jne    140008614 <__diff_D2A+0x67>
   1400085d6:	b9 00 00 00 00       	mov    ecx,0x0
   1400085db:	e8 4d f6 ff ff       	call   140007c2d <__Balloc_D2A>
   1400085e0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400085e4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400085e9:	75 0a                	jne    1400085f5 <__diff_D2A+0x48>
   1400085eb:	b8 00 00 00 00       	mov    eax,0x0
   1400085f0:	e9 ab 01 00 00       	jmp    1400087a0 <__diff_D2A+0x1f3>
   1400085f5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400085f9:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008600:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008604:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000860b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000860f:	e9 8c 01 00 00       	jmp    1400087a0 <__diff_D2A+0x1f3>
   140008614:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008618:	79 21                	jns    14000863b <__diff_D2A+0x8e>
   14000861a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000861e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008622:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008626:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000862a:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000862e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140008632:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140008639:	eb 07                	jmp    140008642 <__diff_D2A+0x95>
   14000863b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008642:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008646:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008649:	89 c1                	mov    ecx,eax
   14000864b:	e8 dd f5 ff ff       	call   140007c2d <__Balloc_D2A>
   140008650:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008654:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008659:	75 0a                	jne    140008665 <__diff_D2A+0xb8>
   14000865b:	b8 00 00 00 00       	mov    eax,0x0
   140008660:	e9 3b 01 00 00       	jmp    1400087a0 <__diff_D2A+0x1f3>
   140008665:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008669:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000866c:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000866f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008673:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008676:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008679:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000867d:	48 83 c0 18          	add    rax,0x18
   140008681:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008685:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008688:	48 98                	cdqe
   14000868a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008691:	00 
   140008692:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008696:	48 01 d0             	add    rax,rdx
   140008699:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000869d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086a1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400086a4:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400086a7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086ab:	48 83 c0 18          	add    rax,0x18
   1400086af:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400086b3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   1400086b6:	48 98                	cdqe
   1400086b8:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400086bf:	00 
   1400086c0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400086c4:	48 01 d0             	add    rax,rdx
   1400086c7:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400086cb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086cf:	48 83 c0 18          	add    rax,0x18
   1400086d3:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400086d7:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   1400086de:	00 
   1400086df:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400086e3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400086e7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400086eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400086ed:	89 c1                	mov    ecx,eax
   1400086ef:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400086f3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400086f7:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400086fb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400086fd:	89 c2                	mov    edx,eax
   1400086ff:	48 89 c8             	mov    rax,rcx
   140008702:	48 29 d0             	sub    rax,rdx
   140008705:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140008709:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000870d:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008711:	48 c1 e8 20          	shr    rax,0x20
   140008715:	83 e0 01             	and    eax,0x1
   140008718:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000871c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008720:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008724:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008728:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000872c:	89 10                	mov    DWORD PTR [rax],edx
   14000872e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008732:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   140008736:	72 a7                	jb     1400086df <__diff_D2A+0x132>
   140008738:	eb 39                	jmp    140008773 <__diff_D2A+0x1c6>
   14000873a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000873e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008742:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008746:	8b 00                	mov    eax,DWORD PTR [rax]
   140008748:	89 c0                	mov    eax,eax
   14000874a:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   14000874e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008752:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008756:	48 c1 e8 20          	shr    rax,0x20
   14000875a:	83 e0 01             	and    eax,0x1
   14000875d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008761:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008765:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008769:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000876d:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140008771:	89 10                	mov    DWORD PTR [rax],edx
   140008773:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008777:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   14000877b:	72 bd                	jb     14000873a <__diff_D2A+0x18d>
   14000877d:	eb 04                	jmp    140008783 <__diff_D2A+0x1d6>
   14000877f:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008783:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008788:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000878c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000878e:	85 c0                	test   eax,eax
   140008790:	74 ed                	je     14000877f <__diff_D2A+0x1d2>
   140008792:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008796:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008799:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000879c:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087a0:	48 83 c4 70          	add    rsp,0x70
   1400087a4:	5d                   	pop    rbp
   1400087a5:	c3                   	ret

00000001400087a6 <__b2d_D2A>:
   1400087a6:	55                   	push   rbp
   1400087a7:	48 89 e5             	mov    rbp,rsp
   1400087aa:	48 83 ec 50          	sub    rsp,0x50
   1400087ae:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400087b2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400087b6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400087ba:	48 83 c0 18          	add    rax,0x18
   1400087be:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400087c2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400087c6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400087c9:	48 98                	cdqe
   1400087cb:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400087d2:	00 
   1400087d3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087d7:	48 01 d0             	add    rax,rdx
   1400087da:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400087de:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400087e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400087e7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087e9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400087ec:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400087ef:	89 c1                	mov    ecx,eax
   1400087f1:	e8 27 f4 ff ff       	call   140007c1d <__hi0bits_D2A>
   1400087f6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400087f9:	b8 20 00 00 00       	mov    eax,0x20
   1400087fe:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008801:	89 c2                	mov    edx,eax
   140008803:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008807:	89 10                	mov    DWORD PTR [rax],edx
   140008809:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   14000880d:	7f 66                	jg     140008875 <__b2d_D2A+0xcf>
   14000880f:	b8 0b 00 00 00       	mov    eax,0xb
   140008814:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008817:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000881a:	89 c1                	mov    ecx,eax
   14000881c:	d3 ea                	shr    edx,cl
   14000881e:	89 d0                	mov    eax,edx
   140008820:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008825:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008828:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000882c:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008830:	73 10                	jae    140008842 <__b2d_D2A+0x9c>
   140008832:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008837:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000883b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000883d:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008840:	eb 07                	jmp    140008849 <__b2d_D2A+0xa3>
   140008842:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140008849:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000884c:	83 c0 15             	add    eax,0x15
   14000884f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008852:	89 c1                	mov    ecx,eax
   140008854:	d3 e2                	shl    edx,cl
   140008856:	41 89 d0             	mov    r8d,edx
   140008859:	b8 0b 00 00 00       	mov    eax,0xb
   14000885e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008861:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140008864:	89 c1                	mov    ecx,eax
   140008866:	d3 ea                	shr    edx,cl
   140008868:	89 d0                	mov    eax,edx
   14000886a:	44 09 c0             	or     eax,r8d
   14000886d:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008870:	e9 ac 00 00 00       	jmp    140008921 <__b2d_D2A+0x17b>
   140008875:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008879:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000887d:	73 10                	jae    14000888f <__b2d_D2A+0xe9>
   14000887f:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008884:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008888:	8b 00                	mov    eax,DWORD PTR [rax]
   14000888a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000888d:	eb 07                	jmp    140008896 <__b2d_D2A+0xf0>
   14000888f:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   140008896:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   14000889a:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   14000889e:	74 70                	je     140008910 <__b2d_D2A+0x16a>
   1400088a0:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400088a3:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400088a6:	89 c1                	mov    ecx,eax
   1400088a8:	d3 e2                	shl    edx,cl
   1400088aa:	41 89 d0             	mov    r8d,edx
   1400088ad:	b8 20 00 00 00       	mov    eax,0x20
   1400088b2:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088b5:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400088b8:	89 c1                	mov    ecx,eax
   1400088ba:	d3 ea                	shr    edx,cl
   1400088bc:	89 d0                	mov    eax,edx
   1400088be:	44 09 c0             	or     eax,r8d
   1400088c1:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400088c6:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400088c9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088cd:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400088d1:	73 10                	jae    1400088e3 <__b2d_D2A+0x13d>
   1400088d3:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088d8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088dc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088de:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400088e1:	eb 07                	jmp    1400088ea <__b2d_D2A+0x144>
   1400088e3:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   1400088ea:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400088ed:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400088f0:	89 c1                	mov    ecx,eax
   1400088f2:	d3 e2                	shl    edx,cl
   1400088f4:	41 89 d0             	mov    r8d,edx
   1400088f7:	b8 20 00 00 00       	mov    eax,0x20
   1400088fc:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088ff:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008902:	89 c1                	mov    ecx,eax
   140008904:	d3 ea                	shr    edx,cl
   140008906:	89 d0                	mov    eax,edx
   140008908:	44 09 c0             	or     eax,r8d
   14000890b:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000890e:	eb 11                	jmp    140008921 <__b2d_D2A+0x17b>
   140008910:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008913:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008918:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000891b:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   14000891e:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008921:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   140008926:	48 83 c4 50          	add    rsp,0x50
   14000892a:	5d                   	pop    rbp
   14000892b:	c3                   	ret

000000014000892c <__d2b_D2A>:
   14000892c:	55                   	push   rbp
   14000892d:	53                   	push   rbx
   14000892e:	48 83 ec 58          	sub    rsp,0x58
   140008932:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140008937:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   14000893c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140008940:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140008944:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140008949:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   14000894e:	b9 01 00 00 00       	mov    ecx,0x1
   140008953:	e8 d5 f2 ff ff       	call   140007c2d <__Balloc_D2A>
   140008958:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000895c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008961:	75 0a                	jne    14000896d <__d2b_D2A+0x41>
   140008963:	b8 00 00 00 00       	mov    eax,0x0
   140008968:	e9 68 01 00 00       	jmp    140008ad5 <__d2b_D2A+0x1a9>
   14000896d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008971:	48 83 c0 18          	add    rax,0x18
   140008975:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008979:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000897c:	25 ff ff 0f 00       	and    eax,0xfffff
   140008981:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008984:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008987:	25 ff ff ff 7f       	and    eax,0x7fffffff
   14000898c:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   14000898f:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008992:	c1 e8 14             	shr    eax,0x14
   140008995:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140008998:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   14000899c:	74 0b                	je     1400089a9 <__d2b_D2A+0x7d>
   14000899e:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   1400089a1:	0d 00 00 10 00       	or     eax,0x100000
   1400089a6:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089a9:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   1400089ac:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089af:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400089b2:	85 c0                	test   eax,eax
   1400089b4:	74 7b                	je     140008a31 <__d2b_D2A+0x105>
   1400089b6:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   1400089ba:	48 89 c1             	mov    rcx,rax
   1400089bd:	e8 26 f2 ff ff       	call   140007be8 <__lo0bits_D2A>
   1400089c2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400089c5:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400089c9:	74 2b                	je     1400089f6 <__d2b_D2A+0xca>
   1400089cb:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   1400089ce:	b8 20 00 00 00       	mov    eax,0x20
   1400089d3:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   1400089d6:	89 c1                	mov    ecx,eax
   1400089d8:	d3 e2                	shl    edx,cl
   1400089da:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400089dd:	09 c2                	or     edx,eax
   1400089df:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400089e3:	89 10                	mov    DWORD PTR [rax],edx
   1400089e5:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   1400089e8:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400089eb:	89 c1                	mov    ecx,eax
   1400089ed:	d3 ea                	shr    edx,cl
   1400089ef:	89 d0                	mov    eax,edx
   1400089f1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089f4:	eb 09                	jmp    1400089ff <__d2b_D2A+0xd3>
   1400089f6:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   1400089f9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400089fd:	89 10                	mov    DWORD PTR [rax],edx
   1400089ff:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a03:	48 83 c0 04          	add    rax,0x4
   140008a07:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a0a:	89 10                	mov    DWORD PTR [rax],edx
   140008a0c:	8b 00                	mov    eax,DWORD PTR [rax]
   140008a0e:	85 c0                	test   eax,eax
   140008a10:	74 07                	je     140008a19 <__d2b_D2A+0xed>
   140008a12:	ba 02 00 00 00       	mov    edx,0x2
   140008a17:	eb 05                	jmp    140008a1e <__d2b_D2A+0xf2>
   140008a19:	ba 01 00 00 00       	mov    edx,0x1
   140008a1e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a22:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008a25:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a29:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008a2c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008a2f:	eb 31                	jmp    140008a62 <__d2b_D2A+0x136>
   140008a31:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008a35:	48 89 c1             	mov    rcx,rax
   140008a38:	e8 ab f1 ff ff       	call   140007be8 <__lo0bits_D2A>
   140008a3d:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008a40:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a43:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a47:	89 10                	mov    DWORD PTR [rax],edx
   140008a49:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a4d:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008a54:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a58:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008a5b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008a5e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008a62:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008a66:	74 26                	je     140008a8e <__d2b_D2A+0x162>
   140008a68:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008a6b:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008a71:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008a74:	01 c2                	add    edx,eax
   140008a76:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008a7a:	89 10                	mov    DWORD PTR [rax],edx
   140008a7c:	b8 35 00 00 00       	mov    eax,0x35
   140008a81:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008a84:	89 c2                	mov    edx,eax
   140008a86:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008a8a:	89 10                	mov    DWORD PTR [rax],edx
   140008a8c:	eb 43                	jmp    140008ad1 <__d2b_D2A+0x1a5>
   140008a8e:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008a91:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008a97:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008a9a:	01 c2                	add    edx,eax
   140008a9c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008aa0:	89 10                	mov    DWORD PTR [rax],edx
   140008aa2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008aa5:	c1 e0 05             	shl    eax,0x5
   140008aa8:	89 c3                	mov    ebx,eax
   140008aaa:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008aad:	48 98                	cdqe
   140008aaf:	48 c1 e0 02          	shl    rax,0x2
   140008ab3:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008ab7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008abb:	48 01 d0             	add    rax,rdx
   140008abe:	8b 00                	mov    eax,DWORD PTR [rax]
   140008ac0:	89 c1                	mov    ecx,eax
   140008ac2:	e8 56 f1 ff ff       	call   140007c1d <__hi0bits_D2A>
   140008ac7:	29 c3                	sub    ebx,eax
   140008ac9:	89 da                	mov    edx,ebx
   140008acb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008acf:	89 10                	mov    DWORD PTR [rax],edx
   140008ad1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ad5:	48 83 c4 58          	add    rsp,0x58
   140008ad9:	5b                   	pop    rbx
   140008ada:	5d                   	pop    rbp
   140008adb:	c3                   	ret

0000000140008adc <__strcp_D2A>:
   140008adc:	55                   	push   rbp
   140008add:	48 89 e5             	mov    rbp,rsp
   140008ae0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008ae4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008ae8:	eb 05                	jmp    140008aef <__strcp_D2A+0x13>
   140008aea:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008aef:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008af3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008af7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008afb:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008afe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b02:	88 10                	mov    BYTE PTR [rax],dl
   140008b04:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b08:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008b0b:	84 c0                	test   al,al
   140008b0d:	75 db                	jne    140008aea <__strcp_D2A+0xe>
   140008b0f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b13:	5d                   	pop    rbp
   140008b14:	c3                   	ret
   140008b15:	90                   	nop
   140008b16:	90                   	nop
   140008b17:	90                   	nop
   140008b18:	90                   	nop
   140008b19:	90                   	nop
   140008b1a:	90                   	nop
   140008b1b:	90                   	nop
   140008b1c:	90                   	nop
   140008b1d:	90                   	nop
   140008b1e:	90                   	nop
   140008b1f:	90                   	nop

0000000140008b20 <__fpclassify>:
   140008b20:	55                   	push   rbp
   140008b21:	48 89 e5             	mov    rbp,rsp
   140008b24:	48 83 ec 10          	sub    rsp,0x10
   140008b28:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008b2d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008b32:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008b37:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008b3a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b3d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008b40:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008b43:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008b49:	09 d0                	or     eax,edx
   140008b4b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008b4e:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008b55:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b58:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008b5b:	85 c0                	test   eax,eax
   140008b5d:	75 07                	jne    140008b66 <__fpclassify+0x46>
   140008b5f:	b8 00 40 00 00       	mov    eax,0x4000
   140008b64:	eb 2f                	jmp    140008b95 <__fpclassify+0x75>
   140008b66:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008b6a:	75 07                	jne    140008b73 <__fpclassify+0x53>
   140008b6c:	b8 00 44 00 00       	mov    eax,0x4400
   140008b71:	eb 22                	jmp    140008b95 <__fpclassify+0x75>
   140008b73:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008b7a:	75 14                	jne    140008b90 <__fpclassify+0x70>
   140008b7c:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008b80:	74 07                	je     140008b89 <__fpclassify+0x69>
   140008b82:	b8 00 01 00 00       	mov    eax,0x100
   140008b87:	eb 0c                	jmp    140008b95 <__fpclassify+0x75>
   140008b89:	b8 00 05 00 00       	mov    eax,0x500
   140008b8e:	eb 05                	jmp    140008b95 <__fpclassify+0x75>
   140008b90:	b8 00 04 00 00       	mov    eax,0x400
   140008b95:	48 83 c4 10          	add    rsp,0x10
   140008b99:	5d                   	pop    rbp
   140008b9a:	c3                   	ret
   140008b9b:	90                   	nop
   140008b9c:	90                   	nop
   140008b9d:	90                   	nop
   140008b9e:	90                   	nop
   140008b9f:	90                   	nop

0000000140008ba0 <__fpclassifyl>:
   140008ba0:	55                   	push   rbp
   140008ba1:	53                   	push   rbx
   140008ba2:	48 83 ec 38          	sub    rsp,0x38
   140008ba6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008bab:	48 89 cb             	mov    rbx,rcx
   140008bae:	db 2b                	fld    TBYTE PTR [rbx]
   140008bb0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008bb3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008bb6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008bb9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008bbd:	98                   	cwde
   140008bbe:	25 ff 7f 00 00       	and    eax,0x7fff
   140008bc3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008bc6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008bca:	75 25                	jne    140008bf1 <__fpclassifyl+0x51>
   140008bcc:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008bcf:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008bd2:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008bd5:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008bd8:	85 c0                	test   eax,eax
   140008bda:	75 07                	jne    140008be3 <__fpclassifyl+0x43>
   140008bdc:	b8 00 40 00 00       	mov    eax,0x4000
   140008be1:	eb 3d                	jmp    140008c20 <__fpclassifyl+0x80>
   140008be3:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008be6:	85 c0                	test   eax,eax
   140008be8:	78 31                	js     140008c1b <__fpclassifyl+0x7b>
   140008bea:	b8 00 44 00 00       	mov    eax,0x4400
   140008bef:	eb 2f                	jmp    140008c20 <__fpclassifyl+0x80>
   140008bf1:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008bf8:	75 21                	jne    140008c1b <__fpclassifyl+0x7b>
   140008bfa:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008bfd:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008c02:	89 c2                	mov    edx,eax
   140008c04:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c07:	09 d0                	or     eax,edx
   140008c09:	85 c0                	test   eax,eax
   140008c0b:	75 07                	jne    140008c14 <__fpclassifyl+0x74>
   140008c0d:	b8 00 05 00 00       	mov    eax,0x500
   140008c12:	eb 0c                	jmp    140008c20 <__fpclassifyl+0x80>
   140008c14:	b8 00 01 00 00       	mov    eax,0x100
   140008c19:	eb 05                	jmp    140008c20 <__fpclassifyl+0x80>
   140008c1b:	b8 00 04 00 00       	mov    eax,0x400
   140008c20:	48 83 c4 38          	add    rsp,0x38
   140008c24:	5b                   	pop    rbx
   140008c25:	5d                   	pop    rbp
   140008c26:	c3                   	ret
   140008c27:	90                   	nop
   140008c28:	90                   	nop
   140008c29:	90                   	nop
   140008c2a:	90                   	nop
   140008c2b:	90                   	nop
   140008c2c:	90                   	nop
   140008c2d:	90                   	nop
   140008c2e:	90                   	nop
   140008c2f:	90                   	nop

0000000140008c30 <__isnan>:
   140008c30:	55                   	push   rbp
   140008c31:	48 89 e5             	mov    rbp,rsp
   140008c34:	48 83 ec 10          	sub    rsp,0x10
   140008c38:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008c3d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008c42:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008c47:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008c4a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c4d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008c50:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008c55:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c58:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c5b:	f7 d8                	neg    eax
   140008c5d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008c60:	c1 e8 1f             	shr    eax,0x1f
   140008c63:	89 c2                	mov    edx,eax
   140008c65:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c68:	09 d0                	or     eax,edx
   140008c6a:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c6d:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008c72:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008c75:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c78:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c7b:	c1 f8 1f             	sar    eax,0x1f
   140008c7e:	48 83 c4 10          	add    rsp,0x10
   140008c82:	5d                   	pop    rbp
   140008c83:	c3                   	ret
   140008c84:	90                   	nop
   140008c85:	90                   	nop
   140008c86:	90                   	nop
   140008c87:	90                   	nop
   140008c88:	90                   	nop
   140008c89:	90                   	nop
   140008c8a:	90                   	nop
   140008c8b:	90                   	nop
   140008c8c:	90                   	nop
   140008c8d:	90                   	nop
   140008c8e:	90                   	nop
   140008c8f:	90                   	nop

0000000140008c90 <__isnanl>:
   140008c90:	55                   	push   rbp
   140008c91:	53                   	push   rbx
   140008c92:	48 83 ec 38          	sub    rsp,0x38
   140008c96:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008c9b:	48 89 cb             	mov    rbx,rcx
   140008c9e:	db 2b                	fld    TBYTE PTR [rbx]
   140008ca0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008ca3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008ca6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008ca9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008cad:	98                   	cwde
   140008cae:	01 c0                	add    eax,eax
   140008cb0:	25 ff ff 00 00       	and    eax,0xffff
   140008cb5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cb8:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008cbb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008cbe:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008cc4:	09 d0                	or     eax,edx
   140008cc6:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008cc9:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008ccc:	f7 d8                	neg    eax
   140008cce:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008cd1:	c1 e8 1f             	shr    eax,0x1f
   140008cd4:	89 c2                	mov    edx,eax
   140008cd6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008cd9:	09 d0                	or     eax,edx
   140008cdb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cde:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008ce3:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008ce6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008ce9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008cec:	c1 f8 10             	sar    eax,0x10
   140008cef:	48 83 c4 38          	add    rsp,0x38
   140008cf3:	5b                   	pop    rbx
   140008cf4:	5d                   	pop    rbp
   140008cf5:	c3                   	ret
   140008cf6:	90                   	nop
   140008cf7:	90                   	nop
   140008cf8:	90                   	nop
   140008cf9:	90                   	nop
   140008cfa:	90                   	nop
   140008cfb:	90                   	nop
   140008cfc:	90                   	nop
   140008cfd:	90                   	nop
   140008cfe:	90                   	nop
   140008cff:	90                   	nop

0000000140008d00 <wcsnlen>:
   140008d00:	55                   	push   rbp
   140008d01:	48 89 e5             	mov    rbp,rsp
   140008d04:	48 83 ec 10          	sub    rsp,0x10
   140008d08:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008d0c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008d10:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008d17:	00 
   140008d18:	eb 0a                	jmp    140008d24 <wcsnlen+0x24>
   140008d1a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008d1f:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008d24:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d28:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008d2c:	73 0c                	jae    140008d3a <wcsnlen+0x3a>
   140008d2e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008d32:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008d35:	66 85 c0             	test   ax,ax
   140008d38:	75 e0                	jne    140008d1a <wcsnlen+0x1a>
   140008d3a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d3e:	48 83 c4 10          	add    rsp,0x10
   140008d42:	5d                   	pop    rbp
   140008d43:	c3                   	ret
   140008d44:	90                   	nop
   140008d45:	90                   	nop
   140008d46:	90                   	nop
   140008d47:	90                   	nop
   140008d48:	90                   	nop
   140008d49:	90                   	nop
   140008d4a:	90                   	nop
   140008d4b:	90                   	nop
   140008d4c:	90                   	nop
   140008d4d:	90                   	nop
   140008d4e:	90                   	nop
   140008d4f:	90                   	nop

0000000140008d50 <strnlen>:
   140008d50:	55                   	push   rbp
   140008d51:	48 89 e5             	mov    rbp,rsp
   140008d54:	48 83 ec 10          	sub    rsp,0x10
   140008d58:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008d5c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008d60:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008d64:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008d68:	eb 05                	jmp    140008d6f <strnlen+0x1f>
   140008d6a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008d6f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d73:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008d77:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008d7b:	73 0b                	jae    140008d88 <strnlen+0x38>
   140008d7d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d81:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008d84:	84 c0                	test   al,al
   140008d86:	75 e2                	jne    140008d6a <strnlen+0x1a>
   140008d88:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d8c:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008d90:	48 83 c4 10          	add    rsp,0x10
   140008d94:	5d                   	pop    rbp
   140008d95:	c3                   	ret
   140008d96:	90                   	nop
   140008d97:	90                   	nop
   140008d98:	90                   	nop
   140008d99:	90                   	nop
   140008d9a:	90                   	nop
   140008d9b:	90                   	nop
   140008d9c:	90                   	nop
   140008d9d:	90                   	nop
   140008d9e:	90                   	nop
   140008d9f:	90                   	nop

0000000140008da0 <_initterm_e>:
   140008da0:	55                   	push   rbp
   140008da1:	48 89 e5             	mov    rbp,rsp
   140008da4:	48 83 ec 30          	sub    rsp,0x30
   140008da8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008dac:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008db0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008db4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008db8:	eb 29                	jmp    140008de3 <_initterm_e+0x43>
   140008dba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dbe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008dc1:	48 85 c0             	test   rax,rax
   140008dc4:	74 17                	je     140008ddd <_initterm_e+0x3d>
   140008dc6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dca:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008dcd:	ff d0                	call   rax
   140008dcf:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008dd2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008dd6:	74 06                	je     140008dde <_initterm_e+0x3e>
   140008dd8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008ddb:	eb 15                	jmp    140008df2 <_initterm_e+0x52>
   140008ddd:	90                   	nop
   140008dde:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008de3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008de7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008deb:	72 cd                	jb     140008dba <_initterm_e+0x1a>
   140008ded:	b8 00 00 00 00       	mov    eax,0x0
   140008df2:	48 83 c4 30          	add    rsp,0x30
   140008df6:	5d                   	pop    rbp
   140008df7:	c3                   	ret
   140008df8:	90                   	nop
   140008df9:	90                   	nop
   140008dfa:	90                   	nop
   140008dfb:	90                   	nop
   140008dfc:	90                   	nop
   140008dfd:	90                   	nop
   140008dfe:	90                   	nop
   140008dff:	90                   	nop

0000000140008e00 <__p__fmode>:
   140008e00:	55                   	push   rbp
   140008e01:	48 89 e5             	mov    rbp,rsp
   140008e04:	48 8b 05 f5 27 00 00 	mov    rax,QWORD PTR [rip+0x27f5]        # 14000b600 <.refptr.__imp__fmode>
   140008e0b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e0e:	5d                   	pop    rbp
   140008e0f:	c3                   	ret

0000000140008e10 <__p__commode>:
   140008e10:	55                   	push   rbp
   140008e11:	48 89 e5             	mov    rbp,rsp
   140008e14:	48 8b 05 d5 27 00 00 	mov    rax,QWORD PTR [rip+0x27d5]        # 14000b5f0 <.refptr.__imp__commode>
   140008e1b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e1e:	5d                   	pop    rbp
   140008e1f:	c3                   	ret

0000000140008e20 <__p___initenv>:
   140008e20:	55                   	push   rbp
   140008e21:	48 89 e5             	mov    rbp,rsp
   140008e24:	48 8b 05 b5 27 00 00 	mov    rax,QWORD PTR [rip+0x27b5]        # 14000b5e0 <.refptr.__imp___initenv>
   140008e2b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e2e:	5d                   	pop    rbp
   140008e2f:	c3                   	ret

0000000140008e30 <_set_invalid_parameter_handler>:
   140008e30:	55                   	push   rbp
   140008e31:	48 89 e5             	mov    rbp,rsp
   140008e34:	48 83 ec 10          	sub    rsp,0x10
   140008e38:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e3c:	48 8d 05 3d 6d 00 00 	lea    rax,[rip+0x6d3d]        # 14000fb80 <handler>
   140008e43:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e47:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e4b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008e4f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140008e53:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e57:	48 87 10             	xchg   QWORD PTR [rax],rdx
   140008e5a:	48 89 d0             	mov    rax,rdx
   140008e5d:	48 83 c4 10          	add    rsp,0x10
   140008e61:	5d                   	pop    rbp
   140008e62:	c3                   	ret

0000000140008e63 <_get_invalid_parameter_handler>:
   140008e63:	55                   	push   rbp
   140008e64:	48 89 e5             	mov    rbp,rsp
   140008e67:	48 8b 05 12 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d12]        # 14000fb80 <handler>
   140008e6e:	5d                   	pop    rbp
   140008e6f:	c3                   	ret

0000000140008e70 <_configthreadlocale>:
   140008e70:	55                   	push   rbp
   140008e71:	48 89 e5             	mov    rbp,rsp
   140008e74:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008e77:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   140008e7b:	75 07                	jne    140008e84 <_configthreadlocale+0x14>
   140008e7d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140008e82:	eb 05                	jmp    140008e89 <_configthreadlocale+0x19>
   140008e84:	b8 02 00 00 00       	mov    eax,0x2
   140008e89:	5d                   	pop    rbp
   140008e8a:	c3                   	ret
   140008e8b:	90                   	nop
   140008e8c:	90                   	nop
   140008e8d:	90                   	nop
   140008e8e:	90                   	nop
   140008e8f:	90                   	nop

0000000140008e90 <__acrt_iob_func>:
   140008e90:	55                   	push   rbp
   140008e91:	48 89 e5             	mov    rbp,rsp
   140008e94:	48 83 ec 20          	sub    rsp,0x20
   140008e98:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008e9b:	e8 b0 05 00 00       	call   140009450 <__iob_func>
   140008ea0:	48 89 c1             	mov    rcx,rax
   140008ea3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008ea6:	48 89 d0             	mov    rax,rdx
   140008ea9:	48 01 c0             	add    rax,rax
   140008eac:	48 01 d0             	add    rax,rdx
   140008eaf:	48 c1 e0 04          	shl    rax,0x4
   140008eb3:	48 01 c8             	add    rax,rcx
   140008eb6:	48 83 c4 20          	add    rsp,0x20
   140008eba:	5d                   	pop    rbp
   140008ebb:	c3                   	ret
   140008ebc:	90                   	nop
   140008ebd:	90                   	nop
   140008ebe:	90                   	nop
   140008ebf:	90                   	nop

0000000140008ec0 <wcrtomb>:
   140008ec0:	55                   	push   rbp
   140008ec1:	48 89 e5             	mov    rbp,rsp
   140008ec4:	48 83 ec 40          	sub    rsp,0x40
   140008ec8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008ecc:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140008ed0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140008ed4:	e8 5f 05 00 00       	call   140009438 <___lc_codepage_func>
   140008ed9:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008edc:	e8 5f 05 00 00       	call   140009440 <___mb_cur_max_func>
   140008ee1:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008ee4:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   140008ee8:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140008eec:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   140008ef0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ef4:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140008ef7:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   140008efb:	48 89 c1             	mov    rcx,rax
   140008efe:	e8 7d 00 00 00       	call   140008f80 <__mingw_wcrtomb_cp>
   140008f03:	48 83 c4 40          	add    rsp,0x40
   140008f07:	5d                   	pop    rbp
   140008f08:	c3                   	ret
   140008f09:	90                   	nop
   140008f0a:	90                   	nop
   140008f0b:	90                   	nop
   140008f0c:	90                   	nop
   140008f0d:	90                   	nop
   140008f0e:	90                   	nop
   140008f0f:	90                   	nop

0000000140008f10 <mbrtowc>:
   140008f10:	55                   	push   rbp
   140008f11:	48 89 e5             	mov    rbp,rsp
   140008f14:	48 83 ec 40          	sub    rsp,0x40
   140008f18:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f1c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008f20:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140008f24:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140008f28:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   140008f2d:	75 0b                	jne    140008f3a <mbrtowc+0x2a>
   140008f2f:	48 8d 05 5a 6c 00 00 	lea    rax,[rip+0x6c5a]        # 14000fb90 <state_mbrtowc.0>
   140008f36:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140008f3a:	e8 f9 04 00 00       	call   140009438 <___lc_codepage_func>
   140008f3f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008f42:	e8 f9 04 00 00       	call   140009440 <___mb_cur_max_func>
   140008f47:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008f4a:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   140008f4e:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140008f52:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140008f56:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f5a:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140008f5d:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   140008f61:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   140008f64:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   140008f68:	48 89 c1             	mov    rcx,rax
   140008f6b:	e8 70 01 00 00       	call   1400090e0 <__mingw_mbrtowc_cp>
   140008f70:	48 83 c4 40          	add    rsp,0x40
   140008f74:	5d                   	pop    rbp
   140008f75:	c3                   	ret
   140008f76:	90                   	nop
   140008f77:	90                   	nop
   140008f78:	90                   	nop
   140008f79:	90                   	nop
   140008f7a:	90                   	nop
   140008f7b:	90                   	nop
   140008f7c:	90                   	nop
   140008f7d:	90                   	nop
   140008f7e:	90                   	nop
   140008f7f:	90                   	nop

0000000140008f80 <__mingw_wcrtomb_cp>:
   140008f80:	55                   	push   rbp
   140008f81:	48 89 e5             	mov    rbp,rsp
   140008f84:	48 83 ec 50          	sub    rsp,0x50
   140008f88:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f8c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140008f90:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140008f94:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   140008f98:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140008f9d:	75 1b                	jne    140008fba <__mingw_wcrtomb_cp+0x3a>
   140008f9f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140008fa4:	74 0a                	je     140008fb0 <__mingw_wcrtomb_cp+0x30>
   140008fa6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140008faa:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008fb0:	b8 01 00 00 00       	mov    eax,0x1
   140008fb5:	e9 17 01 00 00       	jmp    1400090d1 <__mingw_wcrtomb_cp+0x151>
   140008fba:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140008fbf:	74 21                	je     140008fe2 <__mingw_wcrtomb_cp+0x62>
   140008fc1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140008fc5:	8b 00                	mov    eax,DWORD PTR [rax]
   140008fc7:	85 c0                	test   eax,eax
   140008fc9:	74 17                	je     140008fe2 <__mingw_wcrtomb_cp+0x62>
   140008fcb:	e8 a8 04 00 00       	call   140009478 <_errno>
   140008fd0:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140008fd6:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140008fdd:	e9 ef 00 00 00       	jmp    1400090d1 <__mingw_wcrtomb_cp+0x151>
   140008fe2:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140008fe6:	66 85 c0             	test   ax,ax
   140008fe9:	75 18                	jne    140009003 <__mingw_wcrtomb_cp+0x83>
   140008feb:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140008ff0:	74 07                	je     140008ff9 <__mingw_wcrtomb_cp+0x79>
   140008ff2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ff6:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140008ff9:	b8 01 00 00 00       	mov    eax,0x1
   140008ffe:	e9 ce 00 00 00       	jmp    1400090d1 <__mingw_wcrtomb_cp+0x151>
   140009003:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   140009007:	75 2b                	jne    140009034 <__mingw_wcrtomb_cp+0xb4>
   140009009:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   14000900d:	66 3d ff 00          	cmp    ax,0xff
   140009011:	0f 87 a4 00 00 00    	ja     1400090bb <__mingw_wcrtomb_cp+0x13b>
   140009017:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000901c:	74 0c                	je     14000902a <__mingw_wcrtomb_cp+0xaa>
   14000901e:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009022:	89 c2                	mov    edx,eax
   140009024:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009028:	88 10                	mov    BYTE PTR [rax],dl
   14000902a:	b8 01 00 00 00       	mov    eax,0x1
   14000902f:	e9 9d 00 00 00       	jmp    1400090d1 <__mingw_wcrtomb_cp+0x151>
   140009034:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000903b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   140009041:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   140009045:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140009048:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   14000904c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140009051:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   140009058:	00 00 
   14000905a:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000905d:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140009061:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009065:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000906a:	41 b9 01 00 00 00    	mov    r9d,0x1
   140009070:	49 89 c8             	mov    r8,rcx
   140009073:	ba 00 00 00 00       	mov    edx,0x0
   140009078:	89 c1                	mov    ecx,eax
   14000907a:	48 8b 05 df 71 00 00 	mov    rax,QWORD PTR [rip+0x71df]        # 140010260 <__imp_WideCharToMultiByte>
   140009081:	ff d0                	call   rax
   140009083:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009086:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000908a:	74 32                	je     1400090be <__mingw_wcrtomb_cp+0x13e>
   14000908c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000908f:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   140009092:	7f 2a                	jg     1400090be <__mingw_wcrtomb_cp+0x13e>
   140009094:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009097:	85 c0                	test   eax,eax
   140009099:	75 23                	jne    1400090be <__mingw_wcrtomb_cp+0x13e>
   14000909b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000909e:	48 63 c8             	movsxd rcx,eax
   1400090a1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400090a5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400090a9:	49 89 c8             	mov    r8,rcx
   1400090ac:	48 89 c1             	mov    rcx,rax
   1400090af:	e8 24 04 00 00       	call   1400094d8 <memcpy>
   1400090b4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400090b7:	48 98                	cdqe
   1400090b9:	eb 16                	jmp    1400090d1 <__mingw_wcrtomb_cp+0x151>
   1400090bb:	90                   	nop
   1400090bc:	eb 01                	jmp    1400090bf <__mingw_wcrtomb_cp+0x13f>
   1400090be:	90                   	nop
   1400090bf:	e8 b4 03 00 00       	call   140009478 <_errno>
   1400090c4:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400090ca:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400090d1:	48 83 c4 50          	add    rsp,0x50
   1400090d5:	5d                   	pop    rbp
   1400090d6:	c3                   	ret
   1400090d7:	90                   	nop
   1400090d8:	90                   	nop
   1400090d9:	90                   	nop
   1400090da:	90                   	nop
   1400090db:	90                   	nop
   1400090dc:	90                   	nop
   1400090dd:	90                   	nop
   1400090de:	90                   	nop
   1400090df:	90                   	nop

00000001400090e0 <__mingw_mbrtowc_cp>:
   1400090e0:	55                   	push   rbp
   1400090e1:	48 89 e5             	mov    rbp,rsp
   1400090e4:	48 83 ec 50          	sub    rsp,0x50
   1400090e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090ec:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400090f0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090f4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400090f8:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   1400090fd:	75 1b                	jne    14000911a <__mingw_mbrtowc_cp+0x3a>
   1400090ff:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   140009106:	00 
   140009107:	48 8d 05 12 24 00 00 	lea    rax,[rip+0x2412]        # 14000b520 <.rdata>
   14000910e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140009112:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   140009119:	00 
   14000911a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000911e:	8b 00                	mov    eax,DWORD PTR [rax]
   140009120:	3d ff 00 00 00       	cmp    eax,0xff
   140009125:	0f 87 b9 01 00 00    	ja     1400092e4 <__mingw_mbrtowc_cp+0x204>
   14000912b:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009130:	75 0c                	jne    14000913e <__mingw_mbrtowc_cp+0x5e>
   140009132:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009139:	e9 bc 01 00 00       	jmp    1400092fa <__mingw_mbrtowc_cp+0x21a>
   14000913e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009142:	8b 00                	mov    eax,DWORD PTR [rax]
   140009144:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140009147:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   14000914b:	75 0c                	jne    140009159 <__mingw_mbrtowc_cp+0x79>
   14000914d:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009151:	84 c0                	test   al,al
   140009153:	0f 85 8e 01 00 00    	jne    1400092e7 <__mingw_mbrtowc_cp+0x207>
   140009159:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   14000915d:	75 2c                	jne    14000918b <__mingw_mbrtowc_cp+0xab>
   14000915f:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009164:	74 11                	je     140009177 <__mingw_mbrtowc_cp+0x97>
   140009166:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000916a:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000916d:	0f b6 d0             	movzx  edx,al
   140009170:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009174:	66 89 10             	mov    WORD PTR [rax],dx
   140009177:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000917b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000917e:	84 c0                	test   al,al
   140009180:	0f 95 c0             	setne  al
   140009183:	0f b6 c0             	movzx  eax,al
   140009186:	e9 6f 01 00 00       	jmp    1400092fa <__mingw_mbrtowc_cp+0x21a>
   14000918b:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140009192:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140009199:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   14000919d:	84 c0                	test   al,al
   14000919f:	74 1a                	je     1400091bb <__mingw_mbrtowc_cp+0xdb>
   1400091a1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400091a5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400091a8:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   1400091ab:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400091b2:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400091b9:	eb 73                	jmp    14000922e <__mingw_mbrtowc_cp+0x14e>
   1400091bb:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   1400091bf:	75 5c                	jne    14000921d <__mingw_mbrtowc_cp+0x13d>
   1400091c1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400091c5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400091c8:	0f b6 c0             	movzx  eax,al
   1400091cb:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   1400091ce:	89 c1                	mov    ecx,eax
   1400091d0:	e8 ab 01 00 00       	call   140009380 <__mingw_isleadbyte_cp>
   1400091d5:	85 c0                	test   eax,eax
   1400091d7:	74 44                	je     14000921d <__mingw_mbrtowc_cp+0x13d>
   1400091d9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400091dd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400091e0:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   1400091e3:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   1400091e8:	77 15                	ja     1400091ff <__mingw_mbrtowc_cp+0x11f>
   1400091ea:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400091ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400091f1:	89 10                	mov    DWORD PTR [rax],edx
   1400091f3:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   1400091fa:	e9 fb 00 00 00       	jmp    1400092fa <__mingw_mbrtowc_cp+0x21a>
   1400091ff:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009203:	48 83 c0 01          	add    rax,0x1
   140009207:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000920a:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000920d:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140009214:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   14000921b:	eb 11                	jmp    14000922e <__mingw_mbrtowc_cp+0x14e>
   14000921d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009221:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009224:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009227:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000922e:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009232:	84 c0                	test   al,al
   140009234:	75 24                	jne    14000925a <__mingw_mbrtowc_cp+0x17a>
   140009236:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000923b:	74 09                	je     140009246 <__mingw_mbrtowc_cp+0x166>
   14000923d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009241:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   140009246:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000924a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009250:	b8 00 00 00 00       	mov    eax,0x0
   140009255:	e9 a0 00 00 00       	jmp    1400092fa <__mingw_mbrtowc_cp+0x21a>
   14000925a:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   14000925e:	75 08                	jne    140009268 <__mingw_mbrtowc_cp+0x188>
   140009260:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   140009264:	84 c0                	test   al,al
   140009266:	74 64                	je     1400092cc <__mingw_mbrtowc_cp+0x1ec>
   140009268:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   14000926e:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   140009272:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   140009276:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   140009279:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   140009280:	00 
   140009281:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   140009285:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000928a:	45 89 c1             	mov    r9d,r8d
   14000928d:	49 89 c8             	mov    r8,rcx
   140009290:	ba 08 00 00 00       	mov    edx,0x8
   140009295:	89 c1                	mov    ecx,eax
   140009297:	48 8b 05 92 6f 00 00 	mov    rax,QWORD PTR [rip+0x6f92]        # 140010230 <__imp_MultiByteToWideChar>
   14000929e:	ff d0                	call   rax
   1400092a0:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400092a3:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   1400092a7:	75 26                	jne    1400092cf <__mingw_mbrtowc_cp+0x1ef>
   1400092a9:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400092ae:	74 0b                	je     1400092bb <__mingw_mbrtowc_cp+0x1db>
   1400092b0:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   1400092b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400092b8:	66 89 10             	mov    WORD PTR [rax],dx
   1400092bb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400092bf:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400092c5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400092c8:	48 98                	cdqe
   1400092ca:	eb 2e                	jmp    1400092fa <__mingw_mbrtowc_cp+0x21a>
   1400092cc:	90                   	nop
   1400092cd:	eb 01                	jmp    1400092d0 <__mingw_mbrtowc_cp+0x1f0>
   1400092cf:	90                   	nop
   1400092d0:	e8 a3 01 00 00       	call   140009478 <_errno>
   1400092d5:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400092db:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400092e2:	eb 16                	jmp    1400092fa <__mingw_mbrtowc_cp+0x21a>
   1400092e4:	90                   	nop
   1400092e5:	eb 01                	jmp    1400092e8 <__mingw_mbrtowc_cp+0x208>
   1400092e7:	90                   	nop
   1400092e8:	e8 8b 01 00 00       	call   140009478 <_errno>
   1400092ed:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   1400092f3:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400092fa:	48 83 c4 50          	add    rsp,0x50
   1400092fe:	5d                   	pop    rbp
   1400092ff:	c3                   	ret

0000000140009300 <fallback_IsDBCSLeadByteEx>:
   140009300:	55                   	push   rbp
   140009301:	48 89 e5             	mov    rbp,rsp
   140009304:	48 83 ec 40          	sub    rsp,0x40
   140009308:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000930b:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   14000930e:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   140009312:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009315:	89 c1                	mov    ecx,eax
   140009317:	48 8b 05 da 6e 00 00 	mov    rax,QWORD PTR [rip+0x6eda]        # 1400101f8 <__imp_GetCPInfo>
   14000931e:	ff d0                	call   rax
   140009320:	85 c0                	test   eax,eax
   140009322:	74 51                	je     140009375 <fallback_IsDBCSLeadByteEx+0x75>
   140009324:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140009327:	83 f8 02             	cmp    eax,0x2
   14000932a:	75 49                	jne    140009375 <fallback_IsDBCSLeadByteEx+0x75>
   14000932c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009333:	eb 2c                	jmp    140009361 <fallback_IsDBCSLeadByteEx+0x61>
   140009335:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009338:	48 98                	cdqe
   14000933a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000933f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   140009342:	72 19                	jb     14000935d <fallback_IsDBCSLeadByteEx+0x5d>
   140009344:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009347:	83 c0 01             	add    eax,0x1
   14000934a:	48 98                	cdqe
   14000934c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009351:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   140009354:	72 07                	jb     14000935d <fallback_IsDBCSLeadByteEx+0x5d>
   140009356:	b8 01 00 00 00       	mov    eax,0x1
   14000935b:	eb 1d                	jmp    14000937a <fallback_IsDBCSLeadByteEx+0x7a>
   14000935d:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   140009361:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   140009365:	7f 0e                	jg     140009375 <fallback_IsDBCSLeadByteEx+0x75>
   140009367:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000936a:	48 98                	cdqe
   14000936c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009371:	84 c0                	test   al,al
   140009373:	75 c0                	jne    140009335 <fallback_IsDBCSLeadByteEx+0x35>
   140009375:	b8 00 00 00 00       	mov    eax,0x0
   14000937a:	48 83 c4 40          	add    rsp,0x40
   14000937e:	5d                   	pop    rbp
   14000937f:	c3                   	ret

0000000140009380 <__mingw_isleadbyte_cp>:
   140009380:	55                   	push   rbp
   140009381:	48 89 e5             	mov    rbp,rsp
   140009384:	48 83 ec 40          	sub    rsp,0x40
   140009388:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000938b:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000938e:	48 8b 05 0b 68 00 00 	mov    rax,QWORD PTR [rip+0x680b]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009395:	48 85 c0             	test   rax,rax
   140009398:	75 71                	jne    14000940b <__mingw_isleadbyte_cp+0x8b>
   14000939a:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400093a1:	00 
   1400093a2:	48 8d 05 87 21 00 00 	lea    rax,[rip+0x2187]        # 14000b530 <.rdata>
   1400093a9:	48 89 c1             	mov    rcx,rax
   1400093ac:	48 8b 05 55 6e 00 00 	mov    rax,QWORD PTR [rip+0x6e55]        # 140010208 <__imp_GetModuleHandleA>
   1400093b3:	ff d0                	call   rax
   1400093b5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400093b9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400093be:	74 1b                	je     1400093db <__mingw_isleadbyte_cp+0x5b>
   1400093c0:	48 8d 15 76 21 00 00 	lea    rdx,[rip+0x2176]        # 14000b53d <.rdata+0xd>
   1400093c7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400093cb:	48 89 c1             	mov    rcx,rax
   1400093ce:	48 8b 05 3b 6e 00 00 	mov    rax,QWORD PTR [rip+0x6e3b]        # 140010210 <__imp_GetProcAddress>
   1400093d5:	ff d0                	call   rax
   1400093d7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400093db:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400093e0:	75 0b                	jne    1400093ed <__mingw_isleadbyte_cp+0x6d>
   1400093e2:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 140009300 <fallback_IsDBCSLeadByteEx>
   1400093e9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400093ed:	48 8d 05 ac 67 00 00 	lea    rax,[rip+0x67ac]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400093f4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400093f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400093fc:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140009400:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140009404:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140009408:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000940b:	4c 8b 05 8e 67 00 00 	mov    r8,QWORD PTR [rip+0x678e]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009412:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009415:	0f b6 d0             	movzx  edx,al
   140009418:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000941b:	89 c1                	mov    ecx,eax
   14000941d:	41 ff d0             	call   r8
   140009420:	48 83 c4 40          	add    rsp,0x40
   140009424:	5d                   	pop    rbp
   140009425:	c3                   	ret
   140009426:	90                   	nop
   140009427:	90                   	nop
   140009428:	90                   	nop
   140009429:	90                   	nop
   14000942a:	90                   	nop
   14000942b:	90                   	nop
   14000942c:	90                   	nop
   14000942d:	90                   	nop
   14000942e:	90                   	nop
   14000942f:	90                   	nop

0000000140009430 <__C_specific_handler>:
   140009430:	ff 25 3a 6e 00 00    	jmp    QWORD PTR [rip+0x6e3a]        # 140010270 <__imp___C_specific_handler>
   140009436:	90                   	nop
   140009437:	90                   	nop

0000000140009438 <___lc_codepage_func>:
   140009438:	ff 25 3a 6e 00 00    	jmp    QWORD PTR [rip+0x6e3a]        # 140010278 <__imp____lc_codepage_func>
   14000943e:	90                   	nop
   14000943f:	90                   	nop

0000000140009440 <___mb_cur_max_func>:
   140009440:	ff 25 3a 6e 00 00    	jmp    QWORD PTR [rip+0x6e3a]        # 140010280 <__imp____mb_cur_max_func>
   140009446:	90                   	nop
   140009447:	90                   	nop

0000000140009448 <__getmainargs>:
   140009448:	ff 25 3a 6e 00 00    	jmp    QWORD PTR [rip+0x6e3a]        # 140010288 <__imp___getmainargs>
   14000944e:	90                   	nop
   14000944f:	90                   	nop

0000000140009450 <__iob_func>:
   140009450:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 140010298 <__imp___iob_func>
   140009456:	90                   	nop
   140009457:	90                   	nop

0000000140009458 <__set_app_type>:
   140009458:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 1400102a0 <__imp___set_app_type>
   14000945e:	90                   	nop
   14000945f:	90                   	nop

0000000140009460 <__setusermatherr>:
   140009460:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 1400102a8 <__imp___setusermatherr>
   140009466:	90                   	nop
   140009467:	90                   	nop

0000000140009468 <_amsg_exit>:
   140009468:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 1400102b0 <__imp__amsg_exit>
   14000946e:	90                   	nop
   14000946f:	90                   	nop

0000000140009470 <_cexit>:
   140009470:	ff 25 42 6e 00 00    	jmp    QWORD PTR [rip+0x6e42]        # 1400102b8 <__imp__cexit>
   140009476:	90                   	nop
   140009477:	90                   	nop

0000000140009478 <_errno>:
   140009478:	ff 25 4a 6e 00 00    	jmp    QWORD PTR [rip+0x6e4a]        # 1400102c8 <__imp__errno>
   14000947e:	90                   	nop
   14000947f:	90                   	nop

0000000140009480 <_initterm>:
   140009480:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 1400102d8 <__imp__initterm>
   140009486:	90                   	nop
   140009487:	90                   	nop

0000000140009488 <_crt_atexit>:
   140009488:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 1400102e0 <__imp__crt_atexit>
   14000948e:	90                   	nop
   14000948f:	90                   	nop

0000000140009490 <abort>:
   140009490:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 1400102e8 <__imp_abort>
   140009496:	90                   	nop
   140009497:	90                   	nop

0000000140009498 <calloc>:
   140009498:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 1400102f0 <__imp_calloc>
   14000949e:	90                   	nop
   14000949f:	90                   	nop

00000001400094a0 <exit>:
   1400094a0:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 1400102f8 <__imp_exit>
   1400094a6:	90                   	nop
   1400094a7:	90                   	nop

00000001400094a8 <fflush>:
   1400094a8:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010300 <__imp_fflush>
   1400094ae:	90                   	nop
   1400094af:	90                   	nop

00000001400094b0 <fprintf>:
   1400094b0:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010308 <__imp_fprintf>
   1400094b6:	90                   	nop
   1400094b7:	90                   	nop

00000001400094b8 <fputc>:
   1400094b8:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010310 <__imp_fputc>
   1400094be:	90                   	nop
   1400094bf:	90                   	nop

00000001400094c0 <free>:
   1400094c0:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010318 <__imp_free>
   1400094c6:	90                   	nop
   1400094c7:	90                   	nop

00000001400094c8 <localeconv>:
   1400094c8:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010320 <__imp_localeconv>
   1400094ce:	90                   	nop
   1400094cf:	90                   	nop

00000001400094d0 <malloc>:
   1400094d0:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010328 <__imp_malloc>
   1400094d6:	90                   	nop
   1400094d7:	90                   	nop

00000001400094d8 <memcpy>:
   1400094d8:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010330 <__imp_memcpy>
   1400094de:	90                   	nop
   1400094df:	90                   	nop

00000001400094e0 <puts>:
   1400094e0:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010338 <__imp_puts>
   1400094e6:	90                   	nop
   1400094e7:	90                   	nop

00000001400094e8 <setvbuf>:
   1400094e8:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010340 <__imp_setvbuf>
   1400094ee:	90                   	nop
   1400094ef:	90                   	nop

00000001400094f0 <signal>:
   1400094f0:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010348 <__imp_signal>
   1400094f6:	90                   	nop
   1400094f7:	90                   	nop

00000001400094f8 <strerror>:
   1400094f8:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010350 <__imp_strerror>
   1400094fe:	90                   	nop
   1400094ff:	90                   	nop

0000000140009500 <strlen>:
   140009500:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010358 <__imp_strlen>
   140009506:	90                   	nop
   140009507:	90                   	nop

0000000140009508 <strncmp>:
   140009508:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010360 <__imp_strncmp>
   14000950e:	90                   	nop
   14000950f:	90                   	nop

0000000140009510 <vfprintf>:
   140009510:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010368 <__imp_vfprintf>
   140009516:	90                   	nop
   140009517:	90                   	nop

0000000140009518 <wcslen>:
   140009518:	ff 25 52 6e 00 00    	jmp    QWORD PTR [rip+0x6e52]        # 140010370 <__imp_wcslen>
   14000951e:	90                   	nop
   14000951f:	90                   	nop

0000000140009520 <WideCharToMultiByte>:
   140009520:	ff 25 3a 6d 00 00    	jmp    QWORD PTR [rip+0x6d3a]        # 140010260 <__imp_WideCharToMultiByte>
   140009526:	90                   	nop
   140009527:	90                   	nop

0000000140009528 <VirtualQuery>:
   140009528:	ff 25 2a 6d 00 00    	jmp    QWORD PTR [rip+0x6d2a]        # 140010258 <__imp_VirtualQuery>
   14000952e:	90                   	nop
   14000952f:	90                   	nop

0000000140009530 <VirtualProtect>:
   140009530:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010250 <__imp_VirtualProtect>
   140009536:	90                   	nop
   140009537:	90                   	nop

0000000140009538 <TlsGetValue>:
   140009538:	ff 25 0a 6d 00 00    	jmp    QWORD PTR [rip+0x6d0a]        # 140010248 <__imp_TlsGetValue>
   14000953e:	90                   	nop
   14000953f:	90                   	nop

0000000140009540 <Sleep>:
   140009540:	ff 25 fa 6c 00 00    	jmp    QWORD PTR [rip+0x6cfa]        # 140010240 <__imp_Sleep>
   140009546:	90                   	nop
   140009547:	90                   	nop

0000000140009548 <SetUnhandledExceptionFilter>:
   140009548:	ff 25 ea 6c 00 00    	jmp    QWORD PTR [rip+0x6cea]        # 140010238 <__imp_SetUnhandledExceptionFilter>
   14000954e:	90                   	nop
   14000954f:	90                   	nop

0000000140009550 <MultiByteToWideChar>:
   140009550:	ff 25 da 6c 00 00    	jmp    QWORD PTR [rip+0x6cda]        # 140010230 <__imp_MultiByteToWideChar>
   140009556:	90                   	nop
   140009557:	90                   	nop

0000000140009558 <LoadLibraryA>:
   140009558:	ff 25 ca 6c 00 00    	jmp    QWORD PTR [rip+0x6cca]        # 140010228 <__imp_LoadLibraryA>
   14000955e:	90                   	nop
   14000955f:	90                   	nop

0000000140009560 <LeaveCriticalSection>:
   140009560:	ff 25 ba 6c 00 00    	jmp    QWORD PTR [rip+0x6cba]        # 140010220 <__imp_LeaveCriticalSection>
   140009566:	90                   	nop
   140009567:	90                   	nop

0000000140009568 <InitializeCriticalSection>:
   140009568:	ff 25 aa 6c 00 00    	jmp    QWORD PTR [rip+0x6caa]        # 140010218 <__imp_InitializeCriticalSection>
   14000956e:	90                   	nop
   14000956f:	90                   	nop

0000000140009570 <GetProcAddress>:
   140009570:	ff 25 9a 6c 00 00    	jmp    QWORD PTR [rip+0x6c9a]        # 140010210 <__imp_GetProcAddress>
   140009576:	90                   	nop
   140009577:	90                   	nop

0000000140009578 <GetModuleHandleA>:
   140009578:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010208 <__imp_GetModuleHandleA>
   14000957e:	90                   	nop
   14000957f:	90                   	nop

0000000140009580 <GetLastError>:
   140009580:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010200 <__imp_GetLastError>
   140009586:	90                   	nop
   140009587:	90                   	nop

0000000140009588 <GetCPInfo>:
   140009588:	ff 25 6a 6c 00 00    	jmp    QWORD PTR [rip+0x6c6a]        # 1400101f8 <__imp_GetCPInfo>
   14000958e:	90                   	nop
   14000958f:	90                   	nop

0000000140009590 <FreeLibrary>:
   140009590:	ff 25 5a 6c 00 00    	jmp    QWORD PTR [rip+0x6c5a]        # 1400101f0 <__imp_FreeLibrary>
   140009596:	90                   	nop
   140009597:	90                   	nop

0000000140009598 <EnterCriticalSection>:
   140009598:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 1400101e8 <__imp_EnterCriticalSection>
   14000959e:	90                   	nop
   14000959f:	90                   	nop

00000001400095a0 <DeleteCriticalSection>:
   1400095a0:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 1400101e0 <__IAT_start__>
   1400095a6:	90                   	nop
   1400095a7:	90                   	nop
   1400095a8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   1400095af:	00 

00000001400095b0 <register_frame_ctor>:
   1400095b0:	e9 bb 80 ff ff       	jmp    140001670 <__gcc_register_frame>
   1400095b5:	90                   	nop
   1400095b6:	90                   	nop
   1400095b7:	90                   	nop
   1400095b8:	90                   	nop
   1400095b9:	90                   	nop
   1400095ba:	90                   	nop
   1400095bb:	90                   	nop
   1400095bc:	90                   	nop
   1400095bd:	90                   	nop
   1400095be:	90                   	nop
   1400095bf:	90                   	nop
