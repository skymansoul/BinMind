
C:\Users\Administrator\Desktop\BinMind\round2\samples\uaf\safe_03_no_use\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 1f 86 00 00       	call   140009648 <fflush>
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
   1400010e8:	48 8b 05 61 f1 00 00 	mov    rax,QWORD PTR [rip+0xf161]        # 140010250 <__imp_Sleep>
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
   14000113b:	e8 b8 84 00 00       	call   1400095f8 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 b8 7e 00 00       	call   140009020 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 07 85 00 00       	call   140009688 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 97 84 00 00       	call   140009630 <abort>
   140001199:	e8 82 11 00 00       	call   140002320 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 99 f0 00 00 	mov    rax,QWORD PTR [rip+0xf099]        # 140010248 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 f6 7d 00 00       	call   140008fc0 <_set_invalid_parameter_handler>
   1400011ca:	e8 61 1a 00 00       	call   140002c30 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 f7 83 00 00       	call   1400095e8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 eb 83 00 00       	call   1400095e8 <__set_app_type>
   1400011fd:	e8 6e 7c 00 00       	call   140008e70 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 6e 7c 00 00       	call   140008e80 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 de 06 00 00       	call   140001900 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 c3 83 00 00       	call   1400095f8 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 e8 11 00 00       	call   14000243a <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 96 7d 00 00       	call   140009000 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 90 7b 00 00       	call   140008e10 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 6a 83 00 00       	call   1400095f8 <_amsg_exit>
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
   1400012cb:	e8 08 83 00 00       	call   1400095d8 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 15 83 00 00       	call   1400095f8 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 ee 82 00 00       	call   1400095f8 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 f0 82 00 00       	call   140009610 <_initterm>
   140001320:	e8 b2 05 00 00       	call   1400018d7 <__main>
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
   14000138d:	e8 fe 7a 00 00       	call   140008e90 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 da 03 00 00       	call   140001794 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 6f 82 00 00       	call   140009640 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 20 82 00 00       	call   140009600 <_cexit>
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
   140001511:	e8 5a 81 00 00       	call   140009670 <malloc>
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
   14000155c:	e8 3f 81 00 00       	call   1400096a0 <strlen>
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
   140001585:	e8 e6 80 00 00       	call   140009670 <malloc>
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
   1400015e8:	e8 8b 80 00 00       	call   140009678 <memcpy>
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
   140001642:	e8 e1 7f 00 00       	call   140009628 <_crt_atexit>
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
   140001682:	ff 15 90 eb 00 00    	call   QWORD PTR [rip+0xeb90]        # 140010218 <__imp_GetModuleHandleA>
   140001688:	48 89 c3             	mov    rbx,rax
   14000168b:	48 85 c0             	test   rax,rax
   14000168e:	74 70                	je     140001700 <__gcc_register_frame+0x90>
   140001690:	48 8d 0d 69 99 00 00 	lea    rcx,[rip+0x9969]        # 14000b000 <.rdata>
   140001697:	ff 15 9b eb 00 00    	call   QWORD PTR [rip+0xeb9b]        # 140010238 <__imp_LoadLibraryA>
   14000169d:	4c 8b 0d 7c eb 00 00 	mov    r9,QWORD PTR [rip+0xeb7c]        # 140010220 <__imp_GetProcAddress>
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
   14000174e:	48 ff 25 ab ea 00 00 	rex.W jmp QWORD PTR [rip+0xeaab]        # 140010200 <__imp_FreeLibrary>
   140001755:	0f 1f 00             	nop    DWORD PTR [rax]
   140001758:	48 83 c4 20          	add    rsp,0x20
   14000175c:	5d                   	pop    rbp
   14000175d:	c3                   	ret
   14000175e:	90                   	nop
   14000175f:	90                   	nop

0000000140001760 <process>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001768:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000176c:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001771:	75 07                	jne    14000177a <process+0x1a>
   140001773:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140001778:	eb 18                	jmp    140001792 <process+0x32>
   14000177a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000177e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140001782:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001786:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001789:	48 89 02             	mov    QWORD PTR [rdx],rax
   14000178c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001790:	8b 00                	mov    eax,DWORD PTR [rax]
   140001792:	5d                   	pop    rbp
   140001793:	c3                   	ret

0000000140001794 <main>:
   140001794:	55                   	push   rbp
   140001795:	48 89 e5             	mov    rbp,rsp
   140001798:	48 83 ec 30          	sub    rsp,0x30
   14000179c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000179f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400017a3:	e8 2f 01 00 00       	call   1400018d7 <__main>
   1400017a8:	b9 14 00 00 00       	mov    ecx,0x14
   1400017ad:	e8 be 7e 00 00       	call   140009670 <malloc>
   1400017b2:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400017b6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017ba:	c7 00 03 00 00 00    	mov    DWORD PTR [rax],0x3
   1400017c0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017c4:	48 83 c0 04          	add    rax,0x4
   1400017c8:	41 b8 10 00 00 00    	mov    r8d,0x10
   1400017ce:	ba 00 00 00 00       	mov    edx,0x0
   1400017d3:	48 89 c1             	mov    rcx,rax
   1400017d6:	e8 a5 7e 00 00       	call   140009680 <memset>
   1400017db:	48 8d 15 6e 98 00 00 	lea    rdx,[rip+0x986e]        # 14000b050 <.rdata>
   1400017e2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017e6:	48 89 c1             	mov    rcx,rax
   1400017e9:	e8 72 ff ff ff       	call   140001760 <process>
   1400017ee:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400017f1:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400017f4:	48 8d 0d 5b 98 00 00 	lea    rcx,[rip+0x985b]        # 14000b056 <.rdata+0x6>
   1400017fb:	89 c2                	mov    edx,eax
   1400017fd:	e8 2e 19 00 00       	call   140003130 <__mingw_printf>
   140001802:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001806:	48 89 c1             	mov    rcx,rax
   140001809:	e8 52 7e 00 00       	call   140009660 <free>
   14000180e:	b8 00 00 00 00       	mov    eax,0x0
   140001813:	48 83 c4 30          	add    rsp,0x30
   140001817:	5d                   	pop    rbp
   140001818:	c3                   	ret
   140001819:	90                   	nop
   14000181a:	90                   	nop
   14000181b:	90                   	nop
   14000181c:	90                   	nop
   14000181d:	90                   	nop
   14000181e:	90                   	nop
   14000181f:	90                   	nop

0000000140001820 <__do_global_dtors>:
   140001820:	55                   	push   rbp
   140001821:	48 89 e5             	mov    rbp,rsp
   140001824:	48 83 ec 20          	sub    rsp,0x20
   140001828:	eb 1e                	jmp    140001848 <__do_global_dtors+0x28>
   14000182a:	48 8b 05 df 87 00 00 	mov    rax,QWORD PTR [rip+0x87df]        # 14000a010 <p.0>
   140001831:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001834:	ff d0                	call   rax
   140001836:	48 8b 05 d3 87 00 00 	mov    rax,QWORD PTR [rip+0x87d3]        # 14000a010 <p.0>
   14000183d:	48 83 c0 08          	add    rax,0x8
   140001841:	48 89 05 c8 87 00 00 	mov    QWORD PTR [rip+0x87c8],rax        # 14000a010 <p.0>
   140001848:	48 8b 05 c1 87 00 00 	mov    rax,QWORD PTR [rip+0x87c1]        # 14000a010 <p.0>
   14000184f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001852:	48 85 c0             	test   rax,rax
   140001855:	75 d3                	jne    14000182a <__do_global_dtors+0xa>
   140001857:	90                   	nop
   140001858:	90                   	nop
   140001859:	48 83 c4 20          	add    rsp,0x20
   14000185d:	5d                   	pop    rbp
   14000185e:	c3                   	ret

000000014000185f <__do_global_ctors>:
   14000185f:	55                   	push   rbp
   140001860:	48 89 e5             	mov    rbp,rsp
   140001863:	48 83 ec 30          	sub    rsp,0x30
   140001867:	48 8b 05 02 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d02]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000186e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001871:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001874:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001878:	75 25                	jne    14000189f <__do_global_ctors+0x40>
   14000187a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001881:	eb 04                	jmp    140001887 <__do_global_ctors+0x28>
   140001883:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001887:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000188a:	8d 50 01             	lea    edx,[rax+0x1]
   14000188d:	48 8b 05 dc 9c 00 00 	mov    rax,QWORD PTR [rip+0x9cdc]        # 14000b570 <.refptr.__CTOR_LIST__>
   140001894:	89 d2                	mov    edx,edx
   140001896:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000189a:	48 85 c0             	test   rax,rax
   14000189d:	75 e4                	jne    140001883 <__do_global_ctors+0x24>
   14000189f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018a2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400018a5:	eb 14                	jmp    1400018bb <__do_global_ctors+0x5c>
   1400018a7:	48 8b 05 c2 9c 00 00 	mov    rax,QWORD PTR [rip+0x9cc2]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018ae:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400018b1:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018b5:	ff d0                	call   rax
   1400018b7:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400018bb:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400018bf:	75 e6                	jne    1400018a7 <__do_global_ctors+0x48>
   1400018c1:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001820 <__do_global_dtors>
   1400018c8:	48 89 c1             	mov    rcx,rax
   1400018cb:	e8 5f fd ff ff       	call   14000162f <atexit>
   1400018d0:	90                   	nop
   1400018d1:	48 83 c4 30          	add    rsp,0x30
   1400018d5:	5d                   	pop    rbp
   1400018d6:	c3                   	ret

00000001400018d7 <__main>:
   1400018d7:	55                   	push   rbp
   1400018d8:	48 89 e5             	mov    rbp,rsp
   1400018db:	48 83 ec 20          	sub    rsp,0x20
   1400018df:	8b 05 9b d7 00 00    	mov    eax,DWORD PTR [rip+0xd79b]        # 14000f080 <initialized>
   1400018e5:	85 c0                	test   eax,eax
   1400018e7:	75 0f                	jne    1400018f8 <__main+0x21>
   1400018e9:	c7 05 8d d7 00 00 01 	mov    DWORD PTR [rip+0xd78d],0x1        # 14000f080 <initialized>
   1400018f0:	00 00 00 
   1400018f3:	e8 67 ff ff ff       	call   14000185f <__do_global_ctors>
   1400018f8:	90                   	nop
   1400018f9:	48 83 c4 20          	add    rsp,0x20
   1400018fd:	5d                   	pop    rbp
   1400018fe:	c3                   	ret
   1400018ff:	90                   	nop

0000000140001900 <_setargv>:
   140001900:	55                   	push   rbp
   140001901:	48 89 e5             	mov    rbp,rsp
   140001904:	b8 00 00 00 00       	mov    eax,0x0
   140001909:	5d                   	pop    rbp
   14000190a:	c3                   	ret
   14000190b:	90                   	nop
   14000190c:	90                   	nop
   14000190d:	90                   	nop
   14000190e:	90                   	nop
   14000190f:	90                   	nop

0000000140001910 <__dyn_tls_init>:
   140001910:	55                   	push   rbp
   140001911:	48 89 e5             	mov    rbp,rsp
   140001914:	48 83 ec 30          	sub    rsp,0x30
   140001918:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000191c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000191f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001923:	48 8b 05 26 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c26]        # 14000b550 <.refptr._CRT_MT>
   14000192a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000192c:	83 f8 02             	cmp    eax,0x2
   14000192f:	74 0d                	je     14000193e <__dyn_tls_init+0x2e>
   140001931:	48 8b 05 18 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c18]        # 14000b550 <.refptr._CRT_MT>
   140001938:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000193e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001942:	74 1e                	je     140001962 <__dyn_tls_init+0x52>
   140001944:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001948:	75 5b                	jne    1400019a5 <__dyn_tls_init+0x95>
   14000194a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000194e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001951:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001955:	49 89 c8             	mov    r8,rcx
   140001958:	48 89 c1             	mov    rcx,rax
   14000195b:	e8 d1 11 00 00       	call   140002b31 <__mingw_TLScallback>
   140001960:	eb 43                	jmp    1400019a5 <__dyn_tls_init+0x95>
   140001962:	48 8d 05 6f 9f 00 00 	lea    rax,[rip+0x9f6f]        # 14000b8d8 <___crt_xd_start__>
   140001969:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000196d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001972:	eb 22                	jmp    140001996 <__dyn_tls_init+0x86>
   140001974:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001978:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000197c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001980:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001983:	48 85 c0             	test   rax,rax
   140001986:	74 09                	je     140001991 <__dyn_tls_init+0x81>
   140001988:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000198c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000198f:	ff d0                	call   rax
   140001991:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001996:	48 8d 05 43 9f 00 00 	lea    rax,[rip+0x9f43]        # 14000b8e0 <__xd_z>
   14000199d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   1400019a1:	75 d1                	jne    140001974 <__dyn_tls_init+0x64>
   1400019a3:	eb 01                	jmp    1400019a6 <__dyn_tls_init+0x96>
   1400019a5:	90                   	nop
   1400019a6:	48 83 c4 30          	add    rsp,0x30
   1400019aa:	5d                   	pop    rbp
   1400019ab:	c3                   	ret

00000001400019ac <__tlregdtor>:
   1400019ac:	55                   	push   rbp
   1400019ad:	48 89 e5             	mov    rbp,rsp
   1400019b0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019b4:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400019b9:	75 07                	jne    1400019c2 <__tlregdtor+0x16>
   1400019bb:	b8 00 00 00 00       	mov    eax,0x0
   1400019c0:	eb 05                	jmp    1400019c7 <__tlregdtor+0x1b>
   1400019c2:	b8 00 00 00 00       	mov    eax,0x0
   1400019c7:	5d                   	pop    rbp
   1400019c8:	c3                   	ret

00000001400019c9 <__dyn_tls_dtor>:
   1400019c9:	55                   	push   rbp
   1400019ca:	48 89 e5             	mov    rbp,rsp
   1400019cd:	48 83 ec 20          	sub    rsp,0x20
   1400019d1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019d5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019d8:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019dc:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   1400019e0:	74 06                	je     1400019e8 <__dyn_tls_dtor+0x1f>
   1400019e2:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400019e6:	75 18                	jne    140001a00 <__dyn_tls_dtor+0x37>
   1400019e8:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019ec:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019ef:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019f3:	49 89 c8             	mov    r8,rcx
   1400019f6:	48 89 c1             	mov    rcx,rax
   1400019f9:	e8 33 11 00 00       	call   140002b31 <__mingw_TLScallback>
   1400019fe:	eb 01                	jmp    140001a01 <__dyn_tls_dtor+0x38>
   140001a00:	90                   	nop
   140001a01:	48 83 c4 20          	add    rsp,0x20
   140001a05:	5d                   	pop    rbp
   140001a06:	c3                   	ret
   140001a07:	90                   	nop
   140001a08:	90                   	nop
   140001a09:	90                   	nop
   140001a0a:	90                   	nop
   140001a0b:	90                   	nop
   140001a0c:	90                   	nop
   140001a0d:	90                   	nop
   140001a0e:	90                   	nop
   140001a0f:	90                   	nop

0000000140001a10 <_matherr>:
   140001a10:	55                   	push   rbp
   140001a11:	53                   	push   rbx
   140001a12:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a19:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a1e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a22:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a26:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a2b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a2f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a33:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a35:	83 f8 06             	cmp    eax,0x6
   140001a38:	74 56                	je     140001a90 <_matherr+0x80>
   140001a3a:	83 f8 06             	cmp    eax,0x6
   140001a3d:	7f 78                	jg     140001ab7 <_matherr+0xa7>
   140001a3f:	83 f8 05             	cmp    eax,0x5
   140001a42:	74 59                	je     140001a9d <_matherr+0x8d>
   140001a44:	83 f8 05             	cmp    eax,0x5
   140001a47:	7f 6e                	jg     140001ab7 <_matherr+0xa7>
   140001a49:	83 f8 04             	cmp    eax,0x4
   140001a4c:	74 5c                	je     140001aaa <_matherr+0x9a>
   140001a4e:	83 f8 04             	cmp    eax,0x4
   140001a51:	7f 64                	jg     140001ab7 <_matherr+0xa7>
   140001a53:	83 f8 03             	cmp    eax,0x3
   140001a56:	74 2b                	je     140001a83 <_matherr+0x73>
   140001a58:	83 f8 03             	cmp    eax,0x3
   140001a5b:	7f 5a                	jg     140001ab7 <_matherr+0xa7>
   140001a5d:	83 f8 01             	cmp    eax,0x1
   140001a60:	74 07                	je     140001a69 <_matherr+0x59>
   140001a62:	83 f8 02             	cmp    eax,0x2
   140001a65:	74 0f                	je     140001a76 <_matherr+0x66>
   140001a67:	eb 4e                	jmp    140001ab7 <_matherr+0xa7>
   140001a69:	48 8d 05 30 96 00 00 	lea    rax,[rip+0x9630]        # 14000b0a0 <.rdata>
   140001a70:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a74:	eb 4d                	jmp    140001ac3 <_matherr+0xb3>
   140001a76:	48 8d 05 42 96 00 00 	lea    rax,[rip+0x9642]        # 14000b0bf <.rdata+0x1f>
   140001a7d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a81:	eb 40                	jmp    140001ac3 <_matherr+0xb3>
   140001a83:	48 8d 05 56 96 00 00 	lea    rax,[rip+0x9656]        # 14000b0e0 <.rdata+0x40>
   140001a8a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a8e:	eb 33                	jmp    140001ac3 <_matherr+0xb3>
   140001a90:	48 8d 05 69 96 00 00 	lea    rax,[rip+0x9669]        # 14000b100 <.rdata+0x60>
   140001a97:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a9b:	eb 26                	jmp    140001ac3 <_matherr+0xb3>
   140001a9d:	48 8d 05 84 96 00 00 	lea    rax,[rip+0x9684]        # 14000b128 <.rdata+0x88>
   140001aa4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001aa8:	eb 19                	jmp    140001ac3 <_matherr+0xb3>
   140001aaa:	48 8d 05 9f 96 00 00 	lea    rax,[rip+0x969f]        # 14000b150 <.rdata+0xb0>
   140001ab1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ab5:	eb 0c                	jmp    140001ac3 <_matherr+0xb3>
   140001ab7:	48 8d 05 c8 96 00 00 	lea    rax,[rip+0x96c8]        # 14000b186 <.rdata+0xe6>
   140001abe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ac2:	90                   	nop
   140001ac3:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ac7:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001acd:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ad1:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001ad6:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ada:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001adf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ae3:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001ae7:	b9 02 00 00 00       	mov    ecx,0x2
   140001aec:	e8 2f 75 00 00       	call   140009020 <__acrt_iob_func>
   140001af1:	48 89 c1             	mov    rcx,rax
   140001af4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001af8:	48 8d 05 99 96 00 00 	lea    rax,[rip+0x9699]        # 14000b198 <.rdata+0xf8>
   140001aff:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b06:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b0c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b12:	49 89 d9             	mov    r9,rbx
   140001b15:	49 89 d0             	mov    r8,rdx
   140001b18:	48 89 c2             	mov    rdx,rax
   140001b1b:	e8 30 7b 00 00       	call   140009650 <fprintf>
   140001b20:	b8 00 00 00 00       	mov    eax,0x0
   140001b25:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b29:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b2d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b32:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b39:	5b                   	pop    rbx
   140001b3a:	5d                   	pop    rbp
   140001b3b:	c3                   	ret
   140001b3c:	90                   	nop
   140001b3d:	90                   	nop
   140001b3e:	90                   	nop
   140001b3f:	90                   	nop

0000000140001b40 <__report_error>:
   140001b40:	55                   	push   rbp
   140001b41:	53                   	push   rbx
   140001b42:	48 83 ec 38          	sub    rsp,0x38
   140001b46:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b4b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b4f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b53:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b57:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b5b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b5f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b63:	b9 02 00 00 00       	mov    ecx,0x2
   140001b68:	e8 b3 74 00 00       	call   140009020 <__acrt_iob_func>
   140001b6d:	48 89 c1             	mov    rcx,rax
   140001b70:	48 8d 05 59 96 00 00 	lea    rax,[rip+0x9659]        # 14000b1d0 <.rdata>
   140001b77:	48 89 c2             	mov    rdx,rax
   140001b7a:	e8 d1 7a 00 00       	call   140009650 <fprintf>
   140001b7f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b83:	b9 02 00 00 00       	mov    ecx,0x2
   140001b88:	e8 93 74 00 00       	call   140009020 <__acrt_iob_func>
   140001b8d:	48 89 c1             	mov    rcx,rax
   140001b90:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b94:	49 89 d8             	mov    r8,rbx
   140001b97:	48 89 c2             	mov    rdx,rax
   140001b9a:	e8 11 7b 00 00       	call   1400096b0 <vfprintf>
   140001b9f:	e8 8c 7a 00 00       	call   140009630 <abort>
   140001ba4:	90                   	nop

0000000140001ba5 <mark_section_writable>:
   140001ba5:	55                   	push   rbp
   140001ba6:	48 89 e5             	mov    rbp,rsp
   140001ba9:	48 83 ec 60          	sub    rsp,0x60
   140001bad:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001bb1:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001bb8:	e9 82 00 00 00       	jmp    140001c3f <mark_section_writable+0x9a>
   140001bbd:	48 8b 0d 1c d5 00 00 	mov    rcx,QWORD PTR [rip+0xd51c]        # 14000f0e0 <the_secs>
   140001bc4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bc7:	48 63 d0             	movsxd rdx,eax
   140001bca:	48 89 d0             	mov    rax,rdx
   140001bcd:	48 c1 e0 02          	shl    rax,0x2
   140001bd1:	48 01 d0             	add    rax,rdx
   140001bd4:	48 c1 e0 03          	shl    rax,0x3
   140001bd8:	48 01 c8             	add    rax,rcx
   140001bdb:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001bdf:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001be3:	72 56                	jb     140001c3b <mark_section_writable+0x96>
   140001be5:	48 8b 0d f4 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd4f4]        # 14000f0e0 <the_secs>
   140001bec:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bef:	48 63 d0             	movsxd rdx,eax
   140001bf2:	48 89 d0             	mov    rax,rdx
   140001bf5:	48 c1 e0 02          	shl    rax,0x2
   140001bf9:	48 01 d0             	add    rax,rdx
   140001bfc:	48 c1 e0 03          	shl    rax,0x3
   140001c00:	48 01 c8             	add    rax,rcx
   140001c03:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c07:	4c 8b 05 d2 d4 00 00 	mov    r8,QWORD PTR [rip+0xd4d2]        # 14000f0e0 <the_secs>
   140001c0e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c11:	48 63 d0             	movsxd rdx,eax
   140001c14:	48 89 d0             	mov    rax,rdx
   140001c17:	48 c1 e0 02          	shl    rax,0x2
   140001c1b:	48 01 d0             	add    rax,rdx
   140001c1e:	48 c1 e0 03          	shl    rax,0x3
   140001c22:	4c 01 c0             	add    rax,r8
   140001c25:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c29:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c2c:	89 c0                	mov    eax,eax
   140001c2e:	48 01 c8             	add    rax,rcx
   140001c31:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c35:	0f 82 41 02 00 00    	jb     140001e7c <mark_section_writable+0x2d7>
   140001c3b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c3f:	8b 05 a3 d4 00 00    	mov    eax,DWORD PTR [rip+0xd4a3]        # 14000f0e8 <maxSections>
   140001c45:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c48:	0f 8c 6f ff ff ff    	jl     140001bbd <mark_section_writable+0x18>
   140001c4e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c52:	48 89 c1             	mov    rcx,rax
   140001c55:	e8 c1 11 00 00       	call   140002e1b <__mingw_GetSectionForAddress>
   140001c5a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c5e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c63:	75 13                	jne    140001c78 <mark_section_writable+0xd3>
   140001c65:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c69:	48 8d 0d 80 95 00 00 	lea    rcx,[rip+0x9580]        # 14000b1f0 <.rdata+0x20>
   140001c70:	48 89 c2             	mov    rdx,rax
   140001c73:	e8 c8 fe ff ff       	call   140001b40 <__report_error>
   140001c78:	48 8b 0d 61 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd461]        # 14000f0e0 <the_secs>
   140001c7f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c82:	48 63 d0             	movsxd rdx,eax
   140001c85:	48 89 d0             	mov    rax,rdx
   140001c88:	48 c1 e0 02          	shl    rax,0x2
   140001c8c:	48 01 d0             	add    rax,rdx
   140001c8f:	48 c1 e0 03          	shl    rax,0x3
   140001c93:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c97:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c9b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c9f:	48 8b 0d 3a d4 00 00 	mov    rcx,QWORD PTR [rip+0xd43a]        # 14000f0e0 <the_secs>
   140001ca6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ca9:	48 63 d0             	movsxd rdx,eax
   140001cac:	48 89 d0             	mov    rax,rdx
   140001caf:	48 c1 e0 02          	shl    rax,0x2
   140001cb3:	48 01 d0             	add    rax,rdx
   140001cb6:	48 c1 e0 03          	shl    rax,0x3
   140001cba:	48 01 c8             	add    rax,rcx
   140001cbd:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001cc3:	e8 9f 12 00 00       	call   140002f67 <_GetPEImageBase>
   140001cc8:	48 89 c1             	mov    rcx,rax
   140001ccb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001ccf:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001cd2:	41 89 c1             	mov    r9d,eax
   140001cd5:	4c 8b 05 04 d4 00 00 	mov    r8,QWORD PTR [rip+0xd404]        # 14000f0e0 <the_secs>
   140001cdc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cdf:	48 63 d0             	movsxd rdx,eax
   140001ce2:	48 89 d0             	mov    rax,rdx
   140001ce5:	48 c1 e0 02          	shl    rax,0x2
   140001ce9:	48 01 d0             	add    rax,rdx
   140001cec:	48 c1 e0 03          	shl    rax,0x3
   140001cf0:	4c 01 c0             	add    rax,r8
   140001cf3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001cf7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001cfb:	48 8b 0d de d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3de]        # 14000f0e0 <the_secs>
   140001d02:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d05:	48 63 d0             	movsxd rdx,eax
   140001d08:	48 89 d0             	mov    rax,rdx
   140001d0b:	48 c1 e0 02          	shl    rax,0x2
   140001d0f:	48 01 d0             	add    rax,rdx
   140001d12:	48 c1 e0 03          	shl    rax,0x3
   140001d16:	48 01 c8             	add    rax,rcx
   140001d19:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d1d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d21:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d27:	48 89 c1             	mov    rcx,rax
   140001d2a:	48 8b 05 37 e5 00 00 	mov    rax,QWORD PTR [rip+0xe537]        # 140010268 <__imp_VirtualQuery>
   140001d31:	ff d0                	call   rax
   140001d33:	48 85 c0             	test   rax,rax
   140001d36:	75 3f                	jne    140001d77 <mark_section_writable+0x1d2>
   140001d38:	48 8b 0d a1 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3a1]        # 14000f0e0 <the_secs>
   140001d3f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d42:	48 63 d0             	movsxd rdx,eax
   140001d45:	48 89 d0             	mov    rax,rdx
   140001d48:	48 c1 e0 02          	shl    rax,0x2
   140001d4c:	48 01 d0             	add    rax,rdx
   140001d4f:	48 c1 e0 03          	shl    rax,0x3
   140001d53:	48 01 c8             	add    rax,rcx
   140001d56:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d5e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d61:	89 c1                	mov    ecx,eax
   140001d63:	48 8d 05 a6 94 00 00 	lea    rax,[rip+0x94a6]        # 14000b210 <.rdata+0x40>
   140001d6a:	49 89 d0             	mov    r8,rdx
   140001d6d:	89 ca                	mov    edx,ecx
   140001d6f:	48 89 c1             	mov    rcx,rax
   140001d72:	e8 c9 fd ff ff       	call   140001b40 <__report_error>
   140001d77:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d7a:	83 f8 40             	cmp    eax,0x40
   140001d7d:	0f 84 e8 00 00 00    	je     140001e6b <mark_section_writable+0x2c6>
   140001d83:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d86:	83 f8 04             	cmp    eax,0x4
   140001d89:	0f 84 dc 00 00 00    	je     140001e6b <mark_section_writable+0x2c6>
   140001d8f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d92:	3d 80 00 00 00       	cmp    eax,0x80
   140001d97:	0f 84 ce 00 00 00    	je     140001e6b <mark_section_writable+0x2c6>
   140001d9d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001da0:	83 f8 08             	cmp    eax,0x8
   140001da3:	0f 84 c2 00 00 00    	je     140001e6b <mark_section_writable+0x2c6>
   140001da9:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dac:	83 f8 02             	cmp    eax,0x2
   140001daf:	75 09                	jne    140001dba <mark_section_writable+0x215>
   140001db1:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001db8:	eb 07                	jmp    140001dc1 <mark_section_writable+0x21c>
   140001dba:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001dc1:	48 8b 0d 18 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd318]        # 14000f0e0 <the_secs>
   140001dc8:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dcb:	48 63 d0             	movsxd rdx,eax
   140001dce:	48 89 d0             	mov    rax,rdx
   140001dd1:	48 c1 e0 02          	shl    rax,0x2
   140001dd5:	48 01 d0             	add    rax,rdx
   140001dd8:	48 c1 e0 03          	shl    rax,0x3
   140001ddc:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001de0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001de4:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001de8:	48 8b 0d f1 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2f1]        # 14000f0e0 <the_secs>
   140001def:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001df2:	48 63 d0             	movsxd rdx,eax
   140001df5:	48 89 d0             	mov    rax,rdx
   140001df8:	48 c1 e0 02          	shl    rax,0x2
   140001dfc:	48 01 d0             	add    rax,rdx
   140001dff:	48 c1 e0 03          	shl    rax,0x3
   140001e03:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e07:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e0b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e0f:	48 8b 0d ca d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2ca]        # 14000f0e0 <the_secs>
   140001e16:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e19:	48 63 d0             	movsxd rdx,eax
   140001e1c:	48 89 d0             	mov    rax,rdx
   140001e1f:	48 c1 e0 02          	shl    rax,0x2
   140001e23:	48 01 d0             	add    rax,rdx
   140001e26:	48 c1 e0 03          	shl    rax,0x3
   140001e2a:	48 01 c8             	add    rax,rcx
   140001e2d:	49 89 c0             	mov    r8,rax
   140001e30:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e34:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e38:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e3b:	4d 89 c1             	mov    r9,r8
   140001e3e:	41 89 c8             	mov    r8d,ecx
   140001e41:	48 89 c1             	mov    rcx,rax
   140001e44:	48 8b 05 15 e4 00 00 	mov    rax,QWORD PTR [rip+0xe415]        # 140010260 <__imp_VirtualProtect>
   140001e4b:	ff d0                	call   rax
   140001e4d:	85 c0                	test   eax,eax
   140001e4f:	75 1a                	jne    140001e6b <mark_section_writable+0x2c6>
   140001e51:	48 8b 05 b8 e3 00 00 	mov    rax,QWORD PTR [rip+0xe3b8]        # 140010210 <__imp_GetLastError>
   140001e58:	ff d0                	call   rax
   140001e5a:	89 c2                	mov    edx,eax
   140001e5c:	48 8d 05 e5 93 00 00 	lea    rax,[rip+0x93e5]        # 14000b248 <.rdata+0x78>
   140001e63:	48 89 c1             	mov    rcx,rax
   140001e66:	e8 d5 fc ff ff       	call   140001b40 <__report_error>
   140001e6b:	8b 05 77 d2 00 00    	mov    eax,DWORD PTR [rip+0xd277]        # 14000f0e8 <maxSections>
   140001e71:	83 c0 01             	add    eax,0x1
   140001e74:	89 05 6e d2 00 00    	mov    DWORD PTR [rip+0xd26e],eax        # 14000f0e8 <maxSections>
   140001e7a:	eb 01                	jmp    140001e7d <mark_section_writable+0x2d8>
   140001e7c:	90                   	nop
   140001e7d:	48 83 c4 60          	add    rsp,0x60
   140001e81:	5d                   	pop    rbp
   140001e82:	c3                   	ret

0000000140001e83 <restore_modified_sections>:
   140001e83:	55                   	push   rbp
   140001e84:	48 89 e5             	mov    rbp,rsp
   140001e87:	48 83 ec 30          	sub    rsp,0x30
   140001e8b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e92:	e9 ad 00 00 00       	jmp    140001f44 <restore_modified_sections+0xc1>
   140001e97:	48 8b 0d 42 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd242]        # 14000f0e0 <the_secs>
   140001e9e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ea1:	48 63 d0             	movsxd rdx,eax
   140001ea4:	48 89 d0             	mov    rax,rdx
   140001ea7:	48 c1 e0 02          	shl    rax,0x2
   140001eab:	48 01 d0             	add    rax,rdx
   140001eae:	48 c1 e0 03          	shl    rax,0x3
   140001eb2:	48 01 c8             	add    rax,rcx
   140001eb5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001eb7:	85 c0                	test   eax,eax
   140001eb9:	0f 84 80 00 00 00    	je     140001f3f <restore_modified_sections+0xbc>
   140001ebf:	48 8b 0d 1a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd21a]        # 14000f0e0 <the_secs>
   140001ec6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ec9:	48 63 d0             	movsxd rdx,eax
   140001ecc:	48 89 d0             	mov    rax,rdx
   140001ecf:	48 c1 e0 02          	shl    rax,0x2
   140001ed3:	48 01 d0             	add    rax,rdx
   140001ed6:	48 c1 e0 03          	shl    rax,0x3
   140001eda:	48 01 c8             	add    rax,rcx
   140001edd:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001ee0:	48 8b 0d f9 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd1f9]        # 14000f0e0 <the_secs>
   140001ee7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eea:	48 63 d0             	movsxd rdx,eax
   140001eed:	48 89 d0             	mov    rax,rdx
   140001ef0:	48 c1 e0 02          	shl    rax,0x2
   140001ef4:	48 01 d0             	add    rax,rdx
   140001ef7:	48 c1 e0 03          	shl    rax,0x3
   140001efb:	48 01 c8             	add    rax,rcx
   140001efe:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f02:	4c 8b 05 d7 d1 00 00 	mov    r8,QWORD PTR [rip+0xd1d7]        # 14000f0e0 <the_secs>
   140001f09:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f0c:	48 63 d0             	movsxd rdx,eax
   140001f0f:	48 89 d0             	mov    rax,rdx
   140001f12:	48 c1 e0 02          	shl    rax,0x2
   140001f16:	48 01 d0             	add    rax,rdx
   140001f19:	48 c1 e0 03          	shl    rax,0x3
   140001f1d:	4c 01 c0             	add    rax,r8
   140001f20:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f24:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f28:	49 89 d1             	mov    r9,rdx
   140001f2b:	45 89 d0             	mov    r8d,r10d
   140001f2e:	48 89 ca             	mov    rdx,rcx
   140001f31:	48 89 c1             	mov    rcx,rax
   140001f34:	48 8b 05 25 e3 00 00 	mov    rax,QWORD PTR [rip+0xe325]        # 140010260 <__imp_VirtualProtect>
   140001f3b:	ff d0                	call   rax
   140001f3d:	eb 01                	jmp    140001f40 <restore_modified_sections+0xbd>
   140001f3f:	90                   	nop
   140001f40:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f44:	8b 05 9e d1 00 00    	mov    eax,DWORD PTR [rip+0xd19e]        # 14000f0e8 <maxSections>
   140001f4a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f4d:	0f 8c 44 ff ff ff    	jl     140001e97 <restore_modified_sections+0x14>
   140001f53:	90                   	nop
   140001f54:	90                   	nop
   140001f55:	48 83 c4 30          	add    rsp,0x30
   140001f59:	5d                   	pop    rbp
   140001f5a:	c3                   	ret

0000000140001f5b <__write_memory>:
   140001f5b:	55                   	push   rbp
   140001f5c:	48 89 e5             	mov    rbp,rsp
   140001f5f:	48 83 ec 20          	sub    rsp,0x20
   140001f63:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f67:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f6b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f6f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f74:	74 25                	je     140001f9b <__write_memory+0x40>
   140001f76:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f7a:	48 89 c1             	mov    rcx,rax
   140001f7d:	e8 23 fc ff ff       	call   140001ba5 <mark_section_writable>
   140001f82:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f86:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f8a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f8e:	49 89 c8             	mov    r8,rcx
   140001f91:	48 89 c1             	mov    rcx,rax
   140001f94:	e8 df 76 00 00       	call   140009678 <memcpy>
   140001f99:	eb 01                	jmp    140001f9c <__write_memory+0x41>
   140001f9b:	90                   	nop
   140001f9c:	48 83 c4 20          	add    rsp,0x20
   140001fa0:	5d                   	pop    rbp
   140001fa1:	c3                   	ret

0000000140001fa2 <do_pseudo_reloc>:
   140001fa2:	55                   	push   rbp
   140001fa3:	48 89 e5             	mov    rbp,rsp
   140001fa6:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001faa:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fae:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001fb2:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001fb6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001fba:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001fbe:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001fc2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fc6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001fca:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001fcf:	0f 8e 44 03 00 00    	jle    140002319 <do_pseudo_reloc+0x377>
   140001fd5:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001fda:	7e 25                	jle    140002001 <do_pseudo_reloc+0x5f>
   140001fdc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fe0:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fe2:	85 c0                	test   eax,eax
   140001fe4:	75 1b                	jne    140002001 <do_pseudo_reloc+0x5f>
   140001fe6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fea:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fed:	85 c0                	test   eax,eax
   140001fef:	75 10                	jne    140002001 <do_pseudo_reloc+0x5f>
   140001ff1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001ff5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001ff8:	85 c0                	test   eax,eax
   140001ffa:	75 05                	jne    140002001 <do_pseudo_reloc+0x5f>
   140001ffc:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002001:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002005:	8b 00                	mov    eax,DWORD PTR [rax]
   140002007:	85 c0                	test   eax,eax
   140002009:	75 0b                	jne    140002016 <do_pseudo_reloc+0x74>
   14000200b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000200f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002012:	85 c0                	test   eax,eax
   140002014:	74 59                	je     14000206f <do_pseudo_reloc+0xcd>
   140002016:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000201a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000201e:	eb 40                	jmp    140002060 <do_pseudo_reloc+0xbe>
   140002020:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002024:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002027:	89 c2                	mov    edx,eax
   140002029:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000202d:	48 01 d0             	add    rax,rdx
   140002030:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002034:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002038:	8b 10                	mov    edx,DWORD PTR [rax]
   14000203a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000203e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002040:	01 d0                	add    eax,edx
   140002042:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002045:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002049:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000204d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002053:	48 89 c1             	mov    rcx,rax
   140002056:	e8 00 ff ff ff       	call   140001f5b <__write_memory>
   14000205b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002060:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002064:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002068:	72 b6                	jb     140002020 <do_pseudo_reloc+0x7e>
   14000206a:	e9 ab 02 00 00       	jmp    14000231a <do_pseudo_reloc+0x378>
   14000206f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002073:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002076:	83 f8 01             	cmp    eax,0x1
   140002079:	74 18                	je     140002093 <do_pseudo_reloc+0xf1>
   14000207b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000207f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002082:	89 c2                	mov    edx,eax
   140002084:	48 8d 05 e5 91 00 00 	lea    rax,[rip+0x91e5]        # 14000b270 <.rdata+0xa0>
   14000208b:	48 89 c1             	mov    rcx,rax
   14000208e:	e8 ad fa ff ff       	call   140001b40 <__report_error>
   140002093:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002097:	48 83 c0 0c          	add    rax,0xc
   14000209b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000209f:	e9 65 02 00 00       	jmp    140002309 <do_pseudo_reloc+0x367>
   1400020a4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020a8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020ab:	89 c2                	mov    edx,eax
   1400020ad:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020b1:	48 01 d0             	add    rax,rdx
   1400020b4:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020b8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020bc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020be:	89 c2                	mov    edx,eax
   1400020c0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020c4:	48 01 d0             	add    rax,rdx
   1400020c7:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020cb:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400020cf:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400020d2:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020d6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020da:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020dd:	0f b6 c0             	movzx  eax,al
   1400020e0:	83 f8 40             	cmp    eax,0x40
   1400020e3:	0f 84 b6 00 00 00    	je     14000219f <do_pseudo_reloc+0x1fd>
   1400020e9:	83 f8 40             	cmp    eax,0x40
   1400020ec:	0f 87 ba 00 00 00    	ja     1400021ac <do_pseudo_reloc+0x20a>
   1400020f2:	83 f8 20             	cmp    eax,0x20
   1400020f5:	74 77                	je     14000216e <do_pseudo_reloc+0x1cc>
   1400020f7:	83 f8 20             	cmp    eax,0x20
   1400020fa:	0f 87 ac 00 00 00    	ja     1400021ac <do_pseudo_reloc+0x20a>
   140002100:	83 f8 08             	cmp    eax,0x8
   140002103:	74 0a                	je     14000210f <do_pseudo_reloc+0x16d>
   140002105:	83 f8 10             	cmp    eax,0x10
   140002108:	74 38                	je     140002142 <do_pseudo_reloc+0x1a0>
   14000210a:	e9 9d 00 00 00       	jmp    1400021ac <do_pseudo_reloc+0x20a>
   14000210f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002113:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002116:	0f b6 c0             	movzx  eax,al
   140002119:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000211d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002121:	25 80 00 00 00       	and    eax,0x80
   140002126:	48 85 c0             	test   rax,rax
   140002129:	0f 84 9d 00 00 00    	je     1400021cc <do_pseudo_reloc+0x22a>
   14000212f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002133:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002139:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000213d:	e9 8a 00 00 00       	jmp    1400021cc <do_pseudo_reloc+0x22a>
   140002142:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002146:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002149:	0f b7 c0             	movzx  eax,ax
   14000214c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002150:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002154:	25 00 80 00 00       	and    eax,0x8000
   140002159:	48 85 c0             	test   rax,rax
   14000215c:	74 71                	je     1400021cf <do_pseudo_reloc+0x22d>
   14000215e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002162:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002168:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000216c:	eb 61                	jmp    1400021cf <do_pseudo_reloc+0x22d>
   14000216e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002172:	8b 00                	mov    eax,DWORD PTR [rax]
   140002174:	89 c0                	mov    eax,eax
   140002176:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000217a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000217e:	25 00 00 00 80       	and    eax,0x80000000
   140002183:	48 85 c0             	test   rax,rax
   140002186:	74 4a                	je     1400021d2 <do_pseudo_reloc+0x230>
   140002188:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000218c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002193:	ff ff ff 
   140002196:	48 09 d0             	or     rax,rdx
   140002199:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000219d:	eb 33                	jmp    1400021d2 <do_pseudo_reloc+0x230>
   14000219f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021a3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400021a6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021aa:	eb 27                	jmp    1400021d3 <do_pseudo_reloc+0x231>
   1400021ac:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   1400021b3:	00 
   1400021b4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021b8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021bb:	0f b6 c0             	movzx  eax,al
   1400021be:	48 8d 0d e3 90 00 00 	lea    rcx,[rip+0x90e3]        # 14000b2a8 <.rdata+0xd8>
   1400021c5:	89 c2                	mov    edx,eax
   1400021c7:	e8 74 f9 ff ff       	call   140001b40 <__report_error>
   1400021cc:	90                   	nop
   1400021cd:	eb 04                	jmp    1400021d3 <do_pseudo_reloc+0x231>
   1400021cf:	90                   	nop
   1400021d0:	eb 01                	jmp    1400021d3 <do_pseudo_reloc+0x231>
   1400021d2:	90                   	nop
   1400021d3:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   1400021d7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021db:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021dd:	89 c2                	mov    edx,eax
   1400021df:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400021e3:	48 01 c2             	add    rdx,rax
   1400021e6:	48 89 c8             	mov    rax,rcx
   1400021e9:	48 29 d0             	sub    rax,rdx
   1400021ec:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021f0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021f4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400021f8:	48 01 d0             	add    rax,rdx
   1400021fb:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ff:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002203:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002206:	25 ff 00 00 00       	and    eax,0xff
   14000220b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000220e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002212:	77 67                	ja     14000227b <do_pseudo_reloc+0x2d9>
   140002214:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002217:	ba 01 00 00 00       	mov    edx,0x1
   14000221c:	89 c1                	mov    ecx,eax
   14000221e:	48 d3 e2             	shl    rdx,cl
   140002221:	48 89 d0             	mov    rax,rdx
   140002224:	48 83 e8 01          	sub    rax,0x1
   140002228:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000222c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000222f:	83 e8 01             	sub    eax,0x1
   140002232:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002239:	89 c1                	mov    ecx,eax
   14000223b:	48 d3 e2             	shl    rdx,cl
   14000223e:	48 89 d0             	mov    rax,rdx
   140002241:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002245:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002249:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000224d:	7c 0a                	jl     140002259 <do_pseudo_reloc+0x2b7>
   14000224f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002253:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002257:	7e 22                	jle    14000227b <do_pseudo_reloc+0x2d9>
   140002259:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000225d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002261:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002265:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002268:	48 8d 0d 69 90 00 00 	lea    rcx,[rip+0x9069]        # 14000b2d8 <.rdata+0x108>
   14000226f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002274:	89 c2                	mov    edx,eax
   140002276:	e8 c5 f8 ff ff       	call   140001b40 <__report_error>
   14000227b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000227f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002282:	0f b6 c0             	movzx  eax,al
   140002285:	83 f8 40             	cmp    eax,0x40
   140002288:	74 63                	je     1400022ed <do_pseudo_reloc+0x34b>
   14000228a:	83 f8 40             	cmp    eax,0x40
   14000228d:	77 75                	ja     140002304 <do_pseudo_reloc+0x362>
   14000228f:	83 f8 20             	cmp    eax,0x20
   140002292:	74 41                	je     1400022d5 <do_pseudo_reloc+0x333>
   140002294:	83 f8 20             	cmp    eax,0x20
   140002297:	77 6b                	ja     140002304 <do_pseudo_reloc+0x362>
   140002299:	83 f8 08             	cmp    eax,0x8
   14000229c:	74 07                	je     1400022a5 <do_pseudo_reloc+0x303>
   14000229e:	83 f8 10             	cmp    eax,0x10
   1400022a1:	74 1a                	je     1400022bd <do_pseudo_reloc+0x31b>
   1400022a3:	eb 5f                	jmp    140002304 <do_pseudo_reloc+0x362>
   1400022a5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022a9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022ad:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400022b3:	48 89 c1             	mov    rcx,rax
   1400022b6:	e8 a0 fc ff ff       	call   140001f5b <__write_memory>
   1400022bb:	eb 47                	jmp    140002304 <do_pseudo_reloc+0x362>
   1400022bd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022c1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022c5:	41 b8 02 00 00 00    	mov    r8d,0x2
   1400022cb:	48 89 c1             	mov    rcx,rax
   1400022ce:	e8 88 fc ff ff       	call   140001f5b <__write_memory>
   1400022d3:	eb 2f                	jmp    140002304 <do_pseudo_reloc+0x362>
   1400022d5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022d9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022dd:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400022e3:	48 89 c1             	mov    rcx,rax
   1400022e6:	e8 70 fc ff ff       	call   140001f5b <__write_memory>
   1400022eb:	eb 17                	jmp    140002304 <do_pseudo_reloc+0x362>
   1400022ed:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022f1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022f5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400022fb:	48 89 c1             	mov    rcx,rax
   1400022fe:	e8 58 fc ff ff       	call   140001f5b <__write_memory>
   140002303:	90                   	nop
   140002304:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002309:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000230d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002311:	0f 82 8d fd ff ff    	jb     1400020a4 <do_pseudo_reloc+0x102>
   140002317:	eb 01                	jmp    14000231a <do_pseudo_reloc+0x378>
   140002319:	90                   	nop
   14000231a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000231e:	5d                   	pop    rbp
   14000231f:	c3                   	ret

0000000140002320 <_pei386_runtime_relocator>:
   140002320:	55                   	push   rbp
   140002321:	48 89 e5             	mov    rbp,rsp
   140002324:	48 83 ec 30          	sub    rsp,0x30
   140002328:	8b 05 be cd 00 00    	mov    eax,DWORD PTR [rip+0xcdbe]        # 14000f0ec <was_init.0>
   14000232e:	85 c0                	test   eax,eax
   140002330:	0f 85 88 00 00 00    	jne    1400023be <_pei386_runtime_relocator+0x9e>
   140002336:	8b 05 b0 cd 00 00    	mov    eax,DWORD PTR [rip+0xcdb0]        # 14000f0ec <was_init.0>
   14000233c:	83 c0 01             	add    eax,0x1
   14000233f:	89 05 a7 cd 00 00    	mov    DWORD PTR [rip+0xcda7],eax        # 14000f0ec <was_init.0>
   140002345:	e8 21 0b 00 00       	call   140002e6b <__mingw_GetSectionCount>
   14000234a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000234d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002350:	48 63 d0             	movsxd rdx,eax
   140002353:	48 89 d0             	mov    rax,rdx
   140002356:	48 c1 e0 02          	shl    rax,0x2
   14000235a:	48 01 d0             	add    rax,rdx
   14000235d:	48 c1 e0 03          	shl    rax,0x3
   140002361:	48 83 c0 0f          	add    rax,0xf
   140002365:	48 c1 e8 04          	shr    rax,0x4
   140002369:	48 c1 e0 04          	shl    rax,0x4
   14000236d:	e8 7e 0d 00 00       	call   1400030f0 <___chkstk_ms>
   140002372:	48 29 c4             	sub    rsp,rax
   140002375:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000237a:	48 83 c0 0f          	add    rax,0xf
   14000237e:	48 c1 e8 04          	shr    rax,0x4
   140002382:	48 c1 e0 04          	shl    rax,0x4
   140002386:	48 89 05 53 cd 00 00 	mov    QWORD PTR [rip+0xcd53],rax        # 14000f0e0 <the_secs>
   14000238d:	c7 05 51 cd 00 00 00 	mov    DWORD PTR [rip+0xcd51],0x0        # 14000f0e8 <maxSections>
   140002394:	00 00 00 
   140002397:	48 8b 0d e2 91 00 00 	mov    rcx,QWORD PTR [rip+0x91e2]        # 14000b580 <.refptr.__ImageBase>
   14000239e:	48 8b 15 eb 91 00 00 	mov    rdx,QWORD PTR [rip+0x91eb]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   1400023a5:	48 8b 05 f4 91 00 00 	mov    rax,QWORD PTR [rip+0x91f4]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   1400023ac:	49 89 c8             	mov    r8,rcx
   1400023af:	48 89 c1             	mov    rcx,rax
   1400023b2:	e8 eb fb ff ff       	call   140001fa2 <do_pseudo_reloc>
   1400023b7:	e8 c7 fa ff ff       	call   140001e83 <restore_modified_sections>
   1400023bc:	eb 01                	jmp    1400023bf <_pei386_runtime_relocator+0x9f>
   1400023be:	90                   	nop
   1400023bf:	48 89 ec             	mov    rsp,rbp
   1400023c2:	5d                   	pop    rbp
   1400023c3:	c3                   	ret
   1400023c4:	90                   	nop
   1400023c5:	90                   	nop
   1400023c6:	90                   	nop
   1400023c7:	90                   	nop
   1400023c8:	90                   	nop
   1400023c9:	90                   	nop
   1400023ca:	90                   	nop
   1400023cb:	90                   	nop
   1400023cc:	90                   	nop
   1400023cd:	90                   	nop
   1400023ce:	90                   	nop
   1400023cf:	90                   	nop

00000001400023d0 <__mingw_raise_matherr>:
   1400023d0:	55                   	push   rbp
   1400023d1:	48 89 e5             	mov    rbp,rsp
   1400023d4:	48 83 ec 50          	sub    rsp,0x50
   1400023d8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400023db:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400023df:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   1400023e4:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   1400023e9:	48 8b 05 00 cd 00 00 	mov    rax,QWORD PTR [rip+0xcd00]        # 14000f0f0 <stUserMathErr>
   1400023f0:	48 85 c0             	test   rax,rax
   1400023f3:	74 3e                	je     140002433 <__mingw_raise_matherr+0x63>
   1400023f5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400023f8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400023fb:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400023ff:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002403:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002408:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000240d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002412:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002417:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000241c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002421:	48 8b 15 c8 cc 00 00 	mov    rdx,QWORD PTR [rip+0xccc8]        # 14000f0f0 <stUserMathErr>
   140002428:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000242c:	48 89 c1             	mov    rcx,rax
   14000242f:	ff d2                	call   rdx
   140002431:	eb 01                	jmp    140002434 <__mingw_raise_matherr+0x64>
   140002433:	90                   	nop
   140002434:	48 83 c4 50          	add    rsp,0x50
   140002438:	5d                   	pop    rbp
   140002439:	c3                   	ret

000000014000243a <__mingw_setusermatherr>:
   14000243a:	55                   	push   rbp
   14000243b:	48 89 e5             	mov    rbp,rsp
   14000243e:	48 83 ec 20          	sub    rsp,0x20
   140002442:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002446:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000244a:	48 89 05 9f cc 00 00 	mov    QWORD PTR [rip+0xcc9f],rax        # 14000f0f0 <stUserMathErr>
   140002451:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002455:	48 89 c1             	mov    rcx,rax
   140002458:	e8 93 71 00 00       	call   1400095f0 <__setusermatherr>
   14000245d:	90                   	nop
   14000245e:	48 83 c4 20          	add    rsp,0x20
   140002462:	5d                   	pop    rbp
   140002463:	c3                   	ret
   140002464:	90                   	nop
   140002465:	90                   	nop
   140002466:	90                   	nop
   140002467:	90                   	nop
   140002468:	90                   	nop
   140002469:	90                   	nop
   14000246a:	90                   	nop
   14000246b:	90                   	nop
   14000246c:	90                   	nop
   14000246d:	90                   	nop
   14000246e:	90                   	nop
   14000246f:	90                   	nop

0000000140002470 <__mingw_SEH_error_handler>:
   140002470:	55                   	push   rbp
   140002471:	48 89 e5             	mov    rbp,rsp
   140002474:	48 83 ec 30          	sub    rsp,0x30
   140002478:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000247c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002480:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002484:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002488:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000248f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002496:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000249a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000249d:	83 e0 02             	and    eax,0x2
   1400024a0:	85 c0                	test   eax,eax
   1400024a2:	74 0a                	je     1400024ae <__mingw_SEH_error_handler+0x3e>
   1400024a4:	b8 01 00 00 00       	mov    eax,0x1
   1400024a9:	e9 16 02 00 00       	jmp    1400026c4 <__mingw_SEH_error_handler+0x254>
   1400024ae:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024b2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024b4:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400024b9:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400024be:	75 18                	jne    1400024d8 <__mingw_SEH_error_handler+0x68>
   1400024c0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024c4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024c7:	83 e0 01             	and    eax,0x1
   1400024ca:	85 c0                	test   eax,eax
   1400024cc:	75 0a                	jne    1400024d8 <__mingw_SEH_error_handler+0x68>
   1400024ce:	b8 00 00 00 00       	mov    eax,0x0
   1400024d3:	e9 ec 01 00 00       	jmp    1400026c4 <__mingw_SEH_error_handler+0x254>
   1400024d8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024dc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024de:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024e3:	0f 84 12 01 00 00    	je     1400025fb <__mingw_SEH_error_handler+0x18b>
   1400024e9:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024ee:	0f 87 c3 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   1400024f4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400024f9:	0f 87 b8 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   1400024ff:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002504:	0f 83 4c 01 00 00    	jae    140002656 <__mingw_SEH_error_handler+0x1e6>
   14000250a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000250f:	0f 84 3a 01 00 00    	je     14000264f <__mingw_SEH_error_handler+0x1df>
   140002515:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000251a:	0f 87 97 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   140002520:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002525:	0f 84 83 01 00 00    	je     1400026ae <__mingw_SEH_error_handler+0x23e>
   14000252b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002530:	0f 87 81 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   140002536:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000253b:	0f 87 76 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   140002541:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002546:	0f 83 03 01 00 00    	jae    14000264f <__mingw_SEH_error_handler+0x1df>
   14000254c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002551:	0f 84 57 01 00 00    	je     1400026ae <__mingw_SEH_error_handler+0x23e>
   140002557:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000255c:	0f 87 55 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   140002562:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002567:	0f 84 8e 00 00 00    	je     1400025fb <__mingw_SEH_error_handler+0x18b>
   14000256d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002572:	0f 87 3f 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   140002578:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000257d:	0f 84 2b 01 00 00    	je     1400026ae <__mingw_SEH_error_handler+0x23e>
   140002583:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002588:	0f 87 29 01 00 00    	ja     1400026b7 <__mingw_SEH_error_handler+0x247>
   14000258e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002593:	0f 84 15 01 00 00    	je     1400026ae <__mingw_SEH_error_handler+0x23e>
   140002599:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000259e:	0f 85 13 01 00 00    	jne    1400026b7 <__mingw_SEH_error_handler+0x247>
   1400025a4:	ba 00 00 00 00       	mov    edx,0x0
   1400025a9:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025ae:	e8 dd 70 00 00       	call   140009690 <signal>
   1400025b3:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025b7:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025bc:	75 1b                	jne    1400025d9 <__mingw_SEH_error_handler+0x169>
   1400025be:	ba 01 00 00 00       	mov    edx,0x1
   1400025c3:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025c8:	e8 c3 70 00 00       	call   140009690 <signal>
   1400025cd:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025d4:	e9 e1 00 00 00       	jmp    1400026ba <__mingw_SEH_error_handler+0x24a>
   1400025d9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025de:	0f 84 d6 00 00 00    	je     1400026ba <__mingw_SEH_error_handler+0x24a>
   1400025e4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025e8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025ed:	ff d0                	call   rax
   1400025ef:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025f6:	e9 bf 00 00 00       	jmp    1400026ba <__mingw_SEH_error_handler+0x24a>
   1400025fb:	ba 00 00 00 00       	mov    edx,0x0
   140002600:	b9 04 00 00 00       	mov    ecx,0x4
   140002605:	e8 86 70 00 00       	call   140009690 <signal>
   14000260a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000260e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002613:	75 1b                	jne    140002630 <__mingw_SEH_error_handler+0x1c0>
   140002615:	ba 01 00 00 00       	mov    edx,0x1
   14000261a:	b9 04 00 00 00       	mov    ecx,0x4
   14000261f:	e8 6c 70 00 00       	call   140009690 <signal>
   140002624:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000262b:	e9 8d 00 00 00       	jmp    1400026bd <__mingw_SEH_error_handler+0x24d>
   140002630:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002635:	0f 84 82 00 00 00    	je     1400026bd <__mingw_SEH_error_handler+0x24d>
   14000263b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000263f:	b9 04 00 00 00       	mov    ecx,0x4
   140002644:	ff d0                	call   rax
   140002646:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000264d:	eb 6e                	jmp    1400026bd <__mingw_SEH_error_handler+0x24d>
   14000264f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002656:	ba 00 00 00 00       	mov    edx,0x0
   14000265b:	b9 08 00 00 00       	mov    ecx,0x8
   140002660:	e8 2b 70 00 00       	call   140009690 <signal>
   140002665:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002669:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000266e:	75 23                	jne    140002693 <__mingw_SEH_error_handler+0x223>
   140002670:	ba 01 00 00 00       	mov    edx,0x1
   140002675:	b9 08 00 00 00       	mov    ecx,0x8
   14000267a:	e8 11 70 00 00       	call   140009690 <signal>
   14000267f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002683:	74 05                	je     14000268a <__mingw_SEH_error_handler+0x21a>
   140002685:	e8 a6 05 00 00       	call   140002c30 <_fpreset>
   14000268a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002691:	eb 2d                	jmp    1400026c0 <__mingw_SEH_error_handler+0x250>
   140002693:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002698:	74 26                	je     1400026c0 <__mingw_SEH_error_handler+0x250>
   14000269a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000269e:	b9 08 00 00 00       	mov    ecx,0x8
   1400026a3:	ff d0                	call   rax
   1400026a5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026ac:	eb 12                	jmp    1400026c0 <__mingw_SEH_error_handler+0x250>
   1400026ae:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026b5:	eb 0a                	jmp    1400026c1 <__mingw_SEH_error_handler+0x251>
   1400026b7:	90                   	nop
   1400026b8:	eb 07                	jmp    1400026c1 <__mingw_SEH_error_handler+0x251>
   1400026ba:	90                   	nop
   1400026bb:	eb 04                	jmp    1400026c1 <__mingw_SEH_error_handler+0x251>
   1400026bd:	90                   	nop
   1400026be:	eb 01                	jmp    1400026c1 <__mingw_SEH_error_handler+0x251>
   1400026c0:	90                   	nop
   1400026c1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400026c4:	48 83 c4 30          	add    rsp,0x30
   1400026c8:	5d                   	pop    rbp
   1400026c9:	c3                   	ret

00000001400026ca <_gnu_exception_handler>:
   1400026ca:	55                   	push   rbp
   1400026cb:	48 89 e5             	mov    rbp,rsp
   1400026ce:	48 83 ec 30          	sub    rsp,0x30
   1400026d2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400026d6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026dd:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400026e4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026e8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026ed:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400026f2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400026f7:	75 1b                	jne    140002714 <_gnu_exception_handler+0x4a>
   1400026f9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026fd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002700:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002703:	83 e0 01             	and    eax,0x1
   140002706:	85 c0                	test   eax,eax
   140002708:	75 0a                	jne    140002714 <_gnu_exception_handler+0x4a>
   14000270a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000270f:	e9 14 02 00 00       	jmp    140002928 <_gnu_exception_handler+0x25e>
   140002714:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002718:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000271b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000271d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002722:	0f 84 12 01 00 00    	je     14000283a <_gnu_exception_handler+0x170>
   140002728:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000272d:	0f 87 c3 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   140002733:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002738:	0f 87 b8 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   14000273e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002743:	0f 83 4c 01 00 00    	jae    140002895 <_gnu_exception_handler+0x1cb>
   140002749:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000274e:	0f 84 3a 01 00 00    	je     14000288e <_gnu_exception_handler+0x1c4>
   140002754:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002759:	0f 87 97 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   14000275f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002764:	0f 84 83 01 00 00    	je     1400028ed <_gnu_exception_handler+0x223>
   14000276a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000276f:	0f 87 81 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   140002775:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000277a:	0f 87 76 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   140002780:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002785:	0f 83 03 01 00 00    	jae    14000288e <_gnu_exception_handler+0x1c4>
   14000278b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002790:	0f 84 57 01 00 00    	je     1400028ed <_gnu_exception_handler+0x223>
   140002796:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000279b:	0f 87 55 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   1400027a1:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027a6:	0f 84 8e 00 00 00    	je     14000283a <_gnu_exception_handler+0x170>
   1400027ac:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027b1:	0f 87 3f 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   1400027b7:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027bc:	0f 84 2b 01 00 00    	je     1400028ed <_gnu_exception_handler+0x223>
   1400027c2:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027c7:	0f 87 29 01 00 00    	ja     1400028f6 <_gnu_exception_handler+0x22c>
   1400027cd:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400027d2:	0f 84 15 01 00 00    	je     1400028ed <_gnu_exception_handler+0x223>
   1400027d8:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400027dd:	0f 85 13 01 00 00    	jne    1400028f6 <_gnu_exception_handler+0x22c>
   1400027e3:	ba 00 00 00 00       	mov    edx,0x0
   1400027e8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027ed:	e8 9e 6e 00 00       	call   140009690 <signal>
   1400027f2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027f6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027fb:	75 1b                	jne    140002818 <_gnu_exception_handler+0x14e>
   1400027fd:	ba 01 00 00 00       	mov    edx,0x1
   140002802:	b9 0b 00 00 00       	mov    ecx,0xb
   140002807:	e8 84 6e 00 00       	call   140009690 <signal>
   14000280c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002813:	e9 e1 00 00 00       	jmp    1400028f9 <_gnu_exception_handler+0x22f>
   140002818:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000281d:	0f 84 d6 00 00 00    	je     1400028f9 <_gnu_exception_handler+0x22f>
   140002823:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002827:	b9 0b 00 00 00       	mov    ecx,0xb
   14000282c:	ff d0                	call   rax
   14000282e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002835:	e9 bf 00 00 00       	jmp    1400028f9 <_gnu_exception_handler+0x22f>
   14000283a:	ba 00 00 00 00       	mov    edx,0x0
   14000283f:	b9 04 00 00 00       	mov    ecx,0x4
   140002844:	e8 47 6e 00 00       	call   140009690 <signal>
   140002849:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000284d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002852:	75 1b                	jne    14000286f <_gnu_exception_handler+0x1a5>
   140002854:	ba 01 00 00 00       	mov    edx,0x1
   140002859:	b9 04 00 00 00       	mov    ecx,0x4
   14000285e:	e8 2d 6e 00 00       	call   140009690 <signal>
   140002863:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000286a:	e9 8d 00 00 00       	jmp    1400028fc <_gnu_exception_handler+0x232>
   14000286f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002874:	0f 84 82 00 00 00    	je     1400028fc <_gnu_exception_handler+0x232>
   14000287a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000287e:	b9 04 00 00 00       	mov    ecx,0x4
   140002883:	ff d0                	call   rax
   140002885:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000288c:	eb 6e                	jmp    1400028fc <_gnu_exception_handler+0x232>
   14000288e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002895:	ba 00 00 00 00       	mov    edx,0x0
   14000289a:	b9 08 00 00 00       	mov    ecx,0x8
   14000289f:	e8 ec 6d 00 00       	call   140009690 <signal>
   1400028a4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028a8:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028ad:	75 23                	jne    1400028d2 <_gnu_exception_handler+0x208>
   1400028af:	ba 01 00 00 00       	mov    edx,0x1
   1400028b4:	b9 08 00 00 00       	mov    ecx,0x8
   1400028b9:	e8 d2 6d 00 00       	call   140009690 <signal>
   1400028be:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400028c2:	74 05                	je     1400028c9 <_gnu_exception_handler+0x1ff>
   1400028c4:	e8 67 03 00 00       	call   140002c30 <_fpreset>
   1400028c9:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028d0:	eb 2d                	jmp    1400028ff <_gnu_exception_handler+0x235>
   1400028d2:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028d7:	74 26                	je     1400028ff <_gnu_exception_handler+0x235>
   1400028d9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028dd:	b9 08 00 00 00       	mov    ecx,0x8
   1400028e2:	ff d0                	call   rax
   1400028e4:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028eb:	eb 12                	jmp    1400028ff <_gnu_exception_handler+0x235>
   1400028ed:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028f4:	eb 0a                	jmp    140002900 <_gnu_exception_handler+0x236>
   1400028f6:	90                   	nop
   1400028f7:	eb 07                	jmp    140002900 <_gnu_exception_handler+0x236>
   1400028f9:	90                   	nop
   1400028fa:	eb 04                	jmp    140002900 <_gnu_exception_handler+0x236>
   1400028fc:	90                   	nop
   1400028fd:	eb 01                	jmp    140002900 <_gnu_exception_handler+0x236>
   1400028ff:	90                   	nop
   140002900:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002904:	75 1f                	jne    140002925 <_gnu_exception_handler+0x25b>
   140002906:	48 8b 05 03 c8 00 00 	mov    rax,QWORD PTR [rip+0xc803]        # 14000f110 <__mingw_oldexcpt_handler>
   14000290d:	48 85 c0             	test   rax,rax
   140002910:	74 13                	je     140002925 <_gnu_exception_handler+0x25b>
   140002912:	48 8b 15 f7 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc7f7]        # 14000f110 <__mingw_oldexcpt_handler>
   140002919:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000291d:	48 89 c1             	mov    rcx,rax
   140002920:	ff d2                	call   rdx
   140002922:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002925:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002928:	48 83 c4 30          	add    rsp,0x30
   14000292c:	5d                   	pop    rbp
   14000292d:	c3                   	ret
   14000292e:	90                   	nop
   14000292f:	90                   	nop

0000000140002930 <___w64_mingwthr_add_key_dtor>:
   140002930:	55                   	push   rbp
   140002931:	48 89 e5             	mov    rbp,rsp
   140002934:	48 83 ec 30          	sub    rsp,0x30
   140002938:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000293b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000293f:	8b 05 03 c8 00 00    	mov    eax,DWORD PTR [rip+0xc803]        # 14000f148 <__mingwthr_cs_init>
   140002945:	85 c0                	test   eax,eax
   140002947:	75 07                	jne    140002950 <___w64_mingwthr_add_key_dtor+0x20>
   140002949:	b8 00 00 00 00       	mov    eax,0x0
   14000294e:	eb 7b                	jmp    1400029cb <___w64_mingwthr_add_key_dtor+0x9b>
   140002950:	ba 18 00 00 00       	mov    edx,0x18
   140002955:	b9 01 00 00 00       	mov    ecx,0x1
   14000295a:	e8 d9 6c 00 00       	call   140009638 <calloc>
   14000295f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002963:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002968:	75 07                	jne    140002971 <___w64_mingwthr_add_key_dtor+0x41>
   14000296a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000296f:	eb 5a                	jmp    1400029cb <___w64_mingwthr_add_key_dtor+0x9b>
   140002971:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002975:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002978:	89 10                	mov    DWORD PTR [rax],edx
   14000297a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000297e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002982:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002986:	48 8d 05 93 c7 00 00 	lea    rax,[rip+0xc793]        # 14000f120 <__mingwthr_cs>
   14000298d:	48 89 c1             	mov    rcx,rax
   140002990:	48 8b 05 61 d8 00 00 	mov    rax,QWORD PTR [rip+0xd861]        # 1400101f8 <__imp_EnterCriticalSection>
   140002997:	ff d0                	call   rax
   140002999:	48 8b 15 b0 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc7b0]        # 14000f150 <key_dtor_list>
   1400029a0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029a4:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029a8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029ac:	48 89 05 9d c7 00 00 	mov    QWORD PTR [rip+0xc79d],rax        # 14000f150 <key_dtor_list>
   1400029b3:	48 8d 05 66 c7 00 00 	lea    rax,[rip+0xc766]        # 14000f120 <__mingwthr_cs>
   1400029ba:	48 89 c1             	mov    rcx,rax
   1400029bd:	48 8b 05 6c d8 00 00 	mov    rax,QWORD PTR [rip+0xd86c]        # 140010230 <__imp_LeaveCriticalSection>
   1400029c4:	ff d0                	call   rax
   1400029c6:	b8 00 00 00 00       	mov    eax,0x0
   1400029cb:	48 83 c4 30          	add    rsp,0x30
   1400029cf:	5d                   	pop    rbp
   1400029d0:	c3                   	ret

00000001400029d1 <___w64_mingwthr_remove_key_dtor>:
   1400029d1:	55                   	push   rbp
   1400029d2:	48 89 e5             	mov    rbp,rsp
   1400029d5:	48 83 ec 30          	sub    rsp,0x30
   1400029d9:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029dc:	8b 05 66 c7 00 00    	mov    eax,DWORD PTR [rip+0xc766]        # 14000f148 <__mingwthr_cs_init>
   1400029e2:	85 c0                	test   eax,eax
   1400029e4:	75 0a                	jne    1400029f0 <___w64_mingwthr_remove_key_dtor+0x1f>
   1400029e6:	b8 00 00 00 00       	mov    eax,0x0
   1400029eb:	e9 9c 00 00 00       	jmp    140002a8c <___w64_mingwthr_remove_key_dtor+0xbb>
   1400029f0:	48 8d 05 29 c7 00 00 	lea    rax,[rip+0xc729]        # 14000f120 <__mingwthr_cs>
   1400029f7:	48 89 c1             	mov    rcx,rax
   1400029fa:	48 8b 05 f7 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7f7]        # 1400101f8 <__imp_EnterCriticalSection>
   140002a01:	ff d0                	call   rax
   140002a03:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a0a:	00 
   140002a0b:	48 8b 05 3e c7 00 00 	mov    rax,QWORD PTR [rip+0xc73e]        # 14000f150 <key_dtor_list>
   140002a12:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a16:	eb 55                	jmp    140002a6d <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a18:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a1c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a1e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a21:	75 36                	jne    140002a59 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a23:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a28:	75 11                	jne    140002a3b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a2e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a32:	48 89 05 17 c7 00 00 	mov    QWORD PTR [rip+0xc717],rax        # 14000f150 <key_dtor_list>
   140002a39:	eb 10                	jmp    140002a4b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a3b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a3f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a43:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a47:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a4b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a4f:	48 89 c1             	mov    rcx,rax
   140002a52:	e8 09 6c 00 00       	call   140009660 <free>
   140002a57:	eb 1b                	jmp    140002a74 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a59:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a5d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a61:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a65:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a69:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a6d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a72:	75 a4                	jne    140002a18 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a74:	48 8d 05 a5 c6 00 00 	lea    rax,[rip+0xc6a5]        # 14000f120 <__mingwthr_cs>
   140002a7b:	48 89 c1             	mov    rcx,rax
   140002a7e:	48 8b 05 ab d7 00 00 	mov    rax,QWORD PTR [rip+0xd7ab]        # 140010230 <__imp_LeaveCriticalSection>
   140002a85:	ff d0                	call   rax
   140002a87:	b8 00 00 00 00       	mov    eax,0x0
   140002a8c:	48 83 c4 30          	add    rsp,0x30
   140002a90:	5d                   	pop    rbp
   140002a91:	c3                   	ret

0000000140002a92 <__mingwthr_run_key_dtors>:
   140002a92:	55                   	push   rbp
   140002a93:	48 89 e5             	mov    rbp,rsp
   140002a96:	48 83 ec 30          	sub    rsp,0x30
   140002a9a:	8b 05 a8 c6 00 00    	mov    eax,DWORD PTR [rip+0xc6a8]        # 14000f148 <__mingwthr_cs_init>
   140002aa0:	85 c0                	test   eax,eax
   140002aa2:	0f 84 82 00 00 00    	je     140002b2a <__mingwthr_run_key_dtors+0x98>
   140002aa8:	48 8d 05 71 c6 00 00 	lea    rax,[rip+0xc671]        # 14000f120 <__mingwthr_cs>
   140002aaf:	48 89 c1             	mov    rcx,rax
   140002ab2:	48 8b 05 3f d7 00 00 	mov    rax,QWORD PTR [rip+0xd73f]        # 1400101f8 <__imp_EnterCriticalSection>
   140002ab9:	ff d0                	call   rax
   140002abb:	48 8b 05 8e c6 00 00 	mov    rax,QWORD PTR [rip+0xc68e]        # 14000f150 <key_dtor_list>
   140002ac2:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ac6:	eb 46                	jmp    140002b0e <__mingwthr_run_key_dtors+0x7c>
   140002ac8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002acc:	8b 00                	mov    eax,DWORD PTR [rax]
   140002ace:	89 c1                	mov    ecx,eax
   140002ad0:	48 8b 05 81 d7 00 00 	mov    rax,QWORD PTR [rip+0xd781]        # 140010258 <__imp_TlsGetValue>
   140002ad7:	ff d0                	call   rax
   140002ad9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002add:	48 8b 05 2c d7 00 00 	mov    rax,QWORD PTR [rip+0xd72c]        # 140010210 <__imp_GetLastError>
   140002ae4:	ff d0                	call   rax
   140002ae6:	85 c0                	test   eax,eax
   140002ae8:	75 18                	jne    140002b02 <__mingwthr_run_key_dtors+0x70>
   140002aea:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002aef:	74 11                	je     140002b02 <__mingwthr_run_key_dtors+0x70>
   140002af1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002af5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002af9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002afd:	48 89 c1             	mov    rcx,rax
   140002b00:	ff d2                	call   rdx
   140002b02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b06:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b0a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b0e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b13:	75 b3                	jne    140002ac8 <__mingwthr_run_key_dtors+0x36>
   140002b15:	48 8d 05 04 c6 00 00 	lea    rax,[rip+0xc604]        # 14000f120 <__mingwthr_cs>
   140002b1c:	48 89 c1             	mov    rcx,rax
   140002b1f:	48 8b 05 0a d7 00 00 	mov    rax,QWORD PTR [rip+0xd70a]        # 140010230 <__imp_LeaveCriticalSection>
   140002b26:	ff d0                	call   rax
   140002b28:	eb 01                	jmp    140002b2b <__mingwthr_run_key_dtors+0x99>
   140002b2a:	90                   	nop
   140002b2b:	48 83 c4 30          	add    rsp,0x30
   140002b2f:	5d                   	pop    rbp
   140002b30:	c3                   	ret

0000000140002b31 <__mingw_TLScallback>:
   140002b31:	55                   	push   rbp
   140002b32:	48 89 e5             	mov    rbp,rsp
   140002b35:	48 83 ec 30          	sub    rsp,0x30
   140002b39:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b3d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b40:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b44:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b48:	0f 84 cc 00 00 00    	je     140002c1a <__mingw_TLScallback+0xe9>
   140002b4e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b52:	0f 87 ca 00 00 00    	ja     140002c22 <__mingw_TLScallback+0xf1>
   140002b58:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b5c:	0f 84 b1 00 00 00    	je     140002c13 <__mingw_TLScallback+0xe2>
   140002b62:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b66:	0f 87 b6 00 00 00    	ja     140002c22 <__mingw_TLScallback+0xf1>
   140002b6c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b70:	74 33                	je     140002ba5 <__mingw_TLScallback+0x74>
   140002b72:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b76:	0f 85 a6 00 00 00    	jne    140002c22 <__mingw_TLScallback+0xf1>
   140002b7c:	8b 05 c6 c5 00 00    	mov    eax,DWORD PTR [rip+0xc5c6]        # 14000f148 <__mingwthr_cs_init>
   140002b82:	85 c0                	test   eax,eax
   140002b84:	75 13                	jne    140002b99 <__mingw_TLScallback+0x68>
   140002b86:	48 8d 05 93 c5 00 00 	lea    rax,[rip+0xc593]        # 14000f120 <__mingwthr_cs>
   140002b8d:	48 89 c1             	mov    rcx,rax
   140002b90:	48 8b 05 91 d6 00 00 	mov    rax,QWORD PTR [rip+0xd691]        # 140010228 <__imp_InitializeCriticalSection>
   140002b97:	ff d0                	call   rax
   140002b99:	c7 05 a5 c5 00 00 01 	mov    DWORD PTR [rip+0xc5a5],0x1        # 14000f148 <__mingwthr_cs_init>
   140002ba0:	00 00 00 
   140002ba3:	eb 7d                	jmp    140002c22 <__mingw_TLScallback+0xf1>
   140002ba5:	e8 e8 fe ff ff       	call   140002a92 <__mingwthr_run_key_dtors>
   140002baa:	8b 05 98 c5 00 00    	mov    eax,DWORD PTR [rip+0xc598]        # 14000f148 <__mingwthr_cs_init>
   140002bb0:	83 f8 01             	cmp    eax,0x1
   140002bb3:	75 6c                	jne    140002c21 <__mingw_TLScallback+0xf0>
   140002bb5:	48 8b 05 94 c5 00 00 	mov    rax,QWORD PTR [rip+0xc594]        # 14000f150 <key_dtor_list>
   140002bbc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bc0:	eb 20                	jmp    140002be2 <__mingw_TLScallback+0xb1>
   140002bc2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bc6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002bca:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002bce:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bd2:	48 89 c1             	mov    rcx,rax
   140002bd5:	e8 86 6a 00 00       	call   140009660 <free>
   140002bda:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bde:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002be2:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002be7:	75 d9                	jne    140002bc2 <__mingw_TLScallback+0x91>
   140002be9:	48 c7 05 5c c5 00 00 	mov    QWORD PTR [rip+0xc55c],0x0        # 14000f150 <key_dtor_list>
   140002bf0:	00 00 00 00 
   140002bf4:	c7 05 4a c5 00 00 00 	mov    DWORD PTR [rip+0xc54a],0x0        # 14000f148 <__mingwthr_cs_init>
   140002bfb:	00 00 00 
   140002bfe:	48 8d 05 1b c5 00 00 	lea    rax,[rip+0xc51b]        # 14000f120 <__mingwthr_cs>
   140002c05:	48 89 c1             	mov    rcx,rax
   140002c08:	48 8b 05 e1 d5 00 00 	mov    rax,QWORD PTR [rip+0xd5e1]        # 1400101f0 <__IAT_start__>
   140002c0f:	ff d0                	call   rax
   140002c11:	eb 0e                	jmp    140002c21 <__mingw_TLScallback+0xf0>
   140002c13:	e8 18 00 00 00       	call   140002c30 <_fpreset>
   140002c18:	eb 08                	jmp    140002c22 <__mingw_TLScallback+0xf1>
   140002c1a:	e8 73 fe ff ff       	call   140002a92 <__mingwthr_run_key_dtors>
   140002c1f:	eb 01                	jmp    140002c22 <__mingw_TLScallback+0xf1>
   140002c21:	90                   	nop
   140002c22:	b8 01 00 00 00       	mov    eax,0x1
   140002c27:	48 83 c4 30          	add    rsp,0x30
   140002c2b:	5d                   	pop    rbp
   140002c2c:	c3                   	ret
   140002c2d:	90                   	nop
   140002c2e:	90                   	nop
   140002c2f:	90                   	nop

0000000140002c30 <_fpreset>:
   140002c30:	55                   	push   rbp
   140002c31:	48 89 e5             	mov    rbp,rsp
   140002c34:	db e3                	fninit
   140002c36:	90                   	nop
   140002c37:	5d                   	pop    rbp
   140002c38:	c3                   	ret
   140002c39:	90                   	nop
   140002c3a:	90                   	nop
   140002c3b:	90                   	nop
   140002c3c:	90                   	nop
   140002c3d:	90                   	nop
   140002c3e:	90                   	nop
   140002c3f:	90                   	nop

0000000140002c40 <_ValidateImageBase>:
   140002c40:	55                   	push   rbp
   140002c41:	48 89 e5             	mov    rbp,rsp
   140002c44:	48 83 ec 20          	sub    rsp,0x20
   140002c48:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c4c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c50:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c58:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c5b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c5f:	74 07                	je     140002c68 <_ValidateImageBase+0x28>
   140002c61:	b8 00 00 00 00       	mov    eax,0x0
   140002c66:	eb 4e                	jmp    140002cb6 <_ValidateImageBase+0x76>
   140002c68:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c6c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c6f:	48 63 d0             	movsxd rdx,eax
   140002c72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c76:	48 01 d0             	add    rax,rdx
   140002c79:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c7d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c81:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c83:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c88:	74 07                	je     140002c91 <_ValidateImageBase+0x51>
   140002c8a:	b8 00 00 00 00       	mov    eax,0x0
   140002c8f:	eb 25                	jmp    140002cb6 <_ValidateImageBase+0x76>
   140002c91:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c95:	48 83 c0 18          	add    rax,0x18
   140002c99:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c9d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ca1:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002ca4:	66 3d 0b 02          	cmp    ax,0x20b
   140002ca8:	74 07                	je     140002cb1 <_ValidateImageBase+0x71>
   140002caa:	b8 00 00 00 00       	mov    eax,0x0
   140002caf:	eb 05                	jmp    140002cb6 <_ValidateImageBase+0x76>
   140002cb1:	b8 01 00 00 00       	mov    eax,0x1
   140002cb6:	48 83 c4 20          	add    rsp,0x20
   140002cba:	5d                   	pop    rbp
   140002cbb:	c3                   	ret

0000000140002cbc <_FindPESection>:
   140002cbc:	55                   	push   rbp
   140002cbd:	48 89 e5             	mov    rbp,rsp
   140002cc0:	48 83 ec 20          	sub    rsp,0x20
   140002cc4:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002cc8:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002ccc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cd0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002cd3:	48 63 d0             	movsxd rdx,eax
   140002cd6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cda:	48 01 d0             	add    rax,rdx
   140002cdd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ce1:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ce8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cec:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002cf0:	0f b7 d0             	movzx  edx,ax
   140002cf3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cf7:	48 01 d0             	add    rax,rdx
   140002cfa:	48 83 c0 18          	add    rax,0x18
   140002cfe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d02:	eb 36                	jmp    140002d3a <_FindPESection+0x7e>
   140002d04:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d08:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d0b:	89 c0                	mov    eax,eax
   140002d0d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d11:	72 1e                	jb     140002d31 <_FindPESection+0x75>
   140002d13:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d17:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d1a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d1e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d21:	01 d0                	add    eax,edx
   140002d23:	89 c0                	mov    eax,eax
   140002d25:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d29:	73 06                	jae    140002d31 <_FindPESection+0x75>
   140002d2b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d2f:	eb 1e                	jmp    140002d4f <_FindPESection+0x93>
   140002d31:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d35:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d3a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d3e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d42:	0f b7 c0             	movzx  eax,ax
   140002d45:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d48:	72 ba                	jb     140002d04 <_FindPESection+0x48>
   140002d4a:	b8 00 00 00 00       	mov    eax,0x0
   140002d4f:	48 83 c4 20          	add    rsp,0x20
   140002d53:	5d                   	pop    rbp
   140002d54:	c3                   	ret

0000000140002d55 <_FindPESectionByName>:
   140002d55:	55                   	push   rbp
   140002d56:	48 89 e5             	mov    rbp,rsp
   140002d59:	48 83 ec 40          	sub    rsp,0x40
   140002d5d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d61:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d65:	48 89 c1             	mov    rcx,rax
   140002d68:	e8 33 69 00 00       	call   1400096a0 <strlen>
   140002d6d:	48 83 f8 08          	cmp    rax,0x8
   140002d71:	76 0a                	jbe    140002d7d <_FindPESectionByName+0x28>
   140002d73:	b8 00 00 00 00       	mov    eax,0x0
   140002d78:	e9 98 00 00 00       	jmp    140002e15 <_FindPESectionByName+0xc0>
   140002d7d:	48 8b 05 fc 87 00 00 	mov    rax,QWORD PTR [rip+0x87fc]        # 14000b580 <.refptr.__ImageBase>
   140002d84:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d88:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d8c:	48 89 c1             	mov    rcx,rax
   140002d8f:	e8 ac fe ff ff       	call   140002c40 <_ValidateImageBase>
   140002d94:	85 c0                	test   eax,eax
   140002d96:	75 07                	jne    140002d9f <_FindPESectionByName+0x4a>
   140002d98:	b8 00 00 00 00       	mov    eax,0x0
   140002d9d:	eb 76                	jmp    140002e15 <_FindPESectionByName+0xc0>
   140002d9f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002da3:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002da6:	48 63 d0             	movsxd rdx,eax
   140002da9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dad:	48 01 d0             	add    rax,rdx
   140002db0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002db4:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002dbb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dbf:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002dc3:	0f b7 d0             	movzx  edx,ax
   140002dc6:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dca:	48 01 d0             	add    rax,rdx
   140002dcd:	48 83 c0 18          	add    rax,0x18
   140002dd1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002dd5:	eb 29                	jmp    140002e00 <_FindPESectionByName+0xab>
   140002dd7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ddb:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002ddf:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002de5:	48 89 c1             	mov    rcx,rax
   140002de8:	e8 bb 68 00 00       	call   1400096a8 <strncmp>
   140002ded:	85 c0                	test   eax,eax
   140002def:	75 06                	jne    140002df7 <_FindPESectionByName+0xa2>
   140002df1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002df5:	eb 1e                	jmp    140002e15 <_FindPESectionByName+0xc0>
   140002df7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002dfb:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e00:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e04:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e08:	0f b7 c0             	movzx  eax,ax
   140002e0b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e0e:	72 c7                	jb     140002dd7 <_FindPESectionByName+0x82>
   140002e10:	b8 00 00 00 00       	mov    eax,0x0
   140002e15:	48 83 c4 40          	add    rsp,0x40
   140002e19:	5d                   	pop    rbp
   140002e1a:	c3                   	ret

0000000140002e1b <__mingw_GetSectionForAddress>:
   140002e1b:	55                   	push   rbp
   140002e1c:	48 89 e5             	mov    rbp,rsp
   140002e1f:	48 83 ec 30          	sub    rsp,0x30
   140002e23:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e27:	48 8b 05 52 87 00 00 	mov    rax,QWORD PTR [rip+0x8752]        # 14000b580 <.refptr.__ImageBase>
   140002e2e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e32:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e36:	48 89 c1             	mov    rcx,rax
   140002e39:	e8 02 fe ff ff       	call   140002c40 <_ValidateImageBase>
   140002e3e:	85 c0                	test   eax,eax
   140002e40:	75 07                	jne    140002e49 <__mingw_GetSectionForAddress+0x2e>
   140002e42:	b8 00 00 00 00       	mov    eax,0x0
   140002e47:	eb 1c                	jmp    140002e65 <__mingw_GetSectionForAddress+0x4a>
   140002e49:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e4d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e51:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e55:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e59:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e5d:	48 89 c1             	mov    rcx,rax
   140002e60:	e8 57 fe ff ff       	call   140002cbc <_FindPESection>
   140002e65:	48 83 c4 30          	add    rsp,0x30
   140002e69:	5d                   	pop    rbp
   140002e6a:	c3                   	ret

0000000140002e6b <__mingw_GetSectionCount>:
   140002e6b:	55                   	push   rbp
   140002e6c:	48 89 e5             	mov    rbp,rsp
   140002e6f:	48 83 ec 30          	sub    rsp,0x30
   140002e73:	48 8b 05 06 87 00 00 	mov    rax,QWORD PTR [rip+0x8706]        # 14000b580 <.refptr.__ImageBase>
   140002e7a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e7e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e82:	48 89 c1             	mov    rcx,rax
   140002e85:	e8 b6 fd ff ff       	call   140002c40 <_ValidateImageBase>
   140002e8a:	85 c0                	test   eax,eax
   140002e8c:	75 07                	jne    140002e95 <__mingw_GetSectionCount+0x2a>
   140002e8e:	b8 00 00 00 00       	mov    eax,0x0
   140002e93:	eb 20                	jmp    140002eb5 <__mingw_GetSectionCount+0x4a>
   140002e95:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e99:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e9c:	48 63 d0             	movsxd rdx,eax
   140002e9f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ea3:	48 01 d0             	add    rax,rdx
   140002ea6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002eaa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002eae:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002eb2:	0f b7 c0             	movzx  eax,ax
   140002eb5:	48 83 c4 30          	add    rsp,0x30
   140002eb9:	5d                   	pop    rbp
   140002eba:	c3                   	ret

0000000140002ebb <_FindPESectionExec>:
   140002ebb:	55                   	push   rbp
   140002ebc:	48 89 e5             	mov    rbp,rsp
   140002ebf:	48 83 ec 40          	sub    rsp,0x40
   140002ec3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ec7:	48 8b 05 b2 86 00 00 	mov    rax,QWORD PTR [rip+0x86b2]        # 14000b580 <.refptr.__ImageBase>
   140002ece:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ed2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ed6:	48 89 c1             	mov    rcx,rax
   140002ed9:	e8 62 fd ff ff       	call   140002c40 <_ValidateImageBase>
   140002ede:	85 c0                	test   eax,eax
   140002ee0:	75 07                	jne    140002ee9 <_FindPESectionExec+0x2e>
   140002ee2:	b8 00 00 00 00       	mov    eax,0x0
   140002ee7:	eb 78                	jmp    140002f61 <_FindPESectionExec+0xa6>
   140002ee9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002eed:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ef0:	48 63 d0             	movsxd rdx,eax
   140002ef3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ef7:	48 01 d0             	add    rax,rdx
   140002efa:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002efe:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f05:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f09:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f0d:	0f b7 d0             	movzx  edx,ax
   140002f10:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f14:	48 01 d0             	add    rax,rdx
   140002f17:	48 83 c0 18          	add    rax,0x18
   140002f1b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f1f:	eb 2b                	jmp    140002f4c <_FindPESectionExec+0x91>
   140002f21:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f25:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f28:	25 00 00 00 20       	and    eax,0x20000000
   140002f2d:	85 c0                	test   eax,eax
   140002f2f:	74 12                	je     140002f43 <_FindPESectionExec+0x88>
   140002f31:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f36:	75 06                	jne    140002f3e <_FindPESectionExec+0x83>
   140002f38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f3c:	eb 23                	jmp    140002f61 <_FindPESectionExec+0xa6>
   140002f3e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f43:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f47:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f4c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f50:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f54:	0f b7 c0             	movzx  eax,ax
   140002f57:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f5a:	72 c5                	jb     140002f21 <_FindPESectionExec+0x66>
   140002f5c:	b8 00 00 00 00       	mov    eax,0x0
   140002f61:	48 83 c4 40          	add    rsp,0x40
   140002f65:	5d                   	pop    rbp
   140002f66:	c3                   	ret

0000000140002f67 <_GetPEImageBase>:
   140002f67:	55                   	push   rbp
   140002f68:	48 89 e5             	mov    rbp,rsp
   140002f6b:	48 83 ec 30          	sub    rsp,0x30
   140002f6f:	48 8b 05 0a 86 00 00 	mov    rax,QWORD PTR [rip+0x860a]        # 14000b580 <.refptr.__ImageBase>
   140002f76:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f7a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f7e:	48 89 c1             	mov    rcx,rax
   140002f81:	e8 ba fc ff ff       	call   140002c40 <_ValidateImageBase>
   140002f86:	85 c0                	test   eax,eax
   140002f88:	75 07                	jne    140002f91 <_GetPEImageBase+0x2a>
   140002f8a:	b8 00 00 00 00       	mov    eax,0x0
   140002f8f:	eb 04                	jmp    140002f95 <_GetPEImageBase+0x2e>
   140002f91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f95:	48 83 c4 30          	add    rsp,0x30
   140002f99:	5d                   	pop    rbp
   140002f9a:	c3                   	ret

0000000140002f9b <_IsNonwritableInCurrentImage>:
   140002f9b:	55                   	push   rbp
   140002f9c:	48 89 e5             	mov    rbp,rsp
   140002f9f:	48 83 ec 40          	sub    rsp,0x40
   140002fa3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002fa7:	48 8b 05 d2 85 00 00 	mov    rax,QWORD PTR [rip+0x85d2]        # 14000b580 <.refptr.__ImageBase>
   140002fae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fb2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fb6:	48 89 c1             	mov    rcx,rax
   140002fb9:	e8 82 fc ff ff       	call   140002c40 <_ValidateImageBase>
   140002fbe:	85 c0                	test   eax,eax
   140002fc0:	75 07                	jne    140002fc9 <_IsNonwritableInCurrentImage+0x2e>
   140002fc2:	b8 00 00 00 00       	mov    eax,0x0
   140002fc7:	eb 3d                	jmp    140003006 <_IsNonwritableInCurrentImage+0x6b>
   140002fc9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002fcd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002fd1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fd5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002fd9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fdd:	48 89 c1             	mov    rcx,rax
   140002fe0:	e8 d7 fc ff ff       	call   140002cbc <_FindPESection>
   140002fe5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002fe9:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002fee:	75 07                	jne    140002ff7 <_IsNonwritableInCurrentImage+0x5c>
   140002ff0:	b8 00 00 00 00       	mov    eax,0x0
   140002ff5:	eb 0f                	jmp    140003006 <_IsNonwritableInCurrentImage+0x6b>
   140002ff7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ffb:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002ffe:	f7 d0                	not    eax
   140003000:	c1 e8 1f             	shr    eax,0x1f
   140003003:	0f b6 c0             	movzx  eax,al
   140003006:	48 83 c4 40          	add    rsp,0x40
   14000300a:	5d                   	pop    rbp
   14000300b:	c3                   	ret

000000014000300c <__mingw_enum_import_library_names>:
   14000300c:	55                   	push   rbp
   14000300d:	48 89 e5             	mov    rbp,rsp
   140003010:	48 83 ec 50          	sub    rsp,0x50
   140003014:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003017:	48 8b 05 62 85 00 00 	mov    rax,QWORD PTR [rip+0x8562]        # 14000b580 <.refptr.__ImageBase>
   14000301e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003022:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003026:	48 89 c1             	mov    rcx,rax
   140003029:	e8 12 fc ff ff       	call   140002c40 <_ValidateImageBase>
   14000302e:	85 c0                	test   eax,eax
   140003030:	75 0a                	jne    14000303c <__mingw_enum_import_library_names+0x30>
   140003032:	b8 00 00 00 00       	mov    eax,0x0
   140003037:	e9 ab 00 00 00       	jmp    1400030e7 <__mingw_enum_import_library_names+0xdb>
   14000303c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003040:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003043:	48 63 d0             	movsxd rdx,eax
   140003046:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000304a:	48 01 d0             	add    rax,rdx
   14000304d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003051:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003055:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000305b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000305e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003062:	75 07                	jne    14000306b <__mingw_enum_import_library_names+0x5f>
   140003064:	b8 00 00 00 00       	mov    eax,0x0
   140003069:	eb 7c                	jmp    1400030e7 <__mingw_enum_import_library_names+0xdb>
   14000306b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000306e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003072:	48 89 c1             	mov    rcx,rax
   140003075:	e8 42 fc ff ff       	call   140002cbc <_FindPESection>
   14000307a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000307e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003083:	75 07                	jne    14000308c <__mingw_enum_import_library_names+0x80>
   140003085:	b8 00 00 00 00       	mov    eax,0x0
   14000308a:	eb 5b                	jmp    1400030e7 <__mingw_enum_import_library_names+0xdb>
   14000308c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000308f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003093:	48 01 d0             	add    rax,rdx
   140003096:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000309a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000309f:	75 07                	jne    1400030a8 <__mingw_enum_import_library_names+0x9c>
   1400030a1:	b8 00 00 00 00       	mov    eax,0x0
   1400030a6:	eb 3f                	jmp    1400030e7 <__mingw_enum_import_library_names+0xdb>
   1400030a8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030ac:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400030af:	85 c0                	test   eax,eax
   1400030b1:	75 0b                	jne    1400030be <__mingw_enum_import_library_names+0xb2>
   1400030b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030b7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030ba:	85 c0                	test   eax,eax
   1400030bc:	74 23                	je     1400030e1 <__mingw_enum_import_library_names+0xd5>
   1400030be:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400030c2:	7f 12                	jg     1400030d6 <__mingw_enum_import_library_names+0xca>
   1400030c4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030c8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030cb:	89 c2                	mov    edx,eax
   1400030cd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030d1:	48 01 d0             	add    rax,rdx
   1400030d4:	eb 11                	jmp    1400030e7 <__mingw_enum_import_library_names+0xdb>
   1400030d6:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   1400030da:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   1400030df:	eb c7                	jmp    1400030a8 <__mingw_enum_import_library_names+0x9c>
   1400030e1:	90                   	nop
   1400030e2:	b8 00 00 00 00       	mov    eax,0x0
   1400030e7:	48 83 c4 50          	add    rsp,0x50
   1400030eb:	5d                   	pop    rbp
   1400030ec:	c3                   	ret
   1400030ed:	90                   	nop
   1400030ee:	90                   	nop
   1400030ef:	90                   	nop

00000001400030f0 <___chkstk_ms>:
   1400030f0:	51                   	push   rcx
   1400030f1:	50                   	push   rax
   1400030f2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030f8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400030fd:	72 19                	jb     140003118 <___chkstk_ms+0x28>
   1400030ff:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003106:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000310a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003110:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003116:	77 e7                	ja     1400030ff <___chkstk_ms+0xf>
   140003118:	48 29 c1             	sub    rcx,rax
   14000311b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000311f:	58                   	pop    rax
   140003120:	59                   	pop    rcx
   140003121:	c3                   	ret
   140003122:	90                   	nop
   140003123:	90                   	nop
   140003124:	90                   	nop
   140003125:	90                   	nop
   140003126:	90                   	nop
   140003127:	90                   	nop
   140003128:	90                   	nop
   140003129:	90                   	nop
   14000312a:	90                   	nop
   14000312b:	90                   	nop
   14000312c:	90                   	nop
   14000312d:	90                   	nop
   14000312e:	90                   	nop
   14000312f:	90                   	nop

0000000140003130 <__mingw_printf>:
   140003130:	55                   	push   rbp
   140003131:	53                   	push   rbx
   140003132:	48 83 ec 48          	sub    rsp,0x48
   140003136:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   14000313b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000313f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140003143:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003147:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   14000314b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   14000314f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003153:	b9 01 00 00 00       	mov    ecx,0x1
   140003158:	e8 c3 5e 00 00       	call   140009020 <__acrt_iob_func>
   14000315d:	48 89 c1             	mov    rcx,rax
   140003160:	e8 3b 5d 00 00       	call   140008ea0 <_lock_file>
   140003165:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140003169:	b9 01 00 00 00       	mov    ecx,0x1
   14000316e:	e8 ad 5e 00 00       	call   140009020 <__acrt_iob_func>
   140003173:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003177:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
   14000317c:	49 89 d1             	mov    r9,rdx
   14000317f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140003185:	48 89 c2             	mov    rdx,rax
   140003188:	b9 00 60 00 00       	mov    ecx,0x6000
   14000318d:	e8 b1 1f 00 00       	call   140005143 <__mingw_pformat>
   140003192:	89 c3                	mov    ebx,eax
   140003194:	b9 01 00 00 00       	mov    ecx,0x1
   140003199:	e8 82 5e 00 00       	call   140009020 <__acrt_iob_func>
   14000319e:	48 89 c1             	mov    rcx,rax
   1400031a1:	e8 84 5d 00 00       	call   140008f2a <_unlock_file>
   1400031a6:	89 d8                	mov    eax,ebx
   1400031a8:	48 83 c4 48          	add    rsp,0x48
   1400031ac:	5b                   	pop    rbx
   1400031ad:	5d                   	pop    rbp
   1400031ae:	c3                   	ret
   1400031af:	90                   	nop

00000001400031b0 <__pformat_putc>:
   1400031b0:	55                   	push   rbp
   1400031b1:	48 89 e5             	mov    rbp,rsp
   1400031b4:	48 83 ec 20          	sub    rsp,0x20
   1400031b8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031bb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400031bf:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031c3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400031c6:	25 00 40 00 00       	and    eax,0x4000
   1400031cb:	85 c0                	test   eax,eax
   1400031cd:	75 12                	jne    1400031e1 <__pformat_putc+0x31>
   1400031cf:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031d3:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   1400031d6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031da:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031dd:	39 c2                	cmp    edx,eax
   1400031df:	7e 3b                	jle    14000321c <__pformat_putc+0x6c>
   1400031e1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031e5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400031e8:	25 00 20 00 00       	and    eax,0x2000
   1400031ed:	85 c0                	test   eax,eax
   1400031ef:	74 13                	je     140003204 <__pformat_putc+0x54>
   1400031f1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031f5:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400031f8:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400031fb:	89 c1                	mov    ecx,eax
   1400031fd:	e8 56 64 00 00       	call   140009658 <fputc>
   140003202:	eb 18                	jmp    14000321c <__pformat_putc+0x6c>
   140003204:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003208:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   14000320b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000320f:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003212:	48 98                	cdqe
   140003214:	48 01 d0             	add    rax,rdx
   140003217:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   14000321a:	88 10                	mov    BYTE PTR [rax],dl
   14000321c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003220:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003223:	8d 50 01             	lea    edx,[rax+0x1]
   140003226:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000322a:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   14000322d:	90                   	nop
   14000322e:	48 83 c4 20          	add    rsp,0x20
   140003232:	5d                   	pop    rbp
   140003233:	c3                   	ret

0000000140003234 <__pformat_putchars>:
   140003234:	55                   	push   rbp
   140003235:	48 89 e5             	mov    rbp,rsp
   140003238:	48 83 ec 20          	sub    rsp,0x20
   14000323c:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003240:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003243:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003247:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000324b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000324e:	85 c0                	test   eax,eax
   140003250:	78 16                	js     140003268 <__pformat_putchars+0x34>
   140003252:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003256:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003259:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000325c:	7e 0a                	jle    140003268 <__pformat_putchars+0x34>
   14000325e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003262:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003265:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003268:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000326c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000326f:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003272:	7d 15                	jge    140003289 <__pformat_putchars+0x55>
   140003274:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003278:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000327b:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000327e:	89 c2                	mov    edx,eax
   140003280:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003284:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003287:	eb 0b                	jmp    140003294 <__pformat_putchars+0x60>
   140003289:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000328d:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003294:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003298:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000329b:	85 c0                	test   eax,eax
   14000329d:	7e 57                	jle    1400032f6 <__pformat_putchars+0xc2>
   14000329f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032a3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400032a6:	25 00 04 00 00       	and    eax,0x400
   1400032ab:	85 c0                	test   eax,eax
   1400032ad:	75 47                	jne    1400032f6 <__pformat_putchars+0xc2>
   1400032af:	eb 11                	jmp    1400032c2 <__pformat_putchars+0x8e>
   1400032b1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032b5:	48 89 c2             	mov    rdx,rax
   1400032b8:	b9 20 00 00 00       	mov    ecx,0x20
   1400032bd:	e8 ee fe ff ff       	call   1400031b0 <__pformat_putc>
   1400032c2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032c6:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032c9:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400032cc:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400032d0:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400032d3:	85 c0                	test   eax,eax
   1400032d5:	75 da                	jne    1400032b1 <__pformat_putchars+0x7d>
   1400032d7:	eb 1d                	jmp    1400032f6 <__pformat_putchars+0xc2>
   1400032d9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400032dd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400032e1:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   1400032e5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400032e8:	0f be c0             	movsx  eax,al
   1400032eb:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400032ef:	89 c1                	mov    ecx,eax
   1400032f1:	e8 ba fe ff ff       	call   1400031b0 <__pformat_putc>
   1400032f6:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400032f9:	8d 50 ff             	lea    edx,[rax-0x1]
   1400032fc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400032ff:	85 c0                	test   eax,eax
   140003301:	75 d6                	jne    1400032d9 <__pformat_putchars+0xa5>
   140003303:	eb 11                	jmp    140003316 <__pformat_putchars+0xe2>
   140003305:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003309:	48 89 c2             	mov    rdx,rax
   14000330c:	b9 20 00 00 00       	mov    ecx,0x20
   140003311:	e8 9a fe ff ff       	call   1400031b0 <__pformat_putc>
   140003316:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000331a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000331d:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003320:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003324:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003327:	85 c0                	test   eax,eax
   140003329:	7f da                	jg     140003305 <__pformat_putchars+0xd1>
   14000332b:	90                   	nop
   14000332c:	90                   	nop
   14000332d:	48 83 c4 20          	add    rsp,0x20
   140003331:	5d                   	pop    rbp
   140003332:	c3                   	ret

0000000140003333 <__pformat_puts>:
   140003333:	55                   	push   rbp
   140003334:	48 89 e5             	mov    rbp,rsp
   140003337:	48 83 ec 20          	sub    rsp,0x20
   14000333b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000333f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003343:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140003348:	75 0b                	jne    140003355 <__pformat_puts+0x22>
   14000334a:	48 8d 05 df 7f 00 00 	lea    rax,[rip+0x7fdf]        # 14000b330 <.rdata>
   140003351:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003355:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003359:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000335c:	85 c0                	test   eax,eax
   14000335e:	78 2f                	js     14000338f <__pformat_puts+0x5c>
   140003360:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003364:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003367:	48 63 d0             	movsxd rdx,eax
   14000336a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000336e:	48 89 c1             	mov    rcx,rax
   140003371:	e8 4a 5a 00 00       	call   140008dc0 <strnlen>
   140003376:	89 c1                	mov    ecx,eax
   140003378:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000337c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003380:	49 89 d0             	mov    r8,rdx
   140003383:	89 ca                	mov    edx,ecx
   140003385:	48 89 c1             	mov    rcx,rax
   140003388:	e8 a7 fe ff ff       	call   140003234 <__pformat_putchars>
   14000338d:	eb 23                	jmp    1400033b2 <__pformat_puts+0x7f>
   14000338f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003393:	48 89 c1             	mov    rcx,rax
   140003396:	e8 05 63 00 00       	call   1400096a0 <strlen>
   14000339b:	89 c1                	mov    ecx,eax
   14000339d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400033a1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033a5:	49 89 d0             	mov    r8,rdx
   1400033a8:	89 ca                	mov    edx,ecx
   1400033aa:	48 89 c1             	mov    rcx,rax
   1400033ad:	e8 82 fe ff ff       	call   140003234 <__pformat_putchars>
   1400033b2:	90                   	nop
   1400033b3:	48 83 c4 20          	add    rsp,0x20
   1400033b7:	5d                   	pop    rbp
   1400033b8:	c3                   	ret

00000001400033b9 <__pformat_wputchars>:
   1400033b9:	55                   	push   rbp
   1400033ba:	48 89 e5             	mov    rbp,rsp
   1400033bd:	48 83 ec 50          	sub    rsp,0x50
   1400033c1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400033c5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400033c8:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400033cc:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   1400033d3:	00 
   1400033d4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033d8:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033db:	85 c0                	test   eax,eax
   1400033dd:	78 16                	js     1400033f5 <__pformat_wputchars+0x3c>
   1400033df:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033e3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033e6:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400033e9:	7e 0a                	jle    1400033f5 <__pformat_wputchars+0x3c>
   1400033eb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033ef:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033f2:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400033f5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033f9:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033fc:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400033ff:	7d 15                	jge    140003416 <__pformat_wputchars+0x5d>
   140003401:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003405:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003408:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000340b:	89 c2                	mov    edx,eax
   14000340d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003411:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003414:	eb 0b                	jmp    140003421 <__pformat_wputchars+0x68>
   140003416:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000341a:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003421:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003425:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003428:	85 c0                	test   eax,eax
   14000342a:	7e 6e                	jle    14000349a <__pformat_wputchars+0xe1>
   14000342c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003430:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003433:	25 00 04 00 00       	and    eax,0x400
   140003438:	85 c0                	test   eax,eax
   14000343a:	75 5e                	jne    14000349a <__pformat_wputchars+0xe1>
   14000343c:	eb 11                	jmp    14000344f <__pformat_wputchars+0x96>
   14000343e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003442:	48 89 c2             	mov    rdx,rax
   140003445:	b9 20 00 00 00       	mov    ecx,0x20
   14000344a:	e8 61 fd ff ff       	call   1400031b0 <__pformat_putc>
   14000344f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003453:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003456:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003459:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000345d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003460:	85 c0                	test   eax,eax
   140003462:	75 da                	jne    14000343e <__pformat_wputchars+0x85>
   140003464:	eb 34                	jmp    14000349a <__pformat_wputchars+0xe1>
   140003466:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   14000346a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000346e:	eb 1d                	jmp    14000348d <__pformat_wputchars+0xd4>
   140003470:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003474:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003478:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000347c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000347f:	0f be c0             	movsx  eax,al
   140003482:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003486:	89 c1                	mov    ecx,eax
   140003488:	e8 23 fd ff ff       	call   1400031b0 <__pformat_putc>
   14000348d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003490:	8d 50 ff             	lea    edx,[rax-0x1]
   140003493:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003496:	85 c0                	test   eax,eax
   140003498:	7f d6                	jg     140003470 <__pformat_wputchars+0xb7>
   14000349a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000349d:	8d 50 ff             	lea    edx,[rax-0x1]
   1400034a0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400034a3:	85 c0                	test   eax,eax
   1400034a5:	7e 41                	jle    1400034e8 <__pformat_wputchars+0x12f>
   1400034a7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400034ab:	48 8d 50 02          	lea    rdx,[rax+0x2]
   1400034af:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   1400034b3:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400034b6:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   1400034ba:	0f b7 d0             	movzx  edx,ax
   1400034bd:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400034c1:	49 89 c8             	mov    r8,rcx
   1400034c4:	48 89 c1             	mov    rcx,rax
   1400034c7:	e8 84 5b 00 00       	call   140009050 <wcrtomb>
   1400034cc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400034cf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400034d3:	7f 91                	jg     140003466 <__pformat_wputchars+0xad>
   1400034d5:	eb 11                	jmp    1400034e8 <__pformat_wputchars+0x12f>
   1400034d7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034db:	48 89 c2             	mov    rdx,rax
   1400034de:	b9 20 00 00 00       	mov    ecx,0x20
   1400034e3:	e8 c8 fc ff ff       	call   1400031b0 <__pformat_putc>
   1400034e8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034ec:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034ef:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400034f2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034f6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400034f9:	85 c0                	test   eax,eax
   1400034fb:	7f da                	jg     1400034d7 <__pformat_wputchars+0x11e>
   1400034fd:	90                   	nop
   1400034fe:	90                   	nop
   1400034ff:	48 83 c4 50          	add    rsp,0x50
   140003503:	5d                   	pop    rbp
   140003504:	c3                   	ret

0000000140003505 <__pformat_wcputs>:
   140003505:	55                   	push   rbp
   140003506:	48 89 e5             	mov    rbp,rsp
   140003509:	48 83 ec 20          	sub    rsp,0x20
   14000350d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003511:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003515:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000351a:	75 0b                	jne    140003527 <__pformat_wcputs+0x22>
   14000351c:	48 8d 05 15 7e 00 00 	lea    rax,[rip+0x7e15]        # 14000b338 <.rdata+0x8>
   140003523:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003527:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000352b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000352e:	85 c0                	test   eax,eax
   140003530:	78 2f                	js     140003561 <__pformat_wcputs+0x5c>
   140003532:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003536:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003539:	48 63 d0             	movsxd rdx,eax
   14000353c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003540:	48 89 c1             	mov    rcx,rax
   140003543:	e8 28 58 00 00       	call   140008d70 <wcsnlen>
   140003548:	89 c1                	mov    ecx,eax
   14000354a:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000354e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003552:	49 89 d0             	mov    r8,rdx
   140003555:	89 ca                	mov    edx,ecx
   140003557:	48 89 c1             	mov    rcx,rax
   14000355a:	e8 5a fe ff ff       	call   1400033b9 <__pformat_wputchars>
   14000355f:	eb 23                	jmp    140003584 <__pformat_wcputs+0x7f>
   140003561:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003565:	48 89 c1             	mov    rcx,rax
   140003568:	e8 4b 61 00 00       	call   1400096b8 <wcslen>
   14000356d:	89 c1                	mov    ecx,eax
   14000356f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003573:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003577:	49 89 d0             	mov    r8,rdx
   14000357a:	89 ca                	mov    edx,ecx
   14000357c:	48 89 c1             	mov    rcx,rax
   14000357f:	e8 35 fe ff ff       	call   1400033b9 <__pformat_wputchars>
   140003584:	90                   	nop
   140003585:	48 83 c4 20          	add    rsp,0x20
   140003589:	5d                   	pop    rbp
   14000358a:	c3                   	ret

000000014000358b <__pformat_int_bufsiz>:
   14000358b:	55                   	push   rbp
   14000358c:	48 89 e5             	mov    rbp,rsp
   14000358f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003592:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003595:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003599:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000359c:	83 e8 01             	sub    eax,0x1
   14000359f:	48 98                	cdqe
   1400035a1:	48 83 c0 40          	add    rax,0x40
   1400035a5:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400035a8:	48 63 ca             	movsxd rcx,edx
   1400035ab:	ba 00 00 00 00       	mov    edx,0x0
   1400035b0:	48 f7 f1             	div    rcx
   1400035b3:	89 c2                	mov    edx,eax
   1400035b5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400035b8:	01 d0                	add    eax,edx
   1400035ba:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400035bd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035c1:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400035c4:	ba 00 00 00 00       	mov    edx,0x0
   1400035c9:	85 c0                	test   eax,eax
   1400035cb:	0f 48 c2             	cmovs  eax,edx
   1400035ce:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   1400035d1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035d5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400035d8:	25 00 10 00 00       	and    eax,0x1000
   1400035dd:	85 c0                	test   eax,eax
   1400035df:	74 29                	je     14000360a <__pformat_int_bufsiz+0x7f>
   1400035e1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035e5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400035e9:	66 85 c0             	test   ax,ax
   1400035ec:	74 1c                	je     14000360a <__pformat_int_bufsiz+0x7f>
   1400035ee:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035f1:	48 63 d0             	movsxd rdx,eax
   1400035f4:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   1400035fb:	48 89 d1             	mov    rcx,rdx
   1400035fe:	48 c1 e9 20          	shr    rcx,0x20
   140003602:	99                   	cdq
   140003603:	89 c8                	mov    eax,ecx
   140003605:	29 d0                	sub    eax,edx
   140003607:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   14000360a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000360e:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140003611:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003614:	39 c2                	cmp    edx,eax
   140003616:	0f 4d c2             	cmovge eax,edx
   140003619:	5d                   	pop    rbp
   14000361a:	c3                   	ret

000000014000361b <__pformat_int>:
   14000361b:	55                   	push   rbp
   14000361c:	53                   	push   rbx
   14000361d:	48 83 ec 58          	sub    rsp,0x58
   140003621:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003626:	48 89 cb             	mov    rbx,rcx
   140003629:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   14000362c:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   140003630:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   140003634:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   140003638:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000363c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003640:	49 89 c0             	mov    r8,rax
   140003643:	ba 03 00 00 00       	mov    edx,0x3
   140003648:	b9 01 00 00 00       	mov    ecx,0x1
   14000364d:	e8 39 ff ff ff       	call   14000358b <__pformat_int_bufsiz>
   140003652:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140003655:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   14000365c:	00 
   14000365d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140003660:	48 98                	cdqe
   140003662:	48 83 c0 0f          	add    rax,0xf
   140003666:	48 c1 e8 04          	shr    rax,0x4
   14000366a:	48 c1 e0 04          	shl    rax,0x4
   14000366e:	e8 7d fa ff ff       	call   1400030f0 <___chkstk_ms>
   140003673:	48 29 c4             	sub    rsp,rax
   140003676:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000367b:	48 83 c0 0f          	add    rax,0xf
   14000367f:	48 c1 e8 04          	shr    rax,0x4
   140003683:	48 c1 e0 04          	shl    rax,0x4
   140003687:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000368b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000368f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003693:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003697:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000369a:	25 80 00 00 00       	and    eax,0x80
   14000369f:	85 c0                	test   eax,eax
   1400036a1:	0f 84 ea 00 00 00    	je     140003791 <__pformat_int+0x176>
   1400036a7:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400036ab:	48 85 c0             	test   rax,rax
   1400036ae:	79 10                	jns    1400036c0 <__pformat_int+0xa5>
   1400036b0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400036b4:	48 f7 d8             	neg    rax
   1400036b7:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400036bb:	e9 d1 00 00 00       	jmp    140003791 <__pformat_int+0x176>
   1400036c0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036c4:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400036c7:	24 7f                	and    al,0x7f
   1400036c9:	89 c2                	mov    edx,eax
   1400036cb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036cf:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400036d2:	e9 ba 00 00 00       	jmp    140003791 <__pformat_int+0x176>
   1400036d7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036db:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400036df:	74 54                	je     140003735 <__pformat_int+0x11a>
   1400036e1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036e5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400036e8:	25 00 10 00 00       	and    eax,0x1000
   1400036ed:	85 c0                	test   eax,eax
   1400036ef:	74 44                	je     140003735 <__pformat_int+0x11a>
   1400036f1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036f5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400036f9:	66 85 c0             	test   ax,ax
   1400036fc:	74 37                	je     140003735 <__pformat_int+0x11a>
   1400036fe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003702:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   140003706:	48 89 c2             	mov    rdx,rax
   140003709:	48 89 d0             	mov    rax,rdx
   14000370c:	48 c1 f8 3f          	sar    rax,0x3f
   140003710:	48 c1 e8 3e          	shr    rax,0x3e
   140003714:	48 01 c2             	add    rdx,rax
   140003717:	83 e2 03             	and    edx,0x3
   14000371a:	48 29 c2             	sub    rdx,rax
   14000371d:	48 89 d0             	mov    rax,rdx
   140003720:	48 83 f8 03          	cmp    rax,0x3
   140003724:	75 0f                	jne    140003735 <__pformat_int+0x11a>
   140003726:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000372a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000372e:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003732:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   140003735:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   140003739:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003740:	cc cc cc 
   140003743:	48 89 c8             	mov    rax,rcx
   140003746:	48 f7 e2             	mul    rdx
   140003749:	48 c1 ea 03          	shr    rdx,0x3
   14000374d:	48 89 d0             	mov    rax,rdx
   140003750:	48 c1 e0 02          	shl    rax,0x2
   140003754:	48 01 d0             	add    rax,rdx
   140003757:	48 01 c0             	add    rax,rax
   14000375a:	48 29 c1             	sub    rcx,rax
   14000375d:	48 89 ca             	mov    rdx,rcx
   140003760:	89 d0                	mov    eax,edx
   140003762:	8d 48 30             	lea    ecx,[rax+0x30]
   140003765:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003769:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000376d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003771:	89 ca                	mov    edx,ecx
   140003773:	88 10                	mov    BYTE PTR [rax],dl
   140003775:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003779:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003780:	cc cc cc 
   140003783:	48 f7 e2             	mul    rdx
   140003786:	48 89 d0             	mov    rax,rdx
   140003789:	48 c1 e8 03          	shr    rax,0x3
   14000378d:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140003791:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003795:	48 85 c0             	test   rax,rax
   140003798:	0f 85 39 ff ff ff    	jne    1400036d7 <__pformat_int+0xbc>
   14000379e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037a2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400037a5:	85 c0                	test   eax,eax
   1400037a7:	7e 3e                	jle    1400037e7 <__pformat_int+0x1cc>
   1400037a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037ad:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400037b0:	89 c1                	mov    ecx,eax
   1400037b2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037b6:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400037ba:	89 c2                	mov    edx,eax
   1400037bc:	89 c8                	mov    eax,ecx
   1400037be:	29 d0                	sub    eax,edx
   1400037c0:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400037c3:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   1400037c7:	7e 1e                	jle    1400037e7 <__pformat_int+0x1cc>
   1400037c9:	eb 0f                	jmp    1400037da <__pformat_int+0x1bf>
   1400037cb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037cf:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037d3:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037d7:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400037da:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400037dd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400037e0:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   1400037e3:	85 c0                	test   eax,eax
   1400037e5:	7f e4                	jg     1400037cb <__pformat_int+0x1b0>
   1400037e7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037eb:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400037ef:	75 1a                	jne    14000380b <__pformat_int+0x1f0>
   1400037f1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037f5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400037f8:	85 c0                	test   eax,eax
   1400037fa:	74 0f                	je     14000380b <__pformat_int+0x1f0>
   1400037fc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003800:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003804:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003808:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000380b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000380f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003812:	85 c0                	test   eax,eax
   140003814:	0f 8e ce 00 00 00    	jle    1400038e8 <__pformat_int+0x2cd>
   14000381a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000381e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003821:	89 c1                	mov    ecx,eax
   140003823:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003827:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000382b:	89 c2                	mov    edx,eax
   14000382d:	89 c8                	mov    eax,ecx
   14000382f:	29 d0                	sub    eax,edx
   140003831:	89 c2                	mov    edx,eax
   140003833:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003837:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000383a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000383e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003841:	85 c0                	test   eax,eax
   140003843:	0f 8e 9f 00 00 00    	jle    1400038e8 <__pformat_int+0x2cd>
   140003849:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000384d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003850:	25 c0 01 00 00       	and    eax,0x1c0
   140003855:	85 c0                	test   eax,eax
   140003857:	74 11                	je     14000386a <__pformat_int+0x24f>
   140003859:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000385d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003860:	8d 50 ff             	lea    edx,[rax-0x1]
   140003863:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003867:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000386a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000386e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003871:	85 c0                	test   eax,eax
   140003873:	79 3b                	jns    1400038b0 <__pformat_int+0x295>
   140003875:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003879:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000387c:	25 00 06 00 00       	and    eax,0x600
   140003881:	3d 00 02 00 00       	cmp    eax,0x200
   140003886:	75 28                	jne    1400038b0 <__pformat_int+0x295>
   140003888:	eb 0f                	jmp    140003899 <__pformat_int+0x27e>
   14000388a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000388e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003892:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003896:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003899:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000389d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038a0:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400038a3:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400038a7:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400038aa:	85 c0                	test   eax,eax
   1400038ac:	7f dc                	jg     14000388a <__pformat_int+0x26f>
   1400038ae:	eb 38                	jmp    1400038e8 <__pformat_int+0x2cd>
   1400038b0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038b4:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038b7:	25 00 04 00 00       	and    eax,0x400
   1400038bc:	85 c0                	test   eax,eax
   1400038be:	75 28                	jne    1400038e8 <__pformat_int+0x2cd>
   1400038c0:	eb 11                	jmp    1400038d3 <__pformat_int+0x2b8>
   1400038c2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038c6:	48 89 c2             	mov    rdx,rax
   1400038c9:	b9 20 00 00 00       	mov    ecx,0x20
   1400038ce:	e8 dd f8 ff ff       	call   1400031b0 <__pformat_putc>
   1400038d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038d7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038da:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400038dd:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400038e1:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400038e4:	85 c0                	test   eax,eax
   1400038e6:	7f da                	jg     1400038c2 <__pformat_int+0x2a7>
   1400038e8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ec:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038ef:	25 80 00 00 00       	and    eax,0x80
   1400038f4:	85 c0                	test   eax,eax
   1400038f6:	74 11                	je     140003909 <__pformat_int+0x2ee>
   1400038f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038fc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003900:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003904:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   140003907:	eb 5a                	jmp    140003963 <__pformat_int+0x348>
   140003909:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000390d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003910:	25 00 01 00 00       	and    eax,0x100
   140003915:	85 c0                	test   eax,eax
   140003917:	74 11                	je     14000392a <__pformat_int+0x30f>
   140003919:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000391d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003921:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003925:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140003928:	eb 39                	jmp    140003963 <__pformat_int+0x348>
   14000392a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000392e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003931:	83 e0 40             	and    eax,0x40
   140003934:	85 c0                	test   eax,eax
   140003936:	74 2b                	je     140003963 <__pformat_int+0x348>
   140003938:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000393c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003940:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003944:	c6 00 20             	mov    BYTE PTR [rax],0x20
   140003947:	eb 1a                	jmp    140003963 <__pformat_int+0x348>
   140003949:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   14000394e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003952:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003955:	0f be c0             	movsx  eax,al
   140003958:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000395c:	89 c1                	mov    ecx,eax
   14000395e:	e8 4d f8 ff ff       	call   1400031b0 <__pformat_putc>
   140003963:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003967:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   14000396b:	72 dc                	jb     140003949 <__pformat_int+0x32e>
   14000396d:	eb 11                	jmp    140003980 <__pformat_int+0x365>
   14000396f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003973:	48 89 c2             	mov    rdx,rax
   140003976:	b9 20 00 00 00       	mov    ecx,0x20
   14000397b:	e8 30 f8 ff ff       	call   1400031b0 <__pformat_putc>
   140003980:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003984:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003987:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000398a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000398e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003991:	85 c0                	test   eax,eax
   140003993:	7f da                	jg     14000396f <__pformat_int+0x354>
   140003995:	90                   	nop
   140003996:	90                   	nop
   140003997:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   14000399b:	5b                   	pop    rbx
   14000399c:	5d                   	pop    rbp
   14000399d:	c3                   	ret

000000014000399e <__pformat_xint>:
   14000399e:	55                   	push   rbp
   14000399f:	53                   	push   rbx
   1400039a0:	48 83 ec 68          	sub    rsp,0x68
   1400039a4:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   1400039a9:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   1400039ac:	48 89 d3             	mov    rbx,rdx
   1400039af:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   1400039b2:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   1400039b6:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400039ba:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400039be:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400039c2:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   1400039c6:	74 1e                	je     1400039e6 <__pformat_xint+0x48>
   1400039c8:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   1400039cc:	74 06                	je     1400039d4 <__pformat_xint+0x36>
   1400039ce:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   1400039d2:	75 09                	jne    1400039dd <__pformat_xint+0x3f>
   1400039d4:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400039db:	eb 10                	jmp    1400039ed <__pformat_xint+0x4f>
   1400039dd:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   1400039e4:	eb 07                	jmp    1400039ed <__pformat_xint+0x4f>
   1400039e6:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   1400039ed:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   1400039f1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400039f4:	49 89 d0             	mov    r8,rdx
   1400039f7:	89 c2                	mov    edx,eax
   1400039f9:	b9 02 00 00 00       	mov    ecx,0x2
   1400039fe:	e8 88 fb ff ff       	call   14000358b <__pformat_int_bufsiz>
   140003a03:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140003a06:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   140003a0d:	00 
   140003a0e:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140003a11:	48 98                	cdqe
   140003a13:	48 83 c0 0f          	add    rax,0xf
   140003a17:	48 c1 e8 04          	shr    rax,0x4
   140003a1b:	48 c1 e0 04          	shl    rax,0x4
   140003a1f:	e8 cc f6 ff ff       	call   1400030f0 <___chkstk_ms>
   140003a24:	48 29 c4             	sub    rsp,rax
   140003a27:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003a2c:	48 83 c0 0f          	add    rax,0xf
   140003a30:	48 c1 e8 04          	shr    rax,0x4
   140003a34:	48 c1 e0 04          	shl    rax,0x4
   140003a38:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140003a3c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003a40:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003a44:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a48:	74 1e                	je     140003a68 <__pformat_xint+0xca>
   140003a4a:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a4e:	74 06                	je     140003a56 <__pformat_xint+0xb8>
   140003a50:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a54:	75 09                	jne    140003a5f <__pformat_xint+0xc1>
   140003a56:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003a5d:	eb 10                	jmp    140003a6f <__pformat_xint+0xd1>
   140003a5f:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003a66:	eb 67                	jmp    140003acf <__pformat_xint+0x131>
   140003a68:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003a6f:	eb 5e                	jmp    140003acf <__pformat_xint+0x131>
   140003a71:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003a75:	89 c2                	mov    edx,eax
   140003a77:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003a7a:	21 d0                	and    eax,edx
   140003a7c:	8d 48 30             	lea    ecx,[rax+0x30]
   140003a7f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003a83:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003a87:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003a8b:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003a8f:	89 ca                	mov    edx,ecx
   140003a91:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a95:	88 10                	mov    BYTE PTR [rax],dl
   140003a97:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a9b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a9e:	3c 39                	cmp    al,0x39
   140003aa0:	7e 1a                	jle    140003abc <__pformat_xint+0x11e>
   140003aa2:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003aa6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003aa9:	83 c0 07             	add    eax,0x7
   140003aac:	89 c2                	mov    edx,eax
   140003aae:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003ab1:	83 e0 20             	and    eax,0x20
   140003ab4:	09 c2                	or     edx,eax
   140003ab6:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003aba:	88 10                	mov    BYTE PTR [rax],dl
   140003abc:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003ac0:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003ac3:	89 c1                	mov    ecx,eax
   140003ac5:	48 d3 ea             	shr    rdx,cl
   140003ac8:	48 89 d0             	mov    rax,rdx
   140003acb:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003acf:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003ad3:	48 85 c0             	test   rax,rax
   140003ad6:	75 99                	jne    140003a71 <__pformat_xint+0xd3>
   140003ad8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003adc:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003ae0:	75 13                	jne    140003af5 <__pformat_xint+0x157>
   140003ae2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ae6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003ae9:	80 e4 f7             	and    ah,0xf7
   140003aec:	89 c2                	mov    edx,eax
   140003aee:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003af2:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003af5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003af9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003afc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003aff:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b03:	7e 3a                	jle    140003b3f <__pformat_xint+0x1a1>
   140003b05:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003b08:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b0c:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003b10:	89 c1                	mov    ecx,eax
   140003b12:	89 d0                	mov    eax,edx
   140003b14:	29 c8                	sub    eax,ecx
   140003b16:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b19:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b1d:	7e 20                	jle    140003b3f <__pformat_xint+0x1a1>
   140003b1f:	eb 0f                	jmp    140003b30 <__pformat_xint+0x192>
   140003b21:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b25:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b29:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b2d:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b30:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003b33:	8d 50 ff             	lea    edx,[rax-0x1]
   140003b36:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b39:	85 c0                	test   eax,eax
   140003b3b:	7f e4                	jg     140003b21 <__pformat_xint+0x183>
   140003b3d:	eb 25                	jmp    140003b64 <__pformat_xint+0x1c6>
   140003b3f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003b43:	75 1f                	jne    140003b64 <__pformat_xint+0x1c6>
   140003b45:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b49:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b4c:	25 00 08 00 00       	and    eax,0x800
   140003b51:	85 c0                	test   eax,eax
   140003b53:	74 0f                	je     140003b64 <__pformat_xint+0x1c6>
   140003b55:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b59:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b5d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b61:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b64:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b68:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b6c:	75 1a                	jne    140003b88 <__pformat_xint+0x1ea>
   140003b6e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b72:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b75:	85 c0                	test   eax,eax
   140003b77:	74 0f                	je     140003b88 <__pformat_xint+0x1ea>
   140003b79:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b7d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b81:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b85:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b88:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b8c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b8f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003b93:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003b97:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b9a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003b9d:	7d 15                	jge    140003bb4 <__pformat_xint+0x216>
   140003b9f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ba3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003ba6:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003ba9:	89 c2                	mov    edx,eax
   140003bab:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003baf:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003bb2:	eb 0b                	jmp    140003bbf <__pformat_xint+0x221>
   140003bb4:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bb8:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003bbf:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bc3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003bc6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003bc9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003bcd:	7e 1a                	jle    140003be9 <__pformat_xint+0x24b>
   140003bcf:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003bd3:	74 14                	je     140003be9 <__pformat_xint+0x24b>
   140003bd5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bd9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bdc:	25 00 08 00 00       	and    eax,0x800
   140003be1:	85 c0                	test   eax,eax
   140003be3:	74 04                	je     140003be9 <__pformat_xint+0x24b>
   140003be5:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003be9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003bed:	7e 3c                	jle    140003c2b <__pformat_xint+0x28d>
   140003bef:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bf3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003bf6:	85 c0                	test   eax,eax
   140003bf8:	79 31                	jns    140003c2b <__pformat_xint+0x28d>
   140003bfa:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bfe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c01:	25 00 06 00 00       	and    eax,0x600
   140003c06:	3d 00 02 00 00       	cmp    eax,0x200
   140003c0b:	75 1e                	jne    140003c2b <__pformat_xint+0x28d>
   140003c0d:	eb 0f                	jmp    140003c1e <__pformat_xint+0x280>
   140003c0f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c13:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c17:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c1b:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c1e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c21:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c24:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c27:	85 c0                	test   eax,eax
   140003c29:	7f e4                	jg     140003c0f <__pformat_xint+0x271>
   140003c2b:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c2f:	74 30                	je     140003c61 <__pformat_xint+0x2c3>
   140003c31:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c35:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c38:	25 00 08 00 00       	and    eax,0x800
   140003c3d:	85 c0                	test   eax,eax
   140003c3f:	74 20                	je     140003c61 <__pformat_xint+0x2c3>
   140003c41:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c45:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c49:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c4d:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003c50:	88 10                	mov    BYTE PTR [rax],dl
   140003c52:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c56:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c5a:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c5e:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c61:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c65:	7e 4c                	jle    140003cb3 <__pformat_xint+0x315>
   140003c67:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c6b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c6e:	25 00 04 00 00       	and    eax,0x400
   140003c73:	85 c0                	test   eax,eax
   140003c75:	75 3c                	jne    140003cb3 <__pformat_xint+0x315>
   140003c77:	eb 11                	jmp    140003c8a <__pformat_xint+0x2ec>
   140003c79:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c7d:	48 89 c2             	mov    rdx,rax
   140003c80:	b9 20 00 00 00       	mov    ecx,0x20
   140003c85:	e8 26 f5 ff ff       	call   1400031b0 <__pformat_putc>
   140003c8a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c8d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c90:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c93:	85 c0                	test   eax,eax
   140003c95:	7f e2                	jg     140003c79 <__pformat_xint+0x2db>
   140003c97:	eb 1a                	jmp    140003cb3 <__pformat_xint+0x315>
   140003c99:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003c9e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ca2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003ca5:	0f be c0             	movsx  eax,al
   140003ca8:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003cac:	89 c1                	mov    ecx,eax
   140003cae:	e8 fd f4 ff ff       	call   1400031b0 <__pformat_putc>
   140003cb3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cb7:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003cbb:	72 dc                	jb     140003c99 <__pformat_xint+0x2fb>
   140003cbd:	eb 11                	jmp    140003cd0 <__pformat_xint+0x332>
   140003cbf:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cc3:	48 89 c2             	mov    rdx,rax
   140003cc6:	b9 20 00 00 00       	mov    ecx,0x20
   140003ccb:	e8 e0 f4 ff ff       	call   1400031b0 <__pformat_putc>
   140003cd0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003cd3:	8d 50 ff             	lea    edx,[rax-0x1]
   140003cd6:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003cd9:	85 c0                	test   eax,eax
   140003cdb:	7f e2                	jg     140003cbf <__pformat_xint+0x321>
   140003cdd:	90                   	nop
   140003cde:	90                   	nop
   140003cdf:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003ce3:	5b                   	pop    rbx
   140003ce4:	5d                   	pop    rbp
   140003ce5:	c3                   	ret

0000000140003ce6 <init_fpreg_ldouble>:
   140003ce6:	55                   	push   rbp
   140003ce7:	53                   	push   rbx
   140003ce8:	48 83 ec 28          	sub    rsp,0x28
   140003cec:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003cf1:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003cf5:	48 89 d3             	mov    rbx,rdx
   140003cf8:	db 2b                	fld    TBYTE PTR [rbx]
   140003cfa:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003cfd:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003d00:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003d03:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003d07:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d0b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003d0f:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003d12:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003d16:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003d1a:	48 83 c4 28          	add    rsp,0x28
   140003d1e:	5b                   	pop    rbx
   140003d1f:	5d                   	pop    rbp
   140003d20:	c3                   	ret

0000000140003d21 <__pformat_cvt>:
   140003d21:	55                   	push   rbp
   140003d22:	53                   	push   rbx
   140003d23:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003d2a:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003d31:	00 
   140003d32:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003d35:	48 89 d3             	mov    rbx,rdx
   140003d38:	db 2b                	fld    TBYTE PTR [rbx]
   140003d3a:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003d3d:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003d41:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003d45:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003d4c:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003d50:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003d53:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003d56:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003d5a:	48 89 c1             	mov    rcx,rax
   140003d5d:	e8 84 ff ff ff       	call   140003ce6 <init_fpreg_ldouble>
   140003d62:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003d65:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003d68:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003d6c:	48 89 c1             	mov    rcx,rax
   140003d6f:	e8 9c 4e 00 00       	call   140008c10 <__fpclassifyl>
   140003d74:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d77:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d7a:	25 00 01 00 00       	and    eax,0x100
   140003d7f:	85 c0                	test   eax,eax
   140003d81:	74 1d                	je     140003da0 <__pformat_cvt+0x7f>
   140003d83:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d86:	25 00 04 00 00       	and    eax,0x400
   140003d8b:	85 c0                	test   eax,eax
   140003d8d:	74 07                	je     140003d96 <__pformat_cvt+0x75>
   140003d8f:	b8 03 00 00 00       	mov    eax,0x3
   140003d94:	eb 05                	jmp    140003d9b <__pformat_cvt+0x7a>
   140003d96:	b8 04 00 00 00       	mov    eax,0x4
   140003d9b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d9e:	eb 4a                	jmp    140003dea <__pformat_cvt+0xc9>
   140003da0:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003da3:	25 00 04 00 00       	and    eax,0x400
   140003da8:	85 c0                	test   eax,eax
   140003daa:	74 37                	je     140003de3 <__pformat_cvt+0xc2>
   140003dac:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003daf:	25 00 40 00 00       	and    eax,0x4000
   140003db4:	85 c0                	test   eax,eax
   140003db6:	74 10                	je     140003dc8 <__pformat_cvt+0xa7>
   140003db8:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003dbf:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003dc6:	eb 22                	jmp    140003dea <__pformat_cvt+0xc9>
   140003dc8:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003dcf:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003dd3:	98                   	cwde
   140003dd4:	25 ff 7f 00 00       	and    eax,0x7fff
   140003dd9:	2d 3e 40 00 00       	sub    eax,0x403e
   140003dde:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003de1:	eb 07                	jmp    140003dea <__pformat_cvt+0xc9>
   140003de3:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003dea:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003ded:	83 f8 04             	cmp    eax,0x4
   140003df0:	74 0e                	je     140003e00 <__pformat_cvt+0xdf>
   140003df2:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003df6:	98                   	cwde
   140003df7:	25 00 80 00 00       	and    eax,0x8000
   140003dfc:	89 c2                	mov    edx,eax
   140003dfe:	eb 05                	jmp    140003e05 <__pformat_cvt+0xe4>
   140003e00:	ba 00 00 00 00       	mov    edx,0x0
   140003e05:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003e09:	89 10                	mov    DWORD PTR [rax],edx
   140003e0b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003e0e:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003e12:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003e16:	48 8d 0d 53 62 00 00 	lea    rcx,[rip+0x6253]        # 14000a070 <fpi.0>
   140003e1d:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003e21:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003e26:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e2a:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003e2f:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003e32:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003e36:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003e39:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003e3d:	89 c2                	mov    edx,eax
   140003e3f:	e8 96 24 00 00       	call   1400062da <__gdtoa>
   140003e44:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003e4b:	5b                   	pop    rbx
   140003e4c:	5d                   	pop    rbp
   140003e4d:	c3                   	ret

0000000140003e4e <__pformat_ecvt>:
   140003e4e:	55                   	push   rbp
   140003e4f:	53                   	push   rbx
   140003e50:	48 83 ec 58          	sub    rsp,0x58
   140003e54:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003e59:	48 89 cb             	mov    rbx,rcx
   140003e5c:	db 2b                	fld    TBYTE PTR [rbx]
   140003e5e:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003e61:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003e64:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003e68:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003e6c:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003e6f:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003e72:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003e76:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003e79:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e7d:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e81:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003e86:	4d 89 c1             	mov    r9,r8
   140003e89:	41 89 c8             	mov    r8d,ecx
   140003e8c:	48 89 c2             	mov    rdx,rax
   140003e8f:	b9 02 00 00 00       	mov    ecx,0x2
   140003e94:	e8 88 fe ff ff       	call   140003d21 <__pformat_cvt>
   140003e99:	48 83 c4 58          	add    rsp,0x58
   140003e9d:	5b                   	pop    rbx
   140003e9e:	5d                   	pop    rbp
   140003e9f:	c3                   	ret

0000000140003ea0 <__pformat_fcvt>:
   140003ea0:	55                   	push   rbp
   140003ea1:	53                   	push   rbx
   140003ea2:	48 83 ec 58          	sub    rsp,0x58
   140003ea6:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003eab:	48 89 cb             	mov    rbx,rcx
   140003eae:	db 2b                	fld    TBYTE PTR [rbx]
   140003eb0:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003eb3:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003eb6:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003eba:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003ebe:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003ec1:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003ec4:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003ec8:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003ecb:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003ecf:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003ed3:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003ed8:	4d 89 c1             	mov    r9,r8
   140003edb:	41 89 c8             	mov    r8d,ecx
   140003ede:	48 89 c2             	mov    rdx,rax
   140003ee1:	b9 03 00 00 00       	mov    ecx,0x3
   140003ee6:	e8 36 fe ff ff       	call   140003d21 <__pformat_cvt>
   140003eeb:	48 83 c4 58          	add    rsp,0x58
   140003eef:	5b                   	pop    rbx
   140003ef0:	5d                   	pop    rbp
   140003ef1:	c3                   	ret

0000000140003ef2 <__pformat_emit_radix_point>:
   140003ef2:	55                   	push   rbp
   140003ef3:	53                   	push   rbx
   140003ef4:	48 83 ec 68          	sub    rsp,0x68
   140003ef8:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003efd:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003f01:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f05:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f08:	83 f8 fd             	cmp    eax,0xfffffffd
   140003f0b:	75 48                	jne    140003f55 <__pformat_emit_radix_point+0x63>
   140003f0d:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003f14:	00 
   140003f15:	e8 4e 57 00 00       	call   140009668 <localeconv>
   140003f1a:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003f1d:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003f21:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003f25:	49 89 c9             	mov    r9,rcx
   140003f28:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003f2e:	48 89 c1             	mov    rcx,rax
   140003f31:	e8 6a 51 00 00       	call   1400090a0 <mbrtowc>
   140003f36:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003f39:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003f3d:	7e 0c                	jle    140003f4b <__pformat_emit_radix_point+0x59>
   140003f3f:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003f43:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f47:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003f4b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f4f:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003f52:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003f55:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f59:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003f5d:	66 85 c0             	test   ax,ax
   140003f60:	0f 84 b8 00 00 00    	je     14000401e <__pformat_emit_radix_point+0x12c>
   140003f66:	48 89 e0             	mov    rax,rsp
   140003f69:	48 89 c3             	mov    rbx,rax
   140003f6c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f70:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f73:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003f76:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003f79:	48 63 d0             	movsxd rdx,eax
   140003f7c:	48 83 ea 01          	sub    rdx,0x1
   140003f80:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140003f84:	48 98                	cdqe
   140003f86:	48 83 c0 0f          	add    rax,0xf
   140003f8a:	48 c1 e8 04          	shr    rax,0x4
   140003f8e:	48 c1 e0 04          	shl    rax,0x4
   140003f92:	e8 59 f1 ff ff       	call   1400030f0 <___chkstk_ms>
   140003f97:	48 29 c4             	sub    rsp,rax
   140003f9a:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003f9f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003fa3:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   140003faa:	00 
   140003fab:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003faf:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003fb3:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140003fb7:	0f b7 d0             	movzx  edx,ax
   140003fba:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003fbe:	49 89 c8             	mov    r8,rcx
   140003fc1:	48 89 c1             	mov    rcx,rax
   140003fc4:	e8 87 50 00 00       	call   140009050 <wcrtomb>
   140003fc9:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003fcc:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003fd0:	7e 36                	jle    140004008 <__pformat_emit_radix_point+0x116>
   140003fd2:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003fd6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003fda:	eb 1d                	jmp    140003ff9 <__pformat_emit_radix_point+0x107>
   140003fdc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003fe0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003fe4:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003fe8:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003feb:	0f be c0             	movsx  eax,al
   140003fee:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003ff2:	89 c1                	mov    ecx,eax
   140003ff4:	e8 b7 f1 ff ff       	call   1400031b0 <__pformat_putc>
   140003ff9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ffc:	8d 50 ff             	lea    edx,[rax-0x1]
   140003fff:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140004002:	85 c0                	test   eax,eax
   140004004:	7f d6                	jg     140003fdc <__pformat_emit_radix_point+0xea>
   140004006:	eb 11                	jmp    140004019 <__pformat_emit_radix_point+0x127>
   140004008:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000400c:	48 89 c2             	mov    rdx,rax
   14000400f:	b9 2e 00 00 00       	mov    ecx,0x2e
   140004014:	e8 97 f1 ff ff       	call   1400031b0 <__pformat_putc>
   140004019:	48 89 dc             	mov    rsp,rbx
   14000401c:	eb 11                	jmp    14000402f <__pformat_emit_radix_point+0x13d>
   14000401e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004022:	48 89 c2             	mov    rdx,rax
   140004025:	b9 2e 00 00 00       	mov    ecx,0x2e
   14000402a:	e8 81 f1 ff ff       	call   1400031b0 <__pformat_putc>
   14000402f:	90                   	nop
   140004030:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140004034:	5b                   	pop    rbx
   140004035:	5d                   	pop    rbp
   140004036:	c3                   	ret

0000000140004037 <__pformat_emit_numeric_value>:
   140004037:	55                   	push   rbp
   140004038:	48 89 e5             	mov    rbp,rsp
   14000403b:	48 83 ec 30          	sub    rsp,0x30
   14000403f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004042:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004046:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   14000404a:	75 0e                	jne    14000405a <__pformat_emit_numeric_value+0x23>
   14000404c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004050:	48 89 c1             	mov    rcx,rax
   140004053:	e8 9a fe ff ff       	call   140003ef2 <__pformat_emit_radix_point>
   140004058:	eb 43                	jmp    14000409d <__pformat_emit_numeric_value+0x66>
   14000405a:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   14000405e:	75 2f                	jne    14000408f <__pformat_emit_numeric_value+0x58>
   140004060:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004064:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004068:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   14000406c:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   140004070:	66 85 c0             	test   ax,ax
   140004073:	74 28                	je     14000409d <__pformat_emit_numeric_value+0x66>
   140004075:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004079:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   14000407d:	49 89 d0             	mov    r8,rdx
   140004080:	ba 01 00 00 00       	mov    edx,0x1
   140004085:	48 89 c1             	mov    rcx,rax
   140004088:	e8 2c f3 ff ff       	call   1400033b9 <__pformat_wputchars>
   14000408d:	eb 0e                	jmp    14000409d <__pformat_emit_numeric_value+0x66>
   14000408f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004093:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140004096:	89 c1                	mov    ecx,eax
   140004098:	e8 13 f1 ff ff       	call   1400031b0 <__pformat_putc>
   14000409d:	90                   	nop
   14000409e:	48 83 c4 30          	add    rsp,0x30
   1400040a2:	5d                   	pop    rbp
   1400040a3:	c3                   	ret

00000001400040a4 <__pformat_emit_inf_or_nan>:
   1400040a4:	55                   	push   rbp
   1400040a5:	48 89 e5             	mov    rbp,rsp
   1400040a8:	48 83 ec 40          	sub    rsp,0x40
   1400040ac:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400040af:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400040b3:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400040b7:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400040bb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400040bf:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040c3:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   1400040ca:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400040ce:	74 11                	je     1400040e1 <__pformat_emit_inf_or_nan+0x3d>
   1400040d0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040d4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040d8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040dc:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   1400040df:	eb 3e                	jmp    14000411f <__pformat_emit_inf_or_nan+0x7b>
   1400040e1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040e5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400040e8:	25 00 01 00 00       	and    eax,0x100
   1400040ed:	85 c0                	test   eax,eax
   1400040ef:	74 11                	je     140004102 <__pformat_emit_inf_or_nan+0x5e>
   1400040f1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040f5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040f9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040fd:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140004100:	eb 1d                	jmp    14000411f <__pformat_emit_inf_or_nan+0x7b>
   140004102:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004106:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004109:	83 e0 40             	and    eax,0x40
   14000410c:	85 c0                	test   eax,eax
   14000410e:	74 0f                	je     14000411f <__pformat_emit_inf_or_nan+0x7b>
   140004110:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004114:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004118:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000411c:	c6 00 20             	mov    BYTE PTR [rax],0x20
   14000411f:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140004126:	eb 38                	jmp    140004160 <__pformat_emit_inf_or_nan+0xbc>
   140004128:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000412c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004130:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004134:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004137:	83 e0 df             	and    eax,0xffffffdf
   14000413a:	41 89 c0             	mov    r8d,eax
   14000413d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004141:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004144:	83 e0 20             	and    eax,0x20
   140004147:	89 c1                	mov    ecx,eax
   140004149:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000414d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004151:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004155:	44 89 c2             	mov    edx,r8d
   140004158:	09 ca                	or     edx,ecx
   14000415a:	88 10                	mov    BYTE PTR [rax],dl
   14000415c:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004160:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004164:	7f c2                	jg     140004128 <__pformat_emit_inf_or_nan+0x84>
   140004166:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000416a:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   14000416e:	48 29 c2             	sub    rdx,rax
   140004171:	89 d1                	mov    ecx,edx
   140004173:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004177:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000417b:	49 89 d0             	mov    r8,rdx
   14000417e:	89 ca                	mov    edx,ecx
   140004180:	48 89 c1             	mov    rcx,rax
   140004183:	e8 ac f0 ff ff       	call   140003234 <__pformat_putchars>
   140004188:	90                   	nop
   140004189:	48 83 c4 40          	add    rsp,0x40
   14000418d:	5d                   	pop    rbp
   14000418e:	c3                   	ret

000000014000418f <__pformat_emit_float>:
   14000418f:	55                   	push   rbp
   140004190:	48 89 e5             	mov    rbp,rsp
   140004193:	48 83 ec 30          	sub    rsp,0x30
   140004197:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000419a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000419e:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400041a2:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400041a6:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400041aa:	7e 2e                	jle    1400041da <__pformat_emit_float+0x4b>
   1400041ac:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041b0:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041b3:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   1400041b6:	7f 15                	jg     1400041cd <__pformat_emit_float+0x3e>
   1400041b8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041bc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041bf:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   1400041c2:	89 c2                	mov    edx,eax
   1400041c4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041c8:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400041cb:	eb 29                	jmp    1400041f6 <__pformat_emit_float+0x67>
   1400041cd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041d1:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400041d8:	eb 1c                	jmp    1400041f6 <__pformat_emit_float+0x67>
   1400041da:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041de:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041e1:	85 c0                	test   eax,eax
   1400041e3:	7e 11                	jle    1400041f6 <__pformat_emit_float+0x67>
   1400041e5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041e9:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041ec:	8d 50 ff             	lea    edx,[rax-0x1]
   1400041ef:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041f3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400041f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041fa:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041fd:	85 c0                	test   eax,eax
   1400041ff:	78 2b                	js     14000422c <__pformat_emit_float+0x9d>
   140004201:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004205:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004208:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000420c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000420f:	39 c2                	cmp    edx,eax
   140004211:	7e 19                	jle    14000422c <__pformat_emit_float+0x9d>
   140004213:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004217:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   14000421a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000421e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004221:	29 c2                	sub    edx,eax
   140004223:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004227:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000422a:	eb 0b                	jmp    140004237 <__pformat_emit_float+0xa8>
   14000422c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004230:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004237:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000423b:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000423e:	85 c0                	test   eax,eax
   140004240:	7e 2c                	jle    14000426e <__pformat_emit_float+0xdf>
   140004242:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004246:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004249:	85 c0                	test   eax,eax
   14000424b:	7f 10                	jg     14000425d <__pformat_emit_float+0xce>
   14000424d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004251:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004254:	25 00 08 00 00       	and    eax,0x800
   140004259:	85 c0                	test   eax,eax
   14000425b:	74 11                	je     14000426e <__pformat_emit_float+0xdf>
   14000425d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004261:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004264:	8d 50 ff             	lea    edx,[rax-0x1]
   140004267:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000426b:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000426e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004272:	7e 64                	jle    1400042d8 <__pformat_emit_float+0x149>
   140004274:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004278:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000427b:	25 00 10 00 00       	and    eax,0x1000
   140004280:	85 c0                	test   eax,eax
   140004282:	74 54                	je     1400042d8 <__pformat_emit_float+0x149>
   140004284:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004288:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   14000428c:	66 85 c0             	test   ax,ax
   14000428f:	74 47                	je     1400042d8 <__pformat_emit_float+0x149>
   140004291:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004294:	83 c0 02             	add    eax,0x2
   140004297:	48 63 d0             	movsxd rdx,eax
   14000429a:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   1400042a1:	48 c1 ea 20          	shr    rdx,0x20
   1400042a5:	c1 f8 1f             	sar    eax,0x1f
   1400042a8:	29 c2                	sub    edx,eax
   1400042aa:	8d 42 ff             	lea    eax,[rdx-0x1]
   1400042ad:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400042b0:	eb 15                	jmp    1400042c7 <__pformat_emit_float+0x138>
   1400042b2:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400042b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042ba:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042bd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042c0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042c4:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042c7:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400042cb:	7e 0b                	jle    1400042d8 <__pformat_emit_float+0x149>
   1400042cd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042d1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042d4:	85 c0                	test   eax,eax
   1400042d6:	7f da                	jg     1400042b2 <__pformat_emit_float+0x123>
   1400042d8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042dc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042df:	85 c0                	test   eax,eax
   1400042e1:	7e 27                	jle    14000430a <__pformat_emit_float+0x17b>
   1400042e3:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400042e7:	75 10                	jne    1400042f9 <__pformat_emit_float+0x16a>
   1400042e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042ed:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042f0:	25 c0 01 00 00       	and    eax,0x1c0
   1400042f5:	85 c0                	test   eax,eax
   1400042f7:	74 11                	je     14000430a <__pformat_emit_float+0x17b>
   1400042f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042fd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004300:	8d 50 ff             	lea    edx,[rax-0x1]
   140004303:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004307:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000430a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000430e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004311:	85 c0                	test   eax,eax
   140004313:	7e 38                	jle    14000434d <__pformat_emit_float+0x1be>
   140004315:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004319:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000431c:	25 00 06 00 00       	and    eax,0x600
   140004321:	85 c0                	test   eax,eax
   140004323:	75 28                	jne    14000434d <__pformat_emit_float+0x1be>
   140004325:	eb 11                	jmp    140004338 <__pformat_emit_float+0x1a9>
   140004327:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000432b:	48 89 c2             	mov    rdx,rax
   14000432e:	b9 20 00 00 00       	mov    ecx,0x20
   140004333:	e8 78 ee ff ff       	call   1400031b0 <__pformat_putc>
   140004338:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000433c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000433f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004342:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004346:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004349:	85 c0                	test   eax,eax
   14000434b:	7f da                	jg     140004327 <__pformat_emit_float+0x198>
   14000434d:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004351:	74 13                	je     140004366 <__pformat_emit_float+0x1d7>
   140004353:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004357:	48 89 c2             	mov    rdx,rax
   14000435a:	b9 2d 00 00 00       	mov    ecx,0x2d
   14000435f:	e8 4c ee ff ff       	call   1400031b0 <__pformat_putc>
   140004364:	eb 42                	jmp    1400043a8 <__pformat_emit_float+0x219>
   140004366:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000436a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000436d:	25 00 01 00 00       	and    eax,0x100
   140004372:	85 c0                	test   eax,eax
   140004374:	74 13                	je     140004389 <__pformat_emit_float+0x1fa>
   140004376:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000437a:	48 89 c2             	mov    rdx,rax
   14000437d:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004382:	e8 29 ee ff ff       	call   1400031b0 <__pformat_putc>
   140004387:	eb 1f                	jmp    1400043a8 <__pformat_emit_float+0x219>
   140004389:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000438d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004390:	83 e0 40             	and    eax,0x40
   140004393:	85 c0                	test   eax,eax
   140004395:	74 11                	je     1400043a8 <__pformat_emit_float+0x219>
   140004397:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000439b:	48 89 c2             	mov    rdx,rax
   14000439e:	b9 20 00 00 00       	mov    ecx,0x20
   1400043a3:	e8 08 ee ff ff       	call   1400031b0 <__pformat_putc>
   1400043a8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ac:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043af:	85 c0                	test   eax,eax
   1400043b1:	7e 3b                	jle    1400043ee <__pformat_emit_float+0x25f>
   1400043b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043b7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043ba:	25 00 06 00 00       	and    eax,0x600
   1400043bf:	3d 00 02 00 00       	cmp    eax,0x200
   1400043c4:	75 28                	jne    1400043ee <__pformat_emit_float+0x25f>
   1400043c6:	eb 11                	jmp    1400043d9 <__pformat_emit_float+0x24a>
   1400043c8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043cc:	48 89 c2             	mov    rdx,rax
   1400043cf:	b9 30 00 00 00       	mov    ecx,0x30
   1400043d4:	e8 d7 ed ff ff       	call   1400031b0 <__pformat_putc>
   1400043d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043dd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043e0:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400043e3:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400043e7:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400043ea:	85 c0                	test   eax,eax
   1400043ec:	7f da                	jg     1400043c8 <__pformat_emit_float+0x239>
   1400043ee:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400043f2:	0f 8e a7 00 00 00    	jle    14000449f <__pformat_emit_float+0x310>
   1400043f8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400043fc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400043ff:	84 c0                	test   al,al
   140004401:	74 14                	je     140004417 <__pformat_emit_float+0x288>
   140004403:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004407:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000440b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000440f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004412:	0f be c0             	movsx  eax,al
   140004415:	eb 05                	jmp    14000441c <__pformat_emit_float+0x28d>
   140004417:	b8 30 00 00 00       	mov    eax,0x30
   14000441c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004420:	89 c1                	mov    ecx,eax
   140004422:	e8 89 ed ff ff       	call   1400031b0 <__pformat_putc>
   140004427:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000442b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000442f:	74 62                	je     140004493 <__pformat_emit_float+0x304>
   140004431:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004435:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004438:	25 00 10 00 00       	and    eax,0x1000
   14000443d:	85 c0                	test   eax,eax
   14000443f:	74 52                	je     140004493 <__pformat_emit_float+0x304>
   140004441:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004445:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004449:	66 85 c0             	test   ax,ax
   14000444c:	74 45                	je     140004493 <__pformat_emit_float+0x304>
   14000444e:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   140004451:	48 63 c1             	movsxd rax,ecx
   140004454:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   14000445b:	48 c1 e8 20          	shr    rax,0x20
   14000445f:	48 89 c2             	mov    rdx,rax
   140004462:	89 c8                	mov    eax,ecx
   140004464:	c1 f8 1f             	sar    eax,0x1f
   140004467:	29 c2                	sub    edx,eax
   140004469:	89 d0                	mov    eax,edx
   14000446b:	01 c0                	add    eax,eax
   14000446d:	01 d0                	add    eax,edx
   14000446f:	29 c1                	sub    ecx,eax
   140004471:	89 ca                	mov    edx,ecx
   140004473:	85 d2                	test   edx,edx
   140004475:	75 1c                	jne    140004493 <__pformat_emit_float+0x304>
   140004477:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000447b:	48 83 c0 20          	add    rax,0x20
   14000447f:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004483:	49 89 d0             	mov    r8,rdx
   140004486:	ba 01 00 00 00       	mov    edx,0x1
   14000448b:	48 89 c1             	mov    rcx,rax
   14000448e:	e8 26 ef ff ff       	call   1400033b9 <__pformat_wputchars>
   140004493:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004497:	0f 8f 5b ff ff ff    	jg     1400043f8 <__pformat_emit_float+0x269>
   14000449d:	eb 11                	jmp    1400044b0 <__pformat_emit_float+0x321>
   14000449f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044a3:	48 89 c2             	mov    rdx,rax
   1400044a6:	b9 30 00 00 00       	mov    ecx,0x30
   1400044ab:	e8 00 ed ff ff       	call   1400031b0 <__pformat_putc>
   1400044b0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044b4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400044b7:	85 c0                	test   eax,eax
   1400044b9:	7f 10                	jg     1400044cb <__pformat_emit_float+0x33c>
   1400044bb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044bf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400044c2:	25 00 08 00 00       	and    eax,0x800
   1400044c7:	85 c0                	test   eax,eax
   1400044c9:	74 0c                	je     1400044d7 <__pformat_emit_float+0x348>
   1400044cb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044cf:	48 89 c1             	mov    rcx,rax
   1400044d2:	e8 1b fa ff ff       	call   140003ef2 <__pformat_emit_radix_point>
   1400044d7:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044db:	79 5f                	jns    14000453c <__pformat_emit_float+0x3ad>
   1400044dd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044e1:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400044e4:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400044e7:	01 c2                	add    edx,eax
   1400044e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044ed:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400044f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044f4:	48 89 c2             	mov    rdx,rax
   1400044f7:	b9 30 00 00 00       	mov    ecx,0x30
   1400044fc:	e8 af ec ff ff       	call   1400031b0 <__pformat_putc>
   140004501:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   140004505:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004509:	78 e5                	js     1400044f0 <__pformat_emit_float+0x361>
   14000450b:	eb 2f                	jmp    14000453c <__pformat_emit_float+0x3ad>
   14000450d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004511:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004514:	84 c0                	test   al,al
   140004516:	74 14                	je     14000452c <__pformat_emit_float+0x39d>
   140004518:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000451c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004520:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004524:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004527:	0f be c0             	movsx  eax,al
   14000452a:	eb 05                	jmp    140004531 <__pformat_emit_float+0x3a2>
   14000452c:	b8 30 00 00 00       	mov    eax,0x30
   140004531:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004535:	89 c1                	mov    ecx,eax
   140004537:	e8 74 ec ff ff       	call   1400031b0 <__pformat_putc>
   14000453c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004540:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004543:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004546:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000454a:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   14000454d:	85 c0                	test   eax,eax
   14000454f:	7f bc                	jg     14000450d <__pformat_emit_float+0x37e>
   140004551:	90                   	nop
   140004552:	90                   	nop
   140004553:	48 83 c4 30          	add    rsp,0x30
   140004557:	5d                   	pop    rbp
   140004558:	c3                   	ret

0000000140004559 <__pformat_emit_efloat>:
   140004559:	55                   	push   rbp
   14000455a:	48 89 e5             	mov    rbp,rsp
   14000455d:	48 83 ec 50          	sub    rsp,0x50
   140004561:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004564:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004568:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   14000456c:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004570:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140004577:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000457b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000457f:	79 09                	jns    14000458a <__pformat_emit_efloat+0x31>
   140004581:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004588:	eb 05                	jmp    14000458f <__pformat_emit_efloat+0x36>
   14000458a:	b8 00 00 00 00       	mov    eax,0x0
   14000458f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140004593:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004596:	48 98                	cdqe
   140004598:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000459c:	eb 04                	jmp    1400045a2 <__pformat_emit_efloat+0x49>
   14000459e:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400045a2:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400045a5:	48 63 d0             	movsxd rdx,eax
   1400045a8:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   1400045af:	48 c1 ea 20          	shr    rdx,0x20
   1400045b3:	89 d1                	mov    ecx,edx
   1400045b5:	c1 f9 02             	sar    ecx,0x2
   1400045b8:	99                   	cdq
   1400045b9:	89 c8                	mov    eax,ecx
   1400045bb:	29 d0                	sub    eax,edx
   1400045bd:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   1400045c0:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400045c4:	75 d8                	jne    14000459e <__pformat_emit_efloat+0x45>
   1400045c6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045ca:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   1400045cd:	83 f8 ff             	cmp    eax,0xffffffff
   1400045d0:	75 0b                	jne    1400045dd <__pformat_emit_efloat+0x84>
   1400045d2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045d6:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   1400045dd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045e1:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   1400045e4:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   1400045e7:	7d 0a                	jge    1400045f3 <__pformat_emit_efloat+0x9a>
   1400045e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045ed:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   1400045f0:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400045f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045f7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400045fa:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400045fe:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004601:	7d 15                	jge    140004618 <__pformat_emit_efloat+0xbf>
   140004603:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004607:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000460a:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   14000460d:	89 c2                	mov    edx,eax
   14000460f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004613:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004616:	eb 0b                	jmp    140004623 <__pformat_emit_efloat+0xca>
   140004618:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000461c:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004623:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004627:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000462b:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000462e:	49 89 c9             	mov    r9,rcx
   140004631:	41 b8 01 00 00 00    	mov    r8d,0x1
   140004637:	89 c1                	mov    ecx,eax
   140004639:	e8 51 fb ff ff       	call   14000418f <__pformat_emit_float>
   14000463e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004642:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   140004645:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004649:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000464c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004650:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004653:	0d c0 01 00 00       	or     eax,0x1c0
   140004658:	89 c2                	mov    edx,eax
   14000465a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000465e:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004661:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004665:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004668:	83 e0 20             	and    eax,0x20
   14000466b:	83 c8 45             	or     eax,0x45
   14000466e:	89 c1                	mov    ecx,eax
   140004670:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004674:	48 89 c2             	mov    rdx,rax
   140004677:	e8 34 eb ff ff       	call   1400031b0 <__pformat_putc>
   14000467c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004680:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004683:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140004686:	83 ea 01             	sub    edx,0x1
   140004689:	01 c2                	add    edx,eax
   14000468b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000468f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004692:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004696:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   14000469a:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000469e:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   1400046a2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400046a6:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400046aa:	48 89 c1             	mov    rcx,rax
   1400046ad:	e8 69 ef ff ff       	call   14000361b <__pformat_int>
   1400046b2:	90                   	nop
   1400046b3:	48 83 c4 50          	add    rsp,0x50
   1400046b7:	5d                   	pop    rbp
   1400046b8:	c3                   	ret

00000001400046b9 <__pformat_float>:
   1400046b9:	55                   	push   rbp
   1400046ba:	53                   	push   rbx
   1400046bb:	48 83 ec 58          	sub    rsp,0x58
   1400046bf:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400046c4:	48 89 cb             	mov    rbx,rcx
   1400046c7:	db 2b                	fld    TBYTE PTR [rbx]
   1400046c9:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400046cc:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400046d0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046d4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400046d7:	85 c0                	test   eax,eax
   1400046d9:	79 0b                	jns    1400046e6 <__pformat_float+0x2d>
   1400046db:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046df:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400046e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046ea:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400046ed:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400046f0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400046f3:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400046f7:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400046fb:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400046ff:	4d 89 c1             	mov    r9,r8
   140004702:	49 89 c8             	mov    r8,rcx
   140004705:	48 89 c1             	mov    rcx,rax
   140004708:	e8 93 f7 ff ff       	call   140003ea0 <__pformat_fcvt>
   14000470d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004711:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004714:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   140004719:	75 17                	jne    140004732 <__pformat_float+0x79>
   14000471b:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000471e:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004722:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004726:	49 89 c8             	mov    r8,rcx
   140004729:	89 c1                	mov    ecx,eax
   14000472b:	e8 74 f9 ff ff       	call   1400040a4 <__pformat_emit_inf_or_nan>
   140004730:	eb 43                	jmp    140004775 <__pformat_float+0xbc>
   140004732:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004735:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004738:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000473c:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004740:	4d 89 c1             	mov    r9,r8
   140004743:	41 89 c8             	mov    r8d,ecx
   140004746:	89 c1                	mov    ecx,eax
   140004748:	e8 42 fa ff ff       	call   14000418f <__pformat_emit_float>
   14000474d:	eb 11                	jmp    140004760 <__pformat_float+0xa7>
   14000474f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004753:	48 89 c2             	mov    rdx,rax
   140004756:	b9 20 00 00 00       	mov    ecx,0x20
   14000475b:	e8 50 ea ff ff       	call   1400031b0 <__pformat_putc>
   140004760:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004764:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004767:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000476a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000476e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004771:	85 c0                	test   eax,eax
   140004773:	7f da                	jg     14000474f <__pformat_float+0x96>
   140004775:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004779:	48 89 c1             	mov    rcx,rax
   14000477c:	e8 4e 17 00 00       	call   140005ecf <__freedtoa>
   140004781:	90                   	nop
   140004782:	48 83 c4 58          	add    rsp,0x58
   140004786:	5b                   	pop    rbx
   140004787:	5d                   	pop    rbp
   140004788:	c3                   	ret

0000000140004789 <__pformat_efloat>:
   140004789:	55                   	push   rbp
   14000478a:	53                   	push   rbx
   14000478b:	48 83 ec 58          	sub    rsp,0x58
   14000478f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004794:	48 89 cb             	mov    rbx,rcx
   140004797:	db 2b                	fld    TBYTE PTR [rbx]
   140004799:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000479c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400047a0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047a4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400047a7:	85 c0                	test   eax,eax
   1400047a9:	79 0b                	jns    1400047b6 <__pformat_efloat+0x2d>
   1400047ab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047af:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400047b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047ba:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400047bd:	8d 50 01             	lea    edx,[rax+0x1]
   1400047c0:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400047c3:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400047c6:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400047ca:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400047ce:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400047d2:	4d 89 c1             	mov    r9,r8
   1400047d5:	49 89 c8             	mov    r8,rcx
   1400047d8:	48 89 c1             	mov    rcx,rax
   1400047db:	e8 6e f6 ff ff       	call   140003e4e <__pformat_ecvt>
   1400047e0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400047e4:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400047e7:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400047ec:	75 17                	jne    140004805 <__pformat_efloat+0x7c>
   1400047ee:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047f1:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400047f5:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047f9:	49 89 c8             	mov    r8,rcx
   1400047fc:	89 c1                	mov    ecx,eax
   1400047fe:	e8 a1 f8 ff ff       	call   1400040a4 <__pformat_emit_inf_or_nan>
   140004803:	eb 1b                	jmp    140004820 <__pformat_efloat+0x97>
   140004805:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004808:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000480b:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000480f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004813:	4d 89 c1             	mov    r9,r8
   140004816:	41 89 c8             	mov    r8d,ecx
   140004819:	89 c1                	mov    ecx,eax
   14000481b:	e8 39 fd ff ff       	call   140004559 <__pformat_emit_efloat>
   140004820:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004824:	48 89 c1             	mov    rcx,rax
   140004827:	e8 a3 16 00 00       	call   140005ecf <__freedtoa>
   14000482c:	90                   	nop
   14000482d:	48 83 c4 58          	add    rsp,0x58
   140004831:	5b                   	pop    rbx
   140004832:	5d                   	pop    rbp
   140004833:	c3                   	ret

0000000140004834 <__pformat_gfloat>:
   140004834:	55                   	push   rbp
   140004835:	53                   	push   rbx
   140004836:	48 83 ec 58          	sub    rsp,0x58
   14000483a:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000483f:	48 89 cb             	mov    rbx,rcx
   140004842:	db 2b                	fld    TBYTE PTR [rbx]
   140004844:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140004847:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000484b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000484f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004852:	85 c0                	test   eax,eax
   140004854:	79 0d                	jns    140004863 <__pformat_gfloat+0x2f>
   140004856:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000485a:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004861:	eb 16                	jmp    140004879 <__pformat_gfloat+0x45>
   140004863:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004867:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000486a:	85 c0                	test   eax,eax
   14000486c:	75 0b                	jne    140004879 <__pformat_gfloat+0x45>
   14000486e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004872:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   140004879:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000487d:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004880:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004883:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004886:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000488a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000488e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004892:	4d 89 c1             	mov    r9,r8
   140004895:	49 89 c8             	mov    r8,rcx
   140004898:	48 89 c1             	mov    rcx,rax
   14000489b:	e8 ae f5 ff ff       	call   140003e4e <__pformat_ecvt>
   1400048a0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400048a4:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048a7:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400048ac:	75 1a                	jne    1400048c8 <__pformat_gfloat+0x94>
   1400048ae:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400048b1:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400048b5:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048b9:	49 89 c8             	mov    r8,rcx
   1400048bc:	89 c1                	mov    ecx,eax
   1400048be:	e8 e1 f7 ff ff       	call   1400040a4 <__pformat_emit_inf_or_nan>
   1400048c3:	e9 14 01 00 00       	jmp    1400049dc <__pformat_gfloat+0x1a8>
   1400048c8:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048cb:	83 f8 fd             	cmp    eax,0xfffffffd
   1400048ce:	0f 8c b2 00 00 00    	jl     140004986 <__pformat_gfloat+0x152>
   1400048d4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048d8:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400048db:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048de:	39 c2                	cmp    edx,eax
   1400048e0:	0f 8c a0 00 00 00    	jl     140004986 <__pformat_gfloat+0x152>
   1400048e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048ea:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400048ed:	25 00 08 00 00       	and    eax,0x800
   1400048f2:	85 c0                	test   eax,eax
   1400048f4:	74 15                	je     14000490b <__pformat_gfloat+0xd7>
   1400048f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048fa:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400048fd:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004900:	29 c2                	sub    edx,eax
   140004902:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004906:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004909:	eb 20                	jmp    14000492b <__pformat_gfloat+0xf7>
   14000490b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000490f:	48 89 c1             	mov    rcx,rax
   140004912:	e8 89 4d 00 00       	call   1400096a0 <strlen>
   140004917:	89 c1                	mov    ecx,eax
   140004919:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000491c:	89 c2                	mov    edx,eax
   14000491e:	89 c8                	mov    eax,ecx
   140004920:	29 d0                	sub    eax,edx
   140004922:	89 c2                	mov    edx,eax
   140004924:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004928:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000492b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000492f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004932:	85 c0                	test   eax,eax
   140004934:	79 0b                	jns    140004941 <__pformat_gfloat+0x10d>
   140004936:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000493a:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   140004941:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004944:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004947:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000494b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   14000494f:	4d 89 c1             	mov    r9,r8
   140004952:	41 89 c8             	mov    r8d,ecx
   140004955:	89 c1                	mov    ecx,eax
   140004957:	e8 33 f8 ff ff       	call   14000418f <__pformat_emit_float>
   14000495c:	eb 11                	jmp    14000496f <__pformat_gfloat+0x13b>
   14000495e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004962:	48 89 c2             	mov    rdx,rax
   140004965:	b9 20 00 00 00       	mov    ecx,0x20
   14000496a:	e8 41 e8 ff ff       	call   1400031b0 <__pformat_putc>
   14000496f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004973:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004976:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004979:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000497d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004980:	85 c0                	test   eax,eax
   140004982:	7f da                	jg     14000495e <__pformat_gfloat+0x12a>
   140004984:	eb 56                	jmp    1400049dc <__pformat_gfloat+0x1a8>
   140004986:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000498a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000498d:	25 00 08 00 00       	and    eax,0x800
   140004992:	85 c0                	test   eax,eax
   140004994:	74 13                	je     1400049a9 <__pformat_gfloat+0x175>
   140004996:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000499a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000499d:	8d 50 ff             	lea    edx,[rax-0x1]
   1400049a0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049a4:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049a7:	eb 18                	jmp    1400049c1 <__pformat_gfloat+0x18d>
   1400049a9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400049ad:	48 89 c1             	mov    rcx,rax
   1400049b0:	e8 eb 4c 00 00       	call   1400096a0 <strlen>
   1400049b5:	83 e8 01             	sub    eax,0x1
   1400049b8:	89 c2                	mov    edx,eax
   1400049ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049be:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049c1:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400049c4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400049c7:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400049cb:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400049cf:	4d 89 c1             	mov    r9,r8
   1400049d2:	41 89 c8             	mov    r8d,ecx
   1400049d5:	89 c1                	mov    ecx,eax
   1400049d7:	e8 7d fb ff ff       	call   140004559 <__pformat_emit_efloat>
   1400049dc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400049e0:	48 89 c1             	mov    rcx,rax
   1400049e3:	e8 e7 14 00 00       	call   140005ecf <__freedtoa>
   1400049e8:	90                   	nop
   1400049e9:	48 83 c4 58          	add    rsp,0x58
   1400049ed:	5b                   	pop    rbx
   1400049ee:	5d                   	pop    rbp
   1400049ef:	c3                   	ret

00000001400049f0 <__pformat_emit_xfloat>:
   1400049f0:	55                   	push   rbp
   1400049f1:	53                   	push   rbx
   1400049f2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400049f9:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140004a00:	00 
   140004a01:	48 89 cb             	mov    rbx,rcx
   140004a04:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004a08:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004a0c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004a10:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   140004a16:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a19:	48 85 c0             	test   rax,rax
   140004a1c:	75 09                	jne    140004a27 <__pformat_emit_xfloat+0x37>
   140004a1e:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a22:	66 85 c0             	test   ax,ax
   140004a25:	74 0b                	je     140004a32 <__pformat_emit_xfloat+0x42>
   140004a27:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a2b:	83 e8 03             	sub    eax,0x3
   140004a2e:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004a32:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a36:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a39:	85 c0                	test   eax,eax
   140004a3b:	0f 88 90 00 00 00    	js     140004ad1 <__pformat_emit_xfloat+0xe1>
   140004a41:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a45:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a48:	83 f8 0e             	cmp    eax,0xe
   140004a4b:	0f 8f 80 00 00 00    	jg     140004ad1 <__pformat_emit_xfloat+0xe1>
   140004a51:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a54:	48 d1 e8             	shr    rax,1
   140004a57:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a5a:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004a5d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a61:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a64:	b9 0e 00 00 00       	mov    ecx,0xe
   140004a69:	29 c1                	sub    ecx,eax
   140004a6b:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004a72:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004a78:	89 c1                	mov    ecx,eax
   140004a7a:	49 d3 e0             	shl    r8,cl
   140004a7d:	4c 89 c0             	mov    rax,r8
   140004a80:	48 01 d0             	add    rax,rdx
   140004a83:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a86:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a89:	48 85 c0             	test   rax,rax
   140004a8c:	78 0b                	js     140004a99 <__pformat_emit_xfloat+0xa9>
   140004a8e:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a91:	48 01 c0             	add    rax,rax
   140004a94:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a97:	eb 15                	jmp    140004aae <__pformat_emit_xfloat+0xbe>
   140004a99:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a9d:	83 c0 04             	add    eax,0x4
   140004aa0:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004aa4:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004aa7:	48 c1 e8 03          	shr    rax,0x3
   140004aab:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004aae:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004ab1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ab5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ab8:	b9 0f 00 00 00       	mov    ecx,0xf
   140004abd:	29 c1                	sub    ecx,eax
   140004abf:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004ac6:	89 c1                	mov    ecx,eax
   140004ac8:	48 d3 ea             	shr    rdx,cl
   140004acb:	48 89 d0             	mov    rax,rdx
   140004ace:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004ad1:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ad4:	48 85 c0             	test   rax,rax
   140004ad7:	75 0f                	jne    140004ae8 <__pformat_emit_xfloat+0xf8>
   140004ad9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004add:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ae0:	85 c0                	test   eax,eax
   140004ae2:	0f 8e f8 00 00 00    	jle    140004be0 <__pformat_emit_xfloat+0x1f0>
   140004ae8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004aec:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004aef:	83 f8 0e             	cmp    eax,0xe
   140004af2:	7f 1a                	jg     140004b0e <__pformat_emit_xfloat+0x11e>
   140004af4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004af8:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004afb:	85 c0                	test   eax,eax
   140004afd:	78 0f                	js     140004b0e <__pformat_emit_xfloat+0x11e>
   140004aff:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b03:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b06:	83 c0 01             	add    eax,0x1
   140004b09:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004b0c:	eb 07                	jmp    140004b15 <__pformat_emit_xfloat+0x125>
   140004b0e:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004b15:	e9 bc 00 00 00       	jmp    140004bd6 <__pformat_emit_xfloat+0x1e6>
   140004b1a:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b1d:	83 e0 0f             	and    eax,0xf
   140004b20:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004b23:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004b27:	75 36                	jne    140004b5f <__pformat_emit_xfloat+0x16f>
   140004b29:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b2d:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b31:	72 1b                	jb     140004b4e <__pformat_emit_xfloat+0x15e>
   140004b33:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b37:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b3a:	25 00 08 00 00       	and    eax,0x800
   140004b3f:	85 c0                	test   eax,eax
   140004b41:	75 0b                	jne    140004b4e <__pformat_emit_xfloat+0x15e>
   140004b43:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b47:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b4a:	85 c0                	test   eax,eax
   140004b4c:	7e 2d                	jle    140004b7b <__pformat_emit_xfloat+0x18b>
   140004b4e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004b52:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004b56:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004b5a:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004b5d:	eb 1c                	jmp    140004b7b <__pformat_emit_xfloat+0x18b>
   140004b5f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b63:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b66:	85 c0                	test   eax,eax
   140004b68:	7e 11                	jle    140004b7b <__pformat_emit_xfloat+0x18b>
   140004b6a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b6e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b71:	8d 50 ff             	lea    edx,[rax-0x1]
   140004b74:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b78:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004b7b:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004b7f:	75 15                	jne    140004b96 <__pformat_emit_xfloat+0x1a6>
   140004b81:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b85:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b89:	72 0b                	jb     140004b96 <__pformat_emit_xfloat+0x1a6>
   140004b8b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b8f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b92:	85 c0                	test   eax,eax
   140004b94:	78 32                	js     140004bc8 <__pformat_emit_xfloat+0x1d8>
   140004b96:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004b9a:	76 16                	jbe    140004bb2 <__pformat_emit_xfloat+0x1c2>
   140004b9c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004b9f:	8d 50 37             	lea    edx,[rax+0x37]
   140004ba2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ba6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ba9:	83 e0 20             	and    eax,0x20
   140004bac:	09 d0                	or     eax,edx
   140004bae:	89 c1                	mov    ecx,eax
   140004bb0:	eb 08                	jmp    140004bba <__pformat_emit_xfloat+0x1ca>
   140004bb2:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004bb5:	83 c0 30             	add    eax,0x30
   140004bb8:	89 c1                	mov    ecx,eax
   140004bba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004bbe:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004bc2:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004bc6:	88 08                	mov    BYTE PTR [rax],cl
   140004bc8:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004bcb:	48 c1 e8 04          	shr    rax,0x4
   140004bcf:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004bd2:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004bd6:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004bda:	0f 8f 3a ff ff ff    	jg     140004b1a <__pformat_emit_xfloat+0x12a>
   140004be0:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004be4:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004be8:	75 39                	jne    140004c23 <__pformat_emit_xfloat+0x233>
   140004bea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bee:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bf1:	85 c0                	test   eax,eax
   140004bf3:	7f 10                	jg     140004c05 <__pformat_emit_xfloat+0x215>
   140004bf5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bf9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004bfc:	25 00 08 00 00       	and    eax,0x800
   140004c01:	85 c0                	test   eax,eax
   140004c03:	74 0f                	je     140004c14 <__pformat_emit_xfloat+0x224>
   140004c05:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c09:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c0d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c11:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004c14:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c18:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c1c:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c20:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004c23:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c27:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c2a:	85 c0                	test   eax,eax
   140004c2c:	0f 8e e3 00 00 00    	jle    140004d15 <__pformat_emit_xfloat+0x325>
   140004c32:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c36:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004c3a:	48 29 c2             	sub    rdx,rax
   140004c3d:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004c40:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004c44:	98                   	cwde
   140004c45:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004c48:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c4c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c4f:	85 c0                	test   eax,eax
   140004c51:	7e 0a                	jle    140004c5d <__pformat_emit_xfloat+0x26d>
   140004c53:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c57:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c5a:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c5d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c61:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c64:	25 c0 01 00 00       	and    eax,0x1c0
   140004c69:	85 c0                	test   eax,eax
   140004c6b:	74 07                	je     140004c74 <__pformat_emit_xfloat+0x284>
   140004c6d:	b8 06 00 00 00       	mov    eax,0x6
   140004c72:	eb 05                	jmp    140004c79 <__pformat_emit_xfloat+0x289>
   140004c74:	b8 05 00 00 00       	mov    eax,0x5
   140004c79:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c7c:	eb 0f                	jmp    140004c8d <__pformat_emit_xfloat+0x29d>
   140004c7e:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004c82:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004c86:	83 c0 01             	add    eax,0x1
   140004c89:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004c8d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004c90:	48 63 d0             	movsxd rdx,eax
   140004c93:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004c9a:	48 c1 ea 20          	shr    rdx,0x20
   140004c9e:	89 d1                	mov    ecx,edx
   140004ca0:	c1 f9 02             	sar    ecx,0x2
   140004ca3:	99                   	cdq
   140004ca4:	89 c8                	mov    eax,ecx
   140004ca6:	29 d0                	sub    eax,edx
   140004ca8:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004cab:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004caf:	75 cd                	jne    140004c7e <__pformat_emit_xfloat+0x28e>
   140004cb1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cb5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004cb8:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004cbb:	7d 4d                	jge    140004d0a <__pformat_emit_xfloat+0x31a>
   140004cbd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cc1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004cc4:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004cc7:	89 c2                	mov    edx,eax
   140004cc9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ccd:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004cd0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cd4:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cd7:	25 00 06 00 00       	and    eax,0x600
   140004cdc:	85 c0                	test   eax,eax
   140004cde:	75 35                	jne    140004d15 <__pformat_emit_xfloat+0x325>
   140004ce0:	eb 11                	jmp    140004cf3 <__pformat_emit_xfloat+0x303>
   140004ce2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ce6:	48 89 c2             	mov    rdx,rax
   140004ce9:	b9 20 00 00 00       	mov    ecx,0x20
   140004cee:	e8 bd e4 ff ff       	call   1400031b0 <__pformat_putc>
   140004cf3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cf7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004cfa:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004cfd:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d01:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004d04:	85 c0                	test   eax,eax
   140004d06:	7f da                	jg     140004ce2 <__pformat_emit_xfloat+0x2f2>
   140004d08:	eb 0b                	jmp    140004d15 <__pformat_emit_xfloat+0x325>
   140004d0a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d0e:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004d15:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d19:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d1c:	25 80 00 00 00       	and    eax,0x80
   140004d21:	85 c0                	test   eax,eax
   140004d23:	74 13                	je     140004d38 <__pformat_emit_xfloat+0x348>
   140004d25:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d29:	48 89 c2             	mov    rdx,rax
   140004d2c:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004d31:	e8 7a e4 ff ff       	call   1400031b0 <__pformat_putc>
   140004d36:	eb 42                	jmp    140004d7a <__pformat_emit_xfloat+0x38a>
   140004d38:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d3c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d3f:	25 00 01 00 00       	and    eax,0x100
   140004d44:	85 c0                	test   eax,eax
   140004d46:	74 13                	je     140004d5b <__pformat_emit_xfloat+0x36b>
   140004d48:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d4c:	48 89 c2             	mov    rdx,rax
   140004d4f:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004d54:	e8 57 e4 ff ff       	call   1400031b0 <__pformat_putc>
   140004d59:	eb 1f                	jmp    140004d7a <__pformat_emit_xfloat+0x38a>
   140004d5b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d5f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d62:	83 e0 40             	and    eax,0x40
   140004d65:	85 c0                	test   eax,eax
   140004d67:	74 11                	je     140004d7a <__pformat_emit_xfloat+0x38a>
   140004d69:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d6d:	48 89 c2             	mov    rdx,rax
   140004d70:	b9 20 00 00 00       	mov    ecx,0x20
   140004d75:	e8 36 e4 ff ff       	call   1400031b0 <__pformat_putc>
   140004d7a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d7e:	48 89 c2             	mov    rdx,rax
   140004d81:	b9 30 00 00 00       	mov    ecx,0x30
   140004d86:	e8 25 e4 ff ff       	call   1400031b0 <__pformat_putc>
   140004d8b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d8f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d92:	83 e0 20             	and    eax,0x20
   140004d95:	83 c8 58             	or     eax,0x58
   140004d98:	89 c1                	mov    ecx,eax
   140004d9a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d9e:	48 89 c2             	mov    rdx,rax
   140004da1:	e8 0a e4 ff ff       	call   1400031b0 <__pformat_putc>
   140004da6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004daa:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004dad:	85 c0                	test   eax,eax
   140004daf:	7e 54                	jle    140004e05 <__pformat_emit_xfloat+0x415>
   140004db1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004db5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004db8:	25 00 02 00 00       	and    eax,0x200
   140004dbd:	85 c0                	test   eax,eax
   140004dbf:	74 44                	je     140004e05 <__pformat_emit_xfloat+0x415>
   140004dc1:	eb 11                	jmp    140004dd4 <__pformat_emit_xfloat+0x3e4>
   140004dc3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dc7:	48 89 c2             	mov    rdx,rax
   140004dca:	b9 30 00 00 00       	mov    ecx,0x30
   140004dcf:	e8 dc e3 ff ff       	call   1400031b0 <__pformat_putc>
   140004dd4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dd8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004ddb:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004dde:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004de2:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004de5:	85 c0                	test   eax,eax
   140004de7:	7f da                	jg     140004dc3 <__pformat_emit_xfloat+0x3d3>
   140004de9:	eb 1a                	jmp    140004e05 <__pformat_emit_xfloat+0x415>
   140004deb:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004df0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004df4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004df7:	0f be c0             	movsx  eax,al
   140004dfa:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004dfe:	89 c1                	mov    ecx,eax
   140004e00:	e8 32 f2 ff ff       	call   140004037 <__pformat_emit_numeric_value>
   140004e05:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004e09:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004e0d:	72 dc                	jb     140004deb <__pformat_emit_xfloat+0x3fb>
   140004e0f:	eb 11                	jmp    140004e22 <__pformat_emit_xfloat+0x432>
   140004e11:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e15:	48 89 c2             	mov    rdx,rax
   140004e18:	b9 30 00 00 00       	mov    ecx,0x30
   140004e1d:	e8 8e e3 ff ff       	call   1400031b0 <__pformat_putc>
   140004e22:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e26:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004e29:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e2c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e30:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004e33:	85 c0                	test   eax,eax
   140004e35:	7f da                	jg     140004e11 <__pformat_emit_xfloat+0x421>
   140004e37:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e3b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e3e:	83 e0 20             	and    eax,0x20
   140004e41:	83 c8 50             	or     eax,0x50
   140004e44:	89 c1                	mov    ecx,eax
   140004e46:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e4a:	48 89 c2             	mov    rdx,rax
   140004e4d:	e8 5e e3 ff ff       	call   1400031b0 <__pformat_putc>
   140004e52:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e56:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004e59:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004e5d:	01 c2                	add    edx,eax
   140004e5f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e63:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004e66:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e6a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e6d:	0d c0 01 00 00       	or     eax,0x1c0
   140004e72:	89 c2                	mov    edx,eax
   140004e74:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e78:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004e7b:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e7f:	66 85 c0             	test   ax,ax
   140004e82:	79 09                	jns    140004e8d <__pformat_emit_xfloat+0x49d>
   140004e84:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004e8b:	eb 05                	jmp    140004e92 <__pformat_emit_xfloat+0x4a2>
   140004e8d:	b8 00 00 00 00       	mov    eax,0x0
   140004e92:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004e96:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e9a:	48 0f bf c0          	movsx  rax,ax
   140004e9e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004ea2:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004ea6:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004eaa:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004eae:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004eb2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004eb6:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004eba:	48 89 c1             	mov    rcx,rax
   140004ebd:	e8 59 e7 ff ff       	call   14000361b <__pformat_int>
   140004ec2:	90                   	nop
   140004ec3:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004eca:	5b                   	pop    rbx
   140004ecb:	5d                   	pop    rbp
   140004ecc:	c3                   	ret

0000000140004ecd <__pformat_xldouble>:
   140004ecd:	55                   	push   rbp
   140004ece:	53                   	push   rbx
   140004ecf:	48 83 ec 78          	sub    rsp,0x78
   140004ed3:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004ed8:	48 89 cb             	mov    rbx,rcx
   140004edb:	db 2b                	fld    TBYTE PTR [rbx]
   140004edd:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004ee0:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004ee4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004eeb:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004eef:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004ef2:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004ef5:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004ef9:	48 89 c1             	mov    rcx,rax
   140004efc:	e8 e5 ed ff ff       	call   140003ce6 <init_fpreg_ldouble>
   140004f01:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f04:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f07:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f0b:	48 89 c1             	mov    rcx,rax
   140004f0e:	e8 ed 3d 00 00       	call   140008d00 <__isnanl>
   140004f13:	85 c0                	test   eax,eax
   140004f15:	74 1d                	je     140004f34 <__pformat_xldouble+0x67>
   140004f17:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f1a:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f1e:	48 8d 15 21 64 00 00 	lea    rdx,[rip+0x6421]        # 14000b346 <.rdata+0x16>
   140004f25:	49 89 c8             	mov    r8,rcx
   140004f28:	89 c1                	mov    ecx,eax
   140004f2a:	e8 75 f1 ff ff       	call   1400040a4 <__pformat_emit_inf_or_nan>
   140004f2f:	e9 aa 00 00 00       	jmp    140004fde <__pformat_xldouble+0x111>
   140004f34:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f38:	98                   	cwde
   140004f39:	25 00 80 00 00       	and    eax,0x8000
   140004f3e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004f41:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004f45:	74 12                	je     140004f59 <__pformat_xldouble+0x8c>
   140004f47:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f4b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004f4e:	0c 80                	or     al,0x80
   140004f50:	89 c2                	mov    edx,eax
   140004f52:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f56:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004f59:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f5c:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f5f:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f63:	48 89 c1             	mov    rcx,rax
   140004f66:	e8 a5 3c 00 00       	call   140008c10 <__fpclassifyl>
   140004f6b:	3d 00 05 00 00       	cmp    eax,0x500
   140004f70:	75 1a                	jne    140004f8c <__pformat_xldouble+0xbf>
   140004f72:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f75:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f79:	48 8d 15 ca 63 00 00 	lea    rdx,[rip+0x63ca]        # 14000b34a <.rdata+0x1a>
   140004f80:	49 89 c8             	mov    r8,rcx
   140004f83:	89 c1                	mov    ecx,eax
   140004f85:	e8 1a f1 ff ff       	call   1400040a4 <__pformat_emit_inf_or_nan>
   140004f8a:	eb 52                	jmp    140004fde <__pformat_xldouble+0x111>
   140004f8c:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f90:	66 25 ff 7f          	and    ax,0x7fff
   140004f94:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004f98:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f9c:	66 85 c0             	test   ax,ax
   140004f9f:	75 11                	jne    140004fb2 <__pformat_xldouble+0xe5>
   140004fa1:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004fa5:	48 85 c0             	test   rax,rax
   140004fa8:	74 14                	je     140004fbe <__pformat_xldouble+0xf1>
   140004faa:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140004fb0:	eb 0c                	jmp    140004fbe <__pformat_xldouble+0xf1>
   140004fb2:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fb6:	66 2d ff 3f          	sub    ax,0x3fff
   140004fba:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004fbe:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004fc2:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140004fc6:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004fca:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   140004fce:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004fd2:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140004fd6:	48 89 c1             	mov    rcx,rax
   140004fd9:	e8 12 fa ff ff       	call   1400049f0 <__pformat_emit_xfloat>
   140004fde:	90                   	nop
   140004fdf:	48 83 c4 78          	add    rsp,0x78
   140004fe3:	5b                   	pop    rbx
   140004fe4:	5d                   	pop    rbp
   140004fe5:	c3                   	ret

0000000140004fe6 <__pformat_xdouble>:
   140004fe6:	55                   	push   rbp
   140004fe7:	48 89 e5             	mov    rbp,rsp
   140004fea:	48 83 ec 60          	sub    rsp,0x60
   140004fee:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140004ff3:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004ff7:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004ffe:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140005001:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140005005:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140005008:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   14000500c:	48 89 c1             	mov    rcx,rax
   14000500f:	e8 d2 ec ff ff       	call   140003ce6 <init_fpreg_ldouble>
   140005014:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005018:	66 48 0f 6e c0       	movq   xmm0,rax
   14000501d:	e8 7e 3c 00 00       	call   140008ca0 <__isnan>
   140005022:	85 c0                	test   eax,eax
   140005024:	74 1d                	je     140005043 <__pformat_xdouble+0x5d>
   140005026:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005029:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   14000502d:	48 8d 15 12 63 00 00 	lea    rdx,[rip+0x6312]        # 14000b346 <.rdata+0x16>
   140005034:	49 89 c8             	mov    r8,rcx
   140005037:	89 c1                	mov    ecx,eax
   140005039:	e8 66 f0 ff ff       	call   1400040a4 <__pformat_emit_inf_or_nan>
   14000503e:	e9 f9 00 00 00       	jmp    14000513c <__pformat_xdouble+0x156>
   140005043:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005047:	98                   	cwde
   140005048:	25 00 80 00 00       	and    eax,0x8000
   14000504d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005050:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005054:	74 12                	je     140005068 <__pformat_xdouble+0x82>
   140005056:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000505a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000505d:	0c 80                	or     al,0x80
   14000505f:	89 c2                	mov    edx,eax
   140005061:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005065:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005068:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000506c:	66 48 0f 6e c0       	movq   xmm0,rax
   140005071:	e8 1a 3b 00 00       	call   140008b90 <__fpclassify>
   140005076:	3d 00 05 00 00       	cmp    eax,0x500
   14000507b:	75 1d                	jne    14000509a <__pformat_xdouble+0xb4>
   14000507d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005080:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140005084:	48 8d 15 bf 62 00 00 	lea    rdx,[rip+0x62bf]        # 14000b34a <.rdata+0x1a>
   14000508b:	49 89 c8             	mov    r8,rcx
   14000508e:	89 c1                	mov    ecx,eax
   140005090:	e8 0f f0 ff ff       	call   1400040a4 <__pformat_emit_inf_or_nan>
   140005095:	e9 a2 00 00 00       	jmp    14000513c <__pformat_xdouble+0x156>
   14000509a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000509e:	66 25 ff 7f          	and    ax,0x7fff
   1400050a2:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400050a6:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050aa:	66 85 c0             	test   ax,ax
   1400050ad:	74 3b                	je     1400050ea <__pformat_xdouble+0x104>
   1400050af:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050b3:	66 3d 00 3c          	cmp    ax,0x3c00
   1400050b7:	7f 31                	jg     1400050ea <__pformat_xdouble+0x104>
   1400050b9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050bd:	98                   	cwde
   1400050be:	ba 01 3c 00 00       	mov    edx,0x3c01
   1400050c3:	29 c2                	sub    edx,eax
   1400050c5:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   1400050c8:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   1400050cc:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400050cf:	89 c1                	mov    ecx,eax
   1400050d1:	48 d3 ea             	shr    rdx,cl
   1400050d4:	48 89 d0             	mov    rax,rdx
   1400050d7:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400050db:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050df:	89 c2                	mov    edx,eax
   1400050e1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400050e4:	01 d0                	add    eax,edx
   1400050e6:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400050ea:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050ee:	66 85 c0             	test   ax,ax
   1400050f1:	75 11                	jne    140005104 <__pformat_xdouble+0x11e>
   1400050f3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050f7:	48 85 c0             	test   rax,rax
   1400050fa:	74 14                	je     140005110 <__pformat_xdouble+0x12a>
   1400050fc:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   140005102:	eb 0c                	jmp    140005110 <__pformat_xdouble+0x12a>
   140005104:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005108:	66 2d fc 3f          	sub    ax,0x3ffc
   14000510c:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005110:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005114:	48 c1 e8 03          	shr    rax,0x3
   140005118:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000511c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005120:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005124:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005128:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   14000512c:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140005130:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140005134:	48 89 c1             	mov    rcx,rax
   140005137:	e8 b4 f8 ff ff       	call   1400049f0 <__pformat_emit_xfloat>
   14000513c:	90                   	nop
   14000513d:	48 83 c4 60          	add    rsp,0x60
   140005141:	5d                   	pop    rbp
   140005142:	c3                   	ret

0000000140005143 <__mingw_pformat>:
   140005143:	55                   	push   rbp
   140005144:	48 89 e5             	mov    rbp,rsp
   140005147:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   14000514e:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005151:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005155:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005159:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   14000515d:	e8 a6 44 00 00       	call   140009608 <_errno>
   140005162:	8b 00                	mov    eax,DWORD PTR [rax]
   140005164:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140005167:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000516b:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   14000516f:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   140005176:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140005179:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000517c:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   140005183:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   14000518a:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   140005191:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   140005197:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   14000519e:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   1400051a4:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   1400051ab:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400051ae:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   1400051b1:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   1400051b8:	e9 27 0c 00 00       	jmp    140005de4 <__mingw_pformat+0xca1>
   1400051bd:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400051c1:	0f 85 0f 0c 00 00    	jne    140005dd6 <__mingw_pformat+0xc93>
   1400051c7:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400051ce:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400051d5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400051d9:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400051dd:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400051e1:	48 83 c0 0c          	add    rax,0xc
   1400051e5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400051e9:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400051ec:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400051ef:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400051f6:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400051f9:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400051fc:	e9 c4 0b 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005201:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005205:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005209:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000520d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005210:	0f be c0             	movsx  eax,al
   140005213:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005216:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   14000521a:	0f 84 94 09 00 00    	je     140005bb4 <__mingw_pformat+0xa71>
   140005220:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   140005224:	0f 8f 02 0b 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000522a:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   14000522e:	0f 84 eb 03 00 00    	je     14000561f <__mingw_pformat+0x4dc>
   140005234:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   140005238:	0f 8f ee 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000523e:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   140005242:	0f 84 31 09 00 00    	je     140005b79 <__mingw_pformat+0xa36>
   140005248:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   14000524c:	0f 8f da 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   140005252:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005256:	0f 84 c3 03 00 00    	je     14000561f <__mingw_pformat+0x4dc>
   14000525c:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005260:	0f 8f c6 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   140005266:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   14000526a:	0f 84 31 09 00 00    	je     140005ba1 <__mingw_pformat+0xa5e>
   140005270:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   140005274:	0f 8f b2 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000527a:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   14000527e:	0f 84 31 03 00 00    	je     1400055b5 <__mingw_pformat+0x472>
   140005284:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   140005288:	0f 8f 9e 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000528e:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   140005292:	0f 84 28 05 00 00    	je     1400057c0 <__mingw_pformat+0x67d>
   140005298:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   14000529c:	0f 8f 8a 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400052a2:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   1400052a6:	0f 84 73 03 00 00    	je     14000561f <__mingw_pformat+0x4dc>
   1400052ac:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   1400052b0:	0f 8f 76 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400052b6:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   1400052ba:	0f 84 4d 07 00 00    	je     140005a0d <__mingw_pformat+0x8ca>
   1400052c0:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   1400052c4:	0f 8f 62 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400052ca:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   1400052ce:	0f 84 2d 03 00 00    	je     140005601 <__mingw_pformat+0x4be>
   1400052d4:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   1400052d8:	0f 8f 4e 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400052de:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   1400052e2:	0f 84 65 08 00 00    	je     140005b4d <__mingw_pformat+0xa0a>
   1400052e8:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   1400052ec:	0f 8f 3a 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400052f2:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   1400052f6:	0f 84 db 07 00 00    	je     140005ad7 <__mingw_pformat+0x994>
   1400052fc:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005300:	0f 8f 26 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   140005306:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   14000530a:	0f 84 ee 03 00 00    	je     1400056fe <__mingw_pformat+0x5bb>
   140005310:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   140005314:	0f 8f 12 0a 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000531a:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   14000531e:	0f 84 87 07 00 00    	je     140005aab <__mingw_pformat+0x968>
   140005324:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   140005328:	0f 8f fe 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000532e:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   140005332:	0f 84 f3 05 00 00    	je     14000592b <__mingw_pformat+0x7e8>
   140005338:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   14000533c:	0f 8f ea 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   140005342:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005346:	0f 84 61 05 00 00    	je     1400058ad <__mingw_pformat+0x76a>
   14000534c:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005350:	0f 8f d6 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   140005356:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   14000535a:	0f 84 cf 04 00 00    	je     14000582f <__mingw_pformat+0x6ec>
   140005360:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   140005364:	0f 8f c2 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000536a:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   14000536e:	0f 84 8a 03 00 00    	je     1400056fe <__mingw_pformat+0x5bb>
   140005374:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   140005378:	0f 8f ae 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000537e:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   140005382:	0f 84 b5 01 00 00    	je     14000553d <__mingw_pformat+0x3fa>
   140005388:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   14000538c:	0f 8f 9a 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   140005392:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005396:	0f 84 83 02 00 00    	je     14000561f <__mingw_pformat+0x4dc>
   14000539c:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   1400053a0:	0f 8f 86 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400053a6:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   1400053aa:	0f 84 f9 05 00 00    	je     1400059a9 <__mingw_pformat+0x866>
   1400053b0:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   1400053b4:	0f 8f 72 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400053ba:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   1400053be:	0f 84 5b 02 00 00    	je     14000561f <__mingw_pformat+0x4dc>
   1400053c4:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   1400053c8:	0f 8f 5e 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400053ce:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   1400053d2:	0f 84 d6 01 00 00    	je     1400055ae <__mingw_pformat+0x46b>
   1400053d8:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   1400053dc:	0f 8f 4a 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400053e2:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   1400053e6:	0f 84 a0 07 00 00    	je     140005b8c <__mingw_pformat+0xa49>
   1400053ec:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   1400053f0:	0f 8f 36 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400053f6:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   1400053fa:	0f 84 ea 06 00 00    	je     140005aea <__mingw_pformat+0x9a7>
   140005400:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   140005404:	0f 8f 22 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000540a:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   14000540e:	0f 84 20 05 00 00    	je     140005934 <__mingw_pformat+0x7f1>
   140005414:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   140005418:	0f 8f 0e 09 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000541e:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   140005422:	0f 84 8e 04 00 00    	je     1400058b6 <__mingw_pformat+0x773>
   140005428:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   14000542c:	0f 8f fa 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   140005432:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005436:	0f 84 fc 03 00 00    	je     140005838 <__mingw_pformat+0x6f5>
   14000543c:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005440:	0f 8f e6 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   140005446:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   14000544a:	0f 84 e6 00 00 00    	je     140005536 <__mingw_pformat+0x3f3>
   140005450:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   140005454:	0f 8f d2 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000545a:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   14000545e:	0f 84 bb 01 00 00    	je     14000561f <__mingw_pformat+0x4dc>
   140005464:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   140005468:	0f 8f be 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000546e:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   140005472:	0f 84 3a 05 00 00    	je     1400059b2 <__mingw_pformat+0x86f>
   140005478:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   14000547c:	0f 8f aa 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   140005482:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005486:	0f 84 8c 08 00 00    	je     140005d18 <__mingw_pformat+0xbd5>
   14000548c:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005490:	0f 8f 96 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   140005496:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   14000549a:	0f 84 27 07 00 00    	je     140005bc7 <__mingw_pformat+0xa84>
   1400054a0:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   1400054a4:	0f 8f 82 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400054aa:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   1400054ae:	0f 84 db 07 00 00    	je     140005c8f <__mingw_pformat+0xb4c>
   1400054b4:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   1400054b8:	0f 8f 6e 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400054be:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   1400054c2:	0f 84 af 07 00 00    	je     140005c77 <__mingw_pformat+0xb34>
   1400054c8:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   1400054cc:	0f 8f 5a 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400054d2:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   1400054d6:	0f 84 1c 07 00 00    	je     140005bf8 <__mingw_pformat+0xab5>
   1400054dc:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   1400054e0:	0f 8f 46 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400054e6:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   1400054ea:	0f 84 b7 07 00 00    	je     140005ca7 <__mingw_pformat+0xb64>
   1400054f0:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   1400054f4:	0f 8f 32 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   1400054fa:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400054fe:	74 23                	je     140005523 <__mingw_pformat+0x3e0>
   140005500:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005504:	0f 8f 22 08 00 00    	jg     140005d2c <__mingw_pformat+0xbe9>
   14000550a:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   14000550e:	0f 84 ec 07 00 00    	je     140005d00 <__mingw_pformat+0xbbd>
   140005514:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   140005518:	0f 84 41 07 00 00    	je     140005c5f <__mingw_pformat+0xb1c>
   14000551e:	e9 09 08 00 00       	jmp    140005d2c <__mingw_pformat+0xbe9>
   140005523:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005527:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000552a:	89 c1                	mov    ecx,eax
   14000552c:	e8 7f dc ff ff       	call   1400031b0 <__pformat_putc>
   140005531:	e9 82 fc ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005536:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   14000553d:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005544:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005548:	74 06                	je     140005550 <__mingw_pformat+0x40d>
   14000554a:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000554e:	75 30                	jne    140005580 <__mingw_pformat+0x43d>
   140005550:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005554:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005558:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000555c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000555e:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   140005562:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005566:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   14000556a:	49 89 d0             	mov    r8,rdx
   14000556d:	ba 01 00 00 00       	mov    edx,0x1
   140005572:	48 89 c1             	mov    rcx,rax
   140005575:	e8 3f de ff ff       	call   1400033b9 <__pformat_wputchars>
   14000557a:	90                   	nop
   14000557b:	e9 38 fc ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005580:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005584:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005588:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000558c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000558e:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   140005591:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005595:	48 8d 45 90          	lea    rax,[rbp-0x70]
   140005599:	49 89 d0             	mov    r8,rdx
   14000559c:	ba 01 00 00 00       	mov    edx,0x1
   1400055a1:	48 89 c1             	mov    rcx,rax
   1400055a4:	e8 8b dc ff ff       	call   140003234 <__pformat_putchars>
   1400055a9:	e9 0a fc ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   1400055ae:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400055b5:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400055b9:	74 06                	je     1400055c1 <__mingw_pformat+0x47e>
   1400055bb:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055bf:	75 20                	jne    1400055e1 <__mingw_pformat+0x49e>
   1400055c1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055c5:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055c9:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055cd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400055d0:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055d4:	48 89 c1             	mov    rcx,rax
   1400055d7:	e8 29 df ff ff       	call   140003505 <__pformat_wcputs>
   1400055dc:	e9 d7 fb ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   1400055e1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055e5:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055e9:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055ed:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400055f0:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055f4:	48 89 c1             	mov    rcx,rax
   1400055f7:	e8 37 dd ff ff       	call   140003333 <__pformat_puts>
   1400055fc:	e9 b7 fb ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005601:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140005604:	89 c1                	mov    ecx,eax
   140005606:	e8 8d 40 00 00       	call   140009698 <strerror>
   14000560b:	48 89 c1             	mov    rcx,rax
   14000560e:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005612:	48 89 c2             	mov    rdx,rax
   140005615:	e8 19 dd ff ff       	call   140003333 <__pformat_puts>
   14000561a:	e9 99 fb ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   14000561f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005622:	80 e4 fe             	and    ah,0xfe
   140005625:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005628:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000562c:	75 15                	jne    140005643 <__mingw_pformat+0x500>
   14000562e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005632:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005636:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000563a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000563d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005641:	eb 54                	jmp    140005697 <__mingw_pformat+0x554>
   140005643:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005647:	75 16                	jne    14000565f <__mingw_pformat+0x51c>
   140005649:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000564d:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005651:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005655:	8b 00                	mov    eax,DWORD PTR [rax]
   140005657:	89 c0                	mov    eax,eax
   140005659:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000565d:	eb 38                	jmp    140005697 <__mingw_pformat+0x554>
   14000565f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005663:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005667:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000566b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000566d:	89 c0                	mov    eax,eax
   14000566f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005673:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005677:	75 0d                	jne    140005686 <__mingw_pformat+0x543>
   140005679:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000567d:	0f b7 c0             	movzx  eax,ax
   140005680:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005684:	eb 11                	jmp    140005697 <__mingw_pformat+0x554>
   140005686:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   14000568a:	75 0b                	jne    140005697 <__mingw_pformat+0x554>
   14000568c:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   140005690:	0f b6 c0             	movzx  eax,al
   140005693:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005697:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   14000569b:	75 2e                	jne    1400056cb <__mingw_pformat+0x588>
   14000569d:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400056a1:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400056a5:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400056ac:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400056b3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400056b7:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400056be:	48 89 c1             	mov    rcx,rax
   1400056c1:	e8 55 df ff ff       	call   14000361b <__pformat_int>
   1400056c6:	e9 ed fa ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   1400056cb:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400056cf:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400056d3:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400056da:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400056e1:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   1400056e5:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   1400056ec:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400056ef:	49 89 c8             	mov    r8,rcx
   1400056f2:	89 c1                	mov    ecx,eax
   1400056f4:	e8 a5 e2 ff ff       	call   14000399e <__pformat_xint>
   1400056f9:	e9 ba fa ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   1400056fe:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005701:	0c 80                	or     al,0x80
   140005703:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005706:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000570a:	75 15                	jne    140005721 <__mingw_pformat+0x5de>
   14000570c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005710:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005714:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005718:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000571b:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000571f:	eb 56                	jmp    140005777 <__mingw_pformat+0x634>
   140005721:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005725:	75 16                	jne    14000573d <__mingw_pformat+0x5fa>
   140005727:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000572b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000572f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005733:	8b 00                	mov    eax,DWORD PTR [rax]
   140005735:	48 98                	cdqe
   140005737:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000573b:	eb 3a                	jmp    140005777 <__mingw_pformat+0x634>
   14000573d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005741:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005745:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005749:	8b 00                	mov    eax,DWORD PTR [rax]
   14000574b:	48 98                	cdqe
   14000574d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005751:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005755:	75 0e                	jne    140005765 <__mingw_pformat+0x622>
   140005757:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000575b:	48 0f bf c0          	movsx  rax,ax
   14000575f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005763:	eb 12                	jmp    140005777 <__mingw_pformat+0x634>
   140005765:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005769:	75 0c                	jne    140005777 <__mingw_pformat+0x634>
   14000576b:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   14000576f:	48 0f be c0          	movsx  rax,al
   140005773:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005777:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000577b:	48 85 c0             	test   rax,rax
   14000577e:	79 09                	jns    140005789 <__mingw_pformat+0x646>
   140005780:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140005787:	eb 05                	jmp    14000578e <__mingw_pformat+0x64b>
   140005789:	b8 00 00 00 00       	mov    eax,0x0
   14000578e:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140005792:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005796:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   14000579a:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400057a1:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400057a8:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400057ac:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400057b3:	48 89 c1             	mov    rcx,rax
   1400057b6:	e8 60 de ff ff       	call   14000361b <__pformat_int>
   1400057bb:	e9 f8 f9 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   1400057c0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400057c4:	75 18                	jne    1400057de <__mingw_pformat+0x69b>
   1400057c6:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057c9:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   1400057cc:	75 10                	jne    1400057de <__mingw_pformat+0x69b>
   1400057ce:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057d1:	80 cc 02             	or     ah,0x2
   1400057d4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400057d7:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   1400057de:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057e2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057e6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057ea:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400057ed:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057f1:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   1400057f8:	00 
   1400057f9:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057fd:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005801:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005808:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   14000580f:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005813:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000581a:	49 89 d0             	mov    r8,rdx
   14000581d:	48 89 c2             	mov    rdx,rax
   140005820:	b9 78 00 00 00       	mov    ecx,0x78
   140005825:	e8 74 e1 ff ff       	call   14000399e <__pformat_xint>
   14000582a:	e9 89 f9 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   14000582f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005832:	83 c8 20             	or     eax,0x20
   140005835:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005838:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000583b:	83 e0 04             	and    eax,0x4
   14000583e:	85 c0                	test   eax,eax
   140005840:	74 2f                	je     140005871 <__mingw_pformat+0x72e>
   140005842:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005846:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000584a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000584e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005851:	db 28                	fld    TBYTE PTR [rax]
   140005853:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005859:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000585d:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005864:	48 89 c1             	mov    rcx,rax
   140005867:	e8 1d ef ff ff       	call   140004789 <__pformat_efloat>
   14000586c:	e9 47 f9 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005871:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005875:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005879:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000587d:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   140005881:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   140005888:	ff 
   140005889:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000588f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005895:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005899:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058a0:	48 89 c1             	mov    rcx,rax
   1400058a3:	e8 e1 ee ff ff       	call   140004789 <__pformat_efloat>
   1400058a8:	e9 0b f9 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   1400058ad:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058b0:	83 c8 20             	or     eax,0x20
   1400058b3:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400058b6:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058b9:	83 e0 04             	and    eax,0x4
   1400058bc:	85 c0                	test   eax,eax
   1400058be:	74 2f                	je     1400058ef <__mingw_pformat+0x7ac>
   1400058c0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058c4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058c8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058cc:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400058cf:	db 28                	fld    TBYTE PTR [rax]
   1400058d1:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058d7:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058db:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058e2:	48 89 c1             	mov    rcx,rax
   1400058e5:	e8 cf ed ff ff       	call   1400046b9 <__pformat_float>
   1400058ea:	e9 c9 f8 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   1400058ef:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058f3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058f7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058fb:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   1400058ff:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   140005906:	ff 
   140005907:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000590d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005913:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005917:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000591e:	48 89 c1             	mov    rcx,rax
   140005921:	e8 93 ed ff ff       	call   1400046b9 <__pformat_float>
   140005926:	e9 8d f8 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   14000592b:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000592e:	83 c8 20             	or     eax,0x20
   140005931:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005934:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005937:	83 e0 04             	and    eax,0x4
   14000593a:	85 c0                	test   eax,eax
   14000593c:	74 2f                	je     14000596d <__mingw_pformat+0x82a>
   14000593e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005942:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005946:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000594a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000594d:	db 28                	fld    TBYTE PTR [rax]
   14000594f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005955:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005959:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005960:	48 89 c1             	mov    rcx,rax
   140005963:	e8 cc ee ff ff       	call   140004834 <__pformat_gfloat>
   140005968:	e9 4b f8 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   14000596d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005971:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005975:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005979:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   14000597d:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   140005984:	ff 
   140005985:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000598b:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005991:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005995:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000599c:	48 89 c1             	mov    rcx,rax
   14000599f:	e8 90 ee ff ff       	call   140004834 <__pformat_gfloat>
   1400059a4:	e9 0f f8 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   1400059a9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059ac:	83 c8 20             	or     eax,0x20
   1400059af:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400059b2:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059b5:	83 e0 04             	and    eax,0x4
   1400059b8:	85 c0                	test   eax,eax
   1400059ba:	74 2f                	je     1400059eb <__mingw_pformat+0x8a8>
   1400059bc:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059c0:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059c4:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059c8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059cb:	db 28                	fld    TBYTE PTR [rax]
   1400059cd:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059d3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059d7:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059de:	48 89 c1             	mov    rcx,rax
   1400059e1:	e8 e7 f4 ff ff       	call   140004ecd <__pformat_xldouble>
   1400059e6:	e9 cd f7 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   1400059eb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059ef:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059f3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059f7:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059fa:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059fe:	66 48 0f 6e c0       	movq   xmm0,rax
   140005a03:	e8 de f5 ff ff       	call   140004fe6 <__pformat_xdouble>
   140005a08:	e9 ab f7 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005a0d:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005a11:	75 1b                	jne    140005a2e <__mingw_pformat+0x8eb>
   140005a13:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a16:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a1a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a1e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a22:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a25:	89 ca                	mov    edx,ecx
   140005a27:	88 10                	mov    BYTE PTR [rax],dl
   140005a29:	e9 8a f7 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005a2e:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005a32:	75 1c                	jne    140005a50 <__mingw_pformat+0x90d>
   140005a34:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a37:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a3b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a3f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a43:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a46:	89 ca                	mov    edx,ecx
   140005a48:	66 89 10             	mov    WORD PTR [rax],dx
   140005a4b:	e9 68 f7 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005a50:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005a54:	75 19                	jne    140005a6f <__mingw_pformat+0x92c>
   140005a56:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a5a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a5e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a62:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a65:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005a68:	89 10                	mov    DWORD PTR [rax],edx
   140005a6a:	e9 49 f7 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005a6f:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005a73:	75 1d                	jne    140005a92 <__mingw_pformat+0x94f>
   140005a75:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a78:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a7c:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a80:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a84:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a87:	48 63 d1             	movsxd rdx,ecx
   140005a8a:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005a8d:	e9 26 f7 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005a92:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a96:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a9a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a9e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005aa1:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005aa4:	89 10                	mov    DWORD PTR [rax],edx
   140005aa6:	e9 0d f7 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005aab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005aaf:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ab2:	3c 68                	cmp    al,0x68
   140005ab4:	75 0e                	jne    140005ac4 <__mingw_pformat+0x981>
   140005ab6:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005abb:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005ac2:	eb 07                	jmp    140005acb <__mingw_pformat+0x988>
   140005ac4:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005acb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ad2:	e9 ee 02 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005ad7:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005ade:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ae5:	e9 db 02 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005aea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005aee:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005af1:	3c 36                	cmp    al,0x36
   140005af3:	75 1d                	jne    140005b12 <__mingw_pformat+0x9cf>
   140005af5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005af9:	48 83 c0 01          	add    rax,0x1
   140005afd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b00:	3c 34                	cmp    al,0x34
   140005b02:	75 0e                	jne    140005b12 <__mingw_pformat+0x9cf>
   140005b04:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b0b:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b10:	eb 2f                	jmp    140005b41 <__mingw_pformat+0x9fe>
   140005b12:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b16:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b19:	3c 33                	cmp    al,0x33
   140005b1b:	75 1d                	jne    140005b3a <__mingw_pformat+0x9f7>
   140005b1d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b21:	48 83 c0 01          	add    rax,0x1
   140005b25:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b28:	3c 32                	cmp    al,0x32
   140005b2a:	75 0e                	jne    140005b3a <__mingw_pformat+0x9f7>
   140005b2c:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b33:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b38:	eb 07                	jmp    140005b41 <__mingw_pformat+0x9fe>
   140005b3a:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b41:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b48:	e9 78 02 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005b4d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b51:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b54:	3c 6c                	cmp    al,0x6c
   140005b56:	75 0e                	jne    140005b66 <__mingw_pformat+0xa23>
   140005b58:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b5d:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b64:	eb 07                	jmp    140005b6d <__mingw_pformat+0xa2a>
   140005b66:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b6d:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b74:	e9 4c 02 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005b79:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b80:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b87:	e9 39 02 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005b8c:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005b8f:	83 c8 04             	or     eax,0x4
   140005b92:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005b95:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b9c:	e9 24 02 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005ba1:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005ba8:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005baf:	e9 11 02 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005bb4:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bbb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bc2:	e9 fe 01 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005bc7:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005bcb:	77 1f                	ja     140005bec <__mingw_pformat+0xaa9>
   140005bcd:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005bd4:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005bd8:	48 83 c0 10          	add    rax,0x10
   140005bdc:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005be0:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005be7:	e9 d9 01 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005bec:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bf3:	e9 cd 01 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005bf8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005bfd:	74 4c                	je     140005c4b <__mingw_pformat+0xb08>
   140005bff:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c03:	74 06                	je     140005c0b <__mingw_pformat+0xac8>
   140005c05:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005c09:	75 40                	jne    140005c4b <__mingw_pformat+0xb08>
   140005c0b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005c0f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005c13:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005c17:	8b 10                	mov    edx,DWORD PTR [rax]
   140005c19:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c1d:	89 10                	mov    DWORD PTR [rax],edx
   140005c1f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c23:	8b 00                	mov    eax,DWORD PTR [rax]
   140005c25:	85 c0                	test   eax,eax
   140005c27:	79 29                	jns    140005c52 <__mingw_pformat+0xb0f>
   140005c29:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c2d:	75 13                	jne    140005c42 <__mingw_pformat+0xaff>
   140005c2f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c32:	80 cc 04             	or     ah,0x4
   140005c35:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c38:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005c3b:	f7 d8                	neg    eax
   140005c3d:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005c40:	eb 10                	jmp    140005c52 <__mingw_pformat+0xb0f>
   140005c42:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005c49:	eb 07                	jmp    140005c52 <__mingw_pformat+0xb0f>
   140005c4b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c52:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005c59:	00 
   140005c5a:	e9 66 01 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005c5f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c63:	0f 85 4f 01 00 00    	jne    140005db8 <__mingw_pformat+0xc75>
   140005c69:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c6c:	80 cc 08             	or     ah,0x8
   140005c6f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c72:	e9 41 01 00 00       	jmp    140005db8 <__mingw_pformat+0xc75>
   140005c77:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c7b:	0f 85 3a 01 00 00    	jne    140005dbb <__mingw_pformat+0xc78>
   140005c81:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c84:	80 cc 01             	or     ah,0x1
   140005c87:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c8a:	e9 2c 01 00 00       	jmp    140005dbb <__mingw_pformat+0xc78>
   140005c8f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c93:	0f 85 25 01 00 00    	jne    140005dbe <__mingw_pformat+0xc7b>
   140005c99:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c9c:	80 cc 04             	or     ah,0x4
   140005c9f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005ca2:	e9 17 01 00 00       	jmp    140005dbe <__mingw_pformat+0xc7b>
   140005ca7:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cab:	0f 85 10 01 00 00    	jne    140005dc1 <__mingw_pformat+0xc7e>
   140005cb1:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cb4:	80 cc 10             	or     ah,0x10
   140005cb7:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cba:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005cc1:	00 
   140005cc2:	e8 a1 39 00 00       	call   140009668 <localeconv>
   140005cc7:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005ccb:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005ccf:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005cd3:	49 89 c9             	mov    r9,rcx
   140005cd6:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005cdc:	48 89 c1             	mov    rcx,rax
   140005cdf:	e8 bc 33 00 00       	call   1400090a0 <mbrtowc>
   140005ce4:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005ce7:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005ceb:	7e 08                	jle    140005cf5 <__mingw_pformat+0xbb2>
   140005ced:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005cf1:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005cf5:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005cf8:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005cfb:	e9 c1 00 00 00       	jmp    140005dc1 <__mingw_pformat+0xc7e>
   140005d00:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d04:	0f 85 ba 00 00 00    	jne    140005dc4 <__mingw_pformat+0xc81>
   140005d0a:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d0d:	83 c8 40             	or     eax,0x40
   140005d10:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d13:	e9 ac 00 00 00       	jmp    140005dc4 <__mingw_pformat+0xc81>
   140005d18:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d1c:	75 0e                	jne    140005d2c <__mingw_pformat+0xbe9>
   140005d1e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d21:	80 cc 02             	or     ah,0x2
   140005d24:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d27:	e9 99 00 00 00       	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005d2c:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005d30:	77 68                	ja     140005d9a <__mingw_pformat+0xc57>
   140005d32:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005d36:	7f 62                	jg     140005d9a <__mingw_pformat+0xc57>
   140005d38:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005d3c:	7e 5c                	jle    140005d9a <__mingw_pformat+0xc57>
   140005d3e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d42:	75 09                	jne    140005d4d <__mingw_pformat+0xc0a>
   140005d44:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005d4b:	eb 0d                	jmp    140005d5a <__mingw_pformat+0xc17>
   140005d4d:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005d51:	75 07                	jne    140005d5a <__mingw_pformat+0xc17>
   140005d53:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005d5a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005d5f:	74 64                	je     140005dc5 <__mingw_pformat+0xc82>
   140005d61:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d65:	8b 00                	mov    eax,DWORD PTR [rax]
   140005d67:	85 c0                	test   eax,eax
   140005d69:	79 0e                	jns    140005d79 <__mingw_pformat+0xc36>
   140005d6b:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d6e:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d71:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d75:	89 10                	mov    DWORD PTR [rax],edx
   140005d77:	eb 4c                	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005d79:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d7d:	8b 10                	mov    edx,DWORD PTR [rax]
   140005d7f:	89 d0                	mov    eax,edx
   140005d81:	c1 e0 02             	shl    eax,0x2
   140005d84:	01 d0                	add    eax,edx
   140005d86:	01 c0                	add    eax,eax
   140005d88:	89 c2                	mov    edx,eax
   140005d8a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d8d:	01 d0                	add    eax,edx
   140005d8f:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d92:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d96:	89 10                	mov    DWORD PTR [rax],edx
   140005d98:	eb 2b                	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005d9a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005d9e:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005da2:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005da6:	48 89 c2             	mov    rdx,rax
   140005da9:	b9 25 00 00 00       	mov    ecx,0x25
   140005dae:	e8 fd d3 ff ff       	call   1400031b0 <__pformat_putc>
   140005db3:	e9 00 f4 ff ff       	jmp    1400051b8 <__mingw_pformat+0x75>
   140005db8:	90                   	nop
   140005db9:	eb 0a                	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005dbb:	90                   	nop
   140005dbc:	eb 07                	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005dbe:	90                   	nop
   140005dbf:	eb 04                	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005dc1:	90                   	nop
   140005dc2:	eb 01                	jmp    140005dc5 <__mingw_pformat+0xc82>
   140005dc4:	90                   	nop
   140005dc5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005dc9:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005dcc:	84 c0                	test   al,al
   140005dce:	0f 85 2d f4 ff ff    	jne    140005201 <__mingw_pformat+0xbe>
   140005dd4:	eb 0e                	jmp    140005de4 <__mingw_pformat+0xca1>
   140005dd6:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005dda:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005ddd:	89 c1                	mov    ecx,eax
   140005ddf:	e8 cc d3 ff ff       	call   1400031b0 <__pformat_putc>
   140005de4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005de8:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005dec:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005df0:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005df3:	0f be c0             	movsx  eax,al
   140005df6:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005df9:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005dfd:	0f 85 ba f3 ff ff    	jne    1400051bd <__mingw_pformat+0x7a>
   140005e03:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005e06:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005e0d:	5d                   	pop    rbp
   140005e0e:	c3                   	ret
   140005e0f:	90                   	nop

0000000140005e10 <__rv_alloc_D2A>:
   140005e10:	55                   	push   rbp
   140005e11:	48 89 e5             	mov    rbp,rsp
   140005e14:	48 83 ec 30          	sub    rsp,0x30
   140005e18:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005e1b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005e22:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005e29:	eb 07                	jmp    140005e32 <__rv_alloc_D2A+0x22>
   140005e2b:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005e2f:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005e32:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005e35:	83 c0 17             	add    eax,0x17
   140005e38:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005e3b:	7f ee                	jg     140005e2b <__rv_alloc_D2A+0x1b>
   140005e3d:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005e40:	89 c1                	mov    ecx,eax
   140005e42:	e8 56 1e 00 00       	call   140007c9d <__Balloc_D2A>
   140005e47:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005e4b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e4f:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005e52:	89 10                	mov    DWORD PTR [rax],edx
   140005e54:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e58:	48 83 c0 04          	add    rax,0x4
   140005e5c:	48 83 c4 30          	add    rsp,0x30
   140005e60:	5d                   	pop    rbp
   140005e61:	c3                   	ret

0000000140005e62 <__nrv_alloc_D2A>:
   140005e62:	55                   	push   rbp
   140005e63:	48 89 e5             	mov    rbp,rsp
   140005e66:	48 83 ec 30          	sub    rsp,0x30
   140005e6a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005e6e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005e72:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005e76:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005e79:	89 c1                	mov    ecx,eax
   140005e7b:	e8 90 ff ff ff       	call   140005e10 <__rv_alloc_D2A>
   140005e80:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005e84:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e88:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005e8c:	eb 05                	jmp    140005e93 <__nrv_alloc_D2A+0x31>
   140005e8e:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005e93:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005e97:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e9b:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005e9f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005ea2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ea6:	88 10                	mov    BYTE PTR [rax],dl
   140005ea8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005eac:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005eaf:	84 c0                	test   al,al
   140005eb1:	75 db                	jne    140005e8e <__nrv_alloc_D2A+0x2c>
   140005eb3:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005eb8:	74 0b                	je     140005ec5 <__nrv_alloc_D2A+0x63>
   140005eba:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005ebe:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005ec2:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005ec5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ec9:	48 83 c4 30          	add    rsp,0x30
   140005ecd:	5d                   	pop    rbp
   140005ece:	c3                   	ret

0000000140005ecf <__freedtoa>:
   140005ecf:	55                   	push   rbp
   140005ed0:	48 89 e5             	mov    rbp,rsp
   140005ed3:	48 83 ec 30          	sub    rsp,0x30
   140005ed7:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005edb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005edf:	48 83 e8 04          	sub    rax,0x4
   140005ee3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005ee7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005eeb:	8b 10                	mov    edx,DWORD PTR [rax]
   140005eed:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ef1:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005ef4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ef8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005efb:	ba 01 00 00 00       	mov    edx,0x1
   140005f00:	89 c1                	mov    ecx,eax
   140005f02:	d3 e2                	shl    edx,cl
   140005f04:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f08:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005f0b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f0f:	48 89 c1             	mov    rcx,rax
   140005f12:	e8 c7 1e 00 00       	call   140007dde <__Bfree_D2A>
   140005f17:	90                   	nop
   140005f18:	48 83 c4 30          	add    rsp,0x30
   140005f1c:	5d                   	pop    rbp
   140005f1d:	c3                   	ret

0000000140005f1e <__quorem_D2A>:
   140005f1e:	55                   	push   rbp
   140005f1f:	48 89 e5             	mov    rbp,rsp
   140005f22:	48 83 ec 70          	sub    rsp,0x70
   140005f26:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f2a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005f2e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f32:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f35:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005f38:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f3c:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f3f:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005f42:	7e 0a                	jle    140005f4e <__quorem_D2A+0x30>
   140005f44:	b8 00 00 00 00       	mov    eax,0x0
   140005f49:	e9 3f 02 00 00       	jmp    14000618d <__quorem_D2A+0x26f>
   140005f4e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f52:	48 83 c0 18          	add    rax,0x18
   140005f56:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005f5a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005f5e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005f61:	48 98                	cdqe
   140005f63:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005f6a:	00 
   140005f6b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005f6f:	48 01 d0             	add    rax,rdx
   140005f72:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005f76:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f7a:	48 83 c0 18          	add    rax,0x18
   140005f7e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005f82:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005f85:	48 98                	cdqe
   140005f87:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005f8e:	00 
   140005f8f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f93:	48 01 d0             	add    rax,rdx
   140005f96:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140005f9a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005f9e:	8b 00                	mov    eax,DWORD PTR [rax]
   140005fa0:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140005fa4:	8b 12                	mov    edx,DWORD PTR [rdx]
   140005fa6:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140005fa9:	ba 00 00 00 00       	mov    edx,0x0
   140005fae:	f7 f1                	div    ecx
   140005fb0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140005fb3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140005fb7:	0f 84 c4 00 00 00    	je     140006081 <__quorem_D2A+0x163>
   140005fbd:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140005fc4:	00 
   140005fc5:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   140005fcc:	00 
   140005fcd:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005fd1:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140005fd5:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140005fd9:	8b 00                	mov    eax,DWORD PTR [rax]
   140005fdb:	89 c2                	mov    edx,eax
   140005fdd:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140005fe0:	48 0f af d0          	imul   rdx,rax
   140005fe4:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140005fe8:	48 01 d0             	add    rax,rdx
   140005feb:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140005fef:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140005ff3:	48 c1 e8 20          	shr    rax,0x20
   140005ff7:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140005ffb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005fff:	8b 00                	mov    eax,DWORD PTR [rax]
   140006001:	89 c1                	mov    ecx,eax
   140006003:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006007:	89 c2                	mov    edx,eax
   140006009:	48 89 c8             	mov    rax,rcx
   14000600c:	48 29 d0             	sub    rax,rdx
   14000600f:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006013:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006017:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000601b:	48 c1 e8 20          	shr    rax,0x20
   14000601f:	83 e0 01             	and    eax,0x1
   140006022:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006026:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000602a:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000602e:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006032:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006036:	89 10                	mov    DWORD PTR [rax],edx
   140006038:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000603c:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006040:	73 8b                	jae    140005fcd <__quorem_D2A+0xaf>
   140006042:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006046:	8b 00                	mov    eax,DWORD PTR [rax]
   140006048:	85 c0                	test   eax,eax
   14000604a:	75 35                	jne    140006081 <__quorem_D2A+0x163>
   14000604c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006050:	48 83 c0 18          	add    rax,0x18
   140006054:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006058:	eb 04                	jmp    14000605e <__quorem_D2A+0x140>
   14000605a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000605e:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   140006063:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006067:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   14000606b:	73 0a                	jae    140006077 <__quorem_D2A+0x159>
   14000606d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006071:	8b 00                	mov    eax,DWORD PTR [rax]
   140006073:	85 c0                	test   eax,eax
   140006075:	74 e3                	je     14000605a <__quorem_D2A+0x13c>
   140006077:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000607b:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000607e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006081:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140006085:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006089:	48 89 c1             	mov    rcx,rax
   14000608c:	e8 bc 24 00 00       	call   14000854d <__cmp_D2A>
   140006091:	85 c0                	test   eax,eax
   140006093:	0f 88 f1 00 00 00    	js     14000618a <__quorem_D2A+0x26c>
   140006099:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   14000609d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400060a4:	00 
   1400060a5:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   1400060ac:	00 
   1400060ad:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060b1:	48 83 c0 18          	add    rax,0x18
   1400060b5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400060b9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400060bd:	48 83 c0 18          	add    rax,0x18
   1400060c1:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400060c5:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400060c9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400060cd:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   1400060d1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060d3:	89 c2                	mov    edx,eax
   1400060d5:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400060d9:	48 01 d0             	add    rax,rdx
   1400060dc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400060e0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400060e4:	48 c1 e8 20          	shr    rax,0x20
   1400060e8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400060ec:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060f0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060f2:	89 c1                	mov    ecx,eax
   1400060f4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400060f8:	89 c2                	mov    edx,eax
   1400060fa:	48 89 c8             	mov    rax,rcx
   1400060fd:	48 29 d0             	sub    rax,rdx
   140006100:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006104:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006108:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000610c:	48 c1 e8 20          	shr    rax,0x20
   140006110:	83 e0 01             	and    eax,0x1
   140006113:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006117:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000611b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000611f:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006123:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006127:	89 10                	mov    DWORD PTR [rax],edx
   140006129:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000612d:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006131:	73 92                	jae    1400060c5 <__quorem_D2A+0x1a7>
   140006133:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006137:	48 83 c0 18          	add    rax,0x18
   14000613b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000613f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006142:	48 98                	cdqe
   140006144:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000614b:	00 
   14000614c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006150:	48 01 d0             	add    rax,rdx
   140006153:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006157:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000615b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000615d:	85 c0                	test   eax,eax
   14000615f:	75 29                	jne    14000618a <__quorem_D2A+0x26c>
   140006161:	eb 04                	jmp    140006167 <__quorem_D2A+0x249>
   140006163:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140006167:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   14000616c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006170:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   140006174:	73 0a                	jae    140006180 <__quorem_D2A+0x262>
   140006176:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000617a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000617c:	85 c0                	test   eax,eax
   14000617e:	74 e3                	je     140006163 <__quorem_D2A+0x245>
   140006180:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006184:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006187:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000618a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   14000618d:	48 83 c4 70          	add    rsp,0x70
   140006191:	5d                   	pop    rbp
   140006192:	c3                   	ret
   140006193:	90                   	nop
   140006194:	90                   	nop
   140006195:	90                   	nop
   140006196:	90                   	nop
   140006197:	90                   	nop
   140006198:	90                   	nop
   140006199:	90                   	nop
   14000619a:	90                   	nop
   14000619b:	90                   	nop
   14000619c:	90                   	nop
   14000619d:	90                   	nop
   14000619e:	90                   	nop
   14000619f:	90                   	nop

00000001400061a0 <__hi0bits_D2A>:
   1400061a0:	55                   	push   rbp
   1400061a1:	48 89 e5             	mov    rbp,rsp
   1400061a4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400061a7:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   1400061ab:	83 f0 1f             	xor    eax,0x1f
   1400061ae:	5d                   	pop    rbp
   1400061af:	c3                   	ret

00000001400061b0 <bitstob>:
   1400061b0:	55                   	push   rbp
   1400061b1:	53                   	push   rbx
   1400061b2:	48 83 ec 58          	sub    rsp,0x58
   1400061b6:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400061bb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400061bf:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   1400061c2:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400061c6:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   1400061cd:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400061d4:	eb 07                	jmp    1400061dd <bitstob+0x2d>
   1400061d6:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   1400061d9:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   1400061dd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400061e0:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   1400061e3:	7c f1                	jl     1400061d6 <bitstob+0x26>
   1400061e5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400061e8:	89 c1                	mov    ecx,eax
   1400061ea:	e8 ae 1a 00 00       	call   140007c9d <__Balloc_D2A>
   1400061ef:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400061f3:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   1400061f6:	83 e8 01             	sub    eax,0x1
   1400061f9:	c1 f8 05             	sar    eax,0x5
   1400061fc:	48 98                	cdqe
   1400061fe:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006205:	00 
   140006206:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000620a:	48 01 d0             	add    rax,rdx
   14000620d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140006211:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006215:	48 83 c0 18          	add    rax,0x18
   140006219:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000621d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006221:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006225:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006229:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000622d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006231:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140006235:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006237:	89 10                	mov    DWORD PTR [rax],edx
   140006239:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   14000623e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006242:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140006246:	73 dd                	jae    140006225 <bitstob+0x75>
   140006248:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000624c:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140006250:	48 c1 f8 02          	sar    rax,0x2
   140006254:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140006257:	eb 1d                	jmp    140006276 <bitstob+0xc6>
   140006259:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000625d:	75 17                	jne    140006276 <bitstob+0xc6>
   14000625f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006263:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   14000626a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000626e:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140006274:	eb 59                	jmp    1400062cf <bitstob+0x11f>
   140006276:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000627a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000627d:	48 98                	cdqe
   14000627f:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006286:	00 
   140006287:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000628b:	48 01 d0             	add    rax,rdx
   14000628e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006290:	85 c0                	test   eax,eax
   140006292:	74 c5                	je     140006259 <bitstob+0xa9>
   140006294:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006297:	8d 50 01             	lea    edx,[rax+0x1]
   14000629a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000629e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400062a1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062a4:	83 c0 01             	add    eax,0x1
   1400062a7:	c1 e0 05             	shl    eax,0x5
   1400062aa:	89 c3                	mov    ebx,eax
   1400062ac:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062b0:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400062b3:	48 63 d2             	movsxd rdx,edx
   1400062b6:	48 83 c2 04          	add    rdx,0x4
   1400062ba:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   1400062be:	89 c1                	mov    ecx,eax
   1400062c0:	e8 db fe ff ff       	call   1400061a0 <__hi0bits_D2A>
   1400062c5:	29 c3                	sub    ebx,eax
   1400062c7:	89 da                	mov    edx,ebx
   1400062c9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400062cd:	89 10                	mov    DWORD PTR [rax],edx
   1400062cf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062d3:	48 83 c4 58          	add    rsp,0x58
   1400062d7:	5b                   	pop    rbx
   1400062d8:	5d                   	pop    rbp
   1400062d9:	c3                   	ret

00000001400062da <__gdtoa>:
   1400062da:	55                   	push   rbp
   1400062db:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   1400062e2:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   1400062e9:	00 
   1400062ea:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   1400062f1:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   1400062f7:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   1400062fe:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   140006305:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   14000630c:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006313:	8b 00                	mov    eax,DWORD PTR [rax]
   140006315:	83 e0 cf             	and    eax,0xffffffcf
   140006318:	89 c2                	mov    edx,eax
   14000631a:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006321:	89 10                	mov    DWORD PTR [rax],edx
   140006323:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   14000632a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000632c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000632f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006332:	83 e0 07             	and    eax,0x7
   140006335:	83 f8 04             	cmp    eax,0x4
   140006338:	0f 84 b0 00 00 00    	je     1400063ee <__gdtoa+0x114>
   14000633e:	83 f8 04             	cmp    eax,0x4
   140006341:	0f 8f d5 00 00 00    	jg     14000641c <__gdtoa+0x142>
   140006347:	83 f8 03             	cmp    eax,0x3
   14000634a:	74 74                	je     1400063c0 <__gdtoa+0xe6>
   14000634c:	83 f8 03             	cmp    eax,0x3
   14000634f:	0f 8f c7 00 00 00    	jg     14000641c <__gdtoa+0x142>
   140006355:	85 c0                	test   eax,eax
   140006357:	0f 84 05 01 00 00    	je     140006462 <__gdtoa+0x188>
   14000635d:	85 c0                	test   eax,eax
   14000635f:	0f 88 b7 00 00 00    	js     14000641c <__gdtoa+0x142>
   140006365:	83 e8 01             	sub    eax,0x1
   140006368:	83 f8 01             	cmp    eax,0x1
   14000636b:	0f 87 ab 00 00 00    	ja     14000641c <__gdtoa+0x142>
   140006371:	90                   	nop
   140006372:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006379:	8b 00                	mov    eax,DWORD PTR [rax]
   14000637b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000637e:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   140006382:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006385:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   14000638c:	49 89 c8             	mov    r8,rcx
   14000638f:	48 89 c1             	mov    rcx,rax
   140006392:	e8 19 fe ff ff       	call   1400061b0 <bitstob>
   140006397:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000639b:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   1400063a1:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400063a4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063a8:	48 89 c1             	mov    rcx,rax
   1400063ab:	e8 31 16 00 00       	call   1400079e1 <__trailz_D2A>
   1400063b0:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400063b3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400063b6:	85 c0                	test   eax,eax
   1400063b8:	0f 84 8b 00 00 00    	je     140006449 <__gdtoa+0x16f>
   1400063be:	eb 66                	jmp    140006426 <__gdtoa+0x14c>
   1400063c0:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400063c7:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   1400063cd:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400063d4:	48 8d 0d 75 4f 00 00 	lea    rcx,[rip+0x4f75]        # 14000b350 <.rdata>
   1400063db:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400063e1:	48 89 c2             	mov    rdx,rax
   1400063e4:	e8 79 fa ff ff       	call   140005e62 <__nrv_alloc_D2A>
   1400063e9:	e9 4d 14 00 00       	jmp    14000783b <__gdtoa+0x1561>
   1400063ee:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400063f5:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   1400063fb:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006402:	48 8d 0d 50 4f 00 00 	lea    rcx,[rip+0x4f50]        # 14000b359 <.rdata+0x9>
   140006409:	41 b8 03 00 00 00    	mov    r8d,0x3
   14000640f:	48 89 c2             	mov    rdx,rax
   140006412:	e8 4b fa ff ff       	call   140005e62 <__nrv_alloc_D2A>
   140006417:	e9 1f 14 00 00       	jmp    14000783b <__gdtoa+0x1561>
   14000641c:	b8 00 00 00 00       	mov    eax,0x0
   140006421:	e9 15 14 00 00       	jmp    14000783b <__gdtoa+0x1561>
   140006426:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006429:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000642d:	48 89 c1             	mov    rcx,rax
   140006430:	e8 50 14 00 00       	call   140007885 <__rshift_D2A>
   140006435:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006438:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   14000643e:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006441:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006444:	29 c2                	sub    edx,eax
   140006446:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   140006449:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000644d:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006450:	85 c0                	test   eax,eax
   140006452:	75 3d                	jne    140006491 <__gdtoa+0x1b7>
   140006454:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006458:	48 89 c1             	mov    rcx,rax
   14000645b:	e8 7e 19 00 00       	call   140007dde <__Bfree_D2A>
   140006460:	eb 01                	jmp    140006463 <__gdtoa+0x189>
   140006462:	90                   	nop
   140006463:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   14000646a:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140006470:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006477:	48 8d 0d df 4e 00 00 	lea    rcx,[rip+0x4edf]        # 14000b35d <.rdata+0xd>
   14000647e:	41 b8 01 00 00 00    	mov    r8d,0x1
   140006484:	48 89 c2             	mov    rdx,rax
   140006487:	e8 d6 f9 ff ff       	call   140005e62 <__nrv_alloc_D2A>
   14000648c:	e9 aa 13 00 00       	jmp    14000783b <__gdtoa+0x1561>
   140006491:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   140006495:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006499:	48 89 c1             	mov    rcx,rax
   14000649c:	e8 75 23 00 00       	call   140008816 <__b2d_D2A>
   1400064a1:	66 48 0f 7e c0       	movq   rax,xmm0
   1400064a6:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   1400064aa:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400064ad:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   1400064b3:	01 d0                	add    eax,edx
   1400064b5:	83 e8 01             	sub    eax,0x1
   1400064b8:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400064bb:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   1400064be:	25 ff ff 0f 00       	and    eax,0xfffff
   1400064c3:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400064c6:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   1400064c9:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400064ce:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400064d1:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400064d6:	f2 0f 10 15 82 4e 00 	movsd  xmm2,QWORD PTR [rip+0x4e82]        # 14000b360 <.rdata+0x10>
   1400064dd:	00 
   1400064de:	66 0f 28 c8          	movapd xmm1,xmm0
   1400064e2:	f2 0f 5c ca          	subsd  xmm1,xmm2
   1400064e6:	f2 0f 10 05 7a 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e7a]        # 14000b368 <.rdata+0x18>
   1400064ed:	00 
   1400064ee:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   1400064f2:	f2 0f 10 05 76 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e76]        # 14000b370 <.rdata+0x20>
   1400064f9:	00 
   1400064fa:	f2 0f 58 c8          	addsd  xmm1,xmm0
   1400064fe:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006501:	66 0f ef d2          	pxor   xmm2,xmm2
   140006505:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   140006509:	f2 0f 10 05 67 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e67]        # 14000b378 <.rdata+0x28>
   140006510:	00 
   140006511:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006515:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006519:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000651e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006521:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006524:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006528:	79 03                	jns    14000652d <__gdtoa+0x253>
   14000652a:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   14000652d:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   140006534:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006538:	7e 23                	jle    14000655d <__gdtoa+0x283>
   14000653a:	66 0f ef c9          	pxor   xmm1,xmm1
   14000653e:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   140006543:	f2 0f 10 05 35 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e35]        # 14000b380 <.rdata+0x30>
   14000654a:	00 
   14000654b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000654f:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006554:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006558:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000655d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006562:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006566:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006569:	66 0f ef c0          	pxor   xmm0,xmm0
   14000656d:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006572:	76 1b                	jbe    14000658f <__gdtoa+0x2b5>
   140006574:	66 0f ef c0          	pxor   xmm0,xmm0
   140006578:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   14000657d:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006582:	7a 07                	jp     14000658b <__gdtoa+0x2b1>
   140006584:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006589:	74 04                	je     14000658f <__gdtoa+0x2b5>
   14000658b:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000658f:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   140006596:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006599:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   14000659c:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   1400065a2:	01 ca                	add    edx,ecx
   1400065a4:	83 ea 01             	sub    edx,0x1
   1400065a7:	c1 e2 14             	shl    edx,0x14
   1400065aa:	01 d0                	add    eax,edx
   1400065ac:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400065af:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400065b3:	78 2e                	js     1400065e3 <__gdtoa+0x309>
   1400065b5:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   1400065b9:	7f 28                	jg     1400065e3 <__gdtoa+0x309>
   1400065bb:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400065c0:	48 8b 05 b9 50 00 00 	mov    rax,QWORD PTR [rip+0x50b9]        # 14000b680 <.refptr.__tens_D2A>
   1400065c7:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   1400065ca:	48 63 d2             	movsxd rdx,edx
   1400065cd:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400065d2:	66 0f 2f c1          	comisd xmm0,xmm1
   1400065d6:	76 04                	jbe    1400065dc <__gdtoa+0x302>
   1400065d8:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400065dc:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   1400065e3:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400065e6:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400065e9:	29 c2                	sub    edx,eax
   1400065eb:	8d 42 ff             	lea    eax,[rdx-0x1]
   1400065ee:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400065f1:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065f5:	78 0f                	js     140006606 <__gdtoa+0x32c>
   1400065f7:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   1400065fe:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006601:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   140006604:	eb 0f                	jmp    140006615 <__gdtoa+0x33b>
   140006606:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006609:	f7 d8                	neg    eax
   14000660b:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   14000660e:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   140006615:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006619:	78 15                	js     140006630 <__gdtoa+0x356>
   14000661b:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   140006622:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006625:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   140006628:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000662b:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   14000662e:	eb 15                	jmp    140006645 <__gdtoa+0x36b>
   140006630:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006633:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006636:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006639:	f7 d8                	neg    eax
   14000663b:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   14000663e:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   140006645:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000664c:	78 09                	js     140006657 <__gdtoa+0x37d>
   14000664e:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   140006655:	7e 0a                	jle    140006661 <__gdtoa+0x387>
   140006657:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   14000665e:	00 00 00 
   140006661:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   140006668:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   14000666f:	7e 10                	jle    140006681 <__gdtoa+0x3a7>
   140006671:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   140006678:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000667f:	eb 1b                	jmp    14000669c <__gdtoa+0x3c2>
   140006681:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006684:	3d f9 03 00 00       	cmp    eax,0x3f9
   140006689:	7f 0a                	jg     140006695 <__gdtoa+0x3bb>
   14000668b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000668e:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   140006693:	7d 07                	jge    14000669c <__gdtoa+0x3c2>
   140006695:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000669c:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   1400066a3:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   1400066aa:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400066ad:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400066b0:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400066b7:	0f 84 c5 00 00 00    	je     140006782 <__gdtoa+0x4a8>
   1400066bd:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400066c4:	0f 8f e6 00 00 00    	jg     1400067b0 <__gdtoa+0x4d6>
   1400066ca:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   1400066d1:	74 7e                	je     140006751 <__gdtoa+0x477>
   1400066d3:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   1400066da:	0f 8f d0 00 00 00    	jg     1400067b0 <__gdtoa+0x4d6>
   1400066e0:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   1400066e7:	0f 84 8e 00 00 00    	je     14000677b <__gdtoa+0x4a1>
   1400066ed:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   1400066f4:	0f 8f b6 00 00 00    	jg     1400067b0 <__gdtoa+0x4d6>
   1400066fa:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006701:	7f 0e                	jg     140006711 <__gdtoa+0x437>
   140006703:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000670a:	79 13                	jns    14000671f <__gdtoa+0x445>
   14000670c:	e9 9f 00 00 00       	jmp    1400067b0 <__gdtoa+0x4d6>
   140006711:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140006718:	74 30                	je     14000674a <__gdtoa+0x470>
   14000671a:	e9 91 00 00 00       	jmp    1400067b0 <__gdtoa+0x4d6>
   14000671f:	66 0f ef c9          	pxor   xmm1,xmm1
   140006723:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   140006728:	f2 0f 10 05 58 4c 00 	movsd  xmm0,QWORD PTR [rip+0x4c58]        # 14000b388 <.rdata+0x38>
   14000672f:	00 
   140006730:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006734:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006738:	83 c0 03             	add    eax,0x3
   14000673b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000673e:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   140006745:	00 00 00 
   140006748:	eb 66                	jmp    1400067b0 <__gdtoa+0x4d6>
   14000674a:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006751:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006758:	7f 0a                	jg     140006764 <__gdtoa+0x48a>
   14000675a:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   140006761:	00 00 00 
   140006764:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   14000676a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000676d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006770:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006773:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006776:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006779:	eb 35                	jmp    1400067b0 <__gdtoa+0x4d6>
   14000677b:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006782:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   140006788:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000678b:	01 d0                	add    eax,edx
   14000678d:	83 c0 01             	add    eax,0x1
   140006790:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006793:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006796:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006799:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000679c:	83 e8 01             	sub    eax,0x1
   14000679f:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   1400067a2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067a5:	85 c0                	test   eax,eax
   1400067a7:	7f 07                	jg     1400067b0 <__gdtoa+0x4d6>
   1400067a9:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400067b0:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067b3:	89 c1                	mov    ecx,eax
   1400067b5:	e8 56 f6 ff ff       	call   140005e10 <__rv_alloc_D2A>
   1400067ba:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400067be:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400067c2:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   1400067c6:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400067cd:	7f 09                	jg     1400067d8 <__gdtoa+0x4fe>
   1400067cf:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   1400067d6:	eb 38                	jmp    140006810 <__gdtoa+0x536>
   1400067d8:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400067df:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400067e2:	83 e8 01             	sub    eax,0x1
   1400067e5:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   1400067e8:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400067ec:	74 22                	je     140006810 <__gdtoa+0x536>
   1400067ee:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400067f2:	79 07                	jns    1400067fb <__gdtoa+0x521>
   1400067f4:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   1400067fb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400067fe:	83 e0 08             	and    eax,0x8
   140006801:	85 c0                	test   eax,eax
   140006803:	74 0b                	je     140006810 <__gdtoa+0x536>
   140006805:	b8 03 00 00 00       	mov    eax,0x3
   14000680a:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   14000680d:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006810:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006814:	0f 88 b9 04 00 00    	js     140006cd3 <__gdtoa+0x9f9>
   14000681a:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   14000681e:	0f 8f af 04 00 00    	jg     140006cd3 <__gdtoa+0x9f9>
   140006824:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   140006828:	0f 84 a5 04 00 00    	je     140006cd3 <__gdtoa+0x9f9>
   14000682e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006832:	0f 85 9b 04 00 00    	jne    140006cd3 <__gdtoa+0x9f9>
   140006838:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000683c:	0f 85 91 04 00 00    	jne    140006cd3 <__gdtoa+0x9f9>
   140006842:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006849:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   14000684e:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   140006853:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006856:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140006859:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   14000685c:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   14000685f:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   140006866:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000686a:	0f 8e 98 00 00 00    	jle    140006908 <__gdtoa+0x62e>
   140006870:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006873:	83 e0 0f             	and    eax,0xf
   140006876:	89 c2                	mov    edx,eax
   140006878:	48 8b 05 01 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e01]        # 14000b680 <.refptr.__tens_D2A>
   14000687f:	48 63 d2             	movsxd rdx,edx
   140006882:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006887:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000688c:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000688f:	c1 f8 04             	sar    eax,0x4
   140006892:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006895:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006898:	83 e0 10             	and    eax,0x10
   14000689b:	85 c0                	test   eax,eax
   14000689d:	74 5e                	je     1400068fd <__gdtoa+0x623>
   14000689f:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   1400068a3:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400068a8:	48 8b 05 01 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d01]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400068af:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   1400068b4:	f2 0f 5e c1          	divsd  xmm0,xmm1
   1400068b8:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400068bd:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400068c1:	eb 3a                	jmp    1400068fd <__gdtoa+0x623>
   1400068c3:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400068c6:	83 e0 01             	and    eax,0x1
   1400068c9:	85 c0                	test   eax,eax
   1400068cb:	74 24                	je     1400068f1 <__gdtoa+0x617>
   1400068cd:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400068d1:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400068d4:	48 8b 05 d5 4c 00 00 	mov    rax,QWORD PTR [rip+0x4cd5]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400068db:	48 63 d2             	movsxd rdx,edx
   1400068de:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400068e3:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   1400068e8:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400068ec:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068f1:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   1400068f4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400068f7:	83 c0 01             	add    eax,0x1
   1400068fa:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400068fd:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006901:	75 c0                	jne    1400068c3 <__gdtoa+0x5e9>
   140006903:	e9 8b 00 00 00       	jmp    140006993 <__gdtoa+0x6b9>
   140006908:	f2 0f 10 05 80 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a80]        # 14000b390 <.rdata+0x40>
   14000690f:	00 
   140006910:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006915:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006918:	f7 d8                	neg    eax
   14000691a:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   14000691d:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140006921:	74 70                	je     140006993 <__gdtoa+0x6b9>
   140006923:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006928:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   14000692b:	83 e0 0f             	and    eax,0xf
   14000692e:	89 c2                	mov    edx,eax
   140006930:	48 8b 05 49 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d49]        # 14000b680 <.refptr.__tens_D2A>
   140006937:	48 63 d2             	movsxd rdx,edx
   14000693a:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   14000693f:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006943:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006948:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   14000694b:	c1 f8 04             	sar    eax,0x4
   14000694e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006951:	eb 3a                	jmp    14000698d <__gdtoa+0x6b3>
   140006953:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006956:	83 e0 01             	and    eax,0x1
   140006959:	85 c0                	test   eax,eax
   14000695b:	74 24                	je     140006981 <__gdtoa+0x6a7>
   14000695d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006961:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006966:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006969:	48 8b 05 40 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c40]        # 14000b5b0 <.refptr.__bigtens_D2A>
   140006970:	48 63 d2             	movsxd rdx,edx
   140006973:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006978:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000697c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006981:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006984:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006987:	83 c0 01             	add    eax,0x1
   14000698a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000698d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006991:	75 c0                	jne    140006953 <__gdtoa+0x679>
   140006993:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140006997:	74 47                	je     1400069e0 <__gdtoa+0x706>
   140006999:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   14000699e:	f2 0f 10 05 ea 49 00 	movsd  xmm0,QWORD PTR [rip+0x49ea]        # 14000b390 <.rdata+0x40>
   1400069a5:	00 
   1400069a6:	66 0f 2f c1          	comisd xmm0,xmm1
   1400069aa:	76 34                	jbe    1400069e0 <__gdtoa+0x706>
   1400069ac:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400069b0:	7e 2e                	jle    1400069e0 <__gdtoa+0x706>
   1400069b2:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   1400069b6:	0f 8e f5 02 00 00    	jle    140006cb1 <__gdtoa+0x9d7>
   1400069bc:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400069bf:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400069c2:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400069c6:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069cb:	f2 0f 10 05 c5 49 00 	movsd  xmm0,QWORD PTR [rip+0x49c5]        # 14000b398 <.rdata+0x48>
   1400069d2:	00 
   1400069d3:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069d7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069dc:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400069e0:	66 0f ef c9          	pxor   xmm1,xmm1
   1400069e4:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   1400069e9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400069ee:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   1400069f2:	f2 0f 10 05 a6 49 00 	movsd  xmm0,QWORD PTR [rip+0x49a6]        # 14000b3a0 <.rdata+0x50>
   1400069f9:	00 
   1400069fa:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400069fe:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a03:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   140006a06:	2d 00 00 40 03       	sub    eax,0x3400000
   140006a0b:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   140006a0e:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a12:	75 5f                	jne    140006a73 <__gdtoa+0x799>
   140006a14:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006a1b:	00 
   140006a1c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006a20:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006a24:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a29:	f2 0f 10 0d 77 49 00 	movsd  xmm1,QWORD PTR [rip+0x4977]        # 14000b3a8 <.rdata+0x58>
   140006a30:	00 
   140006a31:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a35:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a3a:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a3f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006a44:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a48:	0f 87 ac 07 00 00    	ja     1400071fa <__gdtoa+0xf20>
   140006a4e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a53:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006a58:	f3 0f 7e 15 50 49 00 	movq   xmm2,QWORD PTR [rip+0x4950]        # 14000b3b0 <.rdata+0x60>
   140006a5f:	00 
   140006a60:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006a64:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a68:	0f 87 6e 07 00 00    	ja     1400071dc <__gdtoa+0xf02>
   140006a6e:	e9 42 02 00 00       	jmp    140006cb5 <__gdtoa+0x9db>
   140006a73:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006a77:	0f 84 22 01 00 00    	je     140006b9f <__gdtoa+0x8c5>
   140006a7d:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006a82:	f2 0f 10 05 36 49 00 	movsd  xmm0,QWORD PTR [rip+0x4936]        # 14000b3c0 <.rdata+0x70>
   140006a89:	00 
   140006a8a:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a8e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006a91:	8d 50 ff             	lea    edx,[rax-0x1]
   140006a94:	48 8b 05 e5 4b 00 00 	mov    rax,QWORD PTR [rip+0x4be5]        # 14000b680 <.refptr.__tens_D2A>
   140006a9b:	48 63 d2             	movsxd rdx,edx
   140006a9e:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006aa3:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006aa7:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006aac:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006ab0:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006ab5:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006abc:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ac1:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006ac6:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006aca:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006acd:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ad2:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ad6:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006adb:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006ae0:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006ae4:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006ae9:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006aec:	8d 48 30             	lea    ecx,[rax+0x30]
   140006aef:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006af3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006af7:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006afb:	89 ca                	mov    edx,ecx
   140006afd:	88 10                	mov    BYTE PTR [rax],dl
   140006aff:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b04:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b09:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b0d:	76 29                	jbe    140006b38 <__gdtoa+0x85e>
   140006b0f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b14:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b18:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b1c:	7a 0e                	jp     140006b2c <__gdtoa+0x852>
   140006b1e:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b22:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b26:	0f 84 93 0c 00 00    	je     1400077bf <__gdtoa+0x14e5>
   140006b2c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006b33:	e9 87 0c 00 00       	jmp    1400077bf <__gdtoa+0x14e5>
   140006b38:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006b3d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006b42:	66 0f 28 c8          	movapd xmm1,xmm0
   140006b46:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006b4a:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b4f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b53:	0f 87 c3 02 00 00    	ja     140006e1c <__gdtoa+0xb42>
   140006b59:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006b5c:	83 c0 01             	add    eax,0x1
   140006b5f:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006b62:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006b65:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006b68:	0f 8e 46 01 00 00    	jle    140006cb4 <__gdtoa+0x9da>
   140006b6e:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b73:	f2 0f 10 05 1d 48 00 	movsd  xmm0,QWORD PTR [rip+0x481d]        # 14000b398 <.rdata+0x48>
   140006b7a:	00 
   140006b7b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b7f:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b84:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b89:	f2 0f 10 05 07 48 00 	movsd  xmm0,QWORD PTR [rip+0x4807]        # 14000b398 <.rdata+0x48>
   140006b90:	00 
   140006b91:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b95:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b9a:	e9 1d ff ff ff       	jmp    140006abc <__gdtoa+0x7e2>
   140006b9f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006ba4:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006ba7:	8d 50 ff             	lea    edx,[rax-0x1]
   140006baa:	48 8b 05 cf 4a 00 00 	mov    rax,QWORD PTR [rip+0x4acf]        # 14000b680 <.refptr.__tens_D2A>
   140006bb1:	48 63 d2             	movsxd rdx,edx
   140006bb4:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006bb9:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bbd:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006bc2:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006bc9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006bce:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006bd3:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006bd7:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006bda:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006bde:	74 1c                	je     140006bfc <__gdtoa+0x922>
   140006be0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006be5:	66 0f ef c9          	pxor   xmm1,xmm1
   140006be9:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006bee:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006bf3:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006bf7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006bfc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006bff:	8d 48 30             	lea    ecx,[rax+0x30]
   140006c02:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006c06:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006c0a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006c0e:	89 ca                	mov    edx,ecx
   140006c10:	88 10                	mov    BYTE PTR [rax],dl
   140006c12:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c15:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006c18:	75 73                	jne    140006c8d <__gdtoa+0x9b3>
   140006c1a:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006c1f:	f2 0f 10 05 99 47 00 	movsd  xmm0,QWORD PTR [rip+0x4799]        # 14000b3c0 <.rdata+0x70>
   140006c26:	00 
   140006c27:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c2b:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006c30:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c35:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c3a:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006c3f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c43:	0f 87 d6 01 00 00    	ja     140006e1f <__gdtoa+0xb45>
   140006c49:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c4e:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006c53:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006c58:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006c5c:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c60:	77 02                	ja     140006c64 <__gdtoa+0x98a>
   140006c62:	eb 51                	jmp    140006cb5 <__gdtoa+0x9db>
   140006c64:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c69:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c6d:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c71:	7a 0e                	jp     140006c81 <__gdtoa+0x9a7>
   140006c73:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c77:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c7b:	0f 84 41 0b 00 00    	je     1400077c2 <__gdtoa+0x14e8>
   140006c81:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006c88:	e9 35 0b 00 00       	jmp    1400077c2 <__gdtoa+0x14e8>
   140006c8d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c90:	83 c0 01             	add    eax,0x1
   140006c93:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006c96:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c9b:	f2 0f 10 05 f5 46 00 	movsd  xmm0,QWORD PTR [rip+0x46f5]        # 14000b398 <.rdata+0x48>
   140006ca2:	00 
   140006ca3:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006ca7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006cac:	e9 18 ff ff ff       	jmp    140006bc9 <__gdtoa+0x8ef>
   140006cb1:	90                   	nop
   140006cb2:	eb 01                	jmp    140006cb5 <__gdtoa+0x9db>
   140006cb4:	90                   	nop
   140006cb5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006cb9:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006cbd:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006cc2:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006cc7:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006cca:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006ccd:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006cd0:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006cd3:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006cda:	0f 88 bf 01 00 00    	js     140006e9f <__gdtoa+0xbc5>
   140006ce0:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006ce7:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006cea:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006ced:	0f 8f ac 01 00 00    	jg     140006e9f <__gdtoa+0xbc5>
   140006cf3:	48 8b 05 86 49 00 00 	mov    rax,QWORD PTR [rip+0x4986]        # 14000b680 <.refptr.__tens_D2A>
   140006cfa:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006cfd:	48 63 d2             	movsxd rdx,edx
   140006d00:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006d05:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006d0a:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006d11:	79 45                	jns    140006d58 <__gdtoa+0xa7e>
   140006d13:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d17:	7f 3f                	jg     140006d58 <__gdtoa+0xa7e>
   140006d19:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006d20:	00 
   140006d21:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006d25:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006d29:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d2d:	0f 88 ac 04 00 00    	js     1400071df <__gdtoa+0xf05>
   140006d33:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d38:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006d3d:	f2 0f 10 05 63 46 00 	movsd  xmm0,QWORD PTR [rip+0x4663]        # 14000b3a8 <.rdata+0x58>
   140006d44:	00 
   140006d45:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006d49:	66 0f 2f c1          	comisd xmm0,xmm1
   140006d4d:	0f 83 8c 04 00 00    	jae    1400071df <__gdtoa+0xf05>
   140006d53:	e9 a6 04 00 00       	jmp    1400071fe <__gdtoa+0xf24>
   140006d58:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006d5f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d64:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006d69:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006d6d:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006d70:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d75:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d79:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006d7e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006d83:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006d87:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d8c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006d8f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006d92:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006d96:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006d9a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006d9e:	89 ca                	mov    edx,ecx
   140006da0:	88 10                	mov    BYTE PTR [rax],dl
   140006da2:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006da7:	66 0f ef c9          	pxor   xmm1,xmm1
   140006dab:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006daf:	7a 0e                	jp     140006dbf <__gdtoa+0xae5>
   140006db1:	66 0f ef c9          	pxor   xmm1,xmm1
   140006db5:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006db9:	0f 84 da 00 00 00    	je     140006e99 <__gdtoa+0xbbf>
   140006dbf:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006dc2:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006dc5:	0f 85 aa 00 00 00    	jne    140006e75 <__gdtoa+0xb9b>
   140006dcb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006dcf:	74 12                	je     140006de3 <__gdtoa+0xb09>
   140006dd1:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006dd5:	74 4b                	je     140006e22 <__gdtoa+0xb48>
   140006dd7:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006dde:	e9 e3 09 00 00       	jmp    1400077c6 <__gdtoa+0x14ec>
   140006de3:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006de8:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006dec:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006df1:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006df6:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006dfb:	77 28                	ja     140006e25 <__gdtoa+0xb4b>
   140006dfd:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e02:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e07:	7a 63                	jp     140006e6c <__gdtoa+0xb92>
   140006e09:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e0e:	75 5c                	jne    140006e6c <__gdtoa+0xb92>
   140006e10:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006e13:	83 e0 01             	and    eax,0x1
   140006e16:	85 c0                	test   eax,eax
   140006e18:	74 52                	je     140006e6c <__gdtoa+0xb92>
   140006e1a:	eb 0a                	jmp    140006e26 <__gdtoa+0xb4c>
   140006e1c:	90                   	nop
   140006e1d:	eb 07                	jmp    140006e26 <__gdtoa+0xb4c>
   140006e1f:	90                   	nop
   140006e20:	eb 04                	jmp    140006e26 <__gdtoa+0xb4c>
   140006e22:	90                   	nop
   140006e23:	eb 01                	jmp    140006e26 <__gdtoa+0xb4c>
   140006e25:	90                   	nop
   140006e26:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006e2d:	eb 17                	jmp    140006e46 <__gdtoa+0xb6c>
   140006e2f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e33:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006e37:	75 0d                	jne    140006e46 <__gdtoa+0xb6c>
   140006e39:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006e3d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e41:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006e44:	eb 10                	jmp    140006e56 <__gdtoa+0xb7c>
   140006e46:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006e4b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e4f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006e52:	3c 39                	cmp    al,0x39
   140006e54:	74 d9                	je     140006e2f <__gdtoa+0xb55>
   140006e56:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e5a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006e5e:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006e62:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006e65:	83 c2 01             	add    edx,0x1
   140006e68:	88 10                	mov    BYTE PTR [rax],dl
   140006e6a:	eb 2e                	jmp    140006e9a <__gdtoa+0xbc0>
   140006e6c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e73:	eb 25                	jmp    140006e9a <__gdtoa+0xbc0>
   140006e75:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e78:	83 c0 01             	add    eax,0x1
   140006e7b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006e7e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006e83:	f2 0f 10 05 0d 45 00 	movsd  xmm0,QWORD PTR [rip+0x450d]        # 14000b398 <.rdata+0x48>
   140006e8a:	00 
   140006e8b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006e8f:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e94:	e9 c6 fe ff ff       	jmp    140006d5f <__gdtoa+0xa85>
   140006e99:	90                   	nop
   140006e9a:	e9 27 09 00 00       	jmp    1400077c6 <__gdtoa+0x14ec>
   140006e9f:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006ea2:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006ea5:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006ea8:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006eab:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006eb2:	00 
   140006eb3:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006eb7:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006ebb:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006ebf:	0f 84 e0 00 00 00    	je     140006fa5 <__gdtoa+0xccb>
   140006ec5:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006ec8:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006ecb:	29 c2                	sub    edx,eax
   140006ecd:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006ed0:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ed3:	8d 50 01             	lea    edx,[rax+0x1]
   140006ed6:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006ed9:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006edf:	29 c2                	sub    edx,eax
   140006ee1:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006ee8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006eeb:	39 c2                	cmp    edx,eax
   140006eed:	7d 43                	jge    140006f32 <__gdtoa+0xc58>
   140006eef:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006ef6:	74 3a                	je     140006f32 <__gdtoa+0xc58>
   140006ef8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006eff:	74 31                	je     140006f32 <__gdtoa+0xc58>
   140006f01:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f08:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f0b:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f11:	29 c2                	sub    edx,eax
   140006f13:	8d 42 01             	lea    eax,[rdx+0x1]
   140006f16:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f19:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f20:	7e 68                	jle    140006f8a <__gdtoa+0xcb0>
   140006f22:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006f26:	7e 62                	jle    140006f8a <__gdtoa+0xcb0>
   140006f28:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f2b:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006f2e:	7d 5a                	jge    140006f8a <__gdtoa+0xcb0>
   140006f30:	eb 0a                	jmp    140006f3c <__gdtoa+0xc62>
   140006f32:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f39:	7e 50                	jle    140006f8b <__gdtoa+0xcb1>
   140006f3b:	90                   	nop
   140006f3c:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f3f:	83 e8 01             	sub    eax,0x1
   140006f42:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006f45:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006f48:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006f4b:	7c 08                	jl     140006f55 <__gdtoa+0xc7b>
   140006f4d:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f50:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006f53:	eb 19                	jmp    140006f6e <__gdtoa+0xc94>
   140006f55:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006f58:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006f5b:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f5e:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006f61:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f64:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006f67:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006f6e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f71:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f74:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f77:	85 c0                	test   eax,eax
   140006f79:	79 10                	jns    140006f8b <__gdtoa+0xcb1>
   140006f7b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f7e:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006f81:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006f88:	eb 01                	jmp    140006f8b <__gdtoa+0xcb1>
   140006f8a:	90                   	nop
   140006f8b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f8e:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140006f91:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f94:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140006f97:	b9 01 00 00 00       	mov    ecx,0x1
   140006f9c:	e8 f6 0f 00 00       	call   140007f97 <__i2b_D2A>
   140006fa1:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006fa5:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140006fa9:	7e 26                	jle    140006fd1 <__gdtoa+0xcf7>
   140006fab:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   140006faf:	7e 20                	jle    140006fd1 <__gdtoa+0xcf7>
   140006fb1:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140006fb4:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140006fb7:	39 c2                	cmp    edx,eax
   140006fb9:	0f 4e c2             	cmovle eax,edx
   140006fbc:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006fbf:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fc2:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006fc5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fc8:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006fcb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fce:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140006fd1:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140006fd5:	7e 7e                	jle    140007055 <__gdtoa+0xd7b>
   140006fd7:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006fdb:	74 65                	je     140007042 <__gdtoa+0xd68>
   140006fdd:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140006fe1:	7e 3b                	jle    14000701e <__gdtoa+0xd44>
   140006fe3:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140006fe6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006fea:	48 89 c1             	mov    rcx,rax
   140006fed:	e8 11 12 00 00       	call   140008203 <__pow5mult_D2A>
   140006ff2:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006ff6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140006ffa:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006ffe:	48 89 c1             	mov    rcx,rax
   140007001:	e8 d7 0f 00 00       	call   140007fdd <__mult_D2A>
   140007006:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000700a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000700e:	48 89 c1             	mov    rcx,rax
   140007011:	e8 c8 0d 00 00       	call   140007dde <__Bfree_D2A>
   140007016:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000701a:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000701e:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140007021:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   140007024:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007027:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000702b:	74 28                	je     140007055 <__gdtoa+0xd7b>
   14000702d:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   140007030:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007034:	48 89 c1             	mov    rcx,rax
   140007037:	e8 c7 11 00 00       	call   140008203 <__pow5mult_D2A>
   14000703c:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007040:	eb 13                	jmp    140007055 <__gdtoa+0xd7b>
   140007042:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   140007045:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007049:	48 89 c1             	mov    rcx,rax
   14000704c:	e8 b2 11 00 00       	call   140008203 <__pow5mult_D2A>
   140007051:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007055:	b9 01 00 00 00       	mov    ecx,0x1
   14000705a:	e8 38 0f 00 00       	call   140007f97 <__i2b_D2A>
   14000705f:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007063:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007067:	7e 13                	jle    14000707c <__gdtoa+0xda2>
   140007069:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   14000706c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007070:	48 89 c1             	mov    rcx,rax
   140007073:	e8 8b 11 00 00       	call   140008203 <__pow5mult_D2A>
   140007078:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000707c:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   140007083:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000708a:	7f 29                	jg     1400070b5 <__gdtoa+0xddb>
   14000708c:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   14000708f:	83 f8 01             	cmp    eax,0x1
   140007092:	75 21                	jne    1400070b5 <__gdtoa+0xddb>
   140007094:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000709b:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000709e:	83 c0 01             	add    eax,0x1
   1400070a1:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   1400070a4:	7e 0f                	jle    1400070b5 <__gdtoa+0xddb>
   1400070a6:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   1400070aa:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   1400070ae:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   1400070b5:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   1400070b9:	74 22                	je     1400070dd <__gdtoa+0xe03>
   1400070bb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070bf:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400070c2:	8d 50 ff             	lea    edx,[rax-0x1]
   1400070c5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070c9:	48 63 d2             	movsxd rdx,edx
   1400070cc:	48 83 c2 04          	add    rdx,0x4
   1400070d0:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   1400070d4:	89 c1                	mov    ecx,eax
   1400070d6:	e8 c5 f0 ff ff       	call   1400061a0 <__hi0bits_D2A>
   1400070db:	eb 05                	jmp    1400070e2 <__gdtoa+0xe08>
   1400070dd:	b8 1f 00 00 00       	mov    eax,0x1f
   1400070e2:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   1400070e5:	83 e8 04             	sub    eax,0x4
   1400070e8:	83 e0 1f             	and    eax,0x1f
   1400070eb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400070ee:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400070f1:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   1400070f4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400070f7:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   1400070fa:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   1400070fe:	7e 13                	jle    140007113 <__gdtoa+0xe39>
   140007100:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   140007103:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007107:	48 89 c1             	mov    rcx,rax
   14000710a:	e8 b1 12 00 00       	call   1400083c0 <__lshift_D2A>
   14000710f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007113:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007116:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140007119:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000711d:	7e 13                	jle    140007132 <__gdtoa+0xe58>
   14000711f:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007122:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007126:	48 89 c1             	mov    rcx,rax
   140007129:	e8 92 12 00 00       	call   1400083c0 <__lshift_D2A>
   14000712e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007132:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140007136:	74 5a                	je     140007192 <__gdtoa+0xeb8>
   140007138:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000713c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007140:	48 89 c1             	mov    rcx,rax
   140007143:	e8 05 14 00 00       	call   14000854d <__cmp_D2A>
   140007148:	85 c0                	test   eax,eax
   14000714a:	79 46                	jns    140007192 <__gdtoa+0xeb8>
   14000714c:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140007150:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007154:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000715a:	ba 0a 00 00 00       	mov    edx,0xa
   14000715f:	48 89 c1             	mov    rcx,rax
   140007162:	e8 02 0d 00 00       	call   140007e69 <__multadd_D2A>
   140007167:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000716b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000716f:	74 1b                	je     14000718c <__gdtoa+0xeb2>
   140007171:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007175:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000717b:	ba 0a 00 00 00       	mov    edx,0xa
   140007180:	48 89 c1             	mov    rcx,rax
   140007183:	e8 e1 0c 00 00       	call   140007e69 <__multadd_D2A>
   140007188:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000718c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000718f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140007192:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007196:	0f 8f 81 00 00 00    	jg     14000721d <__gdtoa+0xf43>
   14000719c:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400071a3:	7e 78                	jle    14000721d <__gdtoa+0xf43>
   1400071a5:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400071a9:	78 37                	js     1400071e2 <__gdtoa+0xf08>
   1400071ab:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400071af:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071b5:	ba 05 00 00 00       	mov    edx,0x5
   1400071ba:	48 89 c1             	mov    rcx,rax
   1400071bd:	e8 a7 0c 00 00       	call   140007e69 <__multadd_D2A>
   1400071c2:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400071c6:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400071ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071ce:	48 89 c1             	mov    rcx,rax
   1400071d1:	e8 77 13 00 00       	call   14000854d <__cmp_D2A>
   1400071d6:	85 c0                	test   eax,eax
   1400071d8:	7f 23                	jg     1400071fd <__gdtoa+0xf23>
   1400071da:	eb 07                	jmp    1400071e3 <__gdtoa+0xf09>
   1400071dc:	90                   	nop
   1400071dd:	eb 04                	jmp    1400071e3 <__gdtoa+0xf09>
   1400071df:	90                   	nop
   1400071e0:	eb 01                	jmp    1400071e3 <__gdtoa+0xf09>
   1400071e2:	90                   	nop
   1400071e3:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   1400071e9:	f7 d0                	not    eax
   1400071eb:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   1400071ee:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400071f5:	e9 87 05 00 00       	jmp    140007781 <__gdtoa+0x14a7>
   1400071fa:	90                   	nop
   1400071fb:	eb 01                	jmp    1400071fe <__gdtoa+0xf24>
   1400071fd:	90                   	nop
   1400071fe:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007205:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007209:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000720d:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007211:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007214:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007218:	e9 64 05 00 00       	jmp    140007781 <__gdtoa+0x14a7>
   14000721d:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140007221:	0f 84 14 04 00 00    	je     14000763b <__gdtoa+0x1361>
   140007227:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   14000722b:	7e 13                	jle    140007240 <__gdtoa+0xf66>
   14000722d:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   140007230:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007234:	48 89 c1             	mov    rcx,rax
   140007237:	e8 84 11 00 00       	call   1400083c0 <__lshift_D2A>
   14000723c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007240:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007244:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007248:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   14000724c:	74 57                	je     1400072a5 <__gdtoa+0xfcb>
   14000724e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007252:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007255:	89 c1                	mov    ecx,eax
   140007257:	e8 41 0a 00 00       	call   140007c9d <__Balloc_D2A>
   14000725c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007260:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007264:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007267:	48 98                	cdqe
   140007269:	48 83 c0 02          	add    rax,0x2
   14000726d:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007274:	00 
   140007275:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007279:	48 8d 50 10          	lea    rdx,[rax+0x10]
   14000727d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007281:	48 83 c0 10          	add    rax,0x10
   140007285:	49 89 c8             	mov    r8,rcx
   140007288:	48 89 c1             	mov    rcx,rax
   14000728b:	e8 e8 23 00 00       	call   140009678 <memcpy>
   140007290:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007294:	ba 01 00 00 00       	mov    edx,0x1
   140007299:	48 89 c1             	mov    rcx,rax
   14000729c:	e8 1f 11 00 00       	call   1400083c0 <__lshift_D2A>
   1400072a1:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072a5:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400072ac:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400072b0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072b4:	48 89 c1             	mov    rcx,rax
   1400072b7:	e8 62 ec ff ff       	call   140005f1e <__quorem_D2A>
   1400072bc:	83 c0 30             	add    eax,0x30
   1400072bf:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400072c2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400072c6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072ca:	48 89 c1             	mov    rcx,rax
   1400072cd:	e8 7b 12 00 00       	call   14000854d <__cmp_D2A>
   1400072d2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400072d5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400072d9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400072dd:	48 89 c1             	mov    rcx,rax
   1400072e0:	e8 38 13 00 00       	call   14000861d <__diff_D2A>
   1400072e5:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400072e9:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   1400072ed:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400072f0:	85 c0                	test   eax,eax
   1400072f2:	75 15                	jne    140007309 <__gdtoa+0x102f>
   1400072f4:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   1400072f8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072fc:	48 89 c1             	mov    rcx,rax
   1400072ff:	e8 49 12 00 00       	call   14000854d <__cmp_D2A>
   140007304:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007307:	eb 07                	jmp    140007310 <__gdtoa+0x1036>
   140007309:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   140007310:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140007314:	48 89 c1             	mov    rcx,rax
   140007317:	e8 c2 0a 00 00       	call   140007dde <__Bfree_D2A>
   14000731c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007320:	75 70                	jne    140007392 <__gdtoa+0x10b8>
   140007322:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007329:	75 67                	jne    140007392 <__gdtoa+0x10b8>
   14000732b:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007332:	8b 00                	mov    eax,DWORD PTR [rax]
   140007334:	83 e0 01             	and    eax,0x1
   140007337:	85 c0                	test   eax,eax
   140007339:	75 57                	jne    140007392 <__gdtoa+0x10b8>
   14000733b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000733f:	75 51                	jne    140007392 <__gdtoa+0x10b8>
   140007341:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007345:	0f 84 01 02 00 00    	je     14000754c <__gdtoa+0x1272>
   14000734b:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000734f:	7f 20                	jg     140007371 <__gdtoa+0x1097>
   140007351:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007355:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007358:	83 f8 01             	cmp    eax,0x1
   14000735b:	7f 0b                	jg     140007368 <__gdtoa+0x108e>
   14000735d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007361:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007364:	85 c0                	test   eax,eax
   140007366:	74 14                	je     14000737c <__gdtoa+0x10a2>
   140007368:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000736f:	eb 0b                	jmp    14000737c <__gdtoa+0x10a2>
   140007371:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   140007375:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   14000737c:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007380:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007384:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007388:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000738b:	88 10                	mov    BYTE PTR [rax],dl
   14000738d:	e9 ef 03 00 00       	jmp    140007781 <__gdtoa+0x14a7>
   140007392:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007396:	78 2b                	js     1400073c3 <__gdtoa+0x10e9>
   140007398:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000739c:	0f 85 96 01 00 00    	jne    140007538 <__gdtoa+0x125e>
   1400073a2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400073a9:	0f 85 89 01 00 00    	jne    140007538 <__gdtoa+0x125e>
   1400073af:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400073b6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400073b8:	83 e0 01             	and    eax,0x1
   1400073bb:	85 c0                	test   eax,eax
   1400073bd:	0f 85 75 01 00 00    	jne    140007538 <__gdtoa+0x125e>
   1400073c3:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400073c7:	0f 84 db 00 00 00    	je     1400074a8 <__gdtoa+0x11ce>
   1400073cd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073d1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400073d4:	83 f8 01             	cmp    eax,0x1
   1400073d7:	7f 0f                	jg     1400073e8 <__gdtoa+0x110e>
   1400073d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073dd:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400073e0:	85 c0                	test   eax,eax
   1400073e2:	0f 84 c0 00 00 00    	je     1400074a8 <__gdtoa+0x11ce>
   1400073e8:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400073ec:	0f 85 83 00 00 00    	jne    140007475 <__gdtoa+0x119b>
   1400073f2:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400073f9:	e9 24 01 00 00       	jmp    140007522 <__gdtoa+0x1248>
   1400073fe:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007402:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007406:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000740a:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000740d:	88 10                	mov    BYTE PTR [rax],dl
   14000740f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007413:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007419:	ba 0a 00 00 00       	mov    edx,0xa
   14000741e:	48 89 c1             	mov    rcx,rax
   140007421:	e8 43 0a 00 00       	call   140007e69 <__multadd_D2A>
   140007426:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000742a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000742e:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007432:	75 08                	jne    14000743c <__gdtoa+0x1162>
   140007434:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007438:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   14000743c:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007440:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007444:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007448:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000744e:	ba 0a 00 00 00       	mov    edx,0xa
   140007453:	48 89 c1             	mov    rcx,rax
   140007456:	e8 0e 0a 00 00       	call   140007e69 <__multadd_D2A>
   14000745b:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000745f:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007463:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007467:	48 89 c1             	mov    rcx,rax
   14000746a:	e8 af ea ff ff       	call   140005f1e <__quorem_D2A>
   14000746f:	83 c0 30             	add    eax,0x30
   140007472:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007475:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007479:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000747d:	48 89 c1             	mov    rcx,rax
   140007480:	e8 c8 10 00 00       	call   14000854d <__cmp_D2A>
   140007485:	85 c0                	test   eax,eax
   140007487:	0f 8f 71 ff ff ff    	jg     1400073fe <__gdtoa+0x1124>
   14000748d:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007490:	8d 50 01             	lea    edx,[rax+0x1]
   140007493:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007496:	83 f8 39             	cmp    eax,0x39
   140007499:	0f 84 b0 00 00 00    	je     14000754f <__gdtoa+0x1275>
   14000749f:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400074a6:	eb 7a                	jmp    140007522 <__gdtoa+0x1248>
   1400074a8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074ac:	7e 53                	jle    140007501 <__gdtoa+0x1227>
   1400074ae:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074b2:	ba 01 00 00 00       	mov    edx,0x1
   1400074b7:	48 89 c1             	mov    rcx,rax
   1400074ba:	e8 01 0f 00 00       	call   1400083c0 <__lshift_D2A>
   1400074bf:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400074c3:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400074c7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074cb:	48 89 c1             	mov    rcx,rax
   1400074ce:	e8 7a 10 00 00       	call   14000854d <__cmp_D2A>
   1400074d3:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400074d6:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074da:	7f 10                	jg     1400074ec <__gdtoa+0x1212>
   1400074dc:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074e0:	75 18                	jne    1400074fa <__gdtoa+0x1220>
   1400074e2:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400074e5:	83 e0 01             	and    eax,0x1
   1400074e8:	85 c0                	test   eax,eax
   1400074ea:	74 0e                	je     1400074fa <__gdtoa+0x1220>
   1400074ec:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400074ef:	8d 50 01             	lea    edx,[rax+0x1]
   1400074f2:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   1400074f5:	83 f8 39             	cmp    eax,0x39
   1400074f8:	74 58                	je     140007552 <__gdtoa+0x1278>
   1400074fa:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007501:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007505:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007508:	83 f8 01             	cmp    eax,0x1
   14000750b:	7f 0b                	jg     140007518 <__gdtoa+0x123e>
   14000750d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007511:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007514:	85 c0                	test   eax,eax
   140007516:	74 09                	je     140007521 <__gdtoa+0x1247>
   140007518:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000751f:	eb 01                	jmp    140007522 <__gdtoa+0x1248>
   140007521:	90                   	nop
   140007522:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007526:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000752a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000752e:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007531:	88 10                	mov    BYTE PTR [rax],dl
   140007533:	e9 49 02 00 00       	jmp    140007781 <__gdtoa+0x14a7>
   140007538:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000753c:	7e 52                	jle    140007590 <__gdtoa+0x12b6>
   14000753e:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007542:	74 4c                	je     140007590 <__gdtoa+0x12b6>
   140007544:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007548:	75 24                	jne    14000756e <__gdtoa+0x1294>
   14000754a:	eb 07                	jmp    140007553 <__gdtoa+0x1279>
   14000754c:	90                   	nop
   14000754d:	eb 04                	jmp    140007553 <__gdtoa+0x1279>
   14000754f:	90                   	nop
   140007550:	eb 01                	jmp    140007553 <__gdtoa+0x1279>
   140007552:	90                   	nop
   140007553:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007557:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000755b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000755f:	c6 00 39             	mov    BYTE PTR [rax],0x39
   140007562:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007569:	e9 9d 01 00 00       	jmp    14000770b <__gdtoa+0x1431>
   14000756e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007575:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007578:	8d 48 01             	lea    ecx,[rax+0x1]
   14000757b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000757f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007583:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007587:	89 ca                	mov    edx,ecx
   140007589:	88 10                	mov    BYTE PTR [rax],dl
   14000758b:	e9 f1 01 00 00       	jmp    140007781 <__gdtoa+0x14a7>
   140007590:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007594:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007598:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000759c:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000759f:	88 10                	mov    BYTE PTR [rax],dl
   1400075a1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400075a4:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   1400075a7:	0f 84 ea 00 00 00    	je     140007697 <__gdtoa+0x13bd>
   1400075ad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075b1:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075b7:	ba 0a 00 00 00       	mov    edx,0xa
   1400075bc:	48 89 c1             	mov    rcx,rax
   1400075bf:	e8 a5 08 00 00       	call   140007e69 <__multadd_D2A>
   1400075c4:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400075c8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400075cc:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400075d0:	75 25                	jne    1400075f7 <__gdtoa+0x131d>
   1400075d2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400075d6:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075dc:	ba 0a 00 00 00       	mov    edx,0xa
   1400075e1:	48 89 c1             	mov    rcx,rax
   1400075e4:	e8 80 08 00 00       	call   140007e69 <__multadd_D2A>
   1400075e9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400075ed:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400075f1:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400075f5:	eb 36                	jmp    14000762d <__gdtoa+0x1353>
   1400075f7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400075fb:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007601:	ba 0a 00 00 00       	mov    edx,0xa
   140007606:	48 89 c1             	mov    rcx,rax
   140007609:	e8 5b 08 00 00       	call   140007e69 <__multadd_D2A>
   14000760e:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007612:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007616:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000761c:	ba 0a 00 00 00       	mov    edx,0xa
   140007621:	48 89 c1             	mov    rcx,rax
   140007624:	e8 40 08 00 00       	call   140007e69 <__multadd_D2A>
   140007629:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000762d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007630:	83 c0 01             	add    eax,0x1
   140007633:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007636:	e9 71 fc ff ff       	jmp    1400072ac <__gdtoa+0xfd2>
   14000763b:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140007642:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007646:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000764a:	48 89 c1             	mov    rcx,rax
   14000764d:	e8 cc e8 ff ff       	call   140005f1e <__quorem_D2A>
   140007652:	83 c0 30             	add    eax,0x30
   140007655:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007658:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000765c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007660:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007664:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007667:	88 10                	mov    BYTE PTR [rax],dl
   140007669:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000766c:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   14000766f:	7e 29                	jle    14000769a <__gdtoa+0x13c0>
   140007671:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007675:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000767b:	ba 0a 00 00 00       	mov    edx,0xa
   140007680:	48 89 c1             	mov    rcx,rax
   140007683:	e8 e1 07 00 00       	call   140007e69 <__multadd_D2A>
   140007688:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000768c:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000768f:	83 c0 01             	add    eax,0x1
   140007692:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007695:	eb ab                	jmp    140007642 <__gdtoa+0x1368>
   140007697:	90                   	nop
   140007698:	eb 01                	jmp    14000769b <__gdtoa+0x13c1>
   14000769a:	90                   	nop
   14000769b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000769f:	74 26                	je     1400076c7 <__gdtoa+0x13ed>
   1400076a1:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400076a5:	0f 84 ae 00 00 00    	je     140007759 <__gdtoa+0x147f>
   1400076ab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076af:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400076b2:	83 f8 01             	cmp    eax,0x1
   1400076b5:	7f 50                	jg     140007707 <__gdtoa+0x142d>
   1400076b7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076bb:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400076be:	85 c0                	test   eax,eax
   1400076c0:	75 45                	jne    140007707 <__gdtoa+0x142d>
   1400076c2:	e9 92 00 00 00       	jmp    140007759 <__gdtoa+0x147f>
   1400076c7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076cb:	ba 01 00 00 00       	mov    edx,0x1
   1400076d0:	48 89 c1             	mov    rcx,rax
   1400076d3:	e8 e8 0c 00 00       	call   1400083c0 <__lshift_D2A>
   1400076d8:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400076dc:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400076e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076e4:	48 89 c1             	mov    rcx,rax
   1400076e7:	e8 61 0e 00 00       	call   14000854d <__cmp_D2A>
   1400076ec:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400076ef:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400076f3:	7f 15                	jg     14000770a <__gdtoa+0x1430>
   1400076f5:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400076f9:	75 61                	jne    14000775c <__gdtoa+0x1482>
   1400076fb:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400076fe:	83 e0 01             	and    eax,0x1
   140007701:	85 c0                	test   eax,eax
   140007703:	74 5a                	je     14000775f <__gdtoa+0x1485>
   140007705:	eb 04                	jmp    14000770b <__gdtoa+0x1431>
   140007707:	90                   	nop
   140007708:	eb 01                	jmp    14000770b <__gdtoa+0x1431>
   14000770a:	90                   	nop
   14000770b:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007712:	eb 1f                	jmp    140007733 <__gdtoa+0x1459>
   140007714:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007718:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000771c:	75 15                	jne    140007733 <__gdtoa+0x1459>
   14000771e:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007722:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007726:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000772a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000772e:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007731:	eb 4e                	jmp    140007781 <__gdtoa+0x14a7>
   140007733:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140007738:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000773c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000773f:	3c 39                	cmp    al,0x39
   140007741:	74 d1                	je     140007714 <__gdtoa+0x143a>
   140007743:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007747:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000774b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000774f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140007752:	83 c2 01             	add    edx,0x1
   140007755:	88 10                	mov    BYTE PTR [rax],dl
   140007757:	eb 28                	jmp    140007781 <__gdtoa+0x14a7>
   140007759:	90                   	nop
   14000775a:	eb 04                	jmp    140007760 <__gdtoa+0x1486>
   14000775c:	90                   	nop
   14000775d:	eb 01                	jmp    140007760 <__gdtoa+0x1486>
   14000775f:	90                   	nop
   140007760:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007764:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007767:	83 f8 01             	cmp    eax,0x1
   14000776a:	7f 0b                	jg     140007777 <__gdtoa+0x149d>
   14000776c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007770:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007773:	85 c0                	test   eax,eax
   140007775:	74 09                	je     140007780 <__gdtoa+0x14a6>
   140007777:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000777e:	eb 01                	jmp    140007781 <__gdtoa+0x14a7>
   140007780:	90                   	nop
   140007781:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007785:	48 89 c1             	mov    rcx,rax
   140007788:	e8 51 06 00 00       	call   140007dde <__Bfree_D2A>
   14000778d:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140007792:	74 31                	je     1400077c5 <__gdtoa+0x14eb>
   140007794:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140007799:	74 16                	je     1400077b1 <__gdtoa+0x14d7>
   14000779b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000779f:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400077a3:	74 0c                	je     1400077b1 <__gdtoa+0x14d7>
   1400077a5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400077a9:	48 89 c1             	mov    rcx,rax
   1400077ac:	e8 2d 06 00 00       	call   140007dde <__Bfree_D2A>
   1400077b1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400077b5:	48 89 c1             	mov    rcx,rax
   1400077b8:	e8 21 06 00 00       	call   140007dde <__Bfree_D2A>
   1400077bd:	eb 0e                	jmp    1400077cd <__gdtoa+0x14f3>
   1400077bf:	90                   	nop
   1400077c0:	eb 0b                	jmp    1400077cd <__gdtoa+0x14f3>
   1400077c2:	90                   	nop
   1400077c3:	eb 08                	jmp    1400077cd <__gdtoa+0x14f3>
   1400077c5:	90                   	nop
   1400077c6:	eb 05                	jmp    1400077cd <__gdtoa+0x14f3>
   1400077c8:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   1400077cd:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077d1:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   1400077d5:	73 0f                	jae    1400077e6 <__gdtoa+0x150c>
   1400077d7:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077db:	48 83 e8 01          	sub    rax,0x1
   1400077df:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400077e2:	3c 30                	cmp    al,0x30
   1400077e4:	74 e2                	je     1400077c8 <__gdtoa+0x14ee>
   1400077e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077ea:	48 89 c1             	mov    rcx,rax
   1400077ed:	e8 ec 05 00 00       	call   140007dde <__Bfree_D2A>
   1400077f2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077f6:	c6 00 00             	mov    BYTE PTR [rax],0x0
   1400077f9:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400077fc:	8d 50 01             	lea    edx,[rax+0x1]
   1400077ff:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140007806:	89 10                	mov    DWORD PTR [rax],edx
   140007808:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   14000780f:	00 
   140007810:	74 0e                	je     140007820 <__gdtoa+0x1546>
   140007812:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140007819:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   14000781d:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007820:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007827:	8b 00                	mov    eax,DWORD PTR [rax]
   140007829:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   14000782c:	89 c2                	mov    edx,eax
   14000782e:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007835:	89 10                	mov    DWORD PTR [rax],edx
   140007837:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000783b:	48 81 c4 00 01 00 00 	add    rsp,0x100
   140007842:	5d                   	pop    rbp
   140007843:	c3                   	ret
   140007844:	90                   	nop
   140007845:	90                   	nop
   140007846:	90                   	nop
   140007847:	90                   	nop
   140007848:	90                   	nop
   140007849:	90                   	nop
   14000784a:	90                   	nop
   14000784b:	90                   	nop
   14000784c:	90                   	nop
   14000784d:	90                   	nop
   14000784e:	90                   	nop
   14000784f:	90                   	nop

0000000140007850 <__lo0bits_D2A>:
   140007850:	55                   	push   rbp
   140007851:	48 89 e5             	mov    rbp,rsp
   140007854:	48 83 ec 10          	sub    rsp,0x10
   140007858:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000785c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007860:	8b 00                	mov    eax,DWORD PTR [rax]
   140007862:	f3 0f bc c0          	tzcnt  eax,eax
   140007866:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007869:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000786d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000786f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007872:	89 c1                	mov    ecx,eax
   140007874:	d3 ea                	shr    edx,cl
   140007876:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000787a:	89 10                	mov    DWORD PTR [rax],edx
   14000787c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000787f:	48 83 c4 10          	add    rsp,0x10
   140007883:	5d                   	pop    rbp
   140007884:	c3                   	ret

0000000140007885 <__rshift_D2A>:
   140007885:	55                   	push   rbp
   140007886:	48 89 e5             	mov    rbp,rsp
   140007889:	48 83 ec 20          	sub    rsp,0x20
   14000788d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007891:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007894:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007898:	48 83 c0 18          	add    rax,0x18
   14000789c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400078a0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400078a4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400078a8:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400078ab:	c1 f8 05             	sar    eax,0x5
   1400078ae:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400078b1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078b5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400078b8:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   1400078bb:	0f 8d e4 00 00 00    	jge    1400079a5 <__rshift_D2A+0x120>
   1400078c1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078c5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400078c8:	48 98                	cdqe
   1400078ca:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400078d1:	00 
   1400078d2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078d6:	48 01 d0             	add    rax,rdx
   1400078d9:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400078dd:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400078e0:	48 98                	cdqe
   1400078e2:	48 c1 e0 02          	shl    rax,0x2
   1400078e6:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   1400078ea:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   1400078ee:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400078f2:	0f 84 a3 00 00 00    	je     14000799b <__rshift_D2A+0x116>
   1400078f8:	b8 20 00 00 00       	mov    eax,0x20
   1400078fd:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   140007900:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007903:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007907:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000790b:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000790f:	8b 10                	mov    edx,DWORD PTR [rax]
   140007911:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007914:	89 c1                	mov    ecx,eax
   140007916:	d3 ea                	shr    edx,cl
   140007918:	89 d0                	mov    eax,edx
   14000791a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000791d:	eb 3c                	jmp    14000795b <__rshift_D2A+0xd6>
   14000791f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007923:	8b 10                	mov    edx,DWORD PTR [rax]
   140007925:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007928:	89 c1                	mov    ecx,eax
   14000792a:	d3 e2                	shl    edx,cl
   14000792c:	89 d1                	mov    ecx,edx
   14000792e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007932:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007936:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000793a:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   14000793d:	89 ca                	mov    edx,ecx
   14000793f:	89 10                	mov    DWORD PTR [rax],edx
   140007941:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007945:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007949:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000794d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000794f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007952:	89 c1                	mov    ecx,eax
   140007954:	d3 ea                	shr    edx,cl
   140007956:	89 d0                	mov    eax,edx
   140007958:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000795b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000795f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007963:	72 ba                	jb     14000791f <__rshift_D2A+0x9a>
   140007965:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007969:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   14000796c:	89 10                	mov    DWORD PTR [rax],edx
   14000796e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007972:	8b 00                	mov    eax,DWORD PTR [rax]
   140007974:	85 c0                	test   eax,eax
   140007976:	74 2d                	je     1400079a5 <__rshift_D2A+0x120>
   140007978:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   14000797d:	eb 26                	jmp    1400079a5 <__rshift_D2A+0x120>
   14000797f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140007983:	48 8d 42 04          	lea    rax,[rdx+0x4]
   140007987:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000798b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000798f:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140007993:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   140007997:	8b 12                	mov    edx,DWORD PTR [rdx]
   140007999:	89 10                	mov    DWORD PTR [rax],edx
   14000799b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000799f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   1400079a3:	72 da                	jb     14000797f <__rshift_D2A+0xfa>
   1400079a5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079a9:	48 83 c0 18          	add    rax,0x18
   1400079ad:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400079b1:	48 29 c2             	sub    rdx,rax
   1400079b4:	48 89 d0             	mov    rax,rdx
   1400079b7:	48 c1 f8 02          	sar    rax,0x2
   1400079bb:	89 c2                	mov    edx,eax
   1400079bd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079c1:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400079c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079c8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400079cb:	85 c0                	test   eax,eax
   1400079cd:	75 0b                	jne    1400079da <__rshift_D2A+0x155>
   1400079cf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079d3:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   1400079da:	90                   	nop
   1400079db:	48 83 c4 20          	add    rsp,0x20
   1400079df:	5d                   	pop    rbp
   1400079e0:	c3                   	ret

00000001400079e1 <__trailz_D2A>:
   1400079e1:	55                   	push   rbp
   1400079e2:	48 89 e5             	mov    rbp,rsp
   1400079e5:	48 83 ec 40          	sub    rsp,0x40
   1400079e9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400079ed:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400079f4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079f8:	48 83 c0 18          	add    rax,0x18
   1400079fc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a00:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a04:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a07:	48 98                	cdqe
   140007a09:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007a10:	00 
   140007a11:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a15:	48 01 d0             	add    rax,rdx
   140007a18:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007a1c:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a23:	eb 09                	jmp    140007a2e <__trailz_D2A+0x4d>
   140007a25:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   140007a29:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   140007a2e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a32:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a36:	73 0a                	jae    140007a42 <__trailz_D2A+0x61>
   140007a38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a3c:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a3e:	85 c0                	test   eax,eax
   140007a40:	74 e3                	je     140007a25 <__trailz_D2A+0x44>
   140007a42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a46:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a4a:	73 18                	jae    140007a64 <__trailz_D2A+0x83>
   140007a4c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a50:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a52:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007a55:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007a59:	48 89 c1             	mov    rcx,rax
   140007a5c:	e8 ef fd ff ff       	call   140007850 <__lo0bits_D2A>
   140007a61:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007a64:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007a67:	48 83 c4 40          	add    rsp,0x40
   140007a6b:	5d                   	pop    rbp
   140007a6c:	c3                   	ret
   140007a6d:	90                   	nop
   140007a6e:	90                   	nop
   140007a6f:	90                   	nop

0000000140007a70 <dtoa_lock_cleanup>:
   140007a70:	55                   	push   rbp
   140007a71:	48 89 e5             	mov    rbp,rsp
   140007a74:	48 83 ec 40          	sub    rsp,0x40
   140007a78:	48 8d 05 71 77 00 00 	lea    rax,[rip+0x7771]        # 14000f1f0 <dtoa_CS_init>
   140007a7f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007a83:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007a8a:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007a8d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a91:	87 10                	xchg   DWORD PTR [rax],edx
   140007a93:	89 d0                	mov    eax,edx
   140007a95:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007a98:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007a9c:	75 3d                	jne    140007adb <dtoa_lock_cleanup+0x6b>
   140007a9e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007aa5:	eb 2e                	jmp    140007ad5 <dtoa_lock_cleanup+0x65>
   140007aa7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007aaa:	48 63 d0             	movsxd rdx,eax
   140007aad:	48 89 d0             	mov    rax,rdx
   140007ab0:	48 c1 e0 02          	shl    rax,0x2
   140007ab4:	48 01 d0             	add    rax,rdx
   140007ab7:	48 c1 e0 03          	shl    rax,0x3
   140007abb:	48 8d 15 de 76 00 00 	lea    rdx,[rip+0x76de]        # 14000f1a0 <dtoa_CritSec>
   140007ac2:	48 01 d0             	add    rax,rdx
   140007ac5:	48 89 c1             	mov    rcx,rax
   140007ac8:	48 8b 05 21 87 00 00 	mov    rax,QWORD PTR [rip+0x8721]        # 1400101f0 <__IAT_start__>
   140007acf:	ff d0                	call   rax
   140007ad1:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007ad5:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007ad9:	7e cc                	jle    140007aa7 <dtoa_lock_cleanup+0x37>
   140007adb:	90                   	nop
   140007adc:	48 83 c4 40          	add    rsp,0x40
   140007ae0:	5d                   	pop    rbp
   140007ae1:	c3                   	ret

0000000140007ae2 <dtoa_lock>:
   140007ae2:	55                   	push   rbp
   140007ae3:	48 89 e5             	mov    rbp,rsp
   140007ae6:	48 83 ec 40          	sub    rsp,0x40
   140007aea:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007aed:	8b 05 fd 76 00 00    	mov    eax,DWORD PTR [rip+0x76fd]        # 14000f1f0 <dtoa_CS_init>
   140007af3:	83 f8 02             	cmp    eax,0x2
   140007af6:	75 2c                	jne    140007b24 <dtoa_lock+0x42>
   140007af8:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007afb:	48 89 d0             	mov    rax,rdx
   140007afe:	48 c1 e0 02          	shl    rax,0x2
   140007b02:	48 01 d0             	add    rax,rdx
   140007b05:	48 c1 e0 03          	shl    rax,0x3
   140007b09:	48 8d 15 90 76 00 00 	lea    rdx,[rip+0x7690]        # 14000f1a0 <dtoa_CritSec>
   140007b10:	48 01 d0             	add    rax,rdx
   140007b13:	48 89 c1             	mov    rcx,rax
   140007b16:	48 8b 05 db 86 00 00 	mov    rax,QWORD PTR [rip+0x86db]        # 1400101f8 <__imp_EnterCriticalSection>
   140007b1d:	ff d0                	call   rax
   140007b1f:	e9 ea 00 00 00       	jmp    140007c0e <dtoa_lock+0x12c>
   140007b24:	8b 05 c6 76 00 00    	mov    eax,DWORD PTR [rip+0x76c6]        # 14000f1f0 <dtoa_CS_init>
   140007b2a:	85 c0                	test   eax,eax
   140007b2c:	0f 85 9e 00 00 00    	jne    140007bd0 <dtoa_lock+0xee>
   140007b32:	48 8d 05 b7 76 00 00 	lea    rax,[rip+0x76b7]        # 14000f1f0 <dtoa_CS_init>
   140007b39:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007b3d:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007b44:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007b47:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007b4b:	87 10                	xchg   DWORD PTR [rax],edx
   140007b4d:	89 d0                	mov    eax,edx
   140007b4f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007b52:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007b56:	75 58                	jne    140007bb0 <dtoa_lock+0xce>
   140007b58:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007b5f:	eb 2e                	jmp    140007b8f <dtoa_lock+0xad>
   140007b61:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007b64:	48 63 d0             	movsxd rdx,eax
   140007b67:	48 89 d0             	mov    rax,rdx
   140007b6a:	48 c1 e0 02          	shl    rax,0x2
   140007b6e:	48 01 d0             	add    rax,rdx
   140007b71:	48 c1 e0 03          	shl    rax,0x3
   140007b75:	48 8d 15 24 76 00 00 	lea    rdx,[rip+0x7624]        # 14000f1a0 <dtoa_CritSec>
   140007b7c:	48 01 d0             	add    rax,rdx
   140007b7f:	48 89 c1             	mov    rcx,rax
   140007b82:	48 8b 05 9f 86 00 00 	mov    rax,QWORD PTR [rip+0x869f]        # 140010228 <__imp_InitializeCriticalSection>
   140007b89:	ff d0                	call   rax
   140007b8b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b8f:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b93:	7e cc                	jle    140007b61 <dtoa_lock+0x7f>
   140007b95:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007a70 <dtoa_lock_cleanup>
   140007b9c:	48 89 c1             	mov    rcx,rax
   140007b9f:	e8 8b 9a ff ff       	call   14000162f <atexit>
   140007ba4:	c7 05 42 76 00 00 02 	mov    DWORD PTR [rip+0x7642],0x2        # 14000f1f0 <dtoa_CS_init>
   140007bab:	00 00 00 
   140007bae:	eb 20                	jmp    140007bd0 <dtoa_lock+0xee>
   140007bb0:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007bb4:	75 1a                	jne    140007bd0 <dtoa_lock+0xee>
   140007bb6:	c7 05 30 76 00 00 02 	mov    DWORD PTR [rip+0x7630],0x2        # 14000f1f0 <dtoa_CS_init>
   140007bbd:	00 00 00 
   140007bc0:	eb 0e                	jmp    140007bd0 <dtoa_lock+0xee>
   140007bc2:	b9 01 00 00 00       	mov    ecx,0x1
   140007bc7:	48 8b 05 82 86 00 00 	mov    rax,QWORD PTR [rip+0x8682]        # 140010250 <__imp_Sleep>
   140007bce:	ff d0                	call   rax
   140007bd0:	8b 05 1a 76 00 00    	mov    eax,DWORD PTR [rip+0x761a]        # 14000f1f0 <dtoa_CS_init>
   140007bd6:	83 f8 01             	cmp    eax,0x1
   140007bd9:	74 e7                	je     140007bc2 <dtoa_lock+0xe0>
   140007bdb:	8b 05 0f 76 00 00    	mov    eax,DWORD PTR [rip+0x760f]        # 14000f1f0 <dtoa_CS_init>
   140007be1:	83 f8 02             	cmp    eax,0x2
   140007be4:	75 28                	jne    140007c0e <dtoa_lock+0x12c>
   140007be6:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007be9:	48 89 d0             	mov    rax,rdx
   140007bec:	48 c1 e0 02          	shl    rax,0x2
   140007bf0:	48 01 d0             	add    rax,rdx
   140007bf3:	48 c1 e0 03          	shl    rax,0x3
   140007bf7:	48 8d 15 a2 75 00 00 	lea    rdx,[rip+0x75a2]        # 14000f1a0 <dtoa_CritSec>
   140007bfe:	48 01 d0             	add    rax,rdx
   140007c01:	48 89 c1             	mov    rcx,rax
   140007c04:	48 8b 05 ed 85 00 00 	mov    rax,QWORD PTR [rip+0x85ed]        # 1400101f8 <__imp_EnterCriticalSection>
   140007c0b:	ff d0                	call   rax
   140007c0d:	90                   	nop
   140007c0e:	48 83 c4 40          	add    rsp,0x40
   140007c12:	5d                   	pop    rbp
   140007c13:	c3                   	ret

0000000140007c14 <dtoa_unlock>:
   140007c14:	55                   	push   rbp
   140007c15:	48 89 e5             	mov    rbp,rsp
   140007c18:	48 83 ec 20          	sub    rsp,0x20
   140007c1c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c1f:	8b 05 cb 75 00 00    	mov    eax,DWORD PTR [rip+0x75cb]        # 14000f1f0 <dtoa_CS_init>
   140007c25:	83 f8 02             	cmp    eax,0x2
   140007c28:	75 27                	jne    140007c51 <dtoa_unlock+0x3d>
   140007c2a:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c2d:	48 89 d0             	mov    rax,rdx
   140007c30:	48 c1 e0 02          	shl    rax,0x2
   140007c34:	48 01 d0             	add    rax,rdx
   140007c37:	48 c1 e0 03          	shl    rax,0x3
   140007c3b:	48 8d 15 5e 75 00 00 	lea    rdx,[rip+0x755e]        # 14000f1a0 <dtoa_CritSec>
   140007c42:	48 01 d0             	add    rax,rdx
   140007c45:	48 89 c1             	mov    rcx,rax
   140007c48:	48 8b 05 e1 85 00 00 	mov    rax,QWORD PTR [rip+0x85e1]        # 140010230 <__imp_LeaveCriticalSection>
   140007c4f:	ff d0                	call   rax
   140007c51:	90                   	nop
   140007c52:	48 83 c4 20          	add    rsp,0x20
   140007c56:	5d                   	pop    rbp
   140007c57:	c3                   	ret

0000000140007c58 <__lo0bits_D2A>:
   140007c58:	55                   	push   rbp
   140007c59:	48 89 e5             	mov    rbp,rsp
   140007c5c:	48 83 ec 10          	sub    rsp,0x10
   140007c60:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007c64:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c68:	8b 00                	mov    eax,DWORD PTR [rax]
   140007c6a:	f3 0f bc c0          	tzcnt  eax,eax
   140007c6e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007c71:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c75:	8b 10                	mov    edx,DWORD PTR [rax]
   140007c77:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c7a:	89 c1                	mov    ecx,eax
   140007c7c:	d3 ea                	shr    edx,cl
   140007c7e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c82:	89 10                	mov    DWORD PTR [rax],edx
   140007c84:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c87:	48 83 c4 10          	add    rsp,0x10
   140007c8b:	5d                   	pop    rbp
   140007c8c:	c3                   	ret

0000000140007c8d <__hi0bits_D2A>:
   140007c8d:	55                   	push   rbp
   140007c8e:	48 89 e5             	mov    rbp,rsp
   140007c91:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c94:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007c98:	83 f0 1f             	xor    eax,0x1f
   140007c9b:	5d                   	pop    rbp
   140007c9c:	c3                   	ret

0000000140007c9d <__Balloc_D2A>:
   140007c9d:	55                   	push   rbp
   140007c9e:	48 89 e5             	mov    rbp,rsp
   140007ca1:	48 83 ec 30          	sub    rsp,0x30
   140007ca5:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007ca8:	b9 00 00 00 00       	mov    ecx,0x0
   140007cad:	e8 30 fe ff ff       	call   140007ae2 <dtoa_lock>
   140007cb2:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007cb6:	7f 48                	jg     140007d00 <__Balloc_D2A+0x63>
   140007cb8:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007cbb:	48 98                	cdqe
   140007cbd:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007cc4:	00 
   140007cc5:	48 8d 05 34 75 00 00 	lea    rax,[rip+0x7534]        # 14000f200 <freelist>
   140007ccc:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007cd0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007cd4:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007cd9:	74 25                	je     140007d00 <__Balloc_D2A+0x63>
   140007cdb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007cdf:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007ce2:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007ce5:	48 63 d2             	movsxd rdx,edx
   140007ce8:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007cef:	00 
   140007cf0:	48 8d 15 09 75 00 00 	lea    rdx,[rip+0x7509]        # 14000f200 <freelist>
   140007cf7:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007cfb:	e9 b1 00 00 00       	jmp    140007db1 <__Balloc_D2A+0x114>
   140007d00:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d03:	ba 01 00 00 00       	mov    edx,0x1
   140007d08:	89 c1                	mov    ecx,eax
   140007d0a:	d3 e2                	shl    edx,cl
   140007d0c:	89 d0                	mov    eax,edx
   140007d0e:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007d11:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007d14:	83 e8 01             	sub    eax,0x1
   140007d17:	48 98                	cdqe
   140007d19:	48 c1 e0 02          	shl    rax,0x2
   140007d1d:	48 83 c0 27          	add    rax,0x27
   140007d21:	48 c1 e8 03          	shr    rax,0x3
   140007d25:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007d28:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d2c:	7f 4e                	jg     140007d7c <__Balloc_D2A+0xdf>
   140007d2e:	48 8b 15 5b 23 00 00 	mov    rdx,QWORD PTR [rip+0x235b]        # 14000a090 <pmem_next>
   140007d35:	48 8d 05 24 75 00 00 	lea    rax,[rip+0x7524]        # 14000f260 <private_mem>
   140007d3c:	48 29 c2             	sub    rdx,rax
   140007d3f:	48 89 d0             	mov    rax,rdx
   140007d42:	48 c1 f8 03          	sar    rax,0x3
   140007d46:	48 89 c2             	mov    rdx,rax
   140007d49:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d4c:	48 01 d0             	add    rax,rdx
   140007d4f:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007d55:	77 25                	ja     140007d7c <__Balloc_D2A+0xdf>
   140007d57:	48 8b 05 32 23 00 00 	mov    rax,QWORD PTR [rip+0x2332]        # 14000a090 <pmem_next>
   140007d5e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d62:	48 8b 05 27 23 00 00 	mov    rax,QWORD PTR [rip+0x2327]        # 14000a090 <pmem_next>
   140007d69:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007d6c:	48 c1 e2 03          	shl    rdx,0x3
   140007d70:	48 01 d0             	add    rax,rdx
   140007d73:	48 89 05 16 23 00 00 	mov    QWORD PTR [rip+0x2316],rax        # 14000a090 <pmem_next>
   140007d7a:	eb 21                	jmp    140007d9d <__Balloc_D2A+0x100>
   140007d7c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d7f:	48 c1 e0 03          	shl    rax,0x3
   140007d83:	48 89 c1             	mov    rcx,rax
   140007d86:	e8 e5 18 00 00       	call   140009670 <malloc>
   140007d8b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d8f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d94:	75 07                	jne    140007d9d <__Balloc_D2A+0x100>
   140007d96:	b8 00 00 00 00       	mov    eax,0x0
   140007d9b:	eb 3b                	jmp    140007dd8 <__Balloc_D2A+0x13b>
   140007d9d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007da1:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007da4:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007da7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007dab:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007dae:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007db1:	b9 00 00 00 00       	mov    ecx,0x0
   140007db6:	e8 59 fe ff ff       	call   140007c14 <dtoa_unlock>
   140007dbb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007dbf:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007dc6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007dca:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007dcd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007dd1:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007dd4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007dd8:	48 83 c4 30          	add    rsp,0x30
   140007ddc:	5d                   	pop    rbp
   140007ddd:	c3                   	ret

0000000140007dde <__Bfree_D2A>:
   140007dde:	55                   	push   rbp
   140007ddf:	48 89 e5             	mov    rbp,rsp
   140007de2:	48 83 ec 20          	sub    rsp,0x20
   140007de6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007dea:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007def:	74 71                	je     140007e62 <__Bfree_D2A+0x84>
   140007df1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007df5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007df8:	83 f8 09             	cmp    eax,0x9
   140007dfb:	7e 0e                	jle    140007e0b <__Bfree_D2A+0x2d>
   140007dfd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e01:	48 89 c1             	mov    rcx,rax
   140007e04:	e8 57 18 00 00       	call   140009660 <free>
   140007e09:	eb 57                	jmp    140007e62 <__Bfree_D2A+0x84>
   140007e0b:	b9 00 00 00 00       	mov    ecx,0x0
   140007e10:	e8 cd fc ff ff       	call   140007ae2 <dtoa_lock>
   140007e15:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e19:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e1c:	48 98                	cdqe
   140007e1e:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007e25:	00 
   140007e26:	48 8d 05 d3 73 00 00 	lea    rax,[rip+0x73d3]        # 14000f200 <freelist>
   140007e2d:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007e31:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e35:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007e38:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e3c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e3f:	48 98                	cdqe
   140007e41:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007e48:	00 
   140007e49:	48 8d 15 b0 73 00 00 	lea    rdx,[rip+0x73b0]        # 14000f200 <freelist>
   140007e50:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e54:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007e58:	b9 00 00 00 00       	mov    ecx,0x0
   140007e5d:	e8 b2 fd ff ff       	call   140007c14 <dtoa_unlock>
   140007e62:	90                   	nop
   140007e63:	48 83 c4 20          	add    rsp,0x20
   140007e67:	5d                   	pop    rbp
   140007e68:	c3                   	ret

0000000140007e69 <__multadd_D2A>:
   140007e69:	55                   	push   rbp
   140007e6a:	48 89 e5             	mov    rbp,rsp
   140007e6d:	48 83 ec 50          	sub    rsp,0x50
   140007e71:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e75:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007e78:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007e7c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e80:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007e83:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007e86:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e8a:	48 83 c0 18          	add    rax,0x18
   140007e8e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007e92:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007e99:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007e9c:	48 98                	cdqe
   140007e9e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007ea2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007ea6:	8b 00                	mov    eax,DWORD PTR [rax]
   140007ea8:	89 c2                	mov    edx,eax
   140007eaa:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007ead:	48 98                	cdqe
   140007eaf:	48 0f af d0          	imul   rdx,rax
   140007eb3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007eb7:	48 01 d0             	add    rax,rdx
   140007eba:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007ebe:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007ec2:	48 c1 e8 20          	shr    rax,0x20
   140007ec6:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007eca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007ece:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007ed2:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007ed6:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007eda:	89 10                	mov    DWORD PTR [rax],edx
   140007edc:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007ee0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007ee3:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007ee6:	7c ba                	jl     140007ea2 <__multadd_D2A+0x39>
   140007ee8:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007eed:	0f 84 9a 00 00 00    	je     140007f8d <__multadd_D2A+0x124>
   140007ef3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ef7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007efa:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007efd:	7c 67                	jl     140007f66 <__multadd_D2A+0xfd>
   140007eff:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f03:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007f06:	83 c0 01             	add    eax,0x1
   140007f09:	89 c1                	mov    ecx,eax
   140007f0b:	e8 8d fd ff ff       	call   140007c9d <__Balloc_D2A>
   140007f10:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007f14:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007f19:	75 07                	jne    140007f22 <__multadd_D2A+0xb9>
   140007f1b:	b8 00 00 00 00       	mov    eax,0x0
   140007f20:	eb 6f                	jmp    140007f91 <__multadd_D2A+0x128>
   140007f22:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f26:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f29:	48 98                	cdqe
   140007f2b:	48 83 c0 02          	add    rax,0x2
   140007f2f:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007f36:	00 
   140007f37:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f3b:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007f3f:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007f43:	48 83 c0 10          	add    rax,0x10
   140007f47:	49 89 c8             	mov    r8,rcx
   140007f4a:	48 89 c1             	mov    rcx,rax
   140007f4d:	e8 26 17 00 00       	call   140009678 <memcpy>
   140007f52:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f56:	48 89 c1             	mov    rcx,rax
   140007f59:	e8 80 fe ff ff       	call   140007dde <__Bfree_D2A>
   140007f5e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007f62:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007f66:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007f69:	8d 50 01             	lea    edx,[rax+0x1]
   140007f6c:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007f6f:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140007f73:	89 d1                	mov    ecx,edx
   140007f75:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007f79:	48 98                	cdqe
   140007f7b:	48 83 c0 04          	add    rax,0x4
   140007f7f:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140007f83:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f87:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140007f8a:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007f8d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f91:	48 83 c4 50          	add    rsp,0x50
   140007f95:	5d                   	pop    rbp
   140007f96:	c3                   	ret

0000000140007f97 <__i2b_D2A>:
   140007f97:	55                   	push   rbp
   140007f98:	48 89 e5             	mov    rbp,rsp
   140007f9b:	48 83 ec 30          	sub    rsp,0x30
   140007f9f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007fa2:	b9 01 00 00 00       	mov    ecx,0x1
   140007fa7:	e8 f1 fc ff ff       	call   140007c9d <__Balloc_D2A>
   140007fac:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007fb0:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007fb5:	75 07                	jne    140007fbe <__i2b_D2A+0x27>
   140007fb7:	b8 00 00 00 00       	mov    eax,0x0
   140007fbc:	eb 19                	jmp    140007fd7 <__i2b_D2A+0x40>
   140007fbe:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007fc1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007fc5:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140007fc8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007fcc:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140007fd3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007fd7:	48 83 c4 30          	add    rsp,0x30
   140007fdb:	5d                   	pop    rbp
   140007fdc:	c3                   	ret

0000000140007fdd <__mult_D2A>:
   140007fdd:	55                   	push   rbp
   140007fde:	48 89 e5             	mov    rbp,rsp
   140007fe1:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140007fe8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007fec:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140007ff0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ff4:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007ff7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007ffb:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ffe:	39 c2                	cmp    edx,eax
   140008000:	7d 18                	jge    14000801a <__mult_D2A+0x3d>
   140008002:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008006:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000800a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000800e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008012:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008016:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000801a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000801e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008021:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008024:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008028:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000802b:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   14000802e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008032:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008035:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   140008038:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   14000803b:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   14000803e:	01 d0                	add    eax,edx
   140008040:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008043:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008047:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000804a:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   14000804d:	7e 04                	jle    140008053 <__mult_D2A+0x76>
   14000804f:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008053:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008056:	89 c1                	mov    ecx,eax
   140008058:	e8 40 fc ff ff       	call   140007c9d <__Balloc_D2A>
   14000805d:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008061:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   140008066:	75 0a                	jne    140008072 <__mult_D2A+0x95>
   140008068:	b8 00 00 00 00       	mov    eax,0x0
   14000806d:	e9 88 01 00 00       	jmp    1400081fa <__mult_D2A+0x21d>
   140008072:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008076:	48 83 c0 18          	add    rax,0x18
   14000807a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000807e:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008081:	48 98                	cdqe
   140008083:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000808a:	00 
   14000808b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000808f:	48 01 d0             	add    rax,rdx
   140008092:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140008096:	eb 0f                	jmp    1400080a7 <__mult_D2A+0xca>
   140008098:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000809c:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400080a2:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   1400080a7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080ab:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   1400080af:	72 e7                	jb     140008098 <__mult_D2A+0xbb>
   1400080b1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080b5:	48 83 c0 18          	add    rax,0x18
   1400080b9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400080bd:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   1400080c0:	48 98                	cdqe
   1400080c2:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400080c9:	00 
   1400080ca:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400080ce:	48 01 d0             	add    rax,rdx
   1400080d1:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400080d5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080d9:	48 83 c0 18          	add    rax,0x18
   1400080dd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400080e1:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   1400080e4:	48 98                	cdqe
   1400080e6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400080ed:	00 
   1400080ee:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400080f2:	48 01 d0             	add    rax,rdx
   1400080f5:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   1400080f9:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400080fd:	48 83 c0 18          	add    rax,0x18
   140008101:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008105:	e9 95 00 00 00       	jmp    14000819f <__mult_D2A+0x1c2>
   14000810a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000810e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008112:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008116:	8b 00                	mov    eax,DWORD PTR [rax]
   140008118:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   14000811b:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   14000811f:	74 79                	je     14000819a <__mult_D2A+0x1bd>
   140008121:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140008125:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008129:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000812d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008131:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140008138:	00 
   140008139:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000813d:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008141:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008145:	8b 00                	mov    eax,DWORD PTR [rax]
   140008147:	89 c2                	mov    edx,eax
   140008149:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   14000814c:	48 0f af d0          	imul   rdx,rax
   140008150:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008154:	8b 00                	mov    eax,DWORD PTR [rax]
   140008156:	89 c0                	mov    eax,eax
   140008158:	48 01 c2             	add    rdx,rax
   14000815b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000815f:	48 01 d0             	add    rax,rdx
   140008162:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140008166:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   14000816a:	48 c1 e8 20          	shr    rax,0x20
   14000816e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008172:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008176:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000817a:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000817e:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140008182:	89 10                	mov    DWORD PTR [rax],edx
   140008184:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008188:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   14000818c:	72 ab                	jb     140008139 <__mult_D2A+0x15c>
   14000818e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008192:	89 c2                	mov    edx,eax
   140008194:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008198:	89 10                	mov    DWORD PTR [rax],edx
   14000819a:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   14000819f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400081a3:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   1400081a7:	0f 82 5d ff ff ff    	jb     14000810a <__mult_D2A+0x12d>
   1400081ad:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081b1:	48 83 c0 18          	add    rax,0x18
   1400081b5:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400081b9:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400081bc:	48 98                	cdqe
   1400081be:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400081c5:	00 
   1400081c6:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400081ca:	48 01 d0             	add    rax,rdx
   1400081cd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400081d1:	eb 04                	jmp    1400081d7 <__mult_D2A+0x1fa>
   1400081d3:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400081d7:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400081db:	7e 0f                	jle    1400081ec <__mult_D2A+0x20f>
   1400081dd:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   1400081e2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081e6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081e8:	85 c0                	test   eax,eax
   1400081ea:	74 e7                	je     1400081d3 <__mult_D2A+0x1f6>
   1400081ec:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081f0:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400081f3:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400081f6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081fa:	48 81 c4 90 00 00 00 	add    rsp,0x90
   140008201:	5d                   	pop    rbp
   140008202:	c3                   	ret

0000000140008203 <__pow5mult_D2A>:
   140008203:	55                   	push   rbp
   140008204:	48 89 e5             	mov    rbp,rsp
   140008207:	48 83 ec 40          	sub    rsp,0x40
   14000820b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000820f:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140008212:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008215:	83 e0 03             	and    eax,0x3
   140008218:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000821b:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000821f:	74 41                	je     140008262 <__pow5mult_D2A+0x5f>
   140008221:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008224:	83 e8 01             	sub    eax,0x1
   140008227:	48 98                	cdqe
   140008229:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008230:	00 
   140008231:	48 8d 05 60 1e 00 00 	lea    rax,[rip+0x1e60]        # 14000a098 <p05.0>
   140008238:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   14000823b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000823f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140008245:	48 89 c1             	mov    rcx,rax
   140008248:	e8 1c fc ff ff       	call   140007e69 <__multadd_D2A>
   14000824d:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008251:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140008256:	75 0a                	jne    140008262 <__pow5mult_D2A+0x5f>
   140008258:	b8 00 00 00 00       	mov    eax,0x0
   14000825d:	e9 58 01 00 00       	jmp    1400083ba <__pow5mult_D2A+0x1b7>
   140008262:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   140008266:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000826a:	75 09                	jne    140008275 <__pow5mult_D2A+0x72>
   14000826c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008270:	e9 45 01 00 00       	jmp    1400083ba <__pow5mult_D2A+0x1b7>
   140008275:	48 8b 05 e4 78 00 00 	mov    rax,QWORD PTR [rip+0x78e4]        # 14000fb60 <p5s>
   14000827c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008280:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008285:	75 5e                	jne    1400082e5 <__pow5mult_D2A+0xe2>
   140008287:	b9 01 00 00 00       	mov    ecx,0x1
   14000828c:	e8 51 f8 ff ff       	call   140007ae2 <dtoa_lock>
   140008291:	48 8b 05 c8 78 00 00 	mov    rax,QWORD PTR [rip+0x78c8]        # 14000fb60 <p5s>
   140008298:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000829c:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400082a1:	75 38                	jne    1400082db <__pow5mult_D2A+0xd8>
   1400082a3:	b9 71 02 00 00       	mov    ecx,0x271
   1400082a8:	e8 ea fc ff ff       	call   140007f97 <__i2b_D2A>
   1400082ad:	48 89 05 ac 78 00 00 	mov    QWORD PTR [rip+0x78ac],rax        # 14000fb60 <p5s>
   1400082b4:	48 8b 05 a5 78 00 00 	mov    rax,QWORD PTR [rip+0x78a5]        # 14000fb60 <p5s>
   1400082bb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082bf:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400082c4:	75 0a                	jne    1400082d0 <__pow5mult_D2A+0xcd>
   1400082c6:	b8 00 00 00 00       	mov    eax,0x0
   1400082cb:	e9 ea 00 00 00       	jmp    1400083ba <__pow5mult_D2A+0x1b7>
   1400082d0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400082d4:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   1400082db:	b9 01 00 00 00       	mov    ecx,0x1
   1400082e0:	e8 2f f9 ff ff       	call   140007c14 <dtoa_unlock>
   1400082e5:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400082e8:	83 e0 01             	and    eax,0x1
   1400082eb:	85 c0                	test   eax,eax
   1400082ed:	74 39                	je     140008328 <__pow5mult_D2A+0x125>
   1400082ef:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400082f3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082f7:	48 89 c1             	mov    rcx,rax
   1400082fa:	e8 de fc ff ff       	call   140007fdd <__mult_D2A>
   1400082ff:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008303:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   140008308:	75 0a                	jne    140008314 <__pow5mult_D2A+0x111>
   14000830a:	b8 00 00 00 00       	mov    eax,0x0
   14000830f:	e9 a6 00 00 00       	jmp    1400083ba <__pow5mult_D2A+0x1b7>
   140008314:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008318:	48 89 c1             	mov    rcx,rax
   14000831b:	e8 be fa ff ff       	call   140007dde <__Bfree_D2A>
   140008320:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008324:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008328:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   14000832b:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000832f:	0f 84 80 00 00 00    	je     1400083b5 <__pow5mult_D2A+0x1b2>
   140008335:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008339:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000833c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008340:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008345:	75 61                	jne    1400083a8 <__pow5mult_D2A+0x1a5>
   140008347:	b9 01 00 00 00       	mov    ecx,0x1
   14000834c:	e8 91 f7 ff ff       	call   140007ae2 <dtoa_lock>
   140008351:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008355:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008358:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000835c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008361:	75 3b                	jne    14000839e <__pow5mult_D2A+0x19b>
   140008363:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008367:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000836b:	48 89 c1             	mov    rcx,rax
   14000836e:	e8 6a fc ff ff       	call   140007fdd <__mult_D2A>
   140008373:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008377:	48 89 02             	mov    QWORD PTR [rdx],rax
   14000837a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000837e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008381:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008385:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000838a:	75 07                	jne    140008393 <__pow5mult_D2A+0x190>
   14000838c:	b8 00 00 00 00       	mov    eax,0x0
   140008391:	eb 27                	jmp    1400083ba <__pow5mult_D2A+0x1b7>
   140008393:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008397:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000839e:	b9 01 00 00 00       	mov    ecx,0x1
   1400083a3:	e8 6c f8 ff ff       	call   140007c14 <dtoa_unlock>
   1400083a8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400083ac:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400083b0:	e9 30 ff ff ff       	jmp    1400082e5 <__pow5mult_D2A+0xe2>
   1400083b5:	90                   	nop
   1400083b6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083ba:	48 83 c4 40          	add    rsp,0x40
   1400083be:	5d                   	pop    rbp
   1400083bf:	c3                   	ret

00000001400083c0 <__lshift_D2A>:
   1400083c0:	55                   	push   rbp
   1400083c1:	48 89 e5             	mov    rbp,rsp
   1400083c4:	48 83 ec 60          	sub    rsp,0x60
   1400083c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400083cc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400083cf:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400083d2:	c1 f8 05             	sar    eax,0x5
   1400083d5:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   1400083d8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083dc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400083df:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400083e2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083e6:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   1400083e9:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   1400083ec:	01 d0                	add    eax,edx
   1400083ee:	83 c0 01             	add    eax,0x1
   1400083f1:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400083f4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083f8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400083fb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400083fe:	eb 07                	jmp    140008407 <__lshift_D2A+0x47>
   140008400:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140008404:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140008407:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000840a:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   14000840d:	7f f1                	jg     140008400 <__lshift_D2A+0x40>
   14000840f:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008412:	89 c1                	mov    ecx,eax
   140008414:	e8 84 f8 ff ff       	call   140007c9d <__Balloc_D2A>
   140008419:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000841d:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008422:	75 0a                	jne    14000842e <__lshift_D2A+0x6e>
   140008424:	b8 00 00 00 00       	mov    eax,0x0
   140008429:	e9 19 01 00 00       	jmp    140008547 <__lshift_D2A+0x187>
   14000842e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008432:	48 83 c0 18          	add    rax,0x18
   140008436:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000843a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008441:	eb 16                	jmp    140008459 <__lshift_D2A+0x99>
   140008443:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008447:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000844b:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000844f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008455:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008459:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000845c:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   14000845f:	7c e2                	jl     140008443 <__lshift_D2A+0x83>
   140008461:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008465:	48 83 c0 18          	add    rax,0x18
   140008469:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000846d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008471:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008474:	48 98                	cdqe
   140008476:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000847d:	00 
   14000847e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008482:	48 01 d0             	add    rax,rdx
   140008485:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008489:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000848d:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140008491:	74 71                	je     140008504 <__lshift_D2A+0x144>
   140008493:	b8 20 00 00 00       	mov    eax,0x20
   140008498:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000849b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000849e:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   1400084a5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084a9:	8b 10                	mov    edx,DWORD PTR [rax]
   1400084ab:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400084ae:	89 c1                	mov    ecx,eax
   1400084b0:	d3 e2                	shl    edx,cl
   1400084b2:	89 d1                	mov    ecx,edx
   1400084b4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084b8:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400084bc:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400084c0:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   1400084c3:	89 ca                	mov    edx,ecx
   1400084c5:	89 10                	mov    DWORD PTR [rax],edx
   1400084c7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084cb:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400084cf:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400084d3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400084d5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400084d8:	89 c1                	mov    ecx,eax
   1400084da:	d3 ea                	shr    edx,cl
   1400084dc:	89 d0                	mov    eax,edx
   1400084de:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400084e1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084e5:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400084e9:	72 ba                	jb     1400084a5 <__lshift_D2A+0xe5>
   1400084eb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084ef:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   1400084f2:	89 10                	mov    DWORD PTR [rax],edx
   1400084f4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084f8:	8b 00                	mov    eax,DWORD PTR [rax]
   1400084fa:	85 c0                	test   eax,eax
   1400084fc:	74 2c                	je     14000852a <__lshift_D2A+0x16a>
   1400084fe:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140008502:	eb 26                	jmp    14000852a <__lshift_D2A+0x16a>
   140008504:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008508:	48 8d 42 04          	lea    rax,[rdx+0x4]
   14000850c:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008510:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008514:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140008518:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   14000851c:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000851e:	89 10                	mov    DWORD PTR [rax],edx
   140008520:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008524:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008528:	72 da                	jb     140008504 <__lshift_D2A+0x144>
   14000852a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000852d:	8d 50 ff             	lea    edx,[rax-0x1]
   140008530:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008534:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008537:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000853b:	48 89 c1             	mov    rcx,rax
   14000853e:	e8 9b f8 ff ff       	call   140007dde <__Bfree_D2A>
   140008543:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008547:	48 83 c4 60          	add    rsp,0x60
   14000854b:	5d                   	pop    rbp
   14000854c:	c3                   	ret

000000014000854d <__cmp_D2A>:
   14000854d:	55                   	push   rbp
   14000854e:	48 89 e5             	mov    rbp,rsp
   140008551:	48 83 ec 30          	sub    rsp,0x30
   140008555:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008559:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000855d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008561:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008564:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140008567:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000856b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000856e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140008571:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008574:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   140008577:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000857b:	74 08                	je     140008585 <__cmp_D2A+0x38>
   14000857d:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008580:	e9 92 00 00 00       	jmp    140008617 <__cmp_D2A+0xca>
   140008585:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008589:	48 83 c0 18          	add    rax,0x18
   14000858d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008591:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008594:	48 98                	cdqe
   140008596:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000859d:	00 
   14000859e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400085a2:	48 01 d0             	add    rax,rdx
   1400085a5:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400085a9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400085ad:	48 83 c0 18          	add    rax,0x18
   1400085b1:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400085b5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085b8:	48 98                	cdqe
   1400085ba:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400085c1:	00 
   1400085c2:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400085c6:	48 01 d0             	add    rax,rdx
   1400085c9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400085cd:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400085d2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400085d6:	8b 10                	mov    edx,DWORD PTR [rax]
   1400085d8:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   1400085dd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400085e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400085e3:	39 c2                	cmp    edx,eax
   1400085e5:	74 1e                	je     140008605 <__cmp_D2A+0xb8>
   1400085e7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400085eb:	8b 10                	mov    edx,DWORD PTR [rax]
   1400085ed:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400085f1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400085f3:	39 c2                	cmp    edx,eax
   1400085f5:	73 07                	jae    1400085fe <__cmp_D2A+0xb1>
   1400085f7:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400085fc:	eb 19                	jmp    140008617 <__cmp_D2A+0xca>
   1400085fe:	b8 01 00 00 00       	mov    eax,0x1
   140008603:	eb 12                	jmp    140008617 <__cmp_D2A+0xca>
   140008605:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008609:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000860d:	73 02                	jae    140008611 <__cmp_D2A+0xc4>
   14000860f:	eb bc                	jmp    1400085cd <__cmp_D2A+0x80>
   140008611:	90                   	nop
   140008612:	b8 00 00 00 00       	mov    eax,0x0
   140008617:	48 83 c4 30          	add    rsp,0x30
   14000861b:	5d                   	pop    rbp
   14000861c:	c3                   	ret

000000014000861d <__diff_D2A>:
   14000861d:	55                   	push   rbp
   14000861e:	48 89 e5             	mov    rbp,rsp
   140008621:	48 83 ec 70          	sub    rsp,0x70
   140008625:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008629:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000862d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140008631:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008635:	48 89 c1             	mov    rcx,rax
   140008638:	e8 10 ff ff ff       	call   14000854d <__cmp_D2A>
   14000863d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008640:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008644:	75 3e                	jne    140008684 <__diff_D2A+0x67>
   140008646:	b9 00 00 00 00       	mov    ecx,0x0
   14000864b:	e8 4d f6 ff ff       	call   140007c9d <__Balloc_D2A>
   140008650:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008654:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008659:	75 0a                	jne    140008665 <__diff_D2A+0x48>
   14000865b:	b8 00 00 00 00       	mov    eax,0x0
   140008660:	e9 ab 01 00 00       	jmp    140008810 <__diff_D2A+0x1f3>
   140008665:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008669:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008670:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008674:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000867b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000867f:	e9 8c 01 00 00       	jmp    140008810 <__diff_D2A+0x1f3>
   140008684:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008688:	79 21                	jns    1400086ab <__diff_D2A+0x8e>
   14000868a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000868e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008692:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008696:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000869a:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000869e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400086a2:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400086a9:	eb 07                	jmp    1400086b2 <__diff_D2A+0x95>
   1400086ab:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400086b2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086b6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400086b9:	89 c1                	mov    ecx,eax
   1400086bb:	e8 dd f5 ff ff       	call   140007c9d <__Balloc_D2A>
   1400086c0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400086c4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400086c9:	75 0a                	jne    1400086d5 <__diff_D2A+0xb8>
   1400086cb:	b8 00 00 00 00       	mov    eax,0x0
   1400086d0:	e9 3b 01 00 00       	jmp    140008810 <__diff_D2A+0x1f3>
   1400086d5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086d9:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400086dc:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400086df:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086e3:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400086e6:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400086e9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086ed:	48 83 c0 18          	add    rax,0x18
   1400086f1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400086f5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400086f8:	48 98                	cdqe
   1400086fa:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008701:	00 
   140008702:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008706:	48 01 d0             	add    rax,rdx
   140008709:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000870d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008711:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008714:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   140008717:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000871b:	48 83 c0 18          	add    rax,0x18
   14000871f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008723:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008726:	48 98                	cdqe
   140008728:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000872f:	00 
   140008730:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008734:	48 01 d0             	add    rax,rdx
   140008737:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000873b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000873f:	48 83 c0 18          	add    rax,0x18
   140008743:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008747:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   14000874e:	00 
   14000874f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008753:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008757:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000875b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000875d:	89 c1                	mov    ecx,eax
   14000875f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008763:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008767:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   14000876b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000876d:	89 c2                	mov    edx,eax
   14000876f:	48 89 c8             	mov    rax,rcx
   140008772:	48 29 d0             	sub    rax,rdx
   140008775:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140008779:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000877d:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008781:	48 c1 e8 20          	shr    rax,0x20
   140008785:	83 e0 01             	and    eax,0x1
   140008788:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000878c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008790:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008794:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008798:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000879c:	89 10                	mov    DWORD PTR [rax],edx
   14000879e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087a2:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   1400087a6:	72 a7                	jb     14000874f <__diff_D2A+0x132>
   1400087a8:	eb 39                	jmp    1400087e3 <__diff_D2A+0x1c6>
   1400087aa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087ae:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087b2:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400087b6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087b8:	89 c0                	mov    eax,eax
   1400087ba:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400087be:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400087c2:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400087c6:	48 c1 e8 20          	shr    rax,0x20
   1400087ca:	83 e0 01             	and    eax,0x1
   1400087cd:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400087d1:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087d5:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087d9:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400087dd:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400087e1:	89 10                	mov    DWORD PTR [rax],edx
   1400087e3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087e7:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400087eb:	72 bd                	jb     1400087aa <__diff_D2A+0x18d>
   1400087ed:	eb 04                	jmp    1400087f3 <__diff_D2A+0x1d6>
   1400087ef:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400087f3:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   1400087f8:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087fc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087fe:	85 c0                	test   eax,eax
   140008800:	74 ed                	je     1400087ef <__diff_D2A+0x1d2>
   140008802:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008806:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008809:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000880c:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008810:	48 83 c4 70          	add    rsp,0x70
   140008814:	5d                   	pop    rbp
   140008815:	c3                   	ret

0000000140008816 <__b2d_D2A>:
   140008816:	55                   	push   rbp
   140008817:	48 89 e5             	mov    rbp,rsp
   14000881a:	48 83 ec 50          	sub    rsp,0x50
   14000881e:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008822:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008826:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000882a:	48 83 c0 18          	add    rax,0x18
   14000882e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008832:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008836:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008839:	48 98                	cdqe
   14000883b:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008842:	00 
   140008843:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008847:	48 01 d0             	add    rax,rdx
   14000884a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000884e:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008853:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008857:	8b 00                	mov    eax,DWORD PTR [rax]
   140008859:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   14000885c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000885f:	89 c1                	mov    ecx,eax
   140008861:	e8 27 f4 ff ff       	call   140007c8d <__hi0bits_D2A>
   140008866:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008869:	b8 20 00 00 00       	mov    eax,0x20
   14000886e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008871:	89 c2                	mov    edx,eax
   140008873:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008877:	89 10                	mov    DWORD PTR [rax],edx
   140008879:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   14000887d:	7f 66                	jg     1400088e5 <__b2d_D2A+0xcf>
   14000887f:	b8 0b 00 00 00       	mov    eax,0xb
   140008884:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008887:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000888a:	89 c1                	mov    ecx,eax
   14000888c:	d3 ea                	shr    edx,cl
   14000888e:	89 d0                	mov    eax,edx
   140008890:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008895:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008898:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000889c:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400088a0:	73 10                	jae    1400088b2 <__b2d_D2A+0x9c>
   1400088a2:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088a7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088ad:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400088b0:	eb 07                	jmp    1400088b9 <__b2d_D2A+0xa3>
   1400088b2:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400088b9:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400088bc:	83 c0 15             	add    eax,0x15
   1400088bf:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400088c2:	89 c1                	mov    ecx,eax
   1400088c4:	d3 e2                	shl    edx,cl
   1400088c6:	41 89 d0             	mov    r8d,edx
   1400088c9:	b8 0b 00 00 00       	mov    eax,0xb
   1400088ce:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088d1:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   1400088d4:	89 c1                	mov    ecx,eax
   1400088d6:	d3 ea                	shr    edx,cl
   1400088d8:	89 d0                	mov    eax,edx
   1400088da:	44 09 c0             	or     eax,r8d
   1400088dd:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400088e0:	e9 ac 00 00 00       	jmp    140008991 <__b2d_D2A+0x17b>
   1400088e5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088e9:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400088ed:	73 10                	jae    1400088ff <__b2d_D2A+0xe9>
   1400088ef:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088f4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088f8:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088fa:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400088fd:	eb 07                	jmp    140008906 <__b2d_D2A+0xf0>
   1400088ff:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   140008906:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   14000890a:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   14000890e:	74 70                	je     140008980 <__b2d_D2A+0x16a>
   140008910:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008913:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008916:	89 c1                	mov    ecx,eax
   140008918:	d3 e2                	shl    edx,cl
   14000891a:	41 89 d0             	mov    r8d,edx
   14000891d:	b8 20 00 00 00       	mov    eax,0x20
   140008922:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008925:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008928:	89 c1                	mov    ecx,eax
   14000892a:	d3 ea                	shr    edx,cl
   14000892c:	89 d0                	mov    eax,edx
   14000892e:	44 09 c0             	or     eax,r8d
   140008931:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008936:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008939:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000893d:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008941:	73 10                	jae    140008953 <__b2d_D2A+0x13d>
   140008943:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008948:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000894c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000894e:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140008951:	eb 07                	jmp    14000895a <__b2d_D2A+0x144>
   140008953:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   14000895a:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000895d:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008960:	89 c1                	mov    ecx,eax
   140008962:	d3 e2                	shl    edx,cl
   140008964:	41 89 d0             	mov    r8d,edx
   140008967:	b8 20 00 00 00       	mov    eax,0x20
   14000896c:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   14000896f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008972:	89 c1                	mov    ecx,eax
   140008974:	d3 ea                	shr    edx,cl
   140008976:	89 d0                	mov    eax,edx
   140008978:	44 09 c0             	or     eax,r8d
   14000897b:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000897e:	eb 11                	jmp    140008991 <__b2d_D2A+0x17b>
   140008980:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008983:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008988:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000898b:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   14000898e:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008991:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   140008996:	48 83 c4 50          	add    rsp,0x50
   14000899a:	5d                   	pop    rbp
   14000899b:	c3                   	ret

000000014000899c <__d2b_D2A>:
   14000899c:	55                   	push   rbp
   14000899d:	53                   	push   rbx
   14000899e:	48 83 ec 58          	sub    rsp,0x58
   1400089a2:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400089a7:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   1400089ac:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400089b0:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400089b4:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400089b9:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   1400089be:	b9 01 00 00 00       	mov    ecx,0x1
   1400089c3:	e8 d5 f2 ff ff       	call   140007c9d <__Balloc_D2A>
   1400089c8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400089cc:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400089d1:	75 0a                	jne    1400089dd <__d2b_D2A+0x41>
   1400089d3:	b8 00 00 00 00       	mov    eax,0x0
   1400089d8:	e9 68 01 00 00       	jmp    140008b45 <__d2b_D2A+0x1a9>
   1400089dd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400089e1:	48 83 c0 18          	add    rax,0x18
   1400089e5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400089e9:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089ec:	25 ff ff 0f 00       	and    eax,0xfffff
   1400089f1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089f4:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089f7:	25 ff ff ff 7f       	and    eax,0x7fffffff
   1400089fc:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400089ff:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a02:	c1 e8 14             	shr    eax,0x14
   140008a05:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140008a08:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008a0c:	74 0b                	je     140008a19 <__d2b_D2A+0x7d>
   140008a0e:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   140008a11:	0d 00 00 10 00       	or     eax,0x100000
   140008a16:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a19:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140008a1c:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008a1f:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008a22:	85 c0                	test   eax,eax
   140008a24:	74 7b                	je     140008aa1 <__d2b_D2A+0x105>
   140008a26:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   140008a2a:	48 89 c1             	mov    rcx,rax
   140008a2d:	e8 26 f2 ff ff       	call   140007c58 <__lo0bits_D2A>
   140008a32:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008a35:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008a39:	74 2b                	je     140008a66 <__d2b_D2A+0xca>
   140008a3b:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a3e:	b8 20 00 00 00       	mov    eax,0x20
   140008a43:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008a46:	89 c1                	mov    ecx,eax
   140008a48:	d3 e2                	shl    edx,cl
   140008a4a:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008a4d:	09 c2                	or     edx,eax
   140008a4f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a53:	89 10                	mov    DWORD PTR [rax],edx
   140008a55:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a58:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008a5b:	89 c1                	mov    ecx,eax
   140008a5d:	d3 ea                	shr    edx,cl
   140008a5f:	89 d0                	mov    eax,edx
   140008a61:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a64:	eb 09                	jmp    140008a6f <__d2b_D2A+0xd3>
   140008a66:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008a69:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a6d:	89 10                	mov    DWORD PTR [rax],edx
   140008a6f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a73:	48 83 c0 04          	add    rax,0x4
   140008a77:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a7a:	89 10                	mov    DWORD PTR [rax],edx
   140008a7c:	8b 00                	mov    eax,DWORD PTR [rax]
   140008a7e:	85 c0                	test   eax,eax
   140008a80:	74 07                	je     140008a89 <__d2b_D2A+0xed>
   140008a82:	ba 02 00 00 00       	mov    edx,0x2
   140008a87:	eb 05                	jmp    140008a8e <__d2b_D2A+0xf2>
   140008a89:	ba 01 00 00 00       	mov    edx,0x1
   140008a8e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a92:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008a95:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a99:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008a9c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008a9f:	eb 31                	jmp    140008ad2 <__d2b_D2A+0x136>
   140008aa1:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008aa5:	48 89 c1             	mov    rcx,rax
   140008aa8:	e8 ab f1 ff ff       	call   140007c58 <__lo0bits_D2A>
   140008aad:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008ab0:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008ab3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008ab7:	89 10                	mov    DWORD PTR [rax],edx
   140008ab9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008abd:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008ac4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ac8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008acb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008ace:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008ad2:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008ad6:	74 26                	je     140008afe <__d2b_D2A+0x162>
   140008ad8:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008adb:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008ae1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008ae4:	01 c2                	add    edx,eax
   140008ae6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008aea:	89 10                	mov    DWORD PTR [rax],edx
   140008aec:	b8 35 00 00 00       	mov    eax,0x35
   140008af1:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008af4:	89 c2                	mov    edx,eax
   140008af6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008afa:	89 10                	mov    DWORD PTR [rax],edx
   140008afc:	eb 43                	jmp    140008b41 <__d2b_D2A+0x1a5>
   140008afe:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b01:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008b07:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b0a:	01 c2                	add    edx,eax
   140008b0c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b10:	89 10                	mov    DWORD PTR [rax],edx
   140008b12:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b15:	c1 e0 05             	shl    eax,0x5
   140008b18:	89 c3                	mov    ebx,eax
   140008b1a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b1d:	48 98                	cdqe
   140008b1f:	48 c1 e0 02          	shl    rax,0x2
   140008b23:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008b27:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b2b:	48 01 d0             	add    rax,rdx
   140008b2e:	8b 00                	mov    eax,DWORD PTR [rax]
   140008b30:	89 c1                	mov    ecx,eax
   140008b32:	e8 56 f1 ff ff       	call   140007c8d <__hi0bits_D2A>
   140008b37:	29 c3                	sub    ebx,eax
   140008b39:	89 da                	mov    edx,ebx
   140008b3b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b3f:	89 10                	mov    DWORD PTR [rax],edx
   140008b41:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b45:	48 83 c4 58          	add    rsp,0x58
   140008b49:	5b                   	pop    rbx
   140008b4a:	5d                   	pop    rbp
   140008b4b:	c3                   	ret

0000000140008b4c <__strcp_D2A>:
   140008b4c:	55                   	push   rbp
   140008b4d:	48 89 e5             	mov    rbp,rsp
   140008b50:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008b54:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008b58:	eb 05                	jmp    140008b5f <__strcp_D2A+0x13>
   140008b5a:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008b5f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008b63:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008b67:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008b6b:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008b6e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b72:	88 10                	mov    BYTE PTR [rax],dl
   140008b74:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b78:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008b7b:	84 c0                	test   al,al
   140008b7d:	75 db                	jne    140008b5a <__strcp_D2A+0xe>
   140008b7f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b83:	5d                   	pop    rbp
   140008b84:	c3                   	ret
   140008b85:	90                   	nop
   140008b86:	90                   	nop
   140008b87:	90                   	nop
   140008b88:	90                   	nop
   140008b89:	90                   	nop
   140008b8a:	90                   	nop
   140008b8b:	90                   	nop
   140008b8c:	90                   	nop
   140008b8d:	90                   	nop
   140008b8e:	90                   	nop
   140008b8f:	90                   	nop

0000000140008b90 <__fpclassify>:
   140008b90:	55                   	push   rbp
   140008b91:	48 89 e5             	mov    rbp,rsp
   140008b94:	48 83 ec 10          	sub    rsp,0x10
   140008b98:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008b9d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008ba2:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008ba7:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008baa:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008bad:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008bb0:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008bb3:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008bb9:	09 d0                	or     eax,edx
   140008bbb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008bbe:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008bc5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008bc8:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008bcb:	85 c0                	test   eax,eax
   140008bcd:	75 07                	jne    140008bd6 <__fpclassify+0x46>
   140008bcf:	b8 00 40 00 00       	mov    eax,0x4000
   140008bd4:	eb 2f                	jmp    140008c05 <__fpclassify+0x75>
   140008bd6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008bda:	75 07                	jne    140008be3 <__fpclassify+0x53>
   140008bdc:	b8 00 44 00 00       	mov    eax,0x4400
   140008be1:	eb 22                	jmp    140008c05 <__fpclassify+0x75>
   140008be3:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008bea:	75 14                	jne    140008c00 <__fpclassify+0x70>
   140008bec:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008bf0:	74 07                	je     140008bf9 <__fpclassify+0x69>
   140008bf2:	b8 00 01 00 00       	mov    eax,0x100
   140008bf7:	eb 0c                	jmp    140008c05 <__fpclassify+0x75>
   140008bf9:	b8 00 05 00 00       	mov    eax,0x500
   140008bfe:	eb 05                	jmp    140008c05 <__fpclassify+0x75>
   140008c00:	b8 00 04 00 00       	mov    eax,0x400
   140008c05:	48 83 c4 10          	add    rsp,0x10
   140008c09:	5d                   	pop    rbp
   140008c0a:	c3                   	ret
   140008c0b:	90                   	nop
   140008c0c:	90                   	nop
   140008c0d:	90                   	nop
   140008c0e:	90                   	nop
   140008c0f:	90                   	nop

0000000140008c10 <__fpclassifyl>:
   140008c10:	55                   	push   rbp
   140008c11:	53                   	push   rbx
   140008c12:	48 83 ec 38          	sub    rsp,0x38
   140008c16:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008c1b:	48 89 cb             	mov    rbx,rcx
   140008c1e:	db 2b                	fld    TBYTE PTR [rbx]
   140008c20:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008c23:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008c26:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008c29:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008c2d:	98                   	cwde
   140008c2e:	25 ff 7f 00 00       	and    eax,0x7fff
   140008c33:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c36:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c3a:	75 25                	jne    140008c61 <__fpclassifyl+0x51>
   140008c3c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c3f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c42:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c45:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c48:	85 c0                	test   eax,eax
   140008c4a:	75 07                	jne    140008c53 <__fpclassifyl+0x43>
   140008c4c:	b8 00 40 00 00       	mov    eax,0x4000
   140008c51:	eb 3d                	jmp    140008c90 <__fpclassifyl+0x80>
   140008c53:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c56:	85 c0                	test   eax,eax
   140008c58:	78 31                	js     140008c8b <__fpclassifyl+0x7b>
   140008c5a:	b8 00 44 00 00       	mov    eax,0x4400
   140008c5f:	eb 2f                	jmp    140008c90 <__fpclassifyl+0x80>
   140008c61:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008c68:	75 21                	jne    140008c8b <__fpclassifyl+0x7b>
   140008c6a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c6d:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008c72:	89 c2                	mov    edx,eax
   140008c74:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c77:	09 d0                	or     eax,edx
   140008c79:	85 c0                	test   eax,eax
   140008c7b:	75 07                	jne    140008c84 <__fpclassifyl+0x74>
   140008c7d:	b8 00 05 00 00       	mov    eax,0x500
   140008c82:	eb 0c                	jmp    140008c90 <__fpclassifyl+0x80>
   140008c84:	b8 00 01 00 00       	mov    eax,0x100
   140008c89:	eb 05                	jmp    140008c90 <__fpclassifyl+0x80>
   140008c8b:	b8 00 04 00 00       	mov    eax,0x400
   140008c90:	48 83 c4 38          	add    rsp,0x38
   140008c94:	5b                   	pop    rbx
   140008c95:	5d                   	pop    rbp
   140008c96:	c3                   	ret
   140008c97:	90                   	nop
   140008c98:	90                   	nop
   140008c99:	90                   	nop
   140008c9a:	90                   	nop
   140008c9b:	90                   	nop
   140008c9c:	90                   	nop
   140008c9d:	90                   	nop
   140008c9e:	90                   	nop
   140008c9f:	90                   	nop

0000000140008ca0 <__isnan>:
   140008ca0:	55                   	push   rbp
   140008ca1:	48 89 e5             	mov    rbp,rsp
   140008ca4:	48 83 ec 10          	sub    rsp,0x10
   140008ca8:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008cad:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008cb2:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008cb7:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008cba:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cbd:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008cc0:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008cc5:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008cc8:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008ccb:	f7 d8                	neg    eax
   140008ccd:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008cd0:	c1 e8 1f             	shr    eax,0x1f
   140008cd3:	89 c2                	mov    edx,eax
   140008cd5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008cd8:	09 d0                	or     eax,edx
   140008cda:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008cdd:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008ce2:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008ce5:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008ce8:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008ceb:	c1 f8 1f             	sar    eax,0x1f
   140008cee:	48 83 c4 10          	add    rsp,0x10
   140008cf2:	5d                   	pop    rbp
   140008cf3:	c3                   	ret
   140008cf4:	90                   	nop
   140008cf5:	90                   	nop
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

0000000140008d00 <__isnanl>:
   140008d00:	55                   	push   rbp
   140008d01:	53                   	push   rbx
   140008d02:	48 83 ec 38          	sub    rsp,0x38
   140008d06:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008d0b:	48 89 cb             	mov    rbx,rcx
   140008d0e:	db 2b                	fld    TBYTE PTR [rbx]
   140008d10:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008d13:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008d16:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008d19:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008d1d:	98                   	cwde
   140008d1e:	01 c0                	add    eax,eax
   140008d20:	25 ff ff 00 00       	and    eax,0xffff
   140008d25:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d28:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008d2b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008d2e:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008d34:	09 d0                	or     eax,edx
   140008d36:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d39:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d3c:	f7 d8                	neg    eax
   140008d3e:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008d41:	c1 e8 1f             	shr    eax,0x1f
   140008d44:	89 c2                	mov    edx,eax
   140008d46:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d49:	09 d0                	or     eax,edx
   140008d4b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d4e:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008d53:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008d56:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d59:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d5c:	c1 f8 10             	sar    eax,0x10
   140008d5f:	48 83 c4 38          	add    rsp,0x38
   140008d63:	5b                   	pop    rbx
   140008d64:	5d                   	pop    rbp
   140008d65:	c3                   	ret
   140008d66:	90                   	nop
   140008d67:	90                   	nop
   140008d68:	90                   	nop
   140008d69:	90                   	nop
   140008d6a:	90                   	nop
   140008d6b:	90                   	nop
   140008d6c:	90                   	nop
   140008d6d:	90                   	nop
   140008d6e:	90                   	nop
   140008d6f:	90                   	nop

0000000140008d70 <wcsnlen>:
   140008d70:	55                   	push   rbp
   140008d71:	48 89 e5             	mov    rbp,rsp
   140008d74:	48 83 ec 10          	sub    rsp,0x10
   140008d78:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008d7c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008d80:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008d87:	00 
   140008d88:	eb 0a                	jmp    140008d94 <wcsnlen+0x24>
   140008d8a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008d8f:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008d94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d98:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008d9c:	73 0c                	jae    140008daa <wcsnlen+0x3a>
   140008d9e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008da2:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008da5:	66 85 c0             	test   ax,ax
   140008da8:	75 e0                	jne    140008d8a <wcsnlen+0x1a>
   140008daa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dae:	48 83 c4 10          	add    rsp,0x10
   140008db2:	5d                   	pop    rbp
   140008db3:	c3                   	ret
   140008db4:	90                   	nop
   140008db5:	90                   	nop
   140008db6:	90                   	nop
   140008db7:	90                   	nop
   140008db8:	90                   	nop
   140008db9:	90                   	nop
   140008dba:	90                   	nop
   140008dbb:	90                   	nop
   140008dbc:	90                   	nop
   140008dbd:	90                   	nop
   140008dbe:	90                   	nop
   140008dbf:	90                   	nop

0000000140008dc0 <strnlen>:
   140008dc0:	55                   	push   rbp
   140008dc1:	48 89 e5             	mov    rbp,rsp
   140008dc4:	48 83 ec 10          	sub    rsp,0x10
   140008dc8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008dcc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008dd0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008dd4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008dd8:	eb 05                	jmp    140008ddf <strnlen+0x1f>
   140008dda:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008ddf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008de3:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008de7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008deb:	73 0b                	jae    140008df8 <strnlen+0x38>
   140008ded:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008df1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008df4:	84 c0                	test   al,al
   140008df6:	75 e2                	jne    140008dda <strnlen+0x1a>
   140008df8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dfc:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e00:	48 83 c4 10          	add    rsp,0x10
   140008e04:	5d                   	pop    rbp
   140008e05:	c3                   	ret
   140008e06:	90                   	nop
   140008e07:	90                   	nop
   140008e08:	90                   	nop
   140008e09:	90                   	nop
   140008e0a:	90                   	nop
   140008e0b:	90                   	nop
   140008e0c:	90                   	nop
   140008e0d:	90                   	nop
   140008e0e:	90                   	nop
   140008e0f:	90                   	nop

0000000140008e10 <_initterm_e>:
   140008e10:	55                   	push   rbp
   140008e11:	48 89 e5             	mov    rbp,rsp
   140008e14:	48 83 ec 30          	sub    rsp,0x30
   140008e18:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e1c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e20:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e24:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e28:	eb 29                	jmp    140008e53 <_initterm_e+0x43>
   140008e2a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e2e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e31:	48 85 c0             	test   rax,rax
   140008e34:	74 17                	je     140008e4d <_initterm_e+0x3d>
   140008e36:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e3a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e3d:	ff d0                	call   rax
   140008e3f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008e42:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008e46:	74 06                	je     140008e4e <_initterm_e+0x3e>
   140008e48:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008e4b:	eb 15                	jmp    140008e62 <_initterm_e+0x52>
   140008e4d:	90                   	nop
   140008e4e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008e53:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e57:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e5b:	72 cd                	jb     140008e2a <_initterm_e+0x1a>
   140008e5d:	b8 00 00 00 00       	mov    eax,0x0
   140008e62:	48 83 c4 30          	add    rsp,0x30
   140008e66:	5d                   	pop    rbp
   140008e67:	c3                   	ret
   140008e68:	90                   	nop
   140008e69:	90                   	nop
   140008e6a:	90                   	nop
   140008e6b:	90                   	nop
   140008e6c:	90                   	nop
   140008e6d:	90                   	nop
   140008e6e:	90                   	nop
   140008e6f:	90                   	nop

0000000140008e70 <__p__fmode>:
   140008e70:	55                   	push   rbp
   140008e71:	48 89 e5             	mov    rbp,rsp
   140008e74:	48 8b 05 85 27 00 00 	mov    rax,QWORD PTR [rip+0x2785]        # 14000b600 <.refptr.__imp__fmode>
   140008e7b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e7e:	5d                   	pop    rbp
   140008e7f:	c3                   	ret

0000000140008e80 <__p__commode>:
   140008e80:	55                   	push   rbp
   140008e81:	48 89 e5             	mov    rbp,rsp
   140008e84:	48 8b 05 65 27 00 00 	mov    rax,QWORD PTR [rip+0x2765]        # 14000b5f0 <.refptr.__imp__commode>
   140008e8b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e8e:	5d                   	pop    rbp
   140008e8f:	c3                   	ret

0000000140008e90 <__p___initenv>:
   140008e90:	55                   	push   rbp
   140008e91:	48 89 e5             	mov    rbp,rsp
   140008e94:	48 8b 05 45 27 00 00 	mov    rax,QWORD PTR [rip+0x2745]        # 14000b5e0 <.refptr.__imp___initenv>
   140008e9b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e9e:	5d                   	pop    rbp
   140008e9f:	c3                   	ret

0000000140008ea0 <_lock_file>:
   140008ea0:	55                   	push   rbp
   140008ea1:	48 89 e5             	mov    rbp,rsp
   140008ea4:	48 83 ec 20          	sub    rsp,0x20
   140008ea8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008eac:	b9 00 00 00 00       	mov    ecx,0x0
   140008eb1:	e8 6a 01 00 00       	call   140009020 <__acrt_iob_func>
   140008eb6:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008eba:	72 52                	jb     140008f0e <_lock_file+0x6e>
   140008ebc:	b9 13 00 00 00       	mov    ecx,0x13
   140008ec1:	e8 5a 01 00 00       	call   140009020 <__acrt_iob_func>
   140008ec6:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008eca:	72 42                	jb     140008f0e <_lock_file+0x6e>
   140008ecc:	b9 00 00 00 00       	mov    ecx,0x0
   140008ed1:	e8 4a 01 00 00       	call   140009020 <__acrt_iob_func>
   140008ed6:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008eda:	48 29 c2             	sub    rdx,rax
   140008edd:	48 c1 fa 04          	sar    rdx,0x4
   140008ee1:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008ee8:	aa aa aa 
   140008eeb:	48 0f af c2          	imul   rax,rdx
   140008eef:	83 c0 10             	add    eax,0x10
   140008ef2:	89 c1                	mov    ecx,eax
   140008ef4:	e8 1f 07 00 00       	call   140009618 <_lock>
   140008ef9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008efd:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008f00:	80 cc 80             	or     ah,0x80
   140008f03:	89 c2                	mov    edx,eax
   140008f05:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f09:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008f0c:	eb 15                	jmp    140008f23 <_lock_file+0x83>
   140008f0e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f12:	48 83 c0 30          	add    rax,0x30
   140008f16:	48 89 c1             	mov    rcx,rax
   140008f19:	48 8b 05 d8 72 00 00 	mov    rax,QWORD PTR [rip+0x72d8]        # 1400101f8 <__imp_EnterCriticalSection>
   140008f20:	ff d0                	call   rax
   140008f22:	90                   	nop
   140008f23:	90                   	nop
   140008f24:	48 83 c4 20          	add    rsp,0x20
   140008f28:	5d                   	pop    rbp
   140008f29:	c3                   	ret

0000000140008f2a <_unlock_file>:
   140008f2a:	55                   	push   rbp
   140008f2b:	48 89 e5             	mov    rbp,rsp
   140008f2e:	48 83 ec 20          	sub    rsp,0x20
   140008f32:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f36:	b9 00 00 00 00       	mov    ecx,0x0
   140008f3b:	e8 e0 00 00 00       	call   140009020 <__acrt_iob_func>
   140008f40:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008f44:	72 52                	jb     140008f98 <_unlock_file+0x6e>
   140008f46:	b9 13 00 00 00       	mov    ecx,0x13
   140008f4b:	e8 d0 00 00 00       	call   140009020 <__acrt_iob_func>
   140008f50:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f54:	72 42                	jb     140008f98 <_unlock_file+0x6e>
   140008f56:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f5a:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008f5d:	80 e4 7f             	and    ah,0x7f
   140008f60:	89 c2                	mov    edx,eax
   140008f62:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f66:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008f69:	b9 00 00 00 00       	mov    ecx,0x0
   140008f6e:	e8 ad 00 00 00       	call   140009020 <__acrt_iob_func>
   140008f73:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f77:	48 29 c2             	sub    rdx,rax
   140008f7a:	48 c1 fa 04          	sar    rdx,0x4
   140008f7e:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008f85:	aa aa aa 
   140008f88:	48 0f af c2          	imul   rax,rdx
   140008f8c:	83 c0 10             	add    eax,0x10
   140008f8f:	89 c1                	mov    ecx,eax
   140008f91:	e8 8a 06 00 00       	call   140009620 <_unlock>
   140008f96:	eb 15                	jmp    140008fad <_unlock_file+0x83>
   140008f98:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f9c:	48 83 c0 30          	add    rax,0x30
   140008fa0:	48 89 c1             	mov    rcx,rax
   140008fa3:	48 8b 05 86 72 00 00 	mov    rax,QWORD PTR [rip+0x7286]        # 140010230 <__imp_LeaveCriticalSection>
   140008faa:	ff d0                	call   rax
   140008fac:	90                   	nop
   140008fad:	90                   	nop
   140008fae:	48 83 c4 20          	add    rsp,0x20
   140008fb2:	5d                   	pop    rbp
   140008fb3:	c3                   	ret
   140008fb4:	90                   	nop
   140008fb5:	90                   	nop
   140008fb6:	90                   	nop
   140008fb7:	90                   	nop
   140008fb8:	90                   	nop
   140008fb9:	90                   	nop
   140008fba:	90                   	nop
   140008fbb:	90                   	nop
   140008fbc:	90                   	nop
   140008fbd:	90                   	nop
   140008fbe:	90                   	nop
   140008fbf:	90                   	nop

0000000140008fc0 <_set_invalid_parameter_handler>:
   140008fc0:	55                   	push   rbp
   140008fc1:	48 89 e5             	mov    rbp,rsp
   140008fc4:	48 83 ec 10          	sub    rsp,0x10
   140008fc8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008fcc:	48 8d 05 ad 6b 00 00 	lea    rax,[rip+0x6bad]        # 14000fb80 <handler>
   140008fd3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008fd7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fdb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008fdf:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140008fe3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008fe7:	48 87 10             	xchg   QWORD PTR [rax],rdx
   140008fea:	48 89 d0             	mov    rax,rdx
   140008fed:	48 83 c4 10          	add    rsp,0x10
   140008ff1:	5d                   	pop    rbp
   140008ff2:	c3                   	ret

0000000140008ff3 <_get_invalid_parameter_handler>:
   140008ff3:	55                   	push   rbp
   140008ff4:	48 89 e5             	mov    rbp,rsp
   140008ff7:	48 8b 05 82 6b 00 00 	mov    rax,QWORD PTR [rip+0x6b82]        # 14000fb80 <handler>
   140008ffe:	5d                   	pop    rbp
   140008fff:	c3                   	ret

0000000140009000 <_configthreadlocale>:
   140009000:	55                   	push   rbp
   140009001:	48 89 e5             	mov    rbp,rsp
   140009004:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140009007:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000900b:	75 07                	jne    140009014 <_configthreadlocale+0x14>
   14000900d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140009012:	eb 05                	jmp    140009019 <_configthreadlocale+0x19>
   140009014:	b8 02 00 00 00       	mov    eax,0x2
   140009019:	5d                   	pop    rbp
   14000901a:	c3                   	ret
   14000901b:	90                   	nop
   14000901c:	90                   	nop
   14000901d:	90                   	nop
   14000901e:	90                   	nop
   14000901f:	90                   	nop

0000000140009020 <__acrt_iob_func>:
   140009020:	55                   	push   rbp
   140009021:	48 89 e5             	mov    rbp,rsp
   140009024:	48 83 ec 20          	sub    rsp,0x20
   140009028:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000902b:	e8 b0 05 00 00       	call   1400095e0 <__iob_func>
   140009030:	48 89 c1             	mov    rcx,rax
   140009033:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140009036:	48 89 d0             	mov    rax,rdx
   140009039:	48 01 c0             	add    rax,rax
   14000903c:	48 01 d0             	add    rax,rdx
   14000903f:	48 c1 e0 04          	shl    rax,0x4
   140009043:	48 01 c8             	add    rax,rcx
   140009046:	48 83 c4 20          	add    rsp,0x20
   14000904a:	5d                   	pop    rbp
   14000904b:	c3                   	ret
   14000904c:	90                   	nop
   14000904d:	90                   	nop
   14000904e:	90                   	nop
   14000904f:	90                   	nop

0000000140009050 <wcrtomb>:
   140009050:	55                   	push   rbp
   140009051:	48 89 e5             	mov    rbp,rsp
   140009054:	48 83 ec 40          	sub    rsp,0x40
   140009058:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000905c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009060:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009064:	e8 5f 05 00 00       	call   1400095c8 <___lc_codepage_func>
   140009069:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000906c:	e8 5f 05 00 00       	call   1400095d0 <___mb_cur_max_func>
   140009071:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140009074:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   140009078:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   14000907c:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   140009080:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009084:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140009087:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   14000908b:	48 89 c1             	mov    rcx,rax
   14000908e:	e8 7d 00 00 00       	call   140009110 <__mingw_wcrtomb_cp>
   140009093:	48 83 c4 40          	add    rsp,0x40
   140009097:	5d                   	pop    rbp
   140009098:	c3                   	ret
   140009099:	90                   	nop
   14000909a:	90                   	nop
   14000909b:	90                   	nop
   14000909c:	90                   	nop
   14000909d:	90                   	nop
   14000909e:	90                   	nop
   14000909f:	90                   	nop

00000001400090a0 <mbrtowc>:
   1400090a0:	55                   	push   rbp
   1400090a1:	48 89 e5             	mov    rbp,rsp
   1400090a4:	48 83 ec 40          	sub    rsp,0x40
   1400090a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090ac:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400090b0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090b4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400090b8:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   1400090bd:	75 0b                	jne    1400090ca <mbrtowc+0x2a>
   1400090bf:	48 8d 05 ca 6a 00 00 	lea    rax,[rip+0x6aca]        # 14000fb90 <state_mbrtowc.0>
   1400090c6:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400090ca:	e8 f9 04 00 00       	call   1400095c8 <___lc_codepage_func>
   1400090cf:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400090d2:	e8 f9 04 00 00       	call   1400095d0 <___mb_cur_max_func>
   1400090d7:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400090da:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   1400090de:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   1400090e2:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400090e6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400090ea:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   1400090ed:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   1400090f1:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   1400090f4:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   1400090f8:	48 89 c1             	mov    rcx,rax
   1400090fb:	e8 70 01 00 00       	call   140009270 <__mingw_mbrtowc_cp>
   140009100:	48 83 c4 40          	add    rsp,0x40
   140009104:	5d                   	pop    rbp
   140009105:	c3                   	ret
   140009106:	90                   	nop
   140009107:	90                   	nop
   140009108:	90                   	nop
   140009109:	90                   	nop
   14000910a:	90                   	nop
   14000910b:	90                   	nop
   14000910c:	90                   	nop
   14000910d:	90                   	nop
   14000910e:	90                   	nop
   14000910f:	90                   	nop

0000000140009110 <__mingw_wcrtomb_cp>:
   140009110:	55                   	push   rbp
   140009111:	48 89 e5             	mov    rbp,rsp
   140009114:	48 83 ec 50          	sub    rsp,0x50
   140009118:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000911c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009120:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009124:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   140009128:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000912d:	75 1b                	jne    14000914a <__mingw_wcrtomb_cp+0x3a>
   14000912f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009134:	74 0a                	je     140009140 <__mingw_wcrtomb_cp+0x30>
   140009136:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000913a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009140:	b8 01 00 00 00       	mov    eax,0x1
   140009145:	e9 17 01 00 00       	jmp    140009261 <__mingw_wcrtomb_cp+0x151>
   14000914a:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   14000914f:	74 21                	je     140009172 <__mingw_wcrtomb_cp+0x62>
   140009151:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140009155:	8b 00                	mov    eax,DWORD PTR [rax]
   140009157:	85 c0                	test   eax,eax
   140009159:	74 17                	je     140009172 <__mingw_wcrtomb_cp+0x62>
   14000915b:	e8 a8 04 00 00       	call   140009608 <_errno>
   140009160:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009166:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000916d:	e9 ef 00 00 00       	jmp    140009261 <__mingw_wcrtomb_cp+0x151>
   140009172:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009176:	66 85 c0             	test   ax,ax
   140009179:	75 18                	jne    140009193 <__mingw_wcrtomb_cp+0x83>
   14000917b:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009180:	74 07                	je     140009189 <__mingw_wcrtomb_cp+0x79>
   140009182:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009186:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140009189:	b8 01 00 00 00       	mov    eax,0x1
   14000918e:	e9 ce 00 00 00       	jmp    140009261 <__mingw_wcrtomb_cp+0x151>
   140009193:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   140009197:	75 2b                	jne    1400091c4 <__mingw_wcrtomb_cp+0xb4>
   140009199:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   14000919d:	66 3d ff 00          	cmp    ax,0xff
   1400091a1:	0f 87 a4 00 00 00    	ja     14000924b <__mingw_wcrtomb_cp+0x13b>
   1400091a7:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091ac:	74 0c                	je     1400091ba <__mingw_wcrtomb_cp+0xaa>
   1400091ae:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   1400091b2:	89 c2                	mov    edx,eax
   1400091b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400091b8:	88 10                	mov    BYTE PTR [rax],dl
   1400091ba:	b8 01 00 00 00       	mov    eax,0x1
   1400091bf:	e9 9d 00 00 00       	jmp    140009261 <__mingw_wcrtomb_cp+0x151>
   1400091c4:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400091cb:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   1400091d1:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   1400091d5:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   1400091d8:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   1400091dc:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   1400091e1:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   1400091e8:	00 00 
   1400091ea:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   1400091ed:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   1400091f1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400091f5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400091fa:	41 b9 01 00 00 00    	mov    r9d,0x1
   140009200:	49 89 c8             	mov    r8,rcx
   140009203:	ba 00 00 00 00       	mov    edx,0x0
   140009208:	89 c1                	mov    ecx,eax
   14000920a:	48 8b 05 5f 70 00 00 	mov    rax,QWORD PTR [rip+0x705f]        # 140010270 <__imp_WideCharToMultiByte>
   140009211:	ff d0                	call   rax
   140009213:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009216:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000921a:	74 32                	je     14000924e <__mingw_wcrtomb_cp+0x13e>
   14000921c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000921f:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   140009222:	7f 2a                	jg     14000924e <__mingw_wcrtomb_cp+0x13e>
   140009224:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009227:	85 c0                	test   eax,eax
   140009229:	75 23                	jne    14000924e <__mingw_wcrtomb_cp+0x13e>
   14000922b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000922e:	48 63 c8             	movsxd rcx,eax
   140009231:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009235:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009239:	49 89 c8             	mov    r8,rcx
   14000923c:	48 89 c1             	mov    rcx,rax
   14000923f:	e8 34 04 00 00       	call   140009678 <memcpy>
   140009244:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009247:	48 98                	cdqe
   140009249:	eb 16                	jmp    140009261 <__mingw_wcrtomb_cp+0x151>
   14000924b:	90                   	nop
   14000924c:	eb 01                	jmp    14000924f <__mingw_wcrtomb_cp+0x13f>
   14000924e:	90                   	nop
   14000924f:	e8 b4 03 00 00       	call   140009608 <_errno>
   140009254:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000925a:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009261:	48 83 c4 50          	add    rsp,0x50
   140009265:	5d                   	pop    rbp
   140009266:	c3                   	ret
   140009267:	90                   	nop
   140009268:	90                   	nop
   140009269:	90                   	nop
   14000926a:	90                   	nop
   14000926b:	90                   	nop
   14000926c:	90                   	nop
   14000926d:	90                   	nop
   14000926e:	90                   	nop
   14000926f:	90                   	nop

0000000140009270 <__mingw_mbrtowc_cp>:
   140009270:	55                   	push   rbp
   140009271:	48 89 e5             	mov    rbp,rsp
   140009274:	48 83 ec 50          	sub    rsp,0x50
   140009278:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000927c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009280:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009284:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009288:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   14000928d:	75 1b                	jne    1400092aa <__mingw_mbrtowc_cp+0x3a>
   14000928f:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   140009296:	00 
   140009297:	48 8d 05 82 22 00 00 	lea    rax,[rip+0x2282]        # 14000b520 <.rdata>
   14000929e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400092a2:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   1400092a9:	00 
   1400092aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400092ae:	8b 00                	mov    eax,DWORD PTR [rax]
   1400092b0:	3d ff 00 00 00       	cmp    eax,0xff
   1400092b5:	0f 87 b9 01 00 00    	ja     140009474 <__mingw_mbrtowc_cp+0x204>
   1400092bb:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400092c0:	75 0c                	jne    1400092ce <__mingw_mbrtowc_cp+0x5e>
   1400092c2:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   1400092c9:	e9 bc 01 00 00       	jmp    14000948a <__mingw_mbrtowc_cp+0x21a>
   1400092ce:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400092d2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400092d4:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400092d7:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   1400092db:	75 0c                	jne    1400092e9 <__mingw_mbrtowc_cp+0x79>
   1400092dd:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400092e1:	84 c0                	test   al,al
   1400092e3:	0f 85 8e 01 00 00    	jne    140009477 <__mingw_mbrtowc_cp+0x207>
   1400092e9:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   1400092ed:	75 2c                	jne    14000931b <__mingw_mbrtowc_cp+0xab>
   1400092ef:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400092f4:	74 11                	je     140009307 <__mingw_mbrtowc_cp+0x97>
   1400092f6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400092fa:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400092fd:	0f b6 d0             	movzx  edx,al
   140009300:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009304:	66 89 10             	mov    WORD PTR [rax],dx
   140009307:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000930b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000930e:	84 c0                	test   al,al
   140009310:	0f 95 c0             	setne  al
   140009313:	0f b6 c0             	movzx  eax,al
   140009316:	e9 6f 01 00 00       	jmp    14000948a <__mingw_mbrtowc_cp+0x21a>
   14000931b:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140009322:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140009329:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   14000932d:	84 c0                	test   al,al
   14000932f:	74 1a                	je     14000934b <__mingw_mbrtowc_cp+0xdb>
   140009331:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009335:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009338:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000933b:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140009342:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140009349:	eb 73                	jmp    1400093be <__mingw_mbrtowc_cp+0x14e>
   14000934b:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   14000934f:	75 5c                	jne    1400093ad <__mingw_mbrtowc_cp+0x13d>
   140009351:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009355:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009358:	0f b6 c0             	movzx  eax,al
   14000935b:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000935e:	89 c1                	mov    ecx,eax
   140009360:	e8 ab 01 00 00       	call   140009510 <__mingw_isleadbyte_cp>
   140009365:	85 c0                	test   eax,eax
   140009367:	74 44                	je     1400093ad <__mingw_mbrtowc_cp+0x13d>
   140009369:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000936d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009370:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009373:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   140009378:	77 15                	ja     14000938f <__mingw_mbrtowc_cp+0x11f>
   14000937a:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000937d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009381:	89 10                	mov    DWORD PTR [rax],edx
   140009383:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   14000938a:	e9 fb 00 00 00       	jmp    14000948a <__mingw_mbrtowc_cp+0x21a>
   14000938f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009393:	48 83 c0 01          	add    rax,0x1
   140009397:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000939a:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000939d:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400093a4:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400093ab:	eb 11                	jmp    1400093be <__mingw_mbrtowc_cp+0x14e>
   1400093ad:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093b1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093b4:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   1400093b7:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400093be:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400093c2:	84 c0                	test   al,al
   1400093c4:	75 24                	jne    1400093ea <__mingw_mbrtowc_cp+0x17a>
   1400093c6:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400093cb:	74 09                	je     1400093d6 <__mingw_mbrtowc_cp+0x166>
   1400093cd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400093d1:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   1400093d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400093da:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400093e0:	b8 00 00 00 00       	mov    eax,0x0
   1400093e5:	e9 a0 00 00 00       	jmp    14000948a <__mingw_mbrtowc_cp+0x21a>
   1400093ea:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   1400093ee:	75 08                	jne    1400093f8 <__mingw_mbrtowc_cp+0x188>
   1400093f0:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   1400093f4:	84 c0                	test   al,al
   1400093f6:	74 64                	je     14000945c <__mingw_mbrtowc_cp+0x1ec>
   1400093f8:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   1400093fe:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   140009402:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   140009406:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   140009409:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   140009410:	00 
   140009411:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   140009415:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000941a:	45 89 c1             	mov    r9d,r8d
   14000941d:	49 89 c8             	mov    r8,rcx
   140009420:	ba 08 00 00 00       	mov    edx,0x8
   140009425:	89 c1                	mov    ecx,eax
   140009427:	48 8b 05 12 6e 00 00 	mov    rax,QWORD PTR [rip+0x6e12]        # 140010240 <__imp_MultiByteToWideChar>
   14000942e:	ff d0                	call   rax
   140009430:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140009433:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   140009437:	75 26                	jne    14000945f <__mingw_mbrtowc_cp+0x1ef>
   140009439:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000943e:	74 0b                	je     14000944b <__mingw_mbrtowc_cp+0x1db>
   140009440:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   140009444:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009448:	66 89 10             	mov    WORD PTR [rax],dx
   14000944b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000944f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009455:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009458:	48 98                	cdqe
   14000945a:	eb 2e                	jmp    14000948a <__mingw_mbrtowc_cp+0x21a>
   14000945c:	90                   	nop
   14000945d:	eb 01                	jmp    140009460 <__mingw_mbrtowc_cp+0x1f0>
   14000945f:	90                   	nop
   140009460:	e8 a3 01 00 00       	call   140009608 <_errno>
   140009465:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000946b:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009472:	eb 16                	jmp    14000948a <__mingw_mbrtowc_cp+0x21a>
   140009474:	90                   	nop
   140009475:	eb 01                	jmp    140009478 <__mingw_mbrtowc_cp+0x208>
   140009477:	90                   	nop
   140009478:	e8 8b 01 00 00       	call   140009608 <_errno>
   14000947d:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009483:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000948a:	48 83 c4 50          	add    rsp,0x50
   14000948e:	5d                   	pop    rbp
   14000948f:	c3                   	ret

0000000140009490 <fallback_IsDBCSLeadByteEx>:
   140009490:	55                   	push   rbp
   140009491:	48 89 e5             	mov    rbp,rsp
   140009494:	48 83 ec 40          	sub    rsp,0x40
   140009498:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000949b:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   14000949e:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   1400094a2:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400094a5:	89 c1                	mov    ecx,eax
   1400094a7:	48 8b 05 5a 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d5a]        # 140010208 <__imp_GetCPInfo>
   1400094ae:	ff d0                	call   rax
   1400094b0:	85 c0                	test   eax,eax
   1400094b2:	74 51                	je     140009505 <fallback_IsDBCSLeadByteEx+0x75>
   1400094b4:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   1400094b7:	83 f8 02             	cmp    eax,0x2
   1400094ba:	75 49                	jne    140009505 <fallback_IsDBCSLeadByteEx+0x75>
   1400094bc:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400094c3:	eb 2c                	jmp    1400094f1 <fallback_IsDBCSLeadByteEx+0x61>
   1400094c5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400094c8:	48 98                	cdqe
   1400094ca:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400094cf:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   1400094d2:	72 19                	jb     1400094ed <fallback_IsDBCSLeadByteEx+0x5d>
   1400094d4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400094d7:	83 c0 01             	add    eax,0x1
   1400094da:	48 98                	cdqe
   1400094dc:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400094e1:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   1400094e4:	72 07                	jb     1400094ed <fallback_IsDBCSLeadByteEx+0x5d>
   1400094e6:	b8 01 00 00 00       	mov    eax,0x1
   1400094eb:	eb 1d                	jmp    14000950a <fallback_IsDBCSLeadByteEx+0x7a>
   1400094ed:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400094f1:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   1400094f5:	7f 0e                	jg     140009505 <fallback_IsDBCSLeadByteEx+0x75>
   1400094f7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400094fa:	48 98                	cdqe
   1400094fc:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009501:	84 c0                	test   al,al
   140009503:	75 c0                	jne    1400094c5 <fallback_IsDBCSLeadByteEx+0x35>
   140009505:	b8 00 00 00 00       	mov    eax,0x0
   14000950a:	48 83 c4 40          	add    rsp,0x40
   14000950e:	5d                   	pop    rbp
   14000950f:	c3                   	ret

0000000140009510 <__mingw_isleadbyte_cp>:
   140009510:	55                   	push   rbp
   140009511:	48 89 e5             	mov    rbp,rsp
   140009514:	48 83 ec 40          	sub    rsp,0x40
   140009518:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000951b:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000951e:	48 8b 05 7b 66 00 00 	mov    rax,QWORD PTR [rip+0x667b]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009525:	48 85 c0             	test   rax,rax
   140009528:	75 71                	jne    14000959b <__mingw_isleadbyte_cp+0x8b>
   14000952a:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140009531:	00 
   140009532:	48 8d 05 f7 1f 00 00 	lea    rax,[rip+0x1ff7]        # 14000b530 <.rdata>
   140009539:	48 89 c1             	mov    rcx,rax
   14000953c:	48 8b 05 d5 6c 00 00 	mov    rax,QWORD PTR [rip+0x6cd5]        # 140010218 <__imp_GetModuleHandleA>
   140009543:	ff d0                	call   rax
   140009545:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140009549:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000954e:	74 1b                	je     14000956b <__mingw_isleadbyte_cp+0x5b>
   140009550:	48 8d 15 e6 1f 00 00 	lea    rdx,[rip+0x1fe6]        # 14000b53d <.rdata+0xd>
   140009557:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000955b:	48 89 c1             	mov    rcx,rax
   14000955e:	48 8b 05 bb 6c 00 00 	mov    rax,QWORD PTR [rip+0x6cbb]        # 140010220 <__imp_GetProcAddress>
   140009565:	ff d0                	call   rax
   140009567:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000956b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140009570:	75 0b                	jne    14000957d <__mingw_isleadbyte_cp+0x6d>
   140009572:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 140009490 <fallback_IsDBCSLeadByteEx>
   140009579:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000957d:	48 8d 05 1c 66 00 00 	lea    rax,[rip+0x661c]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009584:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140009588:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000958c:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140009590:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140009594:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140009598:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000959b:	4c 8b 05 fe 65 00 00 	mov    r8,QWORD PTR [rip+0x65fe]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400095a2:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400095a5:	0f b6 d0             	movzx  edx,al
   1400095a8:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400095ab:	89 c1                	mov    ecx,eax
   1400095ad:	41 ff d0             	call   r8
   1400095b0:	48 83 c4 40          	add    rsp,0x40
   1400095b4:	5d                   	pop    rbp
   1400095b5:	c3                   	ret
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

00000001400095c0 <__C_specific_handler>:
   1400095c0:	ff 25 ba 6c 00 00    	jmp    QWORD PTR [rip+0x6cba]        # 140010280 <__imp___C_specific_handler>
   1400095c6:	90                   	nop
   1400095c7:	90                   	nop

00000001400095c8 <___lc_codepage_func>:
   1400095c8:	ff 25 ba 6c 00 00    	jmp    QWORD PTR [rip+0x6cba]        # 140010288 <__imp____lc_codepage_func>
   1400095ce:	90                   	nop
   1400095cf:	90                   	nop

00000001400095d0 <___mb_cur_max_func>:
   1400095d0:	ff 25 ba 6c 00 00    	jmp    QWORD PTR [rip+0x6cba]        # 140010290 <__imp____mb_cur_max_func>
   1400095d6:	90                   	nop
   1400095d7:	90                   	nop

00000001400095d8 <__getmainargs>:
   1400095d8:	ff 25 ba 6c 00 00    	jmp    QWORD PTR [rip+0x6cba]        # 140010298 <__imp___getmainargs>
   1400095de:	90                   	nop
   1400095df:	90                   	nop

00000001400095e0 <__iob_func>:
   1400095e0:	ff 25 c2 6c 00 00    	jmp    QWORD PTR [rip+0x6cc2]        # 1400102a8 <__imp___iob_func>
   1400095e6:	90                   	nop
   1400095e7:	90                   	nop

00000001400095e8 <__set_app_type>:
   1400095e8:	ff 25 c2 6c 00 00    	jmp    QWORD PTR [rip+0x6cc2]        # 1400102b0 <__imp___set_app_type>
   1400095ee:	90                   	nop
   1400095ef:	90                   	nop

00000001400095f0 <__setusermatherr>:
   1400095f0:	ff 25 c2 6c 00 00    	jmp    QWORD PTR [rip+0x6cc2]        # 1400102b8 <__imp___setusermatherr>
   1400095f6:	90                   	nop
   1400095f7:	90                   	nop

00000001400095f8 <_amsg_exit>:
   1400095f8:	ff 25 c2 6c 00 00    	jmp    QWORD PTR [rip+0x6cc2]        # 1400102c0 <__imp__amsg_exit>
   1400095fe:	90                   	nop
   1400095ff:	90                   	nop

0000000140009600 <_cexit>:
   140009600:	ff 25 c2 6c 00 00    	jmp    QWORD PTR [rip+0x6cc2]        # 1400102c8 <__imp__cexit>
   140009606:	90                   	nop
   140009607:	90                   	nop

0000000140009608 <_errno>:
   140009608:	ff 25 ca 6c 00 00    	jmp    QWORD PTR [rip+0x6cca]        # 1400102d8 <__imp__errno>
   14000960e:	90                   	nop
   14000960f:	90                   	nop

0000000140009610 <_initterm>:
   140009610:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 1400102e8 <__imp__initterm>
   140009616:	90                   	nop
   140009617:	90                   	nop

0000000140009618 <_lock>:
   140009618:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 1400102f0 <__imp__lock>
   14000961e:	90                   	nop
   14000961f:	90                   	nop

0000000140009620 <_unlock>:
   140009620:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 1400102f8 <__imp__unlock>
   140009626:	90                   	nop
   140009627:	90                   	nop

0000000140009628 <_crt_atexit>:
   140009628:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010300 <__imp__crt_atexit>
   14000962e:	90                   	nop
   14000962f:	90                   	nop

0000000140009630 <abort>:
   140009630:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010308 <__imp_abort>
   140009636:	90                   	nop
   140009637:	90                   	nop

0000000140009638 <calloc>:
   140009638:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010310 <__imp_calloc>
   14000963e:	90                   	nop
   14000963f:	90                   	nop

0000000140009640 <exit>:
   140009640:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010318 <__imp_exit>
   140009646:	90                   	nop
   140009647:	90                   	nop

0000000140009648 <fflush>:
   140009648:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010320 <__imp_fflush>
   14000964e:	90                   	nop
   14000964f:	90                   	nop

0000000140009650 <fprintf>:
   140009650:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010328 <__imp_fprintf>
   140009656:	90                   	nop
   140009657:	90                   	nop

0000000140009658 <fputc>:
   140009658:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010330 <__imp_fputc>
   14000965e:	90                   	nop
   14000965f:	90                   	nop

0000000140009660 <free>:
   140009660:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010338 <__imp_free>
   140009666:	90                   	nop
   140009667:	90                   	nop

0000000140009668 <localeconv>:
   140009668:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010340 <__imp_localeconv>
   14000966e:	90                   	nop
   14000966f:	90                   	nop

0000000140009670 <malloc>:
   140009670:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010348 <__imp_malloc>
   140009676:	90                   	nop
   140009677:	90                   	nop

0000000140009678 <memcpy>:
   140009678:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010350 <__imp_memcpy>
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <memset>:
   140009680:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010358 <__imp_memset>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <setvbuf>:
   140009688:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010360 <__imp_setvbuf>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <signal>:
   140009690:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010368 <__imp_signal>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <strerror>:
   140009698:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010370 <__imp_strerror>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <strlen>:
   1400096a0:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010378 <__imp_strlen>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <strncmp>:
   1400096a8:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010380 <__imp_strncmp>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <vfprintf>:
   1400096b0:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010388 <__imp_vfprintf>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <wcslen>:
   1400096b8:	ff 25 d2 6c 00 00    	jmp    QWORD PTR [rip+0x6cd2]        # 140010390 <__imp_wcslen>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <WideCharToMultiByte>:
   1400096c0:	ff 25 aa 6b 00 00    	jmp    QWORD PTR [rip+0x6baa]        # 140010270 <__imp_WideCharToMultiByte>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <VirtualQuery>:
   1400096c8:	ff 25 9a 6b 00 00    	jmp    QWORD PTR [rip+0x6b9a]        # 140010268 <__imp_VirtualQuery>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <VirtualProtect>:
   1400096d0:	ff 25 8a 6b 00 00    	jmp    QWORD PTR [rip+0x6b8a]        # 140010260 <__imp_VirtualProtect>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <TlsGetValue>:
   1400096d8:	ff 25 7a 6b 00 00    	jmp    QWORD PTR [rip+0x6b7a]        # 140010258 <__imp_TlsGetValue>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <Sleep>:
   1400096e0:	ff 25 6a 6b 00 00    	jmp    QWORD PTR [rip+0x6b6a]        # 140010250 <__imp_Sleep>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop

00000001400096e8 <SetUnhandledExceptionFilter>:
   1400096e8:	ff 25 5a 6b 00 00    	jmp    QWORD PTR [rip+0x6b5a]        # 140010248 <__imp_SetUnhandledExceptionFilter>
   1400096ee:	90                   	nop
   1400096ef:	90                   	nop

00000001400096f0 <MultiByteToWideChar>:
   1400096f0:	ff 25 4a 6b 00 00    	jmp    QWORD PTR [rip+0x6b4a]        # 140010240 <__imp_MultiByteToWideChar>
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop

00000001400096f8 <LoadLibraryA>:
   1400096f8:	ff 25 3a 6b 00 00    	jmp    QWORD PTR [rip+0x6b3a]        # 140010238 <__imp_LoadLibraryA>
   1400096fe:	90                   	nop
   1400096ff:	90                   	nop

0000000140009700 <LeaveCriticalSection>:
   140009700:	ff 25 2a 6b 00 00    	jmp    QWORD PTR [rip+0x6b2a]        # 140010230 <__imp_LeaveCriticalSection>
   140009706:	90                   	nop
   140009707:	90                   	nop

0000000140009708 <InitializeCriticalSection>:
   140009708:	ff 25 1a 6b 00 00    	jmp    QWORD PTR [rip+0x6b1a]        # 140010228 <__imp_InitializeCriticalSection>
   14000970e:	90                   	nop
   14000970f:	90                   	nop

0000000140009710 <GetProcAddress>:
   140009710:	ff 25 0a 6b 00 00    	jmp    QWORD PTR [rip+0x6b0a]        # 140010220 <__imp_GetProcAddress>
   140009716:	90                   	nop
   140009717:	90                   	nop

0000000140009718 <GetModuleHandleA>:
   140009718:	ff 25 fa 6a 00 00    	jmp    QWORD PTR [rip+0x6afa]        # 140010218 <__imp_GetModuleHandleA>
   14000971e:	90                   	nop
   14000971f:	90                   	nop

0000000140009720 <GetLastError>:
   140009720:	ff 25 ea 6a 00 00    	jmp    QWORD PTR [rip+0x6aea]        # 140010210 <__imp_GetLastError>
   140009726:	90                   	nop
   140009727:	90                   	nop

0000000140009728 <GetCPInfo>:
   140009728:	ff 25 da 6a 00 00    	jmp    QWORD PTR [rip+0x6ada]        # 140010208 <__imp_GetCPInfo>
   14000972e:	90                   	nop
   14000972f:	90                   	nop

0000000140009730 <FreeLibrary>:
   140009730:	ff 25 ca 6a 00 00    	jmp    QWORD PTR [rip+0x6aca]        # 140010200 <__imp_FreeLibrary>
   140009736:	90                   	nop
   140009737:	90                   	nop

0000000140009738 <EnterCriticalSection>:
   140009738:	ff 25 ba 6a 00 00    	jmp    QWORD PTR [rip+0x6aba]        # 1400101f8 <__imp_EnterCriticalSection>
   14000973e:	90                   	nop
   14000973f:	90                   	nop

0000000140009740 <DeleteCriticalSection>:
   140009740:	ff 25 aa 6a 00 00    	jmp    QWORD PTR [rip+0x6aaa]        # 1400101f0 <__IAT_start__>
   140009746:	90                   	nop
   140009747:	90                   	nop
   140009748:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000974f:	00 

0000000140009750 <register_frame_ctor>:
   140009750:	e9 1b 7f ff ff       	jmp    140001670 <__gcc_register_frame>
   140009755:	90                   	nop
   140009756:	90                   	nop
   140009757:	90                   	nop
   140009758:	90                   	nop
   140009759:	90                   	nop
   14000975a:	90                   	nop
   14000975b:	90                   	nop
   14000975c:	90                   	nop
   14000975d:	90                   	nop
   14000975e:	90                   	nop
   14000975f:	90                   	nop
