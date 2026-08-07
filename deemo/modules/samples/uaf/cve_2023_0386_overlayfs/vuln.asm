
C:\Users\Administrator\Desktop\BinMind\round2\samples\uaf\cve_2023_0386_overlayfs\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 af 86 00 00       	call   1400096d8 <fflush>
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
   1400010e8:	48 8b 05 59 f1 00 00 	mov    rax,QWORD PTR [rip+0xf159]        # 140010248 <__imp_Sleep>
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
   14000113b:	e8 48 85 00 00       	call   140009688 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 48 7f 00 00       	call   1400090b0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 8f 85 00 00       	call   140009710 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 27 85 00 00       	call   1400096c0 <abort>
   140001199:	e8 12 12 00 00       	call   1400023b0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 91 f0 00 00 	mov    rax,QWORD PTR [rip+0xf091]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 86 7e 00 00       	call   140009050 <_set_invalid_parameter_handler>
   1400011ca:	e8 f1 1a 00 00       	call   140002cc0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 87 84 00 00       	call   140009678 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 7b 84 00 00       	call   140009678 <__set_app_type>
   1400011fd:	e8 fe 7c 00 00       	call   140008f00 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 fe 7c 00 00       	call   140008f10 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 6e 07 00 00       	call   140001990 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 53 84 00 00       	call   140009688 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 78 12 00 00       	call   1400024ca <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 26 7e 00 00       	call   140009090 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 20 7c 00 00       	call   140008ea0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 fa 83 00 00       	call   140009688 <_amsg_exit>
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
   1400012cb:	e8 98 83 00 00       	call   140009668 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 a5 83 00 00       	call   140009688 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 7e 83 00 00       	call   140009688 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 80 83 00 00       	call   1400096a0 <_initterm>
   140001320:	e8 42 06 00 00       	call   140001967 <__main>
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
   14000138d:	e8 8e 7b 00 00       	call   140008f20 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 2c 04 00 00       	call   1400017e6 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 ff 82 00 00       	call   1400096d0 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 b0 82 00 00       	call   140009690 <_cexit>
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
   140001511:	e8 ea 81 00 00       	call   140009700 <malloc>
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
   14000155c:	e8 c7 81 00 00       	call   140009728 <strlen>
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
   140001585:	e8 76 81 00 00       	call   140009700 <malloc>
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
   1400015e8:	e8 1b 81 00 00       	call   140009708 <memcpy>
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
   140001642:	e8 71 80 00 00       	call   1400096b8 <_crt_atexit>
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
   140001682:	ff 15 88 eb 00 00    	call   QWORD PTR [rip+0xeb88]        # 140010210 <__imp_GetModuleHandleA>
   140001688:	48 89 c3             	mov    rbx,rax
   14000168b:	48 85 c0             	test   rax,rax
   14000168e:	74 70                	je     140001700 <__gcc_register_frame+0x90>
   140001690:	48 8d 0d 69 99 00 00 	lea    rcx,[rip+0x9969]        # 14000b000 <.rdata>
   140001697:	ff 15 93 eb 00 00    	call   QWORD PTR [rip+0xeb93]        # 140010230 <__imp_LoadLibraryA>
   14000169d:	4c 8b 0d 74 eb 00 00 	mov    r9,QWORD PTR [rip+0xeb74]        # 140010218 <__imp_GetProcAddress>
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
   14000174e:	48 ff 25 a3 ea 00 00 	rex.W jmp QWORD PTR [rip+0xeaa3]        # 1400101f8 <__imp_FreeLibrary>
   140001755:	0f 1f 00             	nop    DWORD PTR [rax]
   140001758:	48 83 c4 20          	add    rsp,0x20
   14000175c:	5d                   	pop    rbp
   14000175d:	c3                   	ret
   14000175e:	90                   	nop
   14000175f:	90                   	nop

0000000140001760 <ovl_dentry_release>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 20          	sub    rsp,0x20
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001770:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001774:	48 89 c1             	mov    rcx,rax
   140001777:	e8 74 7f 00 00       	call   1400096f0 <free>
   14000177c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001780:	48 89 c1             	mov    rcx,rax
   140001783:	e8 68 7f 00 00       	call   1400096f0 <free>
   140001788:	90                   	nop
   140001789:	48 83 c4 20          	add    rsp,0x20
   14000178d:	5d                   	pop    rbp
   14000178e:	c3                   	ret

000000014000178f <ovl_do_copy>:
   14000178f:	55                   	push   rbp
   140001790:	48 89 e5             	mov    rbp,rsp
   140001793:	48 83 ec 20          	sub    rsp,0x20
   140001797:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000179b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000179f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017a2:	48 89 c1             	mov    rcx,rax
   1400017a5:	e8 b6 ff ff ff       	call   140001760 <ovl_dentry_release>
   1400017aa:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017ae:	c7 40 08 01 00 00 00 	mov    DWORD PTR [rax+0x8],0x1
   1400017b5:	b8 00 00 00 00       	mov    eax,0x0
   1400017ba:	48 83 c4 20          	add    rsp,0x20
   1400017be:	5d                   	pop    rbp
   1400017bf:	c3                   	ret

00000001400017c0 <ovl_lookup_upper>:
   1400017c0:	55                   	push   rbp
   1400017c1:	48 89 e5             	mov    rbp,rsp
   1400017c4:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400017c8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017cc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400017cf:	85 c0                	test   eax,eax
   1400017d1:	74 0c                	je     1400017df <ovl_lookup_upper+0x1f>
   1400017d3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017d7:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017da:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400017dd:	eb 05                	jmp    1400017e4 <ovl_lookup_upper+0x24>
   1400017df:	b8 00 00 00 00       	mov    eax,0x0
   1400017e4:	5d                   	pop    rbp
   1400017e5:	c3                   	ret

00000001400017e6 <main>:
   1400017e6:	55                   	push   rbp
   1400017e7:	53                   	push   rbx
   1400017e8:	48 83 ec 38          	sub    rsp,0x38
   1400017ec:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   1400017f1:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   1400017f4:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400017f8:	e8 6a 01 00 00       	call   140001967 <__main>
   1400017fd:	b9 10 00 00 00       	mov    ecx,0x10
   140001802:	e8 f9 7e 00 00       	call   140009700 <malloc>
   140001807:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000180b:	b9 20 00 00 00       	mov    ecx,0x20
   140001810:	e8 eb 7e 00 00       	call   140009700 <malloc>
   140001815:	48 89 c2             	mov    rdx,rax
   140001818:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000181c:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000181f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001823:	48 8b 18             	mov    rbx,QWORD PTR [rax]
   140001826:	b9 20 00 00 00       	mov    ecx,0x20
   14000182b:	e8 d0 7e 00 00       	call   140009700 <malloc>
   140001830:	48 89 43 18          	mov    QWORD PTR [rbx+0x18],rax
   140001834:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001838:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000183b:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   140001842:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001846:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001849:	c7 00 75 70 70 65    	mov    DWORD PTR [rax],0x65707075
   14000184f:	66 c7 40 04 72 00    	mov    WORD PTR [rax+0x4],0x72
   140001855:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001859:	c7 40 08 00 00 00 00 	mov    DWORD PTR [rax+0x8],0x0
   140001860:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001864:	48 89 c1             	mov    rcx,rax
   140001867:	e8 23 ff ff ff       	call   14000178f <ovl_do_copy>
   14000186c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001870:	48 89 c1             	mov    rcx,rax
   140001873:	e8 48 ff ff ff       	call   1400017c0 <ovl_lookup_upper>
   140001878:	89 c2                	mov    edx,eax
   14000187a:	48 8d 05 cf 97 00 00 	lea    rax,[rip+0x97cf]        # 14000b050 <.rdata>
   140001881:	48 89 c1             	mov    rcx,rax
   140001884:	e8 37 19 00 00       	call   1400031c0 <__mingw_printf>
   140001889:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000188d:	48 89 c1             	mov    rcx,rax
   140001890:	e8 5b 7e 00 00       	call   1400096f0 <free>
   140001895:	b8 00 00 00 00       	mov    eax,0x0
   14000189a:	48 83 c4 38          	add    rsp,0x38
   14000189e:	5b                   	pop    rbx
   14000189f:	5d                   	pop    rbp
   1400018a0:	c3                   	ret
   1400018a1:	90                   	nop
   1400018a2:	90                   	nop
   1400018a3:	90                   	nop
   1400018a4:	90                   	nop
   1400018a5:	90                   	nop
   1400018a6:	90                   	nop
   1400018a7:	90                   	nop
   1400018a8:	90                   	nop
   1400018a9:	90                   	nop
   1400018aa:	90                   	nop
   1400018ab:	90                   	nop
   1400018ac:	90                   	nop
   1400018ad:	90                   	nop
   1400018ae:	90                   	nop
   1400018af:	90                   	nop

00000001400018b0 <__do_global_dtors>:
   1400018b0:	55                   	push   rbp
   1400018b1:	48 89 e5             	mov    rbp,rsp
   1400018b4:	48 83 ec 20          	sub    rsp,0x20
   1400018b8:	eb 1e                	jmp    1400018d8 <__do_global_dtors+0x28>
   1400018ba:	48 8b 05 4f 87 00 00 	mov    rax,QWORD PTR [rip+0x874f]        # 14000a010 <p.0>
   1400018c1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018c4:	ff d0                	call   rax
   1400018c6:	48 8b 05 43 87 00 00 	mov    rax,QWORD PTR [rip+0x8743]        # 14000a010 <p.0>
   1400018cd:	48 83 c0 08          	add    rax,0x8
   1400018d1:	48 89 05 38 87 00 00 	mov    QWORD PTR [rip+0x8738],rax        # 14000a010 <p.0>
   1400018d8:	48 8b 05 31 87 00 00 	mov    rax,QWORD PTR [rip+0x8731]        # 14000a010 <p.0>
   1400018df:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018e2:	48 85 c0             	test   rax,rax
   1400018e5:	75 d3                	jne    1400018ba <__do_global_dtors+0xa>
   1400018e7:	90                   	nop
   1400018e8:	90                   	nop
   1400018e9:	48 83 c4 20          	add    rsp,0x20
   1400018ed:	5d                   	pop    rbp
   1400018ee:	c3                   	ret

00000001400018ef <__do_global_ctors>:
   1400018ef:	55                   	push   rbp
   1400018f0:	48 89 e5             	mov    rbp,rsp
   1400018f3:	48 83 ec 30          	sub    rsp,0x30
   1400018f7:	48 8b 05 72 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c72]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018fe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001901:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001904:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001908:	75 25                	jne    14000192f <__do_global_ctors+0x40>
   14000190a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001911:	eb 04                	jmp    140001917 <__do_global_ctors+0x28>
   140001913:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001917:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000191a:	8d 50 01             	lea    edx,[rax+0x1]
   14000191d:	48 8b 05 4c 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c4c]        # 14000b570 <.refptr.__CTOR_LIST__>
   140001924:	89 d2                	mov    edx,edx
   140001926:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000192a:	48 85 c0             	test   rax,rax
   14000192d:	75 e4                	jne    140001913 <__do_global_ctors+0x24>
   14000192f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001932:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001935:	eb 14                	jmp    14000194b <__do_global_ctors+0x5c>
   140001937:	48 8b 05 32 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c32]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000193e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001941:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001945:	ff d0                	call   rax
   140001947:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000194b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000194f:	75 e6                	jne    140001937 <__do_global_ctors+0x48>
   140001951:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400018b0 <__do_global_dtors>
   140001958:	48 89 c1             	mov    rcx,rax
   14000195b:	e8 cf fc ff ff       	call   14000162f <atexit>
   140001960:	90                   	nop
   140001961:	48 83 c4 30          	add    rsp,0x30
   140001965:	5d                   	pop    rbp
   140001966:	c3                   	ret

0000000140001967 <__main>:
   140001967:	55                   	push   rbp
   140001968:	48 89 e5             	mov    rbp,rsp
   14000196b:	48 83 ec 20          	sub    rsp,0x20
   14000196f:	8b 05 0b d7 00 00    	mov    eax,DWORD PTR [rip+0xd70b]        # 14000f080 <initialized>
   140001975:	85 c0                	test   eax,eax
   140001977:	75 0f                	jne    140001988 <__main+0x21>
   140001979:	c7 05 fd d6 00 00 01 	mov    DWORD PTR [rip+0xd6fd],0x1        # 14000f080 <initialized>
   140001980:	00 00 00 
   140001983:	e8 67 ff ff ff       	call   1400018ef <__do_global_ctors>
   140001988:	90                   	nop
   140001989:	48 83 c4 20          	add    rsp,0x20
   14000198d:	5d                   	pop    rbp
   14000198e:	c3                   	ret
   14000198f:	90                   	nop

0000000140001990 <_setargv>:
   140001990:	55                   	push   rbp
   140001991:	48 89 e5             	mov    rbp,rsp
   140001994:	b8 00 00 00 00       	mov    eax,0x0
   140001999:	5d                   	pop    rbp
   14000199a:	c3                   	ret
   14000199b:	90                   	nop
   14000199c:	90                   	nop
   14000199d:	90                   	nop
   14000199e:	90                   	nop
   14000199f:	90                   	nop

00000001400019a0 <__dyn_tls_init>:
   1400019a0:	55                   	push   rbp
   1400019a1:	48 89 e5             	mov    rbp,rsp
   1400019a4:	48 83 ec 30          	sub    rsp,0x30
   1400019a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019ac:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019af:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019b3:	48 8b 05 96 9b 00 00 	mov    rax,QWORD PTR [rip+0x9b96]        # 14000b550 <.refptr._CRT_MT>
   1400019ba:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019bc:	83 f8 02             	cmp    eax,0x2
   1400019bf:	74 0d                	je     1400019ce <__dyn_tls_init+0x2e>
   1400019c1:	48 8b 05 88 9b 00 00 	mov    rax,QWORD PTR [rip+0x9b88]        # 14000b550 <.refptr._CRT_MT>
   1400019c8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400019ce:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   1400019d2:	74 1e                	je     1400019f2 <__dyn_tls_init+0x52>
   1400019d4:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   1400019d8:	75 5b                	jne    140001a35 <__dyn_tls_init+0x95>
   1400019da:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019de:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019e5:	49 89 c8             	mov    r8,rcx
   1400019e8:	48 89 c1             	mov    rcx,rax
   1400019eb:	e8 d1 11 00 00       	call   140002bc1 <__mingw_TLScallback>
   1400019f0:	eb 43                	jmp    140001a35 <__dyn_tls_init+0x95>
   1400019f2:	48 8d 05 df 9e 00 00 	lea    rax,[rip+0x9edf]        # 14000b8d8 <___crt_xd_start__>
   1400019f9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400019fd:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001a02:	eb 22                	jmp    140001a26 <__dyn_tls_init+0x86>
   140001a04:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001a08:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001a0c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001a10:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a13:	48 85 c0             	test   rax,rax
   140001a16:	74 09                	je     140001a21 <__dyn_tls_init+0x81>
   140001a18:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001a1c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a1f:	ff d0                	call   rax
   140001a21:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001a26:	48 8d 05 b3 9e 00 00 	lea    rax,[rip+0x9eb3]        # 14000b8e0 <__xd_z>
   140001a2d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001a31:	75 d1                	jne    140001a04 <__dyn_tls_init+0x64>
   140001a33:	eb 01                	jmp    140001a36 <__dyn_tls_init+0x96>
   140001a35:	90                   	nop
   140001a36:	48 83 c4 30          	add    rsp,0x30
   140001a3a:	5d                   	pop    rbp
   140001a3b:	c3                   	ret

0000000140001a3c <__tlregdtor>:
   140001a3c:	55                   	push   rbp
   140001a3d:	48 89 e5             	mov    rbp,rsp
   140001a40:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a44:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001a49:	75 07                	jne    140001a52 <__tlregdtor+0x16>
   140001a4b:	b8 00 00 00 00       	mov    eax,0x0
   140001a50:	eb 05                	jmp    140001a57 <__tlregdtor+0x1b>
   140001a52:	b8 00 00 00 00       	mov    eax,0x0
   140001a57:	5d                   	pop    rbp
   140001a58:	c3                   	ret

0000000140001a59 <__dyn_tls_dtor>:
   140001a59:	55                   	push   rbp
   140001a5a:	48 89 e5             	mov    rbp,rsp
   140001a5d:	48 83 ec 20          	sub    rsp,0x20
   140001a61:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a65:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a68:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a6c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a70:	74 06                	je     140001a78 <__dyn_tls_dtor+0x1f>
   140001a72:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a76:	75 18                	jne    140001a90 <__dyn_tls_dtor+0x37>
   140001a78:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a7c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a7f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a83:	49 89 c8             	mov    r8,rcx
   140001a86:	48 89 c1             	mov    rcx,rax
   140001a89:	e8 33 11 00 00       	call   140002bc1 <__mingw_TLScallback>
   140001a8e:	eb 01                	jmp    140001a91 <__dyn_tls_dtor+0x38>
   140001a90:	90                   	nop
   140001a91:	48 83 c4 20          	add    rsp,0x20
   140001a95:	5d                   	pop    rbp
   140001a96:	c3                   	ret
   140001a97:	90                   	nop
   140001a98:	90                   	nop
   140001a99:	90                   	nop
   140001a9a:	90                   	nop
   140001a9b:	90                   	nop
   140001a9c:	90                   	nop
   140001a9d:	90                   	nop
   140001a9e:	90                   	nop
   140001a9f:	90                   	nop

0000000140001aa0 <_matherr>:
   140001aa0:	55                   	push   rbp
   140001aa1:	53                   	push   rbx
   140001aa2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001aa9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001aae:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001ab2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001ab6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001abb:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001abf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ac3:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ac5:	83 f8 06             	cmp    eax,0x6
   140001ac8:	74 56                	je     140001b20 <_matherr+0x80>
   140001aca:	83 f8 06             	cmp    eax,0x6
   140001acd:	7f 78                	jg     140001b47 <_matherr+0xa7>
   140001acf:	83 f8 05             	cmp    eax,0x5
   140001ad2:	74 59                	je     140001b2d <_matherr+0x8d>
   140001ad4:	83 f8 05             	cmp    eax,0x5
   140001ad7:	7f 6e                	jg     140001b47 <_matherr+0xa7>
   140001ad9:	83 f8 04             	cmp    eax,0x4
   140001adc:	74 5c                	je     140001b3a <_matherr+0x9a>
   140001ade:	83 f8 04             	cmp    eax,0x4
   140001ae1:	7f 64                	jg     140001b47 <_matherr+0xa7>
   140001ae3:	83 f8 03             	cmp    eax,0x3
   140001ae6:	74 2b                	je     140001b13 <_matherr+0x73>
   140001ae8:	83 f8 03             	cmp    eax,0x3
   140001aeb:	7f 5a                	jg     140001b47 <_matherr+0xa7>
   140001aed:	83 f8 01             	cmp    eax,0x1
   140001af0:	74 07                	je     140001af9 <_matherr+0x59>
   140001af2:	83 f8 02             	cmp    eax,0x2
   140001af5:	74 0f                	je     140001b06 <_matherr+0x66>
   140001af7:	eb 4e                	jmp    140001b47 <_matherr+0xa7>
   140001af9:	48 8d 05 a0 95 00 00 	lea    rax,[rip+0x95a0]        # 14000b0a0 <.rdata>
   140001b00:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b04:	eb 4d                	jmp    140001b53 <_matherr+0xb3>
   140001b06:	48 8d 05 b2 95 00 00 	lea    rax,[rip+0x95b2]        # 14000b0bf <.rdata+0x1f>
   140001b0d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b11:	eb 40                	jmp    140001b53 <_matherr+0xb3>
   140001b13:	48 8d 05 c6 95 00 00 	lea    rax,[rip+0x95c6]        # 14000b0e0 <.rdata+0x40>
   140001b1a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b1e:	eb 33                	jmp    140001b53 <_matherr+0xb3>
   140001b20:	48 8d 05 d9 95 00 00 	lea    rax,[rip+0x95d9]        # 14000b100 <.rdata+0x60>
   140001b27:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b2b:	eb 26                	jmp    140001b53 <_matherr+0xb3>
   140001b2d:	48 8d 05 f4 95 00 00 	lea    rax,[rip+0x95f4]        # 14000b128 <.rdata+0x88>
   140001b34:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b38:	eb 19                	jmp    140001b53 <_matherr+0xb3>
   140001b3a:	48 8d 05 0f 96 00 00 	lea    rax,[rip+0x960f]        # 14000b150 <.rdata+0xb0>
   140001b41:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b45:	eb 0c                	jmp    140001b53 <_matherr+0xb3>
   140001b47:	48 8d 05 38 96 00 00 	lea    rax,[rip+0x9638]        # 14000b186 <.rdata+0xe6>
   140001b4e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b52:	90                   	nop
   140001b53:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b57:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b5d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b61:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b66:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b6a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b6f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b73:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b77:	b9 02 00 00 00       	mov    ecx,0x2
   140001b7c:	e8 2f 75 00 00       	call   1400090b0 <__acrt_iob_func>
   140001b81:	48 89 c1             	mov    rcx,rax
   140001b84:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b88:	48 8d 05 09 96 00 00 	lea    rax,[rip+0x9609]        # 14000b198 <.rdata+0xf8>
   140001b8f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b96:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b9c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001ba2:	49 89 d9             	mov    r9,rbx
   140001ba5:	49 89 d0             	mov    r8,rdx
   140001ba8:	48 89 c2             	mov    rdx,rax
   140001bab:	e8 30 7b 00 00       	call   1400096e0 <fprintf>
   140001bb0:	b8 00 00 00 00       	mov    eax,0x0
   140001bb5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001bb9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001bbd:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001bc2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001bc9:	5b                   	pop    rbx
   140001bca:	5d                   	pop    rbp
   140001bcb:	c3                   	ret
   140001bcc:	90                   	nop
   140001bcd:	90                   	nop
   140001bce:	90                   	nop
   140001bcf:	90                   	nop

0000000140001bd0 <__report_error>:
   140001bd0:	55                   	push   rbp
   140001bd1:	53                   	push   rbx
   140001bd2:	48 83 ec 38          	sub    rsp,0x38
   140001bd6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001bdb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001bdf:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001be3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001be7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001beb:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001bef:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bf3:	b9 02 00 00 00       	mov    ecx,0x2
   140001bf8:	e8 b3 74 00 00       	call   1400090b0 <__acrt_iob_func>
   140001bfd:	48 89 c1             	mov    rcx,rax
   140001c00:	48 8d 05 c9 95 00 00 	lea    rax,[rip+0x95c9]        # 14000b1d0 <.rdata>
   140001c07:	48 89 c2             	mov    rdx,rax
   140001c0a:	e8 d1 7a 00 00       	call   1400096e0 <fprintf>
   140001c0f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001c13:	b9 02 00 00 00       	mov    ecx,0x2
   140001c18:	e8 93 74 00 00       	call   1400090b0 <__acrt_iob_func>
   140001c1d:	48 89 c1             	mov    rcx,rax
   140001c20:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001c24:	49 89 d8             	mov    r8,rbx
   140001c27:	48 89 c2             	mov    rdx,rax
   140001c2a:	e8 09 7b 00 00       	call   140009738 <vfprintf>
   140001c2f:	e8 8c 7a 00 00       	call   1400096c0 <abort>
   140001c34:	90                   	nop

0000000140001c35 <mark_section_writable>:
   140001c35:	55                   	push   rbp
   140001c36:	48 89 e5             	mov    rbp,rsp
   140001c39:	48 83 ec 60          	sub    rsp,0x60
   140001c3d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001c41:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001c48:	e9 82 00 00 00       	jmp    140001ccf <mark_section_writable+0x9a>
   140001c4d:	48 8b 0d 8c d4 00 00 	mov    rcx,QWORD PTR [rip+0xd48c]        # 14000f0e0 <the_secs>
   140001c54:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c57:	48 63 d0             	movsxd rdx,eax
   140001c5a:	48 89 d0             	mov    rax,rdx
   140001c5d:	48 c1 e0 02          	shl    rax,0x2
   140001c61:	48 01 d0             	add    rax,rdx
   140001c64:	48 c1 e0 03          	shl    rax,0x3
   140001c68:	48 01 c8             	add    rax,rcx
   140001c6b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c6f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c73:	72 56                	jb     140001ccb <mark_section_writable+0x96>
   140001c75:	48 8b 0d 64 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd464]        # 14000f0e0 <the_secs>
   140001c7c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c7f:	48 63 d0             	movsxd rdx,eax
   140001c82:	48 89 d0             	mov    rax,rdx
   140001c85:	48 c1 e0 02          	shl    rax,0x2
   140001c89:	48 01 d0             	add    rax,rdx
   140001c8c:	48 c1 e0 03          	shl    rax,0x3
   140001c90:	48 01 c8             	add    rax,rcx
   140001c93:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c97:	4c 8b 05 42 d4 00 00 	mov    r8,QWORD PTR [rip+0xd442]        # 14000f0e0 <the_secs>
   140001c9e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ca1:	48 63 d0             	movsxd rdx,eax
   140001ca4:	48 89 d0             	mov    rax,rdx
   140001ca7:	48 c1 e0 02          	shl    rax,0x2
   140001cab:	48 01 d0             	add    rax,rdx
   140001cae:	48 c1 e0 03          	shl    rax,0x3
   140001cb2:	4c 01 c0             	add    rax,r8
   140001cb5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001cb9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001cbc:	89 c0                	mov    eax,eax
   140001cbe:	48 01 c8             	add    rax,rcx
   140001cc1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001cc5:	0f 82 41 02 00 00    	jb     140001f0c <mark_section_writable+0x2d7>
   140001ccb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001ccf:	8b 05 13 d4 00 00    	mov    eax,DWORD PTR [rip+0xd413]        # 14000f0e8 <maxSections>
   140001cd5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001cd8:	0f 8c 6f ff ff ff    	jl     140001c4d <mark_section_writable+0x18>
   140001cde:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001ce2:	48 89 c1             	mov    rcx,rax
   140001ce5:	e8 c1 11 00 00       	call   140002eab <__mingw_GetSectionForAddress>
   140001cea:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001cee:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001cf3:	75 13                	jne    140001d08 <mark_section_writable+0xd3>
   140001cf5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001cf9:	48 8d 0d f0 94 00 00 	lea    rcx,[rip+0x94f0]        # 14000b1f0 <.rdata+0x20>
   140001d00:	48 89 c2             	mov    rdx,rax
   140001d03:	e8 c8 fe ff ff       	call   140001bd0 <__report_error>
   140001d08:	48 8b 0d d1 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3d1]        # 14000f0e0 <the_secs>
   140001d0f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d12:	48 63 d0             	movsxd rdx,eax
   140001d15:	48 89 d0             	mov    rax,rdx
   140001d18:	48 c1 e0 02          	shl    rax,0x2
   140001d1c:	48 01 d0             	add    rax,rdx
   140001d1f:	48 c1 e0 03          	shl    rax,0x3
   140001d23:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d27:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d2b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001d2f:	48 8b 0d aa d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3aa]        # 14000f0e0 <the_secs>
   140001d36:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d39:	48 63 d0             	movsxd rdx,eax
   140001d3c:	48 89 d0             	mov    rax,rdx
   140001d3f:	48 c1 e0 02          	shl    rax,0x2
   140001d43:	48 01 d0             	add    rax,rdx
   140001d46:	48 c1 e0 03          	shl    rax,0x3
   140001d4a:	48 01 c8             	add    rax,rcx
   140001d4d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d53:	e8 9f 12 00 00       	call   140002ff7 <_GetPEImageBase>
   140001d58:	48 89 c1             	mov    rcx,rax
   140001d5b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d5f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d62:	41 89 c1             	mov    r9d,eax
   140001d65:	4c 8b 05 74 d3 00 00 	mov    r8,QWORD PTR [rip+0xd374]        # 14000f0e0 <the_secs>
   140001d6c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d6f:	48 63 d0             	movsxd rdx,eax
   140001d72:	48 89 d0             	mov    rax,rdx
   140001d75:	48 c1 e0 02          	shl    rax,0x2
   140001d79:	48 01 d0             	add    rax,rdx
   140001d7c:	48 c1 e0 03          	shl    rax,0x3
   140001d80:	4c 01 c0             	add    rax,r8
   140001d83:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d87:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d8b:	48 8b 0d 4e d3 00 00 	mov    rcx,QWORD PTR [rip+0xd34e]        # 14000f0e0 <the_secs>
   140001d92:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d95:	48 63 d0             	movsxd rdx,eax
   140001d98:	48 89 d0             	mov    rax,rdx
   140001d9b:	48 c1 e0 02          	shl    rax,0x2
   140001d9f:	48 01 d0             	add    rax,rdx
   140001da2:	48 c1 e0 03          	shl    rax,0x3
   140001da6:	48 01 c8             	add    rax,rcx
   140001da9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001dad:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001db1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001db7:	48 89 c1             	mov    rcx,rax
   140001dba:	48 8b 05 9f e4 00 00 	mov    rax,QWORD PTR [rip+0xe49f]        # 140010260 <__imp_VirtualQuery>
   140001dc1:	ff d0                	call   rax
   140001dc3:	48 85 c0             	test   rax,rax
   140001dc6:	75 3f                	jne    140001e07 <mark_section_writable+0x1d2>
   140001dc8:	48 8b 0d 11 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd311]        # 14000f0e0 <the_secs>
   140001dcf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dd2:	48 63 d0             	movsxd rdx,eax
   140001dd5:	48 89 d0             	mov    rax,rdx
   140001dd8:	48 c1 e0 02          	shl    rax,0x2
   140001ddc:	48 01 d0             	add    rax,rdx
   140001ddf:	48 c1 e0 03          	shl    rax,0x3
   140001de3:	48 01 c8             	add    rax,rcx
   140001de6:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001dea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001dee:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001df1:	89 c1                	mov    ecx,eax
   140001df3:	48 8d 05 16 94 00 00 	lea    rax,[rip+0x9416]        # 14000b210 <.rdata+0x40>
   140001dfa:	49 89 d0             	mov    r8,rdx
   140001dfd:	89 ca                	mov    edx,ecx
   140001dff:	48 89 c1             	mov    rcx,rax
   140001e02:	e8 c9 fd ff ff       	call   140001bd0 <__report_error>
   140001e07:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e0a:	83 f8 40             	cmp    eax,0x40
   140001e0d:	0f 84 e8 00 00 00    	je     140001efb <mark_section_writable+0x2c6>
   140001e13:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e16:	83 f8 04             	cmp    eax,0x4
   140001e19:	0f 84 dc 00 00 00    	je     140001efb <mark_section_writable+0x2c6>
   140001e1f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e22:	3d 80 00 00 00       	cmp    eax,0x80
   140001e27:	0f 84 ce 00 00 00    	je     140001efb <mark_section_writable+0x2c6>
   140001e2d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e30:	83 f8 08             	cmp    eax,0x8
   140001e33:	0f 84 c2 00 00 00    	je     140001efb <mark_section_writable+0x2c6>
   140001e39:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e3c:	83 f8 02             	cmp    eax,0x2
   140001e3f:	75 09                	jne    140001e4a <mark_section_writable+0x215>
   140001e41:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001e48:	eb 07                	jmp    140001e51 <mark_section_writable+0x21c>
   140001e4a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e51:	48 8b 0d 88 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd288]        # 14000f0e0 <the_secs>
   140001e58:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e5b:	48 63 d0             	movsxd rdx,eax
   140001e5e:	48 89 d0             	mov    rax,rdx
   140001e61:	48 c1 e0 02          	shl    rax,0x2
   140001e65:	48 01 d0             	add    rax,rdx
   140001e68:	48 c1 e0 03          	shl    rax,0x3
   140001e6c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e70:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e74:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e78:	48 8b 0d 61 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd261]        # 14000f0e0 <the_secs>
   140001e7f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e82:	48 63 d0             	movsxd rdx,eax
   140001e85:	48 89 d0             	mov    rax,rdx
   140001e88:	48 c1 e0 02          	shl    rax,0x2
   140001e8c:	48 01 d0             	add    rax,rdx
   140001e8f:	48 c1 e0 03          	shl    rax,0x3
   140001e93:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e97:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e9b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e9f:	48 8b 0d 3a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd23a]        # 14000f0e0 <the_secs>
   140001ea6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ea9:	48 63 d0             	movsxd rdx,eax
   140001eac:	48 89 d0             	mov    rax,rdx
   140001eaf:	48 c1 e0 02          	shl    rax,0x2
   140001eb3:	48 01 d0             	add    rax,rdx
   140001eb6:	48 c1 e0 03          	shl    rax,0x3
   140001eba:	48 01 c8             	add    rax,rcx
   140001ebd:	49 89 c0             	mov    r8,rax
   140001ec0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001ec4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001ec8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001ecb:	4d 89 c1             	mov    r9,r8
   140001ece:	41 89 c8             	mov    r8d,ecx
   140001ed1:	48 89 c1             	mov    rcx,rax
   140001ed4:	48 8b 05 7d e3 00 00 	mov    rax,QWORD PTR [rip+0xe37d]        # 140010258 <__imp_VirtualProtect>
   140001edb:	ff d0                	call   rax
   140001edd:	85 c0                	test   eax,eax
   140001edf:	75 1a                	jne    140001efb <mark_section_writable+0x2c6>
   140001ee1:	48 8b 05 20 e3 00 00 	mov    rax,QWORD PTR [rip+0xe320]        # 140010208 <__imp_GetLastError>
   140001ee8:	ff d0                	call   rax
   140001eea:	89 c2                	mov    edx,eax
   140001eec:	48 8d 05 55 93 00 00 	lea    rax,[rip+0x9355]        # 14000b248 <.rdata+0x78>
   140001ef3:	48 89 c1             	mov    rcx,rax
   140001ef6:	e8 d5 fc ff ff       	call   140001bd0 <__report_error>
   140001efb:	8b 05 e7 d1 00 00    	mov    eax,DWORD PTR [rip+0xd1e7]        # 14000f0e8 <maxSections>
   140001f01:	83 c0 01             	add    eax,0x1
   140001f04:	89 05 de d1 00 00    	mov    DWORD PTR [rip+0xd1de],eax        # 14000f0e8 <maxSections>
   140001f0a:	eb 01                	jmp    140001f0d <mark_section_writable+0x2d8>
   140001f0c:	90                   	nop
   140001f0d:	48 83 c4 60          	add    rsp,0x60
   140001f11:	5d                   	pop    rbp
   140001f12:	c3                   	ret

0000000140001f13 <restore_modified_sections>:
   140001f13:	55                   	push   rbp
   140001f14:	48 89 e5             	mov    rbp,rsp
   140001f17:	48 83 ec 30          	sub    rsp,0x30
   140001f1b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001f22:	e9 ad 00 00 00       	jmp    140001fd4 <restore_modified_sections+0xc1>
   140001f27:	48 8b 0d b2 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd1b2]        # 14000f0e0 <the_secs>
   140001f2e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f31:	48 63 d0             	movsxd rdx,eax
   140001f34:	48 89 d0             	mov    rax,rdx
   140001f37:	48 c1 e0 02          	shl    rax,0x2
   140001f3b:	48 01 d0             	add    rax,rdx
   140001f3e:	48 c1 e0 03          	shl    rax,0x3
   140001f42:	48 01 c8             	add    rax,rcx
   140001f45:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f47:	85 c0                	test   eax,eax
   140001f49:	0f 84 80 00 00 00    	je     140001fcf <restore_modified_sections+0xbc>
   140001f4f:	48 8b 0d 8a d1 00 00 	mov    rcx,QWORD PTR [rip+0xd18a]        # 14000f0e0 <the_secs>
   140001f56:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f59:	48 63 d0             	movsxd rdx,eax
   140001f5c:	48 89 d0             	mov    rax,rdx
   140001f5f:	48 c1 e0 02          	shl    rax,0x2
   140001f63:	48 01 d0             	add    rax,rdx
   140001f66:	48 c1 e0 03          	shl    rax,0x3
   140001f6a:	48 01 c8             	add    rax,rcx
   140001f6d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f70:	48 8b 0d 69 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd169]        # 14000f0e0 <the_secs>
   140001f77:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f7a:	48 63 d0             	movsxd rdx,eax
   140001f7d:	48 89 d0             	mov    rax,rdx
   140001f80:	48 c1 e0 02          	shl    rax,0x2
   140001f84:	48 01 d0             	add    rax,rdx
   140001f87:	48 c1 e0 03          	shl    rax,0x3
   140001f8b:	48 01 c8             	add    rax,rcx
   140001f8e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f92:	4c 8b 05 47 d1 00 00 	mov    r8,QWORD PTR [rip+0xd147]        # 14000f0e0 <the_secs>
   140001f99:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f9c:	48 63 d0             	movsxd rdx,eax
   140001f9f:	48 89 d0             	mov    rax,rdx
   140001fa2:	48 c1 e0 02          	shl    rax,0x2
   140001fa6:	48 01 d0             	add    rax,rdx
   140001fa9:	48 c1 e0 03          	shl    rax,0x3
   140001fad:	4c 01 c0             	add    rax,r8
   140001fb0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001fb4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001fb8:	49 89 d1             	mov    r9,rdx
   140001fbb:	45 89 d0             	mov    r8d,r10d
   140001fbe:	48 89 ca             	mov    rdx,rcx
   140001fc1:	48 89 c1             	mov    rcx,rax
   140001fc4:	48 8b 05 8d e2 00 00 	mov    rax,QWORD PTR [rip+0xe28d]        # 140010258 <__imp_VirtualProtect>
   140001fcb:	ff d0                	call   rax
   140001fcd:	eb 01                	jmp    140001fd0 <restore_modified_sections+0xbd>
   140001fcf:	90                   	nop
   140001fd0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001fd4:	8b 05 0e d1 00 00    	mov    eax,DWORD PTR [rip+0xd10e]        # 14000f0e8 <maxSections>
   140001fda:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001fdd:	0f 8c 44 ff ff ff    	jl     140001f27 <restore_modified_sections+0x14>
   140001fe3:	90                   	nop
   140001fe4:	90                   	nop
   140001fe5:	48 83 c4 30          	add    rsp,0x30
   140001fe9:	5d                   	pop    rbp
   140001fea:	c3                   	ret

0000000140001feb <__write_memory>:
   140001feb:	55                   	push   rbp
   140001fec:	48 89 e5             	mov    rbp,rsp
   140001fef:	48 83 ec 20          	sub    rsp,0x20
   140001ff3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001ff7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001ffb:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001fff:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140002004:	74 25                	je     14000202b <__write_memory+0x40>
   140002006:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000200a:	48 89 c1             	mov    rcx,rax
   14000200d:	e8 23 fc ff ff       	call   140001c35 <mark_section_writable>
   140002012:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140002016:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000201a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000201e:	49 89 c8             	mov    r8,rcx
   140002021:	48 89 c1             	mov    rcx,rax
   140002024:	e8 df 76 00 00       	call   140009708 <memcpy>
   140002029:	eb 01                	jmp    14000202c <__write_memory+0x41>
   14000202b:	90                   	nop
   14000202c:	48 83 c4 20          	add    rsp,0x20
   140002030:	5d                   	pop    rbp
   140002031:	c3                   	ret

0000000140002032 <do_pseudo_reloc>:
   140002032:	55                   	push   rbp
   140002033:	48 89 e5             	mov    rbp,rsp
   140002036:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   14000203a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000203e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002042:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002046:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000204a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000204e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002052:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002056:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000205a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000205f:	0f 8e 44 03 00 00    	jle    1400023a9 <do_pseudo_reloc+0x377>
   140002065:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000206a:	7e 25                	jle    140002091 <do_pseudo_reloc+0x5f>
   14000206c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002070:	8b 00                	mov    eax,DWORD PTR [rax]
   140002072:	85 c0                	test   eax,eax
   140002074:	75 1b                	jne    140002091 <do_pseudo_reloc+0x5f>
   140002076:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000207a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000207d:	85 c0                	test   eax,eax
   14000207f:	75 10                	jne    140002091 <do_pseudo_reloc+0x5f>
   140002081:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002085:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002088:	85 c0                	test   eax,eax
   14000208a:	75 05                	jne    140002091 <do_pseudo_reloc+0x5f>
   14000208c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002091:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002095:	8b 00                	mov    eax,DWORD PTR [rax]
   140002097:	85 c0                	test   eax,eax
   140002099:	75 0b                	jne    1400020a6 <do_pseudo_reloc+0x74>
   14000209b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000209f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020a2:	85 c0                	test   eax,eax
   1400020a4:	74 59                	je     1400020ff <do_pseudo_reloc+0xcd>
   1400020a6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020aa:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400020ae:	eb 40                	jmp    1400020f0 <do_pseudo_reloc+0xbe>
   1400020b0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020b4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020b7:	89 c2                	mov    edx,eax
   1400020b9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020bd:	48 01 d0             	add    rax,rdx
   1400020c0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020c4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020c8:	8b 10                	mov    edx,DWORD PTR [rax]
   1400020ca:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020ce:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020d0:	01 d0                	add    eax,edx
   1400020d2:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   1400020d5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020d9:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   1400020dd:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400020e3:	48 89 c1             	mov    rcx,rax
   1400020e6:	e8 00 ff ff ff       	call   140001feb <__write_memory>
   1400020eb:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   1400020f0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020f4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400020f8:	72 b6                	jb     1400020b0 <do_pseudo_reloc+0x7e>
   1400020fa:	e9 ab 02 00 00       	jmp    1400023aa <do_pseudo_reloc+0x378>
   1400020ff:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002103:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002106:	83 f8 01             	cmp    eax,0x1
   140002109:	74 18                	je     140002123 <do_pseudo_reloc+0xf1>
   14000210b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000210f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002112:	89 c2                	mov    edx,eax
   140002114:	48 8d 05 55 91 00 00 	lea    rax,[rip+0x9155]        # 14000b270 <.rdata+0xa0>
   14000211b:	48 89 c1             	mov    rcx,rax
   14000211e:	e8 ad fa ff ff       	call   140001bd0 <__report_error>
   140002123:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002127:	48 83 c0 0c          	add    rax,0xc
   14000212b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000212f:	e9 65 02 00 00       	jmp    140002399 <do_pseudo_reloc+0x367>
   140002134:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002138:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000213b:	89 c2                	mov    edx,eax
   14000213d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002141:	48 01 d0             	add    rax,rdx
   140002144:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002148:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000214c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000214e:	89 c2                	mov    edx,eax
   140002150:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002154:	48 01 d0             	add    rax,rdx
   140002157:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000215b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000215f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002162:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002166:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000216a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000216d:	0f b6 c0             	movzx  eax,al
   140002170:	83 f8 40             	cmp    eax,0x40
   140002173:	0f 84 b6 00 00 00    	je     14000222f <do_pseudo_reloc+0x1fd>
   140002179:	83 f8 40             	cmp    eax,0x40
   14000217c:	0f 87 ba 00 00 00    	ja     14000223c <do_pseudo_reloc+0x20a>
   140002182:	83 f8 20             	cmp    eax,0x20
   140002185:	74 77                	je     1400021fe <do_pseudo_reloc+0x1cc>
   140002187:	83 f8 20             	cmp    eax,0x20
   14000218a:	0f 87 ac 00 00 00    	ja     14000223c <do_pseudo_reloc+0x20a>
   140002190:	83 f8 08             	cmp    eax,0x8
   140002193:	74 0a                	je     14000219f <do_pseudo_reloc+0x16d>
   140002195:	83 f8 10             	cmp    eax,0x10
   140002198:	74 38                	je     1400021d2 <do_pseudo_reloc+0x1a0>
   14000219a:	e9 9d 00 00 00       	jmp    14000223c <do_pseudo_reloc+0x20a>
   14000219f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021a3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400021a6:	0f b6 c0             	movzx  eax,al
   1400021a9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ad:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021b1:	25 80 00 00 00       	and    eax,0x80
   1400021b6:	48 85 c0             	test   rax,rax
   1400021b9:	0f 84 9d 00 00 00    	je     14000225c <do_pseudo_reloc+0x22a>
   1400021bf:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021c3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400021c9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021cd:	e9 8a 00 00 00       	jmp    14000225c <do_pseudo_reloc+0x22a>
   1400021d2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021d6:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400021d9:	0f b7 c0             	movzx  eax,ax
   1400021dc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021e0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021e4:	25 00 80 00 00       	and    eax,0x8000
   1400021e9:	48 85 c0             	test   rax,rax
   1400021ec:	74 71                	je     14000225f <do_pseudo_reloc+0x22d>
   1400021ee:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021f2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400021f8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021fc:	eb 61                	jmp    14000225f <do_pseudo_reloc+0x22d>
   1400021fe:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002202:	8b 00                	mov    eax,DWORD PTR [rax]
   140002204:	89 c0                	mov    eax,eax
   140002206:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000220a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000220e:	25 00 00 00 80       	and    eax,0x80000000
   140002213:	48 85 c0             	test   rax,rax
   140002216:	74 4a                	je     140002262 <do_pseudo_reloc+0x230>
   140002218:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000221c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002223:	ff ff ff 
   140002226:	48 09 d0             	or     rax,rdx
   140002229:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000222d:	eb 33                	jmp    140002262 <do_pseudo_reloc+0x230>
   14000222f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002233:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002236:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000223a:	eb 27                	jmp    140002263 <do_pseudo_reloc+0x231>
   14000223c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002243:	00 
   140002244:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002248:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000224b:	0f b6 c0             	movzx  eax,al
   14000224e:	48 8d 0d 53 90 00 00 	lea    rcx,[rip+0x9053]        # 14000b2a8 <.rdata+0xd8>
   140002255:	89 c2                	mov    edx,eax
   140002257:	e8 74 f9 ff ff       	call   140001bd0 <__report_error>
   14000225c:	90                   	nop
   14000225d:	eb 04                	jmp    140002263 <do_pseudo_reloc+0x231>
   14000225f:	90                   	nop
   140002260:	eb 01                	jmp    140002263 <do_pseudo_reloc+0x231>
   140002262:	90                   	nop
   140002263:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002267:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000226b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000226d:	89 c2                	mov    edx,eax
   14000226f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002273:	48 01 c2             	add    rdx,rax
   140002276:	48 89 c8             	mov    rax,rcx
   140002279:	48 29 d0             	sub    rax,rdx
   14000227c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002280:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002284:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002288:	48 01 d0             	add    rax,rdx
   14000228b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000228f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002293:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002296:	25 ff 00 00 00       	and    eax,0xff
   14000229b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000229e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400022a2:	77 67                	ja     14000230b <do_pseudo_reloc+0x2d9>
   1400022a4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022a7:	ba 01 00 00 00       	mov    edx,0x1
   1400022ac:	89 c1                	mov    ecx,eax
   1400022ae:	48 d3 e2             	shl    rdx,cl
   1400022b1:	48 89 d0             	mov    rax,rdx
   1400022b4:	48 83 e8 01          	sub    rax,0x1
   1400022b8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400022bc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022bf:	83 e8 01             	sub    eax,0x1
   1400022c2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400022c9:	89 c1                	mov    ecx,eax
   1400022cb:	48 d3 e2             	shl    rdx,cl
   1400022ce:	48 89 d0             	mov    rax,rdx
   1400022d1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400022d5:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022d9:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   1400022dd:	7c 0a                	jl     1400022e9 <do_pseudo_reloc+0x2b7>
   1400022df:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022e3:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400022e7:	7e 22                	jle    14000230b <do_pseudo_reloc+0x2d9>
   1400022e9:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400022ed:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400022f1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400022f5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022f8:	48 8d 0d d9 8f 00 00 	lea    rcx,[rip+0x8fd9]        # 14000b2d8 <.rdata+0x108>
   1400022ff:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002304:	89 c2                	mov    edx,eax
   140002306:	e8 c5 f8 ff ff       	call   140001bd0 <__report_error>
   14000230b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000230f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002312:	0f b6 c0             	movzx  eax,al
   140002315:	83 f8 40             	cmp    eax,0x40
   140002318:	74 63                	je     14000237d <do_pseudo_reloc+0x34b>
   14000231a:	83 f8 40             	cmp    eax,0x40
   14000231d:	77 75                	ja     140002394 <do_pseudo_reloc+0x362>
   14000231f:	83 f8 20             	cmp    eax,0x20
   140002322:	74 41                	je     140002365 <do_pseudo_reloc+0x333>
   140002324:	83 f8 20             	cmp    eax,0x20
   140002327:	77 6b                	ja     140002394 <do_pseudo_reloc+0x362>
   140002329:	83 f8 08             	cmp    eax,0x8
   14000232c:	74 07                	je     140002335 <do_pseudo_reloc+0x303>
   14000232e:	83 f8 10             	cmp    eax,0x10
   140002331:	74 1a                	je     14000234d <do_pseudo_reloc+0x31b>
   140002333:	eb 5f                	jmp    140002394 <do_pseudo_reloc+0x362>
   140002335:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002339:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000233d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002343:	48 89 c1             	mov    rcx,rax
   140002346:	e8 a0 fc ff ff       	call   140001feb <__write_memory>
   14000234b:	eb 47                	jmp    140002394 <do_pseudo_reloc+0x362>
   14000234d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002351:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002355:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000235b:	48 89 c1             	mov    rcx,rax
   14000235e:	e8 88 fc ff ff       	call   140001feb <__write_memory>
   140002363:	eb 2f                	jmp    140002394 <do_pseudo_reloc+0x362>
   140002365:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002369:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000236d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002373:	48 89 c1             	mov    rcx,rax
   140002376:	e8 70 fc ff ff       	call   140001feb <__write_memory>
   14000237b:	eb 17                	jmp    140002394 <do_pseudo_reloc+0x362>
   14000237d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002381:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002385:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000238b:	48 89 c1             	mov    rcx,rax
   14000238e:	e8 58 fc ff ff       	call   140001feb <__write_memory>
   140002393:	90                   	nop
   140002394:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002399:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000239d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400023a1:	0f 82 8d fd ff ff    	jb     140002134 <do_pseudo_reloc+0x102>
   1400023a7:	eb 01                	jmp    1400023aa <do_pseudo_reloc+0x378>
   1400023a9:	90                   	nop
   1400023aa:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400023ae:	5d                   	pop    rbp
   1400023af:	c3                   	ret

00000001400023b0 <_pei386_runtime_relocator>:
   1400023b0:	55                   	push   rbp
   1400023b1:	48 89 e5             	mov    rbp,rsp
   1400023b4:	48 83 ec 30          	sub    rsp,0x30
   1400023b8:	8b 05 2e cd 00 00    	mov    eax,DWORD PTR [rip+0xcd2e]        # 14000f0ec <was_init.0>
   1400023be:	85 c0                	test   eax,eax
   1400023c0:	0f 85 88 00 00 00    	jne    14000244e <_pei386_runtime_relocator+0x9e>
   1400023c6:	8b 05 20 cd 00 00    	mov    eax,DWORD PTR [rip+0xcd20]        # 14000f0ec <was_init.0>
   1400023cc:	83 c0 01             	add    eax,0x1
   1400023cf:	89 05 17 cd 00 00    	mov    DWORD PTR [rip+0xcd17],eax        # 14000f0ec <was_init.0>
   1400023d5:	e8 21 0b 00 00       	call   140002efb <__mingw_GetSectionCount>
   1400023da:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400023dd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400023e0:	48 63 d0             	movsxd rdx,eax
   1400023e3:	48 89 d0             	mov    rax,rdx
   1400023e6:	48 c1 e0 02          	shl    rax,0x2
   1400023ea:	48 01 d0             	add    rax,rdx
   1400023ed:	48 c1 e0 03          	shl    rax,0x3
   1400023f1:	48 83 c0 0f          	add    rax,0xf
   1400023f5:	48 c1 e8 04          	shr    rax,0x4
   1400023f9:	48 c1 e0 04          	shl    rax,0x4
   1400023fd:	e8 7e 0d 00 00       	call   140003180 <___chkstk_ms>
   140002402:	48 29 c4             	sub    rsp,rax
   140002405:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000240a:	48 83 c0 0f          	add    rax,0xf
   14000240e:	48 c1 e8 04          	shr    rax,0x4
   140002412:	48 c1 e0 04          	shl    rax,0x4
   140002416:	48 89 05 c3 cc 00 00 	mov    QWORD PTR [rip+0xccc3],rax        # 14000f0e0 <the_secs>
   14000241d:	c7 05 c1 cc 00 00 00 	mov    DWORD PTR [rip+0xccc1],0x0        # 14000f0e8 <maxSections>
   140002424:	00 00 00 
   140002427:	48 8b 0d 52 91 00 00 	mov    rcx,QWORD PTR [rip+0x9152]        # 14000b580 <.refptr.__ImageBase>
   14000242e:	48 8b 15 5b 91 00 00 	mov    rdx,QWORD PTR [rip+0x915b]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002435:	48 8b 05 64 91 00 00 	mov    rax,QWORD PTR [rip+0x9164]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000243c:	49 89 c8             	mov    r8,rcx
   14000243f:	48 89 c1             	mov    rcx,rax
   140002442:	e8 eb fb ff ff       	call   140002032 <do_pseudo_reloc>
   140002447:	e8 c7 fa ff ff       	call   140001f13 <restore_modified_sections>
   14000244c:	eb 01                	jmp    14000244f <_pei386_runtime_relocator+0x9f>
   14000244e:	90                   	nop
   14000244f:	48 89 ec             	mov    rsp,rbp
   140002452:	5d                   	pop    rbp
   140002453:	c3                   	ret
   140002454:	90                   	nop
   140002455:	90                   	nop
   140002456:	90                   	nop
   140002457:	90                   	nop
   140002458:	90                   	nop
   140002459:	90                   	nop
   14000245a:	90                   	nop
   14000245b:	90                   	nop
   14000245c:	90                   	nop
   14000245d:	90                   	nop
   14000245e:	90                   	nop
   14000245f:	90                   	nop

0000000140002460 <__mingw_raise_matherr>:
   140002460:	55                   	push   rbp
   140002461:	48 89 e5             	mov    rbp,rsp
   140002464:	48 83 ec 50          	sub    rsp,0x50
   140002468:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000246b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000246f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002474:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002479:	48 8b 05 70 cc 00 00 	mov    rax,QWORD PTR [rip+0xcc70]        # 14000f0f0 <stUserMathErr>
   140002480:	48 85 c0             	test   rax,rax
   140002483:	74 3e                	je     1400024c3 <__mingw_raise_matherr+0x63>
   140002485:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002488:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000248b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000248f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002493:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002498:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000249d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400024a2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400024a7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400024ac:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400024b1:	48 8b 15 38 cc 00 00 	mov    rdx,QWORD PTR [rip+0xcc38]        # 14000f0f0 <stUserMathErr>
   1400024b8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400024bc:	48 89 c1             	mov    rcx,rax
   1400024bf:	ff d2                	call   rdx
   1400024c1:	eb 01                	jmp    1400024c4 <__mingw_raise_matherr+0x64>
   1400024c3:	90                   	nop
   1400024c4:	48 83 c4 50          	add    rsp,0x50
   1400024c8:	5d                   	pop    rbp
   1400024c9:	c3                   	ret

00000001400024ca <__mingw_setusermatherr>:
   1400024ca:	55                   	push   rbp
   1400024cb:	48 89 e5             	mov    rbp,rsp
   1400024ce:	48 83 ec 20          	sub    rsp,0x20
   1400024d2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024d6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024da:	48 89 05 0f cc 00 00 	mov    QWORD PTR [rip+0xcc0f],rax        # 14000f0f0 <stUserMathErr>
   1400024e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024e5:	48 89 c1             	mov    rcx,rax
   1400024e8:	e8 93 71 00 00       	call   140009680 <__setusermatherr>
   1400024ed:	90                   	nop
   1400024ee:	48 83 c4 20          	add    rsp,0x20
   1400024f2:	5d                   	pop    rbp
   1400024f3:	c3                   	ret
   1400024f4:	90                   	nop
   1400024f5:	90                   	nop
   1400024f6:	90                   	nop
   1400024f7:	90                   	nop
   1400024f8:	90                   	nop
   1400024f9:	90                   	nop
   1400024fa:	90                   	nop
   1400024fb:	90                   	nop
   1400024fc:	90                   	nop
   1400024fd:	90                   	nop
   1400024fe:	90                   	nop
   1400024ff:	90                   	nop

0000000140002500 <__mingw_SEH_error_handler>:
   140002500:	55                   	push   rbp
   140002501:	48 89 e5             	mov    rbp,rsp
   140002504:	48 83 ec 30          	sub    rsp,0x30
   140002508:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000250c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002510:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002514:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002518:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000251f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002526:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000252a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000252d:	83 e0 02             	and    eax,0x2
   140002530:	85 c0                	test   eax,eax
   140002532:	74 0a                	je     14000253e <__mingw_SEH_error_handler+0x3e>
   140002534:	b8 01 00 00 00       	mov    eax,0x1
   140002539:	e9 16 02 00 00       	jmp    140002754 <__mingw_SEH_error_handler+0x254>
   14000253e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002542:	8b 00                	mov    eax,DWORD PTR [rax]
   140002544:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002549:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000254e:	75 18                	jne    140002568 <__mingw_SEH_error_handler+0x68>
   140002550:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002554:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002557:	83 e0 01             	and    eax,0x1
   14000255a:	85 c0                	test   eax,eax
   14000255c:	75 0a                	jne    140002568 <__mingw_SEH_error_handler+0x68>
   14000255e:	b8 00 00 00 00       	mov    eax,0x0
   140002563:	e9 ec 01 00 00       	jmp    140002754 <__mingw_SEH_error_handler+0x254>
   140002568:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000256c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000256e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002573:	0f 84 12 01 00 00    	je     14000268b <__mingw_SEH_error_handler+0x18b>
   140002579:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000257e:	0f 87 c3 01 00 00    	ja     140002747 <__mingw_SEH_error_handler+0x247>
   140002584:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002589:	0f 87 b8 01 00 00    	ja     140002747 <__mingw_SEH_error_handler+0x247>
   14000258f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002594:	0f 83 4c 01 00 00    	jae    1400026e6 <__mingw_SEH_error_handler+0x1e6>
   14000259a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000259f:	0f 84 3a 01 00 00    	je     1400026df <__mingw_SEH_error_handler+0x1df>
   1400025a5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400025aa:	0f 87 97 01 00 00    	ja     140002747 <__mingw_SEH_error_handler+0x247>
   1400025b0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025b5:	0f 84 83 01 00 00    	je     14000273e <__mingw_SEH_error_handler+0x23e>
   1400025bb:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025c0:	0f 87 81 01 00 00    	ja     140002747 <__mingw_SEH_error_handler+0x247>
   1400025c6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400025cb:	0f 87 76 01 00 00    	ja     140002747 <__mingw_SEH_error_handler+0x247>
   1400025d1:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400025d6:	0f 83 03 01 00 00    	jae    1400026df <__mingw_SEH_error_handler+0x1df>
   1400025dc:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025e1:	0f 84 57 01 00 00    	je     14000273e <__mingw_SEH_error_handler+0x23e>
   1400025e7:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025ec:	0f 87 55 01 00 00    	ja     140002747 <__mingw_SEH_error_handler+0x247>
   1400025f2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025f7:	0f 84 8e 00 00 00    	je     14000268b <__mingw_SEH_error_handler+0x18b>
   1400025fd:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002602:	0f 87 3f 01 00 00    	ja     140002747 <__mingw_SEH_error_handler+0x247>
   140002608:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000260d:	0f 84 2b 01 00 00    	je     14000273e <__mingw_SEH_error_handler+0x23e>
   140002613:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002618:	0f 87 29 01 00 00    	ja     140002747 <__mingw_SEH_error_handler+0x247>
   14000261e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002623:	0f 84 15 01 00 00    	je     14000273e <__mingw_SEH_error_handler+0x23e>
   140002629:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000262e:	0f 85 13 01 00 00    	jne    140002747 <__mingw_SEH_error_handler+0x247>
   140002634:	ba 00 00 00 00       	mov    edx,0x0
   140002639:	b9 0b 00 00 00       	mov    ecx,0xb
   14000263e:	e8 d5 70 00 00       	call   140009718 <signal>
   140002643:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002647:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000264c:	75 1b                	jne    140002669 <__mingw_SEH_error_handler+0x169>
   14000264e:	ba 01 00 00 00       	mov    edx,0x1
   140002653:	b9 0b 00 00 00       	mov    ecx,0xb
   140002658:	e8 bb 70 00 00       	call   140009718 <signal>
   14000265d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002664:	e9 e1 00 00 00       	jmp    14000274a <__mingw_SEH_error_handler+0x24a>
   140002669:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000266e:	0f 84 d6 00 00 00    	je     14000274a <__mingw_SEH_error_handler+0x24a>
   140002674:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002678:	b9 0b 00 00 00       	mov    ecx,0xb
   14000267d:	ff d0                	call   rax
   14000267f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002686:	e9 bf 00 00 00       	jmp    14000274a <__mingw_SEH_error_handler+0x24a>
   14000268b:	ba 00 00 00 00       	mov    edx,0x0
   140002690:	b9 04 00 00 00       	mov    ecx,0x4
   140002695:	e8 7e 70 00 00       	call   140009718 <signal>
   14000269a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000269e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026a3:	75 1b                	jne    1400026c0 <__mingw_SEH_error_handler+0x1c0>
   1400026a5:	ba 01 00 00 00       	mov    edx,0x1
   1400026aa:	b9 04 00 00 00       	mov    ecx,0x4
   1400026af:	e8 64 70 00 00       	call   140009718 <signal>
   1400026b4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026bb:	e9 8d 00 00 00       	jmp    14000274d <__mingw_SEH_error_handler+0x24d>
   1400026c0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026c5:	0f 84 82 00 00 00    	je     14000274d <__mingw_SEH_error_handler+0x24d>
   1400026cb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026cf:	b9 04 00 00 00       	mov    ecx,0x4
   1400026d4:	ff d0                	call   rax
   1400026d6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026dd:	eb 6e                	jmp    14000274d <__mingw_SEH_error_handler+0x24d>
   1400026df:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400026e6:	ba 00 00 00 00       	mov    edx,0x0
   1400026eb:	b9 08 00 00 00       	mov    ecx,0x8
   1400026f0:	e8 23 70 00 00       	call   140009718 <signal>
   1400026f5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026f9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026fe:	75 23                	jne    140002723 <__mingw_SEH_error_handler+0x223>
   140002700:	ba 01 00 00 00       	mov    edx,0x1
   140002705:	b9 08 00 00 00       	mov    ecx,0x8
   14000270a:	e8 09 70 00 00       	call   140009718 <signal>
   14000270f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002713:	74 05                	je     14000271a <__mingw_SEH_error_handler+0x21a>
   140002715:	e8 a6 05 00 00       	call   140002cc0 <_fpreset>
   14000271a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002721:	eb 2d                	jmp    140002750 <__mingw_SEH_error_handler+0x250>
   140002723:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002728:	74 26                	je     140002750 <__mingw_SEH_error_handler+0x250>
   14000272a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000272e:	b9 08 00 00 00       	mov    ecx,0x8
   140002733:	ff d0                	call   rax
   140002735:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000273c:	eb 12                	jmp    140002750 <__mingw_SEH_error_handler+0x250>
   14000273e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002745:	eb 0a                	jmp    140002751 <__mingw_SEH_error_handler+0x251>
   140002747:	90                   	nop
   140002748:	eb 07                	jmp    140002751 <__mingw_SEH_error_handler+0x251>
   14000274a:	90                   	nop
   14000274b:	eb 04                	jmp    140002751 <__mingw_SEH_error_handler+0x251>
   14000274d:	90                   	nop
   14000274e:	eb 01                	jmp    140002751 <__mingw_SEH_error_handler+0x251>
   140002750:	90                   	nop
   140002751:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002754:	48 83 c4 30          	add    rsp,0x30
   140002758:	5d                   	pop    rbp
   140002759:	c3                   	ret

000000014000275a <_gnu_exception_handler>:
   14000275a:	55                   	push   rbp
   14000275b:	48 89 e5             	mov    rbp,rsp
   14000275e:	48 83 ec 30          	sub    rsp,0x30
   140002762:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002766:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000276d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002774:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002778:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000277b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000277d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002782:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002787:	75 1b                	jne    1400027a4 <_gnu_exception_handler+0x4a>
   140002789:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000278d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002790:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002793:	83 e0 01             	and    eax,0x1
   140002796:	85 c0                	test   eax,eax
   140002798:	75 0a                	jne    1400027a4 <_gnu_exception_handler+0x4a>
   14000279a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000279f:	e9 14 02 00 00       	jmp    1400029b8 <_gnu_exception_handler+0x25e>
   1400027a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400027a8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400027ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400027ad:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400027b2:	0f 84 12 01 00 00    	je     1400028ca <_gnu_exception_handler+0x170>
   1400027b8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400027bd:	0f 87 c3 01 00 00    	ja     140002986 <_gnu_exception_handler+0x22c>
   1400027c3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400027c8:	0f 87 b8 01 00 00    	ja     140002986 <_gnu_exception_handler+0x22c>
   1400027ce:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400027d3:	0f 83 4c 01 00 00    	jae    140002925 <_gnu_exception_handler+0x1cb>
   1400027d9:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027de:	0f 84 3a 01 00 00    	je     14000291e <_gnu_exception_handler+0x1c4>
   1400027e4:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027e9:	0f 87 97 01 00 00    	ja     140002986 <_gnu_exception_handler+0x22c>
   1400027ef:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027f4:	0f 84 83 01 00 00    	je     14000297d <_gnu_exception_handler+0x223>
   1400027fa:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027ff:	0f 87 81 01 00 00    	ja     140002986 <_gnu_exception_handler+0x22c>
   140002805:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000280a:	0f 87 76 01 00 00    	ja     140002986 <_gnu_exception_handler+0x22c>
   140002810:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002815:	0f 83 03 01 00 00    	jae    14000291e <_gnu_exception_handler+0x1c4>
   14000281b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002820:	0f 84 57 01 00 00    	je     14000297d <_gnu_exception_handler+0x223>
   140002826:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000282b:	0f 87 55 01 00 00    	ja     140002986 <_gnu_exception_handler+0x22c>
   140002831:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002836:	0f 84 8e 00 00 00    	je     1400028ca <_gnu_exception_handler+0x170>
   14000283c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002841:	0f 87 3f 01 00 00    	ja     140002986 <_gnu_exception_handler+0x22c>
   140002847:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000284c:	0f 84 2b 01 00 00    	je     14000297d <_gnu_exception_handler+0x223>
   140002852:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002857:	0f 87 29 01 00 00    	ja     140002986 <_gnu_exception_handler+0x22c>
   14000285d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002862:	0f 84 15 01 00 00    	je     14000297d <_gnu_exception_handler+0x223>
   140002868:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000286d:	0f 85 13 01 00 00    	jne    140002986 <_gnu_exception_handler+0x22c>
   140002873:	ba 00 00 00 00       	mov    edx,0x0
   140002878:	b9 0b 00 00 00       	mov    ecx,0xb
   14000287d:	e8 96 6e 00 00       	call   140009718 <signal>
   140002882:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002886:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000288b:	75 1b                	jne    1400028a8 <_gnu_exception_handler+0x14e>
   14000288d:	ba 01 00 00 00       	mov    edx,0x1
   140002892:	b9 0b 00 00 00       	mov    ecx,0xb
   140002897:	e8 7c 6e 00 00       	call   140009718 <signal>
   14000289c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028a3:	e9 e1 00 00 00       	jmp    140002989 <_gnu_exception_handler+0x22f>
   1400028a8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028ad:	0f 84 d6 00 00 00    	je     140002989 <_gnu_exception_handler+0x22f>
   1400028b3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028b7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400028bc:	ff d0                	call   rax
   1400028be:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028c5:	e9 bf 00 00 00       	jmp    140002989 <_gnu_exception_handler+0x22f>
   1400028ca:	ba 00 00 00 00       	mov    edx,0x0
   1400028cf:	b9 04 00 00 00       	mov    ecx,0x4
   1400028d4:	e8 3f 6e 00 00       	call   140009718 <signal>
   1400028d9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028dd:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028e2:	75 1b                	jne    1400028ff <_gnu_exception_handler+0x1a5>
   1400028e4:	ba 01 00 00 00       	mov    edx,0x1
   1400028e9:	b9 04 00 00 00       	mov    ecx,0x4
   1400028ee:	e8 25 6e 00 00       	call   140009718 <signal>
   1400028f3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028fa:	e9 8d 00 00 00       	jmp    14000298c <_gnu_exception_handler+0x232>
   1400028ff:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002904:	0f 84 82 00 00 00    	je     14000298c <_gnu_exception_handler+0x232>
   14000290a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000290e:	b9 04 00 00 00       	mov    ecx,0x4
   140002913:	ff d0                	call   rax
   140002915:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000291c:	eb 6e                	jmp    14000298c <_gnu_exception_handler+0x232>
   14000291e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002925:	ba 00 00 00 00       	mov    edx,0x0
   14000292a:	b9 08 00 00 00       	mov    ecx,0x8
   14000292f:	e8 e4 6d 00 00       	call   140009718 <signal>
   140002934:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002938:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000293d:	75 23                	jne    140002962 <_gnu_exception_handler+0x208>
   14000293f:	ba 01 00 00 00       	mov    edx,0x1
   140002944:	b9 08 00 00 00       	mov    ecx,0x8
   140002949:	e8 ca 6d 00 00       	call   140009718 <signal>
   14000294e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002952:	74 05                	je     140002959 <_gnu_exception_handler+0x1ff>
   140002954:	e8 67 03 00 00       	call   140002cc0 <_fpreset>
   140002959:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002960:	eb 2d                	jmp    14000298f <_gnu_exception_handler+0x235>
   140002962:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002967:	74 26                	je     14000298f <_gnu_exception_handler+0x235>
   140002969:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000296d:	b9 08 00 00 00       	mov    ecx,0x8
   140002972:	ff d0                	call   rax
   140002974:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000297b:	eb 12                	jmp    14000298f <_gnu_exception_handler+0x235>
   14000297d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002984:	eb 0a                	jmp    140002990 <_gnu_exception_handler+0x236>
   140002986:	90                   	nop
   140002987:	eb 07                	jmp    140002990 <_gnu_exception_handler+0x236>
   140002989:	90                   	nop
   14000298a:	eb 04                	jmp    140002990 <_gnu_exception_handler+0x236>
   14000298c:	90                   	nop
   14000298d:	eb 01                	jmp    140002990 <_gnu_exception_handler+0x236>
   14000298f:	90                   	nop
   140002990:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002994:	75 1f                	jne    1400029b5 <_gnu_exception_handler+0x25b>
   140002996:	48 8b 05 73 c7 00 00 	mov    rax,QWORD PTR [rip+0xc773]        # 14000f110 <__mingw_oldexcpt_handler>
   14000299d:	48 85 c0             	test   rax,rax
   1400029a0:	74 13                	je     1400029b5 <_gnu_exception_handler+0x25b>
   1400029a2:	48 8b 15 67 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc767]        # 14000f110 <__mingw_oldexcpt_handler>
   1400029a9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400029ad:	48 89 c1             	mov    rcx,rax
   1400029b0:	ff d2                	call   rdx
   1400029b2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400029b5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400029b8:	48 83 c4 30          	add    rsp,0x30
   1400029bc:	5d                   	pop    rbp
   1400029bd:	c3                   	ret
   1400029be:	90                   	nop
   1400029bf:	90                   	nop

00000001400029c0 <___w64_mingwthr_add_key_dtor>:
   1400029c0:	55                   	push   rbp
   1400029c1:	48 89 e5             	mov    rbp,rsp
   1400029c4:	48 83 ec 30          	sub    rsp,0x30
   1400029c8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029cb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400029cf:	8b 05 73 c7 00 00    	mov    eax,DWORD PTR [rip+0xc773]        # 14000f148 <__mingwthr_cs_init>
   1400029d5:	85 c0                	test   eax,eax
   1400029d7:	75 07                	jne    1400029e0 <___w64_mingwthr_add_key_dtor+0x20>
   1400029d9:	b8 00 00 00 00       	mov    eax,0x0
   1400029de:	eb 7b                	jmp    140002a5b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029e0:	ba 18 00 00 00       	mov    edx,0x18
   1400029e5:	b9 01 00 00 00       	mov    ecx,0x1
   1400029ea:	e8 d9 6c 00 00       	call   1400096c8 <calloc>
   1400029ef:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400029f3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029f8:	75 07                	jne    140002a01 <___w64_mingwthr_add_key_dtor+0x41>
   1400029fa:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400029ff:	eb 5a                	jmp    140002a5b <___w64_mingwthr_add_key_dtor+0x9b>
   140002a01:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a05:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002a08:	89 10                	mov    DWORD PTR [rax],edx
   140002a0a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a0e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002a12:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002a16:	48 8d 05 03 c7 00 00 	lea    rax,[rip+0xc703]        # 14000f120 <__mingwthr_cs>
   140002a1d:	48 89 c1             	mov    rcx,rax
   140002a20:	48 8b 05 c9 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7c9]        # 1400101f0 <__imp_EnterCriticalSection>
   140002a27:	ff d0                	call   rax
   140002a29:	48 8b 15 20 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc720]        # 14000f150 <key_dtor_list>
   140002a30:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a34:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a3c:	48 89 05 0d c7 00 00 	mov    QWORD PTR [rip+0xc70d],rax        # 14000f150 <key_dtor_list>
   140002a43:	48 8d 05 d6 c6 00 00 	lea    rax,[rip+0xc6d6]        # 14000f120 <__mingwthr_cs>
   140002a4a:	48 89 c1             	mov    rcx,rax
   140002a4d:	48 8b 05 d4 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7d4]        # 140010228 <__imp_LeaveCriticalSection>
   140002a54:	ff d0                	call   rax
   140002a56:	b8 00 00 00 00       	mov    eax,0x0
   140002a5b:	48 83 c4 30          	add    rsp,0x30
   140002a5f:	5d                   	pop    rbp
   140002a60:	c3                   	ret

0000000140002a61 <___w64_mingwthr_remove_key_dtor>:
   140002a61:	55                   	push   rbp
   140002a62:	48 89 e5             	mov    rbp,rsp
   140002a65:	48 83 ec 30          	sub    rsp,0x30
   140002a69:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a6c:	8b 05 d6 c6 00 00    	mov    eax,DWORD PTR [rip+0xc6d6]        # 14000f148 <__mingwthr_cs_init>
   140002a72:	85 c0                	test   eax,eax
   140002a74:	75 0a                	jne    140002a80 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a76:	b8 00 00 00 00       	mov    eax,0x0
   140002a7b:	e9 9c 00 00 00       	jmp    140002b1c <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a80:	48 8d 05 99 c6 00 00 	lea    rax,[rip+0xc699]        # 14000f120 <__mingwthr_cs>
   140002a87:	48 89 c1             	mov    rcx,rax
   140002a8a:	48 8b 05 5f d7 00 00 	mov    rax,QWORD PTR [rip+0xd75f]        # 1400101f0 <__imp_EnterCriticalSection>
   140002a91:	ff d0                	call   rax
   140002a93:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a9a:	00 
   140002a9b:	48 8b 05 ae c6 00 00 	mov    rax,QWORD PTR [rip+0xc6ae]        # 14000f150 <key_dtor_list>
   140002aa2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002aa6:	eb 55                	jmp    140002afd <___w64_mingwthr_remove_key_dtor+0x9c>
   140002aa8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aac:	8b 00                	mov    eax,DWORD PTR [rax]
   140002aae:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002ab1:	75 36                	jne    140002ae9 <___w64_mingwthr_remove_key_dtor+0x88>
   140002ab3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ab8:	75 11                	jne    140002acb <___w64_mingwthr_remove_key_dtor+0x6a>
   140002aba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002abe:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ac2:	48 89 05 87 c6 00 00 	mov    QWORD PTR [rip+0xc687],rax        # 14000f150 <key_dtor_list>
   140002ac9:	eb 10                	jmp    140002adb <___w64_mingwthr_remove_key_dtor+0x7a>
   140002acb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002acf:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002ad3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ad7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002adb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002adf:	48 89 c1             	mov    rcx,rax
   140002ae2:	e8 09 6c 00 00       	call   1400096f0 <free>
   140002ae7:	eb 1b                	jmp    140002b04 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002ae9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aed:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002af1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002af5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002af9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002afd:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b02:	75 a4                	jne    140002aa8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002b04:	48 8d 05 15 c6 00 00 	lea    rax,[rip+0xc615]        # 14000f120 <__mingwthr_cs>
   140002b0b:	48 89 c1             	mov    rcx,rax
   140002b0e:	48 8b 05 13 d7 00 00 	mov    rax,QWORD PTR [rip+0xd713]        # 140010228 <__imp_LeaveCriticalSection>
   140002b15:	ff d0                	call   rax
   140002b17:	b8 00 00 00 00       	mov    eax,0x0
   140002b1c:	48 83 c4 30          	add    rsp,0x30
   140002b20:	5d                   	pop    rbp
   140002b21:	c3                   	ret

0000000140002b22 <__mingwthr_run_key_dtors>:
   140002b22:	55                   	push   rbp
   140002b23:	48 89 e5             	mov    rbp,rsp
   140002b26:	48 83 ec 30          	sub    rsp,0x30
   140002b2a:	8b 05 18 c6 00 00    	mov    eax,DWORD PTR [rip+0xc618]        # 14000f148 <__mingwthr_cs_init>
   140002b30:	85 c0                	test   eax,eax
   140002b32:	0f 84 82 00 00 00    	je     140002bba <__mingwthr_run_key_dtors+0x98>
   140002b38:	48 8d 05 e1 c5 00 00 	lea    rax,[rip+0xc5e1]        # 14000f120 <__mingwthr_cs>
   140002b3f:	48 89 c1             	mov    rcx,rax
   140002b42:	48 8b 05 a7 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6a7]        # 1400101f0 <__imp_EnterCriticalSection>
   140002b49:	ff d0                	call   rax
   140002b4b:	48 8b 05 fe c5 00 00 	mov    rax,QWORD PTR [rip+0xc5fe]        # 14000f150 <key_dtor_list>
   140002b52:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b56:	eb 46                	jmp    140002b9e <__mingwthr_run_key_dtors+0x7c>
   140002b58:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b5c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b5e:	89 c1                	mov    ecx,eax
   140002b60:	48 8b 05 e9 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6e9]        # 140010250 <__imp_TlsGetValue>
   140002b67:	ff d0                	call   rax
   140002b69:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b6d:	48 8b 05 94 d6 00 00 	mov    rax,QWORD PTR [rip+0xd694]        # 140010208 <__imp_GetLastError>
   140002b74:	ff d0                	call   rax
   140002b76:	85 c0                	test   eax,eax
   140002b78:	75 18                	jne    140002b92 <__mingwthr_run_key_dtors+0x70>
   140002b7a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b7f:	74 11                	je     140002b92 <__mingwthr_run_key_dtors+0x70>
   140002b81:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b85:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002b89:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b8d:	48 89 c1             	mov    rcx,rax
   140002b90:	ff d2                	call   rdx
   140002b92:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b96:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b9a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b9e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ba3:	75 b3                	jne    140002b58 <__mingwthr_run_key_dtors+0x36>
   140002ba5:	48 8d 05 74 c5 00 00 	lea    rax,[rip+0xc574]        # 14000f120 <__mingwthr_cs>
   140002bac:	48 89 c1             	mov    rcx,rax
   140002baf:	48 8b 05 72 d6 00 00 	mov    rax,QWORD PTR [rip+0xd672]        # 140010228 <__imp_LeaveCriticalSection>
   140002bb6:	ff d0                	call   rax
   140002bb8:	eb 01                	jmp    140002bbb <__mingwthr_run_key_dtors+0x99>
   140002bba:	90                   	nop
   140002bbb:	48 83 c4 30          	add    rsp,0x30
   140002bbf:	5d                   	pop    rbp
   140002bc0:	c3                   	ret

0000000140002bc1 <__mingw_TLScallback>:
   140002bc1:	55                   	push   rbp
   140002bc2:	48 89 e5             	mov    rbp,rsp
   140002bc5:	48 83 ec 30          	sub    rsp,0x30
   140002bc9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002bcd:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002bd0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002bd4:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002bd8:	0f 84 cc 00 00 00    	je     140002caa <__mingw_TLScallback+0xe9>
   140002bde:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002be2:	0f 87 ca 00 00 00    	ja     140002cb2 <__mingw_TLScallback+0xf1>
   140002be8:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bec:	0f 84 b1 00 00 00    	je     140002ca3 <__mingw_TLScallback+0xe2>
   140002bf2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bf6:	0f 87 b6 00 00 00    	ja     140002cb2 <__mingw_TLScallback+0xf1>
   140002bfc:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002c00:	74 33                	je     140002c35 <__mingw_TLScallback+0x74>
   140002c02:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002c06:	0f 85 a6 00 00 00    	jne    140002cb2 <__mingw_TLScallback+0xf1>
   140002c0c:	8b 05 36 c5 00 00    	mov    eax,DWORD PTR [rip+0xc536]        # 14000f148 <__mingwthr_cs_init>
   140002c12:	85 c0                	test   eax,eax
   140002c14:	75 13                	jne    140002c29 <__mingw_TLScallback+0x68>
   140002c16:	48 8d 05 03 c5 00 00 	lea    rax,[rip+0xc503]        # 14000f120 <__mingwthr_cs>
   140002c1d:	48 89 c1             	mov    rcx,rax
   140002c20:	48 8b 05 f9 d5 00 00 	mov    rax,QWORD PTR [rip+0xd5f9]        # 140010220 <__imp_InitializeCriticalSection>
   140002c27:	ff d0                	call   rax
   140002c29:	c7 05 15 c5 00 00 01 	mov    DWORD PTR [rip+0xc515],0x1        # 14000f148 <__mingwthr_cs_init>
   140002c30:	00 00 00 
   140002c33:	eb 7d                	jmp    140002cb2 <__mingw_TLScallback+0xf1>
   140002c35:	e8 e8 fe ff ff       	call   140002b22 <__mingwthr_run_key_dtors>
   140002c3a:	8b 05 08 c5 00 00    	mov    eax,DWORD PTR [rip+0xc508]        # 14000f148 <__mingwthr_cs_init>
   140002c40:	83 f8 01             	cmp    eax,0x1
   140002c43:	75 6c                	jne    140002cb1 <__mingw_TLScallback+0xf0>
   140002c45:	48 8b 05 04 c5 00 00 	mov    rax,QWORD PTR [rip+0xc504]        # 14000f150 <key_dtor_list>
   140002c4c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c50:	eb 20                	jmp    140002c72 <__mingw_TLScallback+0xb1>
   140002c52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c56:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c5a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c5e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c62:	48 89 c1             	mov    rcx,rax
   140002c65:	e8 86 6a 00 00       	call   1400096f0 <free>
   140002c6a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c6e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c72:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c77:	75 d9                	jne    140002c52 <__mingw_TLScallback+0x91>
   140002c79:	48 c7 05 cc c4 00 00 	mov    QWORD PTR [rip+0xc4cc],0x0        # 14000f150 <key_dtor_list>
   140002c80:	00 00 00 00 
   140002c84:	c7 05 ba c4 00 00 00 	mov    DWORD PTR [rip+0xc4ba],0x0        # 14000f148 <__mingwthr_cs_init>
   140002c8b:	00 00 00 
   140002c8e:	48 8d 05 8b c4 00 00 	lea    rax,[rip+0xc48b]        # 14000f120 <__mingwthr_cs>
   140002c95:	48 89 c1             	mov    rcx,rax
   140002c98:	48 8b 05 49 d5 00 00 	mov    rax,QWORD PTR [rip+0xd549]        # 1400101e8 <__IAT_start__>
   140002c9f:	ff d0                	call   rax
   140002ca1:	eb 0e                	jmp    140002cb1 <__mingw_TLScallback+0xf0>
   140002ca3:	e8 18 00 00 00       	call   140002cc0 <_fpreset>
   140002ca8:	eb 08                	jmp    140002cb2 <__mingw_TLScallback+0xf1>
   140002caa:	e8 73 fe ff ff       	call   140002b22 <__mingwthr_run_key_dtors>
   140002caf:	eb 01                	jmp    140002cb2 <__mingw_TLScallback+0xf1>
   140002cb1:	90                   	nop
   140002cb2:	b8 01 00 00 00       	mov    eax,0x1
   140002cb7:	48 83 c4 30          	add    rsp,0x30
   140002cbb:	5d                   	pop    rbp
   140002cbc:	c3                   	ret
   140002cbd:	90                   	nop
   140002cbe:	90                   	nop
   140002cbf:	90                   	nop

0000000140002cc0 <_fpreset>:
   140002cc0:	55                   	push   rbp
   140002cc1:	48 89 e5             	mov    rbp,rsp
   140002cc4:	db e3                	fninit
   140002cc6:	90                   	nop
   140002cc7:	5d                   	pop    rbp
   140002cc8:	c3                   	ret
   140002cc9:	90                   	nop
   140002cca:	90                   	nop
   140002ccb:	90                   	nop
   140002ccc:	90                   	nop
   140002ccd:	90                   	nop
   140002cce:	90                   	nop
   140002ccf:	90                   	nop

0000000140002cd0 <_ValidateImageBase>:
   140002cd0:	55                   	push   rbp
   140002cd1:	48 89 e5             	mov    rbp,rsp
   140002cd4:	48 83 ec 20          	sub    rsp,0x20
   140002cd8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002cdc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ce0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ce4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ce8:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002ceb:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002cef:	74 07                	je     140002cf8 <_ValidateImageBase+0x28>
   140002cf1:	b8 00 00 00 00       	mov    eax,0x0
   140002cf6:	eb 4e                	jmp    140002d46 <_ValidateImageBase+0x76>
   140002cf8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cfc:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002cff:	48 63 d0             	movsxd rdx,eax
   140002d02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d06:	48 01 d0             	add    rax,rdx
   140002d09:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002d0d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d11:	8b 00                	mov    eax,DWORD PTR [rax]
   140002d13:	3d 50 45 00 00       	cmp    eax,0x4550
   140002d18:	74 07                	je     140002d21 <_ValidateImageBase+0x51>
   140002d1a:	b8 00 00 00 00       	mov    eax,0x0
   140002d1f:	eb 25                	jmp    140002d46 <_ValidateImageBase+0x76>
   140002d21:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d25:	48 83 c0 18          	add    rax,0x18
   140002d29:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d2d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d31:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d34:	66 3d 0b 02          	cmp    ax,0x20b
   140002d38:	74 07                	je     140002d41 <_ValidateImageBase+0x71>
   140002d3a:	b8 00 00 00 00       	mov    eax,0x0
   140002d3f:	eb 05                	jmp    140002d46 <_ValidateImageBase+0x76>
   140002d41:	b8 01 00 00 00       	mov    eax,0x1
   140002d46:	48 83 c4 20          	add    rsp,0x20
   140002d4a:	5d                   	pop    rbp
   140002d4b:	c3                   	ret

0000000140002d4c <_FindPESection>:
   140002d4c:	55                   	push   rbp
   140002d4d:	48 89 e5             	mov    rbp,rsp
   140002d50:	48 83 ec 20          	sub    rsp,0x20
   140002d54:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d58:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d5c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d60:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d63:	48 63 d0             	movsxd rdx,eax
   140002d66:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d6a:	48 01 d0             	add    rax,rdx
   140002d6d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d71:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d78:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d7c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d80:	0f b7 d0             	movzx  edx,ax
   140002d83:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d87:	48 01 d0             	add    rax,rdx
   140002d8a:	48 83 c0 18          	add    rax,0x18
   140002d8e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d92:	eb 36                	jmp    140002dca <_FindPESection+0x7e>
   140002d94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d98:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d9b:	89 c0                	mov    eax,eax
   140002d9d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002da1:	72 1e                	jb     140002dc1 <_FindPESection+0x75>
   140002da3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002da7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002daa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dae:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002db1:	01 d0                	add    eax,edx
   140002db3:	89 c0                	mov    eax,eax
   140002db5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002db9:	73 06                	jae    140002dc1 <_FindPESection+0x75>
   140002dbb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dbf:	eb 1e                	jmp    140002ddf <_FindPESection+0x93>
   140002dc1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002dc5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002dca:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dce:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002dd2:	0f b7 c0             	movzx  eax,ax
   140002dd5:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002dd8:	72 ba                	jb     140002d94 <_FindPESection+0x48>
   140002dda:	b8 00 00 00 00       	mov    eax,0x0
   140002ddf:	48 83 c4 20          	add    rsp,0x20
   140002de3:	5d                   	pop    rbp
   140002de4:	c3                   	ret

0000000140002de5 <_FindPESectionByName>:
   140002de5:	55                   	push   rbp
   140002de6:	48 89 e5             	mov    rbp,rsp
   140002de9:	48 83 ec 40          	sub    rsp,0x40
   140002ded:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002df1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002df5:	48 89 c1             	mov    rcx,rax
   140002df8:	e8 2b 69 00 00       	call   140009728 <strlen>
   140002dfd:	48 83 f8 08          	cmp    rax,0x8
   140002e01:	76 0a                	jbe    140002e0d <_FindPESectionByName+0x28>
   140002e03:	b8 00 00 00 00       	mov    eax,0x0
   140002e08:	e9 98 00 00 00       	jmp    140002ea5 <_FindPESectionByName+0xc0>
   140002e0d:	48 8b 05 6c 87 00 00 	mov    rax,QWORD PTR [rip+0x876c]        # 14000b580 <.refptr.__ImageBase>
   140002e14:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e18:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e1c:	48 89 c1             	mov    rcx,rax
   140002e1f:	e8 ac fe ff ff       	call   140002cd0 <_ValidateImageBase>
   140002e24:	85 c0                	test   eax,eax
   140002e26:	75 07                	jne    140002e2f <_FindPESectionByName+0x4a>
   140002e28:	b8 00 00 00 00       	mov    eax,0x0
   140002e2d:	eb 76                	jmp    140002ea5 <_FindPESectionByName+0xc0>
   140002e2f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e33:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e36:	48 63 d0             	movsxd rdx,eax
   140002e39:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e3d:	48 01 d0             	add    rax,rdx
   140002e40:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e44:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e4b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e4f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e53:	0f b7 d0             	movzx  edx,ax
   140002e56:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e5a:	48 01 d0             	add    rax,rdx
   140002e5d:	48 83 c0 18          	add    rax,0x18
   140002e61:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e65:	eb 29                	jmp    140002e90 <_FindPESectionByName+0xab>
   140002e67:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e6b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e6f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e75:	48 89 c1             	mov    rcx,rax
   140002e78:	e8 b3 68 00 00       	call   140009730 <strncmp>
   140002e7d:	85 c0                	test   eax,eax
   140002e7f:	75 06                	jne    140002e87 <_FindPESectionByName+0xa2>
   140002e81:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e85:	eb 1e                	jmp    140002ea5 <_FindPESectionByName+0xc0>
   140002e87:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e8b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e90:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e94:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e98:	0f b7 c0             	movzx  eax,ax
   140002e9b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e9e:	72 c7                	jb     140002e67 <_FindPESectionByName+0x82>
   140002ea0:	b8 00 00 00 00       	mov    eax,0x0
   140002ea5:	48 83 c4 40          	add    rsp,0x40
   140002ea9:	5d                   	pop    rbp
   140002eaa:	c3                   	ret

0000000140002eab <__mingw_GetSectionForAddress>:
   140002eab:	55                   	push   rbp
   140002eac:	48 89 e5             	mov    rbp,rsp
   140002eaf:	48 83 ec 30          	sub    rsp,0x30
   140002eb3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002eb7:	48 8b 05 c2 86 00 00 	mov    rax,QWORD PTR [rip+0x86c2]        # 14000b580 <.refptr.__ImageBase>
   140002ebe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ec2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ec6:	48 89 c1             	mov    rcx,rax
   140002ec9:	e8 02 fe ff ff       	call   140002cd0 <_ValidateImageBase>
   140002ece:	85 c0                	test   eax,eax
   140002ed0:	75 07                	jne    140002ed9 <__mingw_GetSectionForAddress+0x2e>
   140002ed2:	b8 00 00 00 00       	mov    eax,0x0
   140002ed7:	eb 1c                	jmp    140002ef5 <__mingw_GetSectionForAddress+0x4a>
   140002ed9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002edd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002ee1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ee5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002ee9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002eed:	48 89 c1             	mov    rcx,rax
   140002ef0:	e8 57 fe ff ff       	call   140002d4c <_FindPESection>
   140002ef5:	48 83 c4 30          	add    rsp,0x30
   140002ef9:	5d                   	pop    rbp
   140002efa:	c3                   	ret

0000000140002efb <__mingw_GetSectionCount>:
   140002efb:	55                   	push   rbp
   140002efc:	48 89 e5             	mov    rbp,rsp
   140002eff:	48 83 ec 30          	sub    rsp,0x30
   140002f03:	48 8b 05 76 86 00 00 	mov    rax,QWORD PTR [rip+0x8676]        # 14000b580 <.refptr.__ImageBase>
   140002f0a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f0e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f12:	48 89 c1             	mov    rcx,rax
   140002f15:	e8 b6 fd ff ff       	call   140002cd0 <_ValidateImageBase>
   140002f1a:	85 c0                	test   eax,eax
   140002f1c:	75 07                	jne    140002f25 <__mingw_GetSectionCount+0x2a>
   140002f1e:	b8 00 00 00 00       	mov    eax,0x0
   140002f23:	eb 20                	jmp    140002f45 <__mingw_GetSectionCount+0x4a>
   140002f25:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f29:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f2c:	48 63 d0             	movsxd rdx,eax
   140002f2f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f33:	48 01 d0             	add    rax,rdx
   140002f36:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f3a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002f3e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f42:	0f b7 c0             	movzx  eax,ax
   140002f45:	48 83 c4 30          	add    rsp,0x30
   140002f49:	5d                   	pop    rbp
   140002f4a:	c3                   	ret

0000000140002f4b <_FindPESectionExec>:
   140002f4b:	55                   	push   rbp
   140002f4c:	48 89 e5             	mov    rbp,rsp
   140002f4f:	48 83 ec 40          	sub    rsp,0x40
   140002f53:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f57:	48 8b 05 22 86 00 00 	mov    rax,QWORD PTR [rip+0x8622]        # 14000b580 <.refptr.__ImageBase>
   140002f5e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f62:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f66:	48 89 c1             	mov    rcx,rax
   140002f69:	e8 62 fd ff ff       	call   140002cd0 <_ValidateImageBase>
   140002f6e:	85 c0                	test   eax,eax
   140002f70:	75 07                	jne    140002f79 <_FindPESectionExec+0x2e>
   140002f72:	b8 00 00 00 00       	mov    eax,0x0
   140002f77:	eb 78                	jmp    140002ff1 <_FindPESectionExec+0xa6>
   140002f79:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f7d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f80:	48 63 d0             	movsxd rdx,eax
   140002f83:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f87:	48 01 d0             	add    rax,rdx
   140002f8a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f8e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f95:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f99:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f9d:	0f b7 d0             	movzx  edx,ax
   140002fa0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fa4:	48 01 d0             	add    rax,rdx
   140002fa7:	48 83 c0 18          	add    rax,0x18
   140002fab:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002faf:	eb 2b                	jmp    140002fdc <_FindPESectionExec+0x91>
   140002fb1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fb5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fb8:	25 00 00 00 20       	and    eax,0x20000000
   140002fbd:	85 c0                	test   eax,eax
   140002fbf:	74 12                	je     140002fd3 <_FindPESectionExec+0x88>
   140002fc1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002fc6:	75 06                	jne    140002fce <_FindPESectionExec+0x83>
   140002fc8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fcc:	eb 23                	jmp    140002ff1 <_FindPESectionExec+0xa6>
   140002fce:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002fd3:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002fd7:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002fdc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fe0:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002fe4:	0f b7 c0             	movzx  eax,ax
   140002fe7:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002fea:	72 c5                	jb     140002fb1 <_FindPESectionExec+0x66>
   140002fec:	b8 00 00 00 00       	mov    eax,0x0
   140002ff1:	48 83 c4 40          	add    rsp,0x40
   140002ff5:	5d                   	pop    rbp
   140002ff6:	c3                   	ret

0000000140002ff7 <_GetPEImageBase>:
   140002ff7:	55                   	push   rbp
   140002ff8:	48 89 e5             	mov    rbp,rsp
   140002ffb:	48 83 ec 30          	sub    rsp,0x30
   140002fff:	48 8b 05 7a 85 00 00 	mov    rax,QWORD PTR [rip+0x857a]        # 14000b580 <.refptr.__ImageBase>
   140003006:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000300a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000300e:	48 89 c1             	mov    rcx,rax
   140003011:	e8 ba fc ff ff       	call   140002cd0 <_ValidateImageBase>
   140003016:	85 c0                	test   eax,eax
   140003018:	75 07                	jne    140003021 <_GetPEImageBase+0x2a>
   14000301a:	b8 00 00 00 00       	mov    eax,0x0
   14000301f:	eb 04                	jmp    140003025 <_GetPEImageBase+0x2e>
   140003021:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003025:	48 83 c4 30          	add    rsp,0x30
   140003029:	5d                   	pop    rbp
   14000302a:	c3                   	ret

000000014000302b <_IsNonwritableInCurrentImage>:
   14000302b:	55                   	push   rbp
   14000302c:	48 89 e5             	mov    rbp,rsp
   14000302f:	48 83 ec 40          	sub    rsp,0x40
   140003033:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003037:	48 8b 05 42 85 00 00 	mov    rax,QWORD PTR [rip+0x8542]        # 14000b580 <.refptr.__ImageBase>
   14000303e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003042:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003046:	48 89 c1             	mov    rcx,rax
   140003049:	e8 82 fc ff ff       	call   140002cd0 <_ValidateImageBase>
   14000304e:	85 c0                	test   eax,eax
   140003050:	75 07                	jne    140003059 <_IsNonwritableInCurrentImage+0x2e>
   140003052:	b8 00 00 00 00       	mov    eax,0x0
   140003057:	eb 3d                	jmp    140003096 <_IsNonwritableInCurrentImage+0x6b>
   140003059:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000305d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003061:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003065:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003069:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000306d:	48 89 c1             	mov    rcx,rax
   140003070:	e8 d7 fc ff ff       	call   140002d4c <_FindPESection>
   140003075:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003079:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000307e:	75 07                	jne    140003087 <_IsNonwritableInCurrentImage+0x5c>
   140003080:	b8 00 00 00 00       	mov    eax,0x0
   140003085:	eb 0f                	jmp    140003096 <_IsNonwritableInCurrentImage+0x6b>
   140003087:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000308b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000308e:	f7 d0                	not    eax
   140003090:	c1 e8 1f             	shr    eax,0x1f
   140003093:	0f b6 c0             	movzx  eax,al
   140003096:	48 83 c4 40          	add    rsp,0x40
   14000309a:	5d                   	pop    rbp
   14000309b:	c3                   	ret

000000014000309c <__mingw_enum_import_library_names>:
   14000309c:	55                   	push   rbp
   14000309d:	48 89 e5             	mov    rbp,rsp
   1400030a0:	48 83 ec 50          	sub    rsp,0x50
   1400030a4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400030a7:	48 8b 05 d2 84 00 00 	mov    rax,QWORD PTR [rip+0x84d2]        # 14000b580 <.refptr.__ImageBase>
   1400030ae:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400030b2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030b6:	48 89 c1             	mov    rcx,rax
   1400030b9:	e8 12 fc ff ff       	call   140002cd0 <_ValidateImageBase>
   1400030be:	85 c0                	test   eax,eax
   1400030c0:	75 0a                	jne    1400030cc <__mingw_enum_import_library_names+0x30>
   1400030c2:	b8 00 00 00 00       	mov    eax,0x0
   1400030c7:	e9 ab 00 00 00       	jmp    140003177 <__mingw_enum_import_library_names+0xdb>
   1400030cc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030d0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   1400030d3:	48 63 d0             	movsxd rdx,eax
   1400030d6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030da:	48 01 d0             	add    rax,rdx
   1400030dd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400030e1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030e5:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   1400030eb:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400030ee:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400030f2:	75 07                	jne    1400030fb <__mingw_enum_import_library_names+0x5f>
   1400030f4:	b8 00 00 00 00       	mov    eax,0x0
   1400030f9:	eb 7c                	jmp    140003177 <__mingw_enum_import_library_names+0xdb>
   1400030fb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030fe:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003102:	48 89 c1             	mov    rcx,rax
   140003105:	e8 42 fc ff ff       	call   140002d4c <_FindPESection>
   14000310a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000310e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003113:	75 07                	jne    14000311c <__mingw_enum_import_library_names+0x80>
   140003115:	b8 00 00 00 00       	mov    eax,0x0
   14000311a:	eb 5b                	jmp    140003177 <__mingw_enum_import_library_names+0xdb>
   14000311c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000311f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003123:	48 01 d0             	add    rax,rdx
   140003126:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000312a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000312f:	75 07                	jne    140003138 <__mingw_enum_import_library_names+0x9c>
   140003131:	b8 00 00 00 00       	mov    eax,0x0
   140003136:	eb 3f                	jmp    140003177 <__mingw_enum_import_library_names+0xdb>
   140003138:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000313c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000313f:	85 c0                	test   eax,eax
   140003141:	75 0b                	jne    14000314e <__mingw_enum_import_library_names+0xb2>
   140003143:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003147:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000314a:	85 c0                	test   eax,eax
   14000314c:	74 23                	je     140003171 <__mingw_enum_import_library_names+0xd5>
   14000314e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003152:	7f 12                	jg     140003166 <__mingw_enum_import_library_names+0xca>
   140003154:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003158:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000315b:	89 c2                	mov    edx,eax
   14000315d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003161:	48 01 d0             	add    rax,rdx
   140003164:	eb 11                	jmp    140003177 <__mingw_enum_import_library_names+0xdb>
   140003166:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000316a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000316f:	eb c7                	jmp    140003138 <__mingw_enum_import_library_names+0x9c>
   140003171:	90                   	nop
   140003172:	b8 00 00 00 00       	mov    eax,0x0
   140003177:	48 83 c4 50          	add    rsp,0x50
   14000317b:	5d                   	pop    rbp
   14000317c:	c3                   	ret
   14000317d:	90                   	nop
   14000317e:	90                   	nop
   14000317f:	90                   	nop

0000000140003180 <___chkstk_ms>:
   140003180:	51                   	push   rcx
   140003181:	50                   	push   rax
   140003182:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003188:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000318d:	72 19                	jb     1400031a8 <___chkstk_ms+0x28>
   14000318f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003196:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000319a:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400031a0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400031a6:	77 e7                	ja     14000318f <___chkstk_ms+0xf>
   1400031a8:	48 29 c1             	sub    rcx,rax
   1400031ab:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400031af:	58                   	pop    rax
   1400031b0:	59                   	pop    rcx
   1400031b1:	c3                   	ret
   1400031b2:	90                   	nop
   1400031b3:	90                   	nop
   1400031b4:	90                   	nop
   1400031b5:	90                   	nop
   1400031b6:	90                   	nop
   1400031b7:	90                   	nop
   1400031b8:	90                   	nop
   1400031b9:	90                   	nop
   1400031ba:	90                   	nop
   1400031bb:	90                   	nop
   1400031bc:	90                   	nop
   1400031bd:	90                   	nop
   1400031be:	90                   	nop
   1400031bf:	90                   	nop

00000001400031c0 <__mingw_printf>:
   1400031c0:	55                   	push   rbp
   1400031c1:	53                   	push   rbx
   1400031c2:	48 83 ec 48          	sub    rsp,0x48
   1400031c6:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   1400031cb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400031cf:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400031d3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400031d7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   1400031db:	48 8d 45 28          	lea    rax,[rbp+0x28]
   1400031df:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031e3:	b9 01 00 00 00       	mov    ecx,0x1
   1400031e8:	e8 c3 5e 00 00       	call   1400090b0 <__acrt_iob_func>
   1400031ed:	48 89 c1             	mov    rcx,rax
   1400031f0:	e8 3b 5d 00 00       	call   140008f30 <_lock_file>
   1400031f5:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   1400031f9:	b9 01 00 00 00       	mov    ecx,0x1
   1400031fe:	e8 ad 5e 00 00       	call   1400090b0 <__acrt_iob_func>
   140003203:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003207:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
   14000320c:	49 89 d1             	mov    r9,rdx
   14000320f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140003215:	48 89 c2             	mov    rdx,rax
   140003218:	b9 00 60 00 00       	mov    ecx,0x6000
   14000321d:	e8 b1 1f 00 00       	call   1400051d3 <__mingw_pformat>
   140003222:	89 c3                	mov    ebx,eax
   140003224:	b9 01 00 00 00       	mov    ecx,0x1
   140003229:	e8 82 5e 00 00       	call   1400090b0 <__acrt_iob_func>
   14000322e:	48 89 c1             	mov    rcx,rax
   140003231:	e8 84 5d 00 00       	call   140008fba <_unlock_file>
   140003236:	89 d8                	mov    eax,ebx
   140003238:	48 83 c4 48          	add    rsp,0x48
   14000323c:	5b                   	pop    rbx
   14000323d:	5d                   	pop    rbp
   14000323e:	c3                   	ret
   14000323f:	90                   	nop

0000000140003240 <__pformat_putc>:
   140003240:	55                   	push   rbp
   140003241:	48 89 e5             	mov    rbp,rsp
   140003244:	48 83 ec 20          	sub    rsp,0x20
   140003248:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000324b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000324f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003253:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003256:	25 00 40 00 00       	and    eax,0x4000
   14000325b:	85 c0                	test   eax,eax
   14000325d:	75 12                	jne    140003271 <__pformat_putc+0x31>
   14000325f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003263:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   140003266:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000326a:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000326d:	39 c2                	cmp    edx,eax
   14000326f:	7e 3b                	jle    1400032ac <__pformat_putc+0x6c>
   140003271:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003275:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003278:	25 00 20 00 00       	and    eax,0x2000
   14000327d:	85 c0                	test   eax,eax
   14000327f:	74 13                	je     140003294 <__pformat_putc+0x54>
   140003281:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003285:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003288:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000328b:	89 c1                	mov    ecx,eax
   14000328d:	e8 56 64 00 00       	call   1400096e8 <fputc>
   140003292:	eb 18                	jmp    1400032ac <__pformat_putc+0x6c>
   140003294:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003298:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   14000329b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000329f:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400032a2:	48 98                	cdqe
   1400032a4:	48 01 d0             	add    rax,rdx
   1400032a7:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400032aa:	88 10                	mov    BYTE PTR [rax],dl
   1400032ac:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032b0:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400032b3:	8d 50 01             	lea    edx,[rax+0x1]
   1400032b6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032ba:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   1400032bd:	90                   	nop
   1400032be:	48 83 c4 20          	add    rsp,0x20
   1400032c2:	5d                   	pop    rbp
   1400032c3:	c3                   	ret

00000001400032c4 <__pformat_putchars>:
   1400032c4:	55                   	push   rbp
   1400032c5:	48 89 e5             	mov    rbp,rsp
   1400032c8:	48 83 ec 20          	sub    rsp,0x20
   1400032cc:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400032d0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400032d3:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400032d7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032db:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032de:	85 c0                	test   eax,eax
   1400032e0:	78 16                	js     1400032f8 <__pformat_putchars+0x34>
   1400032e2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032e6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032e9:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400032ec:	7e 0a                	jle    1400032f8 <__pformat_putchars+0x34>
   1400032ee:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032f2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032f5:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400032f8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032fc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032ff:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003302:	7d 15                	jge    140003319 <__pformat_putchars+0x55>
   140003304:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003308:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000330b:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000330e:	89 c2                	mov    edx,eax
   140003310:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003314:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003317:	eb 0b                	jmp    140003324 <__pformat_putchars+0x60>
   140003319:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000331d:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003324:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003328:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000332b:	85 c0                	test   eax,eax
   14000332d:	7e 57                	jle    140003386 <__pformat_putchars+0xc2>
   14000332f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003333:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003336:	25 00 04 00 00       	and    eax,0x400
   14000333b:	85 c0                	test   eax,eax
   14000333d:	75 47                	jne    140003386 <__pformat_putchars+0xc2>
   14000333f:	eb 11                	jmp    140003352 <__pformat_putchars+0x8e>
   140003341:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003345:	48 89 c2             	mov    rdx,rax
   140003348:	b9 20 00 00 00       	mov    ecx,0x20
   14000334d:	e8 ee fe ff ff       	call   140003240 <__pformat_putc>
   140003352:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003356:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003359:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000335c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003360:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003363:	85 c0                	test   eax,eax
   140003365:	75 da                	jne    140003341 <__pformat_putchars+0x7d>
   140003367:	eb 1d                	jmp    140003386 <__pformat_putchars+0xc2>
   140003369:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000336d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003371:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003375:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003378:	0f be c0             	movsx  eax,al
   14000337b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000337f:	89 c1                	mov    ecx,eax
   140003381:	e8 ba fe ff ff       	call   140003240 <__pformat_putc>
   140003386:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003389:	8d 50 ff             	lea    edx,[rax-0x1]
   14000338c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000338f:	85 c0                	test   eax,eax
   140003391:	75 d6                	jne    140003369 <__pformat_putchars+0xa5>
   140003393:	eb 11                	jmp    1400033a6 <__pformat_putchars+0xe2>
   140003395:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003399:	48 89 c2             	mov    rdx,rax
   14000339c:	b9 20 00 00 00       	mov    ecx,0x20
   1400033a1:	e8 9a fe ff ff       	call   140003240 <__pformat_putc>
   1400033a6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033aa:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033ad:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400033b0:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400033b4:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400033b7:	85 c0                	test   eax,eax
   1400033b9:	7f da                	jg     140003395 <__pformat_putchars+0xd1>
   1400033bb:	90                   	nop
   1400033bc:	90                   	nop
   1400033bd:	48 83 c4 20          	add    rsp,0x20
   1400033c1:	5d                   	pop    rbp
   1400033c2:	c3                   	ret

00000001400033c3 <__pformat_puts>:
   1400033c3:	55                   	push   rbp
   1400033c4:	48 89 e5             	mov    rbp,rsp
   1400033c7:	48 83 ec 20          	sub    rsp,0x20
   1400033cb:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400033cf:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400033d3:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400033d8:	75 0b                	jne    1400033e5 <__pformat_puts+0x22>
   1400033da:	48 8d 05 4f 7f 00 00 	lea    rax,[rip+0x7f4f]        # 14000b330 <.rdata>
   1400033e1:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400033e5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400033e9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033ec:	85 c0                	test   eax,eax
   1400033ee:	78 2f                	js     14000341f <__pformat_puts+0x5c>
   1400033f0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400033f4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033f7:	48 63 d0             	movsxd rdx,eax
   1400033fa:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033fe:	48 89 c1             	mov    rcx,rax
   140003401:	e8 4a 5a 00 00       	call   140008e50 <strnlen>
   140003406:	89 c1                	mov    ecx,eax
   140003408:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000340c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003410:	49 89 d0             	mov    r8,rdx
   140003413:	89 ca                	mov    edx,ecx
   140003415:	48 89 c1             	mov    rcx,rax
   140003418:	e8 a7 fe ff ff       	call   1400032c4 <__pformat_putchars>
   14000341d:	eb 23                	jmp    140003442 <__pformat_puts+0x7f>
   14000341f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003423:	48 89 c1             	mov    rcx,rax
   140003426:	e8 fd 62 00 00       	call   140009728 <strlen>
   14000342b:	89 c1                	mov    ecx,eax
   14000342d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003431:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003435:	49 89 d0             	mov    r8,rdx
   140003438:	89 ca                	mov    edx,ecx
   14000343a:	48 89 c1             	mov    rcx,rax
   14000343d:	e8 82 fe ff ff       	call   1400032c4 <__pformat_putchars>
   140003442:	90                   	nop
   140003443:	48 83 c4 20          	add    rsp,0x20
   140003447:	5d                   	pop    rbp
   140003448:	c3                   	ret

0000000140003449 <__pformat_wputchars>:
   140003449:	55                   	push   rbp
   14000344a:	48 89 e5             	mov    rbp,rsp
   14000344d:	48 83 ec 50          	sub    rsp,0x50
   140003451:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003455:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003458:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000345c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   140003463:	00 
   140003464:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003468:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000346b:	85 c0                	test   eax,eax
   14000346d:	78 16                	js     140003485 <__pformat_wputchars+0x3c>
   14000346f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003473:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003476:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003479:	7e 0a                	jle    140003485 <__pformat_wputchars+0x3c>
   14000347b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000347f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003482:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003485:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003489:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000348c:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000348f:	7d 15                	jge    1400034a6 <__pformat_wputchars+0x5d>
   140003491:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003495:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003498:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000349b:	89 c2                	mov    edx,eax
   14000349d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034a1:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400034a4:	eb 0b                	jmp    1400034b1 <__pformat_wputchars+0x68>
   1400034a6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034aa:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400034b1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034b5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034b8:	85 c0                	test   eax,eax
   1400034ba:	7e 6e                	jle    14000352a <__pformat_wputchars+0xe1>
   1400034bc:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034c0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400034c3:	25 00 04 00 00       	and    eax,0x400
   1400034c8:	85 c0                	test   eax,eax
   1400034ca:	75 5e                	jne    14000352a <__pformat_wputchars+0xe1>
   1400034cc:	eb 11                	jmp    1400034df <__pformat_wputchars+0x96>
   1400034ce:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034d2:	48 89 c2             	mov    rdx,rax
   1400034d5:	b9 20 00 00 00       	mov    ecx,0x20
   1400034da:	e8 61 fd ff ff       	call   140003240 <__pformat_putc>
   1400034df:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034e3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034e6:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400034e9:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034ed:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400034f0:	85 c0                	test   eax,eax
   1400034f2:	75 da                	jne    1400034ce <__pformat_wputchars+0x85>
   1400034f4:	eb 34                	jmp    14000352a <__pformat_wputchars+0xe1>
   1400034f6:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400034fa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400034fe:	eb 1d                	jmp    14000351d <__pformat_wputchars+0xd4>
   140003500:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003504:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003508:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000350c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000350f:	0f be c0             	movsx  eax,al
   140003512:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003516:	89 c1                	mov    ecx,eax
   140003518:	e8 23 fd ff ff       	call   140003240 <__pformat_putc>
   14000351d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003520:	8d 50 ff             	lea    edx,[rax-0x1]
   140003523:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003526:	85 c0                	test   eax,eax
   140003528:	7f d6                	jg     140003500 <__pformat_wputchars+0xb7>
   14000352a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000352d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003530:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003533:	85 c0                	test   eax,eax
   140003535:	7e 41                	jle    140003578 <__pformat_wputchars+0x12f>
   140003537:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000353b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000353f:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003543:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140003546:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   14000354a:	0f b7 d0             	movzx  edx,ax
   14000354d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003551:	49 89 c8             	mov    r8,rcx
   140003554:	48 89 c1             	mov    rcx,rax
   140003557:	e8 84 5b 00 00       	call   1400090e0 <wcrtomb>
   14000355c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000355f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003563:	7f 91                	jg     1400034f6 <__pformat_wputchars+0xad>
   140003565:	eb 11                	jmp    140003578 <__pformat_wputchars+0x12f>
   140003567:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000356b:	48 89 c2             	mov    rdx,rax
   14000356e:	b9 20 00 00 00       	mov    ecx,0x20
   140003573:	e8 c8 fc ff ff       	call   140003240 <__pformat_putc>
   140003578:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000357c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000357f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003582:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003586:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003589:	85 c0                	test   eax,eax
   14000358b:	7f da                	jg     140003567 <__pformat_wputchars+0x11e>
   14000358d:	90                   	nop
   14000358e:	90                   	nop
   14000358f:	48 83 c4 50          	add    rsp,0x50
   140003593:	5d                   	pop    rbp
   140003594:	c3                   	ret

0000000140003595 <__pformat_wcputs>:
   140003595:	55                   	push   rbp
   140003596:	48 89 e5             	mov    rbp,rsp
   140003599:	48 83 ec 20          	sub    rsp,0x20
   14000359d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400035a1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400035a5:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400035aa:	75 0b                	jne    1400035b7 <__pformat_wcputs+0x22>
   1400035ac:	48 8d 05 85 7d 00 00 	lea    rax,[rip+0x7d85]        # 14000b338 <.rdata+0x8>
   1400035b3:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400035b7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400035bb:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400035be:	85 c0                	test   eax,eax
   1400035c0:	78 2f                	js     1400035f1 <__pformat_wcputs+0x5c>
   1400035c2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400035c6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400035c9:	48 63 d0             	movsxd rdx,eax
   1400035cc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035d0:	48 89 c1             	mov    rcx,rax
   1400035d3:	e8 28 58 00 00       	call   140008e00 <wcsnlen>
   1400035d8:	89 c1                	mov    ecx,eax
   1400035da:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400035de:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035e2:	49 89 d0             	mov    r8,rdx
   1400035e5:	89 ca                	mov    edx,ecx
   1400035e7:	48 89 c1             	mov    rcx,rax
   1400035ea:	e8 5a fe ff ff       	call   140003449 <__pformat_wputchars>
   1400035ef:	eb 23                	jmp    140003614 <__pformat_wcputs+0x7f>
   1400035f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035f5:	48 89 c1             	mov    rcx,rax
   1400035f8:	e8 43 61 00 00       	call   140009740 <wcslen>
   1400035fd:	89 c1                	mov    ecx,eax
   1400035ff:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003603:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003607:	49 89 d0             	mov    r8,rdx
   14000360a:	89 ca                	mov    edx,ecx
   14000360c:	48 89 c1             	mov    rcx,rax
   14000360f:	e8 35 fe ff ff       	call   140003449 <__pformat_wputchars>
   140003614:	90                   	nop
   140003615:	48 83 c4 20          	add    rsp,0x20
   140003619:	5d                   	pop    rbp
   14000361a:	c3                   	ret

000000014000361b <__pformat_int_bufsiz>:
   14000361b:	55                   	push   rbp
   14000361c:	48 89 e5             	mov    rbp,rsp
   14000361f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003622:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003625:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003629:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000362c:	83 e8 01             	sub    eax,0x1
   14000362f:	48 98                	cdqe
   140003631:	48 83 c0 40          	add    rax,0x40
   140003635:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140003638:	48 63 ca             	movsxd rcx,edx
   14000363b:	ba 00 00 00 00       	mov    edx,0x0
   140003640:	48 f7 f1             	div    rcx
   140003643:	89 c2                	mov    edx,eax
   140003645:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140003648:	01 d0                	add    eax,edx
   14000364a:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   14000364d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003651:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003654:	ba 00 00 00 00       	mov    edx,0x0
   140003659:	85 c0                	test   eax,eax
   14000365b:	0f 48 c2             	cmovs  eax,edx
   14000365e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   140003661:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003665:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003668:	25 00 10 00 00       	and    eax,0x1000
   14000366d:	85 c0                	test   eax,eax
   14000366f:	74 29                	je     14000369a <__pformat_int_bufsiz+0x7f>
   140003671:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003675:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003679:	66 85 c0             	test   ax,ax
   14000367c:	74 1c                	je     14000369a <__pformat_int_bufsiz+0x7f>
   14000367e:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003681:	48 63 d0             	movsxd rdx,eax
   140003684:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   14000368b:	48 89 d1             	mov    rcx,rdx
   14000368e:	48 c1 e9 20          	shr    rcx,0x20
   140003692:	99                   	cdq
   140003693:	89 c8                	mov    eax,ecx
   140003695:	29 d0                	sub    eax,edx
   140003697:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   14000369a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000369e:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400036a1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400036a4:	39 c2                	cmp    edx,eax
   1400036a6:	0f 4d c2             	cmovge eax,edx
   1400036a9:	5d                   	pop    rbp
   1400036aa:	c3                   	ret

00000001400036ab <__pformat_int>:
   1400036ab:	55                   	push   rbp
   1400036ac:	53                   	push   rbx
   1400036ad:	48 83 ec 58          	sub    rsp,0x58
   1400036b1:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400036b6:	48 89 cb             	mov    rbx,rcx
   1400036b9:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   1400036bc:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   1400036c0:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   1400036c4:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   1400036c8:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400036cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036d0:	49 89 c0             	mov    r8,rax
   1400036d3:	ba 03 00 00 00       	mov    edx,0x3
   1400036d8:	b9 01 00 00 00       	mov    ecx,0x1
   1400036dd:	e8 39 ff ff ff       	call   14000361b <__pformat_int_bufsiz>
   1400036e2:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400036e5:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   1400036ec:	00 
   1400036ed:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400036f0:	48 98                	cdqe
   1400036f2:	48 83 c0 0f          	add    rax,0xf
   1400036f6:	48 c1 e8 04          	shr    rax,0x4
   1400036fa:	48 c1 e0 04          	shl    rax,0x4
   1400036fe:	e8 7d fa ff ff       	call   140003180 <___chkstk_ms>
   140003703:	48 29 c4             	sub    rsp,rax
   140003706:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000370b:	48 83 c0 0f          	add    rax,0xf
   14000370f:	48 c1 e8 04          	shr    rax,0x4
   140003713:	48 c1 e0 04          	shl    rax,0x4
   140003717:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000371b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000371f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003723:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003727:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000372a:	25 80 00 00 00       	and    eax,0x80
   14000372f:	85 c0                	test   eax,eax
   140003731:	0f 84 ea 00 00 00    	je     140003821 <__pformat_int+0x176>
   140003737:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000373b:	48 85 c0             	test   rax,rax
   14000373e:	79 10                	jns    140003750 <__pformat_int+0xa5>
   140003740:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003744:	48 f7 d8             	neg    rax
   140003747:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000374b:	e9 d1 00 00 00       	jmp    140003821 <__pformat_int+0x176>
   140003750:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003754:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003757:	24 7f                	and    al,0x7f
   140003759:	89 c2                	mov    edx,eax
   14000375b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000375f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003762:	e9 ba 00 00 00       	jmp    140003821 <__pformat_int+0x176>
   140003767:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000376b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000376f:	74 54                	je     1400037c5 <__pformat_int+0x11a>
   140003771:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003775:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003778:	25 00 10 00 00       	and    eax,0x1000
   14000377d:	85 c0                	test   eax,eax
   14000377f:	74 44                	je     1400037c5 <__pformat_int+0x11a>
   140003781:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003785:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003789:	66 85 c0             	test   ax,ax
   14000378c:	74 37                	je     1400037c5 <__pformat_int+0x11a>
   14000378e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003792:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   140003796:	48 89 c2             	mov    rdx,rax
   140003799:	48 89 d0             	mov    rax,rdx
   14000379c:	48 c1 f8 3f          	sar    rax,0x3f
   1400037a0:	48 c1 e8 3e          	shr    rax,0x3e
   1400037a4:	48 01 c2             	add    rdx,rax
   1400037a7:	83 e2 03             	and    edx,0x3
   1400037aa:	48 29 c2             	sub    rdx,rax
   1400037ad:	48 89 d0             	mov    rax,rdx
   1400037b0:	48 83 f8 03          	cmp    rax,0x3
   1400037b4:	75 0f                	jne    1400037c5 <__pformat_int+0x11a>
   1400037b6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037ba:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037be:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037c2:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   1400037c5:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   1400037c9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400037d0:	cc cc cc 
   1400037d3:	48 89 c8             	mov    rax,rcx
   1400037d6:	48 f7 e2             	mul    rdx
   1400037d9:	48 c1 ea 03          	shr    rdx,0x3
   1400037dd:	48 89 d0             	mov    rax,rdx
   1400037e0:	48 c1 e0 02          	shl    rax,0x2
   1400037e4:	48 01 d0             	add    rax,rdx
   1400037e7:	48 01 c0             	add    rax,rax
   1400037ea:	48 29 c1             	sub    rcx,rax
   1400037ed:	48 89 ca             	mov    rdx,rcx
   1400037f0:	89 d0                	mov    eax,edx
   1400037f2:	8d 48 30             	lea    ecx,[rax+0x30]
   1400037f5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037f9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037fd:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003801:	89 ca                	mov    edx,ecx
   140003803:	88 10                	mov    BYTE PTR [rax],dl
   140003805:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003809:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003810:	cc cc cc 
   140003813:	48 f7 e2             	mul    rdx
   140003816:	48 89 d0             	mov    rax,rdx
   140003819:	48 c1 e8 03          	shr    rax,0x3
   14000381d:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140003821:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003825:	48 85 c0             	test   rax,rax
   140003828:	0f 85 39 ff ff ff    	jne    140003767 <__pformat_int+0xbc>
   14000382e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003832:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003835:	85 c0                	test   eax,eax
   140003837:	7e 3e                	jle    140003877 <__pformat_int+0x1cc>
   140003839:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000383d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003840:	89 c1                	mov    ecx,eax
   140003842:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003846:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000384a:	89 c2                	mov    edx,eax
   14000384c:	89 c8                	mov    eax,ecx
   14000384e:	29 d0                	sub    eax,edx
   140003850:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003853:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003857:	7e 1e                	jle    140003877 <__pformat_int+0x1cc>
   140003859:	eb 0f                	jmp    14000386a <__pformat_int+0x1bf>
   14000385b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000385f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003863:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003867:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000386a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000386d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003870:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   140003873:	85 c0                	test   eax,eax
   140003875:	7f e4                	jg     14000385b <__pformat_int+0x1b0>
   140003877:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000387b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000387f:	75 1a                	jne    14000389b <__pformat_int+0x1f0>
   140003881:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003885:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003888:	85 c0                	test   eax,eax
   14000388a:	74 0f                	je     14000389b <__pformat_int+0x1f0>
   14000388c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003890:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003894:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003898:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000389b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000389f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038a2:	85 c0                	test   eax,eax
   1400038a4:	0f 8e ce 00 00 00    	jle    140003978 <__pformat_int+0x2cd>
   1400038aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ae:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038b1:	89 c1                	mov    ecx,eax
   1400038b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038b7:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400038bb:	89 c2                	mov    edx,eax
   1400038bd:	89 c8                	mov    eax,ecx
   1400038bf:	29 d0                	sub    eax,edx
   1400038c1:	89 c2                	mov    edx,eax
   1400038c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038c7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400038ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ce:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038d1:	85 c0                	test   eax,eax
   1400038d3:	0f 8e 9f 00 00 00    	jle    140003978 <__pformat_int+0x2cd>
   1400038d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038dd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038e0:	25 c0 01 00 00       	and    eax,0x1c0
   1400038e5:	85 c0                	test   eax,eax
   1400038e7:	74 11                	je     1400038fa <__pformat_int+0x24f>
   1400038e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ed:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038f0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400038f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038f7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400038fa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038fe:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003901:	85 c0                	test   eax,eax
   140003903:	79 3b                	jns    140003940 <__pformat_int+0x295>
   140003905:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003909:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000390c:	25 00 06 00 00       	and    eax,0x600
   140003911:	3d 00 02 00 00       	cmp    eax,0x200
   140003916:	75 28                	jne    140003940 <__pformat_int+0x295>
   140003918:	eb 0f                	jmp    140003929 <__pformat_int+0x27e>
   14000391a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000391e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003922:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003926:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003929:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000392d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003930:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003933:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003937:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000393a:	85 c0                	test   eax,eax
   14000393c:	7f dc                	jg     14000391a <__pformat_int+0x26f>
   14000393e:	eb 38                	jmp    140003978 <__pformat_int+0x2cd>
   140003940:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003944:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003947:	25 00 04 00 00       	and    eax,0x400
   14000394c:	85 c0                	test   eax,eax
   14000394e:	75 28                	jne    140003978 <__pformat_int+0x2cd>
   140003950:	eb 11                	jmp    140003963 <__pformat_int+0x2b8>
   140003952:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003956:	48 89 c2             	mov    rdx,rax
   140003959:	b9 20 00 00 00       	mov    ecx,0x20
   14000395e:	e8 dd f8 ff ff       	call   140003240 <__pformat_putc>
   140003963:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003967:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000396a:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000396d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003971:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003974:	85 c0                	test   eax,eax
   140003976:	7f da                	jg     140003952 <__pformat_int+0x2a7>
   140003978:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000397c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000397f:	25 80 00 00 00       	and    eax,0x80
   140003984:	85 c0                	test   eax,eax
   140003986:	74 11                	je     140003999 <__pformat_int+0x2ee>
   140003988:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000398c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003990:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003994:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   140003997:	eb 5a                	jmp    1400039f3 <__pformat_int+0x348>
   140003999:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000399d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400039a0:	25 00 01 00 00       	and    eax,0x100
   1400039a5:	85 c0                	test   eax,eax
   1400039a7:	74 11                	je     1400039ba <__pformat_int+0x30f>
   1400039a9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039ad:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400039b1:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400039b5:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400039b8:	eb 39                	jmp    1400039f3 <__pformat_int+0x348>
   1400039ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039be:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400039c1:	83 e0 40             	and    eax,0x40
   1400039c4:	85 c0                	test   eax,eax
   1400039c6:	74 2b                	je     1400039f3 <__pformat_int+0x348>
   1400039c8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039cc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400039d0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400039d4:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400039d7:	eb 1a                	jmp    1400039f3 <__pformat_int+0x348>
   1400039d9:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   1400039de:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039e2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400039e5:	0f be c0             	movsx  eax,al
   1400039e8:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400039ec:	89 c1                	mov    ecx,eax
   1400039ee:	e8 4d f8 ff ff       	call   140003240 <__pformat_putc>
   1400039f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039f7:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   1400039fb:	72 dc                	jb     1400039d9 <__pformat_int+0x32e>
   1400039fd:	eb 11                	jmp    140003a10 <__pformat_int+0x365>
   1400039ff:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003a03:	48 89 c2             	mov    rdx,rax
   140003a06:	b9 20 00 00 00       	mov    ecx,0x20
   140003a0b:	e8 30 f8 ff ff       	call   140003240 <__pformat_putc>
   140003a10:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003a14:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003a17:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003a1a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003a1e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003a21:	85 c0                	test   eax,eax
   140003a23:	7f da                	jg     1400039ff <__pformat_int+0x354>
   140003a25:	90                   	nop
   140003a26:	90                   	nop
   140003a27:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003a2b:	5b                   	pop    rbx
   140003a2c:	5d                   	pop    rbp
   140003a2d:	c3                   	ret

0000000140003a2e <__pformat_xint>:
   140003a2e:	55                   	push   rbp
   140003a2f:	53                   	push   rbx
   140003a30:	48 83 ec 68          	sub    rsp,0x68
   140003a34:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003a39:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003a3c:	48 89 d3             	mov    rbx,rdx
   140003a3f:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140003a42:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   140003a46:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003a4a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   140003a4e:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003a52:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a56:	74 1e                	je     140003a76 <__pformat_xint+0x48>
   140003a58:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a5c:	74 06                	je     140003a64 <__pformat_xint+0x36>
   140003a5e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a62:	75 09                	jne    140003a6d <__pformat_xint+0x3f>
   140003a64:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003a6b:	eb 10                	jmp    140003a7d <__pformat_xint+0x4f>
   140003a6d:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003a74:	eb 07                	jmp    140003a7d <__pformat_xint+0x4f>
   140003a76:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140003a7d:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003a81:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003a84:	49 89 d0             	mov    r8,rdx
   140003a87:	89 c2                	mov    edx,eax
   140003a89:	b9 02 00 00 00       	mov    ecx,0x2
   140003a8e:	e8 88 fb ff ff       	call   14000361b <__pformat_int_bufsiz>
   140003a93:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140003a96:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   140003a9d:	00 
   140003a9e:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140003aa1:	48 98                	cdqe
   140003aa3:	48 83 c0 0f          	add    rax,0xf
   140003aa7:	48 c1 e8 04          	shr    rax,0x4
   140003aab:	48 c1 e0 04          	shl    rax,0x4
   140003aaf:	e8 cc f6 ff ff       	call   140003180 <___chkstk_ms>
   140003ab4:	48 29 c4             	sub    rsp,rax
   140003ab7:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003abc:	48 83 c0 0f          	add    rax,0xf
   140003ac0:	48 c1 e8 04          	shr    rax,0x4
   140003ac4:	48 c1 e0 04          	shl    rax,0x4
   140003ac8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140003acc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003ad0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003ad4:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003ad8:	74 1e                	je     140003af8 <__pformat_xint+0xca>
   140003ada:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003ade:	74 06                	je     140003ae6 <__pformat_xint+0xb8>
   140003ae0:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003ae4:	75 09                	jne    140003aef <__pformat_xint+0xc1>
   140003ae6:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003aed:	eb 10                	jmp    140003aff <__pformat_xint+0xd1>
   140003aef:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003af6:	eb 67                	jmp    140003b5f <__pformat_xint+0x131>
   140003af8:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003aff:	eb 5e                	jmp    140003b5f <__pformat_xint+0x131>
   140003b01:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003b05:	89 c2                	mov    edx,eax
   140003b07:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003b0a:	21 d0                	and    eax,edx
   140003b0c:	8d 48 30             	lea    ecx,[rax+0x30]
   140003b0f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b13:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b17:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b1b:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003b1f:	89 ca                	mov    edx,ecx
   140003b21:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b25:	88 10                	mov    BYTE PTR [rax],dl
   140003b27:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b2b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003b2e:	3c 39                	cmp    al,0x39
   140003b30:	7e 1a                	jle    140003b4c <__pformat_xint+0x11e>
   140003b32:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b36:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003b39:	83 c0 07             	add    eax,0x7
   140003b3c:	89 c2                	mov    edx,eax
   140003b3e:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003b41:	83 e0 20             	and    eax,0x20
   140003b44:	09 c2                	or     edx,eax
   140003b46:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b4a:	88 10                	mov    BYTE PTR [rax],dl
   140003b4c:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003b50:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003b53:	89 c1                	mov    ecx,eax
   140003b55:	48 d3 ea             	shr    rdx,cl
   140003b58:	48 89 d0             	mov    rax,rdx
   140003b5b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003b5f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003b63:	48 85 c0             	test   rax,rax
   140003b66:	75 99                	jne    140003b01 <__pformat_xint+0xd3>
   140003b68:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b6c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b70:	75 13                	jne    140003b85 <__pformat_xint+0x157>
   140003b72:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b76:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b79:	80 e4 f7             	and    ah,0xf7
   140003b7c:	89 c2                	mov    edx,eax
   140003b7e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b82:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003b85:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b89:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b8c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b8f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b93:	7e 3a                	jle    140003bcf <__pformat_xint+0x1a1>
   140003b95:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003b98:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b9c:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003ba0:	89 c1                	mov    ecx,eax
   140003ba2:	89 d0                	mov    eax,edx
   140003ba4:	29 c8                	sub    eax,ecx
   140003ba6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003ba9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003bad:	7e 20                	jle    140003bcf <__pformat_xint+0x1a1>
   140003baf:	eb 0f                	jmp    140003bc0 <__pformat_xint+0x192>
   140003bb1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bb5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bb9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bbd:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bc0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003bc3:	8d 50 ff             	lea    edx,[rax-0x1]
   140003bc6:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bc9:	85 c0                	test   eax,eax
   140003bcb:	7f e4                	jg     140003bb1 <__pformat_xint+0x183>
   140003bcd:	eb 25                	jmp    140003bf4 <__pformat_xint+0x1c6>
   140003bcf:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003bd3:	75 1f                	jne    140003bf4 <__pformat_xint+0x1c6>
   140003bd5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bd9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bdc:	25 00 08 00 00       	and    eax,0x800
   140003be1:	85 c0                	test   eax,eax
   140003be3:	74 0f                	je     140003bf4 <__pformat_xint+0x1c6>
   140003be5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003be9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bed:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bf1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bf4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bf8:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003bfc:	75 1a                	jne    140003c18 <__pformat_xint+0x1ea>
   140003bfe:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c02:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003c05:	85 c0                	test   eax,eax
   140003c07:	74 0f                	je     140003c18 <__pformat_xint+0x1ea>
   140003c09:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c0d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c11:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c15:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c18:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c1c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c1f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003c23:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003c27:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c2a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003c2d:	7d 15                	jge    140003c44 <__pformat_xint+0x216>
   140003c2f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c33:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c36:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003c39:	89 c2                	mov    edx,eax
   140003c3b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c3f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003c42:	eb 0b                	jmp    140003c4f <__pformat_xint+0x221>
   140003c44:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c48:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003c4f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c53:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c56:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003c59:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c5d:	7e 1a                	jle    140003c79 <__pformat_xint+0x24b>
   140003c5f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c63:	74 14                	je     140003c79 <__pformat_xint+0x24b>
   140003c65:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c69:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c6c:	25 00 08 00 00       	and    eax,0x800
   140003c71:	85 c0                	test   eax,eax
   140003c73:	74 04                	je     140003c79 <__pformat_xint+0x24b>
   140003c75:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003c79:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c7d:	7e 3c                	jle    140003cbb <__pformat_xint+0x28d>
   140003c7f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c83:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003c86:	85 c0                	test   eax,eax
   140003c88:	79 31                	jns    140003cbb <__pformat_xint+0x28d>
   140003c8a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c8e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c91:	25 00 06 00 00       	and    eax,0x600
   140003c96:	3d 00 02 00 00       	cmp    eax,0x200
   140003c9b:	75 1e                	jne    140003cbb <__pformat_xint+0x28d>
   140003c9d:	eb 0f                	jmp    140003cae <__pformat_xint+0x280>
   140003c9f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ca3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ca7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003cab:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003cae:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003cb1:	8d 50 ff             	lea    edx,[rax-0x1]
   140003cb4:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003cb7:	85 c0                	test   eax,eax
   140003cb9:	7f e4                	jg     140003c9f <__pformat_xint+0x271>
   140003cbb:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003cbf:	74 30                	je     140003cf1 <__pformat_xint+0x2c3>
   140003cc1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cc5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003cc8:	25 00 08 00 00       	and    eax,0x800
   140003ccd:	85 c0                	test   eax,eax
   140003ccf:	74 20                	je     140003cf1 <__pformat_xint+0x2c3>
   140003cd1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cd5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003cd9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003cdd:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003ce0:	88 10                	mov    BYTE PTR [rax],dl
   140003ce2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ce6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003cea:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003cee:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003cf1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003cf5:	7e 4c                	jle    140003d43 <__pformat_xint+0x315>
   140003cf7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cfb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003cfe:	25 00 04 00 00       	and    eax,0x400
   140003d03:	85 c0                	test   eax,eax
   140003d05:	75 3c                	jne    140003d43 <__pformat_xint+0x315>
   140003d07:	eb 11                	jmp    140003d1a <__pformat_xint+0x2ec>
   140003d09:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d0d:	48 89 c2             	mov    rdx,rax
   140003d10:	b9 20 00 00 00       	mov    ecx,0x20
   140003d15:	e8 26 f5 ff ff       	call   140003240 <__pformat_putc>
   140003d1a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d1d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d20:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d23:	85 c0                	test   eax,eax
   140003d25:	7f e2                	jg     140003d09 <__pformat_xint+0x2db>
   140003d27:	eb 1a                	jmp    140003d43 <__pformat_xint+0x315>
   140003d29:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003d2e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d32:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003d35:	0f be c0             	movsx  eax,al
   140003d38:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003d3c:	89 c1                	mov    ecx,eax
   140003d3e:	e8 fd f4 ff ff       	call   140003240 <__pformat_putc>
   140003d43:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d47:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003d4b:	72 dc                	jb     140003d29 <__pformat_xint+0x2fb>
   140003d4d:	eb 11                	jmp    140003d60 <__pformat_xint+0x332>
   140003d4f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d53:	48 89 c2             	mov    rdx,rax
   140003d56:	b9 20 00 00 00       	mov    ecx,0x20
   140003d5b:	e8 e0 f4 ff ff       	call   140003240 <__pformat_putc>
   140003d60:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d63:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d66:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d69:	85 c0                	test   eax,eax
   140003d6b:	7f e2                	jg     140003d4f <__pformat_xint+0x321>
   140003d6d:	90                   	nop
   140003d6e:	90                   	nop
   140003d6f:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003d73:	5b                   	pop    rbx
   140003d74:	5d                   	pop    rbp
   140003d75:	c3                   	ret

0000000140003d76 <init_fpreg_ldouble>:
   140003d76:	55                   	push   rbp
   140003d77:	53                   	push   rbx
   140003d78:	48 83 ec 28          	sub    rsp,0x28
   140003d7c:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003d81:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003d85:	48 89 d3             	mov    rbx,rdx
   140003d88:	db 2b                	fld    TBYTE PTR [rbx]
   140003d8a:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003d8d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003d90:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003d93:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003d97:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d9b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003d9f:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003da2:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003da6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003daa:	48 83 c4 28          	add    rsp,0x28
   140003dae:	5b                   	pop    rbx
   140003daf:	5d                   	pop    rbp
   140003db0:	c3                   	ret

0000000140003db1 <__pformat_cvt>:
   140003db1:	55                   	push   rbp
   140003db2:	53                   	push   rbx
   140003db3:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003dba:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003dc1:	00 
   140003dc2:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003dc5:	48 89 d3             	mov    rbx,rdx
   140003dc8:	db 2b                	fld    TBYTE PTR [rbx]
   140003dca:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003dcd:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003dd1:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003dd5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003ddc:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003de0:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003de3:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003de6:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003dea:	48 89 c1             	mov    rcx,rax
   140003ded:	e8 84 ff ff ff       	call   140003d76 <init_fpreg_ldouble>
   140003df2:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003df5:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003df8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003dfc:	48 89 c1             	mov    rcx,rax
   140003dff:	e8 9c 4e 00 00       	call   140008ca0 <__fpclassifyl>
   140003e04:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003e07:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e0a:	25 00 01 00 00       	and    eax,0x100
   140003e0f:	85 c0                	test   eax,eax
   140003e11:	74 1d                	je     140003e30 <__pformat_cvt+0x7f>
   140003e13:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e16:	25 00 04 00 00       	and    eax,0x400
   140003e1b:	85 c0                	test   eax,eax
   140003e1d:	74 07                	je     140003e26 <__pformat_cvt+0x75>
   140003e1f:	b8 03 00 00 00       	mov    eax,0x3
   140003e24:	eb 05                	jmp    140003e2b <__pformat_cvt+0x7a>
   140003e26:	b8 04 00 00 00       	mov    eax,0x4
   140003e2b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003e2e:	eb 4a                	jmp    140003e7a <__pformat_cvt+0xc9>
   140003e30:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e33:	25 00 04 00 00       	and    eax,0x400
   140003e38:	85 c0                	test   eax,eax
   140003e3a:	74 37                	je     140003e73 <__pformat_cvt+0xc2>
   140003e3c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e3f:	25 00 40 00 00       	and    eax,0x4000
   140003e44:	85 c0                	test   eax,eax
   140003e46:	74 10                	je     140003e58 <__pformat_cvt+0xa7>
   140003e48:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003e4f:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003e56:	eb 22                	jmp    140003e7a <__pformat_cvt+0xc9>
   140003e58:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003e5f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e63:	98                   	cwde
   140003e64:	25 ff 7f 00 00       	and    eax,0x7fff
   140003e69:	2d 3e 40 00 00       	sub    eax,0x403e
   140003e6e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003e71:	eb 07                	jmp    140003e7a <__pformat_cvt+0xc9>
   140003e73:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003e7a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e7d:	83 f8 04             	cmp    eax,0x4
   140003e80:	74 0e                	je     140003e90 <__pformat_cvt+0xdf>
   140003e82:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e86:	98                   	cwde
   140003e87:	25 00 80 00 00       	and    eax,0x8000
   140003e8c:	89 c2                	mov    edx,eax
   140003e8e:	eb 05                	jmp    140003e95 <__pformat_cvt+0xe4>
   140003e90:	ba 00 00 00 00       	mov    edx,0x0
   140003e95:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003e99:	89 10                	mov    DWORD PTR [rax],edx
   140003e9b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003e9e:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003ea2:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003ea6:	48 8d 0d c3 61 00 00 	lea    rcx,[rip+0x61c3]        # 14000a070 <fpi.0>
   140003ead:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003eb1:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003eb6:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003eba:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003ebf:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003ec2:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003ec6:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003ec9:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003ecd:	89 c2                	mov    edx,eax
   140003ecf:	e8 96 24 00 00       	call   14000636a <__gdtoa>
   140003ed4:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003edb:	5b                   	pop    rbx
   140003edc:	5d                   	pop    rbp
   140003edd:	c3                   	ret

0000000140003ede <__pformat_ecvt>:
   140003ede:	55                   	push   rbp
   140003edf:	53                   	push   rbx
   140003ee0:	48 83 ec 58          	sub    rsp,0x58
   140003ee4:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003ee9:	48 89 cb             	mov    rbx,rcx
   140003eec:	db 2b                	fld    TBYTE PTR [rbx]
   140003eee:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003ef1:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003ef4:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003ef8:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003efc:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003eff:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003f02:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003f06:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003f09:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003f0d:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f11:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f16:	4d 89 c1             	mov    r9,r8
   140003f19:	41 89 c8             	mov    r8d,ecx
   140003f1c:	48 89 c2             	mov    rdx,rax
   140003f1f:	b9 02 00 00 00       	mov    ecx,0x2
   140003f24:	e8 88 fe ff ff       	call   140003db1 <__pformat_cvt>
   140003f29:	48 83 c4 58          	add    rsp,0x58
   140003f2d:	5b                   	pop    rbx
   140003f2e:	5d                   	pop    rbp
   140003f2f:	c3                   	ret

0000000140003f30 <__pformat_fcvt>:
   140003f30:	55                   	push   rbp
   140003f31:	53                   	push   rbx
   140003f32:	48 83 ec 58          	sub    rsp,0x58
   140003f36:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003f3b:	48 89 cb             	mov    rbx,rcx
   140003f3e:	db 2b                	fld    TBYTE PTR [rbx]
   140003f40:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003f43:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003f46:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003f4a:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003f4e:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003f51:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003f54:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003f58:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003f5b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003f5f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f63:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f68:	4d 89 c1             	mov    r9,r8
   140003f6b:	41 89 c8             	mov    r8d,ecx
   140003f6e:	48 89 c2             	mov    rdx,rax
   140003f71:	b9 03 00 00 00       	mov    ecx,0x3
   140003f76:	e8 36 fe ff ff       	call   140003db1 <__pformat_cvt>
   140003f7b:	48 83 c4 58          	add    rsp,0x58
   140003f7f:	5b                   	pop    rbx
   140003f80:	5d                   	pop    rbp
   140003f81:	c3                   	ret

0000000140003f82 <__pformat_emit_radix_point>:
   140003f82:	55                   	push   rbp
   140003f83:	53                   	push   rbx
   140003f84:	48 83 ec 68          	sub    rsp,0x68
   140003f88:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003f8d:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003f91:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f95:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f98:	83 f8 fd             	cmp    eax,0xfffffffd
   140003f9b:	75 48                	jne    140003fe5 <__pformat_emit_radix_point+0x63>
   140003f9d:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003fa4:	00 
   140003fa5:	e8 4e 57 00 00       	call   1400096f8 <localeconv>
   140003faa:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003fad:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003fb1:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003fb5:	49 89 c9             	mov    r9,rcx
   140003fb8:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003fbe:	48 89 c1             	mov    rcx,rax
   140003fc1:	e8 6a 51 00 00       	call   140009130 <mbrtowc>
   140003fc6:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003fc9:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003fcd:	7e 0c                	jle    140003fdb <__pformat_emit_radix_point+0x59>
   140003fcf:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003fd3:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fd7:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003fdb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fdf:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003fe2:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003fe5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fe9:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003fed:	66 85 c0             	test   ax,ax
   140003ff0:	0f 84 b8 00 00 00    	je     1400040ae <__pformat_emit_radix_point+0x12c>
   140003ff6:	48 89 e0             	mov    rax,rsp
   140003ff9:	48 89 c3             	mov    rbx,rax
   140003ffc:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004000:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140004003:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004006:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004009:	48 63 d0             	movsxd rdx,eax
   14000400c:	48 83 ea 01          	sub    rdx,0x1
   140004010:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140004014:	48 98                	cdqe
   140004016:	48 83 c0 0f          	add    rax,0xf
   14000401a:	48 c1 e8 04          	shr    rax,0x4
   14000401e:	48 c1 e0 04          	shl    rax,0x4
   140004022:	e8 59 f1 ff ff       	call   140003180 <___chkstk_ms>
   140004027:	48 29 c4             	sub    rsp,rax
   14000402a:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000402f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140004033:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   14000403a:	00 
   14000403b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000403f:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140004043:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140004047:	0f b7 d0             	movzx  edx,ax
   14000404a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000404e:	49 89 c8             	mov    r8,rcx
   140004051:	48 89 c1             	mov    rcx,rax
   140004054:	e8 87 50 00 00       	call   1400090e0 <wcrtomb>
   140004059:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000405c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004060:	7e 36                	jle    140004098 <__pformat_emit_radix_point+0x116>
   140004062:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140004066:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000406a:	eb 1d                	jmp    140004089 <__pformat_emit_radix_point+0x107>
   14000406c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004070:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004074:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004078:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000407b:	0f be c0             	movsx  eax,al
   14000407e:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004082:	89 c1                	mov    ecx,eax
   140004084:	e8 b7 f1 ff ff       	call   140003240 <__pformat_putc>
   140004089:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000408c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000408f:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140004092:	85 c0                	test   eax,eax
   140004094:	7f d6                	jg     14000406c <__pformat_emit_radix_point+0xea>
   140004096:	eb 11                	jmp    1400040a9 <__pformat_emit_radix_point+0x127>
   140004098:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000409c:	48 89 c2             	mov    rdx,rax
   14000409f:	b9 2e 00 00 00       	mov    ecx,0x2e
   1400040a4:	e8 97 f1 ff ff       	call   140003240 <__pformat_putc>
   1400040a9:	48 89 dc             	mov    rsp,rbx
   1400040ac:	eb 11                	jmp    1400040bf <__pformat_emit_radix_point+0x13d>
   1400040ae:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040b2:	48 89 c2             	mov    rdx,rax
   1400040b5:	b9 2e 00 00 00       	mov    ecx,0x2e
   1400040ba:	e8 81 f1 ff ff       	call   140003240 <__pformat_putc>
   1400040bf:	90                   	nop
   1400040c0:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   1400040c4:	5b                   	pop    rbx
   1400040c5:	5d                   	pop    rbp
   1400040c6:	c3                   	ret

00000001400040c7 <__pformat_emit_numeric_value>:
   1400040c7:	55                   	push   rbp
   1400040c8:	48 89 e5             	mov    rbp,rsp
   1400040cb:	48 83 ec 30          	sub    rsp,0x30
   1400040cf:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400040d2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400040d6:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   1400040da:	75 0e                	jne    1400040ea <__pformat_emit_numeric_value+0x23>
   1400040dc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040e0:	48 89 c1             	mov    rcx,rax
   1400040e3:	e8 9a fe ff ff       	call   140003f82 <__pformat_emit_radix_point>
   1400040e8:	eb 43                	jmp    14000412d <__pformat_emit_numeric_value+0x66>
   1400040ea:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   1400040ee:	75 2f                	jne    14000411f <__pformat_emit_numeric_value+0x58>
   1400040f0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040f4:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400040f8:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   1400040fc:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   140004100:	66 85 c0             	test   ax,ax
   140004103:	74 28                	je     14000412d <__pformat_emit_numeric_value+0x66>
   140004105:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004109:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   14000410d:	49 89 d0             	mov    r8,rdx
   140004110:	ba 01 00 00 00       	mov    edx,0x1
   140004115:	48 89 c1             	mov    rcx,rax
   140004118:	e8 2c f3 ff ff       	call   140003449 <__pformat_wputchars>
   14000411d:	eb 0e                	jmp    14000412d <__pformat_emit_numeric_value+0x66>
   14000411f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004123:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140004126:	89 c1                	mov    ecx,eax
   140004128:	e8 13 f1 ff ff       	call   140003240 <__pformat_putc>
   14000412d:	90                   	nop
   14000412e:	48 83 c4 30          	add    rsp,0x30
   140004132:	5d                   	pop    rbp
   140004133:	c3                   	ret

0000000140004134 <__pformat_emit_inf_or_nan>:
   140004134:	55                   	push   rbp
   140004135:	48 89 e5             	mov    rbp,rsp
   140004138:	48 83 ec 40          	sub    rsp,0x40
   14000413c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000413f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004143:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140004147:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000414b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000414f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004153:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000415a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000415e:	74 11                	je     140004171 <__pformat_emit_inf_or_nan+0x3d>
   140004160:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004164:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004168:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000416c:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   14000416f:	eb 3e                	jmp    1400041af <__pformat_emit_inf_or_nan+0x7b>
   140004171:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004175:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004178:	25 00 01 00 00       	and    eax,0x100
   14000417d:	85 c0                	test   eax,eax
   14000417f:	74 11                	je     140004192 <__pformat_emit_inf_or_nan+0x5e>
   140004181:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004185:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004189:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000418d:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140004190:	eb 1d                	jmp    1400041af <__pformat_emit_inf_or_nan+0x7b>
   140004192:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004196:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004199:	83 e0 40             	and    eax,0x40
   14000419c:	85 c0                	test   eax,eax
   14000419e:	74 0f                	je     1400041af <__pformat_emit_inf_or_nan+0x7b>
   1400041a0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400041a4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041a8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400041ac:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400041af:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   1400041b6:	eb 38                	jmp    1400041f0 <__pformat_emit_inf_or_nan+0xbc>
   1400041b8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400041bc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041c0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400041c4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400041c7:	83 e0 df             	and    eax,0xffffffdf
   1400041ca:	41 89 c0             	mov    r8d,eax
   1400041cd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400041d1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400041d4:	83 e0 20             	and    eax,0x20
   1400041d7:	89 c1                	mov    ecx,eax
   1400041d9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400041dd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041e1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400041e5:	44 89 c2             	mov    edx,r8d
   1400041e8:	09 ca                	or     edx,ecx
   1400041ea:	88 10                	mov    BYTE PTR [rax],dl
   1400041ec:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400041f0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400041f4:	7f c2                	jg     1400041b8 <__pformat_emit_inf_or_nan+0x84>
   1400041f6:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400041fa:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400041fe:	48 29 c2             	sub    rdx,rax
   140004201:	89 d1                	mov    ecx,edx
   140004203:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004207:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000420b:	49 89 d0             	mov    r8,rdx
   14000420e:	89 ca                	mov    edx,ecx
   140004210:	48 89 c1             	mov    rcx,rax
   140004213:	e8 ac f0 ff ff       	call   1400032c4 <__pformat_putchars>
   140004218:	90                   	nop
   140004219:	48 83 c4 40          	add    rsp,0x40
   14000421d:	5d                   	pop    rbp
   14000421e:	c3                   	ret

000000014000421f <__pformat_emit_float>:
   14000421f:	55                   	push   rbp
   140004220:	48 89 e5             	mov    rbp,rsp
   140004223:	48 83 ec 30          	sub    rsp,0x30
   140004227:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000422a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000422e:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140004232:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004236:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000423a:	7e 2e                	jle    14000426a <__pformat_emit_float+0x4b>
   14000423c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004240:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004243:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   140004246:	7f 15                	jg     14000425d <__pformat_emit_float+0x3e>
   140004248:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000424c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000424f:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004252:	89 c2                	mov    edx,eax
   140004254:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004258:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000425b:	eb 29                	jmp    140004286 <__pformat_emit_float+0x67>
   14000425d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004261:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004268:	eb 1c                	jmp    140004286 <__pformat_emit_float+0x67>
   14000426a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000426e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004271:	85 c0                	test   eax,eax
   140004273:	7e 11                	jle    140004286 <__pformat_emit_float+0x67>
   140004275:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004279:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000427c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000427f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004283:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004286:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000428a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000428d:	85 c0                	test   eax,eax
   14000428f:	78 2b                	js     1400042bc <__pformat_emit_float+0x9d>
   140004291:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004295:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004298:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000429c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000429f:	39 c2                	cmp    edx,eax
   1400042a1:	7e 19                	jle    1400042bc <__pformat_emit_float+0x9d>
   1400042a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400042aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042ae:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400042b1:	29 c2                	sub    edx,eax
   1400042b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042b7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042ba:	eb 0b                	jmp    1400042c7 <__pformat_emit_float+0xa8>
   1400042bc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042c0:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400042c7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042cb:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042ce:	85 c0                	test   eax,eax
   1400042d0:	7e 2c                	jle    1400042fe <__pformat_emit_float+0xdf>
   1400042d2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042d6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400042d9:	85 c0                	test   eax,eax
   1400042db:	7f 10                	jg     1400042ed <__pformat_emit_float+0xce>
   1400042dd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042e1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042e4:	25 00 08 00 00       	and    eax,0x800
   1400042e9:	85 c0                	test   eax,eax
   1400042eb:	74 11                	je     1400042fe <__pformat_emit_float+0xdf>
   1400042ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042f1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042f4:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042f7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042fb:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042fe:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004302:	7e 64                	jle    140004368 <__pformat_emit_float+0x149>
   140004304:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004308:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000430b:	25 00 10 00 00       	and    eax,0x1000
   140004310:	85 c0                	test   eax,eax
   140004312:	74 54                	je     140004368 <__pformat_emit_float+0x149>
   140004314:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004318:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   14000431c:	66 85 c0             	test   ax,ax
   14000431f:	74 47                	je     140004368 <__pformat_emit_float+0x149>
   140004321:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004324:	83 c0 02             	add    eax,0x2
   140004327:	48 63 d0             	movsxd rdx,eax
   14000432a:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   140004331:	48 c1 ea 20          	shr    rdx,0x20
   140004335:	c1 f8 1f             	sar    eax,0x1f
   140004338:	29 c2                	sub    edx,eax
   14000433a:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000433d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004340:	eb 15                	jmp    140004357 <__pformat_emit_float+0x138>
   140004342:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004346:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000434a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000434d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004350:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004354:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004357:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000435b:	7e 0b                	jle    140004368 <__pformat_emit_float+0x149>
   14000435d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004361:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004364:	85 c0                	test   eax,eax
   140004366:	7f da                	jg     140004342 <__pformat_emit_float+0x123>
   140004368:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000436c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000436f:	85 c0                	test   eax,eax
   140004371:	7e 27                	jle    14000439a <__pformat_emit_float+0x17b>
   140004373:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004377:	75 10                	jne    140004389 <__pformat_emit_float+0x16a>
   140004379:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000437d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004380:	25 c0 01 00 00       	and    eax,0x1c0
   140004385:	85 c0                	test   eax,eax
   140004387:	74 11                	je     14000439a <__pformat_emit_float+0x17b>
   140004389:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000438d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004390:	8d 50 ff             	lea    edx,[rax-0x1]
   140004393:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004397:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000439a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000439e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043a1:	85 c0                	test   eax,eax
   1400043a3:	7e 38                	jle    1400043dd <__pformat_emit_float+0x1be>
   1400043a5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043a9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043ac:	25 00 06 00 00       	and    eax,0x600
   1400043b1:	85 c0                	test   eax,eax
   1400043b3:	75 28                	jne    1400043dd <__pformat_emit_float+0x1be>
   1400043b5:	eb 11                	jmp    1400043c8 <__pformat_emit_float+0x1a9>
   1400043b7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043bb:	48 89 c2             	mov    rdx,rax
   1400043be:	b9 20 00 00 00       	mov    ecx,0x20
   1400043c3:	e8 78 ee ff ff       	call   140003240 <__pformat_putc>
   1400043c8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043cc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043cf:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400043d2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400043d6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400043d9:	85 c0                	test   eax,eax
   1400043db:	7f da                	jg     1400043b7 <__pformat_emit_float+0x198>
   1400043dd:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400043e1:	74 13                	je     1400043f6 <__pformat_emit_float+0x1d7>
   1400043e3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043e7:	48 89 c2             	mov    rdx,rax
   1400043ea:	b9 2d 00 00 00       	mov    ecx,0x2d
   1400043ef:	e8 4c ee ff ff       	call   140003240 <__pformat_putc>
   1400043f4:	eb 42                	jmp    140004438 <__pformat_emit_float+0x219>
   1400043f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043fa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043fd:	25 00 01 00 00       	and    eax,0x100
   140004402:	85 c0                	test   eax,eax
   140004404:	74 13                	je     140004419 <__pformat_emit_float+0x1fa>
   140004406:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000440a:	48 89 c2             	mov    rdx,rax
   14000440d:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004412:	e8 29 ee ff ff       	call   140003240 <__pformat_putc>
   140004417:	eb 1f                	jmp    140004438 <__pformat_emit_float+0x219>
   140004419:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000441d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004420:	83 e0 40             	and    eax,0x40
   140004423:	85 c0                	test   eax,eax
   140004425:	74 11                	je     140004438 <__pformat_emit_float+0x219>
   140004427:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000442b:	48 89 c2             	mov    rdx,rax
   14000442e:	b9 20 00 00 00       	mov    ecx,0x20
   140004433:	e8 08 ee ff ff       	call   140003240 <__pformat_putc>
   140004438:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000443c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000443f:	85 c0                	test   eax,eax
   140004441:	7e 3b                	jle    14000447e <__pformat_emit_float+0x25f>
   140004443:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004447:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000444a:	25 00 06 00 00       	and    eax,0x600
   14000444f:	3d 00 02 00 00       	cmp    eax,0x200
   140004454:	75 28                	jne    14000447e <__pformat_emit_float+0x25f>
   140004456:	eb 11                	jmp    140004469 <__pformat_emit_float+0x24a>
   140004458:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000445c:	48 89 c2             	mov    rdx,rax
   14000445f:	b9 30 00 00 00       	mov    ecx,0x30
   140004464:	e8 d7 ed ff ff       	call   140003240 <__pformat_putc>
   140004469:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000446d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004470:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004473:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004477:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000447a:	85 c0                	test   eax,eax
   14000447c:	7f da                	jg     140004458 <__pformat_emit_float+0x239>
   14000447e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004482:	0f 8e a7 00 00 00    	jle    14000452f <__pformat_emit_float+0x310>
   140004488:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000448c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000448f:	84 c0                	test   al,al
   140004491:	74 14                	je     1400044a7 <__pformat_emit_float+0x288>
   140004493:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004497:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000449b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000449f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044a2:	0f be c0             	movsx  eax,al
   1400044a5:	eb 05                	jmp    1400044ac <__pformat_emit_float+0x28d>
   1400044a7:	b8 30 00 00 00       	mov    eax,0x30
   1400044ac:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044b0:	89 c1                	mov    ecx,eax
   1400044b2:	e8 89 ed ff ff       	call   140003240 <__pformat_putc>
   1400044b7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400044bb:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044bf:	74 62                	je     140004523 <__pformat_emit_float+0x304>
   1400044c1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044c5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400044c8:	25 00 10 00 00       	and    eax,0x1000
   1400044cd:	85 c0                	test   eax,eax
   1400044cf:	74 52                	je     140004523 <__pformat_emit_float+0x304>
   1400044d1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044d5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400044d9:	66 85 c0             	test   ax,ax
   1400044dc:	74 45                	je     140004523 <__pformat_emit_float+0x304>
   1400044de:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   1400044e1:	48 63 c1             	movsxd rax,ecx
   1400044e4:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   1400044eb:	48 c1 e8 20          	shr    rax,0x20
   1400044ef:	48 89 c2             	mov    rdx,rax
   1400044f2:	89 c8                	mov    eax,ecx
   1400044f4:	c1 f8 1f             	sar    eax,0x1f
   1400044f7:	29 c2                	sub    edx,eax
   1400044f9:	89 d0                	mov    eax,edx
   1400044fb:	01 c0                	add    eax,eax
   1400044fd:	01 d0                	add    eax,edx
   1400044ff:	29 c1                	sub    ecx,eax
   140004501:	89 ca                	mov    edx,ecx
   140004503:	85 d2                	test   edx,edx
   140004505:	75 1c                	jne    140004523 <__pformat_emit_float+0x304>
   140004507:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000450b:	48 83 c0 20          	add    rax,0x20
   14000450f:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004513:	49 89 d0             	mov    r8,rdx
   140004516:	ba 01 00 00 00       	mov    edx,0x1
   14000451b:	48 89 c1             	mov    rcx,rax
   14000451e:	e8 26 ef ff ff       	call   140003449 <__pformat_wputchars>
   140004523:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004527:	0f 8f 5b ff ff ff    	jg     140004488 <__pformat_emit_float+0x269>
   14000452d:	eb 11                	jmp    140004540 <__pformat_emit_float+0x321>
   14000452f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004533:	48 89 c2             	mov    rdx,rax
   140004536:	b9 30 00 00 00       	mov    ecx,0x30
   14000453b:	e8 00 ed ff ff       	call   140003240 <__pformat_putc>
   140004540:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004544:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004547:	85 c0                	test   eax,eax
   140004549:	7f 10                	jg     14000455b <__pformat_emit_float+0x33c>
   14000454b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000454f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004552:	25 00 08 00 00       	and    eax,0x800
   140004557:	85 c0                	test   eax,eax
   140004559:	74 0c                	je     140004567 <__pformat_emit_float+0x348>
   14000455b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000455f:	48 89 c1             	mov    rcx,rax
   140004562:	e8 1b fa ff ff       	call   140003f82 <__pformat_emit_radix_point>
   140004567:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000456b:	79 5f                	jns    1400045cc <__pformat_emit_float+0x3ad>
   14000456d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004571:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004574:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004577:	01 c2                	add    edx,eax
   140004579:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000457d:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004580:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004584:	48 89 c2             	mov    rdx,rax
   140004587:	b9 30 00 00 00       	mov    ecx,0x30
   14000458c:	e8 af ec ff ff       	call   140003240 <__pformat_putc>
   140004591:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   140004595:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004599:	78 e5                	js     140004580 <__pformat_emit_float+0x361>
   14000459b:	eb 2f                	jmp    1400045cc <__pformat_emit_float+0x3ad>
   14000459d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400045a1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400045a4:	84 c0                	test   al,al
   1400045a6:	74 14                	je     1400045bc <__pformat_emit_float+0x39d>
   1400045a8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400045ac:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400045b0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400045b4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400045b7:	0f be c0             	movsx  eax,al
   1400045ba:	eb 05                	jmp    1400045c1 <__pformat_emit_float+0x3a2>
   1400045bc:	b8 30 00 00 00       	mov    eax,0x30
   1400045c1:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400045c5:	89 c1                	mov    ecx,eax
   1400045c7:	e8 74 ec ff ff       	call   140003240 <__pformat_putc>
   1400045cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045d0:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400045d3:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400045d6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400045da:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   1400045dd:	85 c0                	test   eax,eax
   1400045df:	7f bc                	jg     14000459d <__pformat_emit_float+0x37e>
   1400045e1:	90                   	nop
   1400045e2:	90                   	nop
   1400045e3:	48 83 c4 30          	add    rsp,0x30
   1400045e7:	5d                   	pop    rbp
   1400045e8:	c3                   	ret

00000001400045e9 <__pformat_emit_efloat>:
   1400045e9:	55                   	push   rbp
   1400045ea:	48 89 e5             	mov    rbp,rsp
   1400045ed:	48 83 ec 50          	sub    rsp,0x50
   1400045f1:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400045f4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400045f8:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400045fc:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004600:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140004607:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000460b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000460f:	79 09                	jns    14000461a <__pformat_emit_efloat+0x31>
   140004611:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004618:	eb 05                	jmp    14000461f <__pformat_emit_efloat+0x36>
   14000461a:	b8 00 00 00 00       	mov    eax,0x0
   14000461f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140004623:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004626:	48 98                	cdqe
   140004628:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000462c:	eb 04                	jmp    140004632 <__pformat_emit_efloat+0x49>
   14000462e:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140004632:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004635:	48 63 d0             	movsxd rdx,eax
   140004638:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   14000463f:	48 c1 ea 20          	shr    rdx,0x20
   140004643:	89 d1                	mov    ecx,edx
   140004645:	c1 f9 02             	sar    ecx,0x2
   140004648:	99                   	cdq
   140004649:	89 c8                	mov    eax,ecx
   14000464b:	29 d0                	sub    eax,edx
   14000464d:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004650:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004654:	75 d8                	jne    14000462e <__pformat_emit_efloat+0x45>
   140004656:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000465a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000465d:	83 f8 ff             	cmp    eax,0xffffffff
   140004660:	75 0b                	jne    14000466d <__pformat_emit_efloat+0x84>
   140004662:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004666:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   14000466d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004671:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004674:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004677:	7d 0a                	jge    140004683 <__pformat_emit_efloat+0x9a>
   140004679:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000467d:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004680:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004683:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004687:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000468a:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   14000468e:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004691:	7d 15                	jge    1400046a8 <__pformat_emit_efloat+0xbf>
   140004693:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004697:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000469a:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   14000469d:	89 c2                	mov    edx,eax
   14000469f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046a3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400046a6:	eb 0b                	jmp    1400046b3 <__pformat_emit_efloat+0xca>
   1400046a8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046ac:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400046b3:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400046b7:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400046bb:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400046be:	49 89 c9             	mov    r9,rcx
   1400046c1:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400046c7:	89 c1                	mov    ecx,eax
   1400046c9:	e8 51 fb ff ff       	call   14000421f <__pformat_emit_float>
   1400046ce:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046d2:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   1400046d5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046d9:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400046dc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046e0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400046e3:	0d c0 01 00 00       	or     eax,0x1c0
   1400046e8:	89 c2                	mov    edx,eax
   1400046ea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046ee:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400046f1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046f5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400046f8:	83 e0 20             	and    eax,0x20
   1400046fb:	83 c8 45             	or     eax,0x45
   1400046fe:	89 c1                	mov    ecx,eax
   140004700:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004704:	48 89 c2             	mov    rdx,rax
   140004707:	e8 34 eb ff ff       	call   140003240 <__pformat_putc>
   14000470c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004710:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004713:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140004716:	83 ea 01             	sub    edx,0x1
   140004719:	01 c2                	add    edx,eax
   14000471b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000471f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004722:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004726:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   14000472a:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000472e:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140004732:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004736:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000473a:	48 89 c1             	mov    rcx,rax
   14000473d:	e8 69 ef ff ff       	call   1400036ab <__pformat_int>
   140004742:	90                   	nop
   140004743:	48 83 c4 50          	add    rsp,0x50
   140004747:	5d                   	pop    rbp
   140004748:	c3                   	ret

0000000140004749 <__pformat_float>:
   140004749:	55                   	push   rbp
   14000474a:	53                   	push   rbx
   14000474b:	48 83 ec 58          	sub    rsp,0x58
   14000474f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004754:	48 89 cb             	mov    rbx,rcx
   140004757:	db 2b                	fld    TBYTE PTR [rbx]
   140004759:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000475c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004760:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004764:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004767:	85 c0                	test   eax,eax
   140004769:	79 0b                	jns    140004776 <__pformat_float+0x2d>
   14000476b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000476f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004776:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000477a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000477d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004780:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004783:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   140004787:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000478b:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000478f:	4d 89 c1             	mov    r9,r8
   140004792:	49 89 c8             	mov    r8,rcx
   140004795:	48 89 c1             	mov    rcx,rax
   140004798:	e8 93 f7 ff ff       	call   140003f30 <__pformat_fcvt>
   14000479d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400047a1:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400047a4:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400047a9:	75 17                	jne    1400047c2 <__pformat_float+0x79>
   1400047ab:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047ae:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400047b2:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047b6:	49 89 c8             	mov    r8,rcx
   1400047b9:	89 c1                	mov    ecx,eax
   1400047bb:	e8 74 f9 ff ff       	call   140004134 <__pformat_emit_inf_or_nan>
   1400047c0:	eb 43                	jmp    140004805 <__pformat_float+0xbc>
   1400047c2:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400047c5:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047c8:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400047cc:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047d0:	4d 89 c1             	mov    r9,r8
   1400047d3:	41 89 c8             	mov    r8d,ecx
   1400047d6:	89 c1                	mov    ecx,eax
   1400047d8:	e8 42 fa ff ff       	call   14000421f <__pformat_emit_float>
   1400047dd:	eb 11                	jmp    1400047f0 <__pformat_float+0xa7>
   1400047df:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047e3:	48 89 c2             	mov    rdx,rax
   1400047e6:	b9 20 00 00 00       	mov    ecx,0x20
   1400047eb:	e8 50 ea ff ff       	call   140003240 <__pformat_putc>
   1400047f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047f4:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400047f7:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400047fa:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400047fe:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004801:	85 c0                	test   eax,eax
   140004803:	7f da                	jg     1400047df <__pformat_float+0x96>
   140004805:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004809:	48 89 c1             	mov    rcx,rax
   14000480c:	e8 4e 17 00 00       	call   140005f5f <__freedtoa>
   140004811:	90                   	nop
   140004812:	48 83 c4 58          	add    rsp,0x58
   140004816:	5b                   	pop    rbx
   140004817:	5d                   	pop    rbp
   140004818:	c3                   	ret

0000000140004819 <__pformat_efloat>:
   140004819:	55                   	push   rbp
   14000481a:	53                   	push   rbx
   14000481b:	48 83 ec 58          	sub    rsp,0x58
   14000481f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004824:	48 89 cb             	mov    rbx,rcx
   140004827:	db 2b                	fld    TBYTE PTR [rbx]
   140004829:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000482c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004830:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004834:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004837:	85 c0                	test   eax,eax
   140004839:	79 0b                	jns    140004846 <__pformat_efloat+0x2d>
   14000483b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000483f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004846:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000484a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000484d:	8d 50 01             	lea    edx,[rax+0x1]
   140004850:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004853:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004856:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000485a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000485e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004862:	4d 89 c1             	mov    r9,r8
   140004865:	49 89 c8             	mov    r8,rcx
   140004868:	48 89 c1             	mov    rcx,rax
   14000486b:	e8 6e f6 ff ff       	call   140003ede <__pformat_ecvt>
   140004870:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004874:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004877:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000487c:	75 17                	jne    140004895 <__pformat_efloat+0x7c>
   14000487e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004881:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004885:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004889:	49 89 c8             	mov    r8,rcx
   14000488c:	89 c1                	mov    ecx,eax
   14000488e:	e8 a1 f8 ff ff       	call   140004134 <__pformat_emit_inf_or_nan>
   140004893:	eb 1b                	jmp    1400048b0 <__pformat_efloat+0x97>
   140004895:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004898:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000489b:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000489f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048a3:	4d 89 c1             	mov    r9,r8
   1400048a6:	41 89 c8             	mov    r8d,ecx
   1400048a9:	89 c1                	mov    ecx,eax
   1400048ab:	e8 39 fd ff ff       	call   1400045e9 <__pformat_emit_efloat>
   1400048b0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400048b4:	48 89 c1             	mov    rcx,rax
   1400048b7:	e8 a3 16 00 00       	call   140005f5f <__freedtoa>
   1400048bc:	90                   	nop
   1400048bd:	48 83 c4 58          	add    rsp,0x58
   1400048c1:	5b                   	pop    rbx
   1400048c2:	5d                   	pop    rbp
   1400048c3:	c3                   	ret

00000001400048c4 <__pformat_gfloat>:
   1400048c4:	55                   	push   rbp
   1400048c5:	53                   	push   rbx
   1400048c6:	48 83 ec 58          	sub    rsp,0x58
   1400048ca:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400048cf:	48 89 cb             	mov    rbx,rcx
   1400048d2:	db 2b                	fld    TBYTE PTR [rbx]
   1400048d4:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400048d7:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400048db:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048df:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048e2:	85 c0                	test   eax,eax
   1400048e4:	79 0d                	jns    1400048f3 <__pformat_gfloat+0x2f>
   1400048e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048ea:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400048f1:	eb 16                	jmp    140004909 <__pformat_gfloat+0x45>
   1400048f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048f7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048fa:	85 c0                	test   eax,eax
   1400048fc:	75 0b                	jne    140004909 <__pformat_gfloat+0x45>
   1400048fe:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004902:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   140004909:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000490d:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004910:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004913:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004916:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000491a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000491e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004922:	4d 89 c1             	mov    r9,r8
   140004925:	49 89 c8             	mov    r8,rcx
   140004928:	48 89 c1             	mov    rcx,rax
   14000492b:	e8 ae f5 ff ff       	call   140003ede <__pformat_ecvt>
   140004930:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004934:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004937:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000493c:	75 1a                	jne    140004958 <__pformat_gfloat+0x94>
   14000493e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004941:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004945:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004949:	49 89 c8             	mov    r8,rcx
   14000494c:	89 c1                	mov    ecx,eax
   14000494e:	e8 e1 f7 ff ff       	call   140004134 <__pformat_emit_inf_or_nan>
   140004953:	e9 14 01 00 00       	jmp    140004a6c <__pformat_gfloat+0x1a8>
   140004958:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000495b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000495e:	0f 8c b2 00 00 00    	jl     140004a16 <__pformat_gfloat+0x152>
   140004964:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004968:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000496b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000496e:	39 c2                	cmp    edx,eax
   140004970:	0f 8c a0 00 00 00    	jl     140004a16 <__pformat_gfloat+0x152>
   140004976:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000497a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000497d:	25 00 08 00 00       	and    eax,0x800
   140004982:	85 c0                	test   eax,eax
   140004984:	74 15                	je     14000499b <__pformat_gfloat+0xd7>
   140004986:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000498a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000498d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004990:	29 c2                	sub    edx,eax
   140004992:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004996:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004999:	eb 20                	jmp    1400049bb <__pformat_gfloat+0xf7>
   14000499b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000499f:	48 89 c1             	mov    rcx,rax
   1400049a2:	e8 81 4d 00 00       	call   140009728 <strlen>
   1400049a7:	89 c1                	mov    ecx,eax
   1400049a9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400049ac:	89 c2                	mov    edx,eax
   1400049ae:	89 c8                	mov    eax,ecx
   1400049b0:	29 d0                	sub    eax,edx
   1400049b2:	89 c2                	mov    edx,eax
   1400049b4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049b8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049bb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049bf:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049c2:	85 c0                	test   eax,eax
   1400049c4:	79 0b                	jns    1400049d1 <__pformat_gfloat+0x10d>
   1400049c6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049ca:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   1400049d1:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400049d4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400049d7:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400049db:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400049df:	4d 89 c1             	mov    r9,r8
   1400049e2:	41 89 c8             	mov    r8d,ecx
   1400049e5:	89 c1                	mov    ecx,eax
   1400049e7:	e8 33 f8 ff ff       	call   14000421f <__pformat_emit_float>
   1400049ec:	eb 11                	jmp    1400049ff <__pformat_gfloat+0x13b>
   1400049ee:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049f2:	48 89 c2             	mov    rdx,rax
   1400049f5:	b9 20 00 00 00       	mov    ecx,0x20
   1400049fa:	e8 41 e8 ff ff       	call   140003240 <__pformat_putc>
   1400049ff:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a03:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004a06:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004a09:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004a0d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004a10:	85 c0                	test   eax,eax
   140004a12:	7f da                	jg     1400049ee <__pformat_gfloat+0x12a>
   140004a14:	eb 56                	jmp    140004a6c <__pformat_gfloat+0x1a8>
   140004a16:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a1a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004a1d:	25 00 08 00 00       	and    eax,0x800
   140004a22:	85 c0                	test   eax,eax
   140004a24:	74 13                	je     140004a39 <__pformat_gfloat+0x175>
   140004a26:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a2a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a2d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004a30:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a34:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a37:	eb 18                	jmp    140004a51 <__pformat_gfloat+0x18d>
   140004a39:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a3d:	48 89 c1             	mov    rcx,rax
   140004a40:	e8 e3 4c 00 00       	call   140009728 <strlen>
   140004a45:	83 e8 01             	sub    eax,0x1
   140004a48:	89 c2                	mov    edx,eax
   140004a4a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a4e:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a51:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004a54:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004a57:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   140004a5b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004a5f:	4d 89 c1             	mov    r9,r8
   140004a62:	41 89 c8             	mov    r8d,ecx
   140004a65:	89 c1                	mov    ecx,eax
   140004a67:	e8 7d fb ff ff       	call   1400045e9 <__pformat_emit_efloat>
   140004a6c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a70:	48 89 c1             	mov    rcx,rax
   140004a73:	e8 e7 14 00 00       	call   140005f5f <__freedtoa>
   140004a78:	90                   	nop
   140004a79:	48 83 c4 58          	add    rsp,0x58
   140004a7d:	5b                   	pop    rbx
   140004a7e:	5d                   	pop    rbp
   140004a7f:	c3                   	ret

0000000140004a80 <__pformat_emit_xfloat>:
   140004a80:	55                   	push   rbp
   140004a81:	53                   	push   rbx
   140004a82:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140004a89:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140004a90:	00 
   140004a91:	48 89 cb             	mov    rbx,rcx
   140004a94:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004a98:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004a9c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004aa0:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   140004aa6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004aa9:	48 85 c0             	test   rax,rax
   140004aac:	75 09                	jne    140004ab7 <__pformat_emit_xfloat+0x37>
   140004aae:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004ab2:	66 85 c0             	test   ax,ax
   140004ab5:	74 0b                	je     140004ac2 <__pformat_emit_xfloat+0x42>
   140004ab7:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004abb:	83 e8 03             	sub    eax,0x3
   140004abe:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004ac2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ac6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ac9:	85 c0                	test   eax,eax
   140004acb:	0f 88 90 00 00 00    	js     140004b61 <__pformat_emit_xfloat+0xe1>
   140004ad1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ad5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ad8:	83 f8 0e             	cmp    eax,0xe
   140004adb:	0f 8f 80 00 00 00    	jg     140004b61 <__pformat_emit_xfloat+0xe1>
   140004ae1:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ae4:	48 d1 e8             	shr    rax,1
   140004ae7:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004aea:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004aed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004af1:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004af4:	b9 0e 00 00 00       	mov    ecx,0xe
   140004af9:	29 c1                	sub    ecx,eax
   140004afb:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004b02:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004b08:	89 c1                	mov    ecx,eax
   140004b0a:	49 d3 e0             	shl    r8,cl
   140004b0d:	4c 89 c0             	mov    rax,r8
   140004b10:	48 01 d0             	add    rax,rdx
   140004b13:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b16:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b19:	48 85 c0             	test   rax,rax
   140004b1c:	78 0b                	js     140004b29 <__pformat_emit_xfloat+0xa9>
   140004b1e:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b21:	48 01 c0             	add    rax,rax
   140004b24:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b27:	eb 15                	jmp    140004b3e <__pformat_emit_xfloat+0xbe>
   140004b29:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004b2d:	83 c0 04             	add    eax,0x4
   140004b30:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004b34:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b37:	48 c1 e8 03          	shr    rax,0x3
   140004b3b:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b3e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004b41:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b45:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b48:	b9 0f 00 00 00       	mov    ecx,0xf
   140004b4d:	29 c1                	sub    ecx,eax
   140004b4f:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004b56:	89 c1                	mov    ecx,eax
   140004b58:	48 d3 ea             	shr    rdx,cl
   140004b5b:	48 89 d0             	mov    rax,rdx
   140004b5e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b61:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b64:	48 85 c0             	test   rax,rax
   140004b67:	75 0f                	jne    140004b78 <__pformat_emit_xfloat+0xf8>
   140004b69:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b6d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b70:	85 c0                	test   eax,eax
   140004b72:	0f 8e f8 00 00 00    	jle    140004c70 <__pformat_emit_xfloat+0x1f0>
   140004b78:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b7c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b7f:	83 f8 0e             	cmp    eax,0xe
   140004b82:	7f 1a                	jg     140004b9e <__pformat_emit_xfloat+0x11e>
   140004b84:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b88:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b8b:	85 c0                	test   eax,eax
   140004b8d:	78 0f                	js     140004b9e <__pformat_emit_xfloat+0x11e>
   140004b8f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b93:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b96:	83 c0 01             	add    eax,0x1
   140004b99:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004b9c:	eb 07                	jmp    140004ba5 <__pformat_emit_xfloat+0x125>
   140004b9e:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004ba5:	e9 bc 00 00 00       	jmp    140004c66 <__pformat_emit_xfloat+0x1e6>
   140004baa:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004bad:	83 e0 0f             	and    eax,0xf
   140004bb0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004bb3:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004bb7:	75 36                	jne    140004bef <__pformat_emit_xfloat+0x16f>
   140004bb9:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004bbd:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004bc1:	72 1b                	jb     140004bde <__pformat_emit_xfloat+0x15e>
   140004bc3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bc7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004bca:	25 00 08 00 00       	and    eax,0x800
   140004bcf:	85 c0                	test   eax,eax
   140004bd1:	75 0b                	jne    140004bde <__pformat_emit_xfloat+0x15e>
   140004bd3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bd7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bda:	85 c0                	test   eax,eax
   140004bdc:	7e 2d                	jle    140004c0b <__pformat_emit_xfloat+0x18b>
   140004bde:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004be2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004be6:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004bea:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004bed:	eb 1c                	jmp    140004c0b <__pformat_emit_xfloat+0x18b>
   140004bef:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bf3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bf6:	85 c0                	test   eax,eax
   140004bf8:	7e 11                	jle    140004c0b <__pformat_emit_xfloat+0x18b>
   140004bfa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bfe:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c01:	8d 50 ff             	lea    edx,[rax-0x1]
   140004c04:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c08:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004c0b:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004c0f:	75 15                	jne    140004c26 <__pformat_emit_xfloat+0x1a6>
   140004c11:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c15:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004c19:	72 0b                	jb     140004c26 <__pformat_emit_xfloat+0x1a6>
   140004c1b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c1f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c22:	85 c0                	test   eax,eax
   140004c24:	78 32                	js     140004c58 <__pformat_emit_xfloat+0x1d8>
   140004c26:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004c2a:	76 16                	jbe    140004c42 <__pformat_emit_xfloat+0x1c2>
   140004c2c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004c2f:	8d 50 37             	lea    edx,[rax+0x37]
   140004c32:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c36:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c39:	83 e0 20             	and    eax,0x20
   140004c3c:	09 d0                	or     eax,edx
   140004c3e:	89 c1                	mov    ecx,eax
   140004c40:	eb 08                	jmp    140004c4a <__pformat_emit_xfloat+0x1ca>
   140004c42:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004c45:	83 c0 30             	add    eax,0x30
   140004c48:	89 c1                	mov    ecx,eax
   140004c4a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c4e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c52:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c56:	88 08                	mov    BYTE PTR [rax],cl
   140004c58:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004c5b:	48 c1 e8 04          	shr    rax,0x4
   140004c5f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004c62:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004c66:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004c6a:	0f 8f 3a ff ff ff    	jg     140004baa <__pformat_emit_xfloat+0x12a>
   140004c70:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c74:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004c78:	75 39                	jne    140004cb3 <__pformat_emit_xfloat+0x233>
   140004c7a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c7e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c81:	85 c0                	test   eax,eax
   140004c83:	7f 10                	jg     140004c95 <__pformat_emit_xfloat+0x215>
   140004c85:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c89:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c8c:	25 00 08 00 00       	and    eax,0x800
   140004c91:	85 c0                	test   eax,eax
   140004c93:	74 0f                	je     140004ca4 <__pformat_emit_xfloat+0x224>
   140004c95:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c99:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c9d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004ca1:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004ca4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004ca8:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004cac:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004cb0:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004cb3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cb7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004cba:	85 c0                	test   eax,eax
   140004cbc:	0f 8e e3 00 00 00    	jle    140004da5 <__pformat_emit_xfloat+0x325>
   140004cc2:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004cc6:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004cca:	48 29 c2             	sub    rdx,rax
   140004ccd:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004cd0:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004cd4:	98                   	cwde
   140004cd5:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004cd8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cdc:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004cdf:	85 c0                	test   eax,eax
   140004ce1:	7e 0a                	jle    140004ced <__pformat_emit_xfloat+0x26d>
   140004ce3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ce7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004cea:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004ced:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cf1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cf4:	25 c0 01 00 00       	and    eax,0x1c0
   140004cf9:	85 c0                	test   eax,eax
   140004cfb:	74 07                	je     140004d04 <__pformat_emit_xfloat+0x284>
   140004cfd:	b8 06 00 00 00       	mov    eax,0x6
   140004d02:	eb 05                	jmp    140004d09 <__pformat_emit_xfloat+0x289>
   140004d04:	b8 05 00 00 00       	mov    eax,0x5
   140004d09:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004d0c:	eb 0f                	jmp    140004d1d <__pformat_emit_xfloat+0x29d>
   140004d0e:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004d12:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004d16:	83 c0 01             	add    eax,0x1
   140004d19:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004d1d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004d20:	48 63 d0             	movsxd rdx,eax
   140004d23:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004d2a:	48 c1 ea 20          	shr    rdx,0x20
   140004d2e:	89 d1                	mov    ecx,edx
   140004d30:	c1 f9 02             	sar    ecx,0x2
   140004d33:	99                   	cdq
   140004d34:	89 c8                	mov    eax,ecx
   140004d36:	29 d0                	sub    eax,edx
   140004d38:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004d3b:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004d3f:	75 cd                	jne    140004d0e <__pformat_emit_xfloat+0x28e>
   140004d41:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d45:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d48:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004d4b:	7d 4d                	jge    140004d9a <__pformat_emit_xfloat+0x31a>
   140004d4d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d51:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d54:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004d57:	89 c2                	mov    edx,eax
   140004d59:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d5d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004d60:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d64:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d67:	25 00 06 00 00       	and    eax,0x600
   140004d6c:	85 c0                	test   eax,eax
   140004d6e:	75 35                	jne    140004da5 <__pformat_emit_xfloat+0x325>
   140004d70:	eb 11                	jmp    140004d83 <__pformat_emit_xfloat+0x303>
   140004d72:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d76:	48 89 c2             	mov    rdx,rax
   140004d79:	b9 20 00 00 00       	mov    ecx,0x20
   140004d7e:	e8 bd e4 ff ff       	call   140003240 <__pformat_putc>
   140004d83:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d87:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d8a:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004d8d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d91:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004d94:	85 c0                	test   eax,eax
   140004d96:	7f da                	jg     140004d72 <__pformat_emit_xfloat+0x2f2>
   140004d98:	eb 0b                	jmp    140004da5 <__pformat_emit_xfloat+0x325>
   140004d9a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d9e:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004da5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004da9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dac:	25 80 00 00 00       	and    eax,0x80
   140004db1:	85 c0                	test   eax,eax
   140004db3:	74 13                	je     140004dc8 <__pformat_emit_xfloat+0x348>
   140004db5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004db9:	48 89 c2             	mov    rdx,rax
   140004dbc:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004dc1:	e8 7a e4 ff ff       	call   140003240 <__pformat_putc>
   140004dc6:	eb 42                	jmp    140004e0a <__pformat_emit_xfloat+0x38a>
   140004dc8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dcc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dcf:	25 00 01 00 00       	and    eax,0x100
   140004dd4:	85 c0                	test   eax,eax
   140004dd6:	74 13                	je     140004deb <__pformat_emit_xfloat+0x36b>
   140004dd8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ddc:	48 89 c2             	mov    rdx,rax
   140004ddf:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004de4:	e8 57 e4 ff ff       	call   140003240 <__pformat_putc>
   140004de9:	eb 1f                	jmp    140004e0a <__pformat_emit_xfloat+0x38a>
   140004deb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004def:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004df2:	83 e0 40             	and    eax,0x40
   140004df5:	85 c0                	test   eax,eax
   140004df7:	74 11                	je     140004e0a <__pformat_emit_xfloat+0x38a>
   140004df9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dfd:	48 89 c2             	mov    rdx,rax
   140004e00:	b9 20 00 00 00       	mov    ecx,0x20
   140004e05:	e8 36 e4 ff ff       	call   140003240 <__pformat_putc>
   140004e0a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e0e:	48 89 c2             	mov    rdx,rax
   140004e11:	b9 30 00 00 00       	mov    ecx,0x30
   140004e16:	e8 25 e4 ff ff       	call   140003240 <__pformat_putc>
   140004e1b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e1f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e22:	83 e0 20             	and    eax,0x20
   140004e25:	83 c8 58             	or     eax,0x58
   140004e28:	89 c1                	mov    ecx,eax
   140004e2a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e2e:	48 89 c2             	mov    rdx,rax
   140004e31:	e8 0a e4 ff ff       	call   140003240 <__pformat_putc>
   140004e36:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e3a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e3d:	85 c0                	test   eax,eax
   140004e3f:	7e 54                	jle    140004e95 <__pformat_emit_xfloat+0x415>
   140004e41:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e45:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e48:	25 00 02 00 00       	and    eax,0x200
   140004e4d:	85 c0                	test   eax,eax
   140004e4f:	74 44                	je     140004e95 <__pformat_emit_xfloat+0x415>
   140004e51:	eb 11                	jmp    140004e64 <__pformat_emit_xfloat+0x3e4>
   140004e53:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e57:	48 89 c2             	mov    rdx,rax
   140004e5a:	b9 30 00 00 00       	mov    ecx,0x30
   140004e5f:	e8 dc e3 ff ff       	call   140003240 <__pformat_putc>
   140004e64:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e68:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e6b:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e6e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e72:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004e75:	85 c0                	test   eax,eax
   140004e77:	7f da                	jg     140004e53 <__pformat_emit_xfloat+0x3d3>
   140004e79:	eb 1a                	jmp    140004e95 <__pformat_emit_xfloat+0x415>
   140004e7b:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004e80:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004e84:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004e87:	0f be c0             	movsx  eax,al
   140004e8a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e8e:	89 c1                	mov    ecx,eax
   140004e90:	e8 32 f2 ff ff       	call   1400040c7 <__pformat_emit_numeric_value>
   140004e95:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004e99:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004e9d:	72 dc                	jb     140004e7b <__pformat_emit_xfloat+0x3fb>
   140004e9f:	eb 11                	jmp    140004eb2 <__pformat_emit_xfloat+0x432>
   140004ea1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ea5:	48 89 c2             	mov    rdx,rax
   140004ea8:	b9 30 00 00 00       	mov    ecx,0x30
   140004ead:	e8 8e e3 ff ff       	call   140003240 <__pformat_putc>
   140004eb2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eb6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004eb9:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004ebc:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004ec0:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004ec3:	85 c0                	test   eax,eax
   140004ec5:	7f da                	jg     140004ea1 <__pformat_emit_xfloat+0x421>
   140004ec7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ecb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ece:	83 e0 20             	and    eax,0x20
   140004ed1:	83 c8 50             	or     eax,0x50
   140004ed4:	89 c1                	mov    ecx,eax
   140004ed6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eda:	48 89 c2             	mov    rdx,rax
   140004edd:	e8 5e e3 ff ff       	call   140003240 <__pformat_putc>
   140004ee2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ee6:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004ee9:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004eed:	01 c2                	add    edx,eax
   140004eef:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ef3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004ef6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004efa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004efd:	0d c0 01 00 00       	or     eax,0x1c0
   140004f02:	89 c2                	mov    edx,eax
   140004f04:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f08:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004f0b:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004f0f:	66 85 c0             	test   ax,ax
   140004f12:	79 09                	jns    140004f1d <__pformat_emit_xfloat+0x49d>
   140004f14:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004f1b:	eb 05                	jmp    140004f22 <__pformat_emit_xfloat+0x4a2>
   140004f1d:	b8 00 00 00 00       	mov    eax,0x0
   140004f22:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004f26:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004f2a:	48 0f bf c0          	movsx  rax,ax
   140004f2e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004f32:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004f36:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004f3a:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004f3e:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004f42:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004f46:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004f4a:	48 89 c1             	mov    rcx,rax
   140004f4d:	e8 59 e7 ff ff       	call   1400036ab <__pformat_int>
   140004f52:	90                   	nop
   140004f53:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004f5a:	5b                   	pop    rbx
   140004f5b:	5d                   	pop    rbp
   140004f5c:	c3                   	ret

0000000140004f5d <__pformat_xldouble>:
   140004f5d:	55                   	push   rbp
   140004f5e:	53                   	push   rbx
   140004f5f:	48 83 ec 78          	sub    rsp,0x78
   140004f63:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004f68:	48 89 cb             	mov    rbx,rcx
   140004f6b:	db 2b                	fld    TBYTE PTR [rbx]
   140004f6d:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004f70:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004f74:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004f7b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004f7f:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f82:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f85:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004f89:	48 89 c1             	mov    rcx,rax
   140004f8c:	e8 e5 ed ff ff       	call   140003d76 <init_fpreg_ldouble>
   140004f91:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f94:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f97:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f9b:	48 89 c1             	mov    rcx,rax
   140004f9e:	e8 ed 3d 00 00       	call   140008d90 <__isnanl>
   140004fa3:	85 c0                	test   eax,eax
   140004fa5:	74 1d                	je     140004fc4 <__pformat_xldouble+0x67>
   140004fa7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004faa:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004fae:	48 8d 15 91 63 00 00 	lea    rdx,[rip+0x6391]        # 14000b346 <.rdata+0x16>
   140004fb5:	49 89 c8             	mov    r8,rcx
   140004fb8:	89 c1                	mov    ecx,eax
   140004fba:	e8 75 f1 ff ff       	call   140004134 <__pformat_emit_inf_or_nan>
   140004fbf:	e9 aa 00 00 00       	jmp    14000506e <__pformat_xldouble+0x111>
   140004fc4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fc8:	98                   	cwde
   140004fc9:	25 00 80 00 00       	and    eax,0x8000
   140004fce:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004fd1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004fd5:	74 12                	je     140004fe9 <__pformat_xldouble+0x8c>
   140004fd7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004fdb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004fde:	0c 80                	or     al,0x80
   140004fe0:	89 c2                	mov    edx,eax
   140004fe2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004fe6:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004fe9:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004fec:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004fef:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004ff3:	48 89 c1             	mov    rcx,rax
   140004ff6:	e8 a5 3c 00 00       	call   140008ca0 <__fpclassifyl>
   140004ffb:	3d 00 05 00 00       	cmp    eax,0x500
   140005000:	75 1a                	jne    14000501c <__pformat_xldouble+0xbf>
   140005002:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005005:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140005009:	48 8d 15 3a 63 00 00 	lea    rdx,[rip+0x633a]        # 14000b34a <.rdata+0x1a>
   140005010:	49 89 c8             	mov    r8,rcx
   140005013:	89 c1                	mov    ecx,eax
   140005015:	e8 1a f1 ff ff       	call   140004134 <__pformat_emit_inf_or_nan>
   14000501a:	eb 52                	jmp    14000506e <__pformat_xldouble+0x111>
   14000501c:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005020:	66 25 ff 7f          	and    ax,0x7fff
   140005024:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005028:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000502c:	66 85 c0             	test   ax,ax
   14000502f:	75 11                	jne    140005042 <__pformat_xldouble+0xe5>
   140005031:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005035:	48 85 c0             	test   rax,rax
   140005038:	74 14                	je     14000504e <__pformat_xldouble+0xf1>
   14000503a:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140005040:	eb 0c                	jmp    14000504e <__pformat_xldouble+0xf1>
   140005042:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005046:	66 2d ff 3f          	sub    ax,0x3fff
   14000504a:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000504e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005052:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005056:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000505a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   14000505e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140005062:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140005066:	48 89 c1             	mov    rcx,rax
   140005069:	e8 12 fa ff ff       	call   140004a80 <__pformat_emit_xfloat>
   14000506e:	90                   	nop
   14000506f:	48 83 c4 78          	add    rsp,0x78
   140005073:	5b                   	pop    rbx
   140005074:	5d                   	pop    rbp
   140005075:	c3                   	ret

0000000140005076 <__pformat_xdouble>:
   140005076:	55                   	push   rbp
   140005077:	48 89 e5             	mov    rbp,rsp
   14000507a:	48 83 ec 60          	sub    rsp,0x60
   14000507e:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140005083:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005087:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000508e:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140005091:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140005095:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140005098:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   14000509c:	48 89 c1             	mov    rcx,rax
   14000509f:	e8 d2 ec ff ff       	call   140003d76 <init_fpreg_ldouble>
   1400050a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400050a8:	66 48 0f 6e c0       	movq   xmm0,rax
   1400050ad:	e8 7e 3c 00 00       	call   140008d30 <__isnan>
   1400050b2:	85 c0                	test   eax,eax
   1400050b4:	74 1d                	je     1400050d3 <__pformat_xdouble+0x5d>
   1400050b6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400050b9:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   1400050bd:	48 8d 15 82 62 00 00 	lea    rdx,[rip+0x6282]        # 14000b346 <.rdata+0x16>
   1400050c4:	49 89 c8             	mov    r8,rcx
   1400050c7:	89 c1                	mov    ecx,eax
   1400050c9:	e8 66 f0 ff ff       	call   140004134 <__pformat_emit_inf_or_nan>
   1400050ce:	e9 f9 00 00 00       	jmp    1400051cc <__pformat_xdouble+0x156>
   1400050d3:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050d7:	98                   	cwde
   1400050d8:	25 00 80 00 00       	and    eax,0x8000
   1400050dd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400050e0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400050e4:	74 12                	je     1400050f8 <__pformat_xdouble+0x82>
   1400050e6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400050ea:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400050ed:	0c 80                	or     al,0x80
   1400050ef:	89 c2                	mov    edx,eax
   1400050f1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400050f5:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400050f8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400050fc:	66 48 0f 6e c0       	movq   xmm0,rax
   140005101:	e8 1a 3b 00 00       	call   140008c20 <__fpclassify>
   140005106:	3d 00 05 00 00       	cmp    eax,0x500
   14000510b:	75 1d                	jne    14000512a <__pformat_xdouble+0xb4>
   14000510d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005110:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140005114:	48 8d 15 2f 62 00 00 	lea    rdx,[rip+0x622f]        # 14000b34a <.rdata+0x1a>
   14000511b:	49 89 c8             	mov    r8,rcx
   14000511e:	89 c1                	mov    ecx,eax
   140005120:	e8 0f f0 ff ff       	call   140004134 <__pformat_emit_inf_or_nan>
   140005125:	e9 a2 00 00 00       	jmp    1400051cc <__pformat_xdouble+0x156>
   14000512a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000512e:	66 25 ff 7f          	and    ax,0x7fff
   140005132:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005136:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000513a:	66 85 c0             	test   ax,ax
   14000513d:	74 3b                	je     14000517a <__pformat_xdouble+0x104>
   14000513f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005143:	66 3d 00 3c          	cmp    ax,0x3c00
   140005147:	7f 31                	jg     14000517a <__pformat_xdouble+0x104>
   140005149:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000514d:	98                   	cwde
   14000514e:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005153:	29 c2                	sub    edx,eax
   140005155:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005158:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000515c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000515f:	89 c1                	mov    ecx,eax
   140005161:	48 d3 ea             	shr    rdx,cl
   140005164:	48 89 d0             	mov    rax,rdx
   140005167:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000516b:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000516f:	89 c2                	mov    edx,eax
   140005171:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005174:	01 d0                	add    eax,edx
   140005176:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000517a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000517e:	66 85 c0             	test   ax,ax
   140005181:	75 11                	jne    140005194 <__pformat_xdouble+0x11e>
   140005183:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005187:	48 85 c0             	test   rax,rax
   14000518a:	74 14                	je     1400051a0 <__pformat_xdouble+0x12a>
   14000518c:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   140005192:	eb 0c                	jmp    1400051a0 <__pformat_xdouble+0x12a>
   140005194:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005198:	66 2d fc 3f          	sub    ax,0x3ffc
   14000519c:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400051a0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400051a4:	48 c1 e8 03          	shr    rax,0x3
   1400051a8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400051ac:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400051b0:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400051b4:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400051b8:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400051bc:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400051c0:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   1400051c4:	48 89 c1             	mov    rcx,rax
   1400051c7:	e8 b4 f8 ff ff       	call   140004a80 <__pformat_emit_xfloat>
   1400051cc:	90                   	nop
   1400051cd:	48 83 c4 60          	add    rsp,0x60
   1400051d1:	5d                   	pop    rbp
   1400051d2:	c3                   	ret

00000001400051d3 <__mingw_pformat>:
   1400051d3:	55                   	push   rbp
   1400051d4:	48 89 e5             	mov    rbp,rsp
   1400051d7:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   1400051de:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400051e1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400051e5:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400051e9:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400051ed:	e8 a6 44 00 00       	call   140009698 <_errno>
   1400051f2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400051f4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400051f7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400051fb:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   1400051ff:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   140005206:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140005209:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000520c:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   140005213:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   14000521a:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   140005221:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   140005227:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   14000522e:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   140005234:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   14000523b:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   14000523e:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   140005241:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   140005248:	e9 27 0c 00 00       	jmp    140005e74 <__mingw_pformat+0xca1>
   14000524d:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005251:	0f 85 0f 0c 00 00    	jne    140005e66 <__mingw_pformat+0xc93>
   140005257:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000525e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005265:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005269:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000526d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005271:	48 83 c0 0c          	add    rax,0xc
   140005275:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005279:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000527c:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000527f:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005286:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140005289:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000528c:	e9 c4 0b 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005291:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005295:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005299:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000529d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400052a0:	0f be c0             	movsx  eax,al
   1400052a3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400052a6:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400052aa:	0f 84 94 09 00 00    	je     140005c44 <__mingw_pformat+0xa71>
   1400052b0:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400052b4:	0f 8f 02 0b 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400052ba:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400052be:	0f 84 eb 03 00 00    	je     1400056af <__mingw_pformat+0x4dc>
   1400052c4:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400052c8:	0f 8f ee 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400052ce:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400052d2:	0f 84 31 09 00 00    	je     140005c09 <__mingw_pformat+0xa36>
   1400052d8:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400052dc:	0f 8f da 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400052e2:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400052e6:	0f 84 c3 03 00 00    	je     1400056af <__mingw_pformat+0x4dc>
   1400052ec:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400052f0:	0f 8f c6 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400052f6:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   1400052fa:	0f 84 31 09 00 00    	je     140005c31 <__mingw_pformat+0xa5e>
   140005300:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   140005304:	0f 8f b2 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000530a:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   14000530e:	0f 84 31 03 00 00    	je     140005645 <__mingw_pformat+0x472>
   140005314:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   140005318:	0f 8f 9e 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000531e:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   140005322:	0f 84 28 05 00 00    	je     140005850 <__mingw_pformat+0x67d>
   140005328:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   14000532c:	0f 8f 8a 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005332:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005336:	0f 84 73 03 00 00    	je     1400056af <__mingw_pformat+0x4dc>
   14000533c:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005340:	0f 8f 76 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005346:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   14000534a:	0f 84 4d 07 00 00    	je     140005a9d <__mingw_pformat+0x8ca>
   140005350:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005354:	0f 8f 62 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000535a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000535e:	0f 84 2d 03 00 00    	je     140005691 <__mingw_pformat+0x4be>
   140005364:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   140005368:	0f 8f 4e 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000536e:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   140005372:	0f 84 65 08 00 00    	je     140005bdd <__mingw_pformat+0xa0a>
   140005378:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   14000537c:	0f 8f 3a 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005382:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005386:	0f 84 db 07 00 00    	je     140005b67 <__mingw_pformat+0x994>
   14000538c:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005390:	0f 8f 26 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005396:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   14000539a:	0f 84 ee 03 00 00    	je     14000578e <__mingw_pformat+0x5bb>
   1400053a0:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400053a4:	0f 8f 12 0a 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400053aa:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400053ae:	0f 84 87 07 00 00    	je     140005b3b <__mingw_pformat+0x968>
   1400053b4:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400053b8:	0f 8f fe 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400053be:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400053c2:	0f 84 f3 05 00 00    	je     1400059bb <__mingw_pformat+0x7e8>
   1400053c8:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400053cc:	0f 8f ea 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400053d2:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400053d6:	0f 84 61 05 00 00    	je     14000593d <__mingw_pformat+0x76a>
   1400053dc:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400053e0:	0f 8f d6 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400053e6:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400053ea:	0f 84 cf 04 00 00    	je     1400058bf <__mingw_pformat+0x6ec>
   1400053f0:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400053f4:	0f 8f c2 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400053fa:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   1400053fe:	0f 84 8a 03 00 00    	je     14000578e <__mingw_pformat+0x5bb>
   140005404:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   140005408:	0f 8f ae 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000540e:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   140005412:	0f 84 b5 01 00 00    	je     1400055cd <__mingw_pformat+0x3fa>
   140005418:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   14000541c:	0f 8f 9a 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005422:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005426:	0f 84 83 02 00 00    	je     1400056af <__mingw_pformat+0x4dc>
   14000542c:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005430:	0f 8f 86 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005436:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   14000543a:	0f 84 f9 05 00 00    	je     140005a39 <__mingw_pformat+0x866>
   140005440:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   140005444:	0f 8f 72 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000544a:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   14000544e:	0f 84 5b 02 00 00    	je     1400056af <__mingw_pformat+0x4dc>
   140005454:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005458:	0f 8f 5e 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000545e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   140005462:	0f 84 d6 01 00 00    	je     14000563e <__mingw_pformat+0x46b>
   140005468:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   14000546c:	0f 8f 4a 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005472:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005476:	0f 84 a0 07 00 00    	je     140005c1c <__mingw_pformat+0xa49>
   14000547c:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005480:	0f 8f 36 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005486:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   14000548a:	0f 84 ea 06 00 00    	je     140005b7a <__mingw_pformat+0x9a7>
   140005490:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   140005494:	0f 8f 22 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000549a:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   14000549e:	0f 84 20 05 00 00    	je     1400059c4 <__mingw_pformat+0x7f1>
   1400054a4:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400054a8:	0f 8f 0e 09 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400054ae:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400054b2:	0f 84 8e 04 00 00    	je     140005946 <__mingw_pformat+0x773>
   1400054b8:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400054bc:	0f 8f fa 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400054c2:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400054c6:	0f 84 fc 03 00 00    	je     1400058c8 <__mingw_pformat+0x6f5>
   1400054cc:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400054d0:	0f 8f e6 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400054d6:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400054da:	0f 84 e6 00 00 00    	je     1400055c6 <__mingw_pformat+0x3f3>
   1400054e0:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400054e4:	0f 8f d2 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400054ea:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400054ee:	0f 84 bb 01 00 00    	je     1400056af <__mingw_pformat+0x4dc>
   1400054f4:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400054f8:	0f 8f be 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   1400054fe:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   140005502:	0f 84 3a 05 00 00    	je     140005a42 <__mingw_pformat+0x86f>
   140005508:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   14000550c:	0f 8f aa 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005512:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005516:	0f 84 8c 08 00 00    	je     140005da8 <__mingw_pformat+0xbd5>
   14000551c:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005520:	0f 8f 96 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005526:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   14000552a:	0f 84 27 07 00 00    	je     140005c57 <__mingw_pformat+0xa84>
   140005530:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   140005534:	0f 8f 82 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000553a:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   14000553e:	0f 84 db 07 00 00    	je     140005d1f <__mingw_pformat+0xb4c>
   140005544:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   140005548:	0f 8f 6e 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000554e:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005552:	0f 84 af 07 00 00    	je     140005d07 <__mingw_pformat+0xb34>
   140005558:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000555c:	0f 8f 5a 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005562:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005566:	0f 84 1c 07 00 00    	je     140005c88 <__mingw_pformat+0xab5>
   14000556c:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005570:	0f 8f 46 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   140005576:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   14000557a:	0f 84 b7 07 00 00    	je     140005d37 <__mingw_pformat+0xb64>
   140005580:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   140005584:	0f 8f 32 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000558a:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   14000558e:	74 23                	je     1400055b3 <__mingw_pformat+0x3e0>
   140005590:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005594:	0f 8f 22 08 00 00    	jg     140005dbc <__mingw_pformat+0xbe9>
   14000559a:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   14000559e:	0f 84 ec 07 00 00    	je     140005d90 <__mingw_pformat+0xbbd>
   1400055a4:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   1400055a8:	0f 84 41 07 00 00    	je     140005cef <__mingw_pformat+0xb1c>
   1400055ae:	e9 09 08 00 00       	jmp    140005dbc <__mingw_pformat+0xbe9>
   1400055b3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055b7:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400055ba:	89 c1                	mov    ecx,eax
   1400055bc:	e8 7f dc ff ff       	call   140003240 <__pformat_putc>
   1400055c1:	e9 82 fc ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   1400055c6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400055cd:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400055d4:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400055d8:	74 06                	je     1400055e0 <__mingw_pformat+0x40d>
   1400055da:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055de:	75 30                	jne    140005610 <__mingw_pformat+0x43d>
   1400055e0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055e4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055e8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055ec:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055ee:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   1400055f2:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055f6:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   1400055fa:	49 89 d0             	mov    r8,rdx
   1400055fd:	ba 01 00 00 00       	mov    edx,0x1
   140005602:	48 89 c1             	mov    rcx,rax
   140005605:	e8 3f de ff ff       	call   140003449 <__pformat_wputchars>
   14000560a:	90                   	nop
   14000560b:	e9 38 fc ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005610:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005614:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005618:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000561c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000561e:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   140005621:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005625:	48 8d 45 90          	lea    rax,[rbp-0x70]
   140005629:	49 89 d0             	mov    r8,rdx
   14000562c:	ba 01 00 00 00       	mov    edx,0x1
   140005631:	48 89 c1             	mov    rcx,rax
   140005634:	e8 8b dc ff ff       	call   1400032c4 <__pformat_putchars>
   140005639:	e9 0a fc ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   14000563e:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005645:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005649:	74 06                	je     140005651 <__mingw_pformat+0x47e>
   14000564b:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000564f:	75 20                	jne    140005671 <__mingw_pformat+0x49e>
   140005651:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005655:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005659:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000565d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005660:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005664:	48 89 c1             	mov    rcx,rax
   140005667:	e8 29 df ff ff       	call   140003595 <__pformat_wcputs>
   14000566c:	e9 d7 fb ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005671:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005675:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005679:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000567d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005680:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005684:	48 89 c1             	mov    rcx,rax
   140005687:	e8 37 dd ff ff       	call   1400033c3 <__pformat_puts>
   14000568c:	e9 b7 fb ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005691:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140005694:	89 c1                	mov    ecx,eax
   140005696:	e8 85 40 00 00       	call   140009720 <strerror>
   14000569b:	48 89 c1             	mov    rcx,rax
   14000569e:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400056a2:	48 89 c2             	mov    rdx,rax
   1400056a5:	e8 19 dd ff ff       	call   1400033c3 <__pformat_puts>
   1400056aa:	e9 99 fb ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   1400056af:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400056b2:	80 e4 fe             	and    ah,0xfe
   1400056b5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400056b8:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400056bc:	75 15                	jne    1400056d3 <__mingw_pformat+0x500>
   1400056be:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056c2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056c6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056ca:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400056cd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056d1:	eb 54                	jmp    140005727 <__mingw_pformat+0x554>
   1400056d3:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400056d7:	75 16                	jne    1400056ef <__mingw_pformat+0x51c>
   1400056d9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056dd:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056e1:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056e5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056e7:	89 c0                	mov    eax,eax
   1400056e9:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056ed:	eb 38                	jmp    140005727 <__mingw_pformat+0x554>
   1400056ef:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056f3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056f7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056fb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056fd:	89 c0                	mov    eax,eax
   1400056ff:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005703:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005707:	75 0d                	jne    140005716 <__mingw_pformat+0x543>
   140005709:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000570d:	0f b7 c0             	movzx  eax,ax
   140005710:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005714:	eb 11                	jmp    140005727 <__mingw_pformat+0x554>
   140005716:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   14000571a:	75 0b                	jne    140005727 <__mingw_pformat+0x554>
   14000571c:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   140005720:	0f b6 c0             	movzx  eax,al
   140005723:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005727:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   14000572b:	75 2e                	jne    14000575b <__mingw_pformat+0x588>
   14000572d:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005731:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005735:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000573c:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005743:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005747:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000574e:	48 89 c1             	mov    rcx,rax
   140005751:	e8 55 df ff ff       	call   1400036ab <__pformat_int>
   140005756:	e9 ed fa ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   14000575b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000575f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005763:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000576a:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005771:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140005775:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   14000577c:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000577f:	49 89 c8             	mov    r8,rcx
   140005782:	89 c1                	mov    ecx,eax
   140005784:	e8 a5 e2 ff ff       	call   140003a2e <__pformat_xint>
   140005789:	e9 ba fa ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   14000578e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005791:	0c 80                	or     al,0x80
   140005793:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005796:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000579a:	75 15                	jne    1400057b1 <__mingw_pformat+0x5de>
   14000579c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057a0:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057a4:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057a8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400057ab:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057af:	eb 56                	jmp    140005807 <__mingw_pformat+0x634>
   1400057b1:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400057b5:	75 16                	jne    1400057cd <__mingw_pformat+0x5fa>
   1400057b7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057bb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057bf:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057c3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400057c5:	48 98                	cdqe
   1400057c7:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057cb:	eb 3a                	jmp    140005807 <__mingw_pformat+0x634>
   1400057cd:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057d1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057d5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057d9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400057db:	48 98                	cdqe
   1400057dd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057e1:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400057e5:	75 0e                	jne    1400057f5 <__mingw_pformat+0x622>
   1400057e7:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   1400057eb:	48 0f bf c0          	movsx  rax,ax
   1400057ef:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057f3:	eb 12                	jmp    140005807 <__mingw_pformat+0x634>
   1400057f5:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400057f9:	75 0c                	jne    140005807 <__mingw_pformat+0x634>
   1400057fb:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   1400057ff:	48 0f be c0          	movsx  rax,al
   140005803:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005807:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000580b:	48 85 c0             	test   rax,rax
   14000580e:	79 09                	jns    140005819 <__mingw_pformat+0x646>
   140005810:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140005817:	eb 05                	jmp    14000581e <__mingw_pformat+0x64b>
   140005819:	b8 00 00 00 00       	mov    eax,0x0
   14000581e:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140005822:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005826:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   14000582a:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005831:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005838:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000583c:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   140005843:	48 89 c1             	mov    rcx,rax
   140005846:	e8 60 de ff ff       	call   1400036ab <__pformat_int>
   14000584b:	e9 f8 f9 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005850:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005854:	75 18                	jne    14000586e <__mingw_pformat+0x69b>
   140005856:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005859:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000585c:	75 10                	jne    14000586e <__mingw_pformat+0x69b>
   14000585e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005861:	80 cc 02             	or     ah,0x2
   140005864:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005867:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   14000586e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005872:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005876:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000587a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000587d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005881:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   140005888:	00 
   140005889:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000588d:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005891:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005898:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   14000589f:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058a3:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400058aa:	49 89 d0             	mov    r8,rdx
   1400058ad:	48 89 c2             	mov    rdx,rax
   1400058b0:	b9 78 00 00 00       	mov    ecx,0x78
   1400058b5:	e8 74 e1 ff ff       	call   140003a2e <__pformat_xint>
   1400058ba:	e9 89 f9 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   1400058bf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058c2:	83 c8 20             	or     eax,0x20
   1400058c5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400058c8:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058cb:	83 e0 04             	and    eax,0x4
   1400058ce:	85 c0                	test   eax,eax
   1400058d0:	74 2f                	je     140005901 <__mingw_pformat+0x72e>
   1400058d2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058d6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058da:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058de:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400058e1:	db 28                	fld    TBYTE PTR [rax]
   1400058e3:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058e9:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058ed:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058f4:	48 89 c1             	mov    rcx,rax
   1400058f7:	e8 1d ef ff ff       	call   140004819 <__pformat_efloat>
   1400058fc:	e9 47 f9 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005901:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005905:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005909:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000590d:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   140005911:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   140005918:	ff 
   140005919:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000591f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005925:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005929:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005930:	48 89 c1             	mov    rcx,rax
   140005933:	e8 e1 ee ff ff       	call   140004819 <__pformat_efloat>
   140005938:	e9 0b f9 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   14000593d:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005940:	83 c8 20             	or     eax,0x20
   140005943:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005946:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005949:	83 e0 04             	and    eax,0x4
   14000594c:	85 c0                	test   eax,eax
   14000594e:	74 2f                	je     14000597f <__mingw_pformat+0x7ac>
   140005950:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005954:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005958:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000595c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000595f:	db 28                	fld    TBYTE PTR [rax]
   140005961:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005967:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000596b:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005972:	48 89 c1             	mov    rcx,rax
   140005975:	e8 cf ed ff ff       	call   140004749 <__pformat_float>
   14000597a:	e9 c9 f8 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   14000597f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005983:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005987:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000598b:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   14000598f:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   140005996:	ff 
   140005997:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000599d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059a3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059a7:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059ae:	48 89 c1             	mov    rcx,rax
   1400059b1:	e8 93 ed ff ff       	call   140004749 <__pformat_float>
   1400059b6:	e9 8d f8 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   1400059bb:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059be:	83 c8 20             	or     eax,0x20
   1400059c1:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400059c4:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059c7:	83 e0 04             	and    eax,0x4
   1400059ca:	85 c0                	test   eax,eax
   1400059cc:	74 2f                	je     1400059fd <__mingw_pformat+0x82a>
   1400059ce:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059d2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059d6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059da:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059dd:	db 28                	fld    TBYTE PTR [rax]
   1400059df:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059e5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059e9:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059f0:	48 89 c1             	mov    rcx,rax
   1400059f3:	e8 cc ee ff ff       	call   1400048c4 <__pformat_gfloat>
   1400059f8:	e9 4b f8 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   1400059fd:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a01:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a05:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a09:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   140005a0d:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   140005a14:	ff 
   140005a15:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   140005a1b:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a21:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a25:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a2c:	48 89 c1             	mov    rcx,rax
   140005a2f:	e8 90 ee ff ff       	call   1400048c4 <__pformat_gfloat>
   140005a34:	e9 0f f8 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005a39:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a3c:	83 c8 20             	or     eax,0x20
   140005a3f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005a42:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a45:	83 e0 04             	and    eax,0x4
   140005a48:	85 c0                	test   eax,eax
   140005a4a:	74 2f                	je     140005a7b <__mingw_pformat+0x8a8>
   140005a4c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a50:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a54:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a58:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a5b:	db 28                	fld    TBYTE PTR [rax]
   140005a5d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a63:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a67:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a6e:	48 89 c1             	mov    rcx,rax
   140005a71:	e8 e7 f4 ff ff       	call   140004f5d <__pformat_xldouble>
   140005a76:	e9 cd f7 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005a7b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a7f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a83:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a87:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a8a:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a8e:	66 48 0f 6e c0       	movq   xmm0,rax
   140005a93:	e8 de f5 ff ff       	call   140005076 <__pformat_xdouble>
   140005a98:	e9 ab f7 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005a9d:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005aa1:	75 1b                	jne    140005abe <__mingw_pformat+0x8eb>
   140005aa3:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005aa6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005aaa:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005aae:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ab2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ab5:	89 ca                	mov    edx,ecx
   140005ab7:	88 10                	mov    BYTE PTR [rax],dl
   140005ab9:	e9 8a f7 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005abe:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005ac2:	75 1c                	jne    140005ae0 <__mingw_pformat+0x90d>
   140005ac4:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005ac7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005acb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005acf:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ad3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ad6:	89 ca                	mov    edx,ecx
   140005ad8:	66 89 10             	mov    WORD PTR [rax],dx
   140005adb:	e9 68 f7 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005ae0:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005ae4:	75 19                	jne    140005aff <__mingw_pformat+0x92c>
   140005ae6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005aea:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005aee:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005af2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005af5:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005af8:	89 10                	mov    DWORD PTR [rax],edx
   140005afa:	e9 49 f7 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005aff:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005b03:	75 1d                	jne    140005b22 <__mingw_pformat+0x94f>
   140005b05:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005b08:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005b0c:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005b10:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b14:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b17:	48 63 d1             	movsxd rdx,ecx
   140005b1a:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005b1d:	e9 26 f7 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005b22:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005b26:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005b2a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b2e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b31:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005b34:	89 10                	mov    DWORD PTR [rax],edx
   140005b36:	e9 0d f7 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005b3b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b3f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b42:	3c 68                	cmp    al,0x68
   140005b44:	75 0e                	jne    140005b54 <__mingw_pformat+0x981>
   140005b46:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b4b:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005b52:	eb 07                	jmp    140005b5b <__mingw_pformat+0x988>
   140005b54:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005b5b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b62:	e9 ee 02 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005b67:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b6e:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b75:	e9 db 02 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005b7a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b7e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b81:	3c 36                	cmp    al,0x36
   140005b83:	75 1d                	jne    140005ba2 <__mingw_pformat+0x9cf>
   140005b85:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b89:	48 83 c0 01          	add    rax,0x1
   140005b8d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b90:	3c 34                	cmp    al,0x34
   140005b92:	75 0e                	jne    140005ba2 <__mingw_pformat+0x9cf>
   140005b94:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b9b:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005ba0:	eb 2f                	jmp    140005bd1 <__mingw_pformat+0x9fe>
   140005ba2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ba6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ba9:	3c 33                	cmp    al,0x33
   140005bab:	75 1d                	jne    140005bca <__mingw_pformat+0x9f7>
   140005bad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005bb1:	48 83 c0 01          	add    rax,0x1
   140005bb5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005bb8:	3c 32                	cmp    al,0x32
   140005bba:	75 0e                	jne    140005bca <__mingw_pformat+0x9f7>
   140005bbc:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005bc3:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005bc8:	eb 07                	jmp    140005bd1 <__mingw_pformat+0x9fe>
   140005bca:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bd1:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bd8:	e9 78 02 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005bdd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005be1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005be4:	3c 6c                	cmp    al,0x6c
   140005be6:	75 0e                	jne    140005bf6 <__mingw_pformat+0xa23>
   140005be8:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005bed:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bf4:	eb 07                	jmp    140005bfd <__mingw_pformat+0xa2a>
   140005bf6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005bfd:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c04:	e9 4c 02 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005c09:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005c10:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c17:	e9 39 02 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005c1c:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c1f:	83 c8 04             	or     eax,0x4
   140005c22:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c25:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c2c:	e9 24 02 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005c31:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c38:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c3f:	e9 11 02 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005c44:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c4b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c52:	e9 fe 01 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005c57:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005c5b:	77 1f                	ja     140005c7c <__mingw_pformat+0xaa9>
   140005c5d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005c64:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005c68:	48 83 c0 10          	add    rax,0x10
   140005c6c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005c70:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005c77:	e9 d9 01 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005c7c:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c83:	e9 cd 01 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005c88:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005c8d:	74 4c                	je     140005cdb <__mingw_pformat+0xb08>
   140005c8f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c93:	74 06                	je     140005c9b <__mingw_pformat+0xac8>
   140005c95:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005c99:	75 40                	jne    140005cdb <__mingw_pformat+0xb08>
   140005c9b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005c9f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005ca3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ca7:	8b 10                	mov    edx,DWORD PTR [rax]
   140005ca9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005cad:	89 10                	mov    DWORD PTR [rax],edx
   140005caf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005cb3:	8b 00                	mov    eax,DWORD PTR [rax]
   140005cb5:	85 c0                	test   eax,eax
   140005cb7:	79 29                	jns    140005ce2 <__mingw_pformat+0xb0f>
   140005cb9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cbd:	75 13                	jne    140005cd2 <__mingw_pformat+0xaff>
   140005cbf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cc2:	80 cc 04             	or     ah,0x4
   140005cc5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cc8:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005ccb:	f7 d8                	neg    eax
   140005ccd:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005cd0:	eb 10                	jmp    140005ce2 <__mingw_pformat+0xb0f>
   140005cd2:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005cd9:	eb 07                	jmp    140005ce2 <__mingw_pformat+0xb0f>
   140005cdb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ce2:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005ce9:	00 
   140005cea:	e9 66 01 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005cef:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cf3:	0f 85 4f 01 00 00    	jne    140005e48 <__mingw_pformat+0xc75>
   140005cf9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cfc:	80 cc 08             	or     ah,0x8
   140005cff:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d02:	e9 41 01 00 00       	jmp    140005e48 <__mingw_pformat+0xc75>
   140005d07:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d0b:	0f 85 3a 01 00 00    	jne    140005e4b <__mingw_pformat+0xc78>
   140005d11:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d14:	80 cc 01             	or     ah,0x1
   140005d17:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d1a:	e9 2c 01 00 00       	jmp    140005e4b <__mingw_pformat+0xc78>
   140005d1f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d23:	0f 85 25 01 00 00    	jne    140005e4e <__mingw_pformat+0xc7b>
   140005d29:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d2c:	80 cc 04             	or     ah,0x4
   140005d2f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d32:	e9 17 01 00 00       	jmp    140005e4e <__mingw_pformat+0xc7b>
   140005d37:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d3b:	0f 85 10 01 00 00    	jne    140005e51 <__mingw_pformat+0xc7e>
   140005d41:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d44:	80 cc 10             	or     ah,0x10
   140005d47:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d4a:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005d51:	00 
   140005d52:	e8 a1 39 00 00       	call   1400096f8 <localeconv>
   140005d57:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005d5b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005d5f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005d63:	49 89 c9             	mov    r9,rcx
   140005d66:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005d6c:	48 89 c1             	mov    rcx,rax
   140005d6f:	e8 bc 33 00 00       	call   140009130 <mbrtowc>
   140005d74:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005d77:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005d7b:	7e 08                	jle    140005d85 <__mingw_pformat+0xbb2>
   140005d7d:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005d81:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005d85:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005d88:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005d8b:	e9 c1 00 00 00       	jmp    140005e51 <__mingw_pformat+0xc7e>
   140005d90:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d94:	0f 85 ba 00 00 00    	jne    140005e54 <__mingw_pformat+0xc81>
   140005d9a:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d9d:	83 c8 40             	or     eax,0x40
   140005da0:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005da3:	e9 ac 00 00 00       	jmp    140005e54 <__mingw_pformat+0xc81>
   140005da8:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005dac:	75 0e                	jne    140005dbc <__mingw_pformat+0xbe9>
   140005dae:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005db1:	80 cc 02             	or     ah,0x2
   140005db4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005db7:	e9 99 00 00 00       	jmp    140005e55 <__mingw_pformat+0xc82>
   140005dbc:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005dc0:	77 68                	ja     140005e2a <__mingw_pformat+0xc57>
   140005dc2:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005dc6:	7f 62                	jg     140005e2a <__mingw_pformat+0xc57>
   140005dc8:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005dcc:	7e 5c                	jle    140005e2a <__mingw_pformat+0xc57>
   140005dce:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005dd2:	75 09                	jne    140005ddd <__mingw_pformat+0xc0a>
   140005dd4:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005ddb:	eb 0d                	jmp    140005dea <__mingw_pformat+0xc17>
   140005ddd:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005de1:	75 07                	jne    140005dea <__mingw_pformat+0xc17>
   140005de3:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005dea:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005def:	74 64                	je     140005e55 <__mingw_pformat+0xc82>
   140005df1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005df5:	8b 00                	mov    eax,DWORD PTR [rax]
   140005df7:	85 c0                	test   eax,eax
   140005df9:	79 0e                	jns    140005e09 <__mingw_pformat+0xc36>
   140005dfb:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005dfe:	8d 50 d0             	lea    edx,[rax-0x30]
   140005e01:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e05:	89 10                	mov    DWORD PTR [rax],edx
   140005e07:	eb 4c                	jmp    140005e55 <__mingw_pformat+0xc82>
   140005e09:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e0d:	8b 10                	mov    edx,DWORD PTR [rax]
   140005e0f:	89 d0                	mov    eax,edx
   140005e11:	c1 e0 02             	shl    eax,0x2
   140005e14:	01 d0                	add    eax,edx
   140005e16:	01 c0                	add    eax,eax
   140005e18:	89 c2                	mov    edx,eax
   140005e1a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e1d:	01 d0                	add    eax,edx
   140005e1f:	8d 50 d0             	lea    edx,[rax-0x30]
   140005e22:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e26:	89 10                	mov    DWORD PTR [rax],edx
   140005e28:	eb 2b                	jmp    140005e55 <__mingw_pformat+0xc82>
   140005e2a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005e2e:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005e32:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005e36:	48 89 c2             	mov    rdx,rax
   140005e39:	b9 25 00 00 00       	mov    ecx,0x25
   140005e3e:	e8 fd d3 ff ff       	call   140003240 <__pformat_putc>
   140005e43:	e9 00 f4 ff ff       	jmp    140005248 <__mingw_pformat+0x75>
   140005e48:	90                   	nop
   140005e49:	eb 0a                	jmp    140005e55 <__mingw_pformat+0xc82>
   140005e4b:	90                   	nop
   140005e4c:	eb 07                	jmp    140005e55 <__mingw_pformat+0xc82>
   140005e4e:	90                   	nop
   140005e4f:	eb 04                	jmp    140005e55 <__mingw_pformat+0xc82>
   140005e51:	90                   	nop
   140005e52:	eb 01                	jmp    140005e55 <__mingw_pformat+0xc82>
   140005e54:	90                   	nop
   140005e55:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e59:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e5c:	84 c0                	test   al,al
   140005e5e:	0f 85 2d f4 ff ff    	jne    140005291 <__mingw_pformat+0xbe>
   140005e64:	eb 0e                	jmp    140005e74 <__mingw_pformat+0xca1>
   140005e66:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005e6a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e6d:	89 c1                	mov    ecx,eax
   140005e6f:	e8 cc d3 ff ff       	call   140003240 <__pformat_putc>
   140005e74:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e78:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e7c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005e80:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e83:	0f be c0             	movsx  eax,al
   140005e86:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005e89:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005e8d:	0f 85 ba f3 ff ff    	jne    14000524d <__mingw_pformat+0x7a>
   140005e93:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005e96:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005e9d:	5d                   	pop    rbp
   140005e9e:	c3                   	ret
   140005e9f:	90                   	nop

0000000140005ea0 <__rv_alloc_D2A>:
   140005ea0:	55                   	push   rbp
   140005ea1:	48 89 e5             	mov    rbp,rsp
   140005ea4:	48 83 ec 30          	sub    rsp,0x30
   140005ea8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005eab:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005eb2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005eb9:	eb 07                	jmp    140005ec2 <__rv_alloc_D2A+0x22>
   140005ebb:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005ebf:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005ec2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005ec5:	83 c0 17             	add    eax,0x17
   140005ec8:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005ecb:	7f ee                	jg     140005ebb <__rv_alloc_D2A+0x1b>
   140005ecd:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005ed0:	89 c1                	mov    ecx,eax
   140005ed2:	e8 56 1e 00 00       	call   140007d2d <__Balloc_D2A>
   140005ed7:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005edb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005edf:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005ee2:	89 10                	mov    DWORD PTR [rax],edx
   140005ee4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ee8:	48 83 c0 04          	add    rax,0x4
   140005eec:	48 83 c4 30          	add    rsp,0x30
   140005ef0:	5d                   	pop    rbp
   140005ef1:	c3                   	ret

0000000140005ef2 <__nrv_alloc_D2A>:
   140005ef2:	55                   	push   rbp
   140005ef3:	48 89 e5             	mov    rbp,rsp
   140005ef6:	48 83 ec 30          	sub    rsp,0x30
   140005efa:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005efe:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005f02:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005f06:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005f09:	89 c1                	mov    ecx,eax
   140005f0b:	e8 90 ff ff ff       	call   140005ea0 <__rv_alloc_D2A>
   140005f10:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005f14:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f18:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f1c:	eb 05                	jmp    140005f23 <__nrv_alloc_D2A+0x31>
   140005f1e:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005f23:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f27:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005f2b:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005f2f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005f32:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f36:	88 10                	mov    BYTE PTR [rax],dl
   140005f38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f3c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005f3f:	84 c0                	test   al,al
   140005f41:	75 db                	jne    140005f1e <__nrv_alloc_D2A+0x2c>
   140005f43:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005f48:	74 0b                	je     140005f55 <__nrv_alloc_D2A+0x63>
   140005f4a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f4e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005f52:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005f55:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f59:	48 83 c4 30          	add    rsp,0x30
   140005f5d:	5d                   	pop    rbp
   140005f5e:	c3                   	ret

0000000140005f5f <__freedtoa>:
   140005f5f:	55                   	push   rbp
   140005f60:	48 89 e5             	mov    rbp,rsp
   140005f63:	48 83 ec 30          	sub    rsp,0x30
   140005f67:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f6b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f6f:	48 83 e8 04          	sub    rax,0x4
   140005f73:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f77:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f7b:	8b 10                	mov    edx,DWORD PTR [rax]
   140005f7d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f81:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005f84:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f88:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005f8b:	ba 01 00 00 00       	mov    edx,0x1
   140005f90:	89 c1                	mov    ecx,eax
   140005f92:	d3 e2                	shl    edx,cl
   140005f94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f98:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005f9b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f9f:	48 89 c1             	mov    rcx,rax
   140005fa2:	e8 c7 1e 00 00       	call   140007e6e <__Bfree_D2A>
   140005fa7:	90                   	nop
   140005fa8:	48 83 c4 30          	add    rsp,0x30
   140005fac:	5d                   	pop    rbp
   140005fad:	c3                   	ret

0000000140005fae <__quorem_D2A>:
   140005fae:	55                   	push   rbp
   140005faf:	48 89 e5             	mov    rbp,rsp
   140005fb2:	48 83 ec 70          	sub    rsp,0x70
   140005fb6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005fba:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005fbe:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005fc2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005fc5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005fc8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005fcc:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005fcf:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005fd2:	7e 0a                	jle    140005fde <__quorem_D2A+0x30>
   140005fd4:	b8 00 00 00 00       	mov    eax,0x0
   140005fd9:	e9 3f 02 00 00       	jmp    14000621d <__quorem_D2A+0x26f>
   140005fde:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005fe2:	48 83 c0 18          	add    rax,0x18
   140005fe6:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005fea:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005fee:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005ff1:	48 98                	cdqe
   140005ff3:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005ffa:	00 
   140005ffb:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005fff:	48 01 d0             	add    rax,rdx
   140006002:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140006006:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000600a:	48 83 c0 18          	add    rax,0x18
   14000600e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006012:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006015:	48 98                	cdqe
   140006017:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000601e:	00 
   14000601f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006023:	48 01 d0             	add    rax,rdx
   140006026:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000602a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000602e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006030:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140006034:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006036:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140006039:	ba 00 00 00 00       	mov    edx,0x0
   14000603e:	f7 f1                	div    ecx
   140006040:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140006043:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140006047:	0f 84 c4 00 00 00    	je     140006111 <__quorem_D2A+0x163>
   14000604d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006054:	00 
   140006055:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000605c:	00 
   14000605d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006061:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140006065:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006069:	8b 00                	mov    eax,DWORD PTR [rax]
   14000606b:	89 c2                	mov    edx,eax
   14000606d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140006070:	48 0f af d0          	imul   rdx,rax
   140006074:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006078:	48 01 d0             	add    rax,rdx
   14000607b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000607f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006083:	48 c1 e8 20          	shr    rax,0x20
   140006087:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000608b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000608f:	8b 00                	mov    eax,DWORD PTR [rax]
   140006091:	89 c1                	mov    ecx,eax
   140006093:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006097:	89 c2                	mov    edx,eax
   140006099:	48 89 c8             	mov    rax,rcx
   14000609c:	48 29 d0             	sub    rax,rdx
   14000609f:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   1400060a3:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400060a7:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400060ab:	48 c1 e8 20          	shr    rax,0x20
   1400060af:	83 e0 01             	and    eax,0x1
   1400060b2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400060b6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060ba:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400060be:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400060c2:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400060c6:	89 10                	mov    DWORD PTR [rax],edx
   1400060c8:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400060cc:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400060d0:	73 8b                	jae    14000605d <__quorem_D2A+0xaf>
   1400060d2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060d6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060d8:	85 c0                	test   eax,eax
   1400060da:	75 35                	jne    140006111 <__quorem_D2A+0x163>
   1400060dc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060e0:	48 83 c0 18          	add    rax,0x18
   1400060e4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400060e8:	eb 04                	jmp    1400060ee <__quorem_D2A+0x140>
   1400060ea:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400060ee:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400060f3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060f7:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   1400060fb:	73 0a                	jae    140006107 <__quorem_D2A+0x159>
   1400060fd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006101:	8b 00                	mov    eax,DWORD PTR [rax]
   140006103:	85 c0                	test   eax,eax
   140006105:	74 e3                	je     1400060ea <__quorem_D2A+0x13c>
   140006107:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000610b:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000610e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006111:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140006115:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006119:	48 89 c1             	mov    rcx,rax
   14000611c:	e8 bc 24 00 00       	call   1400085dd <__cmp_D2A>
   140006121:	85 c0                	test   eax,eax
   140006123:	0f 88 f1 00 00 00    	js     14000621a <__quorem_D2A+0x26c>
   140006129:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   14000612d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006134:	00 
   140006135:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000613c:	00 
   14000613d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006141:	48 83 c0 18          	add    rax,0x18
   140006145:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006149:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000614d:	48 83 c0 18          	add    rax,0x18
   140006151:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006155:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006159:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000615d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006161:	8b 00                	mov    eax,DWORD PTR [rax]
   140006163:	89 c2                	mov    edx,eax
   140006165:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006169:	48 01 d0             	add    rax,rdx
   14000616c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140006170:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006174:	48 c1 e8 20          	shr    rax,0x20
   140006178:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000617c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006180:	8b 00                	mov    eax,DWORD PTR [rax]
   140006182:	89 c1                	mov    ecx,eax
   140006184:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006188:	89 c2                	mov    edx,eax
   14000618a:	48 89 c8             	mov    rax,rcx
   14000618d:	48 29 d0             	sub    rax,rdx
   140006190:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006194:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006198:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000619c:	48 c1 e8 20          	shr    rax,0x20
   1400061a0:	83 e0 01             	and    eax,0x1
   1400061a3:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400061a7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061ab:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400061af:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400061b3:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400061b7:	89 10                	mov    DWORD PTR [rax],edx
   1400061b9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400061bd:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400061c1:	73 92                	jae    140006155 <__quorem_D2A+0x1a7>
   1400061c3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400061c7:	48 83 c0 18          	add    rax,0x18
   1400061cb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400061cf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400061d2:	48 98                	cdqe
   1400061d4:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400061db:	00 
   1400061dc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061e0:	48 01 d0             	add    rax,rdx
   1400061e3:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400061e7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400061ed:	85 c0                	test   eax,eax
   1400061ef:	75 29                	jne    14000621a <__quorem_D2A+0x26c>
   1400061f1:	eb 04                	jmp    1400061f7 <__quorem_D2A+0x249>
   1400061f3:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400061f7:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400061fc:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006200:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   140006204:	73 0a                	jae    140006210 <__quorem_D2A+0x262>
   140006206:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000620a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000620c:	85 c0                	test   eax,eax
   14000620e:	74 e3                	je     1400061f3 <__quorem_D2A+0x245>
   140006210:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006214:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006217:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000621a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   14000621d:	48 83 c4 70          	add    rsp,0x70
   140006221:	5d                   	pop    rbp
   140006222:	c3                   	ret
   140006223:	90                   	nop
   140006224:	90                   	nop
   140006225:	90                   	nop
   140006226:	90                   	nop
   140006227:	90                   	nop
   140006228:	90                   	nop
   140006229:	90                   	nop
   14000622a:	90                   	nop
   14000622b:	90                   	nop
   14000622c:	90                   	nop
   14000622d:	90                   	nop
   14000622e:	90                   	nop
   14000622f:	90                   	nop

0000000140006230 <__hi0bits_D2A>:
   140006230:	55                   	push   rbp
   140006231:	48 89 e5             	mov    rbp,rsp
   140006234:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140006237:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   14000623b:	83 f0 1f             	xor    eax,0x1f
   14000623e:	5d                   	pop    rbp
   14000623f:	c3                   	ret

0000000140006240 <bitstob>:
   140006240:	55                   	push   rbp
   140006241:	53                   	push   rbx
   140006242:	48 83 ec 58          	sub    rsp,0x58
   140006246:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000624b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000624f:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006252:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006256:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000625d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140006264:	eb 07                	jmp    14000626d <bitstob+0x2d>
   140006266:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140006269:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   14000626d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006270:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   140006273:	7c f1                	jl     140006266 <bitstob+0x26>
   140006275:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140006278:	89 c1                	mov    ecx,eax
   14000627a:	e8 ae 1a 00 00       	call   140007d2d <__Balloc_D2A>
   14000627f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006283:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140006286:	83 e8 01             	sub    eax,0x1
   140006289:	c1 f8 05             	sar    eax,0x5
   14000628c:	48 98                	cdqe
   14000628e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006295:	00 
   140006296:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000629a:	48 01 d0             	add    rax,rdx
   14000629d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400062a1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062a5:	48 83 c0 18          	add    rax,0x18
   1400062a9:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400062ad:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400062b1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400062b5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400062b9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400062bd:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400062c1:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400062c5:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400062c7:	89 10                	mov    DWORD PTR [rax],edx
   1400062c9:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   1400062ce:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400062d2:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400062d6:	73 dd                	jae    1400062b5 <bitstob+0x75>
   1400062d8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400062dc:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400062e0:	48 c1 f8 02          	sar    rax,0x2
   1400062e4:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400062e7:	eb 1d                	jmp    140006306 <bitstob+0xc6>
   1400062e9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400062ed:	75 17                	jne    140006306 <bitstob+0xc6>
   1400062ef:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062f3:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   1400062fa:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400062fe:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140006304:	eb 59                	jmp    14000635f <bitstob+0x11f>
   140006306:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000630a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000630d:	48 98                	cdqe
   14000630f:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006316:	00 
   140006317:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000631b:	48 01 d0             	add    rax,rdx
   14000631e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006320:	85 c0                	test   eax,eax
   140006322:	74 c5                	je     1400062e9 <bitstob+0xa9>
   140006324:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006327:	8d 50 01             	lea    edx,[rax+0x1]
   14000632a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000632e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006331:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006334:	83 c0 01             	add    eax,0x1
   140006337:	c1 e0 05             	shl    eax,0x5
   14000633a:	89 c3                	mov    ebx,eax
   14000633c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006340:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006343:	48 63 d2             	movsxd rdx,edx
   140006346:	48 83 c2 04          	add    rdx,0x4
   14000634a:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   14000634e:	89 c1                	mov    ecx,eax
   140006350:	e8 db fe ff ff       	call   140006230 <__hi0bits_D2A>
   140006355:	29 c3                	sub    ebx,eax
   140006357:	89 da                	mov    edx,ebx
   140006359:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000635d:	89 10                	mov    DWORD PTR [rax],edx
   14000635f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006363:	48 83 c4 58          	add    rsp,0x58
   140006367:	5b                   	pop    rbx
   140006368:	5d                   	pop    rbp
   140006369:	c3                   	ret

000000014000636a <__gdtoa>:
   14000636a:	55                   	push   rbp
   14000636b:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   140006372:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140006379:	00 
   14000637a:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   140006381:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   140006387:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   14000638e:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   140006395:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   14000639c:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063a3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063a5:	83 e0 cf             	and    eax,0xffffffcf
   1400063a8:	89 c2                	mov    edx,eax
   1400063aa:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063b1:	89 10                	mov    DWORD PTR [rax],edx
   1400063b3:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063ba:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063bc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400063bf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400063c2:	83 e0 07             	and    eax,0x7
   1400063c5:	83 f8 04             	cmp    eax,0x4
   1400063c8:	0f 84 b0 00 00 00    	je     14000647e <__gdtoa+0x114>
   1400063ce:	83 f8 04             	cmp    eax,0x4
   1400063d1:	0f 8f d5 00 00 00    	jg     1400064ac <__gdtoa+0x142>
   1400063d7:	83 f8 03             	cmp    eax,0x3
   1400063da:	74 74                	je     140006450 <__gdtoa+0xe6>
   1400063dc:	83 f8 03             	cmp    eax,0x3
   1400063df:	0f 8f c7 00 00 00    	jg     1400064ac <__gdtoa+0x142>
   1400063e5:	85 c0                	test   eax,eax
   1400063e7:	0f 84 05 01 00 00    	je     1400064f2 <__gdtoa+0x188>
   1400063ed:	85 c0                	test   eax,eax
   1400063ef:	0f 88 b7 00 00 00    	js     1400064ac <__gdtoa+0x142>
   1400063f5:	83 e8 01             	sub    eax,0x1
   1400063f8:	83 f8 01             	cmp    eax,0x1
   1400063fb:	0f 87 ab 00 00 00    	ja     1400064ac <__gdtoa+0x142>
   140006401:	90                   	nop
   140006402:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006409:	8b 00                	mov    eax,DWORD PTR [rax]
   14000640b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000640e:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   140006412:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006415:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   14000641c:	49 89 c8             	mov    r8,rcx
   14000641f:	48 89 c1             	mov    rcx,rax
   140006422:	e8 19 fe ff ff       	call   140006240 <bitstob>
   140006427:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000642b:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006431:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140006434:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006438:	48 89 c1             	mov    rcx,rax
   14000643b:	e8 31 16 00 00       	call   140007a71 <__trailz_D2A>
   140006440:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006443:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006446:	85 c0                	test   eax,eax
   140006448:	0f 84 8b 00 00 00    	je     1400064d9 <__gdtoa+0x16f>
   14000644e:	eb 66                	jmp    1400064b6 <__gdtoa+0x14c>
   140006450:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006457:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000645d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006464:	48 8d 0d e5 4e 00 00 	lea    rcx,[rip+0x4ee5]        # 14000b350 <.rdata>
   14000646b:	41 b8 08 00 00 00    	mov    r8d,0x8
   140006471:	48 89 c2             	mov    rdx,rax
   140006474:	e8 79 fa ff ff       	call   140005ef2 <__nrv_alloc_D2A>
   140006479:	e9 4d 14 00 00       	jmp    1400078cb <__gdtoa+0x1561>
   14000647e:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006485:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000648b:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006492:	48 8d 0d c0 4e 00 00 	lea    rcx,[rip+0x4ec0]        # 14000b359 <.rdata+0x9>
   140006499:	41 b8 03 00 00 00    	mov    r8d,0x3
   14000649f:	48 89 c2             	mov    rdx,rax
   1400064a2:	e8 4b fa ff ff       	call   140005ef2 <__nrv_alloc_D2A>
   1400064a7:	e9 1f 14 00 00       	jmp    1400078cb <__gdtoa+0x1561>
   1400064ac:	b8 00 00 00 00       	mov    eax,0x0
   1400064b1:	e9 15 14 00 00       	jmp    1400078cb <__gdtoa+0x1561>
   1400064b6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400064b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064bd:	48 89 c1             	mov    rcx,rax
   1400064c0:	e8 50 14 00 00       	call   140007915 <__rshift_D2A>
   1400064c5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064c8:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   1400064ce:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400064d1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064d4:	29 c2                	sub    edx,eax
   1400064d6:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   1400064d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064dd:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400064e0:	85 c0                	test   eax,eax
   1400064e2:	75 3d                	jne    140006521 <__gdtoa+0x1b7>
   1400064e4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064e8:	48 89 c1             	mov    rcx,rax
   1400064eb:	e8 7e 19 00 00       	call   140007e6e <__Bfree_D2A>
   1400064f0:	eb 01                	jmp    1400064f3 <__gdtoa+0x189>
   1400064f2:	90                   	nop
   1400064f3:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400064fa:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140006500:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006507:	48 8d 0d 4f 4e 00 00 	lea    rcx,[rip+0x4e4f]        # 14000b35d <.rdata+0xd>
   14000650e:	41 b8 01 00 00 00    	mov    r8d,0x1
   140006514:	48 89 c2             	mov    rdx,rax
   140006517:	e8 d6 f9 ff ff       	call   140005ef2 <__nrv_alloc_D2A>
   14000651c:	e9 aa 13 00 00       	jmp    1400078cb <__gdtoa+0x1561>
   140006521:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   140006525:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006529:	48 89 c1             	mov    rcx,rax
   14000652c:	e8 75 23 00 00       	call   1400088a6 <__b2d_D2A>
   140006531:	66 48 0f 7e c0       	movq   rax,xmm0
   140006536:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   14000653a:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   14000653d:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006543:	01 d0                	add    eax,edx
   140006545:	83 e8 01             	sub    eax,0x1
   140006548:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000654b:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   14000654e:	25 ff ff 0f 00       	and    eax,0xfffff
   140006553:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006556:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006559:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000655e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006561:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006566:	f2 0f 10 15 f2 4d 00 	movsd  xmm2,QWORD PTR [rip+0x4df2]        # 14000b360 <.rdata+0x10>
   14000656d:	00 
   14000656e:	66 0f 28 c8          	movapd xmm1,xmm0
   140006572:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006576:	f2 0f 10 05 ea 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4dea]        # 14000b368 <.rdata+0x18>
   14000657d:	00 
   14000657e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006582:	f2 0f 10 05 e6 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4de6]        # 14000b370 <.rdata+0x20>
   140006589:	00 
   14000658a:	f2 0f 58 c8          	addsd  xmm1,xmm0
   14000658e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006591:	66 0f ef d2          	pxor   xmm2,xmm2
   140006595:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   140006599:	f2 0f 10 05 d7 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4dd7]        # 14000b378 <.rdata+0x28>
   1400065a0:	00 
   1400065a1:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   1400065a5:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400065a9:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400065ae:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400065b1:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400065b4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065b8:	79 03                	jns    1400065bd <__gdtoa+0x253>
   1400065ba:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   1400065bd:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   1400065c4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065c8:	7e 23                	jle    1400065ed <__gdtoa+0x283>
   1400065ca:	66 0f ef c9          	pxor   xmm1,xmm1
   1400065ce:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   1400065d3:	f2 0f 10 05 a5 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4da5]        # 14000b380 <.rdata+0x30>
   1400065da:	00 
   1400065db:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400065df:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   1400065e4:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400065e8:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400065ed:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   1400065f2:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400065f6:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   1400065f9:	66 0f ef c0          	pxor   xmm0,xmm0
   1400065fd:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006602:	76 1b                	jbe    14000661f <__gdtoa+0x2b5>
   140006604:	66 0f ef c0          	pxor   xmm0,xmm0
   140006608:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   14000660d:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006612:	7a 07                	jp     14000661b <__gdtoa+0x2b1>
   140006614:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006619:	74 04                	je     14000661f <__gdtoa+0x2b5>
   14000661b:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000661f:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   140006626:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006629:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   14000662c:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006632:	01 ca                	add    edx,ecx
   140006634:	83 ea 01             	sub    edx,0x1
   140006637:	c1 e2 14             	shl    edx,0x14
   14000663a:	01 d0                	add    eax,edx
   14000663c:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000663f:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006643:	78 2e                	js     140006673 <__gdtoa+0x309>
   140006645:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   140006649:	7f 28                	jg     140006673 <__gdtoa+0x309>
   14000664b:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006650:	48 8b 05 29 50 00 00 	mov    rax,QWORD PTR [rip+0x5029]        # 14000b680 <.refptr.__tens_D2A>
   140006657:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000665a:	48 63 d2             	movsxd rdx,edx
   14000665d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006662:	66 0f 2f c1          	comisd xmm0,xmm1
   140006666:	76 04                	jbe    14000666c <__gdtoa+0x302>
   140006668:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000666c:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   140006673:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006676:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006679:	29 c2                	sub    edx,eax
   14000667b:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000667e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006681:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006685:	78 0f                	js     140006696 <__gdtoa+0x32c>
   140006687:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   14000668e:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006691:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   140006694:	eb 0f                	jmp    1400066a5 <__gdtoa+0x33b>
   140006696:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006699:	f7 d8                	neg    eax
   14000669b:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   14000669e:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   1400066a5:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400066a9:	78 15                	js     1400066c0 <__gdtoa+0x356>
   1400066ab:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   1400066b2:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066b5:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   1400066b8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066bb:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400066be:	eb 15                	jmp    1400066d5 <__gdtoa+0x36b>
   1400066c0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066c3:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   1400066c6:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066c9:	f7 d8                	neg    eax
   1400066cb:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   1400066ce:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   1400066d5:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400066dc:	78 09                	js     1400066e7 <__gdtoa+0x37d>
   1400066de:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   1400066e5:	7e 0a                	jle    1400066f1 <__gdtoa+0x387>
   1400066e7:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   1400066ee:	00 00 00 
   1400066f1:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   1400066f8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400066ff:	7e 10                	jle    140006711 <__gdtoa+0x3a7>
   140006701:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   140006708:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000670f:	eb 1b                	jmp    14000672c <__gdtoa+0x3c2>
   140006711:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006714:	3d f9 03 00 00       	cmp    eax,0x3f9
   140006719:	7f 0a                	jg     140006725 <__gdtoa+0x3bb>
   14000671b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000671e:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   140006723:	7d 07                	jge    14000672c <__gdtoa+0x3c2>
   140006725:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000672c:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   140006733:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   14000673a:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000673d:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006740:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006747:	0f 84 c5 00 00 00    	je     140006812 <__gdtoa+0x4a8>
   14000674d:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006754:	0f 8f e6 00 00 00    	jg     140006840 <__gdtoa+0x4d6>
   14000675a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   140006761:	74 7e                	je     1400067e1 <__gdtoa+0x477>
   140006763:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   14000676a:	0f 8f d0 00 00 00    	jg     140006840 <__gdtoa+0x4d6>
   140006770:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006777:	0f 84 8e 00 00 00    	je     14000680b <__gdtoa+0x4a1>
   14000677d:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006784:	0f 8f b6 00 00 00    	jg     140006840 <__gdtoa+0x4d6>
   14000678a:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006791:	7f 0e                	jg     1400067a1 <__gdtoa+0x437>
   140006793:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000679a:	79 13                	jns    1400067af <__gdtoa+0x445>
   14000679c:	e9 9f 00 00 00       	jmp    140006840 <__gdtoa+0x4d6>
   1400067a1:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400067a8:	74 30                	je     1400067da <__gdtoa+0x470>
   1400067aa:	e9 91 00 00 00       	jmp    140006840 <__gdtoa+0x4d6>
   1400067af:	66 0f ef c9          	pxor   xmm1,xmm1
   1400067b3:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   1400067b8:	f2 0f 10 05 c8 4b 00 	movsd  xmm0,QWORD PTR [rip+0x4bc8]        # 14000b388 <.rdata+0x38>
   1400067bf:	00 
   1400067c0:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400067c4:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400067c8:	83 c0 03             	add    eax,0x3
   1400067cb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067ce:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   1400067d5:	00 00 00 
   1400067d8:	eb 66                	jmp    140006840 <__gdtoa+0x4d6>
   1400067da:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   1400067e1:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   1400067e8:	7f 0a                	jg     1400067f4 <__gdtoa+0x48a>
   1400067ea:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   1400067f1:	00 00 00 
   1400067f4:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   1400067fa:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067fd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006800:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006803:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006806:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006809:	eb 35                	jmp    140006840 <__gdtoa+0x4d6>
   14000680b:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006812:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   140006818:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000681b:	01 d0                	add    eax,edx
   14000681d:	83 c0 01             	add    eax,0x1
   140006820:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006823:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006826:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006829:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000682c:	83 e8 01             	sub    eax,0x1
   14000682f:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006832:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006835:	85 c0                	test   eax,eax
   140006837:	7f 07                	jg     140006840 <__gdtoa+0x4d6>
   140006839:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006840:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006843:	89 c1                	mov    ecx,eax
   140006845:	e8 56 f6 ff ff       	call   140005ea0 <__rv_alloc_D2A>
   14000684a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000684e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006852:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006856:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000685d:	7f 09                	jg     140006868 <__gdtoa+0x4fe>
   14000685f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   140006866:	eb 38                	jmp    1400068a0 <__gdtoa+0x536>
   140006868:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000686f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140006872:	83 e8 01             	sub    eax,0x1
   140006875:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006878:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000687c:	74 22                	je     1400068a0 <__gdtoa+0x536>
   14000687e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006882:	79 07                	jns    14000688b <__gdtoa+0x521>
   140006884:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   14000688b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000688e:	83 e0 08             	and    eax,0x8
   140006891:	85 c0                	test   eax,eax
   140006893:	74 0b                	je     1400068a0 <__gdtoa+0x536>
   140006895:	b8 03 00 00 00       	mov    eax,0x3
   14000689a:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   14000689d:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   1400068a0:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400068a4:	0f 88 b9 04 00 00    	js     140006d63 <__gdtoa+0x9f9>
   1400068aa:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   1400068ae:	0f 8f af 04 00 00    	jg     140006d63 <__gdtoa+0x9f9>
   1400068b4:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   1400068b8:	0f 84 a5 04 00 00    	je     140006d63 <__gdtoa+0x9f9>
   1400068be:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400068c2:	0f 85 9b 04 00 00    	jne    140006d63 <__gdtoa+0x9f9>
   1400068c8:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400068cc:	0f 85 91 04 00 00    	jne    140006d63 <__gdtoa+0x9f9>
   1400068d2:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   1400068d9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400068de:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400068e3:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068e6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400068e9:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   1400068ec:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   1400068ef:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   1400068f6:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400068fa:	0f 8e 98 00 00 00    	jle    140006998 <__gdtoa+0x62e>
   140006900:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006903:	83 e0 0f             	and    eax,0xf
   140006906:	89 c2                	mov    edx,eax
   140006908:	48 8b 05 71 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d71]        # 14000b680 <.refptr.__tens_D2A>
   14000690f:	48 63 d2             	movsxd rdx,edx
   140006912:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006917:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000691c:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000691f:	c1 f8 04             	sar    eax,0x4
   140006922:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006925:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006928:	83 e0 10             	and    eax,0x10
   14000692b:	85 c0                	test   eax,eax
   14000692d:	74 5e                	je     14000698d <__gdtoa+0x623>
   14000692f:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   140006933:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006938:	48 8b 05 71 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c71]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000693f:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   140006944:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006948:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000694d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006951:	eb 3a                	jmp    14000698d <__gdtoa+0x623>
   140006953:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006956:	83 e0 01             	and    eax,0x1
   140006959:	85 c0                	test   eax,eax
   14000695b:	74 24                	je     140006981 <__gdtoa+0x617>
   14000695d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006961:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006964:	48 8b 05 45 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c45]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000696b:	48 63 d2             	movsxd rdx,edx
   14000696e:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006973:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006978:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000697c:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006981:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006984:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006987:	83 c0 01             	add    eax,0x1
   14000698a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000698d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006991:	75 c0                	jne    140006953 <__gdtoa+0x5e9>
   140006993:	e9 8b 00 00 00       	jmp    140006a23 <__gdtoa+0x6b9>
   140006998:	f2 0f 10 05 f0 49 00 	movsd  xmm0,QWORD PTR [rip+0x49f0]        # 14000b390 <.rdata+0x40>
   14000699f:	00 
   1400069a0:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400069a5:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400069a8:	f7 d8                	neg    eax
   1400069aa:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400069ad:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400069b1:	74 70                	je     140006a23 <__gdtoa+0x6b9>
   1400069b3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069b8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400069bb:	83 e0 0f             	and    eax,0xf
   1400069be:	89 c2                	mov    edx,eax
   1400069c0:	48 8b 05 b9 4c 00 00 	mov    rax,QWORD PTR [rip+0x4cb9]        # 14000b680 <.refptr.__tens_D2A>
   1400069c7:	48 63 d2             	movsxd rdx,edx
   1400069ca:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400069cf:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069d3:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069d8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400069db:	c1 f8 04             	sar    eax,0x4
   1400069de:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400069e1:	eb 3a                	jmp    140006a1d <__gdtoa+0x6b3>
   1400069e3:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400069e6:	83 e0 01             	and    eax,0x1
   1400069e9:	85 c0                	test   eax,eax
   1400069eb:	74 24                	je     140006a11 <__gdtoa+0x6a7>
   1400069ed:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400069f1:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069f6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400069f9:	48 8b 05 b0 4b 00 00 	mov    rax,QWORD PTR [rip+0x4bb0]        # 14000b5b0 <.refptr.__bigtens_D2A>
   140006a00:	48 63 d2             	movsxd rdx,edx
   140006a03:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006a08:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a0c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a11:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006a14:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006a17:	83 c0 01             	add    eax,0x1
   140006a1a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006a1d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006a21:	75 c0                	jne    1400069e3 <__gdtoa+0x679>
   140006a23:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140006a27:	74 47                	je     140006a70 <__gdtoa+0x706>
   140006a29:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a2e:	f2 0f 10 05 5a 49 00 	movsd  xmm0,QWORD PTR [rip+0x495a]        # 14000b390 <.rdata+0x40>
   140006a35:	00 
   140006a36:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a3a:	76 34                	jbe    140006a70 <__gdtoa+0x706>
   140006a3c:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a40:	7e 2e                	jle    140006a70 <__gdtoa+0x706>
   140006a42:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   140006a46:	0f 8e f5 02 00 00    	jle    140006d41 <__gdtoa+0x9d7>
   140006a4c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006a4f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006a52:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006a56:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a5b:	f2 0f 10 05 35 49 00 	movsd  xmm0,QWORD PTR [rip+0x4935]        # 14000b398 <.rdata+0x48>
   140006a62:	00 
   140006a63:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a67:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a6c:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006a70:	66 0f ef c9          	pxor   xmm1,xmm1
   140006a74:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006a79:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a7e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006a82:	f2 0f 10 05 16 49 00 	movsd  xmm0,QWORD PTR [rip+0x4916]        # 14000b3a0 <.rdata+0x50>
   140006a89:	00 
   140006a8a:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006a8e:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a93:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   140006a96:	2d 00 00 40 03       	sub    eax,0x3400000
   140006a9b:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   140006a9e:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006aa2:	75 5f                	jne    140006b03 <__gdtoa+0x799>
   140006aa4:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006aab:	00 
   140006aac:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006ab0:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006ab4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ab9:	f2 0f 10 0d e7 48 00 	movsd  xmm1,QWORD PTR [rip+0x48e7]        # 14000b3a8 <.rdata+0x58>
   140006ac0:	00 
   140006ac1:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006ac5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006aca:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006acf:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006ad4:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ad8:	0f 87 ac 07 00 00    	ja     14000728a <__gdtoa+0xf20>
   140006ade:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ae3:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006ae8:	f3 0f 7e 15 c0 48 00 	movq   xmm2,QWORD PTR [rip+0x48c0]        # 14000b3b0 <.rdata+0x60>
   140006aef:	00 
   140006af0:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006af4:	66 0f 2f c1          	comisd xmm0,xmm1
   140006af8:	0f 87 6e 07 00 00    	ja     14000726c <__gdtoa+0xf02>
   140006afe:	e9 42 02 00 00       	jmp    140006d45 <__gdtoa+0x9db>
   140006b03:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006b07:	0f 84 22 01 00 00    	je     140006c2f <__gdtoa+0x8c5>
   140006b0d:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006b12:	f2 0f 10 05 a6 48 00 	movsd  xmm0,QWORD PTR [rip+0x48a6]        # 14000b3c0 <.rdata+0x70>
   140006b19:	00 
   140006b1a:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b1e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006b21:	8d 50 ff             	lea    edx,[rax-0x1]
   140006b24:	48 8b 05 55 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b55]        # 14000b680 <.refptr.__tens_D2A>
   140006b2b:	48 63 d2             	movsxd rdx,edx
   140006b2e:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006b33:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006b37:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b3c:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b40:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b45:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006b4c:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b51:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006b56:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006b5a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006b5d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b62:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b66:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006b6b:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006b70:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b74:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b79:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006b7c:	8d 48 30             	lea    ecx,[rax+0x30]
   140006b7f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006b83:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006b87:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006b8b:	89 ca                	mov    edx,ecx
   140006b8d:	88 10                	mov    BYTE PTR [rax],dl
   140006b8f:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b94:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b99:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b9d:	76 29                	jbe    140006bc8 <__gdtoa+0x85e>
   140006b9f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ba4:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ba8:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006bac:	7a 0e                	jp     140006bbc <__gdtoa+0x852>
   140006bae:	66 0f ef c9          	pxor   xmm1,xmm1
   140006bb2:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006bb6:	0f 84 93 0c 00 00    	je     14000784f <__gdtoa+0x14e5>
   140006bbc:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006bc3:	e9 87 0c 00 00       	jmp    14000784f <__gdtoa+0x14e5>
   140006bc8:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006bcd:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006bd2:	66 0f 28 c8          	movapd xmm1,xmm0
   140006bd6:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006bda:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006bdf:	66 0f 2f c1          	comisd xmm0,xmm1
   140006be3:	0f 87 c3 02 00 00    	ja     140006eac <__gdtoa+0xb42>
   140006be9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006bec:	83 c0 01             	add    eax,0x1
   140006bef:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006bf2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006bf5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006bf8:	0f 8e 46 01 00 00    	jle    140006d44 <__gdtoa+0x9da>
   140006bfe:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c03:	f2 0f 10 05 8d 47 00 	movsd  xmm0,QWORD PTR [rip+0x478d]        # 14000b398 <.rdata+0x48>
   140006c0a:	00 
   140006c0b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c0f:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c14:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c19:	f2 0f 10 05 77 47 00 	movsd  xmm0,QWORD PTR [rip+0x4777]        # 14000b398 <.rdata+0x48>
   140006c20:	00 
   140006c21:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c25:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c2a:	e9 1d ff ff ff       	jmp    140006b4c <__gdtoa+0x7e2>
   140006c2f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c34:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006c37:	8d 50 ff             	lea    edx,[rax-0x1]
   140006c3a:	48 8b 05 3f 4a 00 00 	mov    rax,QWORD PTR [rip+0x4a3f]        # 14000b680 <.refptr.__tens_D2A>
   140006c41:	48 63 d2             	movsxd rdx,edx
   140006c44:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006c49:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c4d:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c52:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006c59:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c5e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006c63:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006c67:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006c6a:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006c6e:	74 1c                	je     140006c8c <__gdtoa+0x922>
   140006c70:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c75:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c79:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006c7e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006c83:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006c87:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c8c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006c8f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006c92:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006c96:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006c9a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006c9e:	89 ca                	mov    edx,ecx
   140006ca0:	88 10                	mov    BYTE PTR [rax],dl
   140006ca2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ca5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006ca8:	75 73                	jne    140006d1d <__gdtoa+0x9b3>
   140006caa:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006caf:	f2 0f 10 05 09 47 00 	movsd  xmm0,QWORD PTR [rip+0x4709]        # 14000b3c0 <.rdata+0x70>
   140006cb6:	00 
   140006cb7:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006cbb:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006cc0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006cc5:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006cca:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006ccf:	66 0f 2f c1          	comisd xmm0,xmm1
   140006cd3:	0f 87 d6 01 00 00    	ja     140006eaf <__gdtoa+0xb45>
   140006cd9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006cde:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006ce3:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006ce8:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006cec:	66 0f 2f c1          	comisd xmm0,xmm1
   140006cf0:	77 02                	ja     140006cf4 <__gdtoa+0x98a>
   140006cf2:	eb 51                	jmp    140006d45 <__gdtoa+0x9db>
   140006cf4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006cf9:	66 0f ef c9          	pxor   xmm1,xmm1
   140006cfd:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d01:	7a 0e                	jp     140006d11 <__gdtoa+0x9a7>
   140006d03:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d07:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d0b:	0f 84 41 0b 00 00    	je     140007852 <__gdtoa+0x14e8>
   140006d11:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006d18:	e9 35 0b 00 00       	jmp    140007852 <__gdtoa+0x14e8>
   140006d1d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006d20:	83 c0 01             	add    eax,0x1
   140006d23:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006d26:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d2b:	f2 0f 10 05 65 46 00 	movsd  xmm0,QWORD PTR [rip+0x4665]        # 14000b398 <.rdata+0x48>
   140006d32:	00 
   140006d33:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006d37:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d3c:	e9 18 ff ff ff       	jmp    140006c59 <__gdtoa+0x8ef>
   140006d41:	90                   	nop
   140006d42:	eb 01                	jmp    140006d45 <__gdtoa+0x9db>
   140006d44:	90                   	nop
   140006d45:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006d49:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006d4d:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006d52:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d57:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006d5a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006d5d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006d60:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006d63:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006d6a:	0f 88 bf 01 00 00    	js     140006f2f <__gdtoa+0xbc5>
   140006d70:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006d77:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006d7a:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006d7d:	0f 8f ac 01 00 00    	jg     140006f2f <__gdtoa+0xbc5>
   140006d83:	48 8b 05 f6 48 00 00 	mov    rax,QWORD PTR [rip+0x48f6]        # 14000b680 <.refptr.__tens_D2A>
   140006d8a:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006d8d:	48 63 d2             	movsxd rdx,edx
   140006d90:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006d95:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006d9a:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006da1:	79 45                	jns    140006de8 <__gdtoa+0xa7e>
   140006da3:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006da7:	7f 3f                	jg     140006de8 <__gdtoa+0xa7e>
   140006da9:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006db0:	00 
   140006db1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006db5:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006db9:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006dbd:	0f 88 ac 04 00 00    	js     14000726f <__gdtoa+0xf05>
   140006dc3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006dc8:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006dcd:	f2 0f 10 05 d3 45 00 	movsd  xmm0,QWORD PTR [rip+0x45d3]        # 14000b3a8 <.rdata+0x58>
   140006dd4:	00 
   140006dd5:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006dd9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ddd:	0f 83 8c 04 00 00    	jae    14000726f <__gdtoa+0xf05>
   140006de3:	e9 a6 04 00 00       	jmp    14000728e <__gdtoa+0xf24>
   140006de8:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006def:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006df4:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006df9:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006dfd:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006e00:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e05:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e09:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006e0e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006e13:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006e17:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e1c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006e1f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006e22:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e26:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006e2a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006e2e:	89 ca                	mov    edx,ecx
   140006e30:	88 10                	mov    BYTE PTR [rax],dl
   140006e32:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e37:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e3b:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e3f:	7a 0e                	jp     140006e4f <__gdtoa+0xae5>
   140006e41:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e45:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e49:	0f 84 da 00 00 00    	je     140006f29 <__gdtoa+0xbbf>
   140006e4f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e52:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006e55:	0f 85 aa 00 00 00    	jne    140006f05 <__gdtoa+0xb9b>
   140006e5b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006e5f:	74 12                	je     140006e73 <__gdtoa+0xb09>
   140006e61:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006e65:	74 4b                	je     140006eb2 <__gdtoa+0xb48>
   140006e67:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e6e:	e9 e3 09 00 00       	jmp    140007856 <__gdtoa+0x14ec>
   140006e73:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e78:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006e7c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e81:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e86:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006e8b:	77 28                	ja     140006eb5 <__gdtoa+0xb4b>
   140006e8d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e92:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e97:	7a 63                	jp     140006efc <__gdtoa+0xb92>
   140006e99:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e9e:	75 5c                	jne    140006efc <__gdtoa+0xb92>
   140006ea0:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006ea3:	83 e0 01             	and    eax,0x1
   140006ea6:	85 c0                	test   eax,eax
   140006ea8:	74 52                	je     140006efc <__gdtoa+0xb92>
   140006eaa:	eb 0a                	jmp    140006eb6 <__gdtoa+0xb4c>
   140006eac:	90                   	nop
   140006ead:	eb 07                	jmp    140006eb6 <__gdtoa+0xb4c>
   140006eaf:	90                   	nop
   140006eb0:	eb 04                	jmp    140006eb6 <__gdtoa+0xb4c>
   140006eb2:	90                   	nop
   140006eb3:	eb 01                	jmp    140006eb6 <__gdtoa+0xb4c>
   140006eb5:	90                   	nop
   140006eb6:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006ebd:	eb 17                	jmp    140006ed6 <__gdtoa+0xb6c>
   140006ebf:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ec3:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006ec7:	75 0d                	jne    140006ed6 <__gdtoa+0xb6c>
   140006ec9:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006ecd:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ed1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006ed4:	eb 10                	jmp    140006ee6 <__gdtoa+0xb7c>
   140006ed6:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006edb:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006edf:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006ee2:	3c 39                	cmp    al,0x39
   140006ee4:	74 d9                	je     140006ebf <__gdtoa+0xb55>
   140006ee6:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006eea:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006eee:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006ef2:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006ef5:	83 c2 01             	add    edx,0x1
   140006ef8:	88 10                	mov    BYTE PTR [rax],dl
   140006efa:	eb 2e                	jmp    140006f2a <__gdtoa+0xbc0>
   140006efc:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006f03:	eb 25                	jmp    140006f2a <__gdtoa+0xbc0>
   140006f05:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f08:	83 c0 01             	add    eax,0x1
   140006f0b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f0e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006f13:	f2 0f 10 05 7d 44 00 	movsd  xmm0,QWORD PTR [rip+0x447d]        # 14000b398 <.rdata+0x48>
   140006f1a:	00 
   140006f1b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006f1f:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006f24:	e9 c6 fe ff ff       	jmp    140006def <__gdtoa+0xa85>
   140006f29:	90                   	nop
   140006f2a:	e9 27 09 00 00       	jmp    140007856 <__gdtoa+0x14ec>
   140006f2f:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006f32:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006f35:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006f38:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006f3b:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006f42:	00 
   140006f43:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006f47:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f4b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006f4f:	0f 84 e0 00 00 00    	je     140007035 <__gdtoa+0xccb>
   140006f55:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006f58:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006f5b:	29 c2                	sub    edx,eax
   140006f5d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f60:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f63:	8d 50 01             	lea    edx,[rax+0x1]
   140006f66:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f69:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f6f:	29 c2                	sub    edx,eax
   140006f71:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f78:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f7b:	39 c2                	cmp    edx,eax
   140006f7d:	7d 43                	jge    140006fc2 <__gdtoa+0xc58>
   140006f7f:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006f86:	74 3a                	je     140006fc2 <__gdtoa+0xc58>
   140006f88:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006f8f:	74 31                	je     140006fc2 <__gdtoa+0xc58>
   140006f91:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f98:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f9b:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006fa1:	29 c2                	sub    edx,eax
   140006fa3:	8d 42 01             	lea    eax,[rdx+0x1]
   140006fa6:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006fa9:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006fb0:	7e 68                	jle    14000701a <__gdtoa+0xcb0>
   140006fb2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006fb6:	7e 62                	jle    14000701a <__gdtoa+0xcb0>
   140006fb8:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fbb:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006fbe:	7d 5a                	jge    14000701a <__gdtoa+0xcb0>
   140006fc0:	eb 0a                	jmp    140006fcc <__gdtoa+0xc62>
   140006fc2:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006fc9:	7e 50                	jle    14000701b <__gdtoa+0xcb1>
   140006fcb:	90                   	nop
   140006fcc:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006fcf:	83 e8 01             	sub    eax,0x1
   140006fd2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006fd5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006fd8:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006fdb:	7c 08                	jl     140006fe5 <__gdtoa+0xc7b>
   140006fdd:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fe0:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006fe3:	eb 19                	jmp    140006ffe <__gdtoa+0xc94>
   140006fe5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006fe8:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006feb:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fee:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006ff1:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006ff4:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006ff7:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006ffe:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140007001:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007004:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007007:	85 c0                	test   eax,eax
   140007009:	79 10                	jns    14000701b <__gdtoa+0xcb1>
   14000700b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000700e:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140007011:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140007018:	eb 01                	jmp    14000701b <__gdtoa+0xcb1>
   14000701a:	90                   	nop
   14000701b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000701e:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140007021:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007024:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140007027:	b9 01 00 00 00       	mov    ecx,0x1
   14000702c:	e8 f6 0f 00 00       	call   140008027 <__i2b_D2A>
   140007031:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007035:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140007039:	7e 26                	jle    140007061 <__gdtoa+0xcf7>
   14000703b:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000703f:	7e 20                	jle    140007061 <__gdtoa+0xcf7>
   140007041:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007044:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140007047:	39 c2                	cmp    edx,eax
   140007049:	0f 4e c2             	cmovle eax,edx
   14000704c:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000704f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007052:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140007055:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007058:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   14000705b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000705e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140007061:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140007065:	7e 7e                	jle    1400070e5 <__gdtoa+0xd7b>
   140007067:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000706b:	74 65                	je     1400070d2 <__gdtoa+0xd68>
   14000706d:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140007071:	7e 3b                	jle    1400070ae <__gdtoa+0xd44>
   140007073:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140007076:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000707a:	48 89 c1             	mov    rcx,rax
   14000707d:	e8 11 12 00 00       	call   140008293 <__pow5mult_D2A>
   140007082:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007086:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000708a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000708e:	48 89 c1             	mov    rcx,rax
   140007091:	e8 d7 0f 00 00       	call   14000806d <__mult_D2A>
   140007096:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000709a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000709e:	48 89 c1             	mov    rcx,rax
   1400070a1:	e8 c8 0d 00 00       	call   140007e6e <__Bfree_D2A>
   1400070a6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400070aa:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070ae:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   1400070b1:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   1400070b4:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400070b7:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400070bb:	74 28                	je     1400070e5 <__gdtoa+0xd7b>
   1400070bd:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   1400070c0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070c4:	48 89 c1             	mov    rcx,rax
   1400070c7:	e8 c7 11 00 00       	call   140008293 <__pow5mult_D2A>
   1400070cc:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070d0:	eb 13                	jmp    1400070e5 <__gdtoa+0xd7b>
   1400070d2:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   1400070d5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070d9:	48 89 c1             	mov    rcx,rax
   1400070dc:	e8 b2 11 00 00       	call   140008293 <__pow5mult_D2A>
   1400070e1:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070e5:	b9 01 00 00 00       	mov    ecx,0x1
   1400070ea:	e8 38 0f 00 00       	call   140008027 <__i2b_D2A>
   1400070ef:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070f3:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   1400070f7:	7e 13                	jle    14000710c <__gdtoa+0xda2>
   1400070f9:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   1400070fc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007100:	48 89 c1             	mov    rcx,rax
   140007103:	e8 8b 11 00 00       	call   140008293 <__pow5mult_D2A>
   140007108:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000710c:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   140007113:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000711a:	7f 29                	jg     140007145 <__gdtoa+0xddb>
   14000711c:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   14000711f:	83 f8 01             	cmp    eax,0x1
   140007122:	75 21                	jne    140007145 <__gdtoa+0xddb>
   140007124:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000712b:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000712e:	83 c0 01             	add    eax,0x1
   140007131:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140007134:	7e 0f                	jle    140007145 <__gdtoa+0xddb>
   140007136:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   14000713a:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   14000713e:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   140007145:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007149:	74 22                	je     14000716d <__gdtoa+0xe03>
   14000714b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000714f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007152:	8d 50 ff             	lea    edx,[rax-0x1]
   140007155:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007159:	48 63 d2             	movsxd rdx,edx
   14000715c:	48 83 c2 04          	add    rdx,0x4
   140007160:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   140007164:	89 c1                	mov    ecx,eax
   140007166:	e8 c5 f0 ff ff       	call   140006230 <__hi0bits_D2A>
   14000716b:	eb 05                	jmp    140007172 <__gdtoa+0xe08>
   14000716d:	b8 1f 00 00 00       	mov    eax,0x1f
   140007172:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   140007175:	83 e8 04             	sub    eax,0x4
   140007178:	83 e0 1f             	and    eax,0x1f
   14000717b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000717e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007181:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   140007184:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007187:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   14000718a:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   14000718e:	7e 13                	jle    1400071a3 <__gdtoa+0xe39>
   140007190:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   140007193:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007197:	48 89 c1             	mov    rcx,rax
   14000719a:	e8 b1 12 00 00       	call   140008450 <__lshift_D2A>
   14000719f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400071a3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400071a6:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400071a9:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   1400071ad:	7e 13                	jle    1400071c2 <__gdtoa+0xe58>
   1400071af:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   1400071b2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400071b6:	48 89 c1             	mov    rcx,rax
   1400071b9:	e8 92 12 00 00       	call   140008450 <__lshift_D2A>
   1400071be:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400071c2:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400071c6:	74 5a                	je     140007222 <__gdtoa+0xeb8>
   1400071c8:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400071cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071d0:	48 89 c1             	mov    rcx,rax
   1400071d3:	e8 05 14 00 00       	call   1400085dd <__cmp_D2A>
   1400071d8:	85 c0                	test   eax,eax
   1400071da:	79 46                	jns    140007222 <__gdtoa+0xeb8>
   1400071dc:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400071e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071e4:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071ea:	ba 0a 00 00 00       	mov    edx,0xa
   1400071ef:	48 89 c1             	mov    rcx,rax
   1400071f2:	e8 02 0d 00 00       	call   140007ef9 <__multadd_D2A>
   1400071f7:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400071fb:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400071ff:	74 1b                	je     14000721c <__gdtoa+0xeb2>
   140007201:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007205:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000720b:	ba 0a 00 00 00       	mov    edx,0xa
   140007210:	48 89 c1             	mov    rcx,rax
   140007213:	e8 e1 0c 00 00       	call   140007ef9 <__multadd_D2A>
   140007218:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000721c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000721f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140007222:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007226:	0f 8f 81 00 00 00    	jg     1400072ad <__gdtoa+0xf43>
   14000722c:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140007233:	7e 78                	jle    1400072ad <__gdtoa+0xf43>
   140007235:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007239:	78 37                	js     140007272 <__gdtoa+0xf08>
   14000723b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000723f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007245:	ba 05 00 00 00       	mov    edx,0x5
   14000724a:	48 89 c1             	mov    rcx,rax
   14000724d:	e8 a7 0c 00 00       	call   140007ef9 <__multadd_D2A>
   140007252:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007256:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000725a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000725e:	48 89 c1             	mov    rcx,rax
   140007261:	e8 77 13 00 00       	call   1400085dd <__cmp_D2A>
   140007266:	85 c0                	test   eax,eax
   140007268:	7f 23                	jg     14000728d <__gdtoa+0xf23>
   14000726a:	eb 07                	jmp    140007273 <__gdtoa+0xf09>
   14000726c:	90                   	nop
   14000726d:	eb 04                	jmp    140007273 <__gdtoa+0xf09>
   14000726f:	90                   	nop
   140007270:	eb 01                	jmp    140007273 <__gdtoa+0xf09>
   140007272:	90                   	nop
   140007273:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   140007279:	f7 d0                	not    eax
   14000727b:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   14000727e:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007285:	e9 87 05 00 00       	jmp    140007811 <__gdtoa+0x14a7>
   14000728a:	90                   	nop
   14000728b:	eb 01                	jmp    14000728e <__gdtoa+0xf24>
   14000728d:	90                   	nop
   14000728e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007295:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007299:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000729d:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400072a1:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400072a4:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400072a8:	e9 64 05 00 00       	jmp    140007811 <__gdtoa+0x14a7>
   1400072ad:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400072b1:	0f 84 14 04 00 00    	je     1400076cb <__gdtoa+0x1361>
   1400072b7:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   1400072bb:	7e 13                	jle    1400072d0 <__gdtoa+0xf66>
   1400072bd:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   1400072c0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072c4:	48 89 c1             	mov    rcx,rax
   1400072c7:	e8 84 11 00 00       	call   140008450 <__lshift_D2A>
   1400072cc:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072d0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072d4:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400072d8:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   1400072dc:	74 57                	je     140007335 <__gdtoa+0xfcb>
   1400072de:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072e2:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400072e5:	89 c1                	mov    ecx,eax
   1400072e7:	e8 41 0a 00 00       	call   140007d2d <__Balloc_D2A>
   1400072ec:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072f0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400072f4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400072f7:	48 98                	cdqe
   1400072f9:	48 83 c0 02          	add    rax,0x2
   1400072fd:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007304:	00 
   140007305:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007309:	48 8d 50 10          	lea    rdx,[rax+0x10]
   14000730d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007311:	48 83 c0 10          	add    rax,0x10
   140007315:	49 89 c8             	mov    r8,rcx
   140007318:	48 89 c1             	mov    rcx,rax
   14000731b:	e8 e8 23 00 00       	call   140009708 <memcpy>
   140007320:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007324:	ba 01 00 00 00       	mov    edx,0x1
   140007329:	48 89 c1             	mov    rcx,rax
   14000732c:	e8 1f 11 00 00       	call   140008450 <__lshift_D2A>
   140007331:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007335:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   14000733c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007340:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007344:	48 89 c1             	mov    rcx,rax
   140007347:	e8 62 ec ff ff       	call   140005fae <__quorem_D2A>
   14000734c:	83 c0 30             	add    eax,0x30
   14000734f:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007352:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007356:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000735a:	48 89 c1             	mov    rcx,rax
   14000735d:	e8 7b 12 00 00       	call   1400085dd <__cmp_D2A>
   140007362:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007365:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007369:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000736d:	48 89 c1             	mov    rcx,rax
   140007370:	e8 38 13 00 00       	call   1400086ad <__diff_D2A>
   140007375:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140007379:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   14000737d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140007380:	85 c0                	test   eax,eax
   140007382:	75 15                	jne    140007399 <__gdtoa+0x102f>
   140007384:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140007388:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000738c:	48 89 c1             	mov    rcx,rax
   14000738f:	e8 49 12 00 00       	call   1400085dd <__cmp_D2A>
   140007394:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007397:	eb 07                	jmp    1400073a0 <__gdtoa+0x1036>
   140007399:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   1400073a0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   1400073a4:	48 89 c1             	mov    rcx,rax
   1400073a7:	e8 c2 0a 00 00       	call   140007e6e <__Bfree_D2A>
   1400073ac:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400073b0:	75 70                	jne    140007422 <__gdtoa+0x10b8>
   1400073b2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400073b9:	75 67                	jne    140007422 <__gdtoa+0x10b8>
   1400073bb:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400073c2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400073c4:	83 e0 01             	and    eax,0x1
   1400073c7:	85 c0                	test   eax,eax
   1400073c9:	75 57                	jne    140007422 <__gdtoa+0x10b8>
   1400073cb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400073cf:	75 51                	jne    140007422 <__gdtoa+0x10b8>
   1400073d1:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400073d5:	0f 84 01 02 00 00    	je     1400075dc <__gdtoa+0x1272>
   1400073db:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073df:	7f 20                	jg     140007401 <__gdtoa+0x1097>
   1400073e1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073e5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400073e8:	83 f8 01             	cmp    eax,0x1
   1400073eb:	7f 0b                	jg     1400073f8 <__gdtoa+0x108e>
   1400073ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073f1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400073f4:	85 c0                	test   eax,eax
   1400073f6:	74 14                	je     14000740c <__gdtoa+0x10a2>
   1400073f8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400073ff:	eb 0b                	jmp    14000740c <__gdtoa+0x10a2>
   140007401:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   140007405:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   14000740c:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007410:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007414:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007418:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000741b:	88 10                	mov    BYTE PTR [rax],dl
   14000741d:	e9 ef 03 00 00       	jmp    140007811 <__gdtoa+0x14a7>
   140007422:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007426:	78 2b                	js     140007453 <__gdtoa+0x10e9>
   140007428:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000742c:	0f 85 96 01 00 00    	jne    1400075c8 <__gdtoa+0x125e>
   140007432:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007439:	0f 85 89 01 00 00    	jne    1400075c8 <__gdtoa+0x125e>
   14000743f:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007446:	8b 00                	mov    eax,DWORD PTR [rax]
   140007448:	83 e0 01             	and    eax,0x1
   14000744b:	85 c0                	test   eax,eax
   14000744d:	0f 85 75 01 00 00    	jne    1400075c8 <__gdtoa+0x125e>
   140007453:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007457:	0f 84 db 00 00 00    	je     140007538 <__gdtoa+0x11ce>
   14000745d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007461:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007464:	83 f8 01             	cmp    eax,0x1
   140007467:	7f 0f                	jg     140007478 <__gdtoa+0x110e>
   140007469:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000746d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007470:	85 c0                	test   eax,eax
   140007472:	0f 84 c0 00 00 00    	je     140007538 <__gdtoa+0x11ce>
   140007478:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   14000747c:	0f 85 83 00 00 00    	jne    140007505 <__gdtoa+0x119b>
   140007482:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007489:	e9 24 01 00 00       	jmp    1400075b2 <__gdtoa+0x1248>
   14000748e:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007492:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007496:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000749a:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000749d:	88 10                	mov    BYTE PTR [rax],dl
   14000749f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400074a3:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400074a9:	ba 0a 00 00 00       	mov    edx,0xa
   1400074ae:	48 89 c1             	mov    rcx,rax
   1400074b1:	e8 43 0a 00 00       	call   140007ef9 <__multadd_D2A>
   1400074b6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400074ba:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400074be:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400074c2:	75 08                	jne    1400074cc <__gdtoa+0x1162>
   1400074c4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400074c8:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400074cc:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400074d0:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400074d4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074d8:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400074de:	ba 0a 00 00 00       	mov    edx,0xa
   1400074e3:	48 89 c1             	mov    rcx,rax
   1400074e6:	e8 0e 0a 00 00       	call   140007ef9 <__multadd_D2A>
   1400074eb:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400074ef:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400074f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074f7:	48 89 c1             	mov    rcx,rax
   1400074fa:	e8 af ea ff ff       	call   140005fae <__quorem_D2A>
   1400074ff:	83 c0 30             	add    eax,0x30
   140007502:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007505:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007509:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000750d:	48 89 c1             	mov    rcx,rax
   140007510:	e8 c8 10 00 00       	call   1400085dd <__cmp_D2A>
   140007515:	85 c0                	test   eax,eax
   140007517:	0f 8f 71 ff ff ff    	jg     14000748e <__gdtoa+0x1124>
   14000751d:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007520:	8d 50 01             	lea    edx,[rax+0x1]
   140007523:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007526:	83 f8 39             	cmp    eax,0x39
   140007529:	0f 84 b0 00 00 00    	je     1400075df <__gdtoa+0x1275>
   14000752f:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007536:	eb 7a                	jmp    1400075b2 <__gdtoa+0x1248>
   140007538:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000753c:	7e 53                	jle    140007591 <__gdtoa+0x1227>
   14000753e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007542:	ba 01 00 00 00       	mov    edx,0x1
   140007547:	48 89 c1             	mov    rcx,rax
   14000754a:	e8 01 0f 00 00       	call   140008450 <__lshift_D2A>
   14000754f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007553:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007557:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000755b:	48 89 c1             	mov    rcx,rax
   14000755e:	e8 7a 10 00 00       	call   1400085dd <__cmp_D2A>
   140007563:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007566:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000756a:	7f 10                	jg     14000757c <__gdtoa+0x1212>
   14000756c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007570:	75 18                	jne    14000758a <__gdtoa+0x1220>
   140007572:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007575:	83 e0 01             	and    eax,0x1
   140007578:	85 c0                	test   eax,eax
   14000757a:	74 0e                	je     14000758a <__gdtoa+0x1220>
   14000757c:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000757f:	8d 50 01             	lea    edx,[rax+0x1]
   140007582:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007585:	83 f8 39             	cmp    eax,0x39
   140007588:	74 58                	je     1400075e2 <__gdtoa+0x1278>
   14000758a:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007591:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007595:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007598:	83 f8 01             	cmp    eax,0x1
   14000759b:	7f 0b                	jg     1400075a8 <__gdtoa+0x123e>
   14000759d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075a1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400075a4:	85 c0                	test   eax,eax
   1400075a6:	74 09                	je     1400075b1 <__gdtoa+0x1247>
   1400075a8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400075af:	eb 01                	jmp    1400075b2 <__gdtoa+0x1248>
   1400075b1:	90                   	nop
   1400075b2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075b6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075ba:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075be:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400075c1:	88 10                	mov    BYTE PTR [rax],dl
   1400075c3:	e9 49 02 00 00       	jmp    140007811 <__gdtoa+0x14a7>
   1400075c8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400075cc:	7e 52                	jle    140007620 <__gdtoa+0x12b6>
   1400075ce:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400075d2:	74 4c                	je     140007620 <__gdtoa+0x12b6>
   1400075d4:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400075d8:	75 24                	jne    1400075fe <__gdtoa+0x1294>
   1400075da:	eb 07                	jmp    1400075e3 <__gdtoa+0x1279>
   1400075dc:	90                   	nop
   1400075dd:	eb 04                	jmp    1400075e3 <__gdtoa+0x1279>
   1400075df:	90                   	nop
   1400075e0:	eb 01                	jmp    1400075e3 <__gdtoa+0x1279>
   1400075e2:	90                   	nop
   1400075e3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075e7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075eb:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075ef:	c6 00 39             	mov    BYTE PTR [rax],0x39
   1400075f2:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075f9:	e9 9d 01 00 00       	jmp    14000779b <__gdtoa+0x1431>
   1400075fe:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007605:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007608:	8d 48 01             	lea    ecx,[rax+0x1]
   14000760b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000760f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007613:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007617:	89 ca                	mov    edx,ecx
   140007619:	88 10                	mov    BYTE PTR [rax],dl
   14000761b:	e9 f1 01 00 00       	jmp    140007811 <__gdtoa+0x14a7>
   140007620:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007624:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007628:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000762c:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000762f:	88 10                	mov    BYTE PTR [rax],dl
   140007631:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007634:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140007637:	0f 84 ea 00 00 00    	je     140007727 <__gdtoa+0x13bd>
   14000763d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007641:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007647:	ba 0a 00 00 00       	mov    edx,0xa
   14000764c:	48 89 c1             	mov    rcx,rax
   14000764f:	e8 a5 08 00 00       	call   140007ef9 <__multadd_D2A>
   140007654:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007658:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000765c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007660:	75 25                	jne    140007687 <__gdtoa+0x131d>
   140007662:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007666:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000766c:	ba 0a 00 00 00       	mov    edx,0xa
   140007671:	48 89 c1             	mov    rcx,rax
   140007674:	e8 80 08 00 00       	call   140007ef9 <__multadd_D2A>
   140007679:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000767d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007681:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007685:	eb 36                	jmp    1400076bd <__gdtoa+0x1353>
   140007687:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000768b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007691:	ba 0a 00 00 00       	mov    edx,0xa
   140007696:	48 89 c1             	mov    rcx,rax
   140007699:	e8 5b 08 00 00       	call   140007ef9 <__multadd_D2A>
   14000769e:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400076a2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400076a6:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400076ac:	ba 0a 00 00 00       	mov    edx,0xa
   1400076b1:	48 89 c1             	mov    rcx,rax
   1400076b4:	e8 40 08 00 00       	call   140007ef9 <__multadd_D2A>
   1400076b9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400076bd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076c0:	83 c0 01             	add    eax,0x1
   1400076c3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400076c6:	e9 71 fc ff ff       	jmp    14000733c <__gdtoa+0xfd2>
   1400076cb:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400076d2:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400076d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076da:	48 89 c1             	mov    rcx,rax
   1400076dd:	e8 cc e8 ff ff       	call   140005fae <__quorem_D2A>
   1400076e2:	83 c0 30             	add    eax,0x30
   1400076e5:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400076e8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076ec:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076f0:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076f4:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400076f7:	88 10                	mov    BYTE PTR [rax],dl
   1400076f9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076fc:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   1400076ff:	7e 29                	jle    14000772a <__gdtoa+0x13c0>
   140007701:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007705:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000770b:	ba 0a 00 00 00       	mov    edx,0xa
   140007710:	48 89 c1             	mov    rcx,rax
   140007713:	e8 e1 07 00 00       	call   140007ef9 <__multadd_D2A>
   140007718:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000771c:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000771f:	83 c0 01             	add    eax,0x1
   140007722:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007725:	eb ab                	jmp    1400076d2 <__gdtoa+0x1368>
   140007727:	90                   	nop
   140007728:	eb 01                	jmp    14000772b <__gdtoa+0x13c1>
   14000772a:	90                   	nop
   14000772b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000772f:	74 26                	je     140007757 <__gdtoa+0x13ed>
   140007731:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007735:	0f 84 ae 00 00 00    	je     1400077e9 <__gdtoa+0x147f>
   14000773b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000773f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007742:	83 f8 01             	cmp    eax,0x1
   140007745:	7f 50                	jg     140007797 <__gdtoa+0x142d>
   140007747:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000774b:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000774e:	85 c0                	test   eax,eax
   140007750:	75 45                	jne    140007797 <__gdtoa+0x142d>
   140007752:	e9 92 00 00 00       	jmp    1400077e9 <__gdtoa+0x147f>
   140007757:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000775b:	ba 01 00 00 00       	mov    edx,0x1
   140007760:	48 89 c1             	mov    rcx,rax
   140007763:	e8 e8 0c 00 00       	call   140008450 <__lshift_D2A>
   140007768:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000776c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007770:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007774:	48 89 c1             	mov    rcx,rax
   140007777:	e8 61 0e 00 00       	call   1400085dd <__cmp_D2A>
   14000777c:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   14000777f:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007783:	7f 15                	jg     14000779a <__gdtoa+0x1430>
   140007785:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007789:	75 61                	jne    1400077ec <__gdtoa+0x1482>
   14000778b:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000778e:	83 e0 01             	and    eax,0x1
   140007791:	85 c0                	test   eax,eax
   140007793:	74 5a                	je     1400077ef <__gdtoa+0x1485>
   140007795:	eb 04                	jmp    14000779b <__gdtoa+0x1431>
   140007797:	90                   	nop
   140007798:	eb 01                	jmp    14000779b <__gdtoa+0x1431>
   14000779a:	90                   	nop
   14000779b:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400077a2:	eb 1f                	jmp    1400077c3 <__gdtoa+0x1459>
   1400077a4:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077a8:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400077ac:	75 15                	jne    1400077c3 <__gdtoa+0x1459>
   1400077ae:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400077b2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077b6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400077ba:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400077be:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400077c1:	eb 4e                	jmp    140007811 <__gdtoa+0x14a7>
   1400077c3:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   1400077c8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077cc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400077cf:	3c 39                	cmp    al,0x39
   1400077d1:	74 d1                	je     1400077a4 <__gdtoa+0x143a>
   1400077d3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077d7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400077db:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400077df:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   1400077e2:	83 c2 01             	add    edx,0x1
   1400077e5:	88 10                	mov    BYTE PTR [rax],dl
   1400077e7:	eb 28                	jmp    140007811 <__gdtoa+0x14a7>
   1400077e9:	90                   	nop
   1400077ea:	eb 04                	jmp    1400077f0 <__gdtoa+0x1486>
   1400077ec:	90                   	nop
   1400077ed:	eb 01                	jmp    1400077f0 <__gdtoa+0x1486>
   1400077ef:	90                   	nop
   1400077f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077f4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400077f7:	83 f8 01             	cmp    eax,0x1
   1400077fa:	7f 0b                	jg     140007807 <__gdtoa+0x149d>
   1400077fc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007800:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007803:	85 c0                	test   eax,eax
   140007805:	74 09                	je     140007810 <__gdtoa+0x14a6>
   140007807:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000780e:	eb 01                	jmp    140007811 <__gdtoa+0x14a7>
   140007810:	90                   	nop
   140007811:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007815:	48 89 c1             	mov    rcx,rax
   140007818:	e8 51 06 00 00       	call   140007e6e <__Bfree_D2A>
   14000781d:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140007822:	74 31                	je     140007855 <__gdtoa+0x14eb>
   140007824:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140007829:	74 16                	je     140007841 <__gdtoa+0x14d7>
   14000782b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000782f:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007833:	74 0c                	je     140007841 <__gdtoa+0x14d7>
   140007835:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007839:	48 89 c1             	mov    rcx,rax
   14000783c:	e8 2d 06 00 00       	call   140007e6e <__Bfree_D2A>
   140007841:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007845:	48 89 c1             	mov    rcx,rax
   140007848:	e8 21 06 00 00       	call   140007e6e <__Bfree_D2A>
   14000784d:	eb 0e                	jmp    14000785d <__gdtoa+0x14f3>
   14000784f:	90                   	nop
   140007850:	eb 0b                	jmp    14000785d <__gdtoa+0x14f3>
   140007852:	90                   	nop
   140007853:	eb 08                	jmp    14000785d <__gdtoa+0x14f3>
   140007855:	90                   	nop
   140007856:	eb 05                	jmp    14000785d <__gdtoa+0x14f3>
   140007858:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000785d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007861:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140007865:	73 0f                	jae    140007876 <__gdtoa+0x150c>
   140007867:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000786b:	48 83 e8 01          	sub    rax,0x1
   14000786f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140007872:	3c 30                	cmp    al,0x30
   140007874:	74 e2                	je     140007858 <__gdtoa+0x14ee>
   140007876:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000787a:	48 89 c1             	mov    rcx,rax
   14000787d:	e8 ec 05 00 00       	call   140007e6e <__Bfree_D2A>
   140007882:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007886:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140007889:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000788c:	8d 50 01             	lea    edx,[rax+0x1]
   14000788f:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140007896:	89 10                	mov    DWORD PTR [rax],edx
   140007898:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   14000789f:	00 
   1400078a0:	74 0e                	je     1400078b0 <__gdtoa+0x1546>
   1400078a2:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400078a9:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   1400078ad:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400078b0:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400078b7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400078b9:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   1400078bc:	89 c2                	mov    edx,eax
   1400078be:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400078c5:	89 10                	mov    DWORD PTR [rax],edx
   1400078c7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400078cb:	48 81 c4 00 01 00 00 	add    rsp,0x100
   1400078d2:	5d                   	pop    rbp
   1400078d3:	c3                   	ret
   1400078d4:	90                   	nop
   1400078d5:	90                   	nop
   1400078d6:	90                   	nop
   1400078d7:	90                   	nop
   1400078d8:	90                   	nop
   1400078d9:	90                   	nop
   1400078da:	90                   	nop
   1400078db:	90                   	nop
   1400078dc:	90                   	nop
   1400078dd:	90                   	nop
   1400078de:	90                   	nop
   1400078df:	90                   	nop

00000001400078e0 <__lo0bits_D2A>:
   1400078e0:	55                   	push   rbp
   1400078e1:	48 89 e5             	mov    rbp,rsp
   1400078e4:	48 83 ec 10          	sub    rsp,0x10
   1400078e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400078ec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078f0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400078f2:	f3 0f bc c0          	tzcnt  eax,eax
   1400078f6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400078f9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078fd:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078ff:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007902:	89 c1                	mov    ecx,eax
   140007904:	d3 ea                	shr    edx,cl
   140007906:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000790a:	89 10                	mov    DWORD PTR [rax],edx
   14000790c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000790f:	48 83 c4 10          	add    rsp,0x10
   140007913:	5d                   	pop    rbp
   140007914:	c3                   	ret

0000000140007915 <__rshift_D2A>:
   140007915:	55                   	push   rbp
   140007916:	48 89 e5             	mov    rbp,rsp
   140007919:	48 83 ec 20          	sub    rsp,0x20
   14000791d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007921:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007924:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007928:	48 83 c0 18          	add    rax,0x18
   14000792c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007930:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007934:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007938:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000793b:	c1 f8 05             	sar    eax,0x5
   14000793e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007941:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007945:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007948:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   14000794b:	0f 8d e4 00 00 00    	jge    140007a35 <__rshift_D2A+0x120>
   140007951:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007955:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007958:	48 98                	cdqe
   14000795a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007961:	00 
   140007962:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007966:	48 01 d0             	add    rax,rdx
   140007969:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000796d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007970:	48 98                	cdqe
   140007972:	48 c1 e0 02          	shl    rax,0x2
   140007976:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   14000797a:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000797e:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140007982:	0f 84 a3 00 00 00    	je     140007a2b <__rshift_D2A+0x116>
   140007988:	b8 20 00 00 00       	mov    eax,0x20
   14000798d:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   140007990:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007993:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007997:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000799b:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000799f:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079a1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400079a4:	89 c1                	mov    ecx,eax
   1400079a6:	d3 ea                	shr    edx,cl
   1400079a8:	89 d0                	mov    eax,edx
   1400079aa:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400079ad:	eb 3c                	jmp    1400079eb <__rshift_D2A+0xd6>
   1400079af:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079b3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079b5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400079b8:	89 c1                	mov    ecx,eax
   1400079ba:	d3 e2                	shl    edx,cl
   1400079bc:	89 d1                	mov    ecx,edx
   1400079be:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079c2:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400079c6:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400079ca:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   1400079cd:	89 ca                	mov    edx,ecx
   1400079cf:	89 10                	mov    DWORD PTR [rax],edx
   1400079d1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079d5:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400079d9:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400079dd:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079df:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400079e2:	89 c1                	mov    ecx,eax
   1400079e4:	d3 ea                	shr    edx,cl
   1400079e6:	89 d0                	mov    eax,edx
   1400079e8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400079eb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079ef:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   1400079f3:	72 ba                	jb     1400079af <__rshift_D2A+0x9a>
   1400079f5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079f9:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400079fc:	89 10                	mov    DWORD PTR [rax],edx
   1400079fe:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a02:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a04:	85 c0                	test   eax,eax
   140007a06:	74 2d                	je     140007a35 <__rshift_D2A+0x120>
   140007a08:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140007a0d:	eb 26                	jmp    140007a35 <__rshift_D2A+0x120>
   140007a0f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140007a13:	48 8d 42 04          	lea    rax,[rdx+0x4]
   140007a17:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a1b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a1f:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140007a23:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   140007a27:	8b 12                	mov    edx,DWORD PTR [rdx]
   140007a29:	89 10                	mov    DWORD PTR [rax],edx
   140007a2b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a2f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007a33:	72 da                	jb     140007a0f <__rshift_D2A+0xfa>
   140007a35:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a39:	48 83 c0 18          	add    rax,0x18
   140007a3d:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140007a41:	48 29 c2             	sub    rdx,rax
   140007a44:	48 89 d0             	mov    rax,rdx
   140007a47:	48 c1 f8 02          	sar    rax,0x2
   140007a4b:	89 c2                	mov    edx,eax
   140007a4d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a51:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007a54:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a58:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a5b:	85 c0                	test   eax,eax
   140007a5d:	75 0b                	jne    140007a6a <__rshift_D2A+0x155>
   140007a5f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a63:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   140007a6a:	90                   	nop
   140007a6b:	48 83 c4 20          	add    rsp,0x20
   140007a6f:	5d                   	pop    rbp
   140007a70:	c3                   	ret

0000000140007a71 <__trailz_D2A>:
   140007a71:	55                   	push   rbp
   140007a72:	48 89 e5             	mov    rbp,rsp
   140007a75:	48 83 ec 40          	sub    rsp,0x40
   140007a79:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007a7d:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a84:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a88:	48 83 c0 18          	add    rax,0x18
   140007a8c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a90:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a94:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a97:	48 98                	cdqe
   140007a99:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007aa0:	00 
   140007aa1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007aa5:	48 01 d0             	add    rax,rdx
   140007aa8:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007aac:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007ab3:	eb 09                	jmp    140007abe <__trailz_D2A+0x4d>
   140007ab5:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   140007ab9:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   140007abe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ac2:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007ac6:	73 0a                	jae    140007ad2 <__trailz_D2A+0x61>
   140007ac8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007acc:	8b 00                	mov    eax,DWORD PTR [rax]
   140007ace:	85 c0                	test   eax,eax
   140007ad0:	74 e3                	je     140007ab5 <__trailz_D2A+0x44>
   140007ad2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ad6:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007ada:	73 18                	jae    140007af4 <__trailz_D2A+0x83>
   140007adc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ae0:	8b 00                	mov    eax,DWORD PTR [rax]
   140007ae2:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007ae5:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007ae9:	48 89 c1             	mov    rcx,rax
   140007aec:	e8 ef fd ff ff       	call   1400078e0 <__lo0bits_D2A>
   140007af1:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007af4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007af7:	48 83 c4 40          	add    rsp,0x40
   140007afb:	5d                   	pop    rbp
   140007afc:	c3                   	ret
   140007afd:	90                   	nop
   140007afe:	90                   	nop
   140007aff:	90                   	nop

0000000140007b00 <dtoa_lock_cleanup>:
   140007b00:	55                   	push   rbp
   140007b01:	48 89 e5             	mov    rbp,rsp
   140007b04:	48 83 ec 40          	sub    rsp,0x40
   140007b08:	48 8d 05 e1 76 00 00 	lea    rax,[rip+0x76e1]        # 14000f1f0 <dtoa_CS_init>
   140007b0f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007b13:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007b1a:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007b1d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007b21:	87 10                	xchg   DWORD PTR [rax],edx
   140007b23:	89 d0                	mov    eax,edx
   140007b25:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007b28:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007b2c:	75 3d                	jne    140007b6b <dtoa_lock_cleanup+0x6b>
   140007b2e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007b35:	eb 2e                	jmp    140007b65 <dtoa_lock_cleanup+0x65>
   140007b37:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007b3a:	48 63 d0             	movsxd rdx,eax
   140007b3d:	48 89 d0             	mov    rax,rdx
   140007b40:	48 c1 e0 02          	shl    rax,0x2
   140007b44:	48 01 d0             	add    rax,rdx
   140007b47:	48 c1 e0 03          	shl    rax,0x3
   140007b4b:	48 8d 15 4e 76 00 00 	lea    rdx,[rip+0x764e]        # 14000f1a0 <dtoa_CritSec>
   140007b52:	48 01 d0             	add    rax,rdx
   140007b55:	48 89 c1             	mov    rcx,rax
   140007b58:	48 8b 05 89 86 00 00 	mov    rax,QWORD PTR [rip+0x8689]        # 1400101e8 <__IAT_start__>
   140007b5f:	ff d0                	call   rax
   140007b61:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b65:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b69:	7e cc                	jle    140007b37 <dtoa_lock_cleanup+0x37>
   140007b6b:	90                   	nop
   140007b6c:	48 83 c4 40          	add    rsp,0x40
   140007b70:	5d                   	pop    rbp
   140007b71:	c3                   	ret

0000000140007b72 <dtoa_lock>:
   140007b72:	55                   	push   rbp
   140007b73:	48 89 e5             	mov    rbp,rsp
   140007b76:	48 83 ec 40          	sub    rsp,0x40
   140007b7a:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007b7d:	8b 05 6d 76 00 00    	mov    eax,DWORD PTR [rip+0x766d]        # 14000f1f0 <dtoa_CS_init>
   140007b83:	83 f8 02             	cmp    eax,0x2
   140007b86:	75 2c                	jne    140007bb4 <dtoa_lock+0x42>
   140007b88:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007b8b:	48 89 d0             	mov    rax,rdx
   140007b8e:	48 c1 e0 02          	shl    rax,0x2
   140007b92:	48 01 d0             	add    rax,rdx
   140007b95:	48 c1 e0 03          	shl    rax,0x3
   140007b99:	48 8d 15 00 76 00 00 	lea    rdx,[rip+0x7600]        # 14000f1a0 <dtoa_CritSec>
   140007ba0:	48 01 d0             	add    rax,rdx
   140007ba3:	48 89 c1             	mov    rcx,rax
   140007ba6:	48 8b 05 43 86 00 00 	mov    rax,QWORD PTR [rip+0x8643]        # 1400101f0 <__imp_EnterCriticalSection>
   140007bad:	ff d0                	call   rax
   140007baf:	e9 ea 00 00 00       	jmp    140007c9e <dtoa_lock+0x12c>
   140007bb4:	8b 05 36 76 00 00    	mov    eax,DWORD PTR [rip+0x7636]        # 14000f1f0 <dtoa_CS_init>
   140007bba:	85 c0                	test   eax,eax
   140007bbc:	0f 85 9e 00 00 00    	jne    140007c60 <dtoa_lock+0xee>
   140007bc2:	48 8d 05 27 76 00 00 	lea    rax,[rip+0x7627]        # 14000f1f0 <dtoa_CS_init>
   140007bc9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007bcd:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007bd4:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007bd7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007bdb:	87 10                	xchg   DWORD PTR [rax],edx
   140007bdd:	89 d0                	mov    eax,edx
   140007bdf:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007be2:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007be6:	75 58                	jne    140007c40 <dtoa_lock+0xce>
   140007be8:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007bef:	eb 2e                	jmp    140007c1f <dtoa_lock+0xad>
   140007bf1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007bf4:	48 63 d0             	movsxd rdx,eax
   140007bf7:	48 89 d0             	mov    rax,rdx
   140007bfa:	48 c1 e0 02          	shl    rax,0x2
   140007bfe:	48 01 d0             	add    rax,rdx
   140007c01:	48 c1 e0 03          	shl    rax,0x3
   140007c05:	48 8d 15 94 75 00 00 	lea    rdx,[rip+0x7594]        # 14000f1a0 <dtoa_CritSec>
   140007c0c:	48 01 d0             	add    rax,rdx
   140007c0f:	48 89 c1             	mov    rcx,rax
   140007c12:	48 8b 05 07 86 00 00 	mov    rax,QWORD PTR [rip+0x8607]        # 140010220 <__imp_InitializeCriticalSection>
   140007c19:	ff d0                	call   rax
   140007c1b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007c1f:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007c23:	7e cc                	jle    140007bf1 <dtoa_lock+0x7f>
   140007c25:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007b00 <dtoa_lock_cleanup>
   140007c2c:	48 89 c1             	mov    rcx,rax
   140007c2f:	e8 fb 99 ff ff       	call   14000162f <atexit>
   140007c34:	c7 05 b2 75 00 00 02 	mov    DWORD PTR [rip+0x75b2],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c3b:	00 00 00 
   140007c3e:	eb 20                	jmp    140007c60 <dtoa_lock+0xee>
   140007c40:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007c44:	75 1a                	jne    140007c60 <dtoa_lock+0xee>
   140007c46:	c7 05 a0 75 00 00 02 	mov    DWORD PTR [rip+0x75a0],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c4d:	00 00 00 
   140007c50:	eb 0e                	jmp    140007c60 <dtoa_lock+0xee>
   140007c52:	b9 01 00 00 00       	mov    ecx,0x1
   140007c57:	48 8b 05 ea 85 00 00 	mov    rax,QWORD PTR [rip+0x85ea]        # 140010248 <__imp_Sleep>
   140007c5e:	ff d0                	call   rax
   140007c60:	8b 05 8a 75 00 00    	mov    eax,DWORD PTR [rip+0x758a]        # 14000f1f0 <dtoa_CS_init>
   140007c66:	83 f8 01             	cmp    eax,0x1
   140007c69:	74 e7                	je     140007c52 <dtoa_lock+0xe0>
   140007c6b:	8b 05 7f 75 00 00    	mov    eax,DWORD PTR [rip+0x757f]        # 14000f1f0 <dtoa_CS_init>
   140007c71:	83 f8 02             	cmp    eax,0x2
   140007c74:	75 28                	jne    140007c9e <dtoa_lock+0x12c>
   140007c76:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c79:	48 89 d0             	mov    rax,rdx
   140007c7c:	48 c1 e0 02          	shl    rax,0x2
   140007c80:	48 01 d0             	add    rax,rdx
   140007c83:	48 c1 e0 03          	shl    rax,0x3
   140007c87:	48 8d 15 12 75 00 00 	lea    rdx,[rip+0x7512]        # 14000f1a0 <dtoa_CritSec>
   140007c8e:	48 01 d0             	add    rax,rdx
   140007c91:	48 89 c1             	mov    rcx,rax
   140007c94:	48 8b 05 55 85 00 00 	mov    rax,QWORD PTR [rip+0x8555]        # 1400101f0 <__imp_EnterCriticalSection>
   140007c9b:	ff d0                	call   rax
   140007c9d:	90                   	nop
   140007c9e:	48 83 c4 40          	add    rsp,0x40
   140007ca2:	5d                   	pop    rbp
   140007ca3:	c3                   	ret

0000000140007ca4 <dtoa_unlock>:
   140007ca4:	55                   	push   rbp
   140007ca5:	48 89 e5             	mov    rbp,rsp
   140007ca8:	48 83 ec 20          	sub    rsp,0x20
   140007cac:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007caf:	8b 05 3b 75 00 00    	mov    eax,DWORD PTR [rip+0x753b]        # 14000f1f0 <dtoa_CS_init>
   140007cb5:	83 f8 02             	cmp    eax,0x2
   140007cb8:	75 27                	jne    140007ce1 <dtoa_unlock+0x3d>
   140007cba:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007cbd:	48 89 d0             	mov    rax,rdx
   140007cc0:	48 c1 e0 02          	shl    rax,0x2
   140007cc4:	48 01 d0             	add    rax,rdx
   140007cc7:	48 c1 e0 03          	shl    rax,0x3
   140007ccb:	48 8d 15 ce 74 00 00 	lea    rdx,[rip+0x74ce]        # 14000f1a0 <dtoa_CritSec>
   140007cd2:	48 01 d0             	add    rax,rdx
   140007cd5:	48 89 c1             	mov    rcx,rax
   140007cd8:	48 8b 05 49 85 00 00 	mov    rax,QWORD PTR [rip+0x8549]        # 140010228 <__imp_LeaveCriticalSection>
   140007cdf:	ff d0                	call   rax
   140007ce1:	90                   	nop
   140007ce2:	48 83 c4 20          	add    rsp,0x20
   140007ce6:	5d                   	pop    rbp
   140007ce7:	c3                   	ret

0000000140007ce8 <__lo0bits_D2A>:
   140007ce8:	55                   	push   rbp
   140007ce9:	48 89 e5             	mov    rbp,rsp
   140007cec:	48 83 ec 10          	sub    rsp,0x10
   140007cf0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007cf4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007cf8:	8b 00                	mov    eax,DWORD PTR [rax]
   140007cfa:	f3 0f bc c0          	tzcnt  eax,eax
   140007cfe:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007d01:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d05:	8b 10                	mov    edx,DWORD PTR [rax]
   140007d07:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007d0a:	89 c1                	mov    ecx,eax
   140007d0c:	d3 ea                	shr    edx,cl
   140007d0e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d12:	89 10                	mov    DWORD PTR [rax],edx
   140007d14:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007d17:	48 83 c4 10          	add    rsp,0x10
   140007d1b:	5d                   	pop    rbp
   140007d1c:	c3                   	ret

0000000140007d1d <__hi0bits_D2A>:
   140007d1d:	55                   	push   rbp
   140007d1e:	48 89 e5             	mov    rbp,rsp
   140007d21:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007d24:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007d28:	83 f0 1f             	xor    eax,0x1f
   140007d2b:	5d                   	pop    rbp
   140007d2c:	c3                   	ret

0000000140007d2d <__Balloc_D2A>:
   140007d2d:	55                   	push   rbp
   140007d2e:	48 89 e5             	mov    rbp,rsp
   140007d31:	48 83 ec 30          	sub    rsp,0x30
   140007d35:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007d38:	b9 00 00 00 00       	mov    ecx,0x0
   140007d3d:	e8 30 fe ff ff       	call   140007b72 <dtoa_lock>
   140007d42:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d46:	7f 48                	jg     140007d90 <__Balloc_D2A+0x63>
   140007d48:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d4b:	48 98                	cdqe
   140007d4d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007d54:	00 
   140007d55:	48 8d 05 a4 74 00 00 	lea    rax,[rip+0x74a4]        # 14000f200 <freelist>
   140007d5c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007d60:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d64:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d69:	74 25                	je     140007d90 <__Balloc_D2A+0x63>
   140007d6b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d6f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007d72:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d75:	48 63 d2             	movsxd rdx,edx
   140007d78:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007d7f:	00 
   140007d80:	48 8d 15 79 74 00 00 	lea    rdx,[rip+0x7479]        # 14000f200 <freelist>
   140007d87:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007d8b:	e9 b1 00 00 00       	jmp    140007e41 <__Balloc_D2A+0x114>
   140007d90:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d93:	ba 01 00 00 00       	mov    edx,0x1
   140007d98:	89 c1                	mov    ecx,eax
   140007d9a:	d3 e2                	shl    edx,cl
   140007d9c:	89 d0                	mov    eax,edx
   140007d9e:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007da1:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007da4:	83 e8 01             	sub    eax,0x1
   140007da7:	48 98                	cdqe
   140007da9:	48 c1 e0 02          	shl    rax,0x2
   140007dad:	48 83 c0 27          	add    rax,0x27
   140007db1:	48 c1 e8 03          	shr    rax,0x3
   140007db5:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007db8:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007dbc:	7f 4e                	jg     140007e0c <__Balloc_D2A+0xdf>
   140007dbe:	48 8b 15 cb 22 00 00 	mov    rdx,QWORD PTR [rip+0x22cb]        # 14000a090 <pmem_next>
   140007dc5:	48 8d 05 94 74 00 00 	lea    rax,[rip+0x7494]        # 14000f260 <private_mem>
   140007dcc:	48 29 c2             	sub    rdx,rax
   140007dcf:	48 89 d0             	mov    rax,rdx
   140007dd2:	48 c1 f8 03          	sar    rax,0x3
   140007dd6:	48 89 c2             	mov    rdx,rax
   140007dd9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007ddc:	48 01 d0             	add    rax,rdx
   140007ddf:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007de5:	77 25                	ja     140007e0c <__Balloc_D2A+0xdf>
   140007de7:	48 8b 05 a2 22 00 00 	mov    rax,QWORD PTR [rip+0x22a2]        # 14000a090 <pmem_next>
   140007dee:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007df2:	48 8b 05 97 22 00 00 	mov    rax,QWORD PTR [rip+0x2297]        # 14000a090 <pmem_next>
   140007df9:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007dfc:	48 c1 e2 03          	shl    rdx,0x3
   140007e00:	48 01 d0             	add    rax,rdx
   140007e03:	48 89 05 86 22 00 00 	mov    QWORD PTR [rip+0x2286],rax        # 14000a090 <pmem_next>
   140007e0a:	eb 21                	jmp    140007e2d <__Balloc_D2A+0x100>
   140007e0c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007e0f:	48 c1 e0 03          	shl    rax,0x3
   140007e13:	48 89 c1             	mov    rcx,rax
   140007e16:	e8 e5 18 00 00       	call   140009700 <malloc>
   140007e1b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007e1f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007e24:	75 07                	jne    140007e2d <__Balloc_D2A+0x100>
   140007e26:	b8 00 00 00 00       	mov    eax,0x0
   140007e2b:	eb 3b                	jmp    140007e68 <__Balloc_D2A+0x13b>
   140007e2d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e31:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007e34:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007e37:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e3b:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007e3e:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007e41:	b9 00 00 00 00       	mov    ecx,0x0
   140007e46:	e8 59 fe ff ff       	call   140007ca4 <dtoa_unlock>
   140007e4b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e4f:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007e56:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e5a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007e5d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e61:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007e64:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e68:	48 83 c4 30          	add    rsp,0x30
   140007e6c:	5d                   	pop    rbp
   140007e6d:	c3                   	ret

0000000140007e6e <__Bfree_D2A>:
   140007e6e:	55                   	push   rbp
   140007e6f:	48 89 e5             	mov    rbp,rsp
   140007e72:	48 83 ec 20          	sub    rsp,0x20
   140007e76:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e7a:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007e7f:	74 71                	je     140007ef2 <__Bfree_D2A+0x84>
   140007e81:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e85:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e88:	83 f8 09             	cmp    eax,0x9
   140007e8b:	7e 0e                	jle    140007e9b <__Bfree_D2A+0x2d>
   140007e8d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e91:	48 89 c1             	mov    rcx,rax
   140007e94:	e8 57 18 00 00       	call   1400096f0 <free>
   140007e99:	eb 57                	jmp    140007ef2 <__Bfree_D2A+0x84>
   140007e9b:	b9 00 00 00 00       	mov    ecx,0x0
   140007ea0:	e8 cd fc ff ff       	call   140007b72 <dtoa_lock>
   140007ea5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ea9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007eac:	48 98                	cdqe
   140007eae:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007eb5:	00 
   140007eb6:	48 8d 05 43 73 00 00 	lea    rax,[rip+0x7343]        # 14000f200 <freelist>
   140007ebd:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007ec1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ec5:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007ec8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ecc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007ecf:	48 98                	cdqe
   140007ed1:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007ed8:	00 
   140007ed9:	48 8d 15 20 73 00 00 	lea    rdx,[rip+0x7320]        # 14000f200 <freelist>
   140007ee0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ee4:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007ee8:	b9 00 00 00 00       	mov    ecx,0x0
   140007eed:	e8 b2 fd ff ff       	call   140007ca4 <dtoa_unlock>
   140007ef2:	90                   	nop
   140007ef3:	48 83 c4 20          	add    rsp,0x20
   140007ef7:	5d                   	pop    rbp
   140007ef8:	c3                   	ret

0000000140007ef9 <__multadd_D2A>:
   140007ef9:	55                   	push   rbp
   140007efa:	48 89 e5             	mov    rbp,rsp
   140007efd:	48 83 ec 50          	sub    rsp,0x50
   140007f01:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007f05:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007f08:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007f0c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f10:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f13:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007f16:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f1a:	48 83 c0 18          	add    rax,0x18
   140007f1e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007f22:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007f29:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007f2c:	48 98                	cdqe
   140007f2e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f32:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f36:	8b 00                	mov    eax,DWORD PTR [rax]
   140007f38:	89 c2                	mov    edx,eax
   140007f3a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007f3d:	48 98                	cdqe
   140007f3f:	48 0f af d0          	imul   rdx,rax
   140007f43:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007f47:	48 01 d0             	add    rax,rdx
   140007f4a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007f4e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007f52:	48 c1 e8 20          	shr    rax,0x20
   140007f56:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f5e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007f62:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007f66:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007f6a:	89 10                	mov    DWORD PTR [rax],edx
   140007f6c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007f70:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007f73:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007f76:	7c ba                	jl     140007f32 <__multadd_D2A+0x39>
   140007f78:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007f7d:	0f 84 9a 00 00 00    	je     14000801d <__multadd_D2A+0x124>
   140007f83:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f87:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007f8a:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007f8d:	7c 67                	jl     140007ff6 <__multadd_D2A+0xfd>
   140007f8f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f93:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007f96:	83 c0 01             	add    eax,0x1
   140007f99:	89 c1                	mov    ecx,eax
   140007f9b:	e8 8d fd ff ff       	call   140007d2d <__Balloc_D2A>
   140007fa0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007fa4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007fa9:	75 07                	jne    140007fb2 <__multadd_D2A+0xb9>
   140007fab:	b8 00 00 00 00       	mov    eax,0x0
   140007fb0:	eb 6f                	jmp    140008021 <__multadd_D2A+0x128>
   140007fb2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fb6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fb9:	48 98                	cdqe
   140007fbb:	48 83 c0 02          	add    rax,0x2
   140007fbf:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007fc6:	00 
   140007fc7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fcb:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007fcf:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007fd3:	48 83 c0 10          	add    rax,0x10
   140007fd7:	49 89 c8             	mov    r8,rcx
   140007fda:	48 89 c1             	mov    rcx,rax
   140007fdd:	e8 26 17 00 00       	call   140009708 <memcpy>
   140007fe2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fe6:	48 89 c1             	mov    rcx,rax
   140007fe9:	e8 80 fe ff ff       	call   140007e6e <__Bfree_D2A>
   140007fee:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007ff2:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007ff6:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007ff9:	8d 50 01             	lea    edx,[rax+0x1]
   140007ffc:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007fff:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008003:	89 d1                	mov    ecx,edx
   140008005:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008009:	48 98                	cdqe
   14000800b:	48 83 c0 04          	add    rax,0x4
   14000800f:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140008013:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008017:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000801a:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000801d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008021:	48 83 c4 50          	add    rsp,0x50
   140008025:	5d                   	pop    rbp
   140008026:	c3                   	ret

0000000140008027 <__i2b_D2A>:
   140008027:	55                   	push   rbp
   140008028:	48 89 e5             	mov    rbp,rsp
   14000802b:	48 83 ec 30          	sub    rsp,0x30
   14000802f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008032:	b9 01 00 00 00       	mov    ecx,0x1
   140008037:	e8 f1 fc ff ff       	call   140007d2d <__Balloc_D2A>
   14000803c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008040:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008045:	75 07                	jne    14000804e <__i2b_D2A+0x27>
   140008047:	b8 00 00 00 00       	mov    eax,0x0
   14000804c:	eb 19                	jmp    140008067 <__i2b_D2A+0x40>
   14000804e:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008051:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008055:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008058:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000805c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008063:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008067:	48 83 c4 30          	add    rsp,0x30
   14000806b:	5d                   	pop    rbp
   14000806c:	c3                   	ret

000000014000806d <__mult_D2A>:
   14000806d:	55                   	push   rbp
   14000806e:	48 89 e5             	mov    rbp,rsp
   140008071:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140008078:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000807c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008080:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008084:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008087:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000808b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000808e:	39 c2                	cmp    edx,eax
   140008090:	7d 18                	jge    1400080aa <__mult_D2A+0x3d>
   140008092:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008096:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000809a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000809e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400080a2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400080a6:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400080aa:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080ae:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400080b1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400080b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080b8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400080bb:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400080be:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080c2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400080c5:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   1400080c8:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   1400080cb:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   1400080ce:	01 d0                	add    eax,edx
   1400080d0:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400080d3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080d7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400080da:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   1400080dd:	7e 04                	jle    1400080e3 <__mult_D2A+0x76>
   1400080df:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400080e3:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400080e6:	89 c1                	mov    ecx,eax
   1400080e8:	e8 40 fc ff ff       	call   140007d2d <__Balloc_D2A>
   1400080ed:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400080f1:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   1400080f6:	75 0a                	jne    140008102 <__mult_D2A+0x95>
   1400080f8:	b8 00 00 00 00       	mov    eax,0x0
   1400080fd:	e9 88 01 00 00       	jmp    14000828a <__mult_D2A+0x21d>
   140008102:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008106:	48 83 c0 18          	add    rax,0x18
   14000810a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000810e:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008111:	48 98                	cdqe
   140008113:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000811a:	00 
   14000811b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000811f:	48 01 d0             	add    rax,rdx
   140008122:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140008126:	eb 0f                	jmp    140008137 <__mult_D2A+0xca>
   140008128:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000812c:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008132:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140008137:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000813b:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   14000813f:	72 e7                	jb     140008128 <__mult_D2A+0xbb>
   140008141:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008145:	48 83 c0 18          	add    rax,0x18
   140008149:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000814d:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008150:	48 98                	cdqe
   140008152:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008159:	00 
   14000815a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000815e:	48 01 d0             	add    rax,rdx
   140008161:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008165:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008169:	48 83 c0 18          	add    rax,0x18
   14000816d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008171:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140008174:	48 98                	cdqe
   140008176:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000817d:	00 
   14000817e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008182:	48 01 d0             	add    rax,rdx
   140008185:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   140008189:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000818d:	48 83 c0 18          	add    rax,0x18
   140008191:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008195:	e9 95 00 00 00       	jmp    14000822f <__mult_D2A+0x1c2>
   14000819a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000819e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081a2:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400081a6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081a8:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   1400081ab:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   1400081af:	74 79                	je     14000822a <__mult_D2A+0x1bd>
   1400081b1:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400081b5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400081b9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400081bd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400081c1:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400081c8:	00 
   1400081c9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400081cd:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081d1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400081d5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081d7:	89 c2                	mov    edx,eax
   1400081d9:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   1400081dc:	48 0f af d0          	imul   rdx,rax
   1400081e0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081e4:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081e6:	89 c0                	mov    eax,eax
   1400081e8:	48 01 c2             	add    rdx,rax
   1400081eb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400081ef:	48 01 d0             	add    rax,rdx
   1400081f2:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   1400081f6:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   1400081fa:	48 c1 e8 20          	shr    rax,0x20
   1400081fe:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008202:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008206:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000820a:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000820e:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140008212:	89 10                	mov    DWORD PTR [rax],edx
   140008214:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008218:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   14000821c:	72 ab                	jb     1400081c9 <__mult_D2A+0x15c>
   14000821e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008222:	89 c2                	mov    edx,eax
   140008224:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008228:	89 10                	mov    DWORD PTR [rax],edx
   14000822a:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   14000822f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008233:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   140008237:	0f 82 5d ff ff ff    	jb     14000819a <__mult_D2A+0x12d>
   14000823d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008241:	48 83 c0 18          	add    rax,0x18
   140008245:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008249:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000824c:	48 98                	cdqe
   14000824e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008255:	00 
   140008256:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000825a:	48 01 d0             	add    rax,rdx
   14000825d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008261:	eb 04                	jmp    140008267 <__mult_D2A+0x1fa>
   140008263:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008267:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000826b:	7e 0f                	jle    14000827c <__mult_D2A+0x20f>
   14000826d:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008272:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008276:	8b 00                	mov    eax,DWORD PTR [rax]
   140008278:	85 c0                	test   eax,eax
   14000827a:	74 e7                	je     140008263 <__mult_D2A+0x1f6>
   14000827c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008280:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008283:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008286:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000828a:	48 81 c4 90 00 00 00 	add    rsp,0x90
   140008291:	5d                   	pop    rbp
   140008292:	c3                   	ret

0000000140008293 <__pow5mult_D2A>:
   140008293:	55                   	push   rbp
   140008294:	48 89 e5             	mov    rbp,rsp
   140008297:	48 83 ec 40          	sub    rsp,0x40
   14000829b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000829f:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400082a2:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400082a5:	83 e0 03             	and    eax,0x3
   1400082a8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400082ab:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400082af:	74 41                	je     1400082f2 <__pow5mult_D2A+0x5f>
   1400082b1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400082b4:	83 e8 01             	sub    eax,0x1
   1400082b7:	48 98                	cdqe
   1400082b9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400082c0:	00 
   1400082c1:	48 8d 05 d0 1d 00 00 	lea    rax,[rip+0x1dd0]        # 14000a098 <p05.0>
   1400082c8:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   1400082cb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082cf:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400082d5:	48 89 c1             	mov    rcx,rax
   1400082d8:	e8 1c fc ff ff       	call   140007ef9 <__multadd_D2A>
   1400082dd:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400082e1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400082e6:	75 0a                	jne    1400082f2 <__pow5mult_D2A+0x5f>
   1400082e8:	b8 00 00 00 00       	mov    eax,0x0
   1400082ed:	e9 58 01 00 00       	jmp    14000844a <__pow5mult_D2A+0x1b7>
   1400082f2:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   1400082f6:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400082fa:	75 09                	jne    140008305 <__pow5mult_D2A+0x72>
   1400082fc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008300:	e9 45 01 00 00       	jmp    14000844a <__pow5mult_D2A+0x1b7>
   140008305:	48 8b 05 54 78 00 00 	mov    rax,QWORD PTR [rip+0x7854]        # 14000fb60 <p5s>
   14000830c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008310:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008315:	75 5e                	jne    140008375 <__pow5mult_D2A+0xe2>
   140008317:	b9 01 00 00 00       	mov    ecx,0x1
   14000831c:	e8 51 f8 ff ff       	call   140007b72 <dtoa_lock>
   140008321:	48 8b 05 38 78 00 00 	mov    rax,QWORD PTR [rip+0x7838]        # 14000fb60 <p5s>
   140008328:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000832c:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008331:	75 38                	jne    14000836b <__pow5mult_D2A+0xd8>
   140008333:	b9 71 02 00 00       	mov    ecx,0x271
   140008338:	e8 ea fc ff ff       	call   140008027 <__i2b_D2A>
   14000833d:	48 89 05 1c 78 00 00 	mov    QWORD PTR [rip+0x781c],rax        # 14000fb60 <p5s>
   140008344:	48 8b 05 15 78 00 00 	mov    rax,QWORD PTR [rip+0x7815]        # 14000fb60 <p5s>
   14000834b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000834f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008354:	75 0a                	jne    140008360 <__pow5mult_D2A+0xcd>
   140008356:	b8 00 00 00 00       	mov    eax,0x0
   14000835b:	e9 ea 00 00 00       	jmp    14000844a <__pow5mult_D2A+0x1b7>
   140008360:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008364:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000836b:	b9 01 00 00 00       	mov    ecx,0x1
   140008370:	e8 2f f9 ff ff       	call   140007ca4 <dtoa_unlock>
   140008375:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008378:	83 e0 01             	and    eax,0x1
   14000837b:	85 c0                	test   eax,eax
   14000837d:	74 39                	je     1400083b8 <__pow5mult_D2A+0x125>
   14000837f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008383:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008387:	48 89 c1             	mov    rcx,rax
   14000838a:	e8 de fc ff ff       	call   14000806d <__mult_D2A>
   14000838f:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008393:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   140008398:	75 0a                	jne    1400083a4 <__pow5mult_D2A+0x111>
   14000839a:	b8 00 00 00 00       	mov    eax,0x0
   14000839f:	e9 a6 00 00 00       	jmp    14000844a <__pow5mult_D2A+0x1b7>
   1400083a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083a8:	48 89 c1             	mov    rcx,rax
   1400083ab:	e8 be fa ff ff       	call   140007e6e <__Bfree_D2A>
   1400083b0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400083b4:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400083b8:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   1400083bb:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400083bf:	0f 84 80 00 00 00    	je     140008445 <__pow5mult_D2A+0x1b2>
   1400083c5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083c9:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083cc:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083d0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083d5:	75 61                	jne    140008438 <__pow5mult_D2A+0x1a5>
   1400083d7:	b9 01 00 00 00       	mov    ecx,0x1
   1400083dc:	e8 91 f7 ff ff       	call   140007b72 <dtoa_lock>
   1400083e1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083e5:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083e8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083ec:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083f1:	75 3b                	jne    14000842e <__pow5mult_D2A+0x19b>
   1400083f3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083f7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083fb:	48 89 c1             	mov    rcx,rax
   1400083fe:	e8 6a fc ff ff       	call   14000806d <__mult_D2A>
   140008403:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008407:	48 89 02             	mov    QWORD PTR [rdx],rax
   14000840a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000840e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008411:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008415:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000841a:	75 07                	jne    140008423 <__pow5mult_D2A+0x190>
   14000841c:	b8 00 00 00 00       	mov    eax,0x0
   140008421:	eb 27                	jmp    14000844a <__pow5mult_D2A+0x1b7>
   140008423:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008427:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000842e:	b9 01 00 00 00       	mov    ecx,0x1
   140008433:	e8 6c f8 ff ff       	call   140007ca4 <dtoa_unlock>
   140008438:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000843c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008440:	e9 30 ff ff ff       	jmp    140008375 <__pow5mult_D2A+0xe2>
   140008445:	90                   	nop
   140008446:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000844a:	48 83 c4 40          	add    rsp,0x40
   14000844e:	5d                   	pop    rbp
   14000844f:	c3                   	ret

0000000140008450 <__lshift_D2A>:
   140008450:	55                   	push   rbp
   140008451:	48 89 e5             	mov    rbp,rsp
   140008454:	48 83 ec 60          	sub    rsp,0x60
   140008458:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000845c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000845f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008462:	c1 f8 05             	sar    eax,0x5
   140008465:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   140008468:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000846c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000846f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008472:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008476:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008479:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   14000847c:	01 d0                	add    eax,edx
   14000847e:	83 c0 01             	add    eax,0x1
   140008481:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008484:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008488:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000848b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000848e:	eb 07                	jmp    140008497 <__lshift_D2A+0x47>
   140008490:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140008494:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140008497:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000849a:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   14000849d:	7f f1                	jg     140008490 <__lshift_D2A+0x40>
   14000849f:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400084a2:	89 c1                	mov    ecx,eax
   1400084a4:	e8 84 f8 ff ff       	call   140007d2d <__Balloc_D2A>
   1400084a9:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400084ad:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400084b2:	75 0a                	jne    1400084be <__lshift_D2A+0x6e>
   1400084b4:	b8 00 00 00 00       	mov    eax,0x0
   1400084b9:	e9 19 01 00 00       	jmp    1400085d7 <__lshift_D2A+0x187>
   1400084be:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400084c2:	48 83 c0 18          	add    rax,0x18
   1400084c6:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400084ca:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400084d1:	eb 16                	jmp    1400084e9 <__lshift_D2A+0x99>
   1400084d3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084d7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400084db:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400084df:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400084e5:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400084e9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400084ec:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   1400084ef:	7c e2                	jl     1400084d3 <__lshift_D2A+0x83>
   1400084f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084f5:	48 83 c0 18          	add    rax,0x18
   1400084f9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400084fd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008501:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008504:	48 98                	cdqe
   140008506:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000850d:	00 
   14000850e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008512:	48 01 d0             	add    rax,rdx
   140008515:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008519:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000851d:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140008521:	74 71                	je     140008594 <__lshift_D2A+0x144>
   140008523:	b8 20 00 00 00       	mov    eax,0x20
   140008528:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000852b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000852e:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   140008535:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008539:	8b 10                	mov    edx,DWORD PTR [rax]
   14000853b:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000853e:	89 c1                	mov    ecx,eax
   140008540:	d3 e2                	shl    edx,cl
   140008542:	89 d1                	mov    ecx,edx
   140008544:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008548:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000854c:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008550:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008553:	89 ca                	mov    edx,ecx
   140008555:	89 10                	mov    DWORD PTR [rax],edx
   140008557:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000855b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000855f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008563:	8b 10                	mov    edx,DWORD PTR [rax]
   140008565:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008568:	89 c1                	mov    ecx,eax
   14000856a:	d3 ea                	shr    edx,cl
   14000856c:	89 d0                	mov    eax,edx
   14000856e:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008571:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008575:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008579:	72 ba                	jb     140008535 <__lshift_D2A+0xe5>
   14000857b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000857f:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   140008582:	89 10                	mov    DWORD PTR [rax],edx
   140008584:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008588:	8b 00                	mov    eax,DWORD PTR [rax]
   14000858a:	85 c0                	test   eax,eax
   14000858c:	74 2c                	je     1400085ba <__lshift_D2A+0x16a>
   14000858e:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140008592:	eb 26                	jmp    1400085ba <__lshift_D2A+0x16a>
   140008594:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008598:	48 8d 42 04          	lea    rax,[rdx+0x4]
   14000859c:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400085a0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400085a4:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400085a8:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   1400085ac:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400085ae:	89 10                	mov    DWORD PTR [rax],edx
   1400085b0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400085b4:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400085b8:	72 da                	jb     140008594 <__lshift_D2A+0x144>
   1400085ba:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400085bd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400085c0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400085c4:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400085c7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085cb:	48 89 c1             	mov    rcx,rax
   1400085ce:	e8 9b f8 ff ff       	call   140007e6e <__Bfree_D2A>
   1400085d3:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400085d7:	48 83 c4 60          	add    rsp,0x60
   1400085db:	5d                   	pop    rbp
   1400085dc:	c3                   	ret

00000001400085dd <__cmp_D2A>:
   1400085dd:	55                   	push   rbp
   1400085de:	48 89 e5             	mov    rbp,rsp
   1400085e1:	48 83 ec 30          	sub    rsp,0x30
   1400085e5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400085e9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400085ed:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085f1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400085f4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400085f7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400085fb:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400085fe:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140008601:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008604:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   140008607:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000860b:	74 08                	je     140008615 <__cmp_D2A+0x38>
   14000860d:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008610:	e9 92 00 00 00       	jmp    1400086a7 <__cmp_D2A+0xca>
   140008615:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008619:	48 83 c0 18          	add    rax,0x18
   14000861d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008621:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008624:	48 98                	cdqe
   140008626:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000862d:	00 
   14000862e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008632:	48 01 d0             	add    rax,rdx
   140008635:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008639:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000863d:	48 83 c0 18          	add    rax,0x18
   140008641:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008645:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008648:	48 98                	cdqe
   14000864a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008651:	00 
   140008652:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008656:	48 01 d0             	add    rax,rdx
   140008659:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000865d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008662:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008666:	8b 10                	mov    edx,DWORD PTR [rax]
   140008668:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   14000866d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008671:	8b 00                	mov    eax,DWORD PTR [rax]
   140008673:	39 c2                	cmp    edx,eax
   140008675:	74 1e                	je     140008695 <__cmp_D2A+0xb8>
   140008677:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000867b:	8b 10                	mov    edx,DWORD PTR [rax]
   14000867d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008681:	8b 00                	mov    eax,DWORD PTR [rax]
   140008683:	39 c2                	cmp    edx,eax
   140008685:	73 07                	jae    14000868e <__cmp_D2A+0xb1>
   140008687:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000868c:	eb 19                	jmp    1400086a7 <__cmp_D2A+0xca>
   14000868e:	b8 01 00 00 00       	mov    eax,0x1
   140008693:	eb 12                	jmp    1400086a7 <__cmp_D2A+0xca>
   140008695:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008699:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000869d:	73 02                	jae    1400086a1 <__cmp_D2A+0xc4>
   14000869f:	eb bc                	jmp    14000865d <__cmp_D2A+0x80>
   1400086a1:	90                   	nop
   1400086a2:	b8 00 00 00 00       	mov    eax,0x0
   1400086a7:	48 83 c4 30          	add    rsp,0x30
   1400086ab:	5d                   	pop    rbp
   1400086ac:	c3                   	ret

00000001400086ad <__diff_D2A>:
   1400086ad:	55                   	push   rbp
   1400086ae:	48 89 e5             	mov    rbp,rsp
   1400086b1:	48 83 ec 70          	sub    rsp,0x70
   1400086b5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400086b9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400086bd:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400086c1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086c5:	48 89 c1             	mov    rcx,rax
   1400086c8:	e8 10 ff ff ff       	call   1400085dd <__cmp_D2A>
   1400086cd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400086d0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400086d4:	75 3e                	jne    140008714 <__diff_D2A+0x67>
   1400086d6:	b9 00 00 00 00       	mov    ecx,0x0
   1400086db:	e8 4d f6 ff ff       	call   140007d2d <__Balloc_D2A>
   1400086e0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400086e4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400086e9:	75 0a                	jne    1400086f5 <__diff_D2A+0x48>
   1400086eb:	b8 00 00 00 00       	mov    eax,0x0
   1400086f0:	e9 ab 01 00 00       	jmp    1400088a0 <__diff_D2A+0x1f3>
   1400086f5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086f9:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008700:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008704:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000870b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000870f:	e9 8c 01 00 00       	jmp    1400088a0 <__diff_D2A+0x1f3>
   140008714:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008718:	79 21                	jns    14000873b <__diff_D2A+0x8e>
   14000871a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000871e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008722:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008726:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000872a:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000872e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140008732:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140008739:	eb 07                	jmp    140008742 <__diff_D2A+0x95>
   14000873b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008742:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008746:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008749:	89 c1                	mov    ecx,eax
   14000874b:	e8 dd f5 ff ff       	call   140007d2d <__Balloc_D2A>
   140008750:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008754:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008759:	75 0a                	jne    140008765 <__diff_D2A+0xb8>
   14000875b:	b8 00 00 00 00       	mov    eax,0x0
   140008760:	e9 3b 01 00 00       	jmp    1400088a0 <__diff_D2A+0x1f3>
   140008765:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008769:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000876c:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000876f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008773:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008776:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008779:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000877d:	48 83 c0 18          	add    rax,0x18
   140008781:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008785:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008788:	48 98                	cdqe
   14000878a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008791:	00 
   140008792:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008796:	48 01 d0             	add    rax,rdx
   140008799:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000879d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400087a1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400087a4:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400087a7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400087ab:	48 83 c0 18          	add    rax,0x18
   1400087af:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400087b3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   1400087b6:	48 98                	cdqe
   1400087b8:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400087bf:	00 
   1400087c0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087c4:	48 01 d0             	add    rax,rdx
   1400087c7:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400087cb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087cf:	48 83 c0 18          	add    rax,0x18
   1400087d3:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400087d7:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   1400087de:	00 
   1400087df:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087e3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087e7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400087eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087ed:	89 c1                	mov    ecx,eax
   1400087ef:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087f3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087f7:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400087fb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087fd:	89 c2                	mov    edx,eax
   1400087ff:	48 89 c8             	mov    rax,rcx
   140008802:	48 29 d0             	sub    rax,rdx
   140008805:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140008809:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000880d:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008811:	48 c1 e8 20          	shr    rax,0x20
   140008815:	83 e0 01             	and    eax,0x1
   140008818:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000881c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008820:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008824:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008828:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000882c:	89 10                	mov    DWORD PTR [rax],edx
   14000882e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008832:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   140008836:	72 a7                	jb     1400087df <__diff_D2A+0x132>
   140008838:	eb 39                	jmp    140008873 <__diff_D2A+0x1c6>
   14000883a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000883e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008842:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008846:	8b 00                	mov    eax,DWORD PTR [rax]
   140008848:	89 c0                	mov    eax,eax
   14000884a:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   14000884e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008852:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008856:	48 c1 e8 20          	shr    rax,0x20
   14000885a:	83 e0 01             	and    eax,0x1
   14000885d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008861:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008865:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008869:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000886d:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140008871:	89 10                	mov    DWORD PTR [rax],edx
   140008873:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008877:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   14000887b:	72 bd                	jb     14000883a <__diff_D2A+0x18d>
   14000887d:	eb 04                	jmp    140008883 <__diff_D2A+0x1d6>
   14000887f:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008883:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008888:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000888c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000888e:	85 c0                	test   eax,eax
   140008890:	74 ed                	je     14000887f <__diff_D2A+0x1d2>
   140008892:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008896:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008899:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000889c:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400088a0:	48 83 c4 70          	add    rsp,0x70
   1400088a4:	5d                   	pop    rbp
   1400088a5:	c3                   	ret

00000001400088a6 <__b2d_D2A>:
   1400088a6:	55                   	push   rbp
   1400088a7:	48 89 e5             	mov    rbp,rsp
   1400088aa:	48 83 ec 50          	sub    rsp,0x50
   1400088ae:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400088b2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400088b6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400088ba:	48 83 c0 18          	add    rax,0x18
   1400088be:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400088c2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400088c6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400088c9:	48 98                	cdqe
   1400088cb:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400088d2:	00 
   1400088d3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400088d7:	48 01 d0             	add    rax,rdx
   1400088da:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400088de:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088e7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088e9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400088ec:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400088ef:	89 c1                	mov    ecx,eax
   1400088f1:	e8 27 f4 ff ff       	call   140007d1d <__hi0bits_D2A>
   1400088f6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400088f9:	b8 20 00 00 00       	mov    eax,0x20
   1400088fe:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008901:	89 c2                	mov    edx,eax
   140008903:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008907:	89 10                	mov    DWORD PTR [rax],edx
   140008909:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   14000890d:	7f 66                	jg     140008975 <__b2d_D2A+0xcf>
   14000890f:	b8 0b 00 00 00       	mov    eax,0xb
   140008914:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008917:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000891a:	89 c1                	mov    ecx,eax
   14000891c:	d3 ea                	shr    edx,cl
   14000891e:	89 d0                	mov    eax,edx
   140008920:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008925:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008928:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000892c:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008930:	73 10                	jae    140008942 <__b2d_D2A+0x9c>
   140008932:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008937:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000893b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000893d:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008940:	eb 07                	jmp    140008949 <__b2d_D2A+0xa3>
   140008942:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140008949:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000894c:	83 c0 15             	add    eax,0x15
   14000894f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008952:	89 c1                	mov    ecx,eax
   140008954:	d3 e2                	shl    edx,cl
   140008956:	41 89 d0             	mov    r8d,edx
   140008959:	b8 0b 00 00 00       	mov    eax,0xb
   14000895e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008961:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140008964:	89 c1                	mov    ecx,eax
   140008966:	d3 ea                	shr    edx,cl
   140008968:	89 d0                	mov    eax,edx
   14000896a:	44 09 c0             	or     eax,r8d
   14000896d:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008970:	e9 ac 00 00 00       	jmp    140008a21 <__b2d_D2A+0x17b>
   140008975:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008979:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000897d:	73 10                	jae    14000898f <__b2d_D2A+0xe9>
   14000897f:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008984:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008988:	8b 00                	mov    eax,DWORD PTR [rax]
   14000898a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000898d:	eb 07                	jmp    140008996 <__b2d_D2A+0xf0>
   14000898f:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   140008996:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   14000899a:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   14000899e:	74 70                	je     140008a10 <__b2d_D2A+0x16a>
   1400089a0:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089a3:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400089a6:	89 c1                	mov    ecx,eax
   1400089a8:	d3 e2                	shl    edx,cl
   1400089aa:	41 89 d0             	mov    r8d,edx
   1400089ad:	b8 20 00 00 00       	mov    eax,0x20
   1400089b2:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400089b5:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400089b8:	89 c1                	mov    ecx,eax
   1400089ba:	d3 ea                	shr    edx,cl
   1400089bc:	89 d0                	mov    eax,edx
   1400089be:	44 09 c0             	or     eax,r8d
   1400089c1:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400089c6:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089c9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089cd:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400089d1:	73 10                	jae    1400089e3 <__b2d_D2A+0x13d>
   1400089d3:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400089d8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089dc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400089de:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400089e1:	eb 07                	jmp    1400089ea <__b2d_D2A+0x144>
   1400089e3:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   1400089ea:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089ed:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400089f0:	89 c1                	mov    ecx,eax
   1400089f2:	d3 e2                	shl    edx,cl
   1400089f4:	41 89 d0             	mov    r8d,edx
   1400089f7:	b8 20 00 00 00       	mov    eax,0x20
   1400089fc:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400089ff:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008a02:	89 c1                	mov    ecx,eax
   140008a04:	d3 ea                	shr    edx,cl
   140008a06:	89 d0                	mov    eax,edx
   140008a08:	44 09 c0             	or     eax,r8d
   140008a0b:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a0e:	eb 11                	jmp    140008a21 <__b2d_D2A+0x17b>
   140008a10:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008a13:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008a18:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008a1b:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008a1e:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a21:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   140008a26:	48 83 c4 50          	add    rsp,0x50
   140008a2a:	5d                   	pop    rbp
   140008a2b:	c3                   	ret

0000000140008a2c <__d2b_D2A>:
   140008a2c:	55                   	push   rbp
   140008a2d:	53                   	push   rbx
   140008a2e:	48 83 ec 58          	sub    rsp,0x58
   140008a32:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140008a37:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   140008a3c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140008a40:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140008a44:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140008a49:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   140008a4e:	b9 01 00 00 00       	mov    ecx,0x1
   140008a53:	e8 d5 f2 ff ff       	call   140007d2d <__Balloc_D2A>
   140008a58:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008a5c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008a61:	75 0a                	jne    140008a6d <__d2b_D2A+0x41>
   140008a63:	b8 00 00 00 00       	mov    eax,0x0
   140008a68:	e9 68 01 00 00       	jmp    140008bd5 <__d2b_D2A+0x1a9>
   140008a6d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a71:	48 83 c0 18          	add    rax,0x18
   140008a75:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008a79:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a7c:	25 ff ff 0f 00       	and    eax,0xfffff
   140008a81:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a84:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a87:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008a8c:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008a8f:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a92:	c1 e8 14             	shr    eax,0x14
   140008a95:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140008a98:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008a9c:	74 0b                	je     140008aa9 <__d2b_D2A+0x7d>
   140008a9e:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   140008aa1:	0d 00 00 10 00       	or     eax,0x100000
   140008aa6:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008aa9:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140008aac:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008aaf:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008ab2:	85 c0                	test   eax,eax
   140008ab4:	74 7b                	je     140008b31 <__d2b_D2A+0x105>
   140008ab6:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   140008aba:	48 89 c1             	mov    rcx,rax
   140008abd:	e8 26 f2 ff ff       	call   140007ce8 <__lo0bits_D2A>
   140008ac2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008ac5:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008ac9:	74 2b                	je     140008af6 <__d2b_D2A+0xca>
   140008acb:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008ace:	b8 20 00 00 00       	mov    eax,0x20
   140008ad3:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008ad6:	89 c1                	mov    ecx,eax
   140008ad8:	d3 e2                	shl    edx,cl
   140008ada:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008add:	09 c2                	or     edx,eax
   140008adf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008ae3:	89 10                	mov    DWORD PTR [rax],edx
   140008ae5:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008ae8:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008aeb:	89 c1                	mov    ecx,eax
   140008aed:	d3 ea                	shr    edx,cl
   140008aef:	89 d0                	mov    eax,edx
   140008af1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008af4:	eb 09                	jmp    140008aff <__d2b_D2A+0xd3>
   140008af6:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008af9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008afd:	89 10                	mov    DWORD PTR [rax],edx
   140008aff:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b03:	48 83 c0 04          	add    rax,0x4
   140008b07:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b0a:	89 10                	mov    DWORD PTR [rax],edx
   140008b0c:	8b 00                	mov    eax,DWORD PTR [rax]
   140008b0e:	85 c0                	test   eax,eax
   140008b10:	74 07                	je     140008b19 <__d2b_D2A+0xed>
   140008b12:	ba 02 00 00 00       	mov    edx,0x2
   140008b17:	eb 05                	jmp    140008b1e <__d2b_D2A+0xf2>
   140008b19:	ba 01 00 00 00       	mov    edx,0x1
   140008b1e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b22:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008b25:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b29:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b2c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b2f:	eb 31                	jmp    140008b62 <__d2b_D2A+0x136>
   140008b31:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008b35:	48 89 c1             	mov    rcx,rax
   140008b38:	e8 ab f1 ff ff       	call   140007ce8 <__lo0bits_D2A>
   140008b3d:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008b40:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b43:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b47:	89 10                	mov    DWORD PTR [rax],edx
   140008b49:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b4d:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008b54:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b58:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b5b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b5e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008b62:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008b66:	74 26                	je     140008b8e <__d2b_D2A+0x162>
   140008b68:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b6b:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008b71:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b74:	01 c2                	add    edx,eax
   140008b76:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b7a:	89 10                	mov    DWORD PTR [rax],edx
   140008b7c:	b8 35 00 00 00       	mov    eax,0x35
   140008b81:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008b84:	89 c2                	mov    edx,eax
   140008b86:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b8a:	89 10                	mov    DWORD PTR [rax],edx
   140008b8c:	eb 43                	jmp    140008bd1 <__d2b_D2A+0x1a5>
   140008b8e:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b91:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008b97:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b9a:	01 c2                	add    edx,eax
   140008b9c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008ba0:	89 10                	mov    DWORD PTR [rax],edx
   140008ba2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008ba5:	c1 e0 05             	shl    eax,0x5
   140008ba8:	89 c3                	mov    ebx,eax
   140008baa:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008bad:	48 98                	cdqe
   140008baf:	48 c1 e0 02          	shl    rax,0x2
   140008bb3:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008bb7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008bbb:	48 01 d0             	add    rax,rdx
   140008bbe:	8b 00                	mov    eax,DWORD PTR [rax]
   140008bc0:	89 c1                	mov    ecx,eax
   140008bc2:	e8 56 f1 ff ff       	call   140007d1d <__hi0bits_D2A>
   140008bc7:	29 c3                	sub    ebx,eax
   140008bc9:	89 da                	mov    edx,ebx
   140008bcb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008bcf:	89 10                	mov    DWORD PTR [rax],edx
   140008bd1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008bd5:	48 83 c4 58          	add    rsp,0x58
   140008bd9:	5b                   	pop    rbx
   140008bda:	5d                   	pop    rbp
   140008bdb:	c3                   	ret

0000000140008bdc <__strcp_D2A>:
   140008bdc:	55                   	push   rbp
   140008bdd:	48 89 e5             	mov    rbp,rsp
   140008be0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008be4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008be8:	eb 05                	jmp    140008bef <__strcp_D2A+0x13>
   140008bea:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008bef:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008bf3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008bf7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008bfb:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008bfe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008c02:	88 10                	mov    BYTE PTR [rax],dl
   140008c04:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008c08:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008c0b:	84 c0                	test   al,al
   140008c0d:	75 db                	jne    140008bea <__strcp_D2A+0xe>
   140008c0f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008c13:	5d                   	pop    rbp
   140008c14:	c3                   	ret
   140008c15:	90                   	nop
   140008c16:	90                   	nop
   140008c17:	90                   	nop
   140008c18:	90                   	nop
   140008c19:	90                   	nop
   140008c1a:	90                   	nop
   140008c1b:	90                   	nop
   140008c1c:	90                   	nop
   140008c1d:	90                   	nop
   140008c1e:	90                   	nop
   140008c1f:	90                   	nop

0000000140008c20 <__fpclassify>:
   140008c20:	55                   	push   rbp
   140008c21:	48 89 e5             	mov    rbp,rsp
   140008c24:	48 83 ec 10          	sub    rsp,0x10
   140008c28:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008c2d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008c32:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008c37:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008c3a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c3d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008c40:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008c43:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008c49:	09 d0                	or     eax,edx
   140008c4b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c4e:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008c55:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c58:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c5b:	85 c0                	test   eax,eax
   140008c5d:	75 07                	jne    140008c66 <__fpclassify+0x46>
   140008c5f:	b8 00 40 00 00       	mov    eax,0x4000
   140008c64:	eb 2f                	jmp    140008c95 <__fpclassify+0x75>
   140008c66:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c6a:	75 07                	jne    140008c73 <__fpclassify+0x53>
   140008c6c:	b8 00 44 00 00       	mov    eax,0x4400
   140008c71:	eb 22                	jmp    140008c95 <__fpclassify+0x75>
   140008c73:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008c7a:	75 14                	jne    140008c90 <__fpclassify+0x70>
   140008c7c:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008c80:	74 07                	je     140008c89 <__fpclassify+0x69>
   140008c82:	b8 00 01 00 00       	mov    eax,0x100
   140008c87:	eb 0c                	jmp    140008c95 <__fpclassify+0x75>
   140008c89:	b8 00 05 00 00       	mov    eax,0x500
   140008c8e:	eb 05                	jmp    140008c95 <__fpclassify+0x75>
   140008c90:	b8 00 04 00 00       	mov    eax,0x400
   140008c95:	48 83 c4 10          	add    rsp,0x10
   140008c99:	5d                   	pop    rbp
   140008c9a:	c3                   	ret
   140008c9b:	90                   	nop
   140008c9c:	90                   	nop
   140008c9d:	90                   	nop
   140008c9e:	90                   	nop
   140008c9f:	90                   	nop

0000000140008ca0 <__fpclassifyl>:
   140008ca0:	55                   	push   rbp
   140008ca1:	53                   	push   rbx
   140008ca2:	48 83 ec 38          	sub    rsp,0x38
   140008ca6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008cab:	48 89 cb             	mov    rbx,rcx
   140008cae:	db 2b                	fld    TBYTE PTR [rbx]
   140008cb0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008cb3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008cb6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008cb9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008cbd:	98                   	cwde
   140008cbe:	25 ff 7f 00 00       	and    eax,0x7fff
   140008cc3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cc6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008cca:	75 25                	jne    140008cf1 <__fpclassifyl+0x51>
   140008ccc:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008ccf:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008cd2:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008cd5:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008cd8:	85 c0                	test   eax,eax
   140008cda:	75 07                	jne    140008ce3 <__fpclassifyl+0x43>
   140008cdc:	b8 00 40 00 00       	mov    eax,0x4000
   140008ce1:	eb 3d                	jmp    140008d20 <__fpclassifyl+0x80>
   140008ce3:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008ce6:	85 c0                	test   eax,eax
   140008ce8:	78 31                	js     140008d1b <__fpclassifyl+0x7b>
   140008cea:	b8 00 44 00 00       	mov    eax,0x4400
   140008cef:	eb 2f                	jmp    140008d20 <__fpclassifyl+0x80>
   140008cf1:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008cf8:	75 21                	jne    140008d1b <__fpclassifyl+0x7b>
   140008cfa:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008cfd:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008d02:	89 c2                	mov    edx,eax
   140008d04:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008d07:	09 d0                	or     eax,edx
   140008d09:	85 c0                	test   eax,eax
   140008d0b:	75 07                	jne    140008d14 <__fpclassifyl+0x74>
   140008d0d:	b8 00 05 00 00       	mov    eax,0x500
   140008d12:	eb 0c                	jmp    140008d20 <__fpclassifyl+0x80>
   140008d14:	b8 00 01 00 00       	mov    eax,0x100
   140008d19:	eb 05                	jmp    140008d20 <__fpclassifyl+0x80>
   140008d1b:	b8 00 04 00 00       	mov    eax,0x400
   140008d20:	48 83 c4 38          	add    rsp,0x38
   140008d24:	5b                   	pop    rbx
   140008d25:	5d                   	pop    rbp
   140008d26:	c3                   	ret
   140008d27:	90                   	nop
   140008d28:	90                   	nop
   140008d29:	90                   	nop
   140008d2a:	90                   	nop
   140008d2b:	90                   	nop
   140008d2c:	90                   	nop
   140008d2d:	90                   	nop
   140008d2e:	90                   	nop
   140008d2f:	90                   	nop

0000000140008d30 <__isnan>:
   140008d30:	55                   	push   rbp
   140008d31:	48 89 e5             	mov    rbp,rsp
   140008d34:	48 83 ec 10          	sub    rsp,0x10
   140008d38:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008d3d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008d42:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008d47:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008d4a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d4d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008d50:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008d55:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d58:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d5b:	f7 d8                	neg    eax
   140008d5d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008d60:	c1 e8 1f             	shr    eax,0x1f
   140008d63:	89 c2                	mov    edx,eax
   140008d65:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d68:	09 d0                	or     eax,edx
   140008d6a:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d6d:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008d72:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008d75:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d78:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d7b:	c1 f8 1f             	sar    eax,0x1f
   140008d7e:	48 83 c4 10          	add    rsp,0x10
   140008d82:	5d                   	pop    rbp
   140008d83:	c3                   	ret
   140008d84:	90                   	nop
   140008d85:	90                   	nop
   140008d86:	90                   	nop
   140008d87:	90                   	nop
   140008d88:	90                   	nop
   140008d89:	90                   	nop
   140008d8a:	90                   	nop
   140008d8b:	90                   	nop
   140008d8c:	90                   	nop
   140008d8d:	90                   	nop
   140008d8e:	90                   	nop
   140008d8f:	90                   	nop

0000000140008d90 <__isnanl>:
   140008d90:	55                   	push   rbp
   140008d91:	53                   	push   rbx
   140008d92:	48 83 ec 38          	sub    rsp,0x38
   140008d96:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008d9b:	48 89 cb             	mov    rbx,rcx
   140008d9e:	db 2b                	fld    TBYTE PTR [rbx]
   140008da0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008da3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008da6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008da9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008dad:	98                   	cwde
   140008dae:	01 c0                	add    eax,eax
   140008db0:	25 ff ff 00 00       	and    eax,0xffff
   140008db5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008db8:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008dbb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008dbe:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008dc4:	09 d0                	or     eax,edx
   140008dc6:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008dc9:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008dcc:	f7 d8                	neg    eax
   140008dce:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008dd1:	c1 e8 1f             	shr    eax,0x1f
   140008dd4:	89 c2                	mov    edx,eax
   140008dd6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008dd9:	09 d0                	or     eax,edx
   140008ddb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008dde:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008de3:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008de6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008de9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008dec:	c1 f8 10             	sar    eax,0x10
   140008def:	48 83 c4 38          	add    rsp,0x38
   140008df3:	5b                   	pop    rbx
   140008df4:	5d                   	pop    rbp
   140008df5:	c3                   	ret
   140008df6:	90                   	nop
   140008df7:	90                   	nop
   140008df8:	90                   	nop
   140008df9:	90                   	nop
   140008dfa:	90                   	nop
   140008dfb:	90                   	nop
   140008dfc:	90                   	nop
   140008dfd:	90                   	nop
   140008dfe:	90                   	nop
   140008dff:	90                   	nop

0000000140008e00 <wcsnlen>:
   140008e00:	55                   	push   rbp
   140008e01:	48 89 e5             	mov    rbp,rsp
   140008e04:	48 83 ec 10          	sub    rsp,0x10
   140008e08:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e0c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e10:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008e17:	00 
   140008e18:	eb 0a                	jmp    140008e24 <wcsnlen+0x24>
   140008e1a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e1f:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008e24:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e28:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e2c:	73 0c                	jae    140008e3a <wcsnlen+0x3a>
   140008e2e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e32:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008e35:	66 85 c0             	test   ax,ax
   140008e38:	75 e0                	jne    140008e1a <wcsnlen+0x1a>
   140008e3a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e3e:	48 83 c4 10          	add    rsp,0x10
   140008e42:	5d                   	pop    rbp
   140008e43:	c3                   	ret
   140008e44:	90                   	nop
   140008e45:	90                   	nop
   140008e46:	90                   	nop
   140008e47:	90                   	nop
   140008e48:	90                   	nop
   140008e49:	90                   	nop
   140008e4a:	90                   	nop
   140008e4b:	90                   	nop
   140008e4c:	90                   	nop
   140008e4d:	90                   	nop
   140008e4e:	90                   	nop
   140008e4f:	90                   	nop

0000000140008e50 <strnlen>:
   140008e50:	55                   	push   rbp
   140008e51:	48 89 e5             	mov    rbp,rsp
   140008e54:	48 83 ec 10          	sub    rsp,0x10
   140008e58:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e5c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e60:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e64:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e68:	eb 05                	jmp    140008e6f <strnlen+0x1f>
   140008e6a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e6f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e73:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e77:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e7b:	73 0b                	jae    140008e88 <strnlen+0x38>
   140008e7d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e81:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008e84:	84 c0                	test   al,al
   140008e86:	75 e2                	jne    140008e6a <strnlen+0x1a>
   140008e88:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e8c:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e90:	48 83 c4 10          	add    rsp,0x10
   140008e94:	5d                   	pop    rbp
   140008e95:	c3                   	ret
   140008e96:	90                   	nop
   140008e97:	90                   	nop
   140008e98:	90                   	nop
   140008e99:	90                   	nop
   140008e9a:	90                   	nop
   140008e9b:	90                   	nop
   140008e9c:	90                   	nop
   140008e9d:	90                   	nop
   140008e9e:	90                   	nop
   140008e9f:	90                   	nop

0000000140008ea0 <_initterm_e>:
   140008ea0:	55                   	push   rbp
   140008ea1:	48 89 e5             	mov    rbp,rsp
   140008ea4:	48 83 ec 30          	sub    rsp,0x30
   140008ea8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008eac:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008eb0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008eb4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008eb8:	eb 29                	jmp    140008ee3 <_initterm_e+0x43>
   140008eba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008ebe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ec1:	48 85 c0             	test   rax,rax
   140008ec4:	74 17                	je     140008edd <_initterm_e+0x3d>
   140008ec6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008eca:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ecd:	ff d0                	call   rax
   140008ecf:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008ed2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008ed6:	74 06                	je     140008ede <_initterm_e+0x3e>
   140008ed8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008edb:	eb 15                	jmp    140008ef2 <_initterm_e+0x52>
   140008edd:	90                   	nop
   140008ede:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008ee3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008ee7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008eeb:	72 cd                	jb     140008eba <_initterm_e+0x1a>
   140008eed:	b8 00 00 00 00       	mov    eax,0x0
   140008ef2:	48 83 c4 30          	add    rsp,0x30
   140008ef6:	5d                   	pop    rbp
   140008ef7:	c3                   	ret
   140008ef8:	90                   	nop
   140008ef9:	90                   	nop
   140008efa:	90                   	nop
   140008efb:	90                   	nop
   140008efc:	90                   	nop
   140008efd:	90                   	nop
   140008efe:	90                   	nop
   140008eff:	90                   	nop

0000000140008f00 <__p__fmode>:
   140008f00:	55                   	push   rbp
   140008f01:	48 89 e5             	mov    rbp,rsp
   140008f04:	48 8b 05 f5 26 00 00 	mov    rax,QWORD PTR [rip+0x26f5]        # 14000b600 <.refptr.__imp__fmode>
   140008f0b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f0e:	5d                   	pop    rbp
   140008f0f:	c3                   	ret

0000000140008f10 <__p__commode>:
   140008f10:	55                   	push   rbp
   140008f11:	48 89 e5             	mov    rbp,rsp
   140008f14:	48 8b 05 d5 26 00 00 	mov    rax,QWORD PTR [rip+0x26d5]        # 14000b5f0 <.refptr.__imp__commode>
   140008f1b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f1e:	5d                   	pop    rbp
   140008f1f:	c3                   	ret

0000000140008f20 <__p___initenv>:
   140008f20:	55                   	push   rbp
   140008f21:	48 89 e5             	mov    rbp,rsp
   140008f24:	48 8b 05 b5 26 00 00 	mov    rax,QWORD PTR [rip+0x26b5]        # 14000b5e0 <.refptr.__imp___initenv>
   140008f2b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f2e:	5d                   	pop    rbp
   140008f2f:	c3                   	ret

0000000140008f30 <_lock_file>:
   140008f30:	55                   	push   rbp
   140008f31:	48 89 e5             	mov    rbp,rsp
   140008f34:	48 83 ec 20          	sub    rsp,0x20
   140008f38:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f3c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f41:	e8 6a 01 00 00       	call   1400090b0 <__acrt_iob_func>
   140008f46:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008f4a:	72 52                	jb     140008f9e <_lock_file+0x6e>
   140008f4c:	b9 13 00 00 00       	mov    ecx,0x13
   140008f51:	e8 5a 01 00 00       	call   1400090b0 <__acrt_iob_func>
   140008f56:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f5a:	72 42                	jb     140008f9e <_lock_file+0x6e>
   140008f5c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f61:	e8 4a 01 00 00       	call   1400090b0 <__acrt_iob_func>
   140008f66:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f6a:	48 29 c2             	sub    rdx,rax
   140008f6d:	48 c1 fa 04          	sar    rdx,0x4
   140008f71:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008f78:	aa aa aa 
   140008f7b:	48 0f af c2          	imul   rax,rdx
   140008f7f:	83 c0 10             	add    eax,0x10
   140008f82:	89 c1                	mov    ecx,eax
   140008f84:	e8 1f 07 00 00       	call   1400096a8 <_lock>
   140008f89:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f8d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008f90:	80 cc 80             	or     ah,0x80
   140008f93:	89 c2                	mov    edx,eax
   140008f95:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f99:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008f9c:	eb 15                	jmp    140008fb3 <_lock_file+0x83>
   140008f9e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fa2:	48 83 c0 30          	add    rax,0x30
   140008fa6:	48 89 c1             	mov    rcx,rax
   140008fa9:	48 8b 05 40 72 00 00 	mov    rax,QWORD PTR [rip+0x7240]        # 1400101f0 <__imp_EnterCriticalSection>
   140008fb0:	ff d0                	call   rax
   140008fb2:	90                   	nop
   140008fb3:	90                   	nop
   140008fb4:	48 83 c4 20          	add    rsp,0x20
   140008fb8:	5d                   	pop    rbp
   140008fb9:	c3                   	ret

0000000140008fba <_unlock_file>:
   140008fba:	55                   	push   rbp
   140008fbb:	48 89 e5             	mov    rbp,rsp
   140008fbe:	48 83 ec 20          	sub    rsp,0x20
   140008fc2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008fc6:	b9 00 00 00 00       	mov    ecx,0x0
   140008fcb:	e8 e0 00 00 00       	call   1400090b0 <__acrt_iob_func>
   140008fd0:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008fd4:	72 52                	jb     140009028 <_unlock_file+0x6e>
   140008fd6:	b9 13 00 00 00       	mov    ecx,0x13
   140008fdb:	e8 d0 00 00 00       	call   1400090b0 <__acrt_iob_func>
   140008fe0:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008fe4:	72 42                	jb     140009028 <_unlock_file+0x6e>
   140008fe6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fea:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008fed:	80 e4 7f             	and    ah,0x7f
   140008ff0:	89 c2                	mov    edx,eax
   140008ff2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ff6:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008ff9:	b9 00 00 00 00       	mov    ecx,0x0
   140008ffe:	e8 ad 00 00 00       	call   1400090b0 <__acrt_iob_func>
   140009003:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140009007:	48 29 c2             	sub    rdx,rax
   14000900a:	48 c1 fa 04          	sar    rdx,0x4
   14000900e:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140009015:	aa aa aa 
   140009018:	48 0f af c2          	imul   rax,rdx
   14000901c:	83 c0 10             	add    eax,0x10
   14000901f:	89 c1                	mov    ecx,eax
   140009021:	e8 8a 06 00 00       	call   1400096b0 <_unlock>
   140009026:	eb 15                	jmp    14000903d <_unlock_file+0x83>
   140009028:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000902c:	48 83 c0 30          	add    rax,0x30
   140009030:	48 89 c1             	mov    rcx,rax
   140009033:	48 8b 05 ee 71 00 00 	mov    rax,QWORD PTR [rip+0x71ee]        # 140010228 <__imp_LeaveCriticalSection>
   14000903a:	ff d0                	call   rax
   14000903c:	90                   	nop
   14000903d:	90                   	nop
   14000903e:	48 83 c4 20          	add    rsp,0x20
   140009042:	5d                   	pop    rbp
   140009043:	c3                   	ret
   140009044:	90                   	nop
   140009045:	90                   	nop
   140009046:	90                   	nop
   140009047:	90                   	nop
   140009048:	90                   	nop
   140009049:	90                   	nop
   14000904a:	90                   	nop
   14000904b:	90                   	nop
   14000904c:	90                   	nop
   14000904d:	90                   	nop
   14000904e:	90                   	nop
   14000904f:	90                   	nop

0000000140009050 <_set_invalid_parameter_handler>:
   140009050:	55                   	push   rbp
   140009051:	48 89 e5             	mov    rbp,rsp
   140009054:	48 83 ec 10          	sub    rsp,0x10
   140009058:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000905c:	48 8d 05 1d 6b 00 00 	lea    rax,[rip+0x6b1d]        # 14000fb80 <handler>
   140009063:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140009067:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000906b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000906f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140009073:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140009077:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000907a:	48 89 d0             	mov    rax,rdx
   14000907d:	48 83 c4 10          	add    rsp,0x10
   140009081:	5d                   	pop    rbp
   140009082:	c3                   	ret

0000000140009083 <_get_invalid_parameter_handler>:
   140009083:	55                   	push   rbp
   140009084:	48 89 e5             	mov    rbp,rsp
   140009087:	48 8b 05 f2 6a 00 00 	mov    rax,QWORD PTR [rip+0x6af2]        # 14000fb80 <handler>
   14000908e:	5d                   	pop    rbp
   14000908f:	c3                   	ret

0000000140009090 <_configthreadlocale>:
   140009090:	55                   	push   rbp
   140009091:	48 89 e5             	mov    rbp,rsp
   140009094:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140009097:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000909b:	75 07                	jne    1400090a4 <_configthreadlocale+0x14>
   14000909d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400090a2:	eb 05                	jmp    1400090a9 <_configthreadlocale+0x19>
   1400090a4:	b8 02 00 00 00       	mov    eax,0x2
   1400090a9:	5d                   	pop    rbp
   1400090aa:	c3                   	ret
   1400090ab:	90                   	nop
   1400090ac:	90                   	nop
   1400090ad:	90                   	nop
   1400090ae:	90                   	nop
   1400090af:	90                   	nop

00000001400090b0 <__acrt_iob_func>:
   1400090b0:	55                   	push   rbp
   1400090b1:	48 89 e5             	mov    rbp,rsp
   1400090b4:	48 83 ec 20          	sub    rsp,0x20
   1400090b8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400090bb:	e8 b0 05 00 00       	call   140009670 <__iob_func>
   1400090c0:	48 89 c1             	mov    rcx,rax
   1400090c3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400090c6:	48 89 d0             	mov    rax,rdx
   1400090c9:	48 01 c0             	add    rax,rax
   1400090cc:	48 01 d0             	add    rax,rdx
   1400090cf:	48 c1 e0 04          	shl    rax,0x4
   1400090d3:	48 01 c8             	add    rax,rcx
   1400090d6:	48 83 c4 20          	add    rsp,0x20
   1400090da:	5d                   	pop    rbp
   1400090db:	c3                   	ret
   1400090dc:	90                   	nop
   1400090dd:	90                   	nop
   1400090de:	90                   	nop
   1400090df:	90                   	nop

00000001400090e0 <wcrtomb>:
   1400090e0:	55                   	push   rbp
   1400090e1:	48 89 e5             	mov    rbp,rsp
   1400090e4:	48 83 ec 40          	sub    rsp,0x40
   1400090e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090ec:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400090f0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090f4:	e8 5f 05 00 00       	call   140009658 <___lc_codepage_func>
   1400090f9:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400090fc:	e8 5f 05 00 00       	call   140009660 <___mb_cur_max_func>
   140009101:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140009104:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   140009108:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   14000910c:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   140009110:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009114:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140009117:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   14000911b:	48 89 c1             	mov    rcx,rax
   14000911e:	e8 7d 00 00 00       	call   1400091a0 <__mingw_wcrtomb_cp>
   140009123:	48 83 c4 40          	add    rsp,0x40
   140009127:	5d                   	pop    rbp
   140009128:	c3                   	ret
   140009129:	90                   	nop
   14000912a:	90                   	nop
   14000912b:	90                   	nop
   14000912c:	90                   	nop
   14000912d:	90                   	nop
   14000912e:	90                   	nop
   14000912f:	90                   	nop

0000000140009130 <mbrtowc>:
   140009130:	55                   	push   rbp
   140009131:	48 89 e5             	mov    rbp,rsp
   140009134:	48 83 ec 40          	sub    rsp,0x40
   140009138:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000913c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009140:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009144:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009148:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   14000914d:	75 0b                	jne    14000915a <mbrtowc+0x2a>
   14000914f:	48 8d 05 3a 6a 00 00 	lea    rax,[rip+0x6a3a]        # 14000fb90 <state_mbrtowc.0>
   140009156:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000915a:	e8 f9 04 00 00       	call   140009658 <___lc_codepage_func>
   14000915f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009162:	e8 f9 04 00 00       	call   140009660 <___mb_cur_max_func>
   140009167:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000916a:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   14000916e:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140009172:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140009176:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000917a:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   14000917d:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   140009181:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   140009184:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   140009188:	48 89 c1             	mov    rcx,rax
   14000918b:	e8 70 01 00 00       	call   140009300 <__mingw_mbrtowc_cp>
   140009190:	48 83 c4 40          	add    rsp,0x40
   140009194:	5d                   	pop    rbp
   140009195:	c3                   	ret
   140009196:	90                   	nop
   140009197:	90                   	nop
   140009198:	90                   	nop
   140009199:	90                   	nop
   14000919a:	90                   	nop
   14000919b:	90                   	nop
   14000919c:	90                   	nop
   14000919d:	90                   	nop
   14000919e:	90                   	nop
   14000919f:	90                   	nop

00000001400091a0 <__mingw_wcrtomb_cp>:
   1400091a0:	55                   	push   rbp
   1400091a1:	48 89 e5             	mov    rbp,rsp
   1400091a4:	48 83 ec 50          	sub    rsp,0x50
   1400091a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400091ac:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400091b0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400091b4:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   1400091b8:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091bd:	75 1b                	jne    1400091da <__mingw_wcrtomb_cp+0x3a>
   1400091bf:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400091c4:	74 0a                	je     1400091d0 <__mingw_wcrtomb_cp+0x30>
   1400091c6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400091ca:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400091d0:	b8 01 00 00 00       	mov    eax,0x1
   1400091d5:	e9 17 01 00 00       	jmp    1400092f1 <__mingw_wcrtomb_cp+0x151>
   1400091da:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400091df:	74 21                	je     140009202 <__mingw_wcrtomb_cp+0x62>
   1400091e1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400091e5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400091e7:	85 c0                	test   eax,eax
   1400091e9:	74 17                	je     140009202 <__mingw_wcrtomb_cp+0x62>
   1400091eb:	e8 a8 04 00 00       	call   140009698 <_errno>
   1400091f0:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   1400091f6:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400091fd:	e9 ef 00 00 00       	jmp    1400092f1 <__mingw_wcrtomb_cp+0x151>
   140009202:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009206:	66 85 c0             	test   ax,ax
   140009209:	75 18                	jne    140009223 <__mingw_wcrtomb_cp+0x83>
   14000920b:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009210:	74 07                	je     140009219 <__mingw_wcrtomb_cp+0x79>
   140009212:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009216:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140009219:	b8 01 00 00 00       	mov    eax,0x1
   14000921e:	e9 ce 00 00 00       	jmp    1400092f1 <__mingw_wcrtomb_cp+0x151>
   140009223:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   140009227:	75 2b                	jne    140009254 <__mingw_wcrtomb_cp+0xb4>
   140009229:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   14000922d:	66 3d ff 00          	cmp    ax,0xff
   140009231:	0f 87 a4 00 00 00    	ja     1400092db <__mingw_wcrtomb_cp+0x13b>
   140009237:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000923c:	74 0c                	je     14000924a <__mingw_wcrtomb_cp+0xaa>
   14000923e:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009242:	89 c2                	mov    edx,eax
   140009244:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009248:	88 10                	mov    BYTE PTR [rax],dl
   14000924a:	b8 01 00 00 00       	mov    eax,0x1
   14000924f:	e9 9d 00 00 00       	jmp    1400092f1 <__mingw_wcrtomb_cp+0x151>
   140009254:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000925b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   140009261:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   140009265:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140009268:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   14000926c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140009271:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   140009278:	00 00 
   14000927a:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000927d:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140009281:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009285:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000928a:	41 b9 01 00 00 00    	mov    r9d,0x1
   140009290:	49 89 c8             	mov    r8,rcx
   140009293:	ba 00 00 00 00       	mov    edx,0x0
   140009298:	89 c1                	mov    ecx,eax
   14000929a:	48 8b 05 c7 6f 00 00 	mov    rax,QWORD PTR [rip+0x6fc7]        # 140010268 <__imp_WideCharToMultiByte>
   1400092a1:	ff d0                	call   rax
   1400092a3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400092a6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400092aa:	74 32                	je     1400092de <__mingw_wcrtomb_cp+0x13e>
   1400092ac:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092af:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   1400092b2:	7f 2a                	jg     1400092de <__mingw_wcrtomb_cp+0x13e>
   1400092b4:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400092b7:	85 c0                	test   eax,eax
   1400092b9:	75 23                	jne    1400092de <__mingw_wcrtomb_cp+0x13e>
   1400092bb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092be:	48 63 c8             	movsxd rcx,eax
   1400092c1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400092c5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400092c9:	49 89 c8             	mov    r8,rcx
   1400092cc:	48 89 c1             	mov    rcx,rax
   1400092cf:	e8 34 04 00 00       	call   140009708 <memcpy>
   1400092d4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092d7:	48 98                	cdqe
   1400092d9:	eb 16                	jmp    1400092f1 <__mingw_wcrtomb_cp+0x151>
   1400092db:	90                   	nop
   1400092dc:	eb 01                	jmp    1400092df <__mingw_wcrtomb_cp+0x13f>
   1400092de:	90                   	nop
   1400092df:	e8 b4 03 00 00       	call   140009698 <_errno>
   1400092e4:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400092ea:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400092f1:	48 83 c4 50          	add    rsp,0x50
   1400092f5:	5d                   	pop    rbp
   1400092f6:	c3                   	ret
   1400092f7:	90                   	nop
   1400092f8:	90                   	nop
   1400092f9:	90                   	nop
   1400092fa:	90                   	nop
   1400092fb:	90                   	nop
   1400092fc:	90                   	nop
   1400092fd:	90                   	nop
   1400092fe:	90                   	nop
   1400092ff:	90                   	nop

0000000140009300 <__mingw_mbrtowc_cp>:
   140009300:	55                   	push   rbp
   140009301:	48 89 e5             	mov    rbp,rsp
   140009304:	48 83 ec 50          	sub    rsp,0x50
   140009308:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000930c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009310:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009314:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009318:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   14000931d:	75 1b                	jne    14000933a <__mingw_mbrtowc_cp+0x3a>
   14000931f:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   140009326:	00 
   140009327:	48 8d 05 f2 21 00 00 	lea    rax,[rip+0x21f2]        # 14000b520 <.rdata>
   14000932e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140009332:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   140009339:	00 
   14000933a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000933e:	8b 00                	mov    eax,DWORD PTR [rax]
   140009340:	3d ff 00 00 00       	cmp    eax,0xff
   140009345:	0f 87 b9 01 00 00    	ja     140009504 <__mingw_mbrtowc_cp+0x204>
   14000934b:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009350:	75 0c                	jne    14000935e <__mingw_mbrtowc_cp+0x5e>
   140009352:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009359:	e9 bc 01 00 00       	jmp    14000951a <__mingw_mbrtowc_cp+0x21a>
   14000935e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009362:	8b 00                	mov    eax,DWORD PTR [rax]
   140009364:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140009367:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   14000936b:	75 0c                	jne    140009379 <__mingw_mbrtowc_cp+0x79>
   14000936d:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009371:	84 c0                	test   al,al
   140009373:	0f 85 8e 01 00 00    	jne    140009507 <__mingw_mbrtowc_cp+0x207>
   140009379:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   14000937d:	75 2c                	jne    1400093ab <__mingw_mbrtowc_cp+0xab>
   14000937f:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009384:	74 11                	je     140009397 <__mingw_mbrtowc_cp+0x97>
   140009386:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000938a:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000938d:	0f b6 d0             	movzx  edx,al
   140009390:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009394:	66 89 10             	mov    WORD PTR [rax],dx
   140009397:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000939b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000939e:	84 c0                	test   al,al
   1400093a0:	0f 95 c0             	setne  al
   1400093a3:	0f b6 c0             	movzx  eax,al
   1400093a6:	e9 6f 01 00 00       	jmp    14000951a <__mingw_mbrtowc_cp+0x21a>
   1400093ab:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400093b2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400093b9:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400093bd:	84 c0                	test   al,al
   1400093bf:	74 1a                	je     1400093db <__mingw_mbrtowc_cp+0xdb>
   1400093c1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093c5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093c8:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   1400093cb:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400093d2:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400093d9:	eb 73                	jmp    14000944e <__mingw_mbrtowc_cp+0x14e>
   1400093db:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   1400093df:	75 5c                	jne    14000943d <__mingw_mbrtowc_cp+0x13d>
   1400093e1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093e5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093e8:	0f b6 c0             	movzx  eax,al
   1400093eb:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   1400093ee:	89 c1                	mov    ecx,eax
   1400093f0:	e8 ab 01 00 00       	call   1400095a0 <__mingw_isleadbyte_cp>
   1400093f5:	85 c0                	test   eax,eax
   1400093f7:	74 44                	je     14000943d <__mingw_mbrtowc_cp+0x13d>
   1400093f9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093fd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009400:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009403:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   140009408:	77 15                	ja     14000941f <__mingw_mbrtowc_cp+0x11f>
   14000940a:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000940d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009411:	89 10                	mov    DWORD PTR [rax],edx
   140009413:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   14000941a:	e9 fb 00 00 00       	jmp    14000951a <__mingw_mbrtowc_cp+0x21a>
   14000941f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009423:	48 83 c0 01          	add    rax,0x1
   140009427:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000942a:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000942d:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140009434:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   14000943b:	eb 11                	jmp    14000944e <__mingw_mbrtowc_cp+0x14e>
   14000943d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009441:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009444:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009447:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000944e:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009452:	84 c0                	test   al,al
   140009454:	75 24                	jne    14000947a <__mingw_mbrtowc_cp+0x17a>
   140009456:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000945b:	74 09                	je     140009466 <__mingw_mbrtowc_cp+0x166>
   14000945d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009461:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   140009466:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000946a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009470:	b8 00 00 00 00       	mov    eax,0x0
   140009475:	e9 a0 00 00 00       	jmp    14000951a <__mingw_mbrtowc_cp+0x21a>
   14000947a:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   14000947e:	75 08                	jne    140009488 <__mingw_mbrtowc_cp+0x188>
   140009480:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   140009484:	84 c0                	test   al,al
   140009486:	74 64                	je     1400094ec <__mingw_mbrtowc_cp+0x1ec>
   140009488:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   14000948e:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   140009492:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   140009496:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   140009499:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   1400094a0:	00 
   1400094a1:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   1400094a5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400094aa:	45 89 c1             	mov    r9d,r8d
   1400094ad:	49 89 c8             	mov    r8,rcx
   1400094b0:	ba 08 00 00 00       	mov    edx,0x8
   1400094b5:	89 c1                	mov    ecx,eax
   1400094b7:	48 8b 05 7a 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d7a]        # 140010238 <__imp_MultiByteToWideChar>
   1400094be:	ff d0                	call   rax
   1400094c0:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400094c3:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   1400094c7:	75 26                	jne    1400094ef <__mingw_mbrtowc_cp+0x1ef>
   1400094c9:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400094ce:	74 0b                	je     1400094db <__mingw_mbrtowc_cp+0x1db>
   1400094d0:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   1400094d4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400094d8:	66 89 10             	mov    WORD PTR [rax],dx
   1400094db:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400094df:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400094e5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400094e8:	48 98                	cdqe
   1400094ea:	eb 2e                	jmp    14000951a <__mingw_mbrtowc_cp+0x21a>
   1400094ec:	90                   	nop
   1400094ed:	eb 01                	jmp    1400094f0 <__mingw_mbrtowc_cp+0x1f0>
   1400094ef:	90                   	nop
   1400094f0:	e8 a3 01 00 00       	call   140009698 <_errno>
   1400094f5:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400094fb:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009502:	eb 16                	jmp    14000951a <__mingw_mbrtowc_cp+0x21a>
   140009504:	90                   	nop
   140009505:	eb 01                	jmp    140009508 <__mingw_mbrtowc_cp+0x208>
   140009507:	90                   	nop
   140009508:	e8 8b 01 00 00       	call   140009698 <_errno>
   14000950d:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009513:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000951a:	48 83 c4 50          	add    rsp,0x50
   14000951e:	5d                   	pop    rbp
   14000951f:	c3                   	ret

0000000140009520 <fallback_IsDBCSLeadByteEx>:
   140009520:	55                   	push   rbp
   140009521:	48 89 e5             	mov    rbp,rsp
   140009524:	48 83 ec 40          	sub    rsp,0x40
   140009528:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000952b:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   14000952e:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   140009532:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009535:	89 c1                	mov    ecx,eax
   140009537:	48 8b 05 c2 6c 00 00 	mov    rax,QWORD PTR [rip+0x6cc2]        # 140010200 <__imp_GetCPInfo>
   14000953e:	ff d0                	call   rax
   140009540:	85 c0                	test   eax,eax
   140009542:	74 51                	je     140009595 <fallback_IsDBCSLeadByteEx+0x75>
   140009544:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140009547:	83 f8 02             	cmp    eax,0x2
   14000954a:	75 49                	jne    140009595 <fallback_IsDBCSLeadByteEx+0x75>
   14000954c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009553:	eb 2c                	jmp    140009581 <fallback_IsDBCSLeadByteEx+0x61>
   140009555:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009558:	48 98                	cdqe
   14000955a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000955f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   140009562:	72 19                	jb     14000957d <fallback_IsDBCSLeadByteEx+0x5d>
   140009564:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009567:	83 c0 01             	add    eax,0x1
   14000956a:	48 98                	cdqe
   14000956c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009571:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   140009574:	72 07                	jb     14000957d <fallback_IsDBCSLeadByteEx+0x5d>
   140009576:	b8 01 00 00 00       	mov    eax,0x1
   14000957b:	eb 1d                	jmp    14000959a <fallback_IsDBCSLeadByteEx+0x7a>
   14000957d:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   140009581:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   140009585:	7f 0e                	jg     140009595 <fallback_IsDBCSLeadByteEx+0x75>
   140009587:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000958a:	48 98                	cdqe
   14000958c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009591:	84 c0                	test   al,al
   140009593:	75 c0                	jne    140009555 <fallback_IsDBCSLeadByteEx+0x35>
   140009595:	b8 00 00 00 00       	mov    eax,0x0
   14000959a:	48 83 c4 40          	add    rsp,0x40
   14000959e:	5d                   	pop    rbp
   14000959f:	c3                   	ret

00000001400095a0 <__mingw_isleadbyte_cp>:
   1400095a0:	55                   	push   rbp
   1400095a1:	48 89 e5             	mov    rbp,rsp
   1400095a4:	48 83 ec 40          	sub    rsp,0x40
   1400095a8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400095ab:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400095ae:	48 8b 05 eb 65 00 00 	mov    rax,QWORD PTR [rip+0x65eb]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400095b5:	48 85 c0             	test   rax,rax
   1400095b8:	75 71                	jne    14000962b <__mingw_isleadbyte_cp+0x8b>
   1400095ba:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400095c1:	00 
   1400095c2:	48 8d 05 67 1f 00 00 	lea    rax,[rip+0x1f67]        # 14000b530 <.rdata>
   1400095c9:	48 89 c1             	mov    rcx,rax
   1400095cc:	48 8b 05 3d 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c3d]        # 140010210 <__imp_GetModuleHandleA>
   1400095d3:	ff d0                	call   rax
   1400095d5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400095d9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400095de:	74 1b                	je     1400095fb <__mingw_isleadbyte_cp+0x5b>
   1400095e0:	48 8d 15 56 1f 00 00 	lea    rdx,[rip+0x1f56]        # 14000b53d <.rdata+0xd>
   1400095e7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400095eb:	48 89 c1             	mov    rcx,rax
   1400095ee:	48 8b 05 23 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c23]        # 140010218 <__imp_GetProcAddress>
   1400095f5:	ff d0                	call   rax
   1400095f7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400095fb:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140009600:	75 0b                	jne    14000960d <__mingw_isleadbyte_cp+0x6d>
   140009602:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 140009520 <fallback_IsDBCSLeadByteEx>
   140009609:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000960d:	48 8d 05 8c 65 00 00 	lea    rax,[rip+0x658c]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009614:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140009618:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000961c:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140009620:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140009624:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140009628:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000962b:	4c 8b 05 6e 65 00 00 	mov    r8,QWORD PTR [rip+0x656e]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009632:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009635:	0f b6 d0             	movzx  edx,al
   140009638:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000963b:	89 c1                	mov    ecx,eax
   14000963d:	41 ff d0             	call   r8
   140009640:	48 83 c4 40          	add    rsp,0x40
   140009644:	5d                   	pop    rbp
   140009645:	c3                   	ret
   140009646:	90                   	nop
   140009647:	90                   	nop
   140009648:	90                   	nop
   140009649:	90                   	nop
   14000964a:	90                   	nop
   14000964b:	90                   	nop
   14000964c:	90                   	nop
   14000964d:	90                   	nop
   14000964e:	90                   	nop
   14000964f:	90                   	nop

0000000140009650 <__C_specific_handler>:
   140009650:	ff 25 22 6c 00 00    	jmp    QWORD PTR [rip+0x6c22]        # 140010278 <__imp___C_specific_handler>
   140009656:	90                   	nop
   140009657:	90                   	nop

0000000140009658 <___lc_codepage_func>:
   140009658:	ff 25 22 6c 00 00    	jmp    QWORD PTR [rip+0x6c22]        # 140010280 <__imp____lc_codepage_func>
   14000965e:	90                   	nop
   14000965f:	90                   	nop

0000000140009660 <___mb_cur_max_func>:
   140009660:	ff 25 22 6c 00 00    	jmp    QWORD PTR [rip+0x6c22]        # 140010288 <__imp____mb_cur_max_func>
   140009666:	90                   	nop
   140009667:	90                   	nop

0000000140009668 <__getmainargs>:
   140009668:	ff 25 22 6c 00 00    	jmp    QWORD PTR [rip+0x6c22]        # 140010290 <__imp___getmainargs>
   14000966e:	90                   	nop
   14000966f:	90                   	nop

0000000140009670 <__iob_func>:
   140009670:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 1400102a0 <__imp___iob_func>
   140009676:	90                   	nop
   140009677:	90                   	nop

0000000140009678 <__set_app_type>:
   140009678:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 1400102a8 <__imp___set_app_type>
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <__setusermatherr>:
   140009680:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 1400102b0 <__imp___setusermatherr>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <_amsg_exit>:
   140009688:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 1400102b8 <__imp__amsg_exit>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <_cexit>:
   140009690:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 1400102c0 <__imp__cexit>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <_errno>:
   140009698:	ff 25 32 6c 00 00    	jmp    QWORD PTR [rip+0x6c32]        # 1400102d0 <__imp__errno>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <_initterm>:
   1400096a0:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 1400102e0 <__imp__initterm>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <_lock>:
   1400096a8:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 1400102e8 <__imp__lock>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <_unlock>:
   1400096b0:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 1400102f0 <__imp__unlock>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <_crt_atexit>:
   1400096b8:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 1400102f8 <__imp__crt_atexit>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <abort>:
   1400096c0:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010300 <__imp_abort>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <calloc>:
   1400096c8:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010308 <__imp_calloc>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <exit>:
   1400096d0:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010310 <__imp_exit>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <fflush>:
   1400096d8:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010318 <__imp_fflush>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <fprintf>:
   1400096e0:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010320 <__imp_fprintf>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop

00000001400096e8 <fputc>:
   1400096e8:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010328 <__imp_fputc>
   1400096ee:	90                   	nop
   1400096ef:	90                   	nop

00000001400096f0 <free>:
   1400096f0:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010330 <__imp_free>
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop

00000001400096f8 <localeconv>:
   1400096f8:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010338 <__imp_localeconv>
   1400096fe:	90                   	nop
   1400096ff:	90                   	nop

0000000140009700 <malloc>:
   140009700:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010340 <__imp_malloc>
   140009706:	90                   	nop
   140009707:	90                   	nop

0000000140009708 <memcpy>:
   140009708:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010348 <__imp_memcpy>
   14000970e:	90                   	nop
   14000970f:	90                   	nop

0000000140009710 <setvbuf>:
   140009710:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010350 <__imp_setvbuf>
   140009716:	90                   	nop
   140009717:	90                   	nop

0000000140009718 <signal>:
   140009718:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010358 <__imp_signal>
   14000971e:	90                   	nop
   14000971f:	90                   	nop

0000000140009720 <strerror>:
   140009720:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010360 <__imp_strerror>
   140009726:	90                   	nop
   140009727:	90                   	nop

0000000140009728 <strlen>:
   140009728:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010368 <__imp_strlen>
   14000972e:	90                   	nop
   14000972f:	90                   	nop

0000000140009730 <strncmp>:
   140009730:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010370 <__imp_strncmp>
   140009736:	90                   	nop
   140009737:	90                   	nop

0000000140009738 <vfprintf>:
   140009738:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010378 <__imp_vfprintf>
   14000973e:	90                   	nop
   14000973f:	90                   	nop

0000000140009740 <wcslen>:
   140009740:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 140010380 <__imp_wcslen>
   140009746:	90                   	nop
   140009747:	90                   	nop
   140009748:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000974f:	00 

0000000140009750 <WideCharToMultiByte>:
   140009750:	ff 25 12 6b 00 00    	jmp    QWORD PTR [rip+0x6b12]        # 140010268 <__imp_WideCharToMultiByte>
   140009756:	90                   	nop
   140009757:	90                   	nop

0000000140009758 <VirtualQuery>:
   140009758:	ff 25 02 6b 00 00    	jmp    QWORD PTR [rip+0x6b02]        # 140010260 <__imp_VirtualQuery>
   14000975e:	90                   	nop
   14000975f:	90                   	nop

0000000140009760 <VirtualProtect>:
   140009760:	ff 25 f2 6a 00 00    	jmp    QWORD PTR [rip+0x6af2]        # 140010258 <__imp_VirtualProtect>
   140009766:	90                   	nop
   140009767:	90                   	nop

0000000140009768 <TlsGetValue>:
   140009768:	ff 25 e2 6a 00 00    	jmp    QWORD PTR [rip+0x6ae2]        # 140010250 <__imp_TlsGetValue>
   14000976e:	90                   	nop
   14000976f:	90                   	nop

0000000140009770 <Sleep>:
   140009770:	ff 25 d2 6a 00 00    	jmp    QWORD PTR [rip+0x6ad2]        # 140010248 <__imp_Sleep>
   140009776:	90                   	nop
   140009777:	90                   	nop

0000000140009778 <SetUnhandledExceptionFilter>:
   140009778:	ff 25 c2 6a 00 00    	jmp    QWORD PTR [rip+0x6ac2]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   14000977e:	90                   	nop
   14000977f:	90                   	nop

0000000140009780 <MultiByteToWideChar>:
   140009780:	ff 25 b2 6a 00 00    	jmp    QWORD PTR [rip+0x6ab2]        # 140010238 <__imp_MultiByteToWideChar>
   140009786:	90                   	nop
   140009787:	90                   	nop

0000000140009788 <LoadLibraryA>:
   140009788:	ff 25 a2 6a 00 00    	jmp    QWORD PTR [rip+0x6aa2]        # 140010230 <__imp_LoadLibraryA>
   14000978e:	90                   	nop
   14000978f:	90                   	nop

0000000140009790 <LeaveCriticalSection>:
   140009790:	ff 25 92 6a 00 00    	jmp    QWORD PTR [rip+0x6a92]        # 140010228 <__imp_LeaveCriticalSection>
   140009796:	90                   	nop
   140009797:	90                   	nop

0000000140009798 <InitializeCriticalSection>:
   140009798:	ff 25 82 6a 00 00    	jmp    QWORD PTR [rip+0x6a82]        # 140010220 <__imp_InitializeCriticalSection>
   14000979e:	90                   	nop
   14000979f:	90                   	nop

00000001400097a0 <GetProcAddress>:
   1400097a0:	ff 25 72 6a 00 00    	jmp    QWORD PTR [rip+0x6a72]        # 140010218 <__imp_GetProcAddress>
   1400097a6:	90                   	nop
   1400097a7:	90                   	nop

00000001400097a8 <GetModuleHandleA>:
   1400097a8:	ff 25 62 6a 00 00    	jmp    QWORD PTR [rip+0x6a62]        # 140010210 <__imp_GetModuleHandleA>
   1400097ae:	90                   	nop
   1400097af:	90                   	nop

00000001400097b0 <GetLastError>:
   1400097b0:	ff 25 52 6a 00 00    	jmp    QWORD PTR [rip+0x6a52]        # 140010208 <__imp_GetLastError>
   1400097b6:	90                   	nop
   1400097b7:	90                   	nop

00000001400097b8 <GetCPInfo>:
   1400097b8:	ff 25 42 6a 00 00    	jmp    QWORD PTR [rip+0x6a42]        # 140010200 <__imp_GetCPInfo>
   1400097be:	90                   	nop
   1400097bf:	90                   	nop

00000001400097c0 <FreeLibrary>:
   1400097c0:	ff 25 32 6a 00 00    	jmp    QWORD PTR [rip+0x6a32]        # 1400101f8 <__imp_FreeLibrary>
   1400097c6:	90                   	nop
   1400097c7:	90                   	nop

00000001400097c8 <EnterCriticalSection>:
   1400097c8:	ff 25 22 6a 00 00    	jmp    QWORD PTR [rip+0x6a22]        # 1400101f0 <__imp_EnterCriticalSection>
   1400097ce:	90                   	nop
   1400097cf:	90                   	nop

00000001400097d0 <DeleteCriticalSection>:
   1400097d0:	ff 25 12 6a 00 00    	jmp    QWORD PTR [rip+0x6a12]        # 1400101e8 <__IAT_start__>
   1400097d6:	90                   	nop
   1400097d7:	90                   	nop
   1400097d8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   1400097df:	00 

00000001400097e0 <register_frame_ctor>:
   1400097e0:	e9 8b 7e ff ff       	jmp    140001670 <__gcc_register_frame>
   1400097e5:	90                   	nop
   1400097e6:	90                   	nop
   1400097e7:	90                   	nop
   1400097e8:	90                   	nop
   1400097e9:	90                   	nop
   1400097ea:	90                   	nop
   1400097eb:	90                   	nop
   1400097ec:	90                   	nop
   1400097ed:	90                   	nop
   1400097ee:	90                   	nop
   1400097ef:	90                   	nop
