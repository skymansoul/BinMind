
C:\Users\Administrator\Desktop\BinMind\round2\samples\uaf\cve_2023_32233_nft\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 9f 86 00 00       	call   1400096c8 <fflush>
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
   14000113b:	e8 38 85 00 00       	call   140009678 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 38 7f 00 00       	call   1400090a0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 7f 85 00 00       	call   140009700 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 17 85 00 00       	call   1400096b0 <abort>
   140001199:	e8 02 12 00 00       	call   1400023a0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 91 f0 00 00 	mov    rax,QWORD PTR [rip+0xf091]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 76 7e 00 00       	call   140009040 <_set_invalid_parameter_handler>
   1400011ca:	e8 e1 1a 00 00       	call   140002cb0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 77 84 00 00       	call   140009668 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 6b 84 00 00       	call   140009668 <__set_app_type>
   1400011fd:	e8 ee 7c 00 00       	call   140008ef0 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 ee 7c 00 00       	call   140008f00 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 5e 07 00 00       	call   140001980 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 43 84 00 00       	call   140009678 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 68 12 00 00       	call   1400024ba <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 16 7e 00 00       	call   140009080 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 10 7c 00 00       	call   140008e90 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 ea 83 00 00       	call   140009678 <_amsg_exit>
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
   1400012cb:	e8 88 83 00 00       	call   140009658 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 95 83 00 00       	call   140009678 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 6e 83 00 00       	call   140009678 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 70 83 00 00       	call   140009690 <_initterm>
   140001320:	e8 32 06 00 00       	call   140001957 <__main>
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
   14000138d:	e8 7e 7b 00 00       	call   140008f10 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 0e 04 00 00       	call   1400017c8 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 ef 82 00 00       	call   1400096c0 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 a0 82 00 00       	call   140009680 <_cexit>
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
   140001511:	e8 da 81 00 00       	call   1400096f0 <malloc>
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
   14000155c:	e8 b7 81 00 00       	call   140009718 <strlen>
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
   140001585:	e8 66 81 00 00       	call   1400096f0 <malloc>
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
   1400015e8:	e8 0b 81 00 00       	call   1400096f8 <memcpy>
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
   140001642:	e8 61 80 00 00       	call   1400096a8 <_crt_atexit>
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

0000000140001760 <nft_set_destroy>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 20          	sub    rsp,0x20
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001770:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140001774:	48 89 c1             	mov    rcx,rax
   140001777:	e8 64 7f 00 00       	call   1400096e0 <free>
   14000177c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001780:	48 89 c1             	mov    rcx,rax
   140001783:	e8 58 7f 00 00       	call   1400096e0 <free>
   140001788:	90                   	nop
   140001789:	48 83 c4 20          	add    rsp,0x20
   14000178d:	5d                   	pop    rbp
   14000178e:	c3                   	ret

000000014000178f <nft_lookup>:
   14000178f:	55                   	push   rbp
   140001790:	48 89 e5             	mov    rbp,rsp
   140001793:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001797:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000179b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000179e:	8b 10                	mov    edx,DWORD PTR [rax]
   1400017a0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017a4:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400017a7:	39 c2                	cmp    edx,eax
   1400017a9:	74 07                	je     1400017b2 <nft_lookup+0x23>
   1400017ab:	b8 00 00 00 00       	mov    eax,0x0
   1400017b0:	eb 14                	jmp    1400017c6 <nft_lookup+0x37>
   1400017b2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017b6:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017b9:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   1400017bd:	48 85 c0             	test   rax,rax
   1400017c0:	0f 95 c0             	setne  al
   1400017c3:	0f b6 c0             	movzx  eax,al
   1400017c6:	5d                   	pop    rbp
   1400017c7:	c3                   	ret

00000001400017c8 <main>:
   1400017c8:	55                   	push   rbp
   1400017c9:	53                   	push   rbx
   1400017ca:	48 83 ec 38          	sub    rsp,0x38
   1400017ce:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   1400017d3:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   1400017d6:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400017da:	e8 78 01 00 00       	call   140001957 <__main>
   1400017df:	b9 10 00 00 00       	mov    ecx,0x10
   1400017e4:	e8 07 7f 00 00       	call   1400096f0 <malloc>
   1400017e9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400017ed:	b9 18 00 00 00       	mov    ecx,0x18
   1400017f2:	e8 f9 7e 00 00       	call   1400096f0 <malloc>
   1400017f7:	48 89 c2             	mov    rdx,rax
   1400017fa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017fe:	48 89 10             	mov    QWORD PTR [rax],rdx
   140001801:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001805:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001808:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000180e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001812:	48 8b 18             	mov    rbx,QWORD PTR [rax]
   140001815:	b9 08 00 00 00       	mov    ecx,0x8
   14000181a:	e8 d1 7e 00 00       	call   1400096f0 <malloc>
   14000181f:	48 89 43 10          	mov    QWORD PTR [rbx+0x10],rax
   140001823:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001827:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000182a:	48 83 c0 04          	add    rax,0x4
   14000182e:	c7 00 61 6e 6f 6e    	mov    DWORD PTR [rax],0x6e6f6e61
   140001834:	66 c7 40 04 30 00    	mov    WORD PTR [rax+0x4],0x30
   14000183a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000183e:	c7 40 08 01 00 00 00 	mov    DWORD PTR [rax+0x8],0x1
   140001845:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001849:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000184c:	48 89 c1             	mov    rcx,rax
   14000184f:	e8 0c ff ff ff       	call   140001760 <nft_set_destroy>
   140001854:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001858:	48 89 c1             	mov    rcx,rax
   14000185b:	e8 2f ff ff ff       	call   14000178f <nft_lookup>
   140001860:	85 c0                	test   eax,eax
   140001862:	74 1a                	je     14000187e <main+0xb6>
   140001864:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001868:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000186b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000186f:	48 8d 05 da 97 00 00 	lea    rax,[rip+0x97da]        # 14000b050 <.rdata>
   140001876:	48 89 c1             	mov    rcx,rax
   140001879:	e8 32 19 00 00       	call   1400031b0 <__mingw_printf>
   14000187e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001882:	48 89 c1             	mov    rcx,rax
   140001885:	e8 56 7e 00 00       	call   1400096e0 <free>
   14000188a:	b8 00 00 00 00       	mov    eax,0x0
   14000188f:	48 83 c4 38          	add    rsp,0x38
   140001893:	5b                   	pop    rbx
   140001894:	5d                   	pop    rbp
   140001895:	c3                   	ret
   140001896:	90                   	nop
   140001897:	90                   	nop
   140001898:	90                   	nop
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
   1400018aa:	48 8b 05 5f 87 00 00 	mov    rax,QWORD PTR [rip+0x875f]        # 14000a010 <p.0>
   1400018b1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018b4:	ff d0                	call   rax
   1400018b6:	48 8b 05 53 87 00 00 	mov    rax,QWORD PTR [rip+0x8753]        # 14000a010 <p.0>
   1400018bd:	48 83 c0 08          	add    rax,0x8
   1400018c1:	48 89 05 48 87 00 00 	mov    QWORD PTR [rip+0x8748],rax        # 14000a010 <p.0>
   1400018c8:	48 8b 05 41 87 00 00 	mov    rax,QWORD PTR [rip+0x8741]        # 14000a010 <p.0>
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
   1400018e7:	48 8b 05 82 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c82]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018ee:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018f1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400018f4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400018f8:	75 25                	jne    14000191f <__do_global_ctors+0x40>
   1400018fa:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001901:	eb 04                	jmp    140001907 <__do_global_ctors+0x28>
   140001903:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001907:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000190a:	8d 50 01             	lea    edx,[rax+0x1]
   14000190d:	48 8b 05 5c 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c5c]        # 14000b570 <.refptr.__CTOR_LIST__>
   140001914:	89 d2                	mov    edx,edx
   140001916:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000191a:	48 85 c0             	test   rax,rax
   14000191d:	75 e4                	jne    140001903 <__do_global_ctors+0x24>
   14000191f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001922:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001925:	eb 14                	jmp    14000193b <__do_global_ctors+0x5c>
   140001927:	48 8b 05 42 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c42]        # 14000b570 <.refptr.__CTOR_LIST__>
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
   14000195f:	8b 05 1b d7 00 00    	mov    eax,DWORD PTR [rip+0xd71b]        # 14000f080 <initialized>
   140001965:	85 c0                	test   eax,eax
   140001967:	75 0f                	jne    140001978 <__main+0x21>
   140001969:	c7 05 0d d7 00 00 01 	mov    DWORD PTR [rip+0xd70d],0x1        # 14000f080 <initialized>
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
   1400019a3:	48 8b 05 a6 9b 00 00 	mov    rax,QWORD PTR [rip+0x9ba6]        # 14000b550 <.refptr._CRT_MT>
   1400019aa:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019ac:	83 f8 02             	cmp    eax,0x2
   1400019af:	74 0d                	je     1400019be <__dyn_tls_init+0x2e>
   1400019b1:	48 8b 05 98 9b 00 00 	mov    rax,QWORD PTR [rip+0x9b98]        # 14000b550 <.refptr._CRT_MT>
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
   1400019e2:	48 8d 05 ef 9e 00 00 	lea    rax,[rip+0x9eef]        # 14000b8d8 <___crt_xd_start__>
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
   140001a16:	48 8d 05 c3 9e 00 00 	lea    rax,[rip+0x9ec3]        # 14000b8e0 <__xd_z>
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
   140001ae9:	48 8d 05 b0 95 00 00 	lea    rax,[rip+0x95b0]        # 14000b0a0 <.rdata>
   140001af0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001af4:	eb 4d                	jmp    140001b43 <_matherr+0xb3>
   140001af6:	48 8d 05 c2 95 00 00 	lea    rax,[rip+0x95c2]        # 14000b0bf <.rdata+0x1f>
   140001afd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b01:	eb 40                	jmp    140001b43 <_matherr+0xb3>
   140001b03:	48 8d 05 d6 95 00 00 	lea    rax,[rip+0x95d6]        # 14000b0e0 <.rdata+0x40>
   140001b0a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b0e:	eb 33                	jmp    140001b43 <_matherr+0xb3>
   140001b10:	48 8d 05 e9 95 00 00 	lea    rax,[rip+0x95e9]        # 14000b100 <.rdata+0x60>
   140001b17:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b1b:	eb 26                	jmp    140001b43 <_matherr+0xb3>
   140001b1d:	48 8d 05 04 96 00 00 	lea    rax,[rip+0x9604]        # 14000b128 <.rdata+0x88>
   140001b24:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b28:	eb 19                	jmp    140001b43 <_matherr+0xb3>
   140001b2a:	48 8d 05 1f 96 00 00 	lea    rax,[rip+0x961f]        # 14000b150 <.rdata+0xb0>
   140001b31:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b35:	eb 0c                	jmp    140001b43 <_matherr+0xb3>
   140001b37:	48 8d 05 48 96 00 00 	lea    rax,[rip+0x9648]        # 14000b186 <.rdata+0xe6>
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
   140001b6c:	e8 2f 75 00 00       	call   1400090a0 <__acrt_iob_func>
   140001b71:	48 89 c1             	mov    rcx,rax
   140001b74:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b78:	48 8d 05 19 96 00 00 	lea    rax,[rip+0x9619]        # 14000b198 <.rdata+0xf8>
   140001b7f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b86:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b8c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b92:	49 89 d9             	mov    r9,rbx
   140001b95:	49 89 d0             	mov    r8,rdx
   140001b98:	48 89 c2             	mov    rdx,rax
   140001b9b:	e8 30 7b 00 00       	call   1400096d0 <fprintf>
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
   140001be8:	e8 b3 74 00 00       	call   1400090a0 <__acrt_iob_func>
   140001bed:	48 89 c1             	mov    rcx,rax
   140001bf0:	48 8d 05 d9 95 00 00 	lea    rax,[rip+0x95d9]        # 14000b1d0 <.rdata>
   140001bf7:	48 89 c2             	mov    rdx,rax
   140001bfa:	e8 d1 7a 00 00       	call   1400096d0 <fprintf>
   140001bff:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001c03:	b9 02 00 00 00       	mov    ecx,0x2
   140001c08:	e8 93 74 00 00       	call   1400090a0 <__acrt_iob_func>
   140001c0d:	48 89 c1             	mov    rcx,rax
   140001c10:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001c14:	49 89 d8             	mov    r8,rbx
   140001c17:	48 89 c2             	mov    rdx,rax
   140001c1a:	e8 09 7b 00 00       	call   140009728 <vfprintf>
   140001c1f:	e8 8c 7a 00 00       	call   1400096b0 <abort>
   140001c24:	90                   	nop

0000000140001c25 <mark_section_writable>:
   140001c25:	55                   	push   rbp
   140001c26:	48 89 e5             	mov    rbp,rsp
   140001c29:	48 83 ec 60          	sub    rsp,0x60
   140001c2d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001c31:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001c38:	e9 82 00 00 00       	jmp    140001cbf <mark_section_writable+0x9a>
   140001c3d:	48 8b 0d 9c d4 00 00 	mov    rcx,QWORD PTR [rip+0xd49c]        # 14000f0e0 <the_secs>
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
   140001c65:	48 8b 0d 74 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd474]        # 14000f0e0 <the_secs>
   140001c6c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c6f:	48 63 d0             	movsxd rdx,eax
   140001c72:	48 89 d0             	mov    rax,rdx
   140001c75:	48 c1 e0 02          	shl    rax,0x2
   140001c79:	48 01 d0             	add    rax,rdx
   140001c7c:	48 c1 e0 03          	shl    rax,0x3
   140001c80:	48 01 c8             	add    rax,rcx
   140001c83:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c87:	4c 8b 05 52 d4 00 00 	mov    r8,QWORD PTR [rip+0xd452]        # 14000f0e0 <the_secs>
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
   140001cbf:	8b 05 23 d4 00 00    	mov    eax,DWORD PTR [rip+0xd423]        # 14000f0e8 <maxSections>
   140001cc5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001cc8:	0f 8c 6f ff ff ff    	jl     140001c3d <mark_section_writable+0x18>
   140001cce:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001cd2:	48 89 c1             	mov    rcx,rax
   140001cd5:	e8 c1 11 00 00       	call   140002e9b <__mingw_GetSectionForAddress>
   140001cda:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001cde:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001ce3:	75 13                	jne    140001cf8 <mark_section_writable+0xd3>
   140001ce5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001ce9:	48 8d 0d 00 95 00 00 	lea    rcx,[rip+0x9500]        # 14000b1f0 <.rdata+0x20>
   140001cf0:	48 89 c2             	mov    rdx,rax
   140001cf3:	e8 c8 fe ff ff       	call   140001bc0 <__report_error>
   140001cf8:	48 8b 0d e1 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3e1]        # 14000f0e0 <the_secs>
   140001cff:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d02:	48 63 d0             	movsxd rdx,eax
   140001d05:	48 89 d0             	mov    rax,rdx
   140001d08:	48 c1 e0 02          	shl    rax,0x2
   140001d0c:	48 01 d0             	add    rax,rdx
   140001d0f:	48 c1 e0 03          	shl    rax,0x3
   140001d13:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d17:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d1b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001d1f:	48 8b 0d ba d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3ba]        # 14000f0e0 <the_secs>
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
   140001d55:	4c 8b 05 84 d3 00 00 	mov    r8,QWORD PTR [rip+0xd384]        # 14000f0e0 <the_secs>
   140001d5c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d5f:	48 63 d0             	movsxd rdx,eax
   140001d62:	48 89 d0             	mov    rax,rdx
   140001d65:	48 c1 e0 02          	shl    rax,0x2
   140001d69:	48 01 d0             	add    rax,rdx
   140001d6c:	48 c1 e0 03          	shl    rax,0x3
   140001d70:	4c 01 c0             	add    rax,r8
   140001d73:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d77:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d7b:	48 8b 0d 5e d3 00 00 	mov    rcx,QWORD PTR [rip+0xd35e]        # 14000f0e0 <the_secs>
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
   140001daa:	48 8b 05 af e4 00 00 	mov    rax,QWORD PTR [rip+0xe4af]        # 140010260 <__imp_VirtualQuery>
   140001db1:	ff d0                	call   rax
   140001db3:	48 85 c0             	test   rax,rax
   140001db6:	75 3f                	jne    140001df7 <mark_section_writable+0x1d2>
   140001db8:	48 8b 0d 21 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd321]        # 14000f0e0 <the_secs>
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
   140001de3:	48 8d 05 26 94 00 00 	lea    rax,[rip+0x9426]        # 14000b210 <.rdata+0x40>
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
   140001e41:	48 8b 0d 98 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd298]        # 14000f0e0 <the_secs>
   140001e48:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e4b:	48 63 d0             	movsxd rdx,eax
   140001e4e:	48 89 d0             	mov    rax,rdx
   140001e51:	48 c1 e0 02          	shl    rax,0x2
   140001e55:	48 01 d0             	add    rax,rdx
   140001e58:	48 c1 e0 03          	shl    rax,0x3
   140001e5c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e60:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e64:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e68:	48 8b 0d 71 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd271]        # 14000f0e0 <the_secs>
   140001e6f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e72:	48 63 d0             	movsxd rdx,eax
   140001e75:	48 89 d0             	mov    rax,rdx
   140001e78:	48 c1 e0 02          	shl    rax,0x2
   140001e7c:	48 01 d0             	add    rax,rdx
   140001e7f:	48 c1 e0 03          	shl    rax,0x3
   140001e83:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e87:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e8b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e8f:	48 8b 0d 4a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd24a]        # 14000f0e0 <the_secs>
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
   140001ec4:	48 8b 05 8d e3 00 00 	mov    rax,QWORD PTR [rip+0xe38d]        # 140010258 <__imp_VirtualProtect>
   140001ecb:	ff d0                	call   rax
   140001ecd:	85 c0                	test   eax,eax
   140001ecf:	75 1a                	jne    140001eeb <mark_section_writable+0x2c6>
   140001ed1:	48 8b 05 30 e3 00 00 	mov    rax,QWORD PTR [rip+0xe330]        # 140010208 <__imp_GetLastError>
   140001ed8:	ff d0                	call   rax
   140001eda:	89 c2                	mov    edx,eax
   140001edc:	48 8d 05 65 93 00 00 	lea    rax,[rip+0x9365]        # 14000b248 <.rdata+0x78>
   140001ee3:	48 89 c1             	mov    rcx,rax
   140001ee6:	e8 d5 fc ff ff       	call   140001bc0 <__report_error>
   140001eeb:	8b 05 f7 d1 00 00    	mov    eax,DWORD PTR [rip+0xd1f7]        # 14000f0e8 <maxSections>
   140001ef1:	83 c0 01             	add    eax,0x1
   140001ef4:	89 05 ee d1 00 00    	mov    DWORD PTR [rip+0xd1ee],eax        # 14000f0e8 <maxSections>
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
   140001f17:	48 8b 0d c2 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd1c2]        # 14000f0e0 <the_secs>
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
   140001f3f:	48 8b 0d 9a d1 00 00 	mov    rcx,QWORD PTR [rip+0xd19a]        # 14000f0e0 <the_secs>
   140001f46:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f49:	48 63 d0             	movsxd rdx,eax
   140001f4c:	48 89 d0             	mov    rax,rdx
   140001f4f:	48 c1 e0 02          	shl    rax,0x2
   140001f53:	48 01 d0             	add    rax,rdx
   140001f56:	48 c1 e0 03          	shl    rax,0x3
   140001f5a:	48 01 c8             	add    rax,rcx
   140001f5d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f60:	48 8b 0d 79 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd179]        # 14000f0e0 <the_secs>
   140001f67:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f6a:	48 63 d0             	movsxd rdx,eax
   140001f6d:	48 89 d0             	mov    rax,rdx
   140001f70:	48 c1 e0 02          	shl    rax,0x2
   140001f74:	48 01 d0             	add    rax,rdx
   140001f77:	48 c1 e0 03          	shl    rax,0x3
   140001f7b:	48 01 c8             	add    rax,rcx
   140001f7e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f82:	4c 8b 05 57 d1 00 00 	mov    r8,QWORD PTR [rip+0xd157]        # 14000f0e0 <the_secs>
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
   140001fb4:	48 8b 05 9d e2 00 00 	mov    rax,QWORD PTR [rip+0xe29d]        # 140010258 <__imp_VirtualProtect>
   140001fbb:	ff d0                	call   rax
   140001fbd:	eb 01                	jmp    140001fc0 <restore_modified_sections+0xbd>
   140001fbf:	90                   	nop
   140001fc0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001fc4:	8b 05 1e d1 00 00    	mov    eax,DWORD PTR [rip+0xd11e]        # 14000f0e8 <maxSections>
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
   140002014:	e8 df 76 00 00       	call   1400096f8 <memcpy>
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
   140002104:	48 8d 05 65 91 00 00 	lea    rax,[rip+0x9165]        # 14000b270 <.rdata+0xa0>
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
   14000223e:	48 8d 0d 63 90 00 00 	lea    rcx,[rip+0x9063]        # 14000b2a8 <.rdata+0xd8>
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
   1400022e8:	48 8d 0d e9 8f 00 00 	lea    rcx,[rip+0x8fe9]        # 14000b2d8 <.rdata+0x108>
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
   1400023a8:	8b 05 3e cd 00 00    	mov    eax,DWORD PTR [rip+0xcd3e]        # 14000f0ec <was_init.0>
   1400023ae:	85 c0                	test   eax,eax
   1400023b0:	0f 85 88 00 00 00    	jne    14000243e <_pei386_runtime_relocator+0x9e>
   1400023b6:	8b 05 30 cd 00 00    	mov    eax,DWORD PTR [rip+0xcd30]        # 14000f0ec <was_init.0>
   1400023bc:	83 c0 01             	add    eax,0x1
   1400023bf:	89 05 27 cd 00 00    	mov    DWORD PTR [rip+0xcd27],eax        # 14000f0ec <was_init.0>
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
   140002406:	48 89 05 d3 cc 00 00 	mov    QWORD PTR [rip+0xccd3],rax        # 14000f0e0 <the_secs>
   14000240d:	c7 05 d1 cc 00 00 00 	mov    DWORD PTR [rip+0xccd1],0x0        # 14000f0e8 <maxSections>
   140002414:	00 00 00 
   140002417:	48 8b 0d 62 91 00 00 	mov    rcx,QWORD PTR [rip+0x9162]        # 14000b580 <.refptr.__ImageBase>
   14000241e:	48 8b 15 6b 91 00 00 	mov    rdx,QWORD PTR [rip+0x916b]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002425:	48 8b 05 74 91 00 00 	mov    rax,QWORD PTR [rip+0x9174]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
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
   140002469:	48 8b 05 80 cc 00 00 	mov    rax,QWORD PTR [rip+0xcc80]        # 14000f0f0 <stUserMathErr>
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
   1400024a1:	48 8b 15 48 cc 00 00 	mov    rdx,QWORD PTR [rip+0xcc48]        # 14000f0f0 <stUserMathErr>
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
   1400024ca:	48 89 05 1f cc 00 00 	mov    QWORD PTR [rip+0xcc1f],rax        # 14000f0f0 <stUserMathErr>
   1400024d1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024d5:	48 89 c1             	mov    rcx,rax
   1400024d8:	e8 93 71 00 00       	call   140009670 <__setusermatherr>
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
   14000262e:	e8 d5 70 00 00       	call   140009708 <signal>
   140002633:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002637:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000263c:	75 1b                	jne    140002659 <__mingw_SEH_error_handler+0x169>
   14000263e:	ba 01 00 00 00       	mov    edx,0x1
   140002643:	b9 0b 00 00 00       	mov    ecx,0xb
   140002648:	e8 bb 70 00 00       	call   140009708 <signal>
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
   140002685:	e8 7e 70 00 00       	call   140009708 <signal>
   14000268a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000268e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002693:	75 1b                	jne    1400026b0 <__mingw_SEH_error_handler+0x1c0>
   140002695:	ba 01 00 00 00       	mov    edx,0x1
   14000269a:	b9 04 00 00 00       	mov    ecx,0x4
   14000269f:	e8 64 70 00 00       	call   140009708 <signal>
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
   1400026e0:	e8 23 70 00 00       	call   140009708 <signal>
   1400026e5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026e9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026ee:	75 23                	jne    140002713 <__mingw_SEH_error_handler+0x223>
   1400026f0:	ba 01 00 00 00       	mov    edx,0x1
   1400026f5:	b9 08 00 00 00       	mov    ecx,0x8
   1400026fa:	e8 09 70 00 00       	call   140009708 <signal>
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
   14000286d:	e8 96 6e 00 00       	call   140009708 <signal>
   140002872:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002876:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000287b:	75 1b                	jne    140002898 <_gnu_exception_handler+0x14e>
   14000287d:	ba 01 00 00 00       	mov    edx,0x1
   140002882:	b9 0b 00 00 00       	mov    ecx,0xb
   140002887:	e8 7c 6e 00 00       	call   140009708 <signal>
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
   1400028c4:	e8 3f 6e 00 00       	call   140009708 <signal>
   1400028c9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028cd:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028d2:	75 1b                	jne    1400028ef <_gnu_exception_handler+0x1a5>
   1400028d4:	ba 01 00 00 00       	mov    edx,0x1
   1400028d9:	b9 04 00 00 00       	mov    ecx,0x4
   1400028de:	e8 25 6e 00 00       	call   140009708 <signal>
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
   14000291f:	e8 e4 6d 00 00       	call   140009708 <signal>
   140002924:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002928:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000292d:	75 23                	jne    140002952 <_gnu_exception_handler+0x208>
   14000292f:	ba 01 00 00 00       	mov    edx,0x1
   140002934:	b9 08 00 00 00       	mov    ecx,0x8
   140002939:	e8 ca 6d 00 00       	call   140009708 <signal>
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
   140002986:	48 8b 05 83 c7 00 00 	mov    rax,QWORD PTR [rip+0xc783]        # 14000f110 <__mingw_oldexcpt_handler>
   14000298d:	48 85 c0             	test   rax,rax
   140002990:	74 13                	je     1400029a5 <_gnu_exception_handler+0x25b>
   140002992:	48 8b 15 77 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc777]        # 14000f110 <__mingw_oldexcpt_handler>
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
   1400029bf:	8b 05 83 c7 00 00    	mov    eax,DWORD PTR [rip+0xc783]        # 14000f148 <__mingwthr_cs_init>
   1400029c5:	85 c0                	test   eax,eax
   1400029c7:	75 07                	jne    1400029d0 <___w64_mingwthr_add_key_dtor+0x20>
   1400029c9:	b8 00 00 00 00       	mov    eax,0x0
   1400029ce:	eb 7b                	jmp    140002a4b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029d0:	ba 18 00 00 00       	mov    edx,0x18
   1400029d5:	b9 01 00 00 00       	mov    ecx,0x1
   1400029da:	e8 d9 6c 00 00       	call   1400096b8 <calloc>
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
   140002a06:	48 8d 05 13 c7 00 00 	lea    rax,[rip+0xc713]        # 14000f120 <__mingwthr_cs>
   140002a0d:	48 89 c1             	mov    rcx,rax
   140002a10:	48 8b 05 d9 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7d9]        # 1400101f0 <__imp_EnterCriticalSection>
   140002a17:	ff d0                	call   rax
   140002a19:	48 8b 15 30 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc730]        # 14000f150 <key_dtor_list>
   140002a20:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a24:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a28:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a2c:	48 89 05 1d c7 00 00 	mov    QWORD PTR [rip+0xc71d],rax        # 14000f150 <key_dtor_list>
   140002a33:	48 8d 05 e6 c6 00 00 	lea    rax,[rip+0xc6e6]        # 14000f120 <__mingwthr_cs>
   140002a3a:	48 89 c1             	mov    rcx,rax
   140002a3d:	48 8b 05 e4 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7e4]        # 140010228 <__imp_LeaveCriticalSection>
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
   140002a5c:	8b 05 e6 c6 00 00    	mov    eax,DWORD PTR [rip+0xc6e6]        # 14000f148 <__mingwthr_cs_init>
   140002a62:	85 c0                	test   eax,eax
   140002a64:	75 0a                	jne    140002a70 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a66:	b8 00 00 00 00       	mov    eax,0x0
   140002a6b:	e9 9c 00 00 00       	jmp    140002b0c <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a70:	48 8d 05 a9 c6 00 00 	lea    rax,[rip+0xc6a9]        # 14000f120 <__mingwthr_cs>
   140002a77:	48 89 c1             	mov    rcx,rax
   140002a7a:	48 8b 05 6f d7 00 00 	mov    rax,QWORD PTR [rip+0xd76f]        # 1400101f0 <__imp_EnterCriticalSection>
   140002a81:	ff d0                	call   rax
   140002a83:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a8a:	00 
   140002a8b:	48 8b 05 be c6 00 00 	mov    rax,QWORD PTR [rip+0xc6be]        # 14000f150 <key_dtor_list>
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
   140002ab2:	48 89 05 97 c6 00 00 	mov    QWORD PTR [rip+0xc697],rax        # 14000f150 <key_dtor_list>
   140002ab9:	eb 10                	jmp    140002acb <___w64_mingwthr_remove_key_dtor+0x7a>
   140002abb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002abf:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002ac3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ac7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002acb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002acf:	48 89 c1             	mov    rcx,rax
   140002ad2:	e8 09 6c 00 00       	call   1400096e0 <free>
   140002ad7:	eb 1b                	jmp    140002af4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002ad9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002add:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ae1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ae5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ae9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002aed:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002af2:	75 a4                	jne    140002a98 <___w64_mingwthr_remove_key_dtor+0x47>
   140002af4:	48 8d 05 25 c6 00 00 	lea    rax,[rip+0xc625]        # 14000f120 <__mingwthr_cs>
   140002afb:	48 89 c1             	mov    rcx,rax
   140002afe:	48 8b 05 23 d7 00 00 	mov    rax,QWORD PTR [rip+0xd723]        # 140010228 <__imp_LeaveCriticalSection>
   140002b05:	ff d0                	call   rax
   140002b07:	b8 00 00 00 00       	mov    eax,0x0
   140002b0c:	48 83 c4 30          	add    rsp,0x30
   140002b10:	5d                   	pop    rbp
   140002b11:	c3                   	ret

0000000140002b12 <__mingwthr_run_key_dtors>:
   140002b12:	55                   	push   rbp
   140002b13:	48 89 e5             	mov    rbp,rsp
   140002b16:	48 83 ec 30          	sub    rsp,0x30
   140002b1a:	8b 05 28 c6 00 00    	mov    eax,DWORD PTR [rip+0xc628]        # 14000f148 <__mingwthr_cs_init>
   140002b20:	85 c0                	test   eax,eax
   140002b22:	0f 84 82 00 00 00    	je     140002baa <__mingwthr_run_key_dtors+0x98>
   140002b28:	48 8d 05 f1 c5 00 00 	lea    rax,[rip+0xc5f1]        # 14000f120 <__mingwthr_cs>
   140002b2f:	48 89 c1             	mov    rcx,rax
   140002b32:	48 8b 05 b7 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6b7]        # 1400101f0 <__imp_EnterCriticalSection>
   140002b39:	ff d0                	call   rax
   140002b3b:	48 8b 05 0e c6 00 00 	mov    rax,QWORD PTR [rip+0xc60e]        # 14000f150 <key_dtor_list>
   140002b42:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b46:	eb 46                	jmp    140002b8e <__mingwthr_run_key_dtors+0x7c>
   140002b48:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b4c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b4e:	89 c1                	mov    ecx,eax
   140002b50:	48 8b 05 f9 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6f9]        # 140010250 <__imp_TlsGetValue>
   140002b57:	ff d0                	call   rax
   140002b59:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b5d:	48 8b 05 a4 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6a4]        # 140010208 <__imp_GetLastError>
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
   140002b95:	48 8d 05 84 c5 00 00 	lea    rax,[rip+0xc584]        # 14000f120 <__mingwthr_cs>
   140002b9c:	48 89 c1             	mov    rcx,rax
   140002b9f:	48 8b 05 82 d6 00 00 	mov    rax,QWORD PTR [rip+0xd682]        # 140010228 <__imp_LeaveCriticalSection>
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
   140002bfc:	8b 05 46 c5 00 00    	mov    eax,DWORD PTR [rip+0xc546]        # 14000f148 <__mingwthr_cs_init>
   140002c02:	85 c0                	test   eax,eax
   140002c04:	75 13                	jne    140002c19 <__mingw_TLScallback+0x68>
   140002c06:	48 8d 05 13 c5 00 00 	lea    rax,[rip+0xc513]        # 14000f120 <__mingwthr_cs>
   140002c0d:	48 89 c1             	mov    rcx,rax
   140002c10:	48 8b 05 09 d6 00 00 	mov    rax,QWORD PTR [rip+0xd609]        # 140010220 <__imp_InitializeCriticalSection>
   140002c17:	ff d0                	call   rax
   140002c19:	c7 05 25 c5 00 00 01 	mov    DWORD PTR [rip+0xc525],0x1        # 14000f148 <__mingwthr_cs_init>
   140002c20:	00 00 00 
   140002c23:	eb 7d                	jmp    140002ca2 <__mingw_TLScallback+0xf1>
   140002c25:	e8 e8 fe ff ff       	call   140002b12 <__mingwthr_run_key_dtors>
   140002c2a:	8b 05 18 c5 00 00    	mov    eax,DWORD PTR [rip+0xc518]        # 14000f148 <__mingwthr_cs_init>
   140002c30:	83 f8 01             	cmp    eax,0x1
   140002c33:	75 6c                	jne    140002ca1 <__mingw_TLScallback+0xf0>
   140002c35:	48 8b 05 14 c5 00 00 	mov    rax,QWORD PTR [rip+0xc514]        # 14000f150 <key_dtor_list>
   140002c3c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c40:	eb 20                	jmp    140002c62 <__mingw_TLScallback+0xb1>
   140002c42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c46:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c4a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c4e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c52:	48 89 c1             	mov    rcx,rax
   140002c55:	e8 86 6a 00 00       	call   1400096e0 <free>
   140002c5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c5e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c62:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c67:	75 d9                	jne    140002c42 <__mingw_TLScallback+0x91>
   140002c69:	48 c7 05 dc c4 00 00 	mov    QWORD PTR [rip+0xc4dc],0x0        # 14000f150 <key_dtor_list>
   140002c70:	00 00 00 00 
   140002c74:	c7 05 ca c4 00 00 00 	mov    DWORD PTR [rip+0xc4ca],0x0        # 14000f148 <__mingwthr_cs_init>
   140002c7b:	00 00 00 
   140002c7e:	48 8d 05 9b c4 00 00 	lea    rax,[rip+0xc49b]        # 14000f120 <__mingwthr_cs>
   140002c85:	48 89 c1             	mov    rcx,rax
   140002c88:	48 8b 05 59 d5 00 00 	mov    rax,QWORD PTR [rip+0xd559]        # 1400101e8 <__IAT_start__>
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
   140002de8:	e8 2b 69 00 00       	call   140009718 <strlen>
   140002ded:	48 83 f8 08          	cmp    rax,0x8
   140002df1:	76 0a                	jbe    140002dfd <_FindPESectionByName+0x28>
   140002df3:	b8 00 00 00 00       	mov    eax,0x0
   140002df8:	e9 98 00 00 00       	jmp    140002e95 <_FindPESectionByName+0xc0>
   140002dfd:	48 8b 05 7c 87 00 00 	mov    rax,QWORD PTR [rip+0x877c]        # 14000b580 <.refptr.__ImageBase>
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
   140002e68:	e8 b3 68 00 00       	call   140009720 <strncmp>
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
   140002ea7:	48 8b 05 d2 86 00 00 	mov    rax,QWORD PTR [rip+0x86d2]        # 14000b580 <.refptr.__ImageBase>
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
   140002ef3:	48 8b 05 86 86 00 00 	mov    rax,QWORD PTR [rip+0x8686]        # 14000b580 <.refptr.__ImageBase>
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
   140002f47:	48 8b 05 32 86 00 00 	mov    rax,QWORD PTR [rip+0x8632]        # 14000b580 <.refptr.__ImageBase>
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
   140002fef:	48 8b 05 8a 85 00 00 	mov    rax,QWORD PTR [rip+0x858a]        # 14000b580 <.refptr.__ImageBase>
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
   140003027:	48 8b 05 52 85 00 00 	mov    rax,QWORD PTR [rip+0x8552]        # 14000b580 <.refptr.__ImageBase>
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
   140003097:	48 8b 05 e2 84 00 00 	mov    rax,QWORD PTR [rip+0x84e2]        # 14000b580 <.refptr.__ImageBase>
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

00000001400031b0 <__mingw_printf>:
   1400031b0:	55                   	push   rbp
   1400031b1:	53                   	push   rbx
   1400031b2:	48 83 ec 48          	sub    rsp,0x48
   1400031b6:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   1400031bb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400031bf:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400031c3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400031c7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   1400031cb:	48 8d 45 28          	lea    rax,[rbp+0x28]
   1400031cf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031d3:	b9 01 00 00 00       	mov    ecx,0x1
   1400031d8:	e8 c3 5e 00 00       	call   1400090a0 <__acrt_iob_func>
   1400031dd:	48 89 c1             	mov    rcx,rax
   1400031e0:	e8 3b 5d 00 00       	call   140008f20 <_lock_file>
   1400031e5:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   1400031e9:	b9 01 00 00 00       	mov    ecx,0x1
   1400031ee:	e8 ad 5e 00 00       	call   1400090a0 <__acrt_iob_func>
   1400031f3:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400031f7:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
   1400031fc:	49 89 d1             	mov    r9,rdx
   1400031ff:	41 b8 00 00 00 00    	mov    r8d,0x0
   140003205:	48 89 c2             	mov    rdx,rax
   140003208:	b9 00 60 00 00       	mov    ecx,0x6000
   14000320d:	e8 b1 1f 00 00       	call   1400051c3 <__mingw_pformat>
   140003212:	89 c3                	mov    ebx,eax
   140003214:	b9 01 00 00 00       	mov    ecx,0x1
   140003219:	e8 82 5e 00 00       	call   1400090a0 <__acrt_iob_func>
   14000321e:	48 89 c1             	mov    rcx,rax
   140003221:	e8 84 5d 00 00       	call   140008faa <_unlock_file>
   140003226:	89 d8                	mov    eax,ebx
   140003228:	48 83 c4 48          	add    rsp,0x48
   14000322c:	5b                   	pop    rbx
   14000322d:	5d                   	pop    rbp
   14000322e:	c3                   	ret
   14000322f:	90                   	nop

0000000140003230 <__pformat_putc>:
   140003230:	55                   	push   rbp
   140003231:	48 89 e5             	mov    rbp,rsp
   140003234:	48 83 ec 20          	sub    rsp,0x20
   140003238:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000323b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000323f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003243:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003246:	25 00 40 00 00       	and    eax,0x4000
   14000324b:	85 c0                	test   eax,eax
   14000324d:	75 12                	jne    140003261 <__pformat_putc+0x31>
   14000324f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003253:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   140003256:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000325a:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000325d:	39 c2                	cmp    edx,eax
   14000325f:	7e 3b                	jle    14000329c <__pformat_putc+0x6c>
   140003261:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003265:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003268:	25 00 20 00 00       	and    eax,0x2000
   14000326d:	85 c0                	test   eax,eax
   14000326f:	74 13                	je     140003284 <__pformat_putc+0x54>
   140003271:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003275:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003278:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000327b:	89 c1                	mov    ecx,eax
   14000327d:	e8 56 64 00 00       	call   1400096d8 <fputc>
   140003282:	eb 18                	jmp    14000329c <__pformat_putc+0x6c>
   140003284:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003288:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   14000328b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000328f:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003292:	48 98                	cdqe
   140003294:	48 01 d0             	add    rax,rdx
   140003297:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   14000329a:	88 10                	mov    BYTE PTR [rax],dl
   14000329c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032a0:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400032a3:	8d 50 01             	lea    edx,[rax+0x1]
   1400032a6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032aa:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   1400032ad:	90                   	nop
   1400032ae:	48 83 c4 20          	add    rsp,0x20
   1400032b2:	5d                   	pop    rbp
   1400032b3:	c3                   	ret

00000001400032b4 <__pformat_putchars>:
   1400032b4:	55                   	push   rbp
   1400032b5:	48 89 e5             	mov    rbp,rsp
   1400032b8:	48 83 ec 20          	sub    rsp,0x20
   1400032bc:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400032c0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400032c3:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400032c7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032cb:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032ce:	85 c0                	test   eax,eax
   1400032d0:	78 16                	js     1400032e8 <__pformat_putchars+0x34>
   1400032d2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032d6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032d9:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400032dc:	7e 0a                	jle    1400032e8 <__pformat_putchars+0x34>
   1400032de:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032e2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032e5:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400032e8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032ec:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032ef:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400032f2:	7d 15                	jge    140003309 <__pformat_putchars+0x55>
   1400032f4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032f8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032fb:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400032fe:	89 c2                	mov    edx,eax
   140003300:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003304:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003307:	eb 0b                	jmp    140003314 <__pformat_putchars+0x60>
   140003309:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000330d:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003314:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003318:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000331b:	85 c0                	test   eax,eax
   14000331d:	7e 57                	jle    140003376 <__pformat_putchars+0xc2>
   14000331f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003323:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003326:	25 00 04 00 00       	and    eax,0x400
   14000332b:	85 c0                	test   eax,eax
   14000332d:	75 47                	jne    140003376 <__pformat_putchars+0xc2>
   14000332f:	eb 11                	jmp    140003342 <__pformat_putchars+0x8e>
   140003331:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003335:	48 89 c2             	mov    rdx,rax
   140003338:	b9 20 00 00 00       	mov    ecx,0x20
   14000333d:	e8 ee fe ff ff       	call   140003230 <__pformat_putc>
   140003342:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003346:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003349:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000334c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003350:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003353:	85 c0                	test   eax,eax
   140003355:	75 da                	jne    140003331 <__pformat_putchars+0x7d>
   140003357:	eb 1d                	jmp    140003376 <__pformat_putchars+0xc2>
   140003359:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000335d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003361:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003365:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003368:	0f be c0             	movsx  eax,al
   14000336b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000336f:	89 c1                	mov    ecx,eax
   140003371:	e8 ba fe ff ff       	call   140003230 <__pformat_putc>
   140003376:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003379:	8d 50 ff             	lea    edx,[rax-0x1]
   14000337c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000337f:	85 c0                	test   eax,eax
   140003381:	75 d6                	jne    140003359 <__pformat_putchars+0xa5>
   140003383:	eb 11                	jmp    140003396 <__pformat_putchars+0xe2>
   140003385:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003389:	48 89 c2             	mov    rdx,rax
   14000338c:	b9 20 00 00 00       	mov    ecx,0x20
   140003391:	e8 9a fe ff ff       	call   140003230 <__pformat_putc>
   140003396:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000339a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000339d:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400033a0:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400033a4:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400033a7:	85 c0                	test   eax,eax
   1400033a9:	7f da                	jg     140003385 <__pformat_putchars+0xd1>
   1400033ab:	90                   	nop
   1400033ac:	90                   	nop
   1400033ad:	48 83 c4 20          	add    rsp,0x20
   1400033b1:	5d                   	pop    rbp
   1400033b2:	c3                   	ret

00000001400033b3 <__pformat_puts>:
   1400033b3:	55                   	push   rbp
   1400033b4:	48 89 e5             	mov    rbp,rsp
   1400033b7:	48 83 ec 20          	sub    rsp,0x20
   1400033bb:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400033bf:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400033c3:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400033c8:	75 0b                	jne    1400033d5 <__pformat_puts+0x22>
   1400033ca:	48 8d 05 5f 7f 00 00 	lea    rax,[rip+0x7f5f]        # 14000b330 <.rdata>
   1400033d1:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400033d5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400033d9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033dc:	85 c0                	test   eax,eax
   1400033de:	78 2f                	js     14000340f <__pformat_puts+0x5c>
   1400033e0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400033e4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033e7:	48 63 d0             	movsxd rdx,eax
   1400033ea:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033ee:	48 89 c1             	mov    rcx,rax
   1400033f1:	e8 4a 5a 00 00       	call   140008e40 <strnlen>
   1400033f6:	89 c1                	mov    ecx,eax
   1400033f8:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400033fc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003400:	49 89 d0             	mov    r8,rdx
   140003403:	89 ca                	mov    edx,ecx
   140003405:	48 89 c1             	mov    rcx,rax
   140003408:	e8 a7 fe ff ff       	call   1400032b4 <__pformat_putchars>
   14000340d:	eb 23                	jmp    140003432 <__pformat_puts+0x7f>
   14000340f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003413:	48 89 c1             	mov    rcx,rax
   140003416:	e8 fd 62 00 00       	call   140009718 <strlen>
   14000341b:	89 c1                	mov    ecx,eax
   14000341d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003421:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003425:	49 89 d0             	mov    r8,rdx
   140003428:	89 ca                	mov    edx,ecx
   14000342a:	48 89 c1             	mov    rcx,rax
   14000342d:	e8 82 fe ff ff       	call   1400032b4 <__pformat_putchars>
   140003432:	90                   	nop
   140003433:	48 83 c4 20          	add    rsp,0x20
   140003437:	5d                   	pop    rbp
   140003438:	c3                   	ret

0000000140003439 <__pformat_wputchars>:
   140003439:	55                   	push   rbp
   14000343a:	48 89 e5             	mov    rbp,rsp
   14000343d:	48 83 ec 50          	sub    rsp,0x50
   140003441:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003445:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003448:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000344c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   140003453:	00 
   140003454:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003458:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000345b:	85 c0                	test   eax,eax
   14000345d:	78 16                	js     140003475 <__pformat_wputchars+0x3c>
   14000345f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003463:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003466:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003469:	7e 0a                	jle    140003475 <__pformat_wputchars+0x3c>
   14000346b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000346f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003472:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003475:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003479:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000347c:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000347f:	7d 15                	jge    140003496 <__pformat_wputchars+0x5d>
   140003481:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003485:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003488:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000348b:	89 c2                	mov    edx,eax
   14000348d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003491:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003494:	eb 0b                	jmp    1400034a1 <__pformat_wputchars+0x68>
   140003496:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000349a:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400034a1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034a5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034a8:	85 c0                	test   eax,eax
   1400034aa:	7e 6e                	jle    14000351a <__pformat_wputchars+0xe1>
   1400034ac:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034b0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400034b3:	25 00 04 00 00       	and    eax,0x400
   1400034b8:	85 c0                	test   eax,eax
   1400034ba:	75 5e                	jne    14000351a <__pformat_wputchars+0xe1>
   1400034bc:	eb 11                	jmp    1400034cf <__pformat_wputchars+0x96>
   1400034be:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034c2:	48 89 c2             	mov    rdx,rax
   1400034c5:	b9 20 00 00 00       	mov    ecx,0x20
   1400034ca:	e8 61 fd ff ff       	call   140003230 <__pformat_putc>
   1400034cf:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034d3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034d6:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400034d9:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034dd:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400034e0:	85 c0                	test   eax,eax
   1400034e2:	75 da                	jne    1400034be <__pformat_wputchars+0x85>
   1400034e4:	eb 34                	jmp    14000351a <__pformat_wputchars+0xe1>
   1400034e6:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400034ea:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400034ee:	eb 1d                	jmp    14000350d <__pformat_wputchars+0xd4>
   1400034f0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400034f4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400034f8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400034fc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400034ff:	0f be c0             	movsx  eax,al
   140003502:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003506:	89 c1                	mov    ecx,eax
   140003508:	e8 23 fd ff ff       	call   140003230 <__pformat_putc>
   14000350d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003510:	8d 50 ff             	lea    edx,[rax-0x1]
   140003513:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003516:	85 c0                	test   eax,eax
   140003518:	7f d6                	jg     1400034f0 <__pformat_wputchars+0xb7>
   14000351a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000351d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003520:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003523:	85 c0                	test   eax,eax
   140003525:	7e 41                	jle    140003568 <__pformat_wputchars+0x12f>
   140003527:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000352b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000352f:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003533:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140003536:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   14000353a:	0f b7 d0             	movzx  edx,ax
   14000353d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003541:	49 89 c8             	mov    r8,rcx
   140003544:	48 89 c1             	mov    rcx,rax
   140003547:	e8 84 5b 00 00       	call   1400090d0 <wcrtomb>
   14000354c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000354f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003553:	7f 91                	jg     1400034e6 <__pformat_wputchars+0xad>
   140003555:	eb 11                	jmp    140003568 <__pformat_wputchars+0x12f>
   140003557:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000355b:	48 89 c2             	mov    rdx,rax
   14000355e:	b9 20 00 00 00       	mov    ecx,0x20
   140003563:	e8 c8 fc ff ff       	call   140003230 <__pformat_putc>
   140003568:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000356c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000356f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003572:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003576:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003579:	85 c0                	test   eax,eax
   14000357b:	7f da                	jg     140003557 <__pformat_wputchars+0x11e>
   14000357d:	90                   	nop
   14000357e:	90                   	nop
   14000357f:	48 83 c4 50          	add    rsp,0x50
   140003583:	5d                   	pop    rbp
   140003584:	c3                   	ret

0000000140003585 <__pformat_wcputs>:
   140003585:	55                   	push   rbp
   140003586:	48 89 e5             	mov    rbp,rsp
   140003589:	48 83 ec 20          	sub    rsp,0x20
   14000358d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003591:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003595:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000359a:	75 0b                	jne    1400035a7 <__pformat_wcputs+0x22>
   14000359c:	48 8d 05 95 7d 00 00 	lea    rax,[rip+0x7d95]        # 14000b338 <.rdata+0x8>
   1400035a3:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400035a7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400035ab:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400035ae:	85 c0                	test   eax,eax
   1400035b0:	78 2f                	js     1400035e1 <__pformat_wcputs+0x5c>
   1400035b2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400035b6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400035b9:	48 63 d0             	movsxd rdx,eax
   1400035bc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035c0:	48 89 c1             	mov    rcx,rax
   1400035c3:	e8 28 58 00 00       	call   140008df0 <wcsnlen>
   1400035c8:	89 c1                	mov    ecx,eax
   1400035ca:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400035ce:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035d2:	49 89 d0             	mov    r8,rdx
   1400035d5:	89 ca                	mov    edx,ecx
   1400035d7:	48 89 c1             	mov    rcx,rax
   1400035da:	e8 5a fe ff ff       	call   140003439 <__pformat_wputchars>
   1400035df:	eb 23                	jmp    140003604 <__pformat_wcputs+0x7f>
   1400035e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035e5:	48 89 c1             	mov    rcx,rax
   1400035e8:	e8 43 61 00 00       	call   140009730 <wcslen>
   1400035ed:	89 c1                	mov    ecx,eax
   1400035ef:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400035f3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035f7:	49 89 d0             	mov    r8,rdx
   1400035fa:	89 ca                	mov    edx,ecx
   1400035fc:	48 89 c1             	mov    rcx,rax
   1400035ff:	e8 35 fe ff ff       	call   140003439 <__pformat_wputchars>
   140003604:	90                   	nop
   140003605:	48 83 c4 20          	add    rsp,0x20
   140003609:	5d                   	pop    rbp
   14000360a:	c3                   	ret

000000014000360b <__pformat_int_bufsiz>:
   14000360b:	55                   	push   rbp
   14000360c:	48 89 e5             	mov    rbp,rsp
   14000360f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003612:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003615:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003619:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000361c:	83 e8 01             	sub    eax,0x1
   14000361f:	48 98                	cdqe
   140003621:	48 83 c0 40          	add    rax,0x40
   140003625:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140003628:	48 63 ca             	movsxd rcx,edx
   14000362b:	ba 00 00 00 00       	mov    edx,0x0
   140003630:	48 f7 f1             	div    rcx
   140003633:	89 c2                	mov    edx,eax
   140003635:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140003638:	01 d0                	add    eax,edx
   14000363a:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   14000363d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003641:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003644:	ba 00 00 00 00       	mov    edx,0x0
   140003649:	85 c0                	test   eax,eax
   14000364b:	0f 48 c2             	cmovs  eax,edx
   14000364e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   140003651:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003655:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003658:	25 00 10 00 00       	and    eax,0x1000
   14000365d:	85 c0                	test   eax,eax
   14000365f:	74 29                	je     14000368a <__pformat_int_bufsiz+0x7f>
   140003661:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003665:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003669:	66 85 c0             	test   ax,ax
   14000366c:	74 1c                	je     14000368a <__pformat_int_bufsiz+0x7f>
   14000366e:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003671:	48 63 d0             	movsxd rdx,eax
   140003674:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   14000367b:	48 89 d1             	mov    rcx,rdx
   14000367e:	48 c1 e9 20          	shr    rcx,0x20
   140003682:	99                   	cdq
   140003683:	89 c8                	mov    eax,ecx
   140003685:	29 d0                	sub    eax,edx
   140003687:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   14000368a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000368e:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140003691:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003694:	39 c2                	cmp    edx,eax
   140003696:	0f 4d c2             	cmovge eax,edx
   140003699:	5d                   	pop    rbp
   14000369a:	c3                   	ret

000000014000369b <__pformat_int>:
   14000369b:	55                   	push   rbp
   14000369c:	53                   	push   rbx
   14000369d:	48 83 ec 58          	sub    rsp,0x58
   1400036a1:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400036a6:	48 89 cb             	mov    rbx,rcx
   1400036a9:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   1400036ac:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   1400036b0:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   1400036b4:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   1400036b8:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400036bc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036c0:	49 89 c0             	mov    r8,rax
   1400036c3:	ba 03 00 00 00       	mov    edx,0x3
   1400036c8:	b9 01 00 00 00       	mov    ecx,0x1
   1400036cd:	e8 39 ff ff ff       	call   14000360b <__pformat_int_bufsiz>
   1400036d2:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400036d5:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   1400036dc:	00 
   1400036dd:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400036e0:	48 98                	cdqe
   1400036e2:	48 83 c0 0f          	add    rax,0xf
   1400036e6:	48 c1 e8 04          	shr    rax,0x4
   1400036ea:	48 c1 e0 04          	shl    rax,0x4
   1400036ee:	e8 7d fa ff ff       	call   140003170 <___chkstk_ms>
   1400036f3:	48 29 c4             	sub    rsp,rax
   1400036f6:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400036fb:	48 83 c0 0f          	add    rax,0xf
   1400036ff:	48 c1 e8 04          	shr    rax,0x4
   140003703:	48 c1 e0 04          	shl    rax,0x4
   140003707:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000370b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000370f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003713:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003717:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000371a:	25 80 00 00 00       	and    eax,0x80
   14000371f:	85 c0                	test   eax,eax
   140003721:	0f 84 ea 00 00 00    	je     140003811 <__pformat_int+0x176>
   140003727:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000372b:	48 85 c0             	test   rax,rax
   14000372e:	79 10                	jns    140003740 <__pformat_int+0xa5>
   140003730:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003734:	48 f7 d8             	neg    rax
   140003737:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000373b:	e9 d1 00 00 00       	jmp    140003811 <__pformat_int+0x176>
   140003740:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003744:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003747:	24 7f                	and    al,0x7f
   140003749:	89 c2                	mov    edx,eax
   14000374b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000374f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003752:	e9 ba 00 00 00       	jmp    140003811 <__pformat_int+0x176>
   140003757:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000375b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000375f:	74 54                	je     1400037b5 <__pformat_int+0x11a>
   140003761:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003765:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003768:	25 00 10 00 00       	and    eax,0x1000
   14000376d:	85 c0                	test   eax,eax
   14000376f:	74 44                	je     1400037b5 <__pformat_int+0x11a>
   140003771:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003775:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003779:	66 85 c0             	test   ax,ax
   14000377c:	74 37                	je     1400037b5 <__pformat_int+0x11a>
   14000377e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003782:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   140003786:	48 89 c2             	mov    rdx,rax
   140003789:	48 89 d0             	mov    rax,rdx
   14000378c:	48 c1 f8 3f          	sar    rax,0x3f
   140003790:	48 c1 e8 3e          	shr    rax,0x3e
   140003794:	48 01 c2             	add    rdx,rax
   140003797:	83 e2 03             	and    edx,0x3
   14000379a:	48 29 c2             	sub    rdx,rax
   14000379d:	48 89 d0             	mov    rax,rdx
   1400037a0:	48 83 f8 03          	cmp    rax,0x3
   1400037a4:	75 0f                	jne    1400037b5 <__pformat_int+0x11a>
   1400037a6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037aa:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037ae:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037b2:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   1400037b5:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   1400037b9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400037c0:	cc cc cc 
   1400037c3:	48 89 c8             	mov    rax,rcx
   1400037c6:	48 f7 e2             	mul    rdx
   1400037c9:	48 c1 ea 03          	shr    rdx,0x3
   1400037cd:	48 89 d0             	mov    rax,rdx
   1400037d0:	48 c1 e0 02          	shl    rax,0x2
   1400037d4:	48 01 d0             	add    rax,rdx
   1400037d7:	48 01 c0             	add    rax,rax
   1400037da:	48 29 c1             	sub    rcx,rax
   1400037dd:	48 89 ca             	mov    rdx,rcx
   1400037e0:	89 d0                	mov    eax,edx
   1400037e2:	8d 48 30             	lea    ecx,[rax+0x30]
   1400037e5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037e9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037ed:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037f1:	89 ca                	mov    edx,ecx
   1400037f3:	88 10                	mov    BYTE PTR [rax],dl
   1400037f5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400037f9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003800:	cc cc cc 
   140003803:	48 f7 e2             	mul    rdx
   140003806:	48 89 d0             	mov    rax,rdx
   140003809:	48 c1 e8 03          	shr    rax,0x3
   14000380d:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140003811:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003815:	48 85 c0             	test   rax,rax
   140003818:	0f 85 39 ff ff ff    	jne    140003757 <__pformat_int+0xbc>
   14000381e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003822:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003825:	85 c0                	test   eax,eax
   140003827:	7e 3e                	jle    140003867 <__pformat_int+0x1cc>
   140003829:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000382d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003830:	89 c1                	mov    ecx,eax
   140003832:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003836:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000383a:	89 c2                	mov    edx,eax
   14000383c:	89 c8                	mov    eax,ecx
   14000383e:	29 d0                	sub    eax,edx
   140003840:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003843:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003847:	7e 1e                	jle    140003867 <__pformat_int+0x1cc>
   140003849:	eb 0f                	jmp    14000385a <__pformat_int+0x1bf>
   14000384b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000384f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003853:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003857:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000385a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000385d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003860:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   140003863:	85 c0                	test   eax,eax
   140003865:	7f e4                	jg     14000384b <__pformat_int+0x1b0>
   140003867:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000386b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000386f:	75 1a                	jne    14000388b <__pformat_int+0x1f0>
   140003871:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003875:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003878:	85 c0                	test   eax,eax
   14000387a:	74 0f                	je     14000388b <__pformat_int+0x1f0>
   14000387c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003880:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003884:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003888:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000388b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000388f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003892:	85 c0                	test   eax,eax
   140003894:	0f 8e ce 00 00 00    	jle    140003968 <__pformat_int+0x2cd>
   14000389a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000389e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038a1:	89 c1                	mov    ecx,eax
   1400038a3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038a7:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400038ab:	89 c2                	mov    edx,eax
   1400038ad:	89 c8                	mov    eax,ecx
   1400038af:	29 d0                	sub    eax,edx
   1400038b1:	89 c2                	mov    edx,eax
   1400038b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038b7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400038ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038be:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038c1:	85 c0                	test   eax,eax
   1400038c3:	0f 8e 9f 00 00 00    	jle    140003968 <__pformat_int+0x2cd>
   1400038c9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038cd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038d0:	25 c0 01 00 00       	and    eax,0x1c0
   1400038d5:	85 c0                	test   eax,eax
   1400038d7:	74 11                	je     1400038ea <__pformat_int+0x24f>
   1400038d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038dd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038e0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400038e3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038e7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400038ea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ee:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400038f1:	85 c0                	test   eax,eax
   1400038f3:	79 3b                	jns    140003930 <__pformat_int+0x295>
   1400038f5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038f9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038fc:	25 00 06 00 00       	and    eax,0x600
   140003901:	3d 00 02 00 00       	cmp    eax,0x200
   140003906:	75 28                	jne    140003930 <__pformat_int+0x295>
   140003908:	eb 0f                	jmp    140003919 <__pformat_int+0x27e>
   14000390a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000390e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003912:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003916:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003919:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000391d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003920:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003923:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003927:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000392a:	85 c0                	test   eax,eax
   14000392c:	7f dc                	jg     14000390a <__pformat_int+0x26f>
   14000392e:	eb 38                	jmp    140003968 <__pformat_int+0x2cd>
   140003930:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003934:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003937:	25 00 04 00 00       	and    eax,0x400
   14000393c:	85 c0                	test   eax,eax
   14000393e:	75 28                	jne    140003968 <__pformat_int+0x2cd>
   140003940:	eb 11                	jmp    140003953 <__pformat_int+0x2b8>
   140003942:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003946:	48 89 c2             	mov    rdx,rax
   140003949:	b9 20 00 00 00       	mov    ecx,0x20
   14000394e:	e8 dd f8 ff ff       	call   140003230 <__pformat_putc>
   140003953:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003957:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000395a:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000395d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003961:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003964:	85 c0                	test   eax,eax
   140003966:	7f da                	jg     140003942 <__pformat_int+0x2a7>
   140003968:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000396c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000396f:	25 80 00 00 00       	and    eax,0x80
   140003974:	85 c0                	test   eax,eax
   140003976:	74 11                	je     140003989 <__pformat_int+0x2ee>
   140003978:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000397c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003980:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003984:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   140003987:	eb 5a                	jmp    1400039e3 <__pformat_int+0x348>
   140003989:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000398d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003990:	25 00 01 00 00       	and    eax,0x100
   140003995:	85 c0                	test   eax,eax
   140003997:	74 11                	je     1400039aa <__pformat_int+0x30f>
   140003999:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000399d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400039a1:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400039a5:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400039a8:	eb 39                	jmp    1400039e3 <__pformat_int+0x348>
   1400039aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039ae:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400039b1:	83 e0 40             	and    eax,0x40
   1400039b4:	85 c0                	test   eax,eax
   1400039b6:	74 2b                	je     1400039e3 <__pformat_int+0x348>
   1400039b8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039bc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400039c0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400039c4:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400039c7:	eb 1a                	jmp    1400039e3 <__pformat_int+0x348>
   1400039c9:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   1400039ce:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039d2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400039d5:	0f be c0             	movsx  eax,al
   1400039d8:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400039dc:	89 c1                	mov    ecx,eax
   1400039de:	e8 4d f8 ff ff       	call   140003230 <__pformat_putc>
   1400039e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039e7:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   1400039eb:	72 dc                	jb     1400039c9 <__pformat_int+0x32e>
   1400039ed:	eb 11                	jmp    140003a00 <__pformat_int+0x365>
   1400039ef:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039f3:	48 89 c2             	mov    rdx,rax
   1400039f6:	b9 20 00 00 00       	mov    ecx,0x20
   1400039fb:	e8 30 f8 ff ff       	call   140003230 <__pformat_putc>
   140003a00:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003a04:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003a07:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003a0a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003a0e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003a11:	85 c0                	test   eax,eax
   140003a13:	7f da                	jg     1400039ef <__pformat_int+0x354>
   140003a15:	90                   	nop
   140003a16:	90                   	nop
   140003a17:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003a1b:	5b                   	pop    rbx
   140003a1c:	5d                   	pop    rbp
   140003a1d:	c3                   	ret

0000000140003a1e <__pformat_xint>:
   140003a1e:	55                   	push   rbp
   140003a1f:	53                   	push   rbx
   140003a20:	48 83 ec 68          	sub    rsp,0x68
   140003a24:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003a29:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003a2c:	48 89 d3             	mov    rbx,rdx
   140003a2f:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140003a32:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   140003a36:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003a3a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   140003a3e:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003a42:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a46:	74 1e                	je     140003a66 <__pformat_xint+0x48>
   140003a48:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a4c:	74 06                	je     140003a54 <__pformat_xint+0x36>
   140003a4e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a52:	75 09                	jne    140003a5d <__pformat_xint+0x3f>
   140003a54:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003a5b:	eb 10                	jmp    140003a6d <__pformat_xint+0x4f>
   140003a5d:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003a64:	eb 07                	jmp    140003a6d <__pformat_xint+0x4f>
   140003a66:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140003a6d:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003a71:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003a74:	49 89 d0             	mov    r8,rdx
   140003a77:	89 c2                	mov    edx,eax
   140003a79:	b9 02 00 00 00       	mov    ecx,0x2
   140003a7e:	e8 88 fb ff ff       	call   14000360b <__pformat_int_bufsiz>
   140003a83:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140003a86:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   140003a8d:	00 
   140003a8e:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140003a91:	48 98                	cdqe
   140003a93:	48 83 c0 0f          	add    rax,0xf
   140003a97:	48 c1 e8 04          	shr    rax,0x4
   140003a9b:	48 c1 e0 04          	shl    rax,0x4
   140003a9f:	e8 cc f6 ff ff       	call   140003170 <___chkstk_ms>
   140003aa4:	48 29 c4             	sub    rsp,rax
   140003aa7:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003aac:	48 83 c0 0f          	add    rax,0xf
   140003ab0:	48 c1 e8 04          	shr    rax,0x4
   140003ab4:	48 c1 e0 04          	shl    rax,0x4
   140003ab8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140003abc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003ac0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003ac4:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003ac8:	74 1e                	je     140003ae8 <__pformat_xint+0xca>
   140003aca:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003ace:	74 06                	je     140003ad6 <__pformat_xint+0xb8>
   140003ad0:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003ad4:	75 09                	jne    140003adf <__pformat_xint+0xc1>
   140003ad6:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003add:	eb 10                	jmp    140003aef <__pformat_xint+0xd1>
   140003adf:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003ae6:	eb 67                	jmp    140003b4f <__pformat_xint+0x131>
   140003ae8:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003aef:	eb 5e                	jmp    140003b4f <__pformat_xint+0x131>
   140003af1:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003af5:	89 c2                	mov    edx,eax
   140003af7:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003afa:	21 d0                	and    eax,edx
   140003afc:	8d 48 30             	lea    ecx,[rax+0x30]
   140003aff:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b03:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b07:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b0b:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003b0f:	89 ca                	mov    edx,ecx
   140003b11:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b15:	88 10                	mov    BYTE PTR [rax],dl
   140003b17:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b1b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003b1e:	3c 39                	cmp    al,0x39
   140003b20:	7e 1a                	jle    140003b3c <__pformat_xint+0x11e>
   140003b22:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b26:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003b29:	83 c0 07             	add    eax,0x7
   140003b2c:	89 c2                	mov    edx,eax
   140003b2e:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003b31:	83 e0 20             	and    eax,0x20
   140003b34:	09 c2                	or     edx,eax
   140003b36:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b3a:	88 10                	mov    BYTE PTR [rax],dl
   140003b3c:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003b40:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003b43:	89 c1                	mov    ecx,eax
   140003b45:	48 d3 ea             	shr    rdx,cl
   140003b48:	48 89 d0             	mov    rax,rdx
   140003b4b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003b4f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003b53:	48 85 c0             	test   rax,rax
   140003b56:	75 99                	jne    140003af1 <__pformat_xint+0xd3>
   140003b58:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b5c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b60:	75 13                	jne    140003b75 <__pformat_xint+0x157>
   140003b62:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b66:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b69:	80 e4 f7             	and    ah,0xf7
   140003b6c:	89 c2                	mov    edx,eax
   140003b6e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b72:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003b75:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b79:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b7c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b7f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b83:	7e 3a                	jle    140003bbf <__pformat_xint+0x1a1>
   140003b85:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003b88:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b8c:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003b90:	89 c1                	mov    ecx,eax
   140003b92:	89 d0                	mov    eax,edx
   140003b94:	29 c8                	sub    eax,ecx
   140003b96:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b99:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b9d:	7e 20                	jle    140003bbf <__pformat_xint+0x1a1>
   140003b9f:	eb 0f                	jmp    140003bb0 <__pformat_xint+0x192>
   140003ba1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ba5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ba9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bad:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bb0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003bb3:	8d 50 ff             	lea    edx,[rax-0x1]
   140003bb6:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bb9:	85 c0                	test   eax,eax
   140003bbb:	7f e4                	jg     140003ba1 <__pformat_xint+0x183>
   140003bbd:	eb 25                	jmp    140003be4 <__pformat_xint+0x1c6>
   140003bbf:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003bc3:	75 1f                	jne    140003be4 <__pformat_xint+0x1c6>
   140003bc5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bc9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bcc:	25 00 08 00 00       	and    eax,0x800
   140003bd1:	85 c0                	test   eax,eax
   140003bd3:	74 0f                	je     140003be4 <__pformat_xint+0x1c6>
   140003bd5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bd9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bdd:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003be1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003be4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003be8:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003bec:	75 1a                	jne    140003c08 <__pformat_xint+0x1ea>
   140003bee:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bf2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003bf5:	85 c0                	test   eax,eax
   140003bf7:	74 0f                	je     140003c08 <__pformat_xint+0x1ea>
   140003bf9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bfd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c01:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c05:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c08:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c0c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c0f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003c13:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003c17:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c1a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003c1d:	7d 15                	jge    140003c34 <__pformat_xint+0x216>
   140003c1f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c23:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c26:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003c29:	89 c2                	mov    edx,eax
   140003c2b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c2f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003c32:	eb 0b                	jmp    140003c3f <__pformat_xint+0x221>
   140003c34:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c38:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003c3f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c43:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c46:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003c49:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c4d:	7e 1a                	jle    140003c69 <__pformat_xint+0x24b>
   140003c4f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c53:	74 14                	je     140003c69 <__pformat_xint+0x24b>
   140003c55:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c59:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c5c:	25 00 08 00 00       	and    eax,0x800
   140003c61:	85 c0                	test   eax,eax
   140003c63:	74 04                	je     140003c69 <__pformat_xint+0x24b>
   140003c65:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003c69:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c6d:	7e 3c                	jle    140003cab <__pformat_xint+0x28d>
   140003c6f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c73:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003c76:	85 c0                	test   eax,eax
   140003c78:	79 31                	jns    140003cab <__pformat_xint+0x28d>
   140003c7a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c7e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c81:	25 00 06 00 00       	and    eax,0x600
   140003c86:	3d 00 02 00 00       	cmp    eax,0x200
   140003c8b:	75 1e                	jne    140003cab <__pformat_xint+0x28d>
   140003c8d:	eb 0f                	jmp    140003c9e <__pformat_xint+0x280>
   140003c8f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c93:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c97:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c9b:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c9e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ca1:	8d 50 ff             	lea    edx,[rax-0x1]
   140003ca4:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003ca7:	85 c0                	test   eax,eax
   140003ca9:	7f e4                	jg     140003c8f <__pformat_xint+0x271>
   140003cab:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003caf:	74 30                	je     140003ce1 <__pformat_xint+0x2c3>
   140003cb1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cb5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003cb8:	25 00 08 00 00       	and    eax,0x800
   140003cbd:	85 c0                	test   eax,eax
   140003cbf:	74 20                	je     140003ce1 <__pformat_xint+0x2c3>
   140003cc1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cc5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003cc9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003ccd:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003cd0:	88 10                	mov    BYTE PTR [rax],dl
   140003cd2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cd6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003cda:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003cde:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003ce1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003ce5:	7e 4c                	jle    140003d33 <__pformat_xint+0x315>
   140003ce7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ceb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003cee:	25 00 04 00 00       	and    eax,0x400
   140003cf3:	85 c0                	test   eax,eax
   140003cf5:	75 3c                	jne    140003d33 <__pformat_xint+0x315>
   140003cf7:	eb 11                	jmp    140003d0a <__pformat_xint+0x2ec>
   140003cf9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cfd:	48 89 c2             	mov    rdx,rax
   140003d00:	b9 20 00 00 00       	mov    ecx,0x20
   140003d05:	e8 26 f5 ff ff       	call   140003230 <__pformat_putc>
   140003d0a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d0d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d10:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d13:	85 c0                	test   eax,eax
   140003d15:	7f e2                	jg     140003cf9 <__pformat_xint+0x2db>
   140003d17:	eb 1a                	jmp    140003d33 <__pformat_xint+0x315>
   140003d19:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003d1e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d22:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003d25:	0f be c0             	movsx  eax,al
   140003d28:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003d2c:	89 c1                	mov    ecx,eax
   140003d2e:	e8 fd f4 ff ff       	call   140003230 <__pformat_putc>
   140003d33:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d37:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003d3b:	72 dc                	jb     140003d19 <__pformat_xint+0x2fb>
   140003d3d:	eb 11                	jmp    140003d50 <__pformat_xint+0x332>
   140003d3f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d43:	48 89 c2             	mov    rdx,rax
   140003d46:	b9 20 00 00 00       	mov    ecx,0x20
   140003d4b:	e8 e0 f4 ff ff       	call   140003230 <__pformat_putc>
   140003d50:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d53:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d56:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d59:	85 c0                	test   eax,eax
   140003d5b:	7f e2                	jg     140003d3f <__pformat_xint+0x321>
   140003d5d:	90                   	nop
   140003d5e:	90                   	nop
   140003d5f:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003d63:	5b                   	pop    rbx
   140003d64:	5d                   	pop    rbp
   140003d65:	c3                   	ret

0000000140003d66 <init_fpreg_ldouble>:
   140003d66:	55                   	push   rbp
   140003d67:	53                   	push   rbx
   140003d68:	48 83 ec 28          	sub    rsp,0x28
   140003d6c:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003d71:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003d75:	48 89 d3             	mov    rbx,rdx
   140003d78:	db 2b                	fld    TBYTE PTR [rbx]
   140003d7a:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003d7d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003d80:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003d83:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003d87:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d8b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003d8f:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003d92:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003d96:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003d9a:	48 83 c4 28          	add    rsp,0x28
   140003d9e:	5b                   	pop    rbx
   140003d9f:	5d                   	pop    rbp
   140003da0:	c3                   	ret

0000000140003da1 <__pformat_cvt>:
   140003da1:	55                   	push   rbp
   140003da2:	53                   	push   rbx
   140003da3:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003daa:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003db1:	00 
   140003db2:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003db5:	48 89 d3             	mov    rbx,rdx
   140003db8:	db 2b                	fld    TBYTE PTR [rbx]
   140003dba:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003dbd:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003dc1:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003dc5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003dcc:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003dd0:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003dd3:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003dd6:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003dda:	48 89 c1             	mov    rcx,rax
   140003ddd:	e8 84 ff ff ff       	call   140003d66 <init_fpreg_ldouble>
   140003de2:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003de5:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003de8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003dec:	48 89 c1             	mov    rcx,rax
   140003def:	e8 9c 4e 00 00       	call   140008c90 <__fpclassifyl>
   140003df4:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003df7:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003dfa:	25 00 01 00 00       	and    eax,0x100
   140003dff:	85 c0                	test   eax,eax
   140003e01:	74 1d                	je     140003e20 <__pformat_cvt+0x7f>
   140003e03:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e06:	25 00 04 00 00       	and    eax,0x400
   140003e0b:	85 c0                	test   eax,eax
   140003e0d:	74 07                	je     140003e16 <__pformat_cvt+0x75>
   140003e0f:	b8 03 00 00 00       	mov    eax,0x3
   140003e14:	eb 05                	jmp    140003e1b <__pformat_cvt+0x7a>
   140003e16:	b8 04 00 00 00       	mov    eax,0x4
   140003e1b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003e1e:	eb 4a                	jmp    140003e6a <__pformat_cvt+0xc9>
   140003e20:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e23:	25 00 04 00 00       	and    eax,0x400
   140003e28:	85 c0                	test   eax,eax
   140003e2a:	74 37                	je     140003e63 <__pformat_cvt+0xc2>
   140003e2c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e2f:	25 00 40 00 00       	and    eax,0x4000
   140003e34:	85 c0                	test   eax,eax
   140003e36:	74 10                	je     140003e48 <__pformat_cvt+0xa7>
   140003e38:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003e3f:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003e46:	eb 22                	jmp    140003e6a <__pformat_cvt+0xc9>
   140003e48:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003e4f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e53:	98                   	cwde
   140003e54:	25 ff 7f 00 00       	and    eax,0x7fff
   140003e59:	2d 3e 40 00 00       	sub    eax,0x403e
   140003e5e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003e61:	eb 07                	jmp    140003e6a <__pformat_cvt+0xc9>
   140003e63:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003e6a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e6d:	83 f8 04             	cmp    eax,0x4
   140003e70:	74 0e                	je     140003e80 <__pformat_cvt+0xdf>
   140003e72:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e76:	98                   	cwde
   140003e77:	25 00 80 00 00       	and    eax,0x8000
   140003e7c:	89 c2                	mov    edx,eax
   140003e7e:	eb 05                	jmp    140003e85 <__pformat_cvt+0xe4>
   140003e80:	ba 00 00 00 00       	mov    edx,0x0
   140003e85:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003e89:	89 10                	mov    DWORD PTR [rax],edx
   140003e8b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003e8e:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003e92:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003e96:	48 8d 0d d3 61 00 00 	lea    rcx,[rip+0x61d3]        # 14000a070 <fpi.0>
   140003e9d:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003ea1:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003ea6:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003eaa:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003eaf:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003eb2:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003eb6:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003eb9:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003ebd:	89 c2                	mov    edx,eax
   140003ebf:	e8 96 24 00 00       	call   14000635a <__gdtoa>
   140003ec4:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003ecb:	5b                   	pop    rbx
   140003ecc:	5d                   	pop    rbp
   140003ecd:	c3                   	ret

0000000140003ece <__pformat_ecvt>:
   140003ece:	55                   	push   rbp
   140003ecf:	53                   	push   rbx
   140003ed0:	48 83 ec 58          	sub    rsp,0x58
   140003ed4:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003ed9:	48 89 cb             	mov    rbx,rcx
   140003edc:	db 2b                	fld    TBYTE PTR [rbx]
   140003ede:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003ee1:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003ee4:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003ee8:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003eec:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003eef:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003ef2:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003ef6:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003ef9:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003efd:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f01:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f06:	4d 89 c1             	mov    r9,r8
   140003f09:	41 89 c8             	mov    r8d,ecx
   140003f0c:	48 89 c2             	mov    rdx,rax
   140003f0f:	b9 02 00 00 00       	mov    ecx,0x2
   140003f14:	e8 88 fe ff ff       	call   140003da1 <__pformat_cvt>
   140003f19:	48 83 c4 58          	add    rsp,0x58
   140003f1d:	5b                   	pop    rbx
   140003f1e:	5d                   	pop    rbp
   140003f1f:	c3                   	ret

0000000140003f20 <__pformat_fcvt>:
   140003f20:	55                   	push   rbp
   140003f21:	53                   	push   rbx
   140003f22:	48 83 ec 58          	sub    rsp,0x58
   140003f26:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003f2b:	48 89 cb             	mov    rbx,rcx
   140003f2e:	db 2b                	fld    TBYTE PTR [rbx]
   140003f30:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003f33:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003f36:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003f3a:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003f3e:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003f41:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003f44:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003f48:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003f4b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003f4f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f53:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f58:	4d 89 c1             	mov    r9,r8
   140003f5b:	41 89 c8             	mov    r8d,ecx
   140003f5e:	48 89 c2             	mov    rdx,rax
   140003f61:	b9 03 00 00 00       	mov    ecx,0x3
   140003f66:	e8 36 fe ff ff       	call   140003da1 <__pformat_cvt>
   140003f6b:	48 83 c4 58          	add    rsp,0x58
   140003f6f:	5b                   	pop    rbx
   140003f70:	5d                   	pop    rbp
   140003f71:	c3                   	ret

0000000140003f72 <__pformat_emit_radix_point>:
   140003f72:	55                   	push   rbp
   140003f73:	53                   	push   rbx
   140003f74:	48 83 ec 68          	sub    rsp,0x68
   140003f78:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003f7d:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003f81:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f85:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f88:	83 f8 fd             	cmp    eax,0xfffffffd
   140003f8b:	75 48                	jne    140003fd5 <__pformat_emit_radix_point+0x63>
   140003f8d:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003f94:	00 
   140003f95:	e8 4e 57 00 00       	call   1400096e8 <localeconv>
   140003f9a:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003f9d:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003fa1:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003fa5:	49 89 c9             	mov    r9,rcx
   140003fa8:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003fae:	48 89 c1             	mov    rcx,rax
   140003fb1:	e8 6a 51 00 00       	call   140009120 <mbrtowc>
   140003fb6:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003fb9:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003fbd:	7e 0c                	jle    140003fcb <__pformat_emit_radix_point+0x59>
   140003fbf:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003fc3:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fc7:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003fcb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fcf:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003fd2:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003fd5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fd9:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003fdd:	66 85 c0             	test   ax,ax
   140003fe0:	0f 84 b8 00 00 00    	je     14000409e <__pformat_emit_radix_point+0x12c>
   140003fe6:	48 89 e0             	mov    rax,rsp
   140003fe9:	48 89 c3             	mov    rbx,rax
   140003fec:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003ff0:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003ff3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003ff6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ff9:	48 63 d0             	movsxd rdx,eax
   140003ffc:	48 83 ea 01          	sub    rdx,0x1
   140004000:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140004004:	48 98                	cdqe
   140004006:	48 83 c0 0f          	add    rax,0xf
   14000400a:	48 c1 e8 04          	shr    rax,0x4
   14000400e:	48 c1 e0 04          	shl    rax,0x4
   140004012:	e8 59 f1 ff ff       	call   140003170 <___chkstk_ms>
   140004017:	48 29 c4             	sub    rsp,rax
   14000401a:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000401f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140004023:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   14000402a:	00 
   14000402b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000402f:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140004033:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140004037:	0f b7 d0             	movzx  edx,ax
   14000403a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000403e:	49 89 c8             	mov    r8,rcx
   140004041:	48 89 c1             	mov    rcx,rax
   140004044:	e8 87 50 00 00       	call   1400090d0 <wcrtomb>
   140004049:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000404c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004050:	7e 36                	jle    140004088 <__pformat_emit_radix_point+0x116>
   140004052:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140004056:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000405a:	eb 1d                	jmp    140004079 <__pformat_emit_radix_point+0x107>
   14000405c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004060:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004064:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004068:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000406b:	0f be c0             	movsx  eax,al
   14000406e:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004072:	89 c1                	mov    ecx,eax
   140004074:	e8 b7 f1 ff ff       	call   140003230 <__pformat_putc>
   140004079:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000407c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000407f:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140004082:	85 c0                	test   eax,eax
   140004084:	7f d6                	jg     14000405c <__pformat_emit_radix_point+0xea>
   140004086:	eb 11                	jmp    140004099 <__pformat_emit_radix_point+0x127>
   140004088:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000408c:	48 89 c2             	mov    rdx,rax
   14000408f:	b9 2e 00 00 00       	mov    ecx,0x2e
   140004094:	e8 97 f1 ff ff       	call   140003230 <__pformat_putc>
   140004099:	48 89 dc             	mov    rsp,rbx
   14000409c:	eb 11                	jmp    1400040af <__pformat_emit_radix_point+0x13d>
   14000409e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040a2:	48 89 c2             	mov    rdx,rax
   1400040a5:	b9 2e 00 00 00       	mov    ecx,0x2e
   1400040aa:	e8 81 f1 ff ff       	call   140003230 <__pformat_putc>
   1400040af:	90                   	nop
   1400040b0:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   1400040b4:	5b                   	pop    rbx
   1400040b5:	5d                   	pop    rbp
   1400040b6:	c3                   	ret

00000001400040b7 <__pformat_emit_numeric_value>:
   1400040b7:	55                   	push   rbp
   1400040b8:	48 89 e5             	mov    rbp,rsp
   1400040bb:	48 83 ec 30          	sub    rsp,0x30
   1400040bf:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400040c2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400040c6:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   1400040ca:	75 0e                	jne    1400040da <__pformat_emit_numeric_value+0x23>
   1400040cc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040d0:	48 89 c1             	mov    rcx,rax
   1400040d3:	e8 9a fe ff ff       	call   140003f72 <__pformat_emit_radix_point>
   1400040d8:	eb 43                	jmp    14000411d <__pformat_emit_numeric_value+0x66>
   1400040da:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   1400040de:	75 2f                	jne    14000410f <__pformat_emit_numeric_value+0x58>
   1400040e0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040e4:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400040e8:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   1400040ec:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   1400040f0:	66 85 c0             	test   ax,ax
   1400040f3:	74 28                	je     14000411d <__pformat_emit_numeric_value+0x66>
   1400040f5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400040f9:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   1400040fd:	49 89 d0             	mov    r8,rdx
   140004100:	ba 01 00 00 00       	mov    edx,0x1
   140004105:	48 89 c1             	mov    rcx,rax
   140004108:	e8 2c f3 ff ff       	call   140003439 <__pformat_wputchars>
   14000410d:	eb 0e                	jmp    14000411d <__pformat_emit_numeric_value+0x66>
   14000410f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004113:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140004116:	89 c1                	mov    ecx,eax
   140004118:	e8 13 f1 ff ff       	call   140003230 <__pformat_putc>
   14000411d:	90                   	nop
   14000411e:	48 83 c4 30          	add    rsp,0x30
   140004122:	5d                   	pop    rbp
   140004123:	c3                   	ret

0000000140004124 <__pformat_emit_inf_or_nan>:
   140004124:	55                   	push   rbp
   140004125:	48 89 e5             	mov    rbp,rsp
   140004128:	48 83 ec 40          	sub    rsp,0x40
   14000412c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000412f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004133:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140004137:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000413b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000413f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004143:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000414a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000414e:	74 11                	je     140004161 <__pformat_emit_inf_or_nan+0x3d>
   140004150:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004154:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004158:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000415c:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   14000415f:	eb 3e                	jmp    14000419f <__pformat_emit_inf_or_nan+0x7b>
   140004161:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004165:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004168:	25 00 01 00 00       	and    eax,0x100
   14000416d:	85 c0                	test   eax,eax
   14000416f:	74 11                	je     140004182 <__pformat_emit_inf_or_nan+0x5e>
   140004171:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004175:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004179:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000417d:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140004180:	eb 1d                	jmp    14000419f <__pformat_emit_inf_or_nan+0x7b>
   140004182:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004186:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004189:	83 e0 40             	and    eax,0x40
   14000418c:	85 c0                	test   eax,eax
   14000418e:	74 0f                	je     14000419f <__pformat_emit_inf_or_nan+0x7b>
   140004190:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004194:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004198:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000419c:	c6 00 20             	mov    BYTE PTR [rax],0x20
   14000419f:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   1400041a6:	eb 38                	jmp    1400041e0 <__pformat_emit_inf_or_nan+0xbc>
   1400041a8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400041ac:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041b0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400041b4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400041b7:	83 e0 df             	and    eax,0xffffffdf
   1400041ba:	41 89 c0             	mov    r8d,eax
   1400041bd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400041c1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400041c4:	83 e0 20             	and    eax,0x20
   1400041c7:	89 c1                	mov    ecx,eax
   1400041c9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400041cd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041d1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400041d5:	44 89 c2             	mov    edx,r8d
   1400041d8:	09 ca                	or     edx,ecx
   1400041da:	88 10                	mov    BYTE PTR [rax],dl
   1400041dc:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400041e0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400041e4:	7f c2                	jg     1400041a8 <__pformat_emit_inf_or_nan+0x84>
   1400041e6:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400041ea:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400041ee:	48 29 c2             	sub    rdx,rax
   1400041f1:	89 d1                	mov    ecx,edx
   1400041f3:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400041f7:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400041fb:	49 89 d0             	mov    r8,rdx
   1400041fe:	89 ca                	mov    edx,ecx
   140004200:	48 89 c1             	mov    rcx,rax
   140004203:	e8 ac f0 ff ff       	call   1400032b4 <__pformat_putchars>
   140004208:	90                   	nop
   140004209:	48 83 c4 40          	add    rsp,0x40
   14000420d:	5d                   	pop    rbp
   14000420e:	c3                   	ret

000000014000420f <__pformat_emit_float>:
   14000420f:	55                   	push   rbp
   140004210:	48 89 e5             	mov    rbp,rsp
   140004213:	48 83 ec 30          	sub    rsp,0x30
   140004217:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000421a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000421e:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140004222:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004226:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000422a:	7e 2e                	jle    14000425a <__pformat_emit_float+0x4b>
   14000422c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004230:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004233:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   140004236:	7f 15                	jg     14000424d <__pformat_emit_float+0x3e>
   140004238:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000423c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000423f:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004242:	89 c2                	mov    edx,eax
   140004244:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004248:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000424b:	eb 29                	jmp    140004276 <__pformat_emit_float+0x67>
   14000424d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004251:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004258:	eb 1c                	jmp    140004276 <__pformat_emit_float+0x67>
   14000425a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000425e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004261:	85 c0                	test   eax,eax
   140004263:	7e 11                	jle    140004276 <__pformat_emit_float+0x67>
   140004265:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004269:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000426c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000426f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004273:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004276:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000427a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000427d:	85 c0                	test   eax,eax
   14000427f:	78 2b                	js     1400042ac <__pformat_emit_float+0x9d>
   140004281:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004285:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004288:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000428c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000428f:	39 c2                	cmp    edx,eax
   140004291:	7e 19                	jle    1400042ac <__pformat_emit_float+0x9d>
   140004293:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004297:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   14000429a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000429e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400042a1:	29 c2                	sub    edx,eax
   1400042a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042aa:	eb 0b                	jmp    1400042b7 <__pformat_emit_float+0xa8>
   1400042ac:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042b0:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400042b7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042bb:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042be:	85 c0                	test   eax,eax
   1400042c0:	7e 2c                	jle    1400042ee <__pformat_emit_float+0xdf>
   1400042c2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042c6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400042c9:	85 c0                	test   eax,eax
   1400042cb:	7f 10                	jg     1400042dd <__pformat_emit_float+0xce>
   1400042cd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042d1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042d4:	25 00 08 00 00       	and    eax,0x800
   1400042d9:	85 c0                	test   eax,eax
   1400042db:	74 11                	je     1400042ee <__pformat_emit_float+0xdf>
   1400042dd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042e1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042e4:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042e7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042eb:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042ee:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400042f2:	7e 64                	jle    140004358 <__pformat_emit_float+0x149>
   1400042f4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042f8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042fb:	25 00 10 00 00       	and    eax,0x1000
   140004300:	85 c0                	test   eax,eax
   140004302:	74 54                	je     140004358 <__pformat_emit_float+0x149>
   140004304:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004308:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   14000430c:	66 85 c0             	test   ax,ax
   14000430f:	74 47                	je     140004358 <__pformat_emit_float+0x149>
   140004311:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004314:	83 c0 02             	add    eax,0x2
   140004317:	48 63 d0             	movsxd rdx,eax
   14000431a:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   140004321:	48 c1 ea 20          	shr    rdx,0x20
   140004325:	c1 f8 1f             	sar    eax,0x1f
   140004328:	29 c2                	sub    edx,eax
   14000432a:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000432d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004330:	eb 15                	jmp    140004347 <__pformat_emit_float+0x138>
   140004332:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004336:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000433a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000433d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004340:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004344:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004347:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000434b:	7e 0b                	jle    140004358 <__pformat_emit_float+0x149>
   14000434d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004351:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004354:	85 c0                	test   eax,eax
   140004356:	7f da                	jg     140004332 <__pformat_emit_float+0x123>
   140004358:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000435c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000435f:	85 c0                	test   eax,eax
   140004361:	7e 27                	jle    14000438a <__pformat_emit_float+0x17b>
   140004363:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004367:	75 10                	jne    140004379 <__pformat_emit_float+0x16a>
   140004369:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000436d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004370:	25 c0 01 00 00       	and    eax,0x1c0
   140004375:	85 c0                	test   eax,eax
   140004377:	74 11                	je     14000438a <__pformat_emit_float+0x17b>
   140004379:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000437d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004380:	8d 50 ff             	lea    edx,[rax-0x1]
   140004383:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004387:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000438a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000438e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004391:	85 c0                	test   eax,eax
   140004393:	7e 38                	jle    1400043cd <__pformat_emit_float+0x1be>
   140004395:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004399:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000439c:	25 00 06 00 00       	and    eax,0x600
   1400043a1:	85 c0                	test   eax,eax
   1400043a3:	75 28                	jne    1400043cd <__pformat_emit_float+0x1be>
   1400043a5:	eb 11                	jmp    1400043b8 <__pformat_emit_float+0x1a9>
   1400043a7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ab:	48 89 c2             	mov    rdx,rax
   1400043ae:	b9 20 00 00 00       	mov    ecx,0x20
   1400043b3:	e8 78 ee ff ff       	call   140003230 <__pformat_putc>
   1400043b8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043bc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043bf:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400043c2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400043c6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400043c9:	85 c0                	test   eax,eax
   1400043cb:	7f da                	jg     1400043a7 <__pformat_emit_float+0x198>
   1400043cd:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400043d1:	74 13                	je     1400043e6 <__pformat_emit_float+0x1d7>
   1400043d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043d7:	48 89 c2             	mov    rdx,rax
   1400043da:	b9 2d 00 00 00       	mov    ecx,0x2d
   1400043df:	e8 4c ee ff ff       	call   140003230 <__pformat_putc>
   1400043e4:	eb 42                	jmp    140004428 <__pformat_emit_float+0x219>
   1400043e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ea:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043ed:	25 00 01 00 00       	and    eax,0x100
   1400043f2:	85 c0                	test   eax,eax
   1400043f4:	74 13                	je     140004409 <__pformat_emit_float+0x1fa>
   1400043f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043fa:	48 89 c2             	mov    rdx,rax
   1400043fd:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004402:	e8 29 ee ff ff       	call   140003230 <__pformat_putc>
   140004407:	eb 1f                	jmp    140004428 <__pformat_emit_float+0x219>
   140004409:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000440d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004410:	83 e0 40             	and    eax,0x40
   140004413:	85 c0                	test   eax,eax
   140004415:	74 11                	je     140004428 <__pformat_emit_float+0x219>
   140004417:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000441b:	48 89 c2             	mov    rdx,rax
   14000441e:	b9 20 00 00 00       	mov    ecx,0x20
   140004423:	e8 08 ee ff ff       	call   140003230 <__pformat_putc>
   140004428:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000442c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000442f:	85 c0                	test   eax,eax
   140004431:	7e 3b                	jle    14000446e <__pformat_emit_float+0x25f>
   140004433:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004437:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000443a:	25 00 06 00 00       	and    eax,0x600
   14000443f:	3d 00 02 00 00       	cmp    eax,0x200
   140004444:	75 28                	jne    14000446e <__pformat_emit_float+0x25f>
   140004446:	eb 11                	jmp    140004459 <__pformat_emit_float+0x24a>
   140004448:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000444c:	48 89 c2             	mov    rdx,rax
   14000444f:	b9 30 00 00 00       	mov    ecx,0x30
   140004454:	e8 d7 ed ff ff       	call   140003230 <__pformat_putc>
   140004459:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000445d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004460:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004463:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004467:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000446a:	85 c0                	test   eax,eax
   14000446c:	7f da                	jg     140004448 <__pformat_emit_float+0x239>
   14000446e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004472:	0f 8e a7 00 00 00    	jle    14000451f <__pformat_emit_float+0x310>
   140004478:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000447c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000447f:	84 c0                	test   al,al
   140004481:	74 14                	je     140004497 <__pformat_emit_float+0x288>
   140004483:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004487:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000448b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000448f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004492:	0f be c0             	movsx  eax,al
   140004495:	eb 05                	jmp    14000449c <__pformat_emit_float+0x28d>
   140004497:	b8 30 00 00 00       	mov    eax,0x30
   14000449c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044a0:	89 c1                	mov    ecx,eax
   1400044a2:	e8 89 ed ff ff       	call   140003230 <__pformat_putc>
   1400044a7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400044ab:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044af:	74 62                	je     140004513 <__pformat_emit_float+0x304>
   1400044b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044b5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400044b8:	25 00 10 00 00       	and    eax,0x1000
   1400044bd:	85 c0                	test   eax,eax
   1400044bf:	74 52                	je     140004513 <__pformat_emit_float+0x304>
   1400044c1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044c5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400044c9:	66 85 c0             	test   ax,ax
   1400044cc:	74 45                	je     140004513 <__pformat_emit_float+0x304>
   1400044ce:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   1400044d1:	48 63 c1             	movsxd rax,ecx
   1400044d4:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   1400044db:	48 c1 e8 20          	shr    rax,0x20
   1400044df:	48 89 c2             	mov    rdx,rax
   1400044e2:	89 c8                	mov    eax,ecx
   1400044e4:	c1 f8 1f             	sar    eax,0x1f
   1400044e7:	29 c2                	sub    edx,eax
   1400044e9:	89 d0                	mov    eax,edx
   1400044eb:	01 c0                	add    eax,eax
   1400044ed:	01 d0                	add    eax,edx
   1400044ef:	29 c1                	sub    ecx,eax
   1400044f1:	89 ca                	mov    edx,ecx
   1400044f3:	85 d2                	test   edx,edx
   1400044f5:	75 1c                	jne    140004513 <__pformat_emit_float+0x304>
   1400044f7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044fb:	48 83 c0 20          	add    rax,0x20
   1400044ff:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004503:	49 89 d0             	mov    r8,rdx
   140004506:	ba 01 00 00 00       	mov    edx,0x1
   14000450b:	48 89 c1             	mov    rcx,rax
   14000450e:	e8 26 ef ff ff       	call   140003439 <__pformat_wputchars>
   140004513:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004517:	0f 8f 5b ff ff ff    	jg     140004478 <__pformat_emit_float+0x269>
   14000451d:	eb 11                	jmp    140004530 <__pformat_emit_float+0x321>
   14000451f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004523:	48 89 c2             	mov    rdx,rax
   140004526:	b9 30 00 00 00       	mov    ecx,0x30
   14000452b:	e8 00 ed ff ff       	call   140003230 <__pformat_putc>
   140004530:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004534:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004537:	85 c0                	test   eax,eax
   140004539:	7f 10                	jg     14000454b <__pformat_emit_float+0x33c>
   14000453b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000453f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004542:	25 00 08 00 00       	and    eax,0x800
   140004547:	85 c0                	test   eax,eax
   140004549:	74 0c                	je     140004557 <__pformat_emit_float+0x348>
   14000454b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000454f:	48 89 c1             	mov    rcx,rax
   140004552:	e8 1b fa ff ff       	call   140003f72 <__pformat_emit_radix_point>
   140004557:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000455b:	79 5f                	jns    1400045bc <__pformat_emit_float+0x3ad>
   14000455d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004561:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004564:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004567:	01 c2                	add    edx,eax
   140004569:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000456d:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004570:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004574:	48 89 c2             	mov    rdx,rax
   140004577:	b9 30 00 00 00       	mov    ecx,0x30
   14000457c:	e8 af ec ff ff       	call   140003230 <__pformat_putc>
   140004581:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   140004585:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004589:	78 e5                	js     140004570 <__pformat_emit_float+0x361>
   14000458b:	eb 2f                	jmp    1400045bc <__pformat_emit_float+0x3ad>
   14000458d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004591:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004594:	84 c0                	test   al,al
   140004596:	74 14                	je     1400045ac <__pformat_emit_float+0x39d>
   140004598:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000459c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400045a0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400045a4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400045a7:	0f be c0             	movsx  eax,al
   1400045aa:	eb 05                	jmp    1400045b1 <__pformat_emit_float+0x3a2>
   1400045ac:	b8 30 00 00 00       	mov    eax,0x30
   1400045b1:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400045b5:	89 c1                	mov    ecx,eax
   1400045b7:	e8 74 ec ff ff       	call   140003230 <__pformat_putc>
   1400045bc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045c0:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400045c3:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400045c6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400045ca:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   1400045cd:	85 c0                	test   eax,eax
   1400045cf:	7f bc                	jg     14000458d <__pformat_emit_float+0x37e>
   1400045d1:	90                   	nop
   1400045d2:	90                   	nop
   1400045d3:	48 83 c4 30          	add    rsp,0x30
   1400045d7:	5d                   	pop    rbp
   1400045d8:	c3                   	ret

00000001400045d9 <__pformat_emit_efloat>:
   1400045d9:	55                   	push   rbp
   1400045da:	48 89 e5             	mov    rbp,rsp
   1400045dd:	48 83 ec 50          	sub    rsp,0x50
   1400045e1:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400045e4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400045e8:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400045ec:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400045f0:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400045f7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400045fb:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400045ff:	79 09                	jns    14000460a <__pformat_emit_efloat+0x31>
   140004601:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004608:	eb 05                	jmp    14000460f <__pformat_emit_efloat+0x36>
   14000460a:	b8 00 00 00 00       	mov    eax,0x0
   14000460f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140004613:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004616:	48 98                	cdqe
   140004618:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000461c:	eb 04                	jmp    140004622 <__pformat_emit_efloat+0x49>
   14000461e:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140004622:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004625:	48 63 d0             	movsxd rdx,eax
   140004628:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   14000462f:	48 c1 ea 20          	shr    rdx,0x20
   140004633:	89 d1                	mov    ecx,edx
   140004635:	c1 f9 02             	sar    ecx,0x2
   140004638:	99                   	cdq
   140004639:	89 c8                	mov    eax,ecx
   14000463b:	29 d0                	sub    eax,edx
   14000463d:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004640:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004644:	75 d8                	jne    14000461e <__pformat_emit_efloat+0x45>
   140004646:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000464a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000464d:	83 f8 ff             	cmp    eax,0xffffffff
   140004650:	75 0b                	jne    14000465d <__pformat_emit_efloat+0x84>
   140004652:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004656:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   14000465d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004661:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004664:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004667:	7d 0a                	jge    140004673 <__pformat_emit_efloat+0x9a>
   140004669:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000466d:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004670:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004673:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004677:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000467a:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   14000467e:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004681:	7d 15                	jge    140004698 <__pformat_emit_efloat+0xbf>
   140004683:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004687:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000468a:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   14000468d:	89 c2                	mov    edx,eax
   14000468f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004693:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004696:	eb 0b                	jmp    1400046a3 <__pformat_emit_efloat+0xca>
   140004698:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000469c:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400046a3:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400046a7:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400046ab:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400046ae:	49 89 c9             	mov    r9,rcx
   1400046b1:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400046b7:	89 c1                	mov    ecx,eax
   1400046b9:	e8 51 fb ff ff       	call   14000420f <__pformat_emit_float>
   1400046be:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046c2:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   1400046c5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046c9:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400046cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046d0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400046d3:	0d c0 01 00 00       	or     eax,0x1c0
   1400046d8:	89 c2                	mov    edx,eax
   1400046da:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046de:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400046e1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046e5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400046e8:	83 e0 20             	and    eax,0x20
   1400046eb:	83 c8 45             	or     eax,0x45
   1400046ee:	89 c1                	mov    ecx,eax
   1400046f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046f4:	48 89 c2             	mov    rdx,rax
   1400046f7:	e8 34 eb ff ff       	call   140003230 <__pformat_putc>
   1400046fc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004700:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004703:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140004706:	83 ea 01             	sub    edx,0x1
   140004709:	01 c2                	add    edx,eax
   14000470b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000470f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004712:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004716:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   14000471a:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000471e:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140004722:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004726:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000472a:	48 89 c1             	mov    rcx,rax
   14000472d:	e8 69 ef ff ff       	call   14000369b <__pformat_int>
   140004732:	90                   	nop
   140004733:	48 83 c4 50          	add    rsp,0x50
   140004737:	5d                   	pop    rbp
   140004738:	c3                   	ret

0000000140004739 <__pformat_float>:
   140004739:	55                   	push   rbp
   14000473a:	53                   	push   rbx
   14000473b:	48 83 ec 58          	sub    rsp,0x58
   14000473f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004744:	48 89 cb             	mov    rbx,rcx
   140004747:	db 2b                	fld    TBYTE PTR [rbx]
   140004749:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000474c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004750:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004754:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004757:	85 c0                	test   eax,eax
   140004759:	79 0b                	jns    140004766 <__pformat_float+0x2d>
   14000475b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000475f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004766:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000476a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000476d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004770:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004773:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   140004777:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000477b:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000477f:	4d 89 c1             	mov    r9,r8
   140004782:	49 89 c8             	mov    r8,rcx
   140004785:	48 89 c1             	mov    rcx,rax
   140004788:	e8 93 f7 ff ff       	call   140003f20 <__pformat_fcvt>
   14000478d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004791:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004794:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   140004799:	75 17                	jne    1400047b2 <__pformat_float+0x79>
   14000479b:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000479e:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400047a2:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047a6:	49 89 c8             	mov    r8,rcx
   1400047a9:	89 c1                	mov    ecx,eax
   1400047ab:	e8 74 f9 ff ff       	call   140004124 <__pformat_emit_inf_or_nan>
   1400047b0:	eb 43                	jmp    1400047f5 <__pformat_float+0xbc>
   1400047b2:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400047b5:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047b8:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400047bc:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047c0:	4d 89 c1             	mov    r9,r8
   1400047c3:	41 89 c8             	mov    r8d,ecx
   1400047c6:	89 c1                	mov    ecx,eax
   1400047c8:	e8 42 fa ff ff       	call   14000420f <__pformat_emit_float>
   1400047cd:	eb 11                	jmp    1400047e0 <__pformat_float+0xa7>
   1400047cf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047d3:	48 89 c2             	mov    rdx,rax
   1400047d6:	b9 20 00 00 00       	mov    ecx,0x20
   1400047db:	e8 50 ea ff ff       	call   140003230 <__pformat_putc>
   1400047e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047e4:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400047e7:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400047ea:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400047ee:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400047f1:	85 c0                	test   eax,eax
   1400047f3:	7f da                	jg     1400047cf <__pformat_float+0x96>
   1400047f5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400047f9:	48 89 c1             	mov    rcx,rax
   1400047fc:	e8 4e 17 00 00       	call   140005f4f <__freedtoa>
   140004801:	90                   	nop
   140004802:	48 83 c4 58          	add    rsp,0x58
   140004806:	5b                   	pop    rbx
   140004807:	5d                   	pop    rbp
   140004808:	c3                   	ret

0000000140004809 <__pformat_efloat>:
   140004809:	55                   	push   rbp
   14000480a:	53                   	push   rbx
   14000480b:	48 83 ec 58          	sub    rsp,0x58
   14000480f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004814:	48 89 cb             	mov    rbx,rcx
   140004817:	db 2b                	fld    TBYTE PTR [rbx]
   140004819:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000481c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004820:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004824:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004827:	85 c0                	test   eax,eax
   140004829:	79 0b                	jns    140004836 <__pformat_efloat+0x2d>
   14000482b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000482f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004836:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000483a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000483d:	8d 50 01             	lea    edx,[rax+0x1]
   140004840:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004843:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004846:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000484a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000484e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004852:	4d 89 c1             	mov    r9,r8
   140004855:	49 89 c8             	mov    r8,rcx
   140004858:	48 89 c1             	mov    rcx,rax
   14000485b:	e8 6e f6 ff ff       	call   140003ece <__pformat_ecvt>
   140004860:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004864:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004867:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000486c:	75 17                	jne    140004885 <__pformat_efloat+0x7c>
   14000486e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004871:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004875:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004879:	49 89 c8             	mov    r8,rcx
   14000487c:	89 c1                	mov    ecx,eax
   14000487e:	e8 a1 f8 ff ff       	call   140004124 <__pformat_emit_inf_or_nan>
   140004883:	eb 1b                	jmp    1400048a0 <__pformat_efloat+0x97>
   140004885:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004888:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000488b:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000488f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004893:	4d 89 c1             	mov    r9,r8
   140004896:	41 89 c8             	mov    r8d,ecx
   140004899:	89 c1                	mov    ecx,eax
   14000489b:	e8 39 fd ff ff       	call   1400045d9 <__pformat_emit_efloat>
   1400048a0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400048a4:	48 89 c1             	mov    rcx,rax
   1400048a7:	e8 a3 16 00 00       	call   140005f4f <__freedtoa>
   1400048ac:	90                   	nop
   1400048ad:	48 83 c4 58          	add    rsp,0x58
   1400048b1:	5b                   	pop    rbx
   1400048b2:	5d                   	pop    rbp
   1400048b3:	c3                   	ret

00000001400048b4 <__pformat_gfloat>:
   1400048b4:	55                   	push   rbp
   1400048b5:	53                   	push   rbx
   1400048b6:	48 83 ec 58          	sub    rsp,0x58
   1400048ba:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400048bf:	48 89 cb             	mov    rbx,rcx
   1400048c2:	db 2b                	fld    TBYTE PTR [rbx]
   1400048c4:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400048c7:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400048cb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048cf:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048d2:	85 c0                	test   eax,eax
   1400048d4:	79 0d                	jns    1400048e3 <__pformat_gfloat+0x2f>
   1400048d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048da:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400048e1:	eb 16                	jmp    1400048f9 <__pformat_gfloat+0x45>
   1400048e3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048e7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048ea:	85 c0                	test   eax,eax
   1400048ec:	75 0b                	jne    1400048f9 <__pformat_gfloat+0x45>
   1400048ee:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048f2:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   1400048f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048fd:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004900:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004903:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004906:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000490a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000490e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004912:	4d 89 c1             	mov    r9,r8
   140004915:	49 89 c8             	mov    r8,rcx
   140004918:	48 89 c1             	mov    rcx,rax
   14000491b:	e8 ae f5 ff ff       	call   140003ece <__pformat_ecvt>
   140004920:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004924:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004927:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000492c:	75 1a                	jne    140004948 <__pformat_gfloat+0x94>
   14000492e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004931:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004935:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004939:	49 89 c8             	mov    r8,rcx
   14000493c:	89 c1                	mov    ecx,eax
   14000493e:	e8 e1 f7 ff ff       	call   140004124 <__pformat_emit_inf_or_nan>
   140004943:	e9 14 01 00 00       	jmp    140004a5c <__pformat_gfloat+0x1a8>
   140004948:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000494b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000494e:	0f 8c b2 00 00 00    	jl     140004a06 <__pformat_gfloat+0x152>
   140004954:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004958:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000495b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000495e:	39 c2                	cmp    edx,eax
   140004960:	0f 8c a0 00 00 00    	jl     140004a06 <__pformat_gfloat+0x152>
   140004966:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000496a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000496d:	25 00 08 00 00       	and    eax,0x800
   140004972:	85 c0                	test   eax,eax
   140004974:	74 15                	je     14000498b <__pformat_gfloat+0xd7>
   140004976:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000497a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000497d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004980:	29 c2                	sub    edx,eax
   140004982:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004986:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004989:	eb 20                	jmp    1400049ab <__pformat_gfloat+0xf7>
   14000498b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000498f:	48 89 c1             	mov    rcx,rax
   140004992:	e8 81 4d 00 00       	call   140009718 <strlen>
   140004997:	89 c1                	mov    ecx,eax
   140004999:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000499c:	89 c2                	mov    edx,eax
   14000499e:	89 c8                	mov    eax,ecx
   1400049a0:	29 d0                	sub    eax,edx
   1400049a2:	89 c2                	mov    edx,eax
   1400049a4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049a8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049ab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049af:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049b2:	85 c0                	test   eax,eax
   1400049b4:	79 0b                	jns    1400049c1 <__pformat_gfloat+0x10d>
   1400049b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049ba:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   1400049c1:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400049c4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400049c7:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400049cb:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400049cf:	4d 89 c1             	mov    r9,r8
   1400049d2:	41 89 c8             	mov    r8d,ecx
   1400049d5:	89 c1                	mov    ecx,eax
   1400049d7:	e8 33 f8 ff ff       	call   14000420f <__pformat_emit_float>
   1400049dc:	eb 11                	jmp    1400049ef <__pformat_gfloat+0x13b>
   1400049de:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049e2:	48 89 c2             	mov    rdx,rax
   1400049e5:	b9 20 00 00 00       	mov    ecx,0x20
   1400049ea:	e8 41 e8 ff ff       	call   140003230 <__pformat_putc>
   1400049ef:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049f3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400049f6:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400049f9:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400049fd:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004a00:	85 c0                	test   eax,eax
   140004a02:	7f da                	jg     1400049de <__pformat_gfloat+0x12a>
   140004a04:	eb 56                	jmp    140004a5c <__pformat_gfloat+0x1a8>
   140004a06:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a0a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004a0d:	25 00 08 00 00       	and    eax,0x800
   140004a12:	85 c0                	test   eax,eax
   140004a14:	74 13                	je     140004a29 <__pformat_gfloat+0x175>
   140004a16:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a1a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a1d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004a20:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a24:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a27:	eb 18                	jmp    140004a41 <__pformat_gfloat+0x18d>
   140004a29:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a2d:	48 89 c1             	mov    rcx,rax
   140004a30:	e8 e3 4c 00 00       	call   140009718 <strlen>
   140004a35:	83 e8 01             	sub    eax,0x1
   140004a38:	89 c2                	mov    edx,eax
   140004a3a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a3e:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a41:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004a44:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004a47:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   140004a4b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004a4f:	4d 89 c1             	mov    r9,r8
   140004a52:	41 89 c8             	mov    r8d,ecx
   140004a55:	89 c1                	mov    ecx,eax
   140004a57:	e8 7d fb ff ff       	call   1400045d9 <__pformat_emit_efloat>
   140004a5c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a60:	48 89 c1             	mov    rcx,rax
   140004a63:	e8 e7 14 00 00       	call   140005f4f <__freedtoa>
   140004a68:	90                   	nop
   140004a69:	48 83 c4 58          	add    rsp,0x58
   140004a6d:	5b                   	pop    rbx
   140004a6e:	5d                   	pop    rbp
   140004a6f:	c3                   	ret

0000000140004a70 <__pformat_emit_xfloat>:
   140004a70:	55                   	push   rbp
   140004a71:	53                   	push   rbx
   140004a72:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140004a79:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140004a80:	00 
   140004a81:	48 89 cb             	mov    rbx,rcx
   140004a84:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004a88:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004a8c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004a90:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   140004a96:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a99:	48 85 c0             	test   rax,rax
   140004a9c:	75 09                	jne    140004aa7 <__pformat_emit_xfloat+0x37>
   140004a9e:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004aa2:	66 85 c0             	test   ax,ax
   140004aa5:	74 0b                	je     140004ab2 <__pformat_emit_xfloat+0x42>
   140004aa7:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004aab:	83 e8 03             	sub    eax,0x3
   140004aae:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004ab2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ab6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ab9:	85 c0                	test   eax,eax
   140004abb:	0f 88 90 00 00 00    	js     140004b51 <__pformat_emit_xfloat+0xe1>
   140004ac1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ac5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ac8:	83 f8 0e             	cmp    eax,0xe
   140004acb:	0f 8f 80 00 00 00    	jg     140004b51 <__pformat_emit_xfloat+0xe1>
   140004ad1:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ad4:	48 d1 e8             	shr    rax,1
   140004ad7:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004ada:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004add:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ae1:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ae4:	b9 0e 00 00 00       	mov    ecx,0xe
   140004ae9:	29 c1                	sub    ecx,eax
   140004aeb:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004af2:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004af8:	89 c1                	mov    ecx,eax
   140004afa:	49 d3 e0             	shl    r8,cl
   140004afd:	4c 89 c0             	mov    rax,r8
   140004b00:	48 01 d0             	add    rax,rdx
   140004b03:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b06:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b09:	48 85 c0             	test   rax,rax
   140004b0c:	78 0b                	js     140004b19 <__pformat_emit_xfloat+0xa9>
   140004b0e:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b11:	48 01 c0             	add    rax,rax
   140004b14:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b17:	eb 15                	jmp    140004b2e <__pformat_emit_xfloat+0xbe>
   140004b19:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004b1d:	83 c0 04             	add    eax,0x4
   140004b20:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004b24:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b27:	48 c1 e8 03          	shr    rax,0x3
   140004b2b:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b2e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004b31:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b35:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b38:	b9 0f 00 00 00       	mov    ecx,0xf
   140004b3d:	29 c1                	sub    ecx,eax
   140004b3f:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004b46:	89 c1                	mov    ecx,eax
   140004b48:	48 d3 ea             	shr    rdx,cl
   140004b4b:	48 89 d0             	mov    rax,rdx
   140004b4e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b51:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b54:	48 85 c0             	test   rax,rax
   140004b57:	75 0f                	jne    140004b68 <__pformat_emit_xfloat+0xf8>
   140004b59:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b5d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b60:	85 c0                	test   eax,eax
   140004b62:	0f 8e f8 00 00 00    	jle    140004c60 <__pformat_emit_xfloat+0x1f0>
   140004b68:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b6c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b6f:	83 f8 0e             	cmp    eax,0xe
   140004b72:	7f 1a                	jg     140004b8e <__pformat_emit_xfloat+0x11e>
   140004b74:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b78:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b7b:	85 c0                	test   eax,eax
   140004b7d:	78 0f                	js     140004b8e <__pformat_emit_xfloat+0x11e>
   140004b7f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b83:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b86:	83 c0 01             	add    eax,0x1
   140004b89:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004b8c:	eb 07                	jmp    140004b95 <__pformat_emit_xfloat+0x125>
   140004b8e:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004b95:	e9 bc 00 00 00       	jmp    140004c56 <__pformat_emit_xfloat+0x1e6>
   140004b9a:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b9d:	83 e0 0f             	and    eax,0xf
   140004ba0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004ba3:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004ba7:	75 36                	jne    140004bdf <__pformat_emit_xfloat+0x16f>
   140004ba9:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004bad:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004bb1:	72 1b                	jb     140004bce <__pformat_emit_xfloat+0x15e>
   140004bb3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bb7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004bba:	25 00 08 00 00       	and    eax,0x800
   140004bbf:	85 c0                	test   eax,eax
   140004bc1:	75 0b                	jne    140004bce <__pformat_emit_xfloat+0x15e>
   140004bc3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bc7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bca:	85 c0                	test   eax,eax
   140004bcc:	7e 2d                	jle    140004bfb <__pformat_emit_xfloat+0x18b>
   140004bce:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004bd2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004bd6:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004bda:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004bdd:	eb 1c                	jmp    140004bfb <__pformat_emit_xfloat+0x18b>
   140004bdf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004be3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004be6:	85 c0                	test   eax,eax
   140004be8:	7e 11                	jle    140004bfb <__pformat_emit_xfloat+0x18b>
   140004bea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bee:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bf1:	8d 50 ff             	lea    edx,[rax-0x1]
   140004bf4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bf8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004bfb:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004bff:	75 15                	jne    140004c16 <__pformat_emit_xfloat+0x1a6>
   140004c01:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c05:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004c09:	72 0b                	jb     140004c16 <__pformat_emit_xfloat+0x1a6>
   140004c0b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c0f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c12:	85 c0                	test   eax,eax
   140004c14:	78 32                	js     140004c48 <__pformat_emit_xfloat+0x1d8>
   140004c16:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004c1a:	76 16                	jbe    140004c32 <__pformat_emit_xfloat+0x1c2>
   140004c1c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004c1f:	8d 50 37             	lea    edx,[rax+0x37]
   140004c22:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c26:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c29:	83 e0 20             	and    eax,0x20
   140004c2c:	09 d0                	or     eax,edx
   140004c2e:	89 c1                	mov    ecx,eax
   140004c30:	eb 08                	jmp    140004c3a <__pformat_emit_xfloat+0x1ca>
   140004c32:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004c35:	83 c0 30             	add    eax,0x30
   140004c38:	89 c1                	mov    ecx,eax
   140004c3a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c3e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c42:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c46:	88 08                	mov    BYTE PTR [rax],cl
   140004c48:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004c4b:	48 c1 e8 04          	shr    rax,0x4
   140004c4f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004c52:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004c56:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004c5a:	0f 8f 3a ff ff ff    	jg     140004b9a <__pformat_emit_xfloat+0x12a>
   140004c60:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c64:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004c68:	75 39                	jne    140004ca3 <__pformat_emit_xfloat+0x233>
   140004c6a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c6e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c71:	85 c0                	test   eax,eax
   140004c73:	7f 10                	jg     140004c85 <__pformat_emit_xfloat+0x215>
   140004c75:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c79:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c7c:	25 00 08 00 00       	and    eax,0x800
   140004c81:	85 c0                	test   eax,eax
   140004c83:	74 0f                	je     140004c94 <__pformat_emit_xfloat+0x224>
   140004c85:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c89:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c8d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c91:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004c94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c98:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c9c:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004ca0:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004ca3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ca7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004caa:	85 c0                	test   eax,eax
   140004cac:	0f 8e e3 00 00 00    	jle    140004d95 <__pformat_emit_xfloat+0x325>
   140004cb2:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004cb6:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004cba:	48 29 c2             	sub    rdx,rax
   140004cbd:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004cc0:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004cc4:	98                   	cwde
   140004cc5:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004cc8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ccc:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ccf:	85 c0                	test   eax,eax
   140004cd1:	7e 0a                	jle    140004cdd <__pformat_emit_xfloat+0x26d>
   140004cd3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cd7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004cda:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004cdd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ce1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ce4:	25 c0 01 00 00       	and    eax,0x1c0
   140004ce9:	85 c0                	test   eax,eax
   140004ceb:	74 07                	je     140004cf4 <__pformat_emit_xfloat+0x284>
   140004ced:	b8 06 00 00 00       	mov    eax,0x6
   140004cf2:	eb 05                	jmp    140004cf9 <__pformat_emit_xfloat+0x289>
   140004cf4:	b8 05 00 00 00       	mov    eax,0x5
   140004cf9:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004cfc:	eb 0f                	jmp    140004d0d <__pformat_emit_xfloat+0x29d>
   140004cfe:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004d02:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004d06:	83 c0 01             	add    eax,0x1
   140004d09:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004d0d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004d10:	48 63 d0             	movsxd rdx,eax
   140004d13:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004d1a:	48 c1 ea 20          	shr    rdx,0x20
   140004d1e:	89 d1                	mov    ecx,edx
   140004d20:	c1 f9 02             	sar    ecx,0x2
   140004d23:	99                   	cdq
   140004d24:	89 c8                	mov    eax,ecx
   140004d26:	29 d0                	sub    eax,edx
   140004d28:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004d2b:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004d2f:	75 cd                	jne    140004cfe <__pformat_emit_xfloat+0x28e>
   140004d31:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d35:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d38:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004d3b:	7d 4d                	jge    140004d8a <__pformat_emit_xfloat+0x31a>
   140004d3d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d41:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d44:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004d47:	89 c2                	mov    edx,eax
   140004d49:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d4d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004d50:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d54:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d57:	25 00 06 00 00       	and    eax,0x600
   140004d5c:	85 c0                	test   eax,eax
   140004d5e:	75 35                	jne    140004d95 <__pformat_emit_xfloat+0x325>
   140004d60:	eb 11                	jmp    140004d73 <__pformat_emit_xfloat+0x303>
   140004d62:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d66:	48 89 c2             	mov    rdx,rax
   140004d69:	b9 20 00 00 00       	mov    ecx,0x20
   140004d6e:	e8 bd e4 ff ff       	call   140003230 <__pformat_putc>
   140004d73:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d77:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d7a:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004d7d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d81:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004d84:	85 c0                	test   eax,eax
   140004d86:	7f da                	jg     140004d62 <__pformat_emit_xfloat+0x2f2>
   140004d88:	eb 0b                	jmp    140004d95 <__pformat_emit_xfloat+0x325>
   140004d8a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d8e:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004d95:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d99:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d9c:	25 80 00 00 00       	and    eax,0x80
   140004da1:	85 c0                	test   eax,eax
   140004da3:	74 13                	je     140004db8 <__pformat_emit_xfloat+0x348>
   140004da5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004da9:	48 89 c2             	mov    rdx,rax
   140004dac:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004db1:	e8 7a e4 ff ff       	call   140003230 <__pformat_putc>
   140004db6:	eb 42                	jmp    140004dfa <__pformat_emit_xfloat+0x38a>
   140004db8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dbc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dbf:	25 00 01 00 00       	and    eax,0x100
   140004dc4:	85 c0                	test   eax,eax
   140004dc6:	74 13                	je     140004ddb <__pformat_emit_xfloat+0x36b>
   140004dc8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dcc:	48 89 c2             	mov    rdx,rax
   140004dcf:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004dd4:	e8 57 e4 ff ff       	call   140003230 <__pformat_putc>
   140004dd9:	eb 1f                	jmp    140004dfa <__pformat_emit_xfloat+0x38a>
   140004ddb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ddf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004de2:	83 e0 40             	and    eax,0x40
   140004de5:	85 c0                	test   eax,eax
   140004de7:	74 11                	je     140004dfa <__pformat_emit_xfloat+0x38a>
   140004de9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ded:	48 89 c2             	mov    rdx,rax
   140004df0:	b9 20 00 00 00       	mov    ecx,0x20
   140004df5:	e8 36 e4 ff ff       	call   140003230 <__pformat_putc>
   140004dfa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dfe:	48 89 c2             	mov    rdx,rax
   140004e01:	b9 30 00 00 00       	mov    ecx,0x30
   140004e06:	e8 25 e4 ff ff       	call   140003230 <__pformat_putc>
   140004e0b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e0f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e12:	83 e0 20             	and    eax,0x20
   140004e15:	83 c8 58             	or     eax,0x58
   140004e18:	89 c1                	mov    ecx,eax
   140004e1a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e1e:	48 89 c2             	mov    rdx,rax
   140004e21:	e8 0a e4 ff ff       	call   140003230 <__pformat_putc>
   140004e26:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e2a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e2d:	85 c0                	test   eax,eax
   140004e2f:	7e 54                	jle    140004e85 <__pformat_emit_xfloat+0x415>
   140004e31:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e35:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e38:	25 00 02 00 00       	and    eax,0x200
   140004e3d:	85 c0                	test   eax,eax
   140004e3f:	74 44                	je     140004e85 <__pformat_emit_xfloat+0x415>
   140004e41:	eb 11                	jmp    140004e54 <__pformat_emit_xfloat+0x3e4>
   140004e43:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e47:	48 89 c2             	mov    rdx,rax
   140004e4a:	b9 30 00 00 00       	mov    ecx,0x30
   140004e4f:	e8 dc e3 ff ff       	call   140003230 <__pformat_putc>
   140004e54:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e58:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e5b:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e5e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e62:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004e65:	85 c0                	test   eax,eax
   140004e67:	7f da                	jg     140004e43 <__pformat_emit_xfloat+0x3d3>
   140004e69:	eb 1a                	jmp    140004e85 <__pformat_emit_xfloat+0x415>
   140004e6b:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004e70:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004e74:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004e77:	0f be c0             	movsx  eax,al
   140004e7a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e7e:	89 c1                	mov    ecx,eax
   140004e80:	e8 32 f2 ff ff       	call   1400040b7 <__pformat_emit_numeric_value>
   140004e85:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004e89:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004e8d:	72 dc                	jb     140004e6b <__pformat_emit_xfloat+0x3fb>
   140004e8f:	eb 11                	jmp    140004ea2 <__pformat_emit_xfloat+0x432>
   140004e91:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e95:	48 89 c2             	mov    rdx,rax
   140004e98:	b9 30 00 00 00       	mov    ecx,0x30
   140004e9d:	e8 8e e3 ff ff       	call   140003230 <__pformat_putc>
   140004ea2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ea6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ea9:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004eac:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004eb0:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004eb3:	85 c0                	test   eax,eax
   140004eb5:	7f da                	jg     140004e91 <__pformat_emit_xfloat+0x421>
   140004eb7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ebb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ebe:	83 e0 20             	and    eax,0x20
   140004ec1:	83 c8 50             	or     eax,0x50
   140004ec4:	89 c1                	mov    ecx,eax
   140004ec6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eca:	48 89 c2             	mov    rdx,rax
   140004ecd:	e8 5e e3 ff ff       	call   140003230 <__pformat_putc>
   140004ed2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ed6:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004ed9:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004edd:	01 c2                	add    edx,eax
   140004edf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ee3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004ee6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eea:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004eed:	0d c0 01 00 00       	or     eax,0x1c0
   140004ef2:	89 c2                	mov    edx,eax
   140004ef4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ef8:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004efb:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004eff:	66 85 c0             	test   ax,ax
   140004f02:	79 09                	jns    140004f0d <__pformat_emit_xfloat+0x49d>
   140004f04:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004f0b:	eb 05                	jmp    140004f12 <__pformat_emit_xfloat+0x4a2>
   140004f0d:	b8 00 00 00 00       	mov    eax,0x0
   140004f12:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004f16:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004f1a:	48 0f bf c0          	movsx  rax,ax
   140004f1e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004f22:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004f26:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004f2a:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004f2e:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004f32:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004f36:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004f3a:	48 89 c1             	mov    rcx,rax
   140004f3d:	e8 59 e7 ff ff       	call   14000369b <__pformat_int>
   140004f42:	90                   	nop
   140004f43:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004f4a:	5b                   	pop    rbx
   140004f4b:	5d                   	pop    rbp
   140004f4c:	c3                   	ret

0000000140004f4d <__pformat_xldouble>:
   140004f4d:	55                   	push   rbp
   140004f4e:	53                   	push   rbx
   140004f4f:	48 83 ec 78          	sub    rsp,0x78
   140004f53:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004f58:	48 89 cb             	mov    rbx,rcx
   140004f5b:	db 2b                	fld    TBYTE PTR [rbx]
   140004f5d:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004f60:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004f64:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004f6b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004f6f:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f72:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f75:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004f79:	48 89 c1             	mov    rcx,rax
   140004f7c:	e8 e5 ed ff ff       	call   140003d66 <init_fpreg_ldouble>
   140004f81:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f84:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f87:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f8b:	48 89 c1             	mov    rcx,rax
   140004f8e:	e8 ed 3d 00 00       	call   140008d80 <__isnanl>
   140004f93:	85 c0                	test   eax,eax
   140004f95:	74 1d                	je     140004fb4 <__pformat_xldouble+0x67>
   140004f97:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f9a:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f9e:	48 8d 15 a1 63 00 00 	lea    rdx,[rip+0x63a1]        # 14000b346 <.rdata+0x16>
   140004fa5:	49 89 c8             	mov    r8,rcx
   140004fa8:	89 c1                	mov    ecx,eax
   140004faa:	e8 75 f1 ff ff       	call   140004124 <__pformat_emit_inf_or_nan>
   140004faf:	e9 aa 00 00 00       	jmp    14000505e <__pformat_xldouble+0x111>
   140004fb4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fb8:	98                   	cwde
   140004fb9:	25 00 80 00 00       	and    eax,0x8000
   140004fbe:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004fc1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004fc5:	74 12                	je     140004fd9 <__pformat_xldouble+0x8c>
   140004fc7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004fcb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004fce:	0c 80                	or     al,0x80
   140004fd0:	89 c2                	mov    edx,eax
   140004fd2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004fd6:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004fd9:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004fdc:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004fdf:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004fe3:	48 89 c1             	mov    rcx,rax
   140004fe6:	e8 a5 3c 00 00       	call   140008c90 <__fpclassifyl>
   140004feb:	3d 00 05 00 00       	cmp    eax,0x500
   140004ff0:	75 1a                	jne    14000500c <__pformat_xldouble+0xbf>
   140004ff2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004ff5:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004ff9:	48 8d 15 4a 63 00 00 	lea    rdx,[rip+0x634a]        # 14000b34a <.rdata+0x1a>
   140005000:	49 89 c8             	mov    r8,rcx
   140005003:	89 c1                	mov    ecx,eax
   140005005:	e8 1a f1 ff ff       	call   140004124 <__pformat_emit_inf_or_nan>
   14000500a:	eb 52                	jmp    14000505e <__pformat_xldouble+0x111>
   14000500c:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005010:	66 25 ff 7f          	and    ax,0x7fff
   140005014:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005018:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000501c:	66 85 c0             	test   ax,ax
   14000501f:	75 11                	jne    140005032 <__pformat_xldouble+0xe5>
   140005021:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005025:	48 85 c0             	test   rax,rax
   140005028:	74 14                	je     14000503e <__pformat_xldouble+0xf1>
   14000502a:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140005030:	eb 0c                	jmp    14000503e <__pformat_xldouble+0xf1>
   140005032:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005036:	66 2d ff 3f          	sub    ax,0x3fff
   14000503a:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000503e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005042:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005046:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000504a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   14000504e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140005052:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140005056:	48 89 c1             	mov    rcx,rax
   140005059:	e8 12 fa ff ff       	call   140004a70 <__pformat_emit_xfloat>
   14000505e:	90                   	nop
   14000505f:	48 83 c4 78          	add    rsp,0x78
   140005063:	5b                   	pop    rbx
   140005064:	5d                   	pop    rbp
   140005065:	c3                   	ret

0000000140005066 <__pformat_xdouble>:
   140005066:	55                   	push   rbp
   140005067:	48 89 e5             	mov    rbp,rsp
   14000506a:	48 83 ec 60          	sub    rsp,0x60
   14000506e:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140005073:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005077:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000507e:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140005081:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140005085:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140005088:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   14000508c:	48 89 c1             	mov    rcx,rax
   14000508f:	e8 d2 ec ff ff       	call   140003d66 <init_fpreg_ldouble>
   140005094:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005098:	66 48 0f 6e c0       	movq   xmm0,rax
   14000509d:	e8 7e 3c 00 00       	call   140008d20 <__isnan>
   1400050a2:	85 c0                	test   eax,eax
   1400050a4:	74 1d                	je     1400050c3 <__pformat_xdouble+0x5d>
   1400050a6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400050a9:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   1400050ad:	48 8d 15 92 62 00 00 	lea    rdx,[rip+0x6292]        # 14000b346 <.rdata+0x16>
   1400050b4:	49 89 c8             	mov    r8,rcx
   1400050b7:	89 c1                	mov    ecx,eax
   1400050b9:	e8 66 f0 ff ff       	call   140004124 <__pformat_emit_inf_or_nan>
   1400050be:	e9 f9 00 00 00       	jmp    1400051bc <__pformat_xdouble+0x156>
   1400050c3:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050c7:	98                   	cwde
   1400050c8:	25 00 80 00 00       	and    eax,0x8000
   1400050cd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400050d0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400050d4:	74 12                	je     1400050e8 <__pformat_xdouble+0x82>
   1400050d6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400050da:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400050dd:	0c 80                	or     al,0x80
   1400050df:	89 c2                	mov    edx,eax
   1400050e1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400050e5:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400050e8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400050ec:	66 48 0f 6e c0       	movq   xmm0,rax
   1400050f1:	e8 1a 3b 00 00       	call   140008c10 <__fpclassify>
   1400050f6:	3d 00 05 00 00       	cmp    eax,0x500
   1400050fb:	75 1d                	jne    14000511a <__pformat_xdouble+0xb4>
   1400050fd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005100:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140005104:	48 8d 15 3f 62 00 00 	lea    rdx,[rip+0x623f]        # 14000b34a <.rdata+0x1a>
   14000510b:	49 89 c8             	mov    r8,rcx
   14000510e:	89 c1                	mov    ecx,eax
   140005110:	e8 0f f0 ff ff       	call   140004124 <__pformat_emit_inf_or_nan>
   140005115:	e9 a2 00 00 00       	jmp    1400051bc <__pformat_xdouble+0x156>
   14000511a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000511e:	66 25 ff 7f          	and    ax,0x7fff
   140005122:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005126:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000512a:	66 85 c0             	test   ax,ax
   14000512d:	74 3b                	je     14000516a <__pformat_xdouble+0x104>
   14000512f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005133:	66 3d 00 3c          	cmp    ax,0x3c00
   140005137:	7f 31                	jg     14000516a <__pformat_xdouble+0x104>
   140005139:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000513d:	98                   	cwde
   14000513e:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005143:	29 c2                	sub    edx,eax
   140005145:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005148:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000514c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000514f:	89 c1                	mov    ecx,eax
   140005151:	48 d3 ea             	shr    rdx,cl
   140005154:	48 89 d0             	mov    rax,rdx
   140005157:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000515b:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000515f:	89 c2                	mov    edx,eax
   140005161:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005164:	01 d0                	add    eax,edx
   140005166:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000516a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000516e:	66 85 c0             	test   ax,ax
   140005171:	75 11                	jne    140005184 <__pformat_xdouble+0x11e>
   140005173:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005177:	48 85 c0             	test   rax,rax
   14000517a:	74 14                	je     140005190 <__pformat_xdouble+0x12a>
   14000517c:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   140005182:	eb 0c                	jmp    140005190 <__pformat_xdouble+0x12a>
   140005184:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005188:	66 2d fc 3f          	sub    ax,0x3ffc
   14000518c:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005190:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005194:	48 c1 e8 03          	shr    rax,0x3
   140005198:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000519c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400051a0:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400051a4:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400051a8:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400051ac:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400051b0:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   1400051b4:	48 89 c1             	mov    rcx,rax
   1400051b7:	e8 b4 f8 ff ff       	call   140004a70 <__pformat_emit_xfloat>
   1400051bc:	90                   	nop
   1400051bd:	48 83 c4 60          	add    rsp,0x60
   1400051c1:	5d                   	pop    rbp
   1400051c2:	c3                   	ret

00000001400051c3 <__mingw_pformat>:
   1400051c3:	55                   	push   rbp
   1400051c4:	48 89 e5             	mov    rbp,rsp
   1400051c7:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   1400051ce:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400051d1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400051d5:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400051d9:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400051dd:	e8 a6 44 00 00       	call   140009688 <_errno>
   1400051e2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400051e4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400051e7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400051eb:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   1400051ef:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   1400051f6:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400051f9:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400051fc:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   140005203:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   14000520a:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   140005211:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   140005217:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   14000521e:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   140005224:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   14000522b:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   14000522e:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   140005231:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   140005238:	e9 27 0c 00 00       	jmp    140005e64 <__mingw_pformat+0xca1>
   14000523d:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005241:	0f 85 0f 0c 00 00    	jne    140005e56 <__mingw_pformat+0xc93>
   140005247:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000524e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005255:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005259:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000525d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005261:	48 83 c0 0c          	add    rax,0xc
   140005265:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005269:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000526c:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000526f:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005276:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140005279:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000527c:	e9 c4 0b 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005281:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005285:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005289:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000528d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005290:	0f be c0             	movsx  eax,al
   140005293:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005296:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   14000529a:	0f 84 94 09 00 00    	je     140005c34 <__mingw_pformat+0xa71>
   1400052a0:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400052a4:	0f 8f 02 0b 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400052aa:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400052ae:	0f 84 eb 03 00 00    	je     14000569f <__mingw_pformat+0x4dc>
   1400052b4:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400052b8:	0f 8f ee 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400052be:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400052c2:	0f 84 31 09 00 00    	je     140005bf9 <__mingw_pformat+0xa36>
   1400052c8:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400052cc:	0f 8f da 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400052d2:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400052d6:	0f 84 c3 03 00 00    	je     14000569f <__mingw_pformat+0x4dc>
   1400052dc:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400052e0:	0f 8f c6 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400052e6:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   1400052ea:	0f 84 31 09 00 00    	je     140005c21 <__mingw_pformat+0xa5e>
   1400052f0:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   1400052f4:	0f 8f b2 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400052fa:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   1400052fe:	0f 84 31 03 00 00    	je     140005635 <__mingw_pformat+0x472>
   140005304:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   140005308:	0f 8f 9e 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000530e:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   140005312:	0f 84 28 05 00 00    	je     140005840 <__mingw_pformat+0x67d>
   140005318:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   14000531c:	0f 8f 8a 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005322:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005326:	0f 84 73 03 00 00    	je     14000569f <__mingw_pformat+0x4dc>
   14000532c:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005330:	0f 8f 76 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005336:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   14000533a:	0f 84 4d 07 00 00    	je     140005a8d <__mingw_pformat+0x8ca>
   140005340:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005344:	0f 8f 62 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000534a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000534e:	0f 84 2d 03 00 00    	je     140005681 <__mingw_pformat+0x4be>
   140005354:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   140005358:	0f 8f 4e 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000535e:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   140005362:	0f 84 65 08 00 00    	je     140005bcd <__mingw_pformat+0xa0a>
   140005368:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   14000536c:	0f 8f 3a 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005372:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005376:	0f 84 db 07 00 00    	je     140005b57 <__mingw_pformat+0x994>
   14000537c:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005380:	0f 8f 26 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005386:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   14000538a:	0f 84 ee 03 00 00    	je     14000577e <__mingw_pformat+0x5bb>
   140005390:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   140005394:	0f 8f 12 0a 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000539a:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   14000539e:	0f 84 87 07 00 00    	je     140005b2b <__mingw_pformat+0x968>
   1400053a4:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400053a8:	0f 8f fe 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400053ae:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400053b2:	0f 84 f3 05 00 00    	je     1400059ab <__mingw_pformat+0x7e8>
   1400053b8:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400053bc:	0f 8f ea 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400053c2:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400053c6:	0f 84 61 05 00 00    	je     14000592d <__mingw_pformat+0x76a>
   1400053cc:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400053d0:	0f 8f d6 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400053d6:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400053da:	0f 84 cf 04 00 00    	je     1400058af <__mingw_pformat+0x6ec>
   1400053e0:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400053e4:	0f 8f c2 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400053ea:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   1400053ee:	0f 84 8a 03 00 00    	je     14000577e <__mingw_pformat+0x5bb>
   1400053f4:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   1400053f8:	0f 8f ae 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400053fe:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   140005402:	0f 84 b5 01 00 00    	je     1400055bd <__mingw_pformat+0x3fa>
   140005408:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   14000540c:	0f 8f 9a 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005412:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005416:	0f 84 83 02 00 00    	je     14000569f <__mingw_pformat+0x4dc>
   14000541c:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005420:	0f 8f 86 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005426:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   14000542a:	0f 84 f9 05 00 00    	je     140005a29 <__mingw_pformat+0x866>
   140005430:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   140005434:	0f 8f 72 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000543a:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   14000543e:	0f 84 5b 02 00 00    	je     14000569f <__mingw_pformat+0x4dc>
   140005444:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005448:	0f 8f 5e 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000544e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   140005452:	0f 84 d6 01 00 00    	je     14000562e <__mingw_pformat+0x46b>
   140005458:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   14000545c:	0f 8f 4a 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005462:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005466:	0f 84 a0 07 00 00    	je     140005c0c <__mingw_pformat+0xa49>
   14000546c:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005470:	0f 8f 36 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005476:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   14000547a:	0f 84 ea 06 00 00    	je     140005b6a <__mingw_pformat+0x9a7>
   140005480:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   140005484:	0f 8f 22 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000548a:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   14000548e:	0f 84 20 05 00 00    	je     1400059b4 <__mingw_pformat+0x7f1>
   140005494:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   140005498:	0f 8f 0e 09 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000549e:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400054a2:	0f 84 8e 04 00 00    	je     140005936 <__mingw_pformat+0x773>
   1400054a8:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400054ac:	0f 8f fa 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400054b2:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400054b6:	0f 84 fc 03 00 00    	je     1400058b8 <__mingw_pformat+0x6f5>
   1400054bc:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400054c0:	0f 8f e6 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400054c6:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400054ca:	0f 84 e6 00 00 00    	je     1400055b6 <__mingw_pformat+0x3f3>
   1400054d0:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400054d4:	0f 8f d2 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400054da:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400054de:	0f 84 bb 01 00 00    	je     14000569f <__mingw_pformat+0x4dc>
   1400054e4:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400054e8:	0f 8f be 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   1400054ee:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   1400054f2:	0f 84 3a 05 00 00    	je     140005a32 <__mingw_pformat+0x86f>
   1400054f8:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   1400054fc:	0f 8f aa 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005502:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005506:	0f 84 8c 08 00 00    	je     140005d98 <__mingw_pformat+0xbd5>
   14000550c:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005510:	0f 8f 96 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005516:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   14000551a:	0f 84 27 07 00 00    	je     140005c47 <__mingw_pformat+0xa84>
   140005520:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   140005524:	0f 8f 82 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000552a:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   14000552e:	0f 84 db 07 00 00    	je     140005d0f <__mingw_pformat+0xb4c>
   140005534:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   140005538:	0f 8f 6e 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000553e:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005542:	0f 84 af 07 00 00    	je     140005cf7 <__mingw_pformat+0xb34>
   140005548:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000554c:	0f 8f 5a 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005552:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005556:	0f 84 1c 07 00 00    	je     140005c78 <__mingw_pformat+0xab5>
   14000555c:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005560:	0f 8f 46 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   140005566:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   14000556a:	0f 84 b7 07 00 00    	je     140005d27 <__mingw_pformat+0xb64>
   140005570:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   140005574:	0f 8f 32 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000557a:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   14000557e:	74 23                	je     1400055a3 <__mingw_pformat+0x3e0>
   140005580:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005584:	0f 8f 22 08 00 00    	jg     140005dac <__mingw_pformat+0xbe9>
   14000558a:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   14000558e:	0f 84 ec 07 00 00    	je     140005d80 <__mingw_pformat+0xbbd>
   140005594:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   140005598:	0f 84 41 07 00 00    	je     140005cdf <__mingw_pformat+0xb1c>
   14000559e:	e9 09 08 00 00       	jmp    140005dac <__mingw_pformat+0xbe9>
   1400055a3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055a7:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400055aa:	89 c1                	mov    ecx,eax
   1400055ac:	e8 7f dc ff ff       	call   140003230 <__pformat_putc>
   1400055b1:	e9 82 fc ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   1400055b6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400055bd:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400055c4:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400055c8:	74 06                	je     1400055d0 <__mingw_pformat+0x40d>
   1400055ca:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055ce:	75 30                	jne    140005600 <__mingw_pformat+0x43d>
   1400055d0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055d4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055d8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055dc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055de:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   1400055e2:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055e6:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   1400055ea:	49 89 d0             	mov    r8,rdx
   1400055ed:	ba 01 00 00 00       	mov    edx,0x1
   1400055f2:	48 89 c1             	mov    rcx,rax
   1400055f5:	e8 3f de ff ff       	call   140003439 <__pformat_wputchars>
   1400055fa:	90                   	nop
   1400055fb:	e9 38 fc ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005600:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005604:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005608:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000560c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000560e:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   140005611:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005615:	48 8d 45 90          	lea    rax,[rbp-0x70]
   140005619:	49 89 d0             	mov    r8,rdx
   14000561c:	ba 01 00 00 00       	mov    edx,0x1
   140005621:	48 89 c1             	mov    rcx,rax
   140005624:	e8 8b dc ff ff       	call   1400032b4 <__pformat_putchars>
   140005629:	e9 0a fc ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   14000562e:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005635:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005639:	74 06                	je     140005641 <__mingw_pformat+0x47e>
   14000563b:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000563f:	75 20                	jne    140005661 <__mingw_pformat+0x49e>
   140005641:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005645:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005649:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000564d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005650:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005654:	48 89 c1             	mov    rcx,rax
   140005657:	e8 29 df ff ff       	call   140003585 <__pformat_wcputs>
   14000565c:	e9 d7 fb ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005661:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005665:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005669:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000566d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005670:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005674:	48 89 c1             	mov    rcx,rax
   140005677:	e8 37 dd ff ff       	call   1400033b3 <__pformat_puts>
   14000567c:	e9 b7 fb ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005681:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140005684:	89 c1                	mov    ecx,eax
   140005686:	e8 85 40 00 00       	call   140009710 <strerror>
   14000568b:	48 89 c1             	mov    rcx,rax
   14000568e:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005692:	48 89 c2             	mov    rdx,rax
   140005695:	e8 19 dd ff ff       	call   1400033b3 <__pformat_puts>
   14000569a:	e9 99 fb ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   14000569f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400056a2:	80 e4 fe             	and    ah,0xfe
   1400056a5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400056a8:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400056ac:	75 15                	jne    1400056c3 <__mingw_pformat+0x500>
   1400056ae:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056b2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056b6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056ba:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400056bd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056c1:	eb 54                	jmp    140005717 <__mingw_pformat+0x554>
   1400056c3:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400056c7:	75 16                	jne    1400056df <__mingw_pformat+0x51c>
   1400056c9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056cd:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056d1:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056d5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056d7:	89 c0                	mov    eax,eax
   1400056d9:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056dd:	eb 38                	jmp    140005717 <__mingw_pformat+0x554>
   1400056df:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056e3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056e7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056ed:	89 c0                	mov    eax,eax
   1400056ef:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056f3:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400056f7:	75 0d                	jne    140005706 <__mingw_pformat+0x543>
   1400056f9:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   1400056fd:	0f b7 c0             	movzx  eax,ax
   140005700:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005704:	eb 11                	jmp    140005717 <__mingw_pformat+0x554>
   140005706:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   14000570a:	75 0b                	jne    140005717 <__mingw_pformat+0x554>
   14000570c:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   140005710:	0f b6 c0             	movzx  eax,al
   140005713:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005717:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   14000571b:	75 2e                	jne    14000574b <__mingw_pformat+0x588>
   14000571d:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005721:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005725:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000572c:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005733:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005737:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000573e:	48 89 c1             	mov    rcx,rax
   140005741:	e8 55 df ff ff       	call   14000369b <__pformat_int>
   140005746:	e9 ed fa ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   14000574b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000574f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005753:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000575a:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005761:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140005765:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   14000576c:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000576f:	49 89 c8             	mov    r8,rcx
   140005772:	89 c1                	mov    ecx,eax
   140005774:	e8 a5 e2 ff ff       	call   140003a1e <__pformat_xint>
   140005779:	e9 ba fa ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   14000577e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005781:	0c 80                	or     al,0x80
   140005783:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005786:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000578a:	75 15                	jne    1400057a1 <__mingw_pformat+0x5de>
   14000578c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005790:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005794:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005798:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000579b:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000579f:	eb 56                	jmp    1400057f7 <__mingw_pformat+0x634>
   1400057a1:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400057a5:	75 16                	jne    1400057bd <__mingw_pformat+0x5fa>
   1400057a7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057ab:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057af:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057b3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400057b5:	48 98                	cdqe
   1400057b7:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057bb:	eb 3a                	jmp    1400057f7 <__mingw_pformat+0x634>
   1400057bd:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057c1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057c5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057c9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400057cb:	48 98                	cdqe
   1400057cd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057d1:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400057d5:	75 0e                	jne    1400057e5 <__mingw_pformat+0x622>
   1400057d7:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   1400057db:	48 0f bf c0          	movsx  rax,ax
   1400057df:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057e3:	eb 12                	jmp    1400057f7 <__mingw_pformat+0x634>
   1400057e5:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400057e9:	75 0c                	jne    1400057f7 <__mingw_pformat+0x634>
   1400057eb:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   1400057ef:	48 0f be c0          	movsx  rax,al
   1400057f3:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057f7:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057fb:	48 85 c0             	test   rax,rax
   1400057fe:	79 09                	jns    140005809 <__mingw_pformat+0x646>
   140005800:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140005807:	eb 05                	jmp    14000580e <__mingw_pformat+0x64b>
   140005809:	b8 00 00 00 00       	mov    eax,0x0
   14000580e:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140005812:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005816:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   14000581a:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005821:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005828:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000582c:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   140005833:	48 89 c1             	mov    rcx,rax
   140005836:	e8 60 de ff ff       	call   14000369b <__pformat_int>
   14000583b:	e9 f8 f9 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005840:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005844:	75 18                	jne    14000585e <__mingw_pformat+0x69b>
   140005846:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005849:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000584c:	75 10                	jne    14000585e <__mingw_pformat+0x69b>
   14000584e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005851:	80 cc 02             	or     ah,0x2
   140005854:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005857:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   14000585e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005862:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005866:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000586a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000586d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005871:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   140005878:	00 
   140005879:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000587d:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005881:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005888:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   14000588f:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005893:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000589a:	49 89 d0             	mov    r8,rdx
   14000589d:	48 89 c2             	mov    rdx,rax
   1400058a0:	b9 78 00 00 00       	mov    ecx,0x78
   1400058a5:	e8 74 e1 ff ff       	call   140003a1e <__pformat_xint>
   1400058aa:	e9 89 f9 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   1400058af:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058b2:	83 c8 20             	or     eax,0x20
   1400058b5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400058b8:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058bb:	83 e0 04             	and    eax,0x4
   1400058be:	85 c0                	test   eax,eax
   1400058c0:	74 2f                	je     1400058f1 <__mingw_pformat+0x72e>
   1400058c2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058c6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058ca:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058ce:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400058d1:	db 28                	fld    TBYTE PTR [rax]
   1400058d3:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058d9:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058dd:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058e4:	48 89 c1             	mov    rcx,rax
   1400058e7:	e8 1d ef ff ff       	call   140004809 <__pformat_efloat>
   1400058ec:	e9 47 f9 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   1400058f1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058f5:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058f9:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058fd:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   140005901:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   140005908:	ff 
   140005909:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000590f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005915:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005919:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005920:	48 89 c1             	mov    rcx,rax
   140005923:	e8 e1 ee ff ff       	call   140004809 <__pformat_efloat>
   140005928:	e9 0b f9 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   14000592d:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005930:	83 c8 20             	or     eax,0x20
   140005933:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005936:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005939:	83 e0 04             	and    eax,0x4
   14000593c:	85 c0                	test   eax,eax
   14000593e:	74 2f                	je     14000596f <__mingw_pformat+0x7ac>
   140005940:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005944:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005948:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000594c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000594f:	db 28                	fld    TBYTE PTR [rax]
   140005951:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005957:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000595b:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005962:	48 89 c1             	mov    rcx,rax
   140005965:	e8 cf ed ff ff       	call   140004739 <__pformat_float>
   14000596a:	e9 c9 f8 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   14000596f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005973:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005977:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000597b:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   14000597f:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   140005986:	ff 
   140005987:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000598d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005993:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005997:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000599e:	48 89 c1             	mov    rcx,rax
   1400059a1:	e8 93 ed ff ff       	call   140004739 <__pformat_float>
   1400059a6:	e9 8d f8 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   1400059ab:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059ae:	83 c8 20             	or     eax,0x20
   1400059b1:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400059b4:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059b7:	83 e0 04             	and    eax,0x4
   1400059ba:	85 c0                	test   eax,eax
   1400059bc:	74 2f                	je     1400059ed <__mingw_pformat+0x82a>
   1400059be:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059c2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059c6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059ca:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059cd:	db 28                	fld    TBYTE PTR [rax]
   1400059cf:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059d5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059d9:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059e0:	48 89 c1             	mov    rcx,rax
   1400059e3:	e8 cc ee ff ff       	call   1400048b4 <__pformat_gfloat>
   1400059e8:	e9 4b f8 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   1400059ed:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059f1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059f5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059f9:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   1400059fd:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   140005a04:	ff 
   140005a05:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   140005a0b:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a11:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a15:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a1c:	48 89 c1             	mov    rcx,rax
   140005a1f:	e8 90 ee ff ff       	call   1400048b4 <__pformat_gfloat>
   140005a24:	e9 0f f8 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005a29:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a2c:	83 c8 20             	or     eax,0x20
   140005a2f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005a32:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a35:	83 e0 04             	and    eax,0x4
   140005a38:	85 c0                	test   eax,eax
   140005a3a:	74 2f                	je     140005a6b <__mingw_pformat+0x8a8>
   140005a3c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a40:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a44:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a48:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a4b:	db 28                	fld    TBYTE PTR [rax]
   140005a4d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a53:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a57:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a5e:	48 89 c1             	mov    rcx,rax
   140005a61:	e8 e7 f4 ff ff       	call   140004f4d <__pformat_xldouble>
   140005a66:	e9 cd f7 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005a6b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a6f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a73:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a77:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a7a:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a7e:	66 48 0f 6e c0       	movq   xmm0,rax
   140005a83:	e8 de f5 ff ff       	call   140005066 <__pformat_xdouble>
   140005a88:	e9 ab f7 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005a8d:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005a91:	75 1b                	jne    140005aae <__mingw_pformat+0x8eb>
   140005a93:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a96:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a9a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a9e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005aa2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005aa5:	89 ca                	mov    edx,ecx
   140005aa7:	88 10                	mov    BYTE PTR [rax],dl
   140005aa9:	e9 8a f7 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005aae:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005ab2:	75 1c                	jne    140005ad0 <__mingw_pformat+0x90d>
   140005ab4:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005ab7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005abb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005abf:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ac3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ac6:	89 ca                	mov    edx,ecx
   140005ac8:	66 89 10             	mov    WORD PTR [rax],dx
   140005acb:	e9 68 f7 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005ad0:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005ad4:	75 19                	jne    140005aef <__mingw_pformat+0x92c>
   140005ad6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005ada:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005ade:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ae2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ae5:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005ae8:	89 10                	mov    DWORD PTR [rax],edx
   140005aea:	e9 49 f7 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005aef:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005af3:	75 1d                	jne    140005b12 <__mingw_pformat+0x94f>
   140005af5:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005af8:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005afc:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005b00:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b04:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b07:	48 63 d1             	movsxd rdx,ecx
   140005b0a:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005b0d:	e9 26 f7 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005b12:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005b16:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005b1a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b1e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b21:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005b24:	89 10                	mov    DWORD PTR [rax],edx
   140005b26:	e9 0d f7 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005b2b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b2f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b32:	3c 68                	cmp    al,0x68
   140005b34:	75 0e                	jne    140005b44 <__mingw_pformat+0x981>
   140005b36:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b3b:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005b42:	eb 07                	jmp    140005b4b <__mingw_pformat+0x988>
   140005b44:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005b4b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b52:	e9 ee 02 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005b57:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b5e:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b65:	e9 db 02 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005b6a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b6e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b71:	3c 36                	cmp    al,0x36
   140005b73:	75 1d                	jne    140005b92 <__mingw_pformat+0x9cf>
   140005b75:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b79:	48 83 c0 01          	add    rax,0x1
   140005b7d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b80:	3c 34                	cmp    al,0x34
   140005b82:	75 0e                	jne    140005b92 <__mingw_pformat+0x9cf>
   140005b84:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b8b:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b90:	eb 2f                	jmp    140005bc1 <__mingw_pformat+0x9fe>
   140005b92:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b96:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b99:	3c 33                	cmp    al,0x33
   140005b9b:	75 1d                	jne    140005bba <__mingw_pformat+0x9f7>
   140005b9d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ba1:	48 83 c0 01          	add    rax,0x1
   140005ba5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ba8:	3c 32                	cmp    al,0x32
   140005baa:	75 0e                	jne    140005bba <__mingw_pformat+0x9f7>
   140005bac:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005bb3:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005bb8:	eb 07                	jmp    140005bc1 <__mingw_pformat+0x9fe>
   140005bba:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bc1:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bc8:	e9 78 02 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005bcd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005bd1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005bd4:	3c 6c                	cmp    al,0x6c
   140005bd6:	75 0e                	jne    140005be6 <__mingw_pformat+0xa23>
   140005bd8:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005bdd:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005be4:	eb 07                	jmp    140005bed <__mingw_pformat+0xa2a>
   140005be6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005bed:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bf4:	e9 4c 02 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005bf9:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005c00:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c07:	e9 39 02 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005c0c:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c0f:	83 c8 04             	or     eax,0x4
   140005c12:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c15:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c1c:	e9 24 02 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005c21:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c28:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c2f:	e9 11 02 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005c34:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c3b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c42:	e9 fe 01 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005c47:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005c4b:	77 1f                	ja     140005c6c <__mingw_pformat+0xaa9>
   140005c4d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005c54:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005c58:	48 83 c0 10          	add    rax,0x10
   140005c5c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005c60:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005c67:	e9 d9 01 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005c6c:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c73:	e9 cd 01 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005c78:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005c7d:	74 4c                	je     140005ccb <__mingw_pformat+0xb08>
   140005c7f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c83:	74 06                	je     140005c8b <__mingw_pformat+0xac8>
   140005c85:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005c89:	75 40                	jne    140005ccb <__mingw_pformat+0xb08>
   140005c8b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005c8f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005c93:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005c97:	8b 10                	mov    edx,DWORD PTR [rax]
   140005c99:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c9d:	89 10                	mov    DWORD PTR [rax],edx
   140005c9f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ca3:	8b 00                	mov    eax,DWORD PTR [rax]
   140005ca5:	85 c0                	test   eax,eax
   140005ca7:	79 29                	jns    140005cd2 <__mingw_pformat+0xb0f>
   140005ca9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cad:	75 13                	jne    140005cc2 <__mingw_pformat+0xaff>
   140005caf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cb2:	80 cc 04             	or     ah,0x4
   140005cb5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cb8:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005cbb:	f7 d8                	neg    eax
   140005cbd:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005cc0:	eb 10                	jmp    140005cd2 <__mingw_pformat+0xb0f>
   140005cc2:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005cc9:	eb 07                	jmp    140005cd2 <__mingw_pformat+0xb0f>
   140005ccb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005cd2:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005cd9:	00 
   140005cda:	e9 66 01 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005cdf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ce3:	0f 85 4f 01 00 00    	jne    140005e38 <__mingw_pformat+0xc75>
   140005ce9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cec:	80 cc 08             	or     ah,0x8
   140005cef:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cf2:	e9 41 01 00 00       	jmp    140005e38 <__mingw_pformat+0xc75>
   140005cf7:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cfb:	0f 85 3a 01 00 00    	jne    140005e3b <__mingw_pformat+0xc78>
   140005d01:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d04:	80 cc 01             	or     ah,0x1
   140005d07:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d0a:	e9 2c 01 00 00       	jmp    140005e3b <__mingw_pformat+0xc78>
   140005d0f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d13:	0f 85 25 01 00 00    	jne    140005e3e <__mingw_pformat+0xc7b>
   140005d19:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d1c:	80 cc 04             	or     ah,0x4
   140005d1f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d22:	e9 17 01 00 00       	jmp    140005e3e <__mingw_pformat+0xc7b>
   140005d27:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d2b:	0f 85 10 01 00 00    	jne    140005e41 <__mingw_pformat+0xc7e>
   140005d31:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d34:	80 cc 10             	or     ah,0x10
   140005d37:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d3a:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005d41:	00 
   140005d42:	e8 a1 39 00 00       	call   1400096e8 <localeconv>
   140005d47:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005d4b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005d4f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005d53:	49 89 c9             	mov    r9,rcx
   140005d56:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005d5c:	48 89 c1             	mov    rcx,rax
   140005d5f:	e8 bc 33 00 00       	call   140009120 <mbrtowc>
   140005d64:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005d67:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005d6b:	7e 08                	jle    140005d75 <__mingw_pformat+0xbb2>
   140005d6d:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005d71:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005d75:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005d78:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005d7b:	e9 c1 00 00 00       	jmp    140005e41 <__mingw_pformat+0xc7e>
   140005d80:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d84:	0f 85 ba 00 00 00    	jne    140005e44 <__mingw_pformat+0xc81>
   140005d8a:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d8d:	83 c8 40             	or     eax,0x40
   140005d90:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d93:	e9 ac 00 00 00       	jmp    140005e44 <__mingw_pformat+0xc81>
   140005d98:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d9c:	75 0e                	jne    140005dac <__mingw_pformat+0xbe9>
   140005d9e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005da1:	80 cc 02             	or     ah,0x2
   140005da4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005da7:	e9 99 00 00 00       	jmp    140005e45 <__mingw_pformat+0xc82>
   140005dac:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005db0:	77 68                	ja     140005e1a <__mingw_pformat+0xc57>
   140005db2:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005db6:	7f 62                	jg     140005e1a <__mingw_pformat+0xc57>
   140005db8:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005dbc:	7e 5c                	jle    140005e1a <__mingw_pformat+0xc57>
   140005dbe:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005dc2:	75 09                	jne    140005dcd <__mingw_pformat+0xc0a>
   140005dc4:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005dcb:	eb 0d                	jmp    140005dda <__mingw_pformat+0xc17>
   140005dcd:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005dd1:	75 07                	jne    140005dda <__mingw_pformat+0xc17>
   140005dd3:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005dda:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005ddf:	74 64                	je     140005e45 <__mingw_pformat+0xc82>
   140005de1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005de5:	8b 00                	mov    eax,DWORD PTR [rax]
   140005de7:	85 c0                	test   eax,eax
   140005de9:	79 0e                	jns    140005df9 <__mingw_pformat+0xc36>
   140005deb:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005dee:	8d 50 d0             	lea    edx,[rax-0x30]
   140005df1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005df5:	89 10                	mov    DWORD PTR [rax],edx
   140005df7:	eb 4c                	jmp    140005e45 <__mingw_pformat+0xc82>
   140005df9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005dfd:	8b 10                	mov    edx,DWORD PTR [rax]
   140005dff:	89 d0                	mov    eax,edx
   140005e01:	c1 e0 02             	shl    eax,0x2
   140005e04:	01 d0                	add    eax,edx
   140005e06:	01 c0                	add    eax,eax
   140005e08:	89 c2                	mov    edx,eax
   140005e0a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e0d:	01 d0                	add    eax,edx
   140005e0f:	8d 50 d0             	lea    edx,[rax-0x30]
   140005e12:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e16:	89 10                	mov    DWORD PTR [rax],edx
   140005e18:	eb 2b                	jmp    140005e45 <__mingw_pformat+0xc82>
   140005e1a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005e1e:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005e22:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005e26:	48 89 c2             	mov    rdx,rax
   140005e29:	b9 25 00 00 00       	mov    ecx,0x25
   140005e2e:	e8 fd d3 ff ff       	call   140003230 <__pformat_putc>
   140005e33:	e9 00 f4 ff ff       	jmp    140005238 <__mingw_pformat+0x75>
   140005e38:	90                   	nop
   140005e39:	eb 0a                	jmp    140005e45 <__mingw_pformat+0xc82>
   140005e3b:	90                   	nop
   140005e3c:	eb 07                	jmp    140005e45 <__mingw_pformat+0xc82>
   140005e3e:	90                   	nop
   140005e3f:	eb 04                	jmp    140005e45 <__mingw_pformat+0xc82>
   140005e41:	90                   	nop
   140005e42:	eb 01                	jmp    140005e45 <__mingw_pformat+0xc82>
   140005e44:	90                   	nop
   140005e45:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e49:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e4c:	84 c0                	test   al,al
   140005e4e:	0f 85 2d f4 ff ff    	jne    140005281 <__mingw_pformat+0xbe>
   140005e54:	eb 0e                	jmp    140005e64 <__mingw_pformat+0xca1>
   140005e56:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005e5a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e5d:	89 c1                	mov    ecx,eax
   140005e5f:	e8 cc d3 ff ff       	call   140003230 <__pformat_putc>
   140005e64:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e68:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e6c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005e70:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e73:	0f be c0             	movsx  eax,al
   140005e76:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005e79:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005e7d:	0f 85 ba f3 ff ff    	jne    14000523d <__mingw_pformat+0x7a>
   140005e83:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005e86:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005e8d:	5d                   	pop    rbp
   140005e8e:	c3                   	ret
   140005e8f:	90                   	nop

0000000140005e90 <__rv_alloc_D2A>:
   140005e90:	55                   	push   rbp
   140005e91:	48 89 e5             	mov    rbp,rsp
   140005e94:	48 83 ec 30          	sub    rsp,0x30
   140005e98:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005e9b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ea2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005ea9:	eb 07                	jmp    140005eb2 <__rv_alloc_D2A+0x22>
   140005eab:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005eaf:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005eb2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005eb5:	83 c0 17             	add    eax,0x17
   140005eb8:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005ebb:	7f ee                	jg     140005eab <__rv_alloc_D2A+0x1b>
   140005ebd:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005ec0:	89 c1                	mov    ecx,eax
   140005ec2:	e8 56 1e 00 00       	call   140007d1d <__Balloc_D2A>
   140005ec7:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005ecb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ecf:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005ed2:	89 10                	mov    DWORD PTR [rax],edx
   140005ed4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ed8:	48 83 c0 04          	add    rax,0x4
   140005edc:	48 83 c4 30          	add    rsp,0x30
   140005ee0:	5d                   	pop    rbp
   140005ee1:	c3                   	ret

0000000140005ee2 <__nrv_alloc_D2A>:
   140005ee2:	55                   	push   rbp
   140005ee3:	48 89 e5             	mov    rbp,rsp
   140005ee6:	48 83 ec 30          	sub    rsp,0x30
   140005eea:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005eee:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005ef2:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005ef6:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005ef9:	89 c1                	mov    ecx,eax
   140005efb:	e8 90 ff ff ff       	call   140005e90 <__rv_alloc_D2A>
   140005f00:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005f04:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f08:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f0c:	eb 05                	jmp    140005f13 <__nrv_alloc_D2A+0x31>
   140005f0e:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005f13:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f17:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005f1b:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005f1f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005f22:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f26:	88 10                	mov    BYTE PTR [rax],dl
   140005f28:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f2c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005f2f:	84 c0                	test   al,al
   140005f31:	75 db                	jne    140005f0e <__nrv_alloc_D2A+0x2c>
   140005f33:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005f38:	74 0b                	je     140005f45 <__nrv_alloc_D2A+0x63>
   140005f3a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f3e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005f42:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005f45:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f49:	48 83 c4 30          	add    rsp,0x30
   140005f4d:	5d                   	pop    rbp
   140005f4e:	c3                   	ret

0000000140005f4f <__freedtoa>:
   140005f4f:	55                   	push   rbp
   140005f50:	48 89 e5             	mov    rbp,rsp
   140005f53:	48 83 ec 30          	sub    rsp,0x30
   140005f57:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f5b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f5f:	48 83 e8 04          	sub    rax,0x4
   140005f63:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f67:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f6b:	8b 10                	mov    edx,DWORD PTR [rax]
   140005f6d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f71:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005f74:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f78:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005f7b:	ba 01 00 00 00       	mov    edx,0x1
   140005f80:	89 c1                	mov    ecx,eax
   140005f82:	d3 e2                	shl    edx,cl
   140005f84:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f88:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005f8b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f8f:	48 89 c1             	mov    rcx,rax
   140005f92:	e8 c7 1e 00 00       	call   140007e5e <__Bfree_D2A>
   140005f97:	90                   	nop
   140005f98:	48 83 c4 30          	add    rsp,0x30
   140005f9c:	5d                   	pop    rbp
   140005f9d:	c3                   	ret

0000000140005f9e <__quorem_D2A>:
   140005f9e:	55                   	push   rbp
   140005f9f:	48 89 e5             	mov    rbp,rsp
   140005fa2:	48 83 ec 70          	sub    rsp,0x70
   140005fa6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005faa:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005fae:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005fb2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005fb5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005fb8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005fbc:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005fbf:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005fc2:	7e 0a                	jle    140005fce <__quorem_D2A+0x30>
   140005fc4:	b8 00 00 00 00       	mov    eax,0x0
   140005fc9:	e9 3f 02 00 00       	jmp    14000620d <__quorem_D2A+0x26f>
   140005fce:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005fd2:	48 83 c0 18          	add    rax,0x18
   140005fd6:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005fda:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005fde:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005fe1:	48 98                	cdqe
   140005fe3:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005fea:	00 
   140005feb:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005fef:	48 01 d0             	add    rax,rdx
   140005ff2:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005ff6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005ffa:	48 83 c0 18          	add    rax,0x18
   140005ffe:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006002:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006005:	48 98                	cdqe
   140006007:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000600e:	00 
   14000600f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006013:	48 01 d0             	add    rax,rdx
   140006016:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000601a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000601e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006020:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140006024:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006026:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140006029:	ba 00 00 00 00       	mov    edx,0x0
   14000602e:	f7 f1                	div    ecx
   140006030:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140006033:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140006037:	0f 84 c4 00 00 00    	je     140006101 <__quorem_D2A+0x163>
   14000603d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006044:	00 
   140006045:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000604c:	00 
   14000604d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006051:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140006055:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006059:	8b 00                	mov    eax,DWORD PTR [rax]
   14000605b:	89 c2                	mov    edx,eax
   14000605d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140006060:	48 0f af d0          	imul   rdx,rax
   140006064:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006068:	48 01 d0             	add    rax,rdx
   14000606b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000606f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006073:	48 c1 e8 20          	shr    rax,0x20
   140006077:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000607b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000607f:	8b 00                	mov    eax,DWORD PTR [rax]
   140006081:	89 c1                	mov    ecx,eax
   140006083:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006087:	89 c2                	mov    edx,eax
   140006089:	48 89 c8             	mov    rax,rcx
   14000608c:	48 29 d0             	sub    rax,rdx
   14000608f:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006093:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006097:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000609b:	48 c1 e8 20          	shr    rax,0x20
   14000609f:	83 e0 01             	and    eax,0x1
   1400060a2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400060a6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060aa:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400060ae:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400060b2:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400060b6:	89 10                	mov    DWORD PTR [rax],edx
   1400060b8:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400060bc:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400060c0:	73 8b                	jae    14000604d <__quorem_D2A+0xaf>
   1400060c2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060c6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060c8:	85 c0                	test   eax,eax
   1400060ca:	75 35                	jne    140006101 <__quorem_D2A+0x163>
   1400060cc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060d0:	48 83 c0 18          	add    rax,0x18
   1400060d4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400060d8:	eb 04                	jmp    1400060de <__quorem_D2A+0x140>
   1400060da:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400060de:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400060e3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060e7:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   1400060eb:	73 0a                	jae    1400060f7 <__quorem_D2A+0x159>
   1400060ed:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060f1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060f3:	85 c0                	test   eax,eax
   1400060f5:	74 e3                	je     1400060da <__quorem_D2A+0x13c>
   1400060f7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060fb:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400060fe:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006101:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140006105:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006109:	48 89 c1             	mov    rcx,rax
   14000610c:	e8 bc 24 00 00       	call   1400085cd <__cmp_D2A>
   140006111:	85 c0                	test   eax,eax
   140006113:	0f 88 f1 00 00 00    	js     14000620a <__quorem_D2A+0x26c>
   140006119:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   14000611d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006124:	00 
   140006125:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000612c:	00 
   14000612d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006131:	48 83 c0 18          	add    rax,0x18
   140006135:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006139:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000613d:	48 83 c0 18          	add    rax,0x18
   140006141:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006145:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006149:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000614d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006151:	8b 00                	mov    eax,DWORD PTR [rax]
   140006153:	89 c2                	mov    edx,eax
   140006155:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006159:	48 01 d0             	add    rax,rdx
   14000615c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140006160:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006164:	48 c1 e8 20          	shr    rax,0x20
   140006168:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000616c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006170:	8b 00                	mov    eax,DWORD PTR [rax]
   140006172:	89 c1                	mov    ecx,eax
   140006174:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006178:	89 c2                	mov    edx,eax
   14000617a:	48 89 c8             	mov    rax,rcx
   14000617d:	48 29 d0             	sub    rax,rdx
   140006180:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006184:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006188:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000618c:	48 c1 e8 20          	shr    rax,0x20
   140006190:	83 e0 01             	and    eax,0x1
   140006193:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006197:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000619b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000619f:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400061a3:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400061a7:	89 10                	mov    DWORD PTR [rax],edx
   1400061a9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400061ad:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400061b1:	73 92                	jae    140006145 <__quorem_D2A+0x1a7>
   1400061b3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400061b7:	48 83 c0 18          	add    rax,0x18
   1400061bb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400061bf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400061c2:	48 98                	cdqe
   1400061c4:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400061cb:	00 
   1400061cc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061d0:	48 01 d0             	add    rax,rdx
   1400061d3:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400061d7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061db:	8b 00                	mov    eax,DWORD PTR [rax]
   1400061dd:	85 c0                	test   eax,eax
   1400061df:	75 29                	jne    14000620a <__quorem_D2A+0x26c>
   1400061e1:	eb 04                	jmp    1400061e7 <__quorem_D2A+0x249>
   1400061e3:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400061e7:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400061ec:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061f0:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   1400061f4:	73 0a                	jae    140006200 <__quorem_D2A+0x262>
   1400061f6:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061fa:	8b 00                	mov    eax,DWORD PTR [rax]
   1400061fc:	85 c0                	test   eax,eax
   1400061fe:	74 e3                	je     1400061e3 <__quorem_D2A+0x245>
   140006200:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006204:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006207:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000620a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   14000620d:	48 83 c4 70          	add    rsp,0x70
   140006211:	5d                   	pop    rbp
   140006212:	c3                   	ret
   140006213:	90                   	nop
   140006214:	90                   	nop
   140006215:	90                   	nop
   140006216:	90                   	nop
   140006217:	90                   	nop
   140006218:	90                   	nop
   140006219:	90                   	nop
   14000621a:	90                   	nop
   14000621b:	90                   	nop
   14000621c:	90                   	nop
   14000621d:	90                   	nop
   14000621e:	90                   	nop
   14000621f:	90                   	nop

0000000140006220 <__hi0bits_D2A>:
   140006220:	55                   	push   rbp
   140006221:	48 89 e5             	mov    rbp,rsp
   140006224:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140006227:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   14000622b:	83 f0 1f             	xor    eax,0x1f
   14000622e:	5d                   	pop    rbp
   14000622f:	c3                   	ret

0000000140006230 <bitstob>:
   140006230:	55                   	push   rbp
   140006231:	53                   	push   rbx
   140006232:	48 83 ec 58          	sub    rsp,0x58
   140006236:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000623b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000623f:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006242:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006246:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000624d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140006254:	eb 07                	jmp    14000625d <bitstob+0x2d>
   140006256:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140006259:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   14000625d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006260:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   140006263:	7c f1                	jl     140006256 <bitstob+0x26>
   140006265:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140006268:	89 c1                	mov    ecx,eax
   14000626a:	e8 ae 1a 00 00       	call   140007d1d <__Balloc_D2A>
   14000626f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006273:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140006276:	83 e8 01             	sub    eax,0x1
   140006279:	c1 f8 05             	sar    eax,0x5
   14000627c:	48 98                	cdqe
   14000627e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006285:	00 
   140006286:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000628a:	48 01 d0             	add    rax,rdx
   14000628d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140006291:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006295:	48 83 c0 18          	add    rax,0x18
   140006299:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000629d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400062a1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400062a5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400062a9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400062ad:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400062b1:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400062b5:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400062b7:	89 10                	mov    DWORD PTR [rax],edx
   1400062b9:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   1400062be:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400062c2:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400062c6:	73 dd                	jae    1400062a5 <bitstob+0x75>
   1400062c8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400062cc:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400062d0:	48 c1 f8 02          	sar    rax,0x2
   1400062d4:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400062d7:	eb 1d                	jmp    1400062f6 <bitstob+0xc6>
   1400062d9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400062dd:	75 17                	jne    1400062f6 <bitstob+0xc6>
   1400062df:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062e3:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   1400062ea:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400062ee:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400062f4:	eb 59                	jmp    14000634f <bitstob+0x11f>
   1400062f6:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400062fa:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062fd:	48 98                	cdqe
   1400062ff:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006306:	00 
   140006307:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000630b:	48 01 d0             	add    rax,rdx
   14000630e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006310:	85 c0                	test   eax,eax
   140006312:	74 c5                	je     1400062d9 <bitstob+0xa9>
   140006314:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006317:	8d 50 01             	lea    edx,[rax+0x1]
   14000631a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000631e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006321:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006324:	83 c0 01             	add    eax,0x1
   140006327:	c1 e0 05             	shl    eax,0x5
   14000632a:	89 c3                	mov    ebx,eax
   14000632c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006330:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006333:	48 63 d2             	movsxd rdx,edx
   140006336:	48 83 c2 04          	add    rdx,0x4
   14000633a:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   14000633e:	89 c1                	mov    ecx,eax
   140006340:	e8 db fe ff ff       	call   140006220 <__hi0bits_D2A>
   140006345:	29 c3                	sub    ebx,eax
   140006347:	89 da                	mov    edx,ebx
   140006349:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000634d:	89 10                	mov    DWORD PTR [rax],edx
   14000634f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006353:	48 83 c4 58          	add    rsp,0x58
   140006357:	5b                   	pop    rbx
   140006358:	5d                   	pop    rbp
   140006359:	c3                   	ret

000000014000635a <__gdtoa>:
   14000635a:	55                   	push   rbp
   14000635b:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   140006362:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140006369:	00 
   14000636a:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   140006371:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   140006377:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   14000637e:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   140006385:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   14000638c:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006393:	8b 00                	mov    eax,DWORD PTR [rax]
   140006395:	83 e0 cf             	and    eax,0xffffffcf
   140006398:	89 c2                	mov    edx,eax
   14000639a:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063a1:	89 10                	mov    DWORD PTR [rax],edx
   1400063a3:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063aa:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063ac:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400063af:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400063b2:	83 e0 07             	and    eax,0x7
   1400063b5:	83 f8 04             	cmp    eax,0x4
   1400063b8:	0f 84 b0 00 00 00    	je     14000646e <__gdtoa+0x114>
   1400063be:	83 f8 04             	cmp    eax,0x4
   1400063c1:	0f 8f d5 00 00 00    	jg     14000649c <__gdtoa+0x142>
   1400063c7:	83 f8 03             	cmp    eax,0x3
   1400063ca:	74 74                	je     140006440 <__gdtoa+0xe6>
   1400063cc:	83 f8 03             	cmp    eax,0x3
   1400063cf:	0f 8f c7 00 00 00    	jg     14000649c <__gdtoa+0x142>
   1400063d5:	85 c0                	test   eax,eax
   1400063d7:	0f 84 05 01 00 00    	je     1400064e2 <__gdtoa+0x188>
   1400063dd:	85 c0                	test   eax,eax
   1400063df:	0f 88 b7 00 00 00    	js     14000649c <__gdtoa+0x142>
   1400063e5:	83 e8 01             	sub    eax,0x1
   1400063e8:	83 f8 01             	cmp    eax,0x1
   1400063eb:	0f 87 ab 00 00 00    	ja     14000649c <__gdtoa+0x142>
   1400063f1:	90                   	nop
   1400063f2:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400063f9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063fb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400063fe:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   140006402:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006405:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   14000640c:	49 89 c8             	mov    r8,rcx
   14000640f:	48 89 c1             	mov    rcx,rax
   140006412:	e8 19 fe ff ff       	call   140006230 <bitstob>
   140006417:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000641b:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006421:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140006424:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006428:	48 89 c1             	mov    rcx,rax
   14000642b:	e8 31 16 00 00       	call   140007a61 <__trailz_D2A>
   140006430:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006433:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006436:	85 c0                	test   eax,eax
   140006438:	0f 84 8b 00 00 00    	je     1400064c9 <__gdtoa+0x16f>
   14000643e:	eb 66                	jmp    1400064a6 <__gdtoa+0x14c>
   140006440:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006447:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000644d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006454:	48 8d 0d f5 4e 00 00 	lea    rcx,[rip+0x4ef5]        # 14000b350 <.rdata>
   14000645b:	41 b8 08 00 00 00    	mov    r8d,0x8
   140006461:	48 89 c2             	mov    rdx,rax
   140006464:	e8 79 fa ff ff       	call   140005ee2 <__nrv_alloc_D2A>
   140006469:	e9 4d 14 00 00       	jmp    1400078bb <__gdtoa+0x1561>
   14000646e:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006475:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000647b:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006482:	48 8d 0d d0 4e 00 00 	lea    rcx,[rip+0x4ed0]        # 14000b359 <.rdata+0x9>
   140006489:	41 b8 03 00 00 00    	mov    r8d,0x3
   14000648f:	48 89 c2             	mov    rdx,rax
   140006492:	e8 4b fa ff ff       	call   140005ee2 <__nrv_alloc_D2A>
   140006497:	e9 1f 14 00 00       	jmp    1400078bb <__gdtoa+0x1561>
   14000649c:	b8 00 00 00 00       	mov    eax,0x0
   1400064a1:	e9 15 14 00 00       	jmp    1400078bb <__gdtoa+0x1561>
   1400064a6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400064a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064ad:	48 89 c1             	mov    rcx,rax
   1400064b0:	e8 50 14 00 00       	call   140007905 <__rshift_D2A>
   1400064b5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064b8:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   1400064be:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400064c1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064c4:	29 c2                	sub    edx,eax
   1400064c6:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   1400064c9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064cd:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400064d0:	85 c0                	test   eax,eax
   1400064d2:	75 3d                	jne    140006511 <__gdtoa+0x1b7>
   1400064d4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064d8:	48 89 c1             	mov    rcx,rax
   1400064db:	e8 7e 19 00 00       	call   140007e5e <__Bfree_D2A>
   1400064e0:	eb 01                	jmp    1400064e3 <__gdtoa+0x189>
   1400064e2:	90                   	nop
   1400064e3:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400064ea:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   1400064f0:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400064f7:	48 8d 0d 5f 4e 00 00 	lea    rcx,[rip+0x4e5f]        # 14000b35d <.rdata+0xd>
   1400064fe:	41 b8 01 00 00 00    	mov    r8d,0x1
   140006504:	48 89 c2             	mov    rdx,rax
   140006507:	e8 d6 f9 ff ff       	call   140005ee2 <__nrv_alloc_D2A>
   14000650c:	e9 aa 13 00 00       	jmp    1400078bb <__gdtoa+0x1561>
   140006511:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   140006515:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006519:	48 89 c1             	mov    rcx,rax
   14000651c:	e8 75 23 00 00       	call   140008896 <__b2d_D2A>
   140006521:	66 48 0f 7e c0       	movq   rax,xmm0
   140006526:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   14000652a:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   14000652d:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006533:	01 d0                	add    eax,edx
   140006535:	83 e8 01             	sub    eax,0x1
   140006538:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000653b:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   14000653e:	25 ff ff 0f 00       	and    eax,0xfffff
   140006543:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006546:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006549:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000654e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006551:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006556:	f2 0f 10 15 02 4e 00 	movsd  xmm2,QWORD PTR [rip+0x4e02]        # 14000b360 <.rdata+0x10>
   14000655d:	00 
   14000655e:	66 0f 28 c8          	movapd xmm1,xmm0
   140006562:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006566:	f2 0f 10 05 fa 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4dfa]        # 14000b368 <.rdata+0x18>
   14000656d:	00 
   14000656e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006572:	f2 0f 10 05 f6 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4df6]        # 14000b370 <.rdata+0x20>
   140006579:	00 
   14000657a:	f2 0f 58 c8          	addsd  xmm1,xmm0
   14000657e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006581:	66 0f ef d2          	pxor   xmm2,xmm2
   140006585:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   140006589:	f2 0f 10 05 e7 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4de7]        # 14000b378 <.rdata+0x28>
   140006590:	00 
   140006591:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006595:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006599:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000659e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400065a1:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400065a4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065a8:	79 03                	jns    1400065ad <__gdtoa+0x253>
   1400065aa:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   1400065ad:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   1400065b4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065b8:	7e 23                	jle    1400065dd <__gdtoa+0x283>
   1400065ba:	66 0f ef c9          	pxor   xmm1,xmm1
   1400065be:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   1400065c3:	f2 0f 10 05 b5 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4db5]        # 14000b380 <.rdata+0x30>
   1400065ca:	00 
   1400065cb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400065cf:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   1400065d4:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400065d8:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400065dd:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   1400065e2:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400065e6:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   1400065e9:	66 0f ef c0          	pxor   xmm0,xmm0
   1400065ed:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   1400065f2:	76 1b                	jbe    14000660f <__gdtoa+0x2b5>
   1400065f4:	66 0f ef c0          	pxor   xmm0,xmm0
   1400065f8:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   1400065fd:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006602:	7a 07                	jp     14000660b <__gdtoa+0x2b1>
   140006604:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006609:	74 04                	je     14000660f <__gdtoa+0x2b5>
   14000660b:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000660f:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   140006616:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006619:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   14000661c:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006622:	01 ca                	add    edx,ecx
   140006624:	83 ea 01             	sub    edx,0x1
   140006627:	c1 e2 14             	shl    edx,0x14
   14000662a:	01 d0                	add    eax,edx
   14000662c:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000662f:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006633:	78 2e                	js     140006663 <__gdtoa+0x309>
   140006635:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   140006639:	7f 28                	jg     140006663 <__gdtoa+0x309>
   14000663b:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006640:	48 8b 05 39 50 00 00 	mov    rax,QWORD PTR [rip+0x5039]        # 14000b680 <.refptr.__tens_D2A>
   140006647:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000664a:	48 63 d2             	movsxd rdx,edx
   14000664d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006652:	66 0f 2f c1          	comisd xmm0,xmm1
   140006656:	76 04                	jbe    14000665c <__gdtoa+0x302>
   140006658:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000665c:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   140006663:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006666:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006669:	29 c2                	sub    edx,eax
   14000666b:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000666e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006671:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006675:	78 0f                	js     140006686 <__gdtoa+0x32c>
   140006677:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   14000667e:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006681:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   140006684:	eb 0f                	jmp    140006695 <__gdtoa+0x33b>
   140006686:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006689:	f7 d8                	neg    eax
   14000668b:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   14000668e:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   140006695:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006699:	78 15                	js     1400066b0 <__gdtoa+0x356>
   14000669b:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   1400066a2:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066a5:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   1400066a8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066ab:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400066ae:	eb 15                	jmp    1400066c5 <__gdtoa+0x36b>
   1400066b0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066b3:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   1400066b6:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066b9:	f7 d8                	neg    eax
   1400066bb:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   1400066be:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   1400066c5:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400066cc:	78 09                	js     1400066d7 <__gdtoa+0x37d>
   1400066ce:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   1400066d5:	7e 0a                	jle    1400066e1 <__gdtoa+0x387>
   1400066d7:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   1400066de:	00 00 00 
   1400066e1:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   1400066e8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400066ef:	7e 10                	jle    140006701 <__gdtoa+0x3a7>
   1400066f1:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   1400066f8:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   1400066ff:	eb 1b                	jmp    14000671c <__gdtoa+0x3c2>
   140006701:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006704:	3d f9 03 00 00       	cmp    eax,0x3f9
   140006709:	7f 0a                	jg     140006715 <__gdtoa+0x3bb>
   14000670b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000670e:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   140006713:	7d 07                	jge    14000671c <__gdtoa+0x3c2>
   140006715:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000671c:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   140006723:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   14000672a:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000672d:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006730:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006737:	0f 84 c5 00 00 00    	je     140006802 <__gdtoa+0x4a8>
   14000673d:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006744:	0f 8f e6 00 00 00    	jg     140006830 <__gdtoa+0x4d6>
   14000674a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   140006751:	74 7e                	je     1400067d1 <__gdtoa+0x477>
   140006753:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   14000675a:	0f 8f d0 00 00 00    	jg     140006830 <__gdtoa+0x4d6>
   140006760:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006767:	0f 84 8e 00 00 00    	je     1400067fb <__gdtoa+0x4a1>
   14000676d:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006774:	0f 8f b6 00 00 00    	jg     140006830 <__gdtoa+0x4d6>
   14000677a:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006781:	7f 0e                	jg     140006791 <__gdtoa+0x437>
   140006783:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000678a:	79 13                	jns    14000679f <__gdtoa+0x445>
   14000678c:	e9 9f 00 00 00       	jmp    140006830 <__gdtoa+0x4d6>
   140006791:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140006798:	74 30                	je     1400067ca <__gdtoa+0x470>
   14000679a:	e9 91 00 00 00       	jmp    140006830 <__gdtoa+0x4d6>
   14000679f:	66 0f ef c9          	pxor   xmm1,xmm1
   1400067a3:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   1400067a8:	f2 0f 10 05 d8 4b 00 	movsd  xmm0,QWORD PTR [rip+0x4bd8]        # 14000b388 <.rdata+0x38>
   1400067af:	00 
   1400067b0:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400067b4:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400067b8:	83 c0 03             	add    eax,0x3
   1400067bb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067be:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   1400067c5:	00 00 00 
   1400067c8:	eb 66                	jmp    140006830 <__gdtoa+0x4d6>
   1400067ca:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   1400067d1:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   1400067d8:	7f 0a                	jg     1400067e4 <__gdtoa+0x48a>
   1400067da:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   1400067e1:	00 00 00 
   1400067e4:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   1400067ea:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067ed:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067f0:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   1400067f3:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400067f6:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400067f9:	eb 35                	jmp    140006830 <__gdtoa+0x4d6>
   1400067fb:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006802:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   140006808:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000680b:	01 d0                	add    eax,edx
   14000680d:	83 c0 01             	add    eax,0x1
   140006810:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006813:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006816:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006819:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000681c:	83 e8 01             	sub    eax,0x1
   14000681f:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006822:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006825:	85 c0                	test   eax,eax
   140006827:	7f 07                	jg     140006830 <__gdtoa+0x4d6>
   140006829:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006830:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006833:	89 c1                	mov    ecx,eax
   140006835:	e8 56 f6 ff ff       	call   140005e90 <__rv_alloc_D2A>
   14000683a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000683e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006842:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006846:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000684d:	7f 09                	jg     140006858 <__gdtoa+0x4fe>
   14000684f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   140006856:	eb 38                	jmp    140006890 <__gdtoa+0x536>
   140006858:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000685f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140006862:	83 e8 01             	sub    eax,0x1
   140006865:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006868:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000686c:	74 22                	je     140006890 <__gdtoa+0x536>
   14000686e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006872:	79 07                	jns    14000687b <__gdtoa+0x521>
   140006874:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   14000687b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000687e:	83 e0 08             	and    eax,0x8
   140006881:	85 c0                	test   eax,eax
   140006883:	74 0b                	je     140006890 <__gdtoa+0x536>
   140006885:	b8 03 00 00 00       	mov    eax,0x3
   14000688a:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   14000688d:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006890:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006894:	0f 88 b9 04 00 00    	js     140006d53 <__gdtoa+0x9f9>
   14000689a:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   14000689e:	0f 8f af 04 00 00    	jg     140006d53 <__gdtoa+0x9f9>
   1400068a4:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   1400068a8:	0f 84 a5 04 00 00    	je     140006d53 <__gdtoa+0x9f9>
   1400068ae:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400068b2:	0f 85 9b 04 00 00    	jne    140006d53 <__gdtoa+0x9f9>
   1400068b8:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400068bc:	0f 85 91 04 00 00    	jne    140006d53 <__gdtoa+0x9f9>
   1400068c2:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   1400068c9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400068ce:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400068d3:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068d6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400068d9:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   1400068dc:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   1400068df:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   1400068e6:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400068ea:	0f 8e 98 00 00 00    	jle    140006988 <__gdtoa+0x62e>
   1400068f0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068f3:	83 e0 0f             	and    eax,0xf
   1400068f6:	89 c2                	mov    edx,eax
   1400068f8:	48 8b 05 81 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d81]        # 14000b680 <.refptr.__tens_D2A>
   1400068ff:	48 63 d2             	movsxd rdx,edx
   140006902:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006907:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000690c:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000690f:	c1 f8 04             	sar    eax,0x4
   140006912:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006915:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006918:	83 e0 10             	and    eax,0x10
   14000691b:	85 c0                	test   eax,eax
   14000691d:	74 5e                	je     14000697d <__gdtoa+0x623>
   14000691f:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   140006923:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006928:	48 8b 05 81 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c81]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000692f:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   140006934:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006938:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000693d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006941:	eb 3a                	jmp    14000697d <__gdtoa+0x623>
   140006943:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006946:	83 e0 01             	and    eax,0x1
   140006949:	85 c0                	test   eax,eax
   14000694b:	74 24                	je     140006971 <__gdtoa+0x617>
   14000694d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006951:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006954:	48 8b 05 55 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c55]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000695b:	48 63 d2             	movsxd rdx,edx
   14000695e:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006963:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006968:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000696c:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006971:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006974:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006977:	83 c0 01             	add    eax,0x1
   14000697a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000697d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006981:	75 c0                	jne    140006943 <__gdtoa+0x5e9>
   140006983:	e9 8b 00 00 00       	jmp    140006a13 <__gdtoa+0x6b9>
   140006988:	f2 0f 10 05 00 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a00]        # 14000b390 <.rdata+0x40>
   14000698f:	00 
   140006990:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006995:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006998:	f7 d8                	neg    eax
   14000699a:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   14000699d:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400069a1:	74 70                	je     140006a13 <__gdtoa+0x6b9>
   1400069a3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069a8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400069ab:	83 e0 0f             	and    eax,0xf
   1400069ae:	89 c2                	mov    edx,eax
   1400069b0:	48 8b 05 c9 4c 00 00 	mov    rax,QWORD PTR [rip+0x4cc9]        # 14000b680 <.refptr.__tens_D2A>
   1400069b7:	48 63 d2             	movsxd rdx,edx
   1400069ba:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400069bf:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069c3:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069c8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400069cb:	c1 f8 04             	sar    eax,0x4
   1400069ce:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400069d1:	eb 3a                	jmp    140006a0d <__gdtoa+0x6b3>
   1400069d3:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400069d6:	83 e0 01             	and    eax,0x1
   1400069d9:	85 c0                	test   eax,eax
   1400069db:	74 24                	je     140006a01 <__gdtoa+0x6a7>
   1400069dd:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400069e1:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069e6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400069e9:	48 8b 05 c0 4b 00 00 	mov    rax,QWORD PTR [rip+0x4bc0]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400069f0:	48 63 d2             	movsxd rdx,edx
   1400069f3:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400069f8:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069fc:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a01:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006a04:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006a07:	83 c0 01             	add    eax,0x1
   140006a0a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006a0d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006a11:	75 c0                	jne    1400069d3 <__gdtoa+0x679>
   140006a13:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140006a17:	74 47                	je     140006a60 <__gdtoa+0x706>
   140006a19:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a1e:	f2 0f 10 05 6a 49 00 	movsd  xmm0,QWORD PTR [rip+0x496a]        # 14000b390 <.rdata+0x40>
   140006a25:	00 
   140006a26:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a2a:	76 34                	jbe    140006a60 <__gdtoa+0x706>
   140006a2c:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a30:	7e 2e                	jle    140006a60 <__gdtoa+0x706>
   140006a32:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   140006a36:	0f 8e f5 02 00 00    	jle    140006d31 <__gdtoa+0x9d7>
   140006a3c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006a3f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006a42:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006a46:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a4b:	f2 0f 10 05 45 49 00 	movsd  xmm0,QWORD PTR [rip+0x4945]        # 14000b398 <.rdata+0x48>
   140006a52:	00 
   140006a53:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a57:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a5c:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006a60:	66 0f ef c9          	pxor   xmm1,xmm1
   140006a64:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006a69:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a6e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006a72:	f2 0f 10 05 26 49 00 	movsd  xmm0,QWORD PTR [rip+0x4926]        # 14000b3a0 <.rdata+0x50>
   140006a79:	00 
   140006a7a:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006a7e:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a83:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   140006a86:	2d 00 00 40 03       	sub    eax,0x3400000
   140006a8b:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   140006a8e:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a92:	75 5f                	jne    140006af3 <__gdtoa+0x799>
   140006a94:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006a9b:	00 
   140006a9c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006aa0:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006aa4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006aa9:	f2 0f 10 0d f7 48 00 	movsd  xmm1,QWORD PTR [rip+0x48f7]        # 14000b3a8 <.rdata+0x58>
   140006ab0:	00 
   140006ab1:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006ab5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006aba:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006abf:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006ac4:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ac8:	0f 87 ac 07 00 00    	ja     14000727a <__gdtoa+0xf20>
   140006ace:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ad3:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006ad8:	f3 0f 7e 15 d0 48 00 	movq   xmm2,QWORD PTR [rip+0x48d0]        # 14000b3b0 <.rdata+0x60>
   140006adf:	00 
   140006ae0:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006ae4:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ae8:	0f 87 6e 07 00 00    	ja     14000725c <__gdtoa+0xf02>
   140006aee:	e9 42 02 00 00       	jmp    140006d35 <__gdtoa+0x9db>
   140006af3:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006af7:	0f 84 22 01 00 00    	je     140006c1f <__gdtoa+0x8c5>
   140006afd:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006b02:	f2 0f 10 05 b6 48 00 	movsd  xmm0,QWORD PTR [rip+0x48b6]        # 14000b3c0 <.rdata+0x70>
   140006b09:	00 
   140006b0a:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b0e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006b11:	8d 50 ff             	lea    edx,[rax-0x1]
   140006b14:	48 8b 05 65 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b65]        # 14000b680 <.refptr.__tens_D2A>
   140006b1b:	48 63 d2             	movsxd rdx,edx
   140006b1e:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006b23:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006b27:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b2c:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b30:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b35:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006b3c:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b41:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006b46:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006b4a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006b4d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b52:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b56:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006b5b:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006b60:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b64:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b69:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006b6c:	8d 48 30             	lea    ecx,[rax+0x30]
   140006b6f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006b73:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006b77:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006b7b:	89 ca                	mov    edx,ecx
   140006b7d:	88 10                	mov    BYTE PTR [rax],dl
   140006b7f:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b84:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b89:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b8d:	76 29                	jbe    140006bb8 <__gdtoa+0x85e>
   140006b8f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b94:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b98:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b9c:	7a 0e                	jp     140006bac <__gdtoa+0x852>
   140006b9e:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ba2:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006ba6:	0f 84 93 0c 00 00    	je     14000783f <__gdtoa+0x14e5>
   140006bac:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006bb3:	e9 87 0c 00 00       	jmp    14000783f <__gdtoa+0x14e5>
   140006bb8:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006bbd:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006bc2:	66 0f 28 c8          	movapd xmm1,xmm0
   140006bc6:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006bca:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006bcf:	66 0f 2f c1          	comisd xmm0,xmm1
   140006bd3:	0f 87 c3 02 00 00    	ja     140006e9c <__gdtoa+0xb42>
   140006bd9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006bdc:	83 c0 01             	add    eax,0x1
   140006bdf:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006be2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006be5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006be8:	0f 8e 46 01 00 00    	jle    140006d34 <__gdtoa+0x9da>
   140006bee:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006bf3:	f2 0f 10 05 9d 47 00 	movsd  xmm0,QWORD PTR [rip+0x479d]        # 14000b398 <.rdata+0x48>
   140006bfa:	00 
   140006bfb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bff:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c04:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c09:	f2 0f 10 05 87 47 00 	movsd  xmm0,QWORD PTR [rip+0x4787]        # 14000b398 <.rdata+0x48>
   140006c10:	00 
   140006c11:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c15:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c1a:	e9 1d ff ff ff       	jmp    140006b3c <__gdtoa+0x7e2>
   140006c1f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c24:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006c27:	8d 50 ff             	lea    edx,[rax-0x1]
   140006c2a:	48 8b 05 4f 4a 00 00 	mov    rax,QWORD PTR [rip+0x4a4f]        # 14000b680 <.refptr.__tens_D2A>
   140006c31:	48 63 d2             	movsxd rdx,edx
   140006c34:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006c39:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c3d:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c42:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006c49:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c4e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006c53:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006c57:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006c5a:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006c5e:	74 1c                	je     140006c7c <__gdtoa+0x922>
   140006c60:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c65:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c69:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006c6e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006c73:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006c77:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c7c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006c7f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006c82:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006c86:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006c8a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006c8e:	89 ca                	mov    edx,ecx
   140006c90:	88 10                	mov    BYTE PTR [rax],dl
   140006c92:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c95:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006c98:	75 73                	jne    140006d0d <__gdtoa+0x9b3>
   140006c9a:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006c9f:	f2 0f 10 05 19 47 00 	movsd  xmm0,QWORD PTR [rip+0x4719]        # 14000b3c0 <.rdata+0x70>
   140006ca6:	00 
   140006ca7:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006cab:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006cb0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006cb5:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006cba:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006cbf:	66 0f 2f c1          	comisd xmm0,xmm1
   140006cc3:	0f 87 d6 01 00 00    	ja     140006e9f <__gdtoa+0xb45>
   140006cc9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006cce:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006cd3:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006cd8:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006cdc:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ce0:	77 02                	ja     140006ce4 <__gdtoa+0x98a>
   140006ce2:	eb 51                	jmp    140006d35 <__gdtoa+0x9db>
   140006ce4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ce9:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ced:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006cf1:	7a 0e                	jp     140006d01 <__gdtoa+0x9a7>
   140006cf3:	66 0f ef c9          	pxor   xmm1,xmm1
   140006cf7:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006cfb:	0f 84 41 0b 00 00    	je     140007842 <__gdtoa+0x14e8>
   140006d01:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006d08:	e9 35 0b 00 00       	jmp    140007842 <__gdtoa+0x14e8>
   140006d0d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006d10:	83 c0 01             	add    eax,0x1
   140006d13:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006d16:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d1b:	f2 0f 10 05 75 46 00 	movsd  xmm0,QWORD PTR [rip+0x4675]        # 14000b398 <.rdata+0x48>
   140006d22:	00 
   140006d23:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006d27:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d2c:	e9 18 ff ff ff       	jmp    140006c49 <__gdtoa+0x8ef>
   140006d31:	90                   	nop
   140006d32:	eb 01                	jmp    140006d35 <__gdtoa+0x9db>
   140006d34:	90                   	nop
   140006d35:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006d39:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006d3d:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006d42:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d47:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006d4a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006d4d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006d50:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006d53:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006d5a:	0f 88 bf 01 00 00    	js     140006f1f <__gdtoa+0xbc5>
   140006d60:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006d67:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006d6a:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006d6d:	0f 8f ac 01 00 00    	jg     140006f1f <__gdtoa+0xbc5>
   140006d73:	48 8b 05 06 49 00 00 	mov    rax,QWORD PTR [rip+0x4906]        # 14000b680 <.refptr.__tens_D2A>
   140006d7a:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006d7d:	48 63 d2             	movsxd rdx,edx
   140006d80:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006d85:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006d8a:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006d91:	79 45                	jns    140006dd8 <__gdtoa+0xa7e>
   140006d93:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d97:	7f 3f                	jg     140006dd8 <__gdtoa+0xa7e>
   140006d99:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006da0:	00 
   140006da1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006da5:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006da9:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006dad:	0f 88 ac 04 00 00    	js     14000725f <__gdtoa+0xf05>
   140006db3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006db8:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006dbd:	f2 0f 10 05 e3 45 00 	movsd  xmm0,QWORD PTR [rip+0x45e3]        # 14000b3a8 <.rdata+0x58>
   140006dc4:	00 
   140006dc5:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006dc9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006dcd:	0f 83 8c 04 00 00    	jae    14000725f <__gdtoa+0xf05>
   140006dd3:	e9 a6 04 00 00       	jmp    14000727e <__gdtoa+0xf24>
   140006dd8:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006ddf:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006de4:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006de9:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006ded:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006df0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006df5:	66 0f ef c9          	pxor   xmm1,xmm1
   140006df9:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006dfe:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006e03:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006e07:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e0c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006e0f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006e12:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e16:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006e1a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006e1e:	89 ca                	mov    edx,ecx
   140006e20:	88 10                	mov    BYTE PTR [rax],dl
   140006e22:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e27:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e2b:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e2f:	7a 0e                	jp     140006e3f <__gdtoa+0xae5>
   140006e31:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e35:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e39:	0f 84 da 00 00 00    	je     140006f19 <__gdtoa+0xbbf>
   140006e3f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e42:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006e45:	0f 85 aa 00 00 00    	jne    140006ef5 <__gdtoa+0xb9b>
   140006e4b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006e4f:	74 12                	je     140006e63 <__gdtoa+0xb09>
   140006e51:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006e55:	74 4b                	je     140006ea2 <__gdtoa+0xb48>
   140006e57:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e5e:	e9 e3 09 00 00       	jmp    140007846 <__gdtoa+0x14ec>
   140006e63:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e68:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006e6c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e71:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e76:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006e7b:	77 28                	ja     140006ea5 <__gdtoa+0xb4b>
   140006e7d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e82:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e87:	7a 63                	jp     140006eec <__gdtoa+0xb92>
   140006e89:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e8e:	75 5c                	jne    140006eec <__gdtoa+0xb92>
   140006e90:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006e93:	83 e0 01             	and    eax,0x1
   140006e96:	85 c0                	test   eax,eax
   140006e98:	74 52                	je     140006eec <__gdtoa+0xb92>
   140006e9a:	eb 0a                	jmp    140006ea6 <__gdtoa+0xb4c>
   140006e9c:	90                   	nop
   140006e9d:	eb 07                	jmp    140006ea6 <__gdtoa+0xb4c>
   140006e9f:	90                   	nop
   140006ea0:	eb 04                	jmp    140006ea6 <__gdtoa+0xb4c>
   140006ea2:	90                   	nop
   140006ea3:	eb 01                	jmp    140006ea6 <__gdtoa+0xb4c>
   140006ea5:	90                   	nop
   140006ea6:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006ead:	eb 17                	jmp    140006ec6 <__gdtoa+0xb6c>
   140006eaf:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006eb3:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006eb7:	75 0d                	jne    140006ec6 <__gdtoa+0xb6c>
   140006eb9:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006ebd:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ec1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006ec4:	eb 10                	jmp    140006ed6 <__gdtoa+0xb7c>
   140006ec6:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006ecb:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ecf:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006ed2:	3c 39                	cmp    al,0x39
   140006ed4:	74 d9                	je     140006eaf <__gdtoa+0xb55>
   140006ed6:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006eda:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006ede:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006ee2:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006ee5:	83 c2 01             	add    edx,0x1
   140006ee8:	88 10                	mov    BYTE PTR [rax],dl
   140006eea:	eb 2e                	jmp    140006f1a <__gdtoa+0xbc0>
   140006eec:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006ef3:	eb 25                	jmp    140006f1a <__gdtoa+0xbc0>
   140006ef5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ef8:	83 c0 01             	add    eax,0x1
   140006efb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006efe:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006f03:	f2 0f 10 05 8d 44 00 	movsd  xmm0,QWORD PTR [rip+0x448d]        # 14000b398 <.rdata+0x48>
   140006f0a:	00 
   140006f0b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006f0f:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006f14:	e9 c6 fe ff ff       	jmp    140006ddf <__gdtoa+0xa85>
   140006f19:	90                   	nop
   140006f1a:	e9 27 09 00 00       	jmp    140007846 <__gdtoa+0x14ec>
   140006f1f:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006f22:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006f25:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006f28:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006f2b:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006f32:	00 
   140006f33:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006f37:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f3b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006f3f:	0f 84 e0 00 00 00    	je     140007025 <__gdtoa+0xccb>
   140006f45:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006f48:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006f4b:	29 c2                	sub    edx,eax
   140006f4d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f50:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f53:	8d 50 01             	lea    edx,[rax+0x1]
   140006f56:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f59:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f5f:	29 c2                	sub    edx,eax
   140006f61:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f68:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f6b:	39 c2                	cmp    edx,eax
   140006f6d:	7d 43                	jge    140006fb2 <__gdtoa+0xc58>
   140006f6f:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006f76:	74 3a                	je     140006fb2 <__gdtoa+0xc58>
   140006f78:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006f7f:	74 31                	je     140006fb2 <__gdtoa+0xc58>
   140006f81:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f88:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f8b:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f91:	29 c2                	sub    edx,eax
   140006f93:	8d 42 01             	lea    eax,[rdx+0x1]
   140006f96:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f99:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006fa0:	7e 68                	jle    14000700a <__gdtoa+0xcb0>
   140006fa2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006fa6:	7e 62                	jle    14000700a <__gdtoa+0xcb0>
   140006fa8:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fab:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006fae:	7d 5a                	jge    14000700a <__gdtoa+0xcb0>
   140006fb0:	eb 0a                	jmp    140006fbc <__gdtoa+0xc62>
   140006fb2:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006fb9:	7e 50                	jle    14000700b <__gdtoa+0xcb1>
   140006fbb:	90                   	nop
   140006fbc:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006fbf:	83 e8 01             	sub    eax,0x1
   140006fc2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006fc5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006fc8:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006fcb:	7c 08                	jl     140006fd5 <__gdtoa+0xc7b>
   140006fcd:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fd0:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006fd3:	eb 19                	jmp    140006fee <__gdtoa+0xc94>
   140006fd5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006fd8:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006fdb:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fde:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006fe1:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fe4:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006fe7:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006fee:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006ff1:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006ff4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ff7:	85 c0                	test   eax,eax
   140006ff9:	79 10                	jns    14000700b <__gdtoa+0xcb1>
   140006ffb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ffe:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140007001:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140007008:	eb 01                	jmp    14000700b <__gdtoa+0xcb1>
   14000700a:	90                   	nop
   14000700b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000700e:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140007011:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007014:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140007017:	b9 01 00 00 00       	mov    ecx,0x1
   14000701c:	e8 f6 0f 00 00       	call   140008017 <__i2b_D2A>
   140007021:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007025:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140007029:	7e 26                	jle    140007051 <__gdtoa+0xcf7>
   14000702b:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000702f:	7e 20                	jle    140007051 <__gdtoa+0xcf7>
   140007031:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007034:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140007037:	39 c2                	cmp    edx,eax
   140007039:	0f 4e c2             	cmovle eax,edx
   14000703c:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000703f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007042:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140007045:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007048:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   14000704b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000704e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140007051:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140007055:	7e 7e                	jle    1400070d5 <__gdtoa+0xd7b>
   140007057:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000705b:	74 65                	je     1400070c2 <__gdtoa+0xd68>
   14000705d:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140007061:	7e 3b                	jle    14000709e <__gdtoa+0xd44>
   140007063:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140007066:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000706a:	48 89 c1             	mov    rcx,rax
   14000706d:	e8 11 12 00 00       	call   140008283 <__pow5mult_D2A>
   140007072:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007076:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000707a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000707e:	48 89 c1             	mov    rcx,rax
   140007081:	e8 d7 0f 00 00       	call   14000805d <__mult_D2A>
   140007086:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000708a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000708e:	48 89 c1             	mov    rcx,rax
   140007091:	e8 c8 0d 00 00       	call   140007e5e <__Bfree_D2A>
   140007096:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000709a:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000709e:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   1400070a1:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   1400070a4:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400070a7:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400070ab:	74 28                	je     1400070d5 <__gdtoa+0xd7b>
   1400070ad:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   1400070b0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070b4:	48 89 c1             	mov    rcx,rax
   1400070b7:	e8 c7 11 00 00       	call   140008283 <__pow5mult_D2A>
   1400070bc:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070c0:	eb 13                	jmp    1400070d5 <__gdtoa+0xd7b>
   1400070c2:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   1400070c5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070c9:	48 89 c1             	mov    rcx,rax
   1400070cc:	e8 b2 11 00 00       	call   140008283 <__pow5mult_D2A>
   1400070d1:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070d5:	b9 01 00 00 00       	mov    ecx,0x1
   1400070da:	e8 38 0f 00 00       	call   140008017 <__i2b_D2A>
   1400070df:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070e3:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   1400070e7:	7e 13                	jle    1400070fc <__gdtoa+0xda2>
   1400070e9:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   1400070ec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070f0:	48 89 c1             	mov    rcx,rax
   1400070f3:	e8 8b 11 00 00       	call   140008283 <__pow5mult_D2A>
   1400070f8:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070fc:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   140007103:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000710a:	7f 29                	jg     140007135 <__gdtoa+0xddb>
   14000710c:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   14000710f:	83 f8 01             	cmp    eax,0x1
   140007112:	75 21                	jne    140007135 <__gdtoa+0xddb>
   140007114:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000711b:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000711e:	83 c0 01             	add    eax,0x1
   140007121:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140007124:	7e 0f                	jle    140007135 <__gdtoa+0xddb>
   140007126:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   14000712a:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   14000712e:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   140007135:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007139:	74 22                	je     14000715d <__gdtoa+0xe03>
   14000713b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000713f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007142:	8d 50 ff             	lea    edx,[rax-0x1]
   140007145:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007149:	48 63 d2             	movsxd rdx,edx
   14000714c:	48 83 c2 04          	add    rdx,0x4
   140007150:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   140007154:	89 c1                	mov    ecx,eax
   140007156:	e8 c5 f0 ff ff       	call   140006220 <__hi0bits_D2A>
   14000715b:	eb 05                	jmp    140007162 <__gdtoa+0xe08>
   14000715d:	b8 1f 00 00 00       	mov    eax,0x1f
   140007162:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   140007165:	83 e8 04             	sub    eax,0x4
   140007168:	83 e0 1f             	and    eax,0x1f
   14000716b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000716e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007171:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   140007174:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007177:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   14000717a:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   14000717e:	7e 13                	jle    140007193 <__gdtoa+0xe39>
   140007180:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   140007183:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007187:	48 89 c1             	mov    rcx,rax
   14000718a:	e8 b1 12 00 00       	call   140008440 <__lshift_D2A>
   14000718f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007193:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007196:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140007199:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000719d:	7e 13                	jle    1400071b2 <__gdtoa+0xe58>
   14000719f:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   1400071a2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400071a6:	48 89 c1             	mov    rcx,rax
   1400071a9:	e8 92 12 00 00       	call   140008440 <__lshift_D2A>
   1400071ae:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400071b2:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400071b6:	74 5a                	je     140007212 <__gdtoa+0xeb8>
   1400071b8:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400071bc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071c0:	48 89 c1             	mov    rcx,rax
   1400071c3:	e8 05 14 00 00       	call   1400085cd <__cmp_D2A>
   1400071c8:	85 c0                	test   eax,eax
   1400071ca:	79 46                	jns    140007212 <__gdtoa+0xeb8>
   1400071cc:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400071d0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071d4:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071da:	ba 0a 00 00 00       	mov    edx,0xa
   1400071df:	48 89 c1             	mov    rcx,rax
   1400071e2:	e8 02 0d 00 00       	call   140007ee9 <__multadd_D2A>
   1400071e7:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400071eb:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400071ef:	74 1b                	je     14000720c <__gdtoa+0xeb2>
   1400071f1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071f5:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071fb:	ba 0a 00 00 00       	mov    edx,0xa
   140007200:	48 89 c1             	mov    rcx,rax
   140007203:	e8 e1 0c 00 00       	call   140007ee9 <__multadd_D2A>
   140007208:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000720c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000720f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140007212:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007216:	0f 8f 81 00 00 00    	jg     14000729d <__gdtoa+0xf43>
   14000721c:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140007223:	7e 78                	jle    14000729d <__gdtoa+0xf43>
   140007225:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007229:	78 37                	js     140007262 <__gdtoa+0xf08>
   14000722b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000722f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007235:	ba 05 00 00 00       	mov    edx,0x5
   14000723a:	48 89 c1             	mov    rcx,rax
   14000723d:	e8 a7 0c 00 00       	call   140007ee9 <__multadd_D2A>
   140007242:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007246:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000724a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000724e:	48 89 c1             	mov    rcx,rax
   140007251:	e8 77 13 00 00       	call   1400085cd <__cmp_D2A>
   140007256:	85 c0                	test   eax,eax
   140007258:	7f 23                	jg     14000727d <__gdtoa+0xf23>
   14000725a:	eb 07                	jmp    140007263 <__gdtoa+0xf09>
   14000725c:	90                   	nop
   14000725d:	eb 04                	jmp    140007263 <__gdtoa+0xf09>
   14000725f:	90                   	nop
   140007260:	eb 01                	jmp    140007263 <__gdtoa+0xf09>
   140007262:	90                   	nop
   140007263:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   140007269:	f7 d0                	not    eax
   14000726b:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   14000726e:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007275:	e9 87 05 00 00       	jmp    140007801 <__gdtoa+0x14a7>
   14000727a:	90                   	nop
   14000727b:	eb 01                	jmp    14000727e <__gdtoa+0xf24>
   14000727d:	90                   	nop
   14000727e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007285:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007289:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000728d:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007291:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007294:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007298:	e9 64 05 00 00       	jmp    140007801 <__gdtoa+0x14a7>
   14000729d:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400072a1:	0f 84 14 04 00 00    	je     1400076bb <__gdtoa+0x1361>
   1400072a7:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   1400072ab:	7e 13                	jle    1400072c0 <__gdtoa+0xf66>
   1400072ad:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   1400072b0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072b4:	48 89 c1             	mov    rcx,rax
   1400072b7:	e8 84 11 00 00       	call   140008440 <__lshift_D2A>
   1400072bc:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072c0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072c4:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400072c8:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   1400072cc:	74 57                	je     140007325 <__gdtoa+0xfcb>
   1400072ce:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072d2:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400072d5:	89 c1                	mov    ecx,eax
   1400072d7:	e8 41 0a 00 00       	call   140007d1d <__Balloc_D2A>
   1400072dc:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072e0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400072e4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400072e7:	48 98                	cdqe
   1400072e9:	48 83 c0 02          	add    rax,0x2
   1400072ed:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   1400072f4:	00 
   1400072f5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400072f9:	48 8d 50 10          	lea    rdx,[rax+0x10]
   1400072fd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007301:	48 83 c0 10          	add    rax,0x10
   140007305:	49 89 c8             	mov    r8,rcx
   140007308:	48 89 c1             	mov    rcx,rax
   14000730b:	e8 e8 23 00 00       	call   1400096f8 <memcpy>
   140007310:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007314:	ba 01 00 00 00       	mov    edx,0x1
   140007319:	48 89 c1             	mov    rcx,rax
   14000731c:	e8 1f 11 00 00       	call   140008440 <__lshift_D2A>
   140007321:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007325:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   14000732c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007330:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007334:	48 89 c1             	mov    rcx,rax
   140007337:	e8 62 ec ff ff       	call   140005f9e <__quorem_D2A>
   14000733c:	83 c0 30             	add    eax,0x30
   14000733f:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007342:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007346:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000734a:	48 89 c1             	mov    rcx,rax
   14000734d:	e8 7b 12 00 00       	call   1400085cd <__cmp_D2A>
   140007352:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007355:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007359:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000735d:	48 89 c1             	mov    rcx,rax
   140007360:	e8 38 13 00 00       	call   14000869d <__diff_D2A>
   140007365:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140007369:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   14000736d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140007370:	85 c0                	test   eax,eax
   140007372:	75 15                	jne    140007389 <__gdtoa+0x102f>
   140007374:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140007378:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000737c:	48 89 c1             	mov    rcx,rax
   14000737f:	e8 49 12 00 00       	call   1400085cd <__cmp_D2A>
   140007384:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007387:	eb 07                	jmp    140007390 <__gdtoa+0x1036>
   140007389:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   140007390:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140007394:	48 89 c1             	mov    rcx,rax
   140007397:	e8 c2 0a 00 00       	call   140007e5e <__Bfree_D2A>
   14000739c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400073a0:	75 70                	jne    140007412 <__gdtoa+0x10b8>
   1400073a2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400073a9:	75 67                	jne    140007412 <__gdtoa+0x10b8>
   1400073ab:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400073b2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400073b4:	83 e0 01             	and    eax,0x1
   1400073b7:	85 c0                	test   eax,eax
   1400073b9:	75 57                	jne    140007412 <__gdtoa+0x10b8>
   1400073bb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400073bf:	75 51                	jne    140007412 <__gdtoa+0x10b8>
   1400073c1:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400073c5:	0f 84 01 02 00 00    	je     1400075cc <__gdtoa+0x1272>
   1400073cb:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073cf:	7f 20                	jg     1400073f1 <__gdtoa+0x1097>
   1400073d1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073d5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400073d8:	83 f8 01             	cmp    eax,0x1
   1400073db:	7f 0b                	jg     1400073e8 <__gdtoa+0x108e>
   1400073dd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073e1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400073e4:	85 c0                	test   eax,eax
   1400073e6:	74 14                	je     1400073fc <__gdtoa+0x10a2>
   1400073e8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400073ef:	eb 0b                	jmp    1400073fc <__gdtoa+0x10a2>
   1400073f1:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   1400073f5:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400073fc:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007400:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007404:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007408:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000740b:	88 10                	mov    BYTE PTR [rax],dl
   14000740d:	e9 ef 03 00 00       	jmp    140007801 <__gdtoa+0x14a7>
   140007412:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007416:	78 2b                	js     140007443 <__gdtoa+0x10e9>
   140007418:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000741c:	0f 85 96 01 00 00    	jne    1400075b8 <__gdtoa+0x125e>
   140007422:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007429:	0f 85 89 01 00 00    	jne    1400075b8 <__gdtoa+0x125e>
   14000742f:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007436:	8b 00                	mov    eax,DWORD PTR [rax]
   140007438:	83 e0 01             	and    eax,0x1
   14000743b:	85 c0                	test   eax,eax
   14000743d:	0f 85 75 01 00 00    	jne    1400075b8 <__gdtoa+0x125e>
   140007443:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007447:	0f 84 db 00 00 00    	je     140007528 <__gdtoa+0x11ce>
   14000744d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007451:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007454:	83 f8 01             	cmp    eax,0x1
   140007457:	7f 0f                	jg     140007468 <__gdtoa+0x110e>
   140007459:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000745d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007460:	85 c0                	test   eax,eax
   140007462:	0f 84 c0 00 00 00    	je     140007528 <__gdtoa+0x11ce>
   140007468:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   14000746c:	0f 85 83 00 00 00    	jne    1400074f5 <__gdtoa+0x119b>
   140007472:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007479:	e9 24 01 00 00       	jmp    1400075a2 <__gdtoa+0x1248>
   14000747e:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007482:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007486:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000748a:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000748d:	88 10                	mov    BYTE PTR [rax],dl
   14000748f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007493:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007499:	ba 0a 00 00 00       	mov    edx,0xa
   14000749e:	48 89 c1             	mov    rcx,rax
   1400074a1:	e8 43 0a 00 00       	call   140007ee9 <__multadd_D2A>
   1400074a6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400074aa:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400074ae:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400074b2:	75 08                	jne    1400074bc <__gdtoa+0x1162>
   1400074b4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400074b8:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400074bc:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400074c0:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400074c4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074c8:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400074ce:	ba 0a 00 00 00       	mov    edx,0xa
   1400074d3:	48 89 c1             	mov    rcx,rax
   1400074d6:	e8 0e 0a 00 00       	call   140007ee9 <__multadd_D2A>
   1400074db:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400074df:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400074e3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074e7:	48 89 c1             	mov    rcx,rax
   1400074ea:	e8 af ea ff ff       	call   140005f9e <__quorem_D2A>
   1400074ef:	83 c0 30             	add    eax,0x30
   1400074f2:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400074f5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400074f9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400074fd:	48 89 c1             	mov    rcx,rax
   140007500:	e8 c8 10 00 00       	call   1400085cd <__cmp_D2A>
   140007505:	85 c0                	test   eax,eax
   140007507:	0f 8f 71 ff ff ff    	jg     14000747e <__gdtoa+0x1124>
   14000750d:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007510:	8d 50 01             	lea    edx,[rax+0x1]
   140007513:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007516:	83 f8 39             	cmp    eax,0x39
   140007519:	0f 84 b0 00 00 00    	je     1400075cf <__gdtoa+0x1275>
   14000751f:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007526:	eb 7a                	jmp    1400075a2 <__gdtoa+0x1248>
   140007528:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000752c:	7e 53                	jle    140007581 <__gdtoa+0x1227>
   14000752e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007532:	ba 01 00 00 00       	mov    edx,0x1
   140007537:	48 89 c1             	mov    rcx,rax
   14000753a:	e8 01 0f 00 00       	call   140008440 <__lshift_D2A>
   14000753f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007543:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007547:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000754b:	48 89 c1             	mov    rcx,rax
   14000754e:	e8 7a 10 00 00       	call   1400085cd <__cmp_D2A>
   140007553:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007556:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000755a:	7f 10                	jg     14000756c <__gdtoa+0x1212>
   14000755c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007560:	75 18                	jne    14000757a <__gdtoa+0x1220>
   140007562:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007565:	83 e0 01             	and    eax,0x1
   140007568:	85 c0                	test   eax,eax
   14000756a:	74 0e                	je     14000757a <__gdtoa+0x1220>
   14000756c:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000756f:	8d 50 01             	lea    edx,[rax+0x1]
   140007572:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007575:	83 f8 39             	cmp    eax,0x39
   140007578:	74 58                	je     1400075d2 <__gdtoa+0x1278>
   14000757a:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007581:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007585:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007588:	83 f8 01             	cmp    eax,0x1
   14000758b:	7f 0b                	jg     140007598 <__gdtoa+0x123e>
   14000758d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007591:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007594:	85 c0                	test   eax,eax
   140007596:	74 09                	je     1400075a1 <__gdtoa+0x1247>
   140007598:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000759f:	eb 01                	jmp    1400075a2 <__gdtoa+0x1248>
   1400075a1:	90                   	nop
   1400075a2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075a6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075aa:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075ae:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400075b1:	88 10                	mov    BYTE PTR [rax],dl
   1400075b3:	e9 49 02 00 00       	jmp    140007801 <__gdtoa+0x14a7>
   1400075b8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400075bc:	7e 52                	jle    140007610 <__gdtoa+0x12b6>
   1400075be:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400075c2:	74 4c                	je     140007610 <__gdtoa+0x12b6>
   1400075c4:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400075c8:	75 24                	jne    1400075ee <__gdtoa+0x1294>
   1400075ca:	eb 07                	jmp    1400075d3 <__gdtoa+0x1279>
   1400075cc:	90                   	nop
   1400075cd:	eb 04                	jmp    1400075d3 <__gdtoa+0x1279>
   1400075cf:	90                   	nop
   1400075d0:	eb 01                	jmp    1400075d3 <__gdtoa+0x1279>
   1400075d2:	90                   	nop
   1400075d3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075d7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075db:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075df:	c6 00 39             	mov    BYTE PTR [rax],0x39
   1400075e2:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075e9:	e9 9d 01 00 00       	jmp    14000778b <__gdtoa+0x1431>
   1400075ee:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075f5:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400075f8:	8d 48 01             	lea    ecx,[rax+0x1]
   1400075fb:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075ff:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007603:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007607:	89 ca                	mov    edx,ecx
   140007609:	88 10                	mov    BYTE PTR [rax],dl
   14000760b:	e9 f1 01 00 00       	jmp    140007801 <__gdtoa+0x14a7>
   140007610:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007614:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007618:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000761c:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000761f:	88 10                	mov    BYTE PTR [rax],dl
   140007621:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007624:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140007627:	0f 84 ea 00 00 00    	je     140007717 <__gdtoa+0x13bd>
   14000762d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007631:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007637:	ba 0a 00 00 00       	mov    edx,0xa
   14000763c:	48 89 c1             	mov    rcx,rax
   14000763f:	e8 a5 08 00 00       	call   140007ee9 <__multadd_D2A>
   140007644:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007648:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000764c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007650:	75 25                	jne    140007677 <__gdtoa+0x131d>
   140007652:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007656:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000765c:	ba 0a 00 00 00       	mov    edx,0xa
   140007661:	48 89 c1             	mov    rcx,rax
   140007664:	e8 80 08 00 00       	call   140007ee9 <__multadd_D2A>
   140007669:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000766d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007671:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007675:	eb 36                	jmp    1400076ad <__gdtoa+0x1353>
   140007677:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000767b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007681:	ba 0a 00 00 00       	mov    edx,0xa
   140007686:	48 89 c1             	mov    rcx,rax
   140007689:	e8 5b 08 00 00       	call   140007ee9 <__multadd_D2A>
   14000768e:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007692:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007696:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000769c:	ba 0a 00 00 00       	mov    edx,0xa
   1400076a1:	48 89 c1             	mov    rcx,rax
   1400076a4:	e8 40 08 00 00       	call   140007ee9 <__multadd_D2A>
   1400076a9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400076ad:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076b0:	83 c0 01             	add    eax,0x1
   1400076b3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400076b6:	e9 71 fc ff ff       	jmp    14000732c <__gdtoa+0xfd2>
   1400076bb:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400076c2:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400076c6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076ca:	48 89 c1             	mov    rcx,rax
   1400076cd:	e8 cc e8 ff ff       	call   140005f9e <__quorem_D2A>
   1400076d2:	83 c0 30             	add    eax,0x30
   1400076d5:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400076d8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076dc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076e0:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076e4:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400076e7:	88 10                	mov    BYTE PTR [rax],dl
   1400076e9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076ec:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   1400076ef:	7e 29                	jle    14000771a <__gdtoa+0x13c0>
   1400076f1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076f5:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400076fb:	ba 0a 00 00 00       	mov    edx,0xa
   140007700:	48 89 c1             	mov    rcx,rax
   140007703:	e8 e1 07 00 00       	call   140007ee9 <__multadd_D2A>
   140007708:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000770c:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000770f:	83 c0 01             	add    eax,0x1
   140007712:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007715:	eb ab                	jmp    1400076c2 <__gdtoa+0x1368>
   140007717:	90                   	nop
   140007718:	eb 01                	jmp    14000771b <__gdtoa+0x13c1>
   14000771a:	90                   	nop
   14000771b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000771f:	74 26                	je     140007747 <__gdtoa+0x13ed>
   140007721:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007725:	0f 84 ae 00 00 00    	je     1400077d9 <__gdtoa+0x147f>
   14000772b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000772f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007732:	83 f8 01             	cmp    eax,0x1
   140007735:	7f 50                	jg     140007787 <__gdtoa+0x142d>
   140007737:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000773b:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000773e:	85 c0                	test   eax,eax
   140007740:	75 45                	jne    140007787 <__gdtoa+0x142d>
   140007742:	e9 92 00 00 00       	jmp    1400077d9 <__gdtoa+0x147f>
   140007747:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000774b:	ba 01 00 00 00       	mov    edx,0x1
   140007750:	48 89 c1             	mov    rcx,rax
   140007753:	e8 e8 0c 00 00       	call   140008440 <__lshift_D2A>
   140007758:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000775c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007760:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007764:	48 89 c1             	mov    rcx,rax
   140007767:	e8 61 0e 00 00       	call   1400085cd <__cmp_D2A>
   14000776c:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   14000776f:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007773:	7f 15                	jg     14000778a <__gdtoa+0x1430>
   140007775:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007779:	75 61                	jne    1400077dc <__gdtoa+0x1482>
   14000777b:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000777e:	83 e0 01             	and    eax,0x1
   140007781:	85 c0                	test   eax,eax
   140007783:	74 5a                	je     1400077df <__gdtoa+0x1485>
   140007785:	eb 04                	jmp    14000778b <__gdtoa+0x1431>
   140007787:	90                   	nop
   140007788:	eb 01                	jmp    14000778b <__gdtoa+0x1431>
   14000778a:	90                   	nop
   14000778b:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007792:	eb 1f                	jmp    1400077b3 <__gdtoa+0x1459>
   140007794:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007798:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000779c:	75 15                	jne    1400077b3 <__gdtoa+0x1459>
   14000779e:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400077a2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077a6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400077aa:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400077ae:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400077b1:	eb 4e                	jmp    140007801 <__gdtoa+0x14a7>
   1400077b3:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   1400077b8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077bc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400077bf:	3c 39                	cmp    al,0x39
   1400077c1:	74 d1                	je     140007794 <__gdtoa+0x143a>
   1400077c3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077c7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400077cb:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400077cf:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   1400077d2:	83 c2 01             	add    edx,0x1
   1400077d5:	88 10                	mov    BYTE PTR [rax],dl
   1400077d7:	eb 28                	jmp    140007801 <__gdtoa+0x14a7>
   1400077d9:	90                   	nop
   1400077da:	eb 04                	jmp    1400077e0 <__gdtoa+0x1486>
   1400077dc:	90                   	nop
   1400077dd:	eb 01                	jmp    1400077e0 <__gdtoa+0x1486>
   1400077df:	90                   	nop
   1400077e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077e4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400077e7:	83 f8 01             	cmp    eax,0x1
   1400077ea:	7f 0b                	jg     1400077f7 <__gdtoa+0x149d>
   1400077ec:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077f0:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400077f3:	85 c0                	test   eax,eax
   1400077f5:	74 09                	je     140007800 <__gdtoa+0x14a6>
   1400077f7:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400077fe:	eb 01                	jmp    140007801 <__gdtoa+0x14a7>
   140007800:	90                   	nop
   140007801:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007805:	48 89 c1             	mov    rcx,rax
   140007808:	e8 51 06 00 00       	call   140007e5e <__Bfree_D2A>
   14000780d:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140007812:	74 31                	je     140007845 <__gdtoa+0x14eb>
   140007814:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140007819:	74 16                	je     140007831 <__gdtoa+0x14d7>
   14000781b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000781f:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007823:	74 0c                	je     140007831 <__gdtoa+0x14d7>
   140007825:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007829:	48 89 c1             	mov    rcx,rax
   14000782c:	e8 2d 06 00 00       	call   140007e5e <__Bfree_D2A>
   140007831:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007835:	48 89 c1             	mov    rcx,rax
   140007838:	e8 21 06 00 00       	call   140007e5e <__Bfree_D2A>
   14000783d:	eb 0e                	jmp    14000784d <__gdtoa+0x14f3>
   14000783f:	90                   	nop
   140007840:	eb 0b                	jmp    14000784d <__gdtoa+0x14f3>
   140007842:	90                   	nop
   140007843:	eb 08                	jmp    14000784d <__gdtoa+0x14f3>
   140007845:	90                   	nop
   140007846:	eb 05                	jmp    14000784d <__gdtoa+0x14f3>
   140007848:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000784d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007851:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140007855:	73 0f                	jae    140007866 <__gdtoa+0x150c>
   140007857:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000785b:	48 83 e8 01          	sub    rax,0x1
   14000785f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140007862:	3c 30                	cmp    al,0x30
   140007864:	74 e2                	je     140007848 <__gdtoa+0x14ee>
   140007866:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000786a:	48 89 c1             	mov    rcx,rax
   14000786d:	e8 ec 05 00 00       	call   140007e5e <__Bfree_D2A>
   140007872:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007876:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140007879:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000787c:	8d 50 01             	lea    edx,[rax+0x1]
   14000787f:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140007886:	89 10                	mov    DWORD PTR [rax],edx
   140007888:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   14000788f:	00 
   140007890:	74 0e                	je     1400078a0 <__gdtoa+0x1546>
   140007892:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140007899:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   14000789d:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400078a0:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400078a7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400078a9:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   1400078ac:	89 c2                	mov    edx,eax
   1400078ae:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400078b5:	89 10                	mov    DWORD PTR [rax],edx
   1400078b7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400078bb:	48 81 c4 00 01 00 00 	add    rsp,0x100
   1400078c2:	5d                   	pop    rbp
   1400078c3:	c3                   	ret
   1400078c4:	90                   	nop
   1400078c5:	90                   	nop
   1400078c6:	90                   	nop
   1400078c7:	90                   	nop
   1400078c8:	90                   	nop
   1400078c9:	90                   	nop
   1400078ca:	90                   	nop
   1400078cb:	90                   	nop
   1400078cc:	90                   	nop
   1400078cd:	90                   	nop
   1400078ce:	90                   	nop
   1400078cf:	90                   	nop

00000001400078d0 <__lo0bits_D2A>:
   1400078d0:	55                   	push   rbp
   1400078d1:	48 89 e5             	mov    rbp,rsp
   1400078d4:	48 83 ec 10          	sub    rsp,0x10
   1400078d8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400078dc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078e0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400078e2:	f3 0f bc c0          	tzcnt  eax,eax
   1400078e6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400078e9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078ed:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078ef:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400078f2:	89 c1                	mov    ecx,eax
   1400078f4:	d3 ea                	shr    edx,cl
   1400078f6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078fa:	89 10                	mov    DWORD PTR [rax],edx
   1400078fc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400078ff:	48 83 c4 10          	add    rsp,0x10
   140007903:	5d                   	pop    rbp
   140007904:	c3                   	ret

0000000140007905 <__rshift_D2A>:
   140007905:	55                   	push   rbp
   140007906:	48 89 e5             	mov    rbp,rsp
   140007909:	48 83 ec 20          	sub    rsp,0x20
   14000790d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007911:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007914:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007918:	48 83 c0 18          	add    rax,0x18
   14000791c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007920:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007924:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007928:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000792b:	c1 f8 05             	sar    eax,0x5
   14000792e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007931:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007935:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007938:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   14000793b:	0f 8d e4 00 00 00    	jge    140007a25 <__rshift_D2A+0x120>
   140007941:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007945:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007948:	48 98                	cdqe
   14000794a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007951:	00 
   140007952:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007956:	48 01 d0             	add    rax,rdx
   140007959:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000795d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007960:	48 98                	cdqe
   140007962:	48 c1 e0 02          	shl    rax,0x2
   140007966:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   14000796a:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000796e:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140007972:	0f 84 a3 00 00 00    	je     140007a1b <__rshift_D2A+0x116>
   140007978:	b8 20 00 00 00       	mov    eax,0x20
   14000797d:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   140007980:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007983:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007987:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000798b:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000798f:	8b 10                	mov    edx,DWORD PTR [rax]
   140007991:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007994:	89 c1                	mov    ecx,eax
   140007996:	d3 ea                	shr    edx,cl
   140007998:	89 d0                	mov    eax,edx
   14000799a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000799d:	eb 3c                	jmp    1400079db <__rshift_D2A+0xd6>
   14000799f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079a3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079a5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400079a8:	89 c1                	mov    ecx,eax
   1400079aa:	d3 e2                	shl    edx,cl
   1400079ac:	89 d1                	mov    ecx,edx
   1400079ae:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079b2:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400079b6:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400079ba:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   1400079bd:	89 ca                	mov    edx,ecx
   1400079bf:	89 10                	mov    DWORD PTR [rax],edx
   1400079c1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079c5:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400079c9:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400079cd:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079cf:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400079d2:	89 c1                	mov    ecx,eax
   1400079d4:	d3 ea                	shr    edx,cl
   1400079d6:	89 d0                	mov    eax,edx
   1400079d8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400079db:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079df:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   1400079e3:	72 ba                	jb     14000799f <__rshift_D2A+0x9a>
   1400079e5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079e9:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400079ec:	89 10                	mov    DWORD PTR [rax],edx
   1400079ee:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079f2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400079f4:	85 c0                	test   eax,eax
   1400079f6:	74 2d                	je     140007a25 <__rshift_D2A+0x120>
   1400079f8:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   1400079fd:	eb 26                	jmp    140007a25 <__rshift_D2A+0x120>
   1400079ff:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140007a03:	48 8d 42 04          	lea    rax,[rdx+0x4]
   140007a07:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a0b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a0f:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140007a13:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   140007a17:	8b 12                	mov    edx,DWORD PTR [rdx]
   140007a19:	89 10                	mov    DWORD PTR [rax],edx
   140007a1b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a1f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007a23:	72 da                	jb     1400079ff <__rshift_D2A+0xfa>
   140007a25:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a29:	48 83 c0 18          	add    rax,0x18
   140007a2d:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140007a31:	48 29 c2             	sub    rdx,rax
   140007a34:	48 89 d0             	mov    rax,rdx
   140007a37:	48 c1 f8 02          	sar    rax,0x2
   140007a3b:	89 c2                	mov    edx,eax
   140007a3d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a41:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007a44:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a48:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a4b:	85 c0                	test   eax,eax
   140007a4d:	75 0b                	jne    140007a5a <__rshift_D2A+0x155>
   140007a4f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a53:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   140007a5a:	90                   	nop
   140007a5b:	48 83 c4 20          	add    rsp,0x20
   140007a5f:	5d                   	pop    rbp
   140007a60:	c3                   	ret

0000000140007a61 <__trailz_D2A>:
   140007a61:	55                   	push   rbp
   140007a62:	48 89 e5             	mov    rbp,rsp
   140007a65:	48 83 ec 40          	sub    rsp,0x40
   140007a69:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007a6d:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a74:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a78:	48 83 c0 18          	add    rax,0x18
   140007a7c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a80:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a84:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a87:	48 98                	cdqe
   140007a89:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007a90:	00 
   140007a91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a95:	48 01 d0             	add    rax,rdx
   140007a98:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007a9c:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007aa3:	eb 09                	jmp    140007aae <__trailz_D2A+0x4d>
   140007aa5:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   140007aa9:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   140007aae:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ab2:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007ab6:	73 0a                	jae    140007ac2 <__trailz_D2A+0x61>
   140007ab8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007abc:	8b 00                	mov    eax,DWORD PTR [rax]
   140007abe:	85 c0                	test   eax,eax
   140007ac0:	74 e3                	je     140007aa5 <__trailz_D2A+0x44>
   140007ac2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ac6:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007aca:	73 18                	jae    140007ae4 <__trailz_D2A+0x83>
   140007acc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ad0:	8b 00                	mov    eax,DWORD PTR [rax]
   140007ad2:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007ad5:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007ad9:	48 89 c1             	mov    rcx,rax
   140007adc:	e8 ef fd ff ff       	call   1400078d0 <__lo0bits_D2A>
   140007ae1:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007ae4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007ae7:	48 83 c4 40          	add    rsp,0x40
   140007aeb:	5d                   	pop    rbp
   140007aec:	c3                   	ret
   140007aed:	90                   	nop
   140007aee:	90                   	nop
   140007aef:	90                   	nop

0000000140007af0 <dtoa_lock_cleanup>:
   140007af0:	55                   	push   rbp
   140007af1:	48 89 e5             	mov    rbp,rsp
   140007af4:	48 83 ec 40          	sub    rsp,0x40
   140007af8:	48 8d 05 f1 76 00 00 	lea    rax,[rip+0x76f1]        # 14000f1f0 <dtoa_CS_init>
   140007aff:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007b03:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007b0a:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007b0d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007b11:	87 10                	xchg   DWORD PTR [rax],edx
   140007b13:	89 d0                	mov    eax,edx
   140007b15:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007b18:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007b1c:	75 3d                	jne    140007b5b <dtoa_lock_cleanup+0x6b>
   140007b1e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007b25:	eb 2e                	jmp    140007b55 <dtoa_lock_cleanup+0x65>
   140007b27:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007b2a:	48 63 d0             	movsxd rdx,eax
   140007b2d:	48 89 d0             	mov    rax,rdx
   140007b30:	48 c1 e0 02          	shl    rax,0x2
   140007b34:	48 01 d0             	add    rax,rdx
   140007b37:	48 c1 e0 03          	shl    rax,0x3
   140007b3b:	48 8d 15 5e 76 00 00 	lea    rdx,[rip+0x765e]        # 14000f1a0 <dtoa_CritSec>
   140007b42:	48 01 d0             	add    rax,rdx
   140007b45:	48 89 c1             	mov    rcx,rax
   140007b48:	48 8b 05 99 86 00 00 	mov    rax,QWORD PTR [rip+0x8699]        # 1400101e8 <__IAT_start__>
   140007b4f:	ff d0                	call   rax
   140007b51:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b55:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b59:	7e cc                	jle    140007b27 <dtoa_lock_cleanup+0x37>
   140007b5b:	90                   	nop
   140007b5c:	48 83 c4 40          	add    rsp,0x40
   140007b60:	5d                   	pop    rbp
   140007b61:	c3                   	ret

0000000140007b62 <dtoa_lock>:
   140007b62:	55                   	push   rbp
   140007b63:	48 89 e5             	mov    rbp,rsp
   140007b66:	48 83 ec 40          	sub    rsp,0x40
   140007b6a:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007b6d:	8b 05 7d 76 00 00    	mov    eax,DWORD PTR [rip+0x767d]        # 14000f1f0 <dtoa_CS_init>
   140007b73:	83 f8 02             	cmp    eax,0x2
   140007b76:	75 2c                	jne    140007ba4 <dtoa_lock+0x42>
   140007b78:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007b7b:	48 89 d0             	mov    rax,rdx
   140007b7e:	48 c1 e0 02          	shl    rax,0x2
   140007b82:	48 01 d0             	add    rax,rdx
   140007b85:	48 c1 e0 03          	shl    rax,0x3
   140007b89:	48 8d 15 10 76 00 00 	lea    rdx,[rip+0x7610]        # 14000f1a0 <dtoa_CritSec>
   140007b90:	48 01 d0             	add    rax,rdx
   140007b93:	48 89 c1             	mov    rcx,rax
   140007b96:	48 8b 05 53 86 00 00 	mov    rax,QWORD PTR [rip+0x8653]        # 1400101f0 <__imp_EnterCriticalSection>
   140007b9d:	ff d0                	call   rax
   140007b9f:	e9 ea 00 00 00       	jmp    140007c8e <dtoa_lock+0x12c>
   140007ba4:	8b 05 46 76 00 00    	mov    eax,DWORD PTR [rip+0x7646]        # 14000f1f0 <dtoa_CS_init>
   140007baa:	85 c0                	test   eax,eax
   140007bac:	0f 85 9e 00 00 00    	jne    140007c50 <dtoa_lock+0xee>
   140007bb2:	48 8d 05 37 76 00 00 	lea    rax,[rip+0x7637]        # 14000f1f0 <dtoa_CS_init>
   140007bb9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007bbd:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007bc4:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007bc7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007bcb:	87 10                	xchg   DWORD PTR [rax],edx
   140007bcd:	89 d0                	mov    eax,edx
   140007bcf:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007bd2:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007bd6:	75 58                	jne    140007c30 <dtoa_lock+0xce>
   140007bd8:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007bdf:	eb 2e                	jmp    140007c0f <dtoa_lock+0xad>
   140007be1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007be4:	48 63 d0             	movsxd rdx,eax
   140007be7:	48 89 d0             	mov    rax,rdx
   140007bea:	48 c1 e0 02          	shl    rax,0x2
   140007bee:	48 01 d0             	add    rax,rdx
   140007bf1:	48 c1 e0 03          	shl    rax,0x3
   140007bf5:	48 8d 15 a4 75 00 00 	lea    rdx,[rip+0x75a4]        # 14000f1a0 <dtoa_CritSec>
   140007bfc:	48 01 d0             	add    rax,rdx
   140007bff:	48 89 c1             	mov    rcx,rax
   140007c02:	48 8b 05 17 86 00 00 	mov    rax,QWORD PTR [rip+0x8617]        # 140010220 <__imp_InitializeCriticalSection>
   140007c09:	ff d0                	call   rax
   140007c0b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007c0f:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007c13:	7e cc                	jle    140007be1 <dtoa_lock+0x7f>
   140007c15:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007af0 <dtoa_lock_cleanup>
   140007c1c:	48 89 c1             	mov    rcx,rax
   140007c1f:	e8 0b 9a ff ff       	call   14000162f <atexit>
   140007c24:	c7 05 c2 75 00 00 02 	mov    DWORD PTR [rip+0x75c2],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c2b:	00 00 00 
   140007c2e:	eb 20                	jmp    140007c50 <dtoa_lock+0xee>
   140007c30:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007c34:	75 1a                	jne    140007c50 <dtoa_lock+0xee>
   140007c36:	c7 05 b0 75 00 00 02 	mov    DWORD PTR [rip+0x75b0],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c3d:	00 00 00 
   140007c40:	eb 0e                	jmp    140007c50 <dtoa_lock+0xee>
   140007c42:	b9 01 00 00 00       	mov    ecx,0x1
   140007c47:	48 8b 05 fa 85 00 00 	mov    rax,QWORD PTR [rip+0x85fa]        # 140010248 <__imp_Sleep>
   140007c4e:	ff d0                	call   rax
   140007c50:	8b 05 9a 75 00 00    	mov    eax,DWORD PTR [rip+0x759a]        # 14000f1f0 <dtoa_CS_init>
   140007c56:	83 f8 01             	cmp    eax,0x1
   140007c59:	74 e7                	je     140007c42 <dtoa_lock+0xe0>
   140007c5b:	8b 05 8f 75 00 00    	mov    eax,DWORD PTR [rip+0x758f]        # 14000f1f0 <dtoa_CS_init>
   140007c61:	83 f8 02             	cmp    eax,0x2
   140007c64:	75 28                	jne    140007c8e <dtoa_lock+0x12c>
   140007c66:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c69:	48 89 d0             	mov    rax,rdx
   140007c6c:	48 c1 e0 02          	shl    rax,0x2
   140007c70:	48 01 d0             	add    rax,rdx
   140007c73:	48 c1 e0 03          	shl    rax,0x3
   140007c77:	48 8d 15 22 75 00 00 	lea    rdx,[rip+0x7522]        # 14000f1a0 <dtoa_CritSec>
   140007c7e:	48 01 d0             	add    rax,rdx
   140007c81:	48 89 c1             	mov    rcx,rax
   140007c84:	48 8b 05 65 85 00 00 	mov    rax,QWORD PTR [rip+0x8565]        # 1400101f0 <__imp_EnterCriticalSection>
   140007c8b:	ff d0                	call   rax
   140007c8d:	90                   	nop
   140007c8e:	48 83 c4 40          	add    rsp,0x40
   140007c92:	5d                   	pop    rbp
   140007c93:	c3                   	ret

0000000140007c94 <dtoa_unlock>:
   140007c94:	55                   	push   rbp
   140007c95:	48 89 e5             	mov    rbp,rsp
   140007c98:	48 83 ec 20          	sub    rsp,0x20
   140007c9c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c9f:	8b 05 4b 75 00 00    	mov    eax,DWORD PTR [rip+0x754b]        # 14000f1f0 <dtoa_CS_init>
   140007ca5:	83 f8 02             	cmp    eax,0x2
   140007ca8:	75 27                	jne    140007cd1 <dtoa_unlock+0x3d>
   140007caa:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007cad:	48 89 d0             	mov    rax,rdx
   140007cb0:	48 c1 e0 02          	shl    rax,0x2
   140007cb4:	48 01 d0             	add    rax,rdx
   140007cb7:	48 c1 e0 03          	shl    rax,0x3
   140007cbb:	48 8d 15 de 74 00 00 	lea    rdx,[rip+0x74de]        # 14000f1a0 <dtoa_CritSec>
   140007cc2:	48 01 d0             	add    rax,rdx
   140007cc5:	48 89 c1             	mov    rcx,rax
   140007cc8:	48 8b 05 59 85 00 00 	mov    rax,QWORD PTR [rip+0x8559]        # 140010228 <__imp_LeaveCriticalSection>
   140007ccf:	ff d0                	call   rax
   140007cd1:	90                   	nop
   140007cd2:	48 83 c4 20          	add    rsp,0x20
   140007cd6:	5d                   	pop    rbp
   140007cd7:	c3                   	ret

0000000140007cd8 <__lo0bits_D2A>:
   140007cd8:	55                   	push   rbp
   140007cd9:	48 89 e5             	mov    rbp,rsp
   140007cdc:	48 83 ec 10          	sub    rsp,0x10
   140007ce0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007ce4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ce8:	8b 00                	mov    eax,DWORD PTR [rax]
   140007cea:	f3 0f bc c0          	tzcnt  eax,eax
   140007cee:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007cf1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007cf5:	8b 10                	mov    edx,DWORD PTR [rax]
   140007cf7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007cfa:	89 c1                	mov    ecx,eax
   140007cfc:	d3 ea                	shr    edx,cl
   140007cfe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d02:	89 10                	mov    DWORD PTR [rax],edx
   140007d04:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007d07:	48 83 c4 10          	add    rsp,0x10
   140007d0b:	5d                   	pop    rbp
   140007d0c:	c3                   	ret

0000000140007d0d <__hi0bits_D2A>:
   140007d0d:	55                   	push   rbp
   140007d0e:	48 89 e5             	mov    rbp,rsp
   140007d11:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007d14:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007d18:	83 f0 1f             	xor    eax,0x1f
   140007d1b:	5d                   	pop    rbp
   140007d1c:	c3                   	ret

0000000140007d1d <__Balloc_D2A>:
   140007d1d:	55                   	push   rbp
   140007d1e:	48 89 e5             	mov    rbp,rsp
   140007d21:	48 83 ec 30          	sub    rsp,0x30
   140007d25:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007d28:	b9 00 00 00 00       	mov    ecx,0x0
   140007d2d:	e8 30 fe ff ff       	call   140007b62 <dtoa_lock>
   140007d32:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d36:	7f 48                	jg     140007d80 <__Balloc_D2A+0x63>
   140007d38:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d3b:	48 98                	cdqe
   140007d3d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007d44:	00 
   140007d45:	48 8d 05 b4 74 00 00 	lea    rax,[rip+0x74b4]        # 14000f200 <freelist>
   140007d4c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007d50:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d54:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d59:	74 25                	je     140007d80 <__Balloc_D2A+0x63>
   140007d5b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d5f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007d62:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d65:	48 63 d2             	movsxd rdx,edx
   140007d68:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007d6f:	00 
   140007d70:	48 8d 15 89 74 00 00 	lea    rdx,[rip+0x7489]        # 14000f200 <freelist>
   140007d77:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007d7b:	e9 b1 00 00 00       	jmp    140007e31 <__Balloc_D2A+0x114>
   140007d80:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d83:	ba 01 00 00 00       	mov    edx,0x1
   140007d88:	89 c1                	mov    ecx,eax
   140007d8a:	d3 e2                	shl    edx,cl
   140007d8c:	89 d0                	mov    eax,edx
   140007d8e:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007d91:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007d94:	83 e8 01             	sub    eax,0x1
   140007d97:	48 98                	cdqe
   140007d99:	48 c1 e0 02          	shl    rax,0x2
   140007d9d:	48 83 c0 27          	add    rax,0x27
   140007da1:	48 c1 e8 03          	shr    rax,0x3
   140007da5:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007da8:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007dac:	7f 4e                	jg     140007dfc <__Balloc_D2A+0xdf>
   140007dae:	48 8b 15 db 22 00 00 	mov    rdx,QWORD PTR [rip+0x22db]        # 14000a090 <pmem_next>
   140007db5:	48 8d 05 a4 74 00 00 	lea    rax,[rip+0x74a4]        # 14000f260 <private_mem>
   140007dbc:	48 29 c2             	sub    rdx,rax
   140007dbf:	48 89 d0             	mov    rax,rdx
   140007dc2:	48 c1 f8 03          	sar    rax,0x3
   140007dc6:	48 89 c2             	mov    rdx,rax
   140007dc9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007dcc:	48 01 d0             	add    rax,rdx
   140007dcf:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007dd5:	77 25                	ja     140007dfc <__Balloc_D2A+0xdf>
   140007dd7:	48 8b 05 b2 22 00 00 	mov    rax,QWORD PTR [rip+0x22b2]        # 14000a090 <pmem_next>
   140007dde:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007de2:	48 8b 05 a7 22 00 00 	mov    rax,QWORD PTR [rip+0x22a7]        # 14000a090 <pmem_next>
   140007de9:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007dec:	48 c1 e2 03          	shl    rdx,0x3
   140007df0:	48 01 d0             	add    rax,rdx
   140007df3:	48 89 05 96 22 00 00 	mov    QWORD PTR [rip+0x2296],rax        # 14000a090 <pmem_next>
   140007dfa:	eb 21                	jmp    140007e1d <__Balloc_D2A+0x100>
   140007dfc:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007dff:	48 c1 e0 03          	shl    rax,0x3
   140007e03:	48 89 c1             	mov    rcx,rax
   140007e06:	e8 e5 18 00 00       	call   1400096f0 <malloc>
   140007e0b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007e0f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007e14:	75 07                	jne    140007e1d <__Balloc_D2A+0x100>
   140007e16:	b8 00 00 00 00       	mov    eax,0x0
   140007e1b:	eb 3b                	jmp    140007e58 <__Balloc_D2A+0x13b>
   140007e1d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e21:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007e24:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007e27:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e2b:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007e2e:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007e31:	b9 00 00 00 00       	mov    ecx,0x0
   140007e36:	e8 59 fe ff ff       	call   140007c94 <dtoa_unlock>
   140007e3b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e3f:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007e46:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e4a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007e4d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e51:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007e54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e58:	48 83 c4 30          	add    rsp,0x30
   140007e5c:	5d                   	pop    rbp
   140007e5d:	c3                   	ret

0000000140007e5e <__Bfree_D2A>:
   140007e5e:	55                   	push   rbp
   140007e5f:	48 89 e5             	mov    rbp,rsp
   140007e62:	48 83 ec 20          	sub    rsp,0x20
   140007e66:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e6a:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007e6f:	74 71                	je     140007ee2 <__Bfree_D2A+0x84>
   140007e71:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e75:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e78:	83 f8 09             	cmp    eax,0x9
   140007e7b:	7e 0e                	jle    140007e8b <__Bfree_D2A+0x2d>
   140007e7d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e81:	48 89 c1             	mov    rcx,rax
   140007e84:	e8 57 18 00 00       	call   1400096e0 <free>
   140007e89:	eb 57                	jmp    140007ee2 <__Bfree_D2A+0x84>
   140007e8b:	b9 00 00 00 00       	mov    ecx,0x0
   140007e90:	e8 cd fc ff ff       	call   140007b62 <dtoa_lock>
   140007e95:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e99:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e9c:	48 98                	cdqe
   140007e9e:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007ea5:	00 
   140007ea6:	48 8d 05 53 73 00 00 	lea    rax,[rip+0x7353]        # 14000f200 <freelist>
   140007ead:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007eb1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eb5:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007eb8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ebc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007ebf:	48 98                	cdqe
   140007ec1:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007ec8:	00 
   140007ec9:	48 8d 15 30 73 00 00 	lea    rdx,[rip+0x7330]        # 14000f200 <freelist>
   140007ed0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ed4:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007ed8:	b9 00 00 00 00       	mov    ecx,0x0
   140007edd:	e8 b2 fd ff ff       	call   140007c94 <dtoa_unlock>
   140007ee2:	90                   	nop
   140007ee3:	48 83 c4 20          	add    rsp,0x20
   140007ee7:	5d                   	pop    rbp
   140007ee8:	c3                   	ret

0000000140007ee9 <__multadd_D2A>:
   140007ee9:	55                   	push   rbp
   140007eea:	48 89 e5             	mov    rbp,rsp
   140007eed:	48 83 ec 50          	sub    rsp,0x50
   140007ef1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007ef5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007ef8:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007efc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f00:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f03:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007f06:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f0a:	48 83 c0 18          	add    rax,0x18
   140007f0e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007f12:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007f19:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007f1c:	48 98                	cdqe
   140007f1e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f22:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f26:	8b 00                	mov    eax,DWORD PTR [rax]
   140007f28:	89 c2                	mov    edx,eax
   140007f2a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007f2d:	48 98                	cdqe
   140007f2f:	48 0f af d0          	imul   rdx,rax
   140007f33:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007f37:	48 01 d0             	add    rax,rdx
   140007f3a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007f3e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007f42:	48 c1 e8 20          	shr    rax,0x20
   140007f46:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f4a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f4e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007f52:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007f56:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007f5a:	89 10                	mov    DWORD PTR [rax],edx
   140007f5c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007f60:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007f63:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007f66:	7c ba                	jl     140007f22 <__multadd_D2A+0x39>
   140007f68:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007f6d:	0f 84 9a 00 00 00    	je     14000800d <__multadd_D2A+0x124>
   140007f73:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f77:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007f7a:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007f7d:	7c 67                	jl     140007fe6 <__multadd_D2A+0xfd>
   140007f7f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f83:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007f86:	83 c0 01             	add    eax,0x1
   140007f89:	89 c1                	mov    ecx,eax
   140007f8b:	e8 8d fd ff ff       	call   140007d1d <__Balloc_D2A>
   140007f90:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007f94:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007f99:	75 07                	jne    140007fa2 <__multadd_D2A+0xb9>
   140007f9b:	b8 00 00 00 00       	mov    eax,0x0
   140007fa0:	eb 6f                	jmp    140008011 <__multadd_D2A+0x128>
   140007fa2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fa6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fa9:	48 98                	cdqe
   140007fab:	48 83 c0 02          	add    rax,0x2
   140007faf:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007fb6:	00 
   140007fb7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fbb:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007fbf:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007fc3:	48 83 c0 10          	add    rax,0x10
   140007fc7:	49 89 c8             	mov    r8,rcx
   140007fca:	48 89 c1             	mov    rcx,rax
   140007fcd:	e8 26 17 00 00       	call   1400096f8 <memcpy>
   140007fd2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fd6:	48 89 c1             	mov    rcx,rax
   140007fd9:	e8 80 fe ff ff       	call   140007e5e <__Bfree_D2A>
   140007fde:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007fe2:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007fe6:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007fe9:	8d 50 01             	lea    edx,[rax+0x1]
   140007fec:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007fef:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140007ff3:	89 d1                	mov    ecx,edx
   140007ff5:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007ff9:	48 98                	cdqe
   140007ffb:	48 83 c0 04          	add    rax,0x4
   140007fff:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140008003:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008007:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000800a:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000800d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008011:	48 83 c4 50          	add    rsp,0x50
   140008015:	5d                   	pop    rbp
   140008016:	c3                   	ret

0000000140008017 <__i2b_D2A>:
   140008017:	55                   	push   rbp
   140008018:	48 89 e5             	mov    rbp,rsp
   14000801b:	48 83 ec 30          	sub    rsp,0x30
   14000801f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008022:	b9 01 00 00 00       	mov    ecx,0x1
   140008027:	e8 f1 fc ff ff       	call   140007d1d <__Balloc_D2A>
   14000802c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008030:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008035:	75 07                	jne    14000803e <__i2b_D2A+0x27>
   140008037:	b8 00 00 00 00       	mov    eax,0x0
   14000803c:	eb 19                	jmp    140008057 <__i2b_D2A+0x40>
   14000803e:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008041:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008045:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008048:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000804c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008053:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008057:	48 83 c4 30          	add    rsp,0x30
   14000805b:	5d                   	pop    rbp
   14000805c:	c3                   	ret

000000014000805d <__mult_D2A>:
   14000805d:	55                   	push   rbp
   14000805e:	48 89 e5             	mov    rbp,rsp
   140008061:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140008068:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000806c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008070:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008074:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008077:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000807b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000807e:	39 c2                	cmp    edx,eax
   140008080:	7d 18                	jge    14000809a <__mult_D2A+0x3d>
   140008082:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008086:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000808a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000808e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008092:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008096:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000809a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000809e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400080a1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400080a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080a8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400080ab:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400080ae:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080b2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400080b5:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   1400080b8:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   1400080bb:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   1400080be:	01 d0                	add    eax,edx
   1400080c0:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400080c3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080c7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400080ca:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   1400080cd:	7e 04                	jle    1400080d3 <__mult_D2A+0x76>
   1400080cf:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400080d3:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400080d6:	89 c1                	mov    ecx,eax
   1400080d8:	e8 40 fc ff ff       	call   140007d1d <__Balloc_D2A>
   1400080dd:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400080e1:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   1400080e6:	75 0a                	jne    1400080f2 <__mult_D2A+0x95>
   1400080e8:	b8 00 00 00 00       	mov    eax,0x0
   1400080ed:	e9 88 01 00 00       	jmp    14000827a <__mult_D2A+0x21d>
   1400080f2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400080f6:	48 83 c0 18          	add    rax,0x18
   1400080fa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400080fe:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008101:	48 98                	cdqe
   140008103:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000810a:	00 
   14000810b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000810f:	48 01 d0             	add    rax,rdx
   140008112:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140008116:	eb 0f                	jmp    140008127 <__mult_D2A+0xca>
   140008118:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000811c:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008122:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140008127:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000812b:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   14000812f:	72 e7                	jb     140008118 <__mult_D2A+0xbb>
   140008131:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008135:	48 83 c0 18          	add    rax,0x18
   140008139:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000813d:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008140:	48 98                	cdqe
   140008142:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008149:	00 
   14000814a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000814e:	48 01 d0             	add    rax,rdx
   140008151:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008155:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008159:	48 83 c0 18          	add    rax,0x18
   14000815d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008161:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140008164:	48 98                	cdqe
   140008166:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000816d:	00 
   14000816e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008172:	48 01 d0             	add    rax,rdx
   140008175:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   140008179:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000817d:	48 83 c0 18          	add    rax,0x18
   140008181:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008185:	e9 95 00 00 00       	jmp    14000821f <__mult_D2A+0x1c2>
   14000818a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000818e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008192:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008196:	8b 00                	mov    eax,DWORD PTR [rax]
   140008198:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   14000819b:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   14000819f:	74 79                	je     14000821a <__mult_D2A+0x1bd>
   1400081a1:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400081a5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400081a9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400081ad:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400081b1:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400081b8:	00 
   1400081b9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400081bd:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081c1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400081c5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081c7:	89 c2                	mov    edx,eax
   1400081c9:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   1400081cc:	48 0f af d0          	imul   rdx,rax
   1400081d0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081d4:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081d6:	89 c0                	mov    eax,eax
   1400081d8:	48 01 c2             	add    rdx,rax
   1400081db:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400081df:	48 01 d0             	add    rax,rdx
   1400081e2:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   1400081e6:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   1400081ea:	48 c1 e8 20          	shr    rax,0x20
   1400081ee:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400081f2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081f6:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081fa:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400081fe:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140008202:	89 10                	mov    DWORD PTR [rax],edx
   140008204:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008208:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   14000820c:	72 ab                	jb     1400081b9 <__mult_D2A+0x15c>
   14000820e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008212:	89 c2                	mov    edx,eax
   140008214:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008218:	89 10                	mov    DWORD PTR [rax],edx
   14000821a:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   14000821f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008223:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   140008227:	0f 82 5d ff ff ff    	jb     14000818a <__mult_D2A+0x12d>
   14000822d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008231:	48 83 c0 18          	add    rax,0x18
   140008235:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008239:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000823c:	48 98                	cdqe
   14000823e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008245:	00 
   140008246:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000824a:	48 01 d0             	add    rax,rdx
   14000824d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008251:	eb 04                	jmp    140008257 <__mult_D2A+0x1fa>
   140008253:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008257:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000825b:	7e 0f                	jle    14000826c <__mult_D2A+0x20f>
   14000825d:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008262:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008266:	8b 00                	mov    eax,DWORD PTR [rax]
   140008268:	85 c0                	test   eax,eax
   14000826a:	74 e7                	je     140008253 <__mult_D2A+0x1f6>
   14000826c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008270:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008273:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008276:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000827a:	48 81 c4 90 00 00 00 	add    rsp,0x90
   140008281:	5d                   	pop    rbp
   140008282:	c3                   	ret

0000000140008283 <__pow5mult_D2A>:
   140008283:	55                   	push   rbp
   140008284:	48 89 e5             	mov    rbp,rsp
   140008287:	48 83 ec 40          	sub    rsp,0x40
   14000828b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000828f:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140008292:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008295:	83 e0 03             	and    eax,0x3
   140008298:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000829b:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000829f:	74 41                	je     1400082e2 <__pow5mult_D2A+0x5f>
   1400082a1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400082a4:	83 e8 01             	sub    eax,0x1
   1400082a7:	48 98                	cdqe
   1400082a9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400082b0:	00 
   1400082b1:	48 8d 05 e0 1d 00 00 	lea    rax,[rip+0x1de0]        # 14000a098 <p05.0>
   1400082b8:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   1400082bb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082bf:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400082c5:	48 89 c1             	mov    rcx,rax
   1400082c8:	e8 1c fc ff ff       	call   140007ee9 <__multadd_D2A>
   1400082cd:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400082d1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400082d6:	75 0a                	jne    1400082e2 <__pow5mult_D2A+0x5f>
   1400082d8:	b8 00 00 00 00       	mov    eax,0x0
   1400082dd:	e9 58 01 00 00       	jmp    14000843a <__pow5mult_D2A+0x1b7>
   1400082e2:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   1400082e6:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400082ea:	75 09                	jne    1400082f5 <__pow5mult_D2A+0x72>
   1400082ec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082f0:	e9 45 01 00 00       	jmp    14000843a <__pow5mult_D2A+0x1b7>
   1400082f5:	48 8b 05 64 78 00 00 	mov    rax,QWORD PTR [rip+0x7864]        # 14000fb60 <p5s>
   1400082fc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008300:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008305:	75 5e                	jne    140008365 <__pow5mult_D2A+0xe2>
   140008307:	b9 01 00 00 00       	mov    ecx,0x1
   14000830c:	e8 51 f8 ff ff       	call   140007b62 <dtoa_lock>
   140008311:	48 8b 05 48 78 00 00 	mov    rax,QWORD PTR [rip+0x7848]        # 14000fb60 <p5s>
   140008318:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000831c:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008321:	75 38                	jne    14000835b <__pow5mult_D2A+0xd8>
   140008323:	b9 71 02 00 00       	mov    ecx,0x271
   140008328:	e8 ea fc ff ff       	call   140008017 <__i2b_D2A>
   14000832d:	48 89 05 2c 78 00 00 	mov    QWORD PTR [rip+0x782c],rax        # 14000fb60 <p5s>
   140008334:	48 8b 05 25 78 00 00 	mov    rax,QWORD PTR [rip+0x7825]        # 14000fb60 <p5s>
   14000833b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000833f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008344:	75 0a                	jne    140008350 <__pow5mult_D2A+0xcd>
   140008346:	b8 00 00 00 00       	mov    eax,0x0
   14000834b:	e9 ea 00 00 00       	jmp    14000843a <__pow5mult_D2A+0x1b7>
   140008350:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008354:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000835b:	b9 01 00 00 00       	mov    ecx,0x1
   140008360:	e8 2f f9 ff ff       	call   140007c94 <dtoa_unlock>
   140008365:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008368:	83 e0 01             	and    eax,0x1
   14000836b:	85 c0                	test   eax,eax
   14000836d:	74 39                	je     1400083a8 <__pow5mult_D2A+0x125>
   14000836f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008373:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008377:	48 89 c1             	mov    rcx,rax
   14000837a:	e8 de fc ff ff       	call   14000805d <__mult_D2A>
   14000837f:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008383:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   140008388:	75 0a                	jne    140008394 <__pow5mult_D2A+0x111>
   14000838a:	b8 00 00 00 00       	mov    eax,0x0
   14000838f:	e9 a6 00 00 00       	jmp    14000843a <__pow5mult_D2A+0x1b7>
   140008394:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008398:	48 89 c1             	mov    rcx,rax
   14000839b:	e8 be fa ff ff       	call   140007e5e <__Bfree_D2A>
   1400083a0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400083a4:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400083a8:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   1400083ab:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400083af:	0f 84 80 00 00 00    	je     140008435 <__pow5mult_D2A+0x1b2>
   1400083b5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083b9:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083bc:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083c0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083c5:	75 61                	jne    140008428 <__pow5mult_D2A+0x1a5>
   1400083c7:	b9 01 00 00 00       	mov    ecx,0x1
   1400083cc:	e8 91 f7 ff ff       	call   140007b62 <dtoa_lock>
   1400083d1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083d5:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083d8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083dc:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083e1:	75 3b                	jne    14000841e <__pow5mult_D2A+0x19b>
   1400083e3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083e7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083eb:	48 89 c1             	mov    rcx,rax
   1400083ee:	e8 6a fc ff ff       	call   14000805d <__mult_D2A>
   1400083f3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083f7:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400083fa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083fe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008401:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008405:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000840a:	75 07                	jne    140008413 <__pow5mult_D2A+0x190>
   14000840c:	b8 00 00 00 00       	mov    eax,0x0
   140008411:	eb 27                	jmp    14000843a <__pow5mult_D2A+0x1b7>
   140008413:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008417:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000841e:	b9 01 00 00 00       	mov    ecx,0x1
   140008423:	e8 6c f8 ff ff       	call   140007c94 <dtoa_unlock>
   140008428:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000842c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008430:	e9 30 ff ff ff       	jmp    140008365 <__pow5mult_D2A+0xe2>
   140008435:	90                   	nop
   140008436:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000843a:	48 83 c4 40          	add    rsp,0x40
   14000843e:	5d                   	pop    rbp
   14000843f:	c3                   	ret

0000000140008440 <__lshift_D2A>:
   140008440:	55                   	push   rbp
   140008441:	48 89 e5             	mov    rbp,rsp
   140008444:	48 83 ec 60          	sub    rsp,0x60
   140008448:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000844c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000844f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008452:	c1 f8 05             	sar    eax,0x5
   140008455:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   140008458:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000845c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000845f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008462:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008466:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008469:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   14000846c:	01 d0                	add    eax,edx
   14000846e:	83 c0 01             	add    eax,0x1
   140008471:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008474:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008478:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000847b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000847e:	eb 07                	jmp    140008487 <__lshift_D2A+0x47>
   140008480:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140008484:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140008487:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000848a:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   14000848d:	7f f1                	jg     140008480 <__lshift_D2A+0x40>
   14000848f:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008492:	89 c1                	mov    ecx,eax
   140008494:	e8 84 f8 ff ff       	call   140007d1d <__Balloc_D2A>
   140008499:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000849d:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400084a2:	75 0a                	jne    1400084ae <__lshift_D2A+0x6e>
   1400084a4:	b8 00 00 00 00       	mov    eax,0x0
   1400084a9:	e9 19 01 00 00       	jmp    1400085c7 <__lshift_D2A+0x187>
   1400084ae:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400084b2:	48 83 c0 18          	add    rax,0x18
   1400084b6:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400084ba:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400084c1:	eb 16                	jmp    1400084d9 <__lshift_D2A+0x99>
   1400084c3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084c7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400084cb:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400084cf:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400084d5:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400084d9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400084dc:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   1400084df:	7c e2                	jl     1400084c3 <__lshift_D2A+0x83>
   1400084e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084e5:	48 83 c0 18          	add    rax,0x18
   1400084e9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400084ed:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084f1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400084f4:	48 98                	cdqe
   1400084f6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400084fd:	00 
   1400084fe:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008502:	48 01 d0             	add    rax,rdx
   140008505:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008509:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000850d:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140008511:	74 71                	je     140008584 <__lshift_D2A+0x144>
   140008513:	b8 20 00 00 00       	mov    eax,0x20
   140008518:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000851b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000851e:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   140008525:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008529:	8b 10                	mov    edx,DWORD PTR [rax]
   14000852b:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000852e:	89 c1                	mov    ecx,eax
   140008530:	d3 e2                	shl    edx,cl
   140008532:	89 d1                	mov    ecx,edx
   140008534:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008538:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000853c:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008540:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008543:	89 ca                	mov    edx,ecx
   140008545:	89 10                	mov    DWORD PTR [rax],edx
   140008547:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000854b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000854f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008553:	8b 10                	mov    edx,DWORD PTR [rax]
   140008555:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008558:	89 c1                	mov    ecx,eax
   14000855a:	d3 ea                	shr    edx,cl
   14000855c:	89 d0                	mov    eax,edx
   14000855e:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008561:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008565:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008569:	72 ba                	jb     140008525 <__lshift_D2A+0xe5>
   14000856b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000856f:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   140008572:	89 10                	mov    DWORD PTR [rax],edx
   140008574:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008578:	8b 00                	mov    eax,DWORD PTR [rax]
   14000857a:	85 c0                	test   eax,eax
   14000857c:	74 2c                	je     1400085aa <__lshift_D2A+0x16a>
   14000857e:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140008582:	eb 26                	jmp    1400085aa <__lshift_D2A+0x16a>
   140008584:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008588:	48 8d 42 04          	lea    rax,[rdx+0x4]
   14000858c:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008590:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008594:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140008598:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   14000859c:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000859e:	89 10                	mov    DWORD PTR [rax],edx
   1400085a0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400085a4:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400085a8:	72 da                	jb     140008584 <__lshift_D2A+0x144>
   1400085aa:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400085ad:	8d 50 ff             	lea    edx,[rax-0x1]
   1400085b0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400085b4:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400085b7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085bb:	48 89 c1             	mov    rcx,rax
   1400085be:	e8 9b f8 ff ff       	call   140007e5e <__Bfree_D2A>
   1400085c3:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400085c7:	48 83 c4 60          	add    rsp,0x60
   1400085cb:	5d                   	pop    rbp
   1400085cc:	c3                   	ret

00000001400085cd <__cmp_D2A>:
   1400085cd:	55                   	push   rbp
   1400085ce:	48 89 e5             	mov    rbp,rsp
   1400085d1:	48 83 ec 30          	sub    rsp,0x30
   1400085d5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400085d9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400085dd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085e1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400085e4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400085e7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400085eb:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400085ee:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400085f1:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085f4:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   1400085f7:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400085fb:	74 08                	je     140008605 <__cmp_D2A+0x38>
   1400085fd:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008600:	e9 92 00 00 00       	jmp    140008697 <__cmp_D2A+0xca>
   140008605:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008609:	48 83 c0 18          	add    rax,0x18
   14000860d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008611:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008614:	48 98                	cdqe
   140008616:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000861d:	00 
   14000861e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008622:	48 01 d0             	add    rax,rdx
   140008625:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008629:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000862d:	48 83 c0 18          	add    rax,0x18
   140008631:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008635:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008638:	48 98                	cdqe
   14000863a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008641:	00 
   140008642:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008646:	48 01 d0             	add    rax,rdx
   140008649:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000864d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008652:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008656:	8b 10                	mov    edx,DWORD PTR [rax]
   140008658:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   14000865d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008661:	8b 00                	mov    eax,DWORD PTR [rax]
   140008663:	39 c2                	cmp    edx,eax
   140008665:	74 1e                	je     140008685 <__cmp_D2A+0xb8>
   140008667:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000866b:	8b 10                	mov    edx,DWORD PTR [rax]
   14000866d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008671:	8b 00                	mov    eax,DWORD PTR [rax]
   140008673:	39 c2                	cmp    edx,eax
   140008675:	73 07                	jae    14000867e <__cmp_D2A+0xb1>
   140008677:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000867c:	eb 19                	jmp    140008697 <__cmp_D2A+0xca>
   14000867e:	b8 01 00 00 00       	mov    eax,0x1
   140008683:	eb 12                	jmp    140008697 <__cmp_D2A+0xca>
   140008685:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008689:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000868d:	73 02                	jae    140008691 <__cmp_D2A+0xc4>
   14000868f:	eb bc                	jmp    14000864d <__cmp_D2A+0x80>
   140008691:	90                   	nop
   140008692:	b8 00 00 00 00       	mov    eax,0x0
   140008697:	48 83 c4 30          	add    rsp,0x30
   14000869b:	5d                   	pop    rbp
   14000869c:	c3                   	ret

000000014000869d <__diff_D2A>:
   14000869d:	55                   	push   rbp
   14000869e:	48 89 e5             	mov    rbp,rsp
   1400086a1:	48 83 ec 70          	sub    rsp,0x70
   1400086a5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400086a9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400086ad:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400086b1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086b5:	48 89 c1             	mov    rcx,rax
   1400086b8:	e8 10 ff ff ff       	call   1400085cd <__cmp_D2A>
   1400086bd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400086c0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400086c4:	75 3e                	jne    140008704 <__diff_D2A+0x67>
   1400086c6:	b9 00 00 00 00       	mov    ecx,0x0
   1400086cb:	e8 4d f6 ff ff       	call   140007d1d <__Balloc_D2A>
   1400086d0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400086d4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400086d9:	75 0a                	jne    1400086e5 <__diff_D2A+0x48>
   1400086db:	b8 00 00 00 00       	mov    eax,0x0
   1400086e0:	e9 ab 01 00 00       	jmp    140008890 <__diff_D2A+0x1f3>
   1400086e5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086e9:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   1400086f0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086f4:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   1400086fb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086ff:	e9 8c 01 00 00       	jmp    140008890 <__diff_D2A+0x1f3>
   140008704:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008708:	79 21                	jns    14000872b <__diff_D2A+0x8e>
   14000870a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000870e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008712:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008716:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000871a:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000871e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140008722:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140008729:	eb 07                	jmp    140008732 <__diff_D2A+0x95>
   14000872b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008732:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008736:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008739:	89 c1                	mov    ecx,eax
   14000873b:	e8 dd f5 ff ff       	call   140007d1d <__Balloc_D2A>
   140008740:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008744:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008749:	75 0a                	jne    140008755 <__diff_D2A+0xb8>
   14000874b:	b8 00 00 00 00       	mov    eax,0x0
   140008750:	e9 3b 01 00 00       	jmp    140008890 <__diff_D2A+0x1f3>
   140008755:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008759:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000875c:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000875f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008763:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008766:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008769:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000876d:	48 83 c0 18          	add    rax,0x18
   140008771:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008775:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008778:	48 98                	cdqe
   14000877a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008781:	00 
   140008782:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008786:	48 01 d0             	add    rax,rdx
   140008789:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000878d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008791:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008794:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   140008797:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000879b:	48 83 c0 18          	add    rax,0x18
   14000879f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400087a3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   1400087a6:	48 98                	cdqe
   1400087a8:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400087af:	00 
   1400087b0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087b4:	48 01 d0             	add    rax,rdx
   1400087b7:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400087bb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087bf:	48 83 c0 18          	add    rax,0x18
   1400087c3:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400087c7:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   1400087ce:	00 
   1400087cf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087d3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087d7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400087db:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087dd:	89 c1                	mov    ecx,eax
   1400087df:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087e3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087e7:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400087eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087ed:	89 c2                	mov    edx,eax
   1400087ef:	48 89 c8             	mov    rax,rcx
   1400087f2:	48 29 d0             	sub    rax,rdx
   1400087f5:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400087f9:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400087fd:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008801:	48 c1 e8 20          	shr    rax,0x20
   140008805:	83 e0 01             	and    eax,0x1
   140008808:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000880c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008810:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008814:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008818:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000881c:	89 10                	mov    DWORD PTR [rax],edx
   14000881e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008822:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   140008826:	72 a7                	jb     1400087cf <__diff_D2A+0x132>
   140008828:	eb 39                	jmp    140008863 <__diff_D2A+0x1c6>
   14000882a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000882e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008832:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008836:	8b 00                	mov    eax,DWORD PTR [rax]
   140008838:	89 c0                	mov    eax,eax
   14000883a:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   14000883e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008842:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008846:	48 c1 e8 20          	shr    rax,0x20
   14000884a:	83 e0 01             	and    eax,0x1
   14000884d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008851:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008855:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008859:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000885d:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140008861:	89 10                	mov    DWORD PTR [rax],edx
   140008863:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008867:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   14000886b:	72 bd                	jb     14000882a <__diff_D2A+0x18d>
   14000886d:	eb 04                	jmp    140008873 <__diff_D2A+0x1d6>
   14000886f:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008873:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008878:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000887c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000887e:	85 c0                	test   eax,eax
   140008880:	74 ed                	je     14000886f <__diff_D2A+0x1d2>
   140008882:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008886:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008889:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000888c:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008890:	48 83 c4 70          	add    rsp,0x70
   140008894:	5d                   	pop    rbp
   140008895:	c3                   	ret

0000000140008896 <__b2d_D2A>:
   140008896:	55                   	push   rbp
   140008897:	48 89 e5             	mov    rbp,rsp
   14000889a:	48 83 ec 50          	sub    rsp,0x50
   14000889e:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400088a2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400088a6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400088aa:	48 83 c0 18          	add    rax,0x18
   1400088ae:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400088b2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400088b6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400088b9:	48 98                	cdqe
   1400088bb:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400088c2:	00 
   1400088c3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400088c7:	48 01 d0             	add    rax,rdx
   1400088ca:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400088ce:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088d3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088d7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088d9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400088dc:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400088df:	89 c1                	mov    ecx,eax
   1400088e1:	e8 27 f4 ff ff       	call   140007d0d <__hi0bits_D2A>
   1400088e6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400088e9:	b8 20 00 00 00       	mov    eax,0x20
   1400088ee:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088f1:	89 c2                	mov    edx,eax
   1400088f3:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400088f7:	89 10                	mov    DWORD PTR [rax],edx
   1400088f9:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   1400088fd:	7f 66                	jg     140008965 <__b2d_D2A+0xcf>
   1400088ff:	b8 0b 00 00 00       	mov    eax,0xb
   140008904:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008907:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000890a:	89 c1                	mov    ecx,eax
   14000890c:	d3 ea                	shr    edx,cl
   14000890e:	89 d0                	mov    eax,edx
   140008910:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008915:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008918:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000891c:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008920:	73 10                	jae    140008932 <__b2d_D2A+0x9c>
   140008922:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008927:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000892b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000892d:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008930:	eb 07                	jmp    140008939 <__b2d_D2A+0xa3>
   140008932:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140008939:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000893c:	83 c0 15             	add    eax,0x15
   14000893f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008942:	89 c1                	mov    ecx,eax
   140008944:	d3 e2                	shl    edx,cl
   140008946:	41 89 d0             	mov    r8d,edx
   140008949:	b8 0b 00 00 00       	mov    eax,0xb
   14000894e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008951:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140008954:	89 c1                	mov    ecx,eax
   140008956:	d3 ea                	shr    edx,cl
   140008958:	89 d0                	mov    eax,edx
   14000895a:	44 09 c0             	or     eax,r8d
   14000895d:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008960:	e9 ac 00 00 00       	jmp    140008a11 <__b2d_D2A+0x17b>
   140008965:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008969:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000896d:	73 10                	jae    14000897f <__b2d_D2A+0xe9>
   14000896f:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008974:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008978:	8b 00                	mov    eax,DWORD PTR [rax]
   14000897a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000897d:	eb 07                	jmp    140008986 <__b2d_D2A+0xf0>
   14000897f:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   140008986:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   14000898a:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   14000898e:	74 70                	je     140008a00 <__b2d_D2A+0x16a>
   140008990:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008993:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008996:	89 c1                	mov    ecx,eax
   140008998:	d3 e2                	shl    edx,cl
   14000899a:	41 89 d0             	mov    r8d,edx
   14000899d:	b8 20 00 00 00       	mov    eax,0x20
   1400089a2:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400089a5:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400089a8:	89 c1                	mov    ecx,eax
   1400089aa:	d3 ea                	shr    edx,cl
   1400089ac:	89 d0                	mov    eax,edx
   1400089ae:	44 09 c0             	or     eax,r8d
   1400089b1:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400089b6:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089b9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089bd:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400089c1:	73 10                	jae    1400089d3 <__b2d_D2A+0x13d>
   1400089c3:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400089c8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089cc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400089ce:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400089d1:	eb 07                	jmp    1400089da <__b2d_D2A+0x144>
   1400089d3:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   1400089da:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089dd:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400089e0:	89 c1                	mov    ecx,eax
   1400089e2:	d3 e2                	shl    edx,cl
   1400089e4:	41 89 d0             	mov    r8d,edx
   1400089e7:	b8 20 00 00 00       	mov    eax,0x20
   1400089ec:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400089ef:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400089f2:	89 c1                	mov    ecx,eax
   1400089f4:	d3 ea                	shr    edx,cl
   1400089f6:	89 d0                	mov    eax,edx
   1400089f8:	44 09 c0             	or     eax,r8d
   1400089fb:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089fe:	eb 11                	jmp    140008a11 <__b2d_D2A+0x17b>
   140008a00:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008a03:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008a08:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008a0b:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008a0e:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a11:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   140008a16:	48 83 c4 50          	add    rsp,0x50
   140008a1a:	5d                   	pop    rbp
   140008a1b:	c3                   	ret

0000000140008a1c <__d2b_D2A>:
   140008a1c:	55                   	push   rbp
   140008a1d:	53                   	push   rbx
   140008a1e:	48 83 ec 58          	sub    rsp,0x58
   140008a22:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140008a27:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   140008a2c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140008a30:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140008a34:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140008a39:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   140008a3e:	b9 01 00 00 00       	mov    ecx,0x1
   140008a43:	e8 d5 f2 ff ff       	call   140007d1d <__Balloc_D2A>
   140008a48:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008a4c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008a51:	75 0a                	jne    140008a5d <__d2b_D2A+0x41>
   140008a53:	b8 00 00 00 00       	mov    eax,0x0
   140008a58:	e9 68 01 00 00       	jmp    140008bc5 <__d2b_D2A+0x1a9>
   140008a5d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a61:	48 83 c0 18          	add    rax,0x18
   140008a65:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008a69:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a6c:	25 ff ff 0f 00       	and    eax,0xfffff
   140008a71:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a74:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a77:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008a7c:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008a7f:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a82:	c1 e8 14             	shr    eax,0x14
   140008a85:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140008a88:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008a8c:	74 0b                	je     140008a99 <__d2b_D2A+0x7d>
   140008a8e:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   140008a91:	0d 00 00 10 00       	or     eax,0x100000
   140008a96:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a99:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140008a9c:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008a9f:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008aa2:	85 c0                	test   eax,eax
   140008aa4:	74 7b                	je     140008b21 <__d2b_D2A+0x105>
   140008aa6:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   140008aaa:	48 89 c1             	mov    rcx,rax
   140008aad:	e8 26 f2 ff ff       	call   140007cd8 <__lo0bits_D2A>
   140008ab2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008ab5:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008ab9:	74 2b                	je     140008ae6 <__d2b_D2A+0xca>
   140008abb:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008abe:	b8 20 00 00 00       	mov    eax,0x20
   140008ac3:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008ac6:	89 c1                	mov    ecx,eax
   140008ac8:	d3 e2                	shl    edx,cl
   140008aca:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008acd:	09 c2                	or     edx,eax
   140008acf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008ad3:	89 10                	mov    DWORD PTR [rax],edx
   140008ad5:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008ad8:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008adb:	89 c1                	mov    ecx,eax
   140008add:	d3 ea                	shr    edx,cl
   140008adf:	89 d0                	mov    eax,edx
   140008ae1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008ae4:	eb 09                	jmp    140008aef <__d2b_D2A+0xd3>
   140008ae6:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008ae9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008aed:	89 10                	mov    DWORD PTR [rax],edx
   140008aef:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008af3:	48 83 c0 04          	add    rax,0x4
   140008af7:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008afa:	89 10                	mov    DWORD PTR [rax],edx
   140008afc:	8b 00                	mov    eax,DWORD PTR [rax]
   140008afe:	85 c0                	test   eax,eax
   140008b00:	74 07                	je     140008b09 <__d2b_D2A+0xed>
   140008b02:	ba 02 00 00 00       	mov    edx,0x2
   140008b07:	eb 05                	jmp    140008b0e <__d2b_D2A+0xf2>
   140008b09:	ba 01 00 00 00       	mov    edx,0x1
   140008b0e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b12:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008b15:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b19:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b1c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b1f:	eb 31                	jmp    140008b52 <__d2b_D2A+0x136>
   140008b21:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008b25:	48 89 c1             	mov    rcx,rax
   140008b28:	e8 ab f1 ff ff       	call   140007cd8 <__lo0bits_D2A>
   140008b2d:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008b30:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b33:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b37:	89 10                	mov    DWORD PTR [rax],edx
   140008b39:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b3d:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008b44:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b48:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b4b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b4e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008b52:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008b56:	74 26                	je     140008b7e <__d2b_D2A+0x162>
   140008b58:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b5b:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008b61:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b64:	01 c2                	add    edx,eax
   140008b66:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b6a:	89 10                	mov    DWORD PTR [rax],edx
   140008b6c:	b8 35 00 00 00       	mov    eax,0x35
   140008b71:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008b74:	89 c2                	mov    edx,eax
   140008b76:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b7a:	89 10                	mov    DWORD PTR [rax],edx
   140008b7c:	eb 43                	jmp    140008bc1 <__d2b_D2A+0x1a5>
   140008b7e:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b81:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008b87:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b8a:	01 c2                	add    edx,eax
   140008b8c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b90:	89 10                	mov    DWORD PTR [rax],edx
   140008b92:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b95:	c1 e0 05             	shl    eax,0x5
   140008b98:	89 c3                	mov    ebx,eax
   140008b9a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b9d:	48 98                	cdqe
   140008b9f:	48 c1 e0 02          	shl    rax,0x2
   140008ba3:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008ba7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008bab:	48 01 d0             	add    rax,rdx
   140008bae:	8b 00                	mov    eax,DWORD PTR [rax]
   140008bb0:	89 c1                	mov    ecx,eax
   140008bb2:	e8 56 f1 ff ff       	call   140007d0d <__hi0bits_D2A>
   140008bb7:	29 c3                	sub    ebx,eax
   140008bb9:	89 da                	mov    edx,ebx
   140008bbb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008bbf:	89 10                	mov    DWORD PTR [rax],edx
   140008bc1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008bc5:	48 83 c4 58          	add    rsp,0x58
   140008bc9:	5b                   	pop    rbx
   140008bca:	5d                   	pop    rbp
   140008bcb:	c3                   	ret

0000000140008bcc <__strcp_D2A>:
   140008bcc:	55                   	push   rbp
   140008bcd:	48 89 e5             	mov    rbp,rsp
   140008bd0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008bd4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008bd8:	eb 05                	jmp    140008bdf <__strcp_D2A+0x13>
   140008bda:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008bdf:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008be3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008be7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008beb:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008bee:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008bf2:	88 10                	mov    BYTE PTR [rax],dl
   140008bf4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008bf8:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008bfb:	84 c0                	test   al,al
   140008bfd:	75 db                	jne    140008bda <__strcp_D2A+0xe>
   140008bff:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008c03:	5d                   	pop    rbp
   140008c04:	c3                   	ret
   140008c05:	90                   	nop
   140008c06:	90                   	nop
   140008c07:	90                   	nop
   140008c08:	90                   	nop
   140008c09:	90                   	nop
   140008c0a:	90                   	nop
   140008c0b:	90                   	nop
   140008c0c:	90                   	nop
   140008c0d:	90                   	nop
   140008c0e:	90                   	nop
   140008c0f:	90                   	nop

0000000140008c10 <__fpclassify>:
   140008c10:	55                   	push   rbp
   140008c11:	48 89 e5             	mov    rbp,rsp
   140008c14:	48 83 ec 10          	sub    rsp,0x10
   140008c18:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008c1d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008c22:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008c27:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008c2a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c2d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008c30:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008c33:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008c39:	09 d0                	or     eax,edx
   140008c3b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c3e:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008c45:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c48:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c4b:	85 c0                	test   eax,eax
   140008c4d:	75 07                	jne    140008c56 <__fpclassify+0x46>
   140008c4f:	b8 00 40 00 00       	mov    eax,0x4000
   140008c54:	eb 2f                	jmp    140008c85 <__fpclassify+0x75>
   140008c56:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c5a:	75 07                	jne    140008c63 <__fpclassify+0x53>
   140008c5c:	b8 00 44 00 00       	mov    eax,0x4400
   140008c61:	eb 22                	jmp    140008c85 <__fpclassify+0x75>
   140008c63:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008c6a:	75 14                	jne    140008c80 <__fpclassify+0x70>
   140008c6c:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008c70:	74 07                	je     140008c79 <__fpclassify+0x69>
   140008c72:	b8 00 01 00 00       	mov    eax,0x100
   140008c77:	eb 0c                	jmp    140008c85 <__fpclassify+0x75>
   140008c79:	b8 00 05 00 00       	mov    eax,0x500
   140008c7e:	eb 05                	jmp    140008c85 <__fpclassify+0x75>
   140008c80:	b8 00 04 00 00       	mov    eax,0x400
   140008c85:	48 83 c4 10          	add    rsp,0x10
   140008c89:	5d                   	pop    rbp
   140008c8a:	c3                   	ret
   140008c8b:	90                   	nop
   140008c8c:	90                   	nop
   140008c8d:	90                   	nop
   140008c8e:	90                   	nop
   140008c8f:	90                   	nop

0000000140008c90 <__fpclassifyl>:
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
   140008cae:	25 ff 7f 00 00       	and    eax,0x7fff
   140008cb3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cb6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008cba:	75 25                	jne    140008ce1 <__fpclassifyl+0x51>
   140008cbc:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008cbf:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008cc2:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008cc5:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008cc8:	85 c0                	test   eax,eax
   140008cca:	75 07                	jne    140008cd3 <__fpclassifyl+0x43>
   140008ccc:	b8 00 40 00 00       	mov    eax,0x4000
   140008cd1:	eb 3d                	jmp    140008d10 <__fpclassifyl+0x80>
   140008cd3:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008cd6:	85 c0                	test   eax,eax
   140008cd8:	78 31                	js     140008d0b <__fpclassifyl+0x7b>
   140008cda:	b8 00 44 00 00       	mov    eax,0x4400
   140008cdf:	eb 2f                	jmp    140008d10 <__fpclassifyl+0x80>
   140008ce1:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008ce8:	75 21                	jne    140008d0b <__fpclassifyl+0x7b>
   140008cea:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008ced:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008cf2:	89 c2                	mov    edx,eax
   140008cf4:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008cf7:	09 d0                	or     eax,edx
   140008cf9:	85 c0                	test   eax,eax
   140008cfb:	75 07                	jne    140008d04 <__fpclassifyl+0x74>
   140008cfd:	b8 00 05 00 00       	mov    eax,0x500
   140008d02:	eb 0c                	jmp    140008d10 <__fpclassifyl+0x80>
   140008d04:	b8 00 01 00 00       	mov    eax,0x100
   140008d09:	eb 05                	jmp    140008d10 <__fpclassifyl+0x80>
   140008d0b:	b8 00 04 00 00       	mov    eax,0x400
   140008d10:	48 83 c4 38          	add    rsp,0x38
   140008d14:	5b                   	pop    rbx
   140008d15:	5d                   	pop    rbp
   140008d16:	c3                   	ret
   140008d17:	90                   	nop
   140008d18:	90                   	nop
   140008d19:	90                   	nop
   140008d1a:	90                   	nop
   140008d1b:	90                   	nop
   140008d1c:	90                   	nop
   140008d1d:	90                   	nop
   140008d1e:	90                   	nop
   140008d1f:	90                   	nop

0000000140008d20 <__isnan>:
   140008d20:	55                   	push   rbp
   140008d21:	48 89 e5             	mov    rbp,rsp
   140008d24:	48 83 ec 10          	sub    rsp,0x10
   140008d28:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008d2d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008d32:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008d37:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008d3a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d3d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008d40:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008d45:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d48:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d4b:	f7 d8                	neg    eax
   140008d4d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008d50:	c1 e8 1f             	shr    eax,0x1f
   140008d53:	89 c2                	mov    edx,eax
   140008d55:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d58:	09 d0                	or     eax,edx
   140008d5a:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d5d:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008d62:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008d65:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d68:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d6b:	c1 f8 1f             	sar    eax,0x1f
   140008d6e:	48 83 c4 10          	add    rsp,0x10
   140008d72:	5d                   	pop    rbp
   140008d73:	c3                   	ret
   140008d74:	90                   	nop
   140008d75:	90                   	nop
   140008d76:	90                   	nop
   140008d77:	90                   	nop
   140008d78:	90                   	nop
   140008d79:	90                   	nop
   140008d7a:	90                   	nop
   140008d7b:	90                   	nop
   140008d7c:	90                   	nop
   140008d7d:	90                   	nop
   140008d7e:	90                   	nop
   140008d7f:	90                   	nop

0000000140008d80 <__isnanl>:
   140008d80:	55                   	push   rbp
   140008d81:	53                   	push   rbx
   140008d82:	48 83 ec 38          	sub    rsp,0x38
   140008d86:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008d8b:	48 89 cb             	mov    rbx,rcx
   140008d8e:	db 2b                	fld    TBYTE PTR [rbx]
   140008d90:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008d93:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008d96:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008d99:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008d9d:	98                   	cwde
   140008d9e:	01 c0                	add    eax,eax
   140008da0:	25 ff ff 00 00       	and    eax,0xffff
   140008da5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008da8:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008dab:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008dae:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008db4:	09 d0                	or     eax,edx
   140008db6:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008db9:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008dbc:	f7 d8                	neg    eax
   140008dbe:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008dc1:	c1 e8 1f             	shr    eax,0x1f
   140008dc4:	89 c2                	mov    edx,eax
   140008dc6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008dc9:	09 d0                	or     eax,edx
   140008dcb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008dce:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008dd3:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008dd6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008dd9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008ddc:	c1 f8 10             	sar    eax,0x10
   140008ddf:	48 83 c4 38          	add    rsp,0x38
   140008de3:	5b                   	pop    rbx
   140008de4:	5d                   	pop    rbp
   140008de5:	c3                   	ret
   140008de6:	90                   	nop
   140008de7:	90                   	nop
   140008de8:	90                   	nop
   140008de9:	90                   	nop
   140008dea:	90                   	nop
   140008deb:	90                   	nop
   140008dec:	90                   	nop
   140008ded:	90                   	nop
   140008dee:	90                   	nop
   140008def:	90                   	nop

0000000140008df0 <wcsnlen>:
   140008df0:	55                   	push   rbp
   140008df1:	48 89 e5             	mov    rbp,rsp
   140008df4:	48 83 ec 10          	sub    rsp,0x10
   140008df8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008dfc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e00:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008e07:	00 
   140008e08:	eb 0a                	jmp    140008e14 <wcsnlen+0x24>
   140008e0a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e0f:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008e14:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e18:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e1c:	73 0c                	jae    140008e2a <wcsnlen+0x3a>
   140008e1e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e22:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008e25:	66 85 c0             	test   ax,ax
   140008e28:	75 e0                	jne    140008e0a <wcsnlen+0x1a>
   140008e2a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e2e:	48 83 c4 10          	add    rsp,0x10
   140008e32:	5d                   	pop    rbp
   140008e33:	c3                   	ret
   140008e34:	90                   	nop
   140008e35:	90                   	nop
   140008e36:	90                   	nop
   140008e37:	90                   	nop
   140008e38:	90                   	nop
   140008e39:	90                   	nop
   140008e3a:	90                   	nop
   140008e3b:	90                   	nop
   140008e3c:	90                   	nop
   140008e3d:	90                   	nop
   140008e3e:	90                   	nop
   140008e3f:	90                   	nop

0000000140008e40 <strnlen>:
   140008e40:	55                   	push   rbp
   140008e41:	48 89 e5             	mov    rbp,rsp
   140008e44:	48 83 ec 10          	sub    rsp,0x10
   140008e48:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e4c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e50:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e54:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e58:	eb 05                	jmp    140008e5f <strnlen+0x1f>
   140008e5a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e5f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e63:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e67:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e6b:	73 0b                	jae    140008e78 <strnlen+0x38>
   140008e6d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e71:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008e74:	84 c0                	test   al,al
   140008e76:	75 e2                	jne    140008e5a <strnlen+0x1a>
   140008e78:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e7c:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e80:	48 83 c4 10          	add    rsp,0x10
   140008e84:	5d                   	pop    rbp
   140008e85:	c3                   	ret
   140008e86:	90                   	nop
   140008e87:	90                   	nop
   140008e88:	90                   	nop
   140008e89:	90                   	nop
   140008e8a:	90                   	nop
   140008e8b:	90                   	nop
   140008e8c:	90                   	nop
   140008e8d:	90                   	nop
   140008e8e:	90                   	nop
   140008e8f:	90                   	nop

0000000140008e90 <_initterm_e>:
   140008e90:	55                   	push   rbp
   140008e91:	48 89 e5             	mov    rbp,rsp
   140008e94:	48 83 ec 30          	sub    rsp,0x30
   140008e98:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e9c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008ea0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ea4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008ea8:	eb 29                	jmp    140008ed3 <_initterm_e+0x43>
   140008eaa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008eae:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008eb1:	48 85 c0             	test   rax,rax
   140008eb4:	74 17                	je     140008ecd <_initterm_e+0x3d>
   140008eb6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008eba:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ebd:	ff d0                	call   rax
   140008ebf:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008ec2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008ec6:	74 06                	je     140008ece <_initterm_e+0x3e>
   140008ec8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008ecb:	eb 15                	jmp    140008ee2 <_initterm_e+0x52>
   140008ecd:	90                   	nop
   140008ece:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008ed3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008ed7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008edb:	72 cd                	jb     140008eaa <_initterm_e+0x1a>
   140008edd:	b8 00 00 00 00       	mov    eax,0x0
   140008ee2:	48 83 c4 30          	add    rsp,0x30
   140008ee6:	5d                   	pop    rbp
   140008ee7:	c3                   	ret
   140008ee8:	90                   	nop
   140008ee9:	90                   	nop
   140008eea:	90                   	nop
   140008eeb:	90                   	nop
   140008eec:	90                   	nop
   140008eed:	90                   	nop
   140008eee:	90                   	nop
   140008eef:	90                   	nop

0000000140008ef0 <__p__fmode>:
   140008ef0:	55                   	push   rbp
   140008ef1:	48 89 e5             	mov    rbp,rsp
   140008ef4:	48 8b 05 05 27 00 00 	mov    rax,QWORD PTR [rip+0x2705]        # 14000b600 <.refptr.__imp__fmode>
   140008efb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008efe:	5d                   	pop    rbp
   140008eff:	c3                   	ret

0000000140008f00 <__p__commode>:
   140008f00:	55                   	push   rbp
   140008f01:	48 89 e5             	mov    rbp,rsp
   140008f04:	48 8b 05 e5 26 00 00 	mov    rax,QWORD PTR [rip+0x26e5]        # 14000b5f0 <.refptr.__imp__commode>
   140008f0b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f0e:	5d                   	pop    rbp
   140008f0f:	c3                   	ret

0000000140008f10 <__p___initenv>:
   140008f10:	55                   	push   rbp
   140008f11:	48 89 e5             	mov    rbp,rsp
   140008f14:	48 8b 05 c5 26 00 00 	mov    rax,QWORD PTR [rip+0x26c5]        # 14000b5e0 <.refptr.__imp___initenv>
   140008f1b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f1e:	5d                   	pop    rbp
   140008f1f:	c3                   	ret

0000000140008f20 <_lock_file>:
   140008f20:	55                   	push   rbp
   140008f21:	48 89 e5             	mov    rbp,rsp
   140008f24:	48 83 ec 20          	sub    rsp,0x20
   140008f28:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f2c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f31:	e8 6a 01 00 00       	call   1400090a0 <__acrt_iob_func>
   140008f36:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008f3a:	72 52                	jb     140008f8e <_lock_file+0x6e>
   140008f3c:	b9 13 00 00 00       	mov    ecx,0x13
   140008f41:	e8 5a 01 00 00       	call   1400090a0 <__acrt_iob_func>
   140008f46:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f4a:	72 42                	jb     140008f8e <_lock_file+0x6e>
   140008f4c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f51:	e8 4a 01 00 00       	call   1400090a0 <__acrt_iob_func>
   140008f56:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f5a:	48 29 c2             	sub    rdx,rax
   140008f5d:	48 c1 fa 04          	sar    rdx,0x4
   140008f61:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008f68:	aa aa aa 
   140008f6b:	48 0f af c2          	imul   rax,rdx
   140008f6f:	83 c0 10             	add    eax,0x10
   140008f72:	89 c1                	mov    ecx,eax
   140008f74:	e8 1f 07 00 00       	call   140009698 <_lock>
   140008f79:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f7d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008f80:	80 cc 80             	or     ah,0x80
   140008f83:	89 c2                	mov    edx,eax
   140008f85:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f89:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008f8c:	eb 15                	jmp    140008fa3 <_lock_file+0x83>
   140008f8e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f92:	48 83 c0 30          	add    rax,0x30
   140008f96:	48 89 c1             	mov    rcx,rax
   140008f99:	48 8b 05 50 72 00 00 	mov    rax,QWORD PTR [rip+0x7250]        # 1400101f0 <__imp_EnterCriticalSection>
   140008fa0:	ff d0                	call   rax
   140008fa2:	90                   	nop
   140008fa3:	90                   	nop
   140008fa4:	48 83 c4 20          	add    rsp,0x20
   140008fa8:	5d                   	pop    rbp
   140008fa9:	c3                   	ret

0000000140008faa <_unlock_file>:
   140008faa:	55                   	push   rbp
   140008fab:	48 89 e5             	mov    rbp,rsp
   140008fae:	48 83 ec 20          	sub    rsp,0x20
   140008fb2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008fb6:	b9 00 00 00 00       	mov    ecx,0x0
   140008fbb:	e8 e0 00 00 00       	call   1400090a0 <__acrt_iob_func>
   140008fc0:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008fc4:	72 52                	jb     140009018 <_unlock_file+0x6e>
   140008fc6:	b9 13 00 00 00       	mov    ecx,0x13
   140008fcb:	e8 d0 00 00 00       	call   1400090a0 <__acrt_iob_func>
   140008fd0:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008fd4:	72 42                	jb     140009018 <_unlock_file+0x6e>
   140008fd6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fda:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008fdd:	80 e4 7f             	and    ah,0x7f
   140008fe0:	89 c2                	mov    edx,eax
   140008fe2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fe6:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008fe9:	b9 00 00 00 00       	mov    ecx,0x0
   140008fee:	e8 ad 00 00 00       	call   1400090a0 <__acrt_iob_func>
   140008ff3:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008ff7:	48 29 c2             	sub    rdx,rax
   140008ffa:	48 c1 fa 04          	sar    rdx,0x4
   140008ffe:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140009005:	aa aa aa 
   140009008:	48 0f af c2          	imul   rax,rdx
   14000900c:	83 c0 10             	add    eax,0x10
   14000900f:	89 c1                	mov    ecx,eax
   140009011:	e8 8a 06 00 00       	call   1400096a0 <_unlock>
   140009016:	eb 15                	jmp    14000902d <_unlock_file+0x83>
   140009018:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000901c:	48 83 c0 30          	add    rax,0x30
   140009020:	48 89 c1             	mov    rcx,rax
   140009023:	48 8b 05 fe 71 00 00 	mov    rax,QWORD PTR [rip+0x71fe]        # 140010228 <__imp_LeaveCriticalSection>
   14000902a:	ff d0                	call   rax
   14000902c:	90                   	nop
   14000902d:	90                   	nop
   14000902e:	48 83 c4 20          	add    rsp,0x20
   140009032:	5d                   	pop    rbp
   140009033:	c3                   	ret
   140009034:	90                   	nop
   140009035:	90                   	nop
   140009036:	90                   	nop
   140009037:	90                   	nop
   140009038:	90                   	nop
   140009039:	90                   	nop
   14000903a:	90                   	nop
   14000903b:	90                   	nop
   14000903c:	90                   	nop
   14000903d:	90                   	nop
   14000903e:	90                   	nop
   14000903f:	90                   	nop

0000000140009040 <_set_invalid_parameter_handler>:
   140009040:	55                   	push   rbp
   140009041:	48 89 e5             	mov    rbp,rsp
   140009044:	48 83 ec 10          	sub    rsp,0x10
   140009048:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000904c:	48 8d 05 2d 6b 00 00 	lea    rax,[rip+0x6b2d]        # 14000fb80 <handler>
   140009053:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140009057:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000905b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000905f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140009063:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140009067:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000906a:	48 89 d0             	mov    rax,rdx
   14000906d:	48 83 c4 10          	add    rsp,0x10
   140009071:	5d                   	pop    rbp
   140009072:	c3                   	ret

0000000140009073 <_get_invalid_parameter_handler>:
   140009073:	55                   	push   rbp
   140009074:	48 89 e5             	mov    rbp,rsp
   140009077:	48 8b 05 02 6b 00 00 	mov    rax,QWORD PTR [rip+0x6b02]        # 14000fb80 <handler>
   14000907e:	5d                   	pop    rbp
   14000907f:	c3                   	ret

0000000140009080 <_configthreadlocale>:
   140009080:	55                   	push   rbp
   140009081:	48 89 e5             	mov    rbp,rsp
   140009084:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140009087:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000908b:	75 07                	jne    140009094 <_configthreadlocale+0x14>
   14000908d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140009092:	eb 05                	jmp    140009099 <_configthreadlocale+0x19>
   140009094:	b8 02 00 00 00       	mov    eax,0x2
   140009099:	5d                   	pop    rbp
   14000909a:	c3                   	ret
   14000909b:	90                   	nop
   14000909c:	90                   	nop
   14000909d:	90                   	nop
   14000909e:	90                   	nop
   14000909f:	90                   	nop

00000001400090a0 <__acrt_iob_func>:
   1400090a0:	55                   	push   rbp
   1400090a1:	48 89 e5             	mov    rbp,rsp
   1400090a4:	48 83 ec 20          	sub    rsp,0x20
   1400090a8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400090ab:	e8 b0 05 00 00       	call   140009660 <__iob_func>
   1400090b0:	48 89 c1             	mov    rcx,rax
   1400090b3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400090b6:	48 89 d0             	mov    rax,rdx
   1400090b9:	48 01 c0             	add    rax,rax
   1400090bc:	48 01 d0             	add    rax,rdx
   1400090bf:	48 c1 e0 04          	shl    rax,0x4
   1400090c3:	48 01 c8             	add    rax,rcx
   1400090c6:	48 83 c4 20          	add    rsp,0x20
   1400090ca:	5d                   	pop    rbp
   1400090cb:	c3                   	ret
   1400090cc:	90                   	nop
   1400090cd:	90                   	nop
   1400090ce:	90                   	nop
   1400090cf:	90                   	nop

00000001400090d0 <wcrtomb>:
   1400090d0:	55                   	push   rbp
   1400090d1:	48 89 e5             	mov    rbp,rsp
   1400090d4:	48 83 ec 40          	sub    rsp,0x40
   1400090d8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090dc:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400090e0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090e4:	e8 5f 05 00 00       	call   140009648 <___lc_codepage_func>
   1400090e9:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400090ec:	e8 5f 05 00 00       	call   140009650 <___mb_cur_max_func>
   1400090f1:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400090f4:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   1400090f8:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   1400090fc:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   140009100:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009104:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140009107:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   14000910b:	48 89 c1             	mov    rcx,rax
   14000910e:	e8 7d 00 00 00       	call   140009190 <__mingw_wcrtomb_cp>
   140009113:	48 83 c4 40          	add    rsp,0x40
   140009117:	5d                   	pop    rbp
   140009118:	c3                   	ret
   140009119:	90                   	nop
   14000911a:	90                   	nop
   14000911b:	90                   	nop
   14000911c:	90                   	nop
   14000911d:	90                   	nop
   14000911e:	90                   	nop
   14000911f:	90                   	nop

0000000140009120 <mbrtowc>:
   140009120:	55                   	push   rbp
   140009121:	48 89 e5             	mov    rbp,rsp
   140009124:	48 83 ec 40          	sub    rsp,0x40
   140009128:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000912c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009130:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009134:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009138:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   14000913d:	75 0b                	jne    14000914a <mbrtowc+0x2a>
   14000913f:	48 8d 05 4a 6a 00 00 	lea    rax,[rip+0x6a4a]        # 14000fb90 <state_mbrtowc.0>
   140009146:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000914a:	e8 f9 04 00 00       	call   140009648 <___lc_codepage_func>
   14000914f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009152:	e8 f9 04 00 00       	call   140009650 <___mb_cur_max_func>
   140009157:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000915a:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   14000915e:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140009162:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140009166:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000916a:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   14000916d:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   140009171:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   140009174:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   140009178:	48 89 c1             	mov    rcx,rax
   14000917b:	e8 70 01 00 00       	call   1400092f0 <__mingw_mbrtowc_cp>
   140009180:	48 83 c4 40          	add    rsp,0x40
   140009184:	5d                   	pop    rbp
   140009185:	c3                   	ret
   140009186:	90                   	nop
   140009187:	90                   	nop
   140009188:	90                   	nop
   140009189:	90                   	nop
   14000918a:	90                   	nop
   14000918b:	90                   	nop
   14000918c:	90                   	nop
   14000918d:	90                   	nop
   14000918e:	90                   	nop
   14000918f:	90                   	nop

0000000140009190 <__mingw_wcrtomb_cp>:
   140009190:	55                   	push   rbp
   140009191:	48 89 e5             	mov    rbp,rsp
   140009194:	48 83 ec 50          	sub    rsp,0x50
   140009198:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000919c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400091a0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400091a4:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   1400091a8:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091ad:	75 1b                	jne    1400091ca <__mingw_wcrtomb_cp+0x3a>
   1400091af:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400091b4:	74 0a                	je     1400091c0 <__mingw_wcrtomb_cp+0x30>
   1400091b6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400091ba:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400091c0:	b8 01 00 00 00       	mov    eax,0x1
   1400091c5:	e9 17 01 00 00       	jmp    1400092e1 <__mingw_wcrtomb_cp+0x151>
   1400091ca:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400091cf:	74 21                	je     1400091f2 <__mingw_wcrtomb_cp+0x62>
   1400091d1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400091d5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400091d7:	85 c0                	test   eax,eax
   1400091d9:	74 17                	je     1400091f2 <__mingw_wcrtomb_cp+0x62>
   1400091db:	e8 a8 04 00 00       	call   140009688 <_errno>
   1400091e0:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   1400091e6:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400091ed:	e9 ef 00 00 00       	jmp    1400092e1 <__mingw_wcrtomb_cp+0x151>
   1400091f2:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   1400091f6:	66 85 c0             	test   ax,ax
   1400091f9:	75 18                	jne    140009213 <__mingw_wcrtomb_cp+0x83>
   1400091fb:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009200:	74 07                	je     140009209 <__mingw_wcrtomb_cp+0x79>
   140009202:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009206:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140009209:	b8 01 00 00 00       	mov    eax,0x1
   14000920e:	e9 ce 00 00 00       	jmp    1400092e1 <__mingw_wcrtomb_cp+0x151>
   140009213:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   140009217:	75 2b                	jne    140009244 <__mingw_wcrtomb_cp+0xb4>
   140009219:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   14000921d:	66 3d ff 00          	cmp    ax,0xff
   140009221:	0f 87 a4 00 00 00    	ja     1400092cb <__mingw_wcrtomb_cp+0x13b>
   140009227:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000922c:	74 0c                	je     14000923a <__mingw_wcrtomb_cp+0xaa>
   14000922e:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009232:	89 c2                	mov    edx,eax
   140009234:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009238:	88 10                	mov    BYTE PTR [rax],dl
   14000923a:	b8 01 00 00 00       	mov    eax,0x1
   14000923f:	e9 9d 00 00 00       	jmp    1400092e1 <__mingw_wcrtomb_cp+0x151>
   140009244:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000924b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   140009251:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   140009255:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140009258:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   14000925c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140009261:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   140009268:	00 00 
   14000926a:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000926d:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140009271:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009275:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000927a:	41 b9 01 00 00 00    	mov    r9d,0x1
   140009280:	49 89 c8             	mov    r8,rcx
   140009283:	ba 00 00 00 00       	mov    edx,0x0
   140009288:	89 c1                	mov    ecx,eax
   14000928a:	48 8b 05 d7 6f 00 00 	mov    rax,QWORD PTR [rip+0x6fd7]        # 140010268 <__imp_WideCharToMultiByte>
   140009291:	ff d0                	call   rax
   140009293:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009296:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000929a:	74 32                	je     1400092ce <__mingw_wcrtomb_cp+0x13e>
   14000929c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000929f:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   1400092a2:	7f 2a                	jg     1400092ce <__mingw_wcrtomb_cp+0x13e>
   1400092a4:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400092a7:	85 c0                	test   eax,eax
   1400092a9:	75 23                	jne    1400092ce <__mingw_wcrtomb_cp+0x13e>
   1400092ab:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092ae:	48 63 c8             	movsxd rcx,eax
   1400092b1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400092b5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400092b9:	49 89 c8             	mov    r8,rcx
   1400092bc:	48 89 c1             	mov    rcx,rax
   1400092bf:	e8 34 04 00 00       	call   1400096f8 <memcpy>
   1400092c4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092c7:	48 98                	cdqe
   1400092c9:	eb 16                	jmp    1400092e1 <__mingw_wcrtomb_cp+0x151>
   1400092cb:	90                   	nop
   1400092cc:	eb 01                	jmp    1400092cf <__mingw_wcrtomb_cp+0x13f>
   1400092ce:	90                   	nop
   1400092cf:	e8 b4 03 00 00       	call   140009688 <_errno>
   1400092d4:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400092da:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400092e1:	48 83 c4 50          	add    rsp,0x50
   1400092e5:	5d                   	pop    rbp
   1400092e6:	c3                   	ret
   1400092e7:	90                   	nop
   1400092e8:	90                   	nop
   1400092e9:	90                   	nop
   1400092ea:	90                   	nop
   1400092eb:	90                   	nop
   1400092ec:	90                   	nop
   1400092ed:	90                   	nop
   1400092ee:	90                   	nop
   1400092ef:	90                   	nop

00000001400092f0 <__mingw_mbrtowc_cp>:
   1400092f0:	55                   	push   rbp
   1400092f1:	48 89 e5             	mov    rbp,rsp
   1400092f4:	48 83 ec 50          	sub    rsp,0x50
   1400092f8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400092fc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009300:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009304:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009308:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   14000930d:	75 1b                	jne    14000932a <__mingw_mbrtowc_cp+0x3a>
   14000930f:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   140009316:	00 
   140009317:	48 8d 05 02 22 00 00 	lea    rax,[rip+0x2202]        # 14000b520 <.rdata>
   14000931e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140009322:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   140009329:	00 
   14000932a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000932e:	8b 00                	mov    eax,DWORD PTR [rax]
   140009330:	3d ff 00 00 00       	cmp    eax,0xff
   140009335:	0f 87 b9 01 00 00    	ja     1400094f4 <__mingw_mbrtowc_cp+0x204>
   14000933b:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009340:	75 0c                	jne    14000934e <__mingw_mbrtowc_cp+0x5e>
   140009342:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009349:	e9 bc 01 00 00       	jmp    14000950a <__mingw_mbrtowc_cp+0x21a>
   14000934e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009352:	8b 00                	mov    eax,DWORD PTR [rax]
   140009354:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140009357:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   14000935b:	75 0c                	jne    140009369 <__mingw_mbrtowc_cp+0x79>
   14000935d:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009361:	84 c0                	test   al,al
   140009363:	0f 85 8e 01 00 00    	jne    1400094f7 <__mingw_mbrtowc_cp+0x207>
   140009369:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   14000936d:	75 2c                	jne    14000939b <__mingw_mbrtowc_cp+0xab>
   14000936f:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009374:	74 11                	je     140009387 <__mingw_mbrtowc_cp+0x97>
   140009376:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000937a:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000937d:	0f b6 d0             	movzx  edx,al
   140009380:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009384:	66 89 10             	mov    WORD PTR [rax],dx
   140009387:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000938b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000938e:	84 c0                	test   al,al
   140009390:	0f 95 c0             	setne  al
   140009393:	0f b6 c0             	movzx  eax,al
   140009396:	e9 6f 01 00 00       	jmp    14000950a <__mingw_mbrtowc_cp+0x21a>
   14000939b:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400093a2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400093a9:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400093ad:	84 c0                	test   al,al
   1400093af:	74 1a                	je     1400093cb <__mingw_mbrtowc_cp+0xdb>
   1400093b1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093b5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093b8:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   1400093bb:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400093c2:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400093c9:	eb 73                	jmp    14000943e <__mingw_mbrtowc_cp+0x14e>
   1400093cb:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   1400093cf:	75 5c                	jne    14000942d <__mingw_mbrtowc_cp+0x13d>
   1400093d1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093d5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093d8:	0f b6 c0             	movzx  eax,al
   1400093db:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   1400093de:	89 c1                	mov    ecx,eax
   1400093e0:	e8 ab 01 00 00       	call   140009590 <__mingw_isleadbyte_cp>
   1400093e5:	85 c0                	test   eax,eax
   1400093e7:	74 44                	je     14000942d <__mingw_mbrtowc_cp+0x13d>
   1400093e9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093ed:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093f0:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   1400093f3:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   1400093f8:	77 15                	ja     14000940f <__mingw_mbrtowc_cp+0x11f>
   1400093fa:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400093fd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009401:	89 10                	mov    DWORD PTR [rax],edx
   140009403:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   14000940a:	e9 fb 00 00 00       	jmp    14000950a <__mingw_mbrtowc_cp+0x21a>
   14000940f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009413:	48 83 c0 01          	add    rax,0x1
   140009417:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000941a:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000941d:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140009424:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   14000942b:	eb 11                	jmp    14000943e <__mingw_mbrtowc_cp+0x14e>
   14000942d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009431:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009434:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009437:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000943e:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009442:	84 c0                	test   al,al
   140009444:	75 24                	jne    14000946a <__mingw_mbrtowc_cp+0x17a>
   140009446:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000944b:	74 09                	je     140009456 <__mingw_mbrtowc_cp+0x166>
   14000944d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009451:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   140009456:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000945a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009460:	b8 00 00 00 00       	mov    eax,0x0
   140009465:	e9 a0 00 00 00       	jmp    14000950a <__mingw_mbrtowc_cp+0x21a>
   14000946a:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   14000946e:	75 08                	jne    140009478 <__mingw_mbrtowc_cp+0x188>
   140009470:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   140009474:	84 c0                	test   al,al
   140009476:	74 64                	je     1400094dc <__mingw_mbrtowc_cp+0x1ec>
   140009478:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   14000947e:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   140009482:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   140009486:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   140009489:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   140009490:	00 
   140009491:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   140009495:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000949a:	45 89 c1             	mov    r9d,r8d
   14000949d:	49 89 c8             	mov    r8,rcx
   1400094a0:	ba 08 00 00 00       	mov    edx,0x8
   1400094a5:	89 c1                	mov    ecx,eax
   1400094a7:	48 8b 05 8a 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d8a]        # 140010238 <__imp_MultiByteToWideChar>
   1400094ae:	ff d0                	call   rax
   1400094b0:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400094b3:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   1400094b7:	75 26                	jne    1400094df <__mingw_mbrtowc_cp+0x1ef>
   1400094b9:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400094be:	74 0b                	je     1400094cb <__mingw_mbrtowc_cp+0x1db>
   1400094c0:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   1400094c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400094c8:	66 89 10             	mov    WORD PTR [rax],dx
   1400094cb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400094cf:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400094d5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400094d8:	48 98                	cdqe
   1400094da:	eb 2e                	jmp    14000950a <__mingw_mbrtowc_cp+0x21a>
   1400094dc:	90                   	nop
   1400094dd:	eb 01                	jmp    1400094e0 <__mingw_mbrtowc_cp+0x1f0>
   1400094df:	90                   	nop
   1400094e0:	e8 a3 01 00 00       	call   140009688 <_errno>
   1400094e5:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400094eb:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400094f2:	eb 16                	jmp    14000950a <__mingw_mbrtowc_cp+0x21a>
   1400094f4:	90                   	nop
   1400094f5:	eb 01                	jmp    1400094f8 <__mingw_mbrtowc_cp+0x208>
   1400094f7:	90                   	nop
   1400094f8:	e8 8b 01 00 00       	call   140009688 <_errno>
   1400094fd:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009503:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000950a:	48 83 c4 50          	add    rsp,0x50
   14000950e:	5d                   	pop    rbp
   14000950f:	c3                   	ret

0000000140009510 <fallback_IsDBCSLeadByteEx>:
   140009510:	55                   	push   rbp
   140009511:	48 89 e5             	mov    rbp,rsp
   140009514:	48 83 ec 40          	sub    rsp,0x40
   140009518:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000951b:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   14000951e:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   140009522:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009525:	89 c1                	mov    ecx,eax
   140009527:	48 8b 05 d2 6c 00 00 	mov    rax,QWORD PTR [rip+0x6cd2]        # 140010200 <__imp_GetCPInfo>
   14000952e:	ff d0                	call   rax
   140009530:	85 c0                	test   eax,eax
   140009532:	74 51                	je     140009585 <fallback_IsDBCSLeadByteEx+0x75>
   140009534:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140009537:	83 f8 02             	cmp    eax,0x2
   14000953a:	75 49                	jne    140009585 <fallback_IsDBCSLeadByteEx+0x75>
   14000953c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009543:	eb 2c                	jmp    140009571 <fallback_IsDBCSLeadByteEx+0x61>
   140009545:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009548:	48 98                	cdqe
   14000954a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000954f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   140009552:	72 19                	jb     14000956d <fallback_IsDBCSLeadByteEx+0x5d>
   140009554:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009557:	83 c0 01             	add    eax,0x1
   14000955a:	48 98                	cdqe
   14000955c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009561:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   140009564:	72 07                	jb     14000956d <fallback_IsDBCSLeadByteEx+0x5d>
   140009566:	b8 01 00 00 00       	mov    eax,0x1
   14000956b:	eb 1d                	jmp    14000958a <fallback_IsDBCSLeadByteEx+0x7a>
   14000956d:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   140009571:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   140009575:	7f 0e                	jg     140009585 <fallback_IsDBCSLeadByteEx+0x75>
   140009577:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000957a:	48 98                	cdqe
   14000957c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009581:	84 c0                	test   al,al
   140009583:	75 c0                	jne    140009545 <fallback_IsDBCSLeadByteEx+0x35>
   140009585:	b8 00 00 00 00       	mov    eax,0x0
   14000958a:	48 83 c4 40          	add    rsp,0x40
   14000958e:	5d                   	pop    rbp
   14000958f:	c3                   	ret

0000000140009590 <__mingw_isleadbyte_cp>:
   140009590:	55                   	push   rbp
   140009591:	48 89 e5             	mov    rbp,rsp
   140009594:	48 83 ec 40          	sub    rsp,0x40
   140009598:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000959b:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000959e:	48 8b 05 fb 65 00 00 	mov    rax,QWORD PTR [rip+0x65fb]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400095a5:	48 85 c0             	test   rax,rax
   1400095a8:	75 71                	jne    14000961b <__mingw_isleadbyte_cp+0x8b>
   1400095aa:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400095b1:	00 
   1400095b2:	48 8d 05 77 1f 00 00 	lea    rax,[rip+0x1f77]        # 14000b530 <.rdata>
   1400095b9:	48 89 c1             	mov    rcx,rax
   1400095bc:	48 8b 05 4d 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c4d]        # 140010210 <__imp_GetModuleHandleA>
   1400095c3:	ff d0                	call   rax
   1400095c5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400095c9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400095ce:	74 1b                	je     1400095eb <__mingw_isleadbyte_cp+0x5b>
   1400095d0:	48 8d 15 66 1f 00 00 	lea    rdx,[rip+0x1f66]        # 14000b53d <.rdata+0xd>
   1400095d7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400095db:	48 89 c1             	mov    rcx,rax
   1400095de:	48 8b 05 33 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c33]        # 140010218 <__imp_GetProcAddress>
   1400095e5:	ff d0                	call   rax
   1400095e7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400095eb:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400095f0:	75 0b                	jne    1400095fd <__mingw_isleadbyte_cp+0x6d>
   1400095f2:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 140009510 <fallback_IsDBCSLeadByteEx>
   1400095f9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400095fd:	48 8d 05 9c 65 00 00 	lea    rax,[rip+0x659c]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009604:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140009608:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000960c:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140009610:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140009614:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140009618:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000961b:	4c 8b 05 7e 65 00 00 	mov    r8,QWORD PTR [rip+0x657e]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009622:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009625:	0f b6 d0             	movzx  edx,al
   140009628:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000962b:	89 c1                	mov    ecx,eax
   14000962d:	41 ff d0             	call   r8
   140009630:	48 83 c4 40          	add    rsp,0x40
   140009634:	5d                   	pop    rbp
   140009635:	c3                   	ret
   140009636:	90                   	nop
   140009637:	90                   	nop
   140009638:	90                   	nop
   140009639:	90                   	nop
   14000963a:	90                   	nop
   14000963b:	90                   	nop
   14000963c:	90                   	nop
   14000963d:	90                   	nop
   14000963e:	90                   	nop
   14000963f:	90                   	nop

0000000140009640 <__C_specific_handler>:
   140009640:	ff 25 32 6c 00 00    	jmp    QWORD PTR [rip+0x6c32]        # 140010278 <__imp___C_specific_handler>
   140009646:	90                   	nop
   140009647:	90                   	nop

0000000140009648 <___lc_codepage_func>:
   140009648:	ff 25 32 6c 00 00    	jmp    QWORD PTR [rip+0x6c32]        # 140010280 <__imp____lc_codepage_func>
   14000964e:	90                   	nop
   14000964f:	90                   	nop

0000000140009650 <___mb_cur_max_func>:
   140009650:	ff 25 32 6c 00 00    	jmp    QWORD PTR [rip+0x6c32]        # 140010288 <__imp____mb_cur_max_func>
   140009656:	90                   	nop
   140009657:	90                   	nop

0000000140009658 <__getmainargs>:
   140009658:	ff 25 32 6c 00 00    	jmp    QWORD PTR [rip+0x6c32]        # 140010290 <__imp___getmainargs>
   14000965e:	90                   	nop
   14000965f:	90                   	nop

0000000140009660 <__iob_func>:
   140009660:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 1400102a0 <__imp___iob_func>
   140009666:	90                   	nop
   140009667:	90                   	nop

0000000140009668 <__set_app_type>:
   140009668:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 1400102a8 <__imp___set_app_type>
   14000966e:	90                   	nop
   14000966f:	90                   	nop

0000000140009670 <__setusermatherr>:
   140009670:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 1400102b0 <__imp___setusermatherr>
   140009676:	90                   	nop
   140009677:	90                   	nop

0000000140009678 <_amsg_exit>:
   140009678:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 1400102b8 <__imp__amsg_exit>
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <_cexit>:
   140009680:	ff 25 3a 6c 00 00    	jmp    QWORD PTR [rip+0x6c3a]        # 1400102c0 <__imp__cexit>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <_errno>:
   140009688:	ff 25 42 6c 00 00    	jmp    QWORD PTR [rip+0x6c42]        # 1400102d0 <__imp__errno>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <_initterm>:
   140009690:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 1400102e0 <__imp__initterm>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <_lock>:
   140009698:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 1400102e8 <__imp__lock>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <_unlock>:
   1400096a0:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 1400102f0 <__imp__unlock>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <_crt_atexit>:
   1400096a8:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 1400102f8 <__imp__crt_atexit>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <abort>:
   1400096b0:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010300 <__imp_abort>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <calloc>:
   1400096b8:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010308 <__imp_calloc>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <exit>:
   1400096c0:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010310 <__imp_exit>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <fflush>:
   1400096c8:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010318 <__imp_fflush>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <fprintf>:
   1400096d0:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010320 <__imp_fprintf>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <fputc>:
   1400096d8:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010328 <__imp_fputc>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <free>:
   1400096e0:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010330 <__imp_free>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop

00000001400096e8 <localeconv>:
   1400096e8:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010338 <__imp_localeconv>
   1400096ee:	90                   	nop
   1400096ef:	90                   	nop

00000001400096f0 <malloc>:
   1400096f0:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010340 <__imp_malloc>
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop

00000001400096f8 <memcpy>:
   1400096f8:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010348 <__imp_memcpy>
   1400096fe:	90                   	nop
   1400096ff:	90                   	nop

0000000140009700 <setvbuf>:
   140009700:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010350 <__imp_setvbuf>
   140009706:	90                   	nop
   140009707:	90                   	nop

0000000140009708 <signal>:
   140009708:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010358 <__imp_signal>
   14000970e:	90                   	nop
   14000970f:	90                   	nop

0000000140009710 <strerror>:
   140009710:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010360 <__imp_strerror>
   140009716:	90                   	nop
   140009717:	90                   	nop

0000000140009718 <strlen>:
   140009718:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010368 <__imp_strlen>
   14000971e:	90                   	nop
   14000971f:	90                   	nop

0000000140009720 <strncmp>:
   140009720:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010370 <__imp_strncmp>
   140009726:	90                   	nop
   140009727:	90                   	nop

0000000140009728 <vfprintf>:
   140009728:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010378 <__imp_vfprintf>
   14000972e:	90                   	nop
   14000972f:	90                   	nop

0000000140009730 <wcslen>:
   140009730:	ff 25 4a 6c 00 00    	jmp    QWORD PTR [rip+0x6c4a]        # 140010380 <__imp_wcslen>
   140009736:	90                   	nop
   140009737:	90                   	nop
   140009738:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000973f:	00 

0000000140009740 <WideCharToMultiByte>:
   140009740:	ff 25 22 6b 00 00    	jmp    QWORD PTR [rip+0x6b22]        # 140010268 <__imp_WideCharToMultiByte>
   140009746:	90                   	nop
   140009747:	90                   	nop

0000000140009748 <VirtualQuery>:
   140009748:	ff 25 12 6b 00 00    	jmp    QWORD PTR [rip+0x6b12]        # 140010260 <__imp_VirtualQuery>
   14000974e:	90                   	nop
   14000974f:	90                   	nop

0000000140009750 <VirtualProtect>:
   140009750:	ff 25 02 6b 00 00    	jmp    QWORD PTR [rip+0x6b02]        # 140010258 <__imp_VirtualProtect>
   140009756:	90                   	nop
   140009757:	90                   	nop

0000000140009758 <TlsGetValue>:
   140009758:	ff 25 f2 6a 00 00    	jmp    QWORD PTR [rip+0x6af2]        # 140010250 <__imp_TlsGetValue>
   14000975e:	90                   	nop
   14000975f:	90                   	nop

0000000140009760 <Sleep>:
   140009760:	ff 25 e2 6a 00 00    	jmp    QWORD PTR [rip+0x6ae2]        # 140010248 <__imp_Sleep>
   140009766:	90                   	nop
   140009767:	90                   	nop

0000000140009768 <SetUnhandledExceptionFilter>:
   140009768:	ff 25 d2 6a 00 00    	jmp    QWORD PTR [rip+0x6ad2]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   14000976e:	90                   	nop
   14000976f:	90                   	nop

0000000140009770 <MultiByteToWideChar>:
   140009770:	ff 25 c2 6a 00 00    	jmp    QWORD PTR [rip+0x6ac2]        # 140010238 <__imp_MultiByteToWideChar>
   140009776:	90                   	nop
   140009777:	90                   	nop

0000000140009778 <LoadLibraryA>:
   140009778:	ff 25 b2 6a 00 00    	jmp    QWORD PTR [rip+0x6ab2]        # 140010230 <__imp_LoadLibraryA>
   14000977e:	90                   	nop
   14000977f:	90                   	nop

0000000140009780 <LeaveCriticalSection>:
   140009780:	ff 25 a2 6a 00 00    	jmp    QWORD PTR [rip+0x6aa2]        # 140010228 <__imp_LeaveCriticalSection>
   140009786:	90                   	nop
   140009787:	90                   	nop

0000000140009788 <InitializeCriticalSection>:
   140009788:	ff 25 92 6a 00 00    	jmp    QWORD PTR [rip+0x6a92]        # 140010220 <__imp_InitializeCriticalSection>
   14000978e:	90                   	nop
   14000978f:	90                   	nop

0000000140009790 <GetProcAddress>:
   140009790:	ff 25 82 6a 00 00    	jmp    QWORD PTR [rip+0x6a82]        # 140010218 <__imp_GetProcAddress>
   140009796:	90                   	nop
   140009797:	90                   	nop

0000000140009798 <GetModuleHandleA>:
   140009798:	ff 25 72 6a 00 00    	jmp    QWORD PTR [rip+0x6a72]        # 140010210 <__imp_GetModuleHandleA>
   14000979e:	90                   	nop
   14000979f:	90                   	nop

00000001400097a0 <GetLastError>:
   1400097a0:	ff 25 62 6a 00 00    	jmp    QWORD PTR [rip+0x6a62]        # 140010208 <__imp_GetLastError>
   1400097a6:	90                   	nop
   1400097a7:	90                   	nop

00000001400097a8 <GetCPInfo>:
   1400097a8:	ff 25 52 6a 00 00    	jmp    QWORD PTR [rip+0x6a52]        # 140010200 <__imp_GetCPInfo>
   1400097ae:	90                   	nop
   1400097af:	90                   	nop

00000001400097b0 <FreeLibrary>:
   1400097b0:	ff 25 42 6a 00 00    	jmp    QWORD PTR [rip+0x6a42]        # 1400101f8 <__imp_FreeLibrary>
   1400097b6:	90                   	nop
   1400097b7:	90                   	nop

00000001400097b8 <EnterCriticalSection>:
   1400097b8:	ff 25 32 6a 00 00    	jmp    QWORD PTR [rip+0x6a32]        # 1400101f0 <__imp_EnterCriticalSection>
   1400097be:	90                   	nop
   1400097bf:	90                   	nop

00000001400097c0 <DeleteCriticalSection>:
   1400097c0:	ff 25 22 6a 00 00    	jmp    QWORD PTR [rip+0x6a22]        # 1400101e8 <__IAT_start__>
   1400097c6:	90                   	nop
   1400097c7:	90                   	nop
   1400097c8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   1400097cf:	00 

00000001400097d0 <register_frame_ctor>:
   1400097d0:	e9 9b 7e ff ff       	jmp    140001670 <__gcc_register_frame>
   1400097d5:	90                   	nop
   1400097d6:	90                   	nop
   1400097d7:	90                   	nop
   1400097d8:	90                   	nop
   1400097d9:	90                   	nop
   1400097da:	90                   	nop
   1400097db:	90                   	nop
   1400097dc:	90                   	nop
   1400097dd:	90                   	nop
   1400097de:	90                   	nop
   1400097df:	90                   	nop
