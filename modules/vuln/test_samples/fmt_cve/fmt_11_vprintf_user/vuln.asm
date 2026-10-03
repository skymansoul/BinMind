
C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\test_samples\fmt_cve\fmt_11_vprintf_user\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 cf 85 00 00       	call   1400095f8 <fflush>
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
   14000113b:	e8 68 84 00 00       	call   1400095a8 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 68 7e 00 00       	call   140008fd0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 af 84 00 00       	call   140009630 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 47 84 00 00       	call   1400095e0 <abort>
   140001199:	e8 42 11 00 00       	call   1400022e0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 91 f0 00 00 	mov    rax,QWORD PTR [rip+0xf091]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 a6 7d 00 00       	call   140008f70 <_set_invalid_parameter_handler>
   1400011ca:	e8 21 1a 00 00       	call   140002bf0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 a7 83 00 00       	call   140009598 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 9b 83 00 00       	call   140009598 <__set_app_type>
   1400011fd:	e8 1e 7c 00 00       	call   140008e20 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 1e 7c 00 00       	call   140008e30 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 9e 06 00 00       	call   1400018c0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 73 83 00 00       	call   1400095a8 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 a8 11 00 00       	call   1400023fa <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 46 7d 00 00       	call   140008fb0 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 40 7b 00 00       	call   140008dc0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 1a 83 00 00       	call   1400095a8 <_amsg_exit>
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
   1400012cb:	e8 b8 82 00 00       	call   140009588 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 c5 82 00 00       	call   1400095a8 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 9e 82 00 00       	call   1400095a8 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 a0 82 00 00       	call   1400095c0 <_initterm>
   140001320:	e8 72 05 00 00       	call   140001897 <__main>
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
   14000138d:	e8 ae 7a 00 00       	call   140008e40 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 dd 03 00 00       	call   140001797 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 1f 82 00 00       	call   1400095f0 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 d0 81 00 00       	call   1400095b0 <_cexit>
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
   140001511:	e8 0a 81 00 00       	call   140009620 <malloc>
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
   14000155c:	e8 e7 80 00 00       	call   140009648 <strlen>
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
   140001585:	e8 96 80 00 00       	call   140009620 <malloc>
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
   1400015e8:	e8 3b 80 00 00       	call   140009628 <memcpy>
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
   140001642:	e8 91 7f 00 00       	call   1400095d8 <_crt_atexit>
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

0000000140001760 <p>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 30          	sub    rsp,0x30
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001770:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001774:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140001778:	48 8d 45 18          	lea    rax,[rbp+0x18]
   14000177c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001780:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001784:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001788:	48 89 c1             	mov    rcx,rax
   14000178b:	e8 60 19 00 00       	call   1400030f0 <__mingw_vprintf>
   140001790:	90                   	nop
   140001791:	48 83 c4 30          	add    rsp,0x30
   140001795:	5d                   	pop    rbp
   140001796:	c3                   	ret

0000000140001797 <main>:
   140001797:	55                   	push   rbp
   140001798:	48 89 e5             	mov    rbp,rsp
   14000179b:	48 83 ec 20          	sub    rsp,0x20
   14000179f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400017a2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400017a6:	e8 ec 00 00 00       	call   140001897 <__main>
   1400017ab:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   1400017af:	7f 07                	jg     1400017b8 <main+0x21>
   1400017b1:	b8 00 00 00 00       	mov    eax,0x0
   1400017b6:	eb 18                	jmp    1400017d0 <main+0x39>
   1400017b8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400017bc:	48 83 c0 08          	add    rax,0x8
   1400017c0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017c3:	48 89 c1             	mov    rcx,rax
   1400017c6:	e8 95 ff ff ff       	call   140001760 <p>
   1400017cb:	b8 00 00 00 00       	mov    eax,0x0
   1400017d0:	48 83 c4 20          	add    rsp,0x20
   1400017d4:	5d                   	pop    rbp
   1400017d5:	c3                   	ret
   1400017d6:	90                   	nop
   1400017d7:	90                   	nop
   1400017d8:	90                   	nop
   1400017d9:	90                   	nop
   1400017da:	90                   	nop
   1400017db:	90                   	nop
   1400017dc:	90                   	nop
   1400017dd:	90                   	nop
   1400017de:	90                   	nop
   1400017df:	90                   	nop

00000001400017e0 <__do_global_dtors>:
   1400017e0:	55                   	push   rbp
   1400017e1:	48 89 e5             	mov    rbp,rsp
   1400017e4:	48 83 ec 20          	sub    rsp,0x20
   1400017e8:	eb 1e                	jmp    140001808 <__do_global_dtors+0x28>
   1400017ea:	48 8b 05 1f 88 00 00 	mov    rax,QWORD PTR [rip+0x881f]        # 14000a010 <p.0>
   1400017f1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017f4:	ff d0                	call   rax
   1400017f6:	48 8b 05 13 88 00 00 	mov    rax,QWORD PTR [rip+0x8813]        # 14000a010 <p.0>
   1400017fd:	48 83 c0 08          	add    rax,0x8
   140001801:	48 89 05 08 88 00 00 	mov    QWORD PTR [rip+0x8808],rax        # 14000a010 <p.0>
   140001808:	48 8b 05 01 88 00 00 	mov    rax,QWORD PTR [rip+0x8801]        # 14000a010 <p.0>
   14000180f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001812:	48 85 c0             	test   rax,rax
   140001815:	75 d3                	jne    1400017ea <__do_global_dtors+0xa>
   140001817:	90                   	nop
   140001818:	90                   	nop
   140001819:	48 83 c4 20          	add    rsp,0x20
   14000181d:	5d                   	pop    rbp
   14000181e:	c3                   	ret

000000014000181f <__do_global_ctors>:
   14000181f:	55                   	push   rbp
   140001820:	48 89 e5             	mov    rbp,rsp
   140001823:	48 83 ec 30          	sub    rsp,0x30
   140001827:	48 8b 05 42 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d42]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000182e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001831:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001834:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001838:	75 25                	jne    14000185f <__do_global_ctors+0x40>
   14000183a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001841:	eb 04                	jmp    140001847 <__do_global_ctors+0x28>
   140001843:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001847:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000184a:	8d 50 01             	lea    edx,[rax+0x1]
   14000184d:	48 8b 05 1c 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d1c]        # 14000b570 <.refptr.__CTOR_LIST__>
   140001854:	89 d2                	mov    edx,edx
   140001856:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000185a:	48 85 c0             	test   rax,rax
   14000185d:	75 e4                	jne    140001843 <__do_global_ctors+0x24>
   14000185f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001862:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001865:	eb 14                	jmp    14000187b <__do_global_ctors+0x5c>
   140001867:	48 8b 05 02 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d02]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000186e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001871:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001875:	ff d0                	call   rax
   140001877:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000187b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000187f:	75 e6                	jne    140001867 <__do_global_ctors+0x48>
   140001881:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400017e0 <__do_global_dtors>
   140001888:	48 89 c1             	mov    rcx,rax
   14000188b:	e8 9f fd ff ff       	call   14000162f <atexit>
   140001890:	90                   	nop
   140001891:	48 83 c4 30          	add    rsp,0x30
   140001895:	5d                   	pop    rbp
   140001896:	c3                   	ret

0000000140001897 <__main>:
   140001897:	55                   	push   rbp
   140001898:	48 89 e5             	mov    rbp,rsp
   14000189b:	48 83 ec 20          	sub    rsp,0x20
   14000189f:	8b 05 db d7 00 00    	mov    eax,DWORD PTR [rip+0xd7db]        # 14000f080 <initialized>
   1400018a5:	85 c0                	test   eax,eax
   1400018a7:	75 0f                	jne    1400018b8 <__main+0x21>
   1400018a9:	c7 05 cd d7 00 00 01 	mov    DWORD PTR [rip+0xd7cd],0x1        # 14000f080 <initialized>
   1400018b0:	00 00 00 
   1400018b3:	e8 67 ff ff ff       	call   14000181f <__do_global_ctors>
   1400018b8:	90                   	nop
   1400018b9:	48 83 c4 20          	add    rsp,0x20
   1400018bd:	5d                   	pop    rbp
   1400018be:	c3                   	ret
   1400018bf:	90                   	nop

00000001400018c0 <_setargv>:
   1400018c0:	55                   	push   rbp
   1400018c1:	48 89 e5             	mov    rbp,rsp
   1400018c4:	b8 00 00 00 00       	mov    eax,0x0
   1400018c9:	5d                   	pop    rbp
   1400018ca:	c3                   	ret
   1400018cb:	90                   	nop
   1400018cc:	90                   	nop
   1400018cd:	90                   	nop
   1400018ce:	90                   	nop
   1400018cf:	90                   	nop

00000001400018d0 <__dyn_tls_init>:
   1400018d0:	55                   	push   rbp
   1400018d1:	48 89 e5             	mov    rbp,rsp
   1400018d4:	48 83 ec 30          	sub    rsp,0x30
   1400018d8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400018dc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400018df:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400018e3:	48 8b 05 66 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c66]        # 14000b550 <.refptr._CRT_MT>
   1400018ea:	8b 00                	mov    eax,DWORD PTR [rax]
   1400018ec:	83 f8 02             	cmp    eax,0x2
   1400018ef:	74 0d                	je     1400018fe <__dyn_tls_init+0x2e>
   1400018f1:	48 8b 05 58 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c58]        # 14000b550 <.refptr._CRT_MT>
   1400018f8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400018fe:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001902:	74 1e                	je     140001922 <__dyn_tls_init+0x52>
   140001904:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001908:	75 5b                	jne    140001965 <__dyn_tls_init+0x95>
   14000190a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000190e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001911:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001915:	49 89 c8             	mov    r8,rcx
   140001918:	48 89 c1             	mov    rcx,rax
   14000191b:	e8 d1 11 00 00       	call   140002af1 <__mingw_TLScallback>
   140001920:	eb 43                	jmp    140001965 <__dyn_tls_init+0x95>
   140001922:	48 8d 05 af 9f 00 00 	lea    rax,[rip+0x9faf]        # 14000b8d8 <___crt_xd_start__>
   140001929:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000192d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001932:	eb 22                	jmp    140001956 <__dyn_tls_init+0x86>
   140001934:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001938:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000193c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001940:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001943:	48 85 c0             	test   rax,rax
   140001946:	74 09                	je     140001951 <__dyn_tls_init+0x81>
   140001948:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000194c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000194f:	ff d0                	call   rax
   140001951:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001956:	48 8d 05 83 9f 00 00 	lea    rax,[rip+0x9f83]        # 14000b8e0 <__xd_z>
   14000195d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001961:	75 d1                	jne    140001934 <__dyn_tls_init+0x64>
   140001963:	eb 01                	jmp    140001966 <__dyn_tls_init+0x96>
   140001965:	90                   	nop
   140001966:	48 83 c4 30          	add    rsp,0x30
   14000196a:	5d                   	pop    rbp
   14000196b:	c3                   	ret

000000014000196c <__tlregdtor>:
   14000196c:	55                   	push   rbp
   14000196d:	48 89 e5             	mov    rbp,rsp
   140001970:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001974:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001979:	75 07                	jne    140001982 <__tlregdtor+0x16>
   14000197b:	b8 00 00 00 00       	mov    eax,0x0
   140001980:	eb 05                	jmp    140001987 <__tlregdtor+0x1b>
   140001982:	b8 00 00 00 00       	mov    eax,0x0
   140001987:	5d                   	pop    rbp
   140001988:	c3                   	ret

0000000140001989 <__dyn_tls_dtor>:
   140001989:	55                   	push   rbp
   14000198a:	48 89 e5             	mov    rbp,rsp
   14000198d:	48 83 ec 20          	sub    rsp,0x20
   140001991:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001995:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001998:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000199c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   1400019a0:	74 06                	je     1400019a8 <__dyn_tls_dtor+0x1f>
   1400019a2:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400019a6:	75 18                	jne    1400019c0 <__dyn_tls_dtor+0x37>
   1400019a8:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019ac:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019af:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019b3:	49 89 c8             	mov    r8,rcx
   1400019b6:	48 89 c1             	mov    rcx,rax
   1400019b9:	e8 33 11 00 00       	call   140002af1 <__mingw_TLScallback>
   1400019be:	eb 01                	jmp    1400019c1 <__dyn_tls_dtor+0x38>
   1400019c0:	90                   	nop
   1400019c1:	48 83 c4 20          	add    rsp,0x20
   1400019c5:	5d                   	pop    rbp
   1400019c6:	c3                   	ret
   1400019c7:	90                   	nop
   1400019c8:	90                   	nop
   1400019c9:	90                   	nop
   1400019ca:	90                   	nop
   1400019cb:	90                   	nop
   1400019cc:	90                   	nop
   1400019cd:	90                   	nop
   1400019ce:	90                   	nop
   1400019cf:	90                   	nop

00000001400019d0 <_matherr>:
   1400019d0:	55                   	push   rbp
   1400019d1:	53                   	push   rbx
   1400019d2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400019d9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400019de:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   1400019e2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   1400019e6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   1400019eb:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   1400019ef:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   1400019f3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019f5:	83 f8 06             	cmp    eax,0x6
   1400019f8:	74 56                	je     140001a50 <_matherr+0x80>
   1400019fa:	83 f8 06             	cmp    eax,0x6
   1400019fd:	7f 78                	jg     140001a77 <_matherr+0xa7>
   1400019ff:	83 f8 05             	cmp    eax,0x5
   140001a02:	74 59                	je     140001a5d <_matherr+0x8d>
   140001a04:	83 f8 05             	cmp    eax,0x5
   140001a07:	7f 6e                	jg     140001a77 <_matherr+0xa7>
   140001a09:	83 f8 04             	cmp    eax,0x4
   140001a0c:	74 5c                	je     140001a6a <_matherr+0x9a>
   140001a0e:	83 f8 04             	cmp    eax,0x4
   140001a11:	7f 64                	jg     140001a77 <_matherr+0xa7>
   140001a13:	83 f8 03             	cmp    eax,0x3
   140001a16:	74 2b                	je     140001a43 <_matherr+0x73>
   140001a18:	83 f8 03             	cmp    eax,0x3
   140001a1b:	7f 5a                	jg     140001a77 <_matherr+0xa7>
   140001a1d:	83 f8 01             	cmp    eax,0x1
   140001a20:	74 07                	je     140001a29 <_matherr+0x59>
   140001a22:	83 f8 02             	cmp    eax,0x2
   140001a25:	74 0f                	je     140001a36 <_matherr+0x66>
   140001a27:	eb 4e                	jmp    140001a77 <_matherr+0xa7>
   140001a29:	48 8d 05 70 96 00 00 	lea    rax,[rip+0x9670]        # 14000b0a0 <.rdata>
   140001a30:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a34:	eb 4d                	jmp    140001a83 <_matherr+0xb3>
   140001a36:	48 8d 05 82 96 00 00 	lea    rax,[rip+0x9682]        # 14000b0bf <.rdata+0x1f>
   140001a3d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a41:	eb 40                	jmp    140001a83 <_matherr+0xb3>
   140001a43:	48 8d 05 96 96 00 00 	lea    rax,[rip+0x9696]        # 14000b0e0 <.rdata+0x40>
   140001a4a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a4e:	eb 33                	jmp    140001a83 <_matherr+0xb3>
   140001a50:	48 8d 05 a9 96 00 00 	lea    rax,[rip+0x96a9]        # 14000b100 <.rdata+0x60>
   140001a57:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a5b:	eb 26                	jmp    140001a83 <_matherr+0xb3>
   140001a5d:	48 8d 05 c4 96 00 00 	lea    rax,[rip+0x96c4]        # 14000b128 <.rdata+0x88>
   140001a64:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a68:	eb 19                	jmp    140001a83 <_matherr+0xb3>
   140001a6a:	48 8d 05 df 96 00 00 	lea    rax,[rip+0x96df]        # 14000b150 <.rdata+0xb0>
   140001a71:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a75:	eb 0c                	jmp    140001a83 <_matherr+0xb3>
   140001a77:	48 8d 05 08 97 00 00 	lea    rax,[rip+0x9708]        # 14000b186 <.rdata+0xe6>
   140001a7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a82:	90                   	nop
   140001a83:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a87:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001a8d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a91:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001a96:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a9a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001a9f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001aa3:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001aa7:	b9 02 00 00 00       	mov    ecx,0x2
   140001aac:	e8 1f 75 00 00       	call   140008fd0 <__acrt_iob_func>
   140001ab1:	48 89 c1             	mov    rcx,rax
   140001ab4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001ab8:	48 8d 05 d9 96 00 00 	lea    rax,[rip+0x96d9]        # 14000b198 <.rdata+0xf8>
   140001abf:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001ac6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001acc:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001ad2:	49 89 d9             	mov    r9,rbx
   140001ad5:	49 89 d0             	mov    r8,rdx
   140001ad8:	48 89 c2             	mov    rdx,rax
   140001adb:	e8 20 7b 00 00       	call   140009600 <fprintf>
   140001ae0:	b8 00 00 00 00       	mov    eax,0x0
   140001ae5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001ae9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001aed:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001af2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001af9:	5b                   	pop    rbx
   140001afa:	5d                   	pop    rbp
   140001afb:	c3                   	ret
   140001afc:	90                   	nop
   140001afd:	90                   	nop
   140001afe:	90                   	nop
   140001aff:	90                   	nop

0000000140001b00 <__report_error>:
   140001b00:	55                   	push   rbp
   140001b01:	53                   	push   rbx
   140001b02:	48 83 ec 38          	sub    rsp,0x38
   140001b06:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b0b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b0f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b13:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b17:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b1b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b1f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b23:	b9 02 00 00 00       	mov    ecx,0x2
   140001b28:	e8 a3 74 00 00       	call   140008fd0 <__acrt_iob_func>
   140001b2d:	48 89 c1             	mov    rcx,rax
   140001b30:	48 8d 05 99 96 00 00 	lea    rax,[rip+0x9699]        # 14000b1d0 <.rdata>
   140001b37:	48 89 c2             	mov    rdx,rax
   140001b3a:	e8 c1 7a 00 00       	call   140009600 <fprintf>
   140001b3f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b43:	b9 02 00 00 00       	mov    ecx,0x2
   140001b48:	e8 83 74 00 00       	call   140008fd0 <__acrt_iob_func>
   140001b4d:	48 89 c1             	mov    rcx,rax
   140001b50:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b54:	49 89 d8             	mov    r8,rbx
   140001b57:	48 89 c2             	mov    rdx,rax
   140001b5a:	e8 f9 7a 00 00       	call   140009658 <vfprintf>
   140001b5f:	e8 7c 7a 00 00       	call   1400095e0 <abort>
   140001b64:	90                   	nop

0000000140001b65 <mark_section_writable>:
   140001b65:	55                   	push   rbp
   140001b66:	48 89 e5             	mov    rbp,rsp
   140001b69:	48 83 ec 60          	sub    rsp,0x60
   140001b6d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b71:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001b78:	e9 82 00 00 00       	jmp    140001bff <mark_section_writable+0x9a>
   140001b7d:	48 8b 0d 5c d5 00 00 	mov    rcx,QWORD PTR [rip+0xd55c]        # 14000f0e0 <the_secs>
   140001b84:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b87:	48 63 d0             	movsxd rdx,eax
   140001b8a:	48 89 d0             	mov    rax,rdx
   140001b8d:	48 c1 e0 02          	shl    rax,0x2
   140001b91:	48 01 d0             	add    rax,rdx
   140001b94:	48 c1 e0 03          	shl    rax,0x3
   140001b98:	48 01 c8             	add    rax,rcx
   140001b9b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001b9f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001ba3:	72 56                	jb     140001bfb <mark_section_writable+0x96>
   140001ba5:	48 8b 0d 34 d5 00 00 	mov    rcx,QWORD PTR [rip+0xd534]        # 14000f0e0 <the_secs>
   140001bac:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001baf:	48 63 d0             	movsxd rdx,eax
   140001bb2:	48 89 d0             	mov    rax,rdx
   140001bb5:	48 c1 e0 02          	shl    rax,0x2
   140001bb9:	48 01 d0             	add    rax,rdx
   140001bbc:	48 c1 e0 03          	shl    rax,0x3
   140001bc0:	48 01 c8             	add    rax,rcx
   140001bc3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001bc7:	4c 8b 05 12 d5 00 00 	mov    r8,QWORD PTR [rip+0xd512]        # 14000f0e0 <the_secs>
   140001bce:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bd1:	48 63 d0             	movsxd rdx,eax
   140001bd4:	48 89 d0             	mov    rax,rdx
   140001bd7:	48 c1 e0 02          	shl    rax,0x2
   140001bdb:	48 01 d0             	add    rax,rdx
   140001bde:	48 c1 e0 03          	shl    rax,0x3
   140001be2:	4c 01 c0             	add    rax,r8
   140001be5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001be9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001bec:	89 c0                	mov    eax,eax
   140001bee:	48 01 c8             	add    rax,rcx
   140001bf1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001bf5:	0f 82 41 02 00 00    	jb     140001e3c <mark_section_writable+0x2d7>
   140001bfb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001bff:	8b 05 e3 d4 00 00    	mov    eax,DWORD PTR [rip+0xd4e3]        # 14000f0e8 <maxSections>
   140001c05:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c08:	0f 8c 6f ff ff ff    	jl     140001b7d <mark_section_writable+0x18>
   140001c0e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c12:	48 89 c1             	mov    rcx,rax
   140001c15:	e8 c1 11 00 00       	call   140002ddb <__mingw_GetSectionForAddress>
   140001c1a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c1e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c23:	75 13                	jne    140001c38 <mark_section_writable+0xd3>
   140001c25:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c29:	48 8d 0d c0 95 00 00 	lea    rcx,[rip+0x95c0]        # 14000b1f0 <.rdata+0x20>
   140001c30:	48 89 c2             	mov    rdx,rax
   140001c33:	e8 c8 fe ff ff       	call   140001b00 <__report_error>
   140001c38:	48 8b 0d a1 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd4a1]        # 14000f0e0 <the_secs>
   140001c3f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c42:	48 63 d0             	movsxd rdx,eax
   140001c45:	48 89 d0             	mov    rax,rdx
   140001c48:	48 c1 e0 02          	shl    rax,0x2
   140001c4c:	48 01 d0             	add    rax,rdx
   140001c4f:	48 c1 e0 03          	shl    rax,0x3
   140001c53:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c57:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c5b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c5f:	48 8b 0d 7a d4 00 00 	mov    rcx,QWORD PTR [rip+0xd47a]        # 14000f0e0 <the_secs>
   140001c66:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c69:	48 63 d0             	movsxd rdx,eax
   140001c6c:	48 89 d0             	mov    rax,rdx
   140001c6f:	48 c1 e0 02          	shl    rax,0x2
   140001c73:	48 01 d0             	add    rax,rdx
   140001c76:	48 c1 e0 03          	shl    rax,0x3
   140001c7a:	48 01 c8             	add    rax,rcx
   140001c7d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001c83:	e8 9f 12 00 00       	call   140002f27 <_GetPEImageBase>
   140001c88:	48 89 c1             	mov    rcx,rax
   140001c8b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c8f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001c92:	41 89 c1             	mov    r9d,eax
   140001c95:	4c 8b 05 44 d4 00 00 	mov    r8,QWORD PTR [rip+0xd444]        # 14000f0e0 <the_secs>
   140001c9c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c9f:	48 63 d0             	movsxd rdx,eax
   140001ca2:	48 89 d0             	mov    rax,rdx
   140001ca5:	48 c1 e0 02          	shl    rax,0x2
   140001ca9:	48 01 d0             	add    rax,rdx
   140001cac:	48 c1 e0 03          	shl    rax,0x3
   140001cb0:	4c 01 c0             	add    rax,r8
   140001cb3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001cb7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001cbb:	48 8b 0d 1e d4 00 00 	mov    rcx,QWORD PTR [rip+0xd41e]        # 14000f0e0 <the_secs>
   140001cc2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cc5:	48 63 d0             	movsxd rdx,eax
   140001cc8:	48 89 d0             	mov    rax,rdx
   140001ccb:	48 c1 e0 02          	shl    rax,0x2
   140001ccf:	48 01 d0             	add    rax,rdx
   140001cd2:	48 c1 e0 03          	shl    rax,0x3
   140001cd6:	48 01 c8             	add    rax,rcx
   140001cd9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001cdd:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001ce1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001ce7:	48 89 c1             	mov    rcx,rax
   140001cea:	48 8b 05 6f e5 00 00 	mov    rax,QWORD PTR [rip+0xe56f]        # 140010260 <__imp_VirtualQuery>
   140001cf1:	ff d0                	call   rax
   140001cf3:	48 85 c0             	test   rax,rax
   140001cf6:	75 3f                	jne    140001d37 <mark_section_writable+0x1d2>
   140001cf8:	48 8b 0d e1 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3e1]        # 14000f0e0 <the_secs>
   140001cff:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d02:	48 63 d0             	movsxd rdx,eax
   140001d05:	48 89 d0             	mov    rax,rdx
   140001d08:	48 c1 e0 02          	shl    rax,0x2
   140001d0c:	48 01 d0             	add    rax,rdx
   140001d0f:	48 c1 e0 03          	shl    rax,0x3
   140001d13:	48 01 c8             	add    rax,rcx
   140001d16:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d1a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d1e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d21:	89 c1                	mov    ecx,eax
   140001d23:	48 8d 05 e6 94 00 00 	lea    rax,[rip+0x94e6]        # 14000b210 <.rdata+0x40>
   140001d2a:	49 89 d0             	mov    r8,rdx
   140001d2d:	89 ca                	mov    edx,ecx
   140001d2f:	48 89 c1             	mov    rcx,rax
   140001d32:	e8 c9 fd ff ff       	call   140001b00 <__report_error>
   140001d37:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d3a:	83 f8 40             	cmp    eax,0x40
   140001d3d:	0f 84 e8 00 00 00    	je     140001e2b <mark_section_writable+0x2c6>
   140001d43:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d46:	83 f8 04             	cmp    eax,0x4
   140001d49:	0f 84 dc 00 00 00    	je     140001e2b <mark_section_writable+0x2c6>
   140001d4f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d52:	3d 80 00 00 00       	cmp    eax,0x80
   140001d57:	0f 84 ce 00 00 00    	je     140001e2b <mark_section_writable+0x2c6>
   140001d5d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d60:	83 f8 08             	cmp    eax,0x8
   140001d63:	0f 84 c2 00 00 00    	je     140001e2b <mark_section_writable+0x2c6>
   140001d69:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d6c:	83 f8 02             	cmp    eax,0x2
   140001d6f:	75 09                	jne    140001d7a <mark_section_writable+0x215>
   140001d71:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001d78:	eb 07                	jmp    140001d81 <mark_section_writable+0x21c>
   140001d7a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001d81:	48 8b 0d 58 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd358]        # 14000f0e0 <the_secs>
   140001d88:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d8b:	48 63 d0             	movsxd rdx,eax
   140001d8e:	48 89 d0             	mov    rax,rdx
   140001d91:	48 c1 e0 02          	shl    rax,0x2
   140001d95:	48 01 d0             	add    rax,rdx
   140001d98:	48 c1 e0 03          	shl    rax,0x3
   140001d9c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001da0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001da4:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001da8:	48 8b 0d 31 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd331]        # 14000f0e0 <the_secs>
   140001daf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001db2:	48 63 d0             	movsxd rdx,eax
   140001db5:	48 89 d0             	mov    rax,rdx
   140001db8:	48 c1 e0 02          	shl    rax,0x2
   140001dbc:	48 01 d0             	add    rax,rdx
   140001dbf:	48 c1 e0 03          	shl    rax,0x3
   140001dc3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001dc7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001dcb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001dcf:	48 8b 0d 0a d3 00 00 	mov    rcx,QWORD PTR [rip+0xd30a]        # 14000f0e0 <the_secs>
   140001dd6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dd9:	48 63 d0             	movsxd rdx,eax
   140001ddc:	48 89 d0             	mov    rax,rdx
   140001ddf:	48 c1 e0 02          	shl    rax,0x2
   140001de3:	48 01 d0             	add    rax,rdx
   140001de6:	48 c1 e0 03          	shl    rax,0x3
   140001dea:	48 01 c8             	add    rax,rcx
   140001ded:	49 89 c0             	mov    r8,rax
   140001df0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001df4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001df8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001dfb:	4d 89 c1             	mov    r9,r8
   140001dfe:	41 89 c8             	mov    r8d,ecx
   140001e01:	48 89 c1             	mov    rcx,rax
   140001e04:	48 8b 05 4d e4 00 00 	mov    rax,QWORD PTR [rip+0xe44d]        # 140010258 <__imp_VirtualProtect>
   140001e0b:	ff d0                	call   rax
   140001e0d:	85 c0                	test   eax,eax
   140001e0f:	75 1a                	jne    140001e2b <mark_section_writable+0x2c6>
   140001e11:	48 8b 05 f0 e3 00 00 	mov    rax,QWORD PTR [rip+0xe3f0]        # 140010208 <__imp_GetLastError>
   140001e18:	ff d0                	call   rax
   140001e1a:	89 c2                	mov    edx,eax
   140001e1c:	48 8d 05 25 94 00 00 	lea    rax,[rip+0x9425]        # 14000b248 <.rdata+0x78>
   140001e23:	48 89 c1             	mov    rcx,rax
   140001e26:	e8 d5 fc ff ff       	call   140001b00 <__report_error>
   140001e2b:	8b 05 b7 d2 00 00    	mov    eax,DWORD PTR [rip+0xd2b7]        # 14000f0e8 <maxSections>
   140001e31:	83 c0 01             	add    eax,0x1
   140001e34:	89 05 ae d2 00 00    	mov    DWORD PTR [rip+0xd2ae],eax        # 14000f0e8 <maxSections>
   140001e3a:	eb 01                	jmp    140001e3d <mark_section_writable+0x2d8>
   140001e3c:	90                   	nop
   140001e3d:	48 83 c4 60          	add    rsp,0x60
   140001e41:	5d                   	pop    rbp
   140001e42:	c3                   	ret

0000000140001e43 <restore_modified_sections>:
   140001e43:	55                   	push   rbp
   140001e44:	48 89 e5             	mov    rbp,rsp
   140001e47:	48 83 ec 30          	sub    rsp,0x30
   140001e4b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e52:	e9 ad 00 00 00       	jmp    140001f04 <restore_modified_sections+0xc1>
   140001e57:	48 8b 0d 82 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd282]        # 14000f0e0 <the_secs>
   140001e5e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e61:	48 63 d0             	movsxd rdx,eax
   140001e64:	48 89 d0             	mov    rax,rdx
   140001e67:	48 c1 e0 02          	shl    rax,0x2
   140001e6b:	48 01 d0             	add    rax,rdx
   140001e6e:	48 c1 e0 03          	shl    rax,0x3
   140001e72:	48 01 c8             	add    rax,rcx
   140001e75:	8b 00                	mov    eax,DWORD PTR [rax]
   140001e77:	85 c0                	test   eax,eax
   140001e79:	0f 84 80 00 00 00    	je     140001eff <restore_modified_sections+0xbc>
   140001e7f:	48 8b 0d 5a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd25a]        # 14000f0e0 <the_secs>
   140001e86:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e89:	48 63 d0             	movsxd rdx,eax
   140001e8c:	48 89 d0             	mov    rax,rdx
   140001e8f:	48 c1 e0 02          	shl    rax,0x2
   140001e93:	48 01 d0             	add    rax,rdx
   140001e96:	48 c1 e0 03          	shl    rax,0x3
   140001e9a:	48 01 c8             	add    rax,rcx
   140001e9d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001ea0:	48 8b 0d 39 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd239]        # 14000f0e0 <the_secs>
   140001ea7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eaa:	48 63 d0             	movsxd rdx,eax
   140001ead:	48 89 d0             	mov    rax,rdx
   140001eb0:	48 c1 e0 02          	shl    rax,0x2
   140001eb4:	48 01 d0             	add    rax,rdx
   140001eb7:	48 c1 e0 03          	shl    rax,0x3
   140001ebb:	48 01 c8             	add    rax,rcx
   140001ebe:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001ec2:	4c 8b 05 17 d2 00 00 	mov    r8,QWORD PTR [rip+0xd217]        # 14000f0e0 <the_secs>
   140001ec9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ecc:	48 63 d0             	movsxd rdx,eax
   140001ecf:	48 89 d0             	mov    rax,rdx
   140001ed2:	48 c1 e0 02          	shl    rax,0x2
   140001ed6:	48 01 d0             	add    rax,rdx
   140001ed9:	48 c1 e0 03          	shl    rax,0x3
   140001edd:	4c 01 c0             	add    rax,r8
   140001ee0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001ee4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001ee8:	49 89 d1             	mov    r9,rdx
   140001eeb:	45 89 d0             	mov    r8d,r10d
   140001eee:	48 89 ca             	mov    rdx,rcx
   140001ef1:	48 89 c1             	mov    rcx,rax
   140001ef4:	48 8b 05 5d e3 00 00 	mov    rax,QWORD PTR [rip+0xe35d]        # 140010258 <__imp_VirtualProtect>
   140001efb:	ff d0                	call   rax
   140001efd:	eb 01                	jmp    140001f00 <restore_modified_sections+0xbd>
   140001eff:	90                   	nop
   140001f00:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f04:	8b 05 de d1 00 00    	mov    eax,DWORD PTR [rip+0xd1de]        # 14000f0e8 <maxSections>
   140001f0a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f0d:	0f 8c 44 ff ff ff    	jl     140001e57 <restore_modified_sections+0x14>
   140001f13:	90                   	nop
   140001f14:	90                   	nop
   140001f15:	48 83 c4 30          	add    rsp,0x30
   140001f19:	5d                   	pop    rbp
   140001f1a:	c3                   	ret

0000000140001f1b <__write_memory>:
   140001f1b:	55                   	push   rbp
   140001f1c:	48 89 e5             	mov    rbp,rsp
   140001f1f:	48 83 ec 20          	sub    rsp,0x20
   140001f23:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f27:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f2b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f2f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f34:	74 25                	je     140001f5b <__write_memory+0x40>
   140001f36:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f3a:	48 89 c1             	mov    rcx,rax
   140001f3d:	e8 23 fc ff ff       	call   140001b65 <mark_section_writable>
   140001f42:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f46:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f4a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f4e:	49 89 c8             	mov    r8,rcx
   140001f51:	48 89 c1             	mov    rcx,rax
   140001f54:	e8 cf 76 00 00       	call   140009628 <memcpy>
   140001f59:	eb 01                	jmp    140001f5c <__write_memory+0x41>
   140001f5b:	90                   	nop
   140001f5c:	48 83 c4 20          	add    rsp,0x20
   140001f60:	5d                   	pop    rbp
   140001f61:	c3                   	ret

0000000140001f62 <do_pseudo_reloc>:
   140001f62:	55                   	push   rbp
   140001f63:	48 89 e5             	mov    rbp,rsp
   140001f66:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001f6a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f6e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f72:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f76:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001f7a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001f7e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001f82:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f86:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001f8a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001f8f:	0f 8e 44 03 00 00    	jle    1400022d9 <do_pseudo_reloc+0x377>
   140001f95:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001f9a:	7e 25                	jle    140001fc1 <do_pseudo_reloc+0x5f>
   140001f9c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fa0:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fa2:	85 c0                	test   eax,eax
   140001fa4:	75 1b                	jne    140001fc1 <do_pseudo_reloc+0x5f>
   140001fa6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001faa:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fad:	85 c0                	test   eax,eax
   140001faf:	75 10                	jne    140001fc1 <do_pseudo_reloc+0x5f>
   140001fb1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fb5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001fb8:	85 c0                	test   eax,eax
   140001fba:	75 05                	jne    140001fc1 <do_pseudo_reloc+0x5f>
   140001fbc:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140001fc1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fc5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fc7:	85 c0                	test   eax,eax
   140001fc9:	75 0b                	jne    140001fd6 <do_pseudo_reloc+0x74>
   140001fcb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fcf:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fd2:	85 c0                	test   eax,eax
   140001fd4:	74 59                	je     14000202f <do_pseudo_reloc+0xcd>
   140001fd6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fda:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001fde:	eb 40                	jmp    140002020 <do_pseudo_reloc+0xbe>
   140001fe0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001fe4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fe7:	89 c2                	mov    edx,eax
   140001fe9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001fed:	48 01 d0             	add    rax,rdx
   140001ff0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001ff4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001ff8:	8b 10                	mov    edx,DWORD PTR [rax]
   140001ffa:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001ffe:	8b 00                	mov    eax,DWORD PTR [rax]
   140002000:	01 d0                	add    eax,edx
   140002002:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002005:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002009:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000200d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002013:	48 89 c1             	mov    rcx,rax
   140002016:	e8 00 ff ff ff       	call   140001f1b <__write_memory>
   14000201b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002020:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002024:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002028:	72 b6                	jb     140001fe0 <do_pseudo_reloc+0x7e>
   14000202a:	e9 ab 02 00 00       	jmp    1400022da <do_pseudo_reloc+0x378>
   14000202f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002033:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002036:	83 f8 01             	cmp    eax,0x1
   140002039:	74 18                	je     140002053 <do_pseudo_reloc+0xf1>
   14000203b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000203f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002042:	89 c2                	mov    edx,eax
   140002044:	48 8d 05 25 92 00 00 	lea    rax,[rip+0x9225]        # 14000b270 <.rdata+0xa0>
   14000204b:	48 89 c1             	mov    rcx,rax
   14000204e:	e8 ad fa ff ff       	call   140001b00 <__report_error>
   140002053:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002057:	48 83 c0 0c          	add    rax,0xc
   14000205b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000205f:	e9 65 02 00 00       	jmp    1400022c9 <do_pseudo_reloc+0x367>
   140002064:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002068:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000206b:	89 c2                	mov    edx,eax
   14000206d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002071:	48 01 d0             	add    rax,rdx
   140002074:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002078:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000207c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000207e:	89 c2                	mov    edx,eax
   140002080:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002084:	48 01 d0             	add    rax,rdx
   140002087:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000208b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000208f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002092:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002096:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000209a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000209d:	0f b6 c0             	movzx  eax,al
   1400020a0:	83 f8 40             	cmp    eax,0x40
   1400020a3:	0f 84 b6 00 00 00    	je     14000215f <do_pseudo_reloc+0x1fd>
   1400020a9:	83 f8 40             	cmp    eax,0x40
   1400020ac:	0f 87 ba 00 00 00    	ja     14000216c <do_pseudo_reloc+0x20a>
   1400020b2:	83 f8 20             	cmp    eax,0x20
   1400020b5:	74 77                	je     14000212e <do_pseudo_reloc+0x1cc>
   1400020b7:	83 f8 20             	cmp    eax,0x20
   1400020ba:	0f 87 ac 00 00 00    	ja     14000216c <do_pseudo_reloc+0x20a>
   1400020c0:	83 f8 08             	cmp    eax,0x8
   1400020c3:	74 0a                	je     1400020cf <do_pseudo_reloc+0x16d>
   1400020c5:	83 f8 10             	cmp    eax,0x10
   1400020c8:	74 38                	je     140002102 <do_pseudo_reloc+0x1a0>
   1400020ca:	e9 9d 00 00 00       	jmp    14000216c <do_pseudo_reloc+0x20a>
   1400020cf:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020d3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400020d6:	0f b6 c0             	movzx  eax,al
   1400020d9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020dd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020e1:	25 80 00 00 00       	and    eax,0x80
   1400020e6:	48 85 c0             	test   rax,rax
   1400020e9:	0f 84 9d 00 00 00    	je     14000218c <do_pseudo_reloc+0x22a>
   1400020ef:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020f3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400020f9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020fd:	e9 8a 00 00 00       	jmp    14000218c <do_pseudo_reloc+0x22a>
   140002102:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002106:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002109:	0f b7 c0             	movzx  eax,ax
   14000210c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002110:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002114:	25 00 80 00 00       	and    eax,0x8000
   140002119:	48 85 c0             	test   rax,rax
   14000211c:	74 71                	je     14000218f <do_pseudo_reloc+0x22d>
   14000211e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002122:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002128:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000212c:	eb 61                	jmp    14000218f <do_pseudo_reloc+0x22d>
   14000212e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002132:	8b 00                	mov    eax,DWORD PTR [rax]
   140002134:	89 c0                	mov    eax,eax
   140002136:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000213a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000213e:	25 00 00 00 80       	and    eax,0x80000000
   140002143:	48 85 c0             	test   rax,rax
   140002146:	74 4a                	je     140002192 <do_pseudo_reloc+0x230>
   140002148:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000214c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002153:	ff ff ff 
   140002156:	48 09 d0             	or     rax,rdx
   140002159:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000215d:	eb 33                	jmp    140002192 <do_pseudo_reloc+0x230>
   14000215f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002163:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002166:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000216a:	eb 27                	jmp    140002193 <do_pseudo_reloc+0x231>
   14000216c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002173:	00 
   140002174:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002178:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000217b:	0f b6 c0             	movzx  eax,al
   14000217e:	48 8d 0d 23 91 00 00 	lea    rcx,[rip+0x9123]        # 14000b2a8 <.rdata+0xd8>
   140002185:	89 c2                	mov    edx,eax
   140002187:	e8 74 f9 ff ff       	call   140001b00 <__report_error>
   14000218c:	90                   	nop
   14000218d:	eb 04                	jmp    140002193 <do_pseudo_reloc+0x231>
   14000218f:	90                   	nop
   140002190:	eb 01                	jmp    140002193 <do_pseudo_reloc+0x231>
   140002192:	90                   	nop
   140002193:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002197:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000219b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000219d:	89 c2                	mov    edx,eax
   14000219f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400021a3:	48 01 c2             	add    rdx,rax
   1400021a6:	48 89 c8             	mov    rax,rcx
   1400021a9:	48 29 d0             	sub    rax,rdx
   1400021ac:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021b0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021b4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400021b8:	48 01 d0             	add    rax,rdx
   1400021bb:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021bf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021c3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021c6:	25 ff 00 00 00       	and    eax,0xff
   1400021cb:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400021ce:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400021d2:	77 67                	ja     14000223b <do_pseudo_reloc+0x2d9>
   1400021d4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021d7:	ba 01 00 00 00       	mov    edx,0x1
   1400021dc:	89 c1                	mov    ecx,eax
   1400021de:	48 d3 e2             	shl    rdx,cl
   1400021e1:	48 89 d0             	mov    rax,rdx
   1400021e4:	48 83 e8 01          	sub    rax,0x1
   1400021e8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400021ec:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021ef:	83 e8 01             	sub    eax,0x1
   1400021f2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400021f9:	89 c1                	mov    ecx,eax
   1400021fb:	48 d3 e2             	shl    rdx,cl
   1400021fe:	48 89 d0             	mov    rax,rdx
   140002201:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002205:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002209:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000220d:	7c 0a                	jl     140002219 <do_pseudo_reloc+0x2b7>
   14000220f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002213:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002217:	7e 22                	jle    14000223b <do_pseudo_reloc+0x2d9>
   140002219:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000221d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002221:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002225:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002228:	48 8d 0d a9 90 00 00 	lea    rcx,[rip+0x90a9]        # 14000b2d8 <.rdata+0x108>
   14000222f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002234:	89 c2                	mov    edx,eax
   140002236:	e8 c5 f8 ff ff       	call   140001b00 <__report_error>
   14000223b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000223f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002242:	0f b6 c0             	movzx  eax,al
   140002245:	83 f8 40             	cmp    eax,0x40
   140002248:	74 63                	je     1400022ad <do_pseudo_reloc+0x34b>
   14000224a:	83 f8 40             	cmp    eax,0x40
   14000224d:	77 75                	ja     1400022c4 <do_pseudo_reloc+0x362>
   14000224f:	83 f8 20             	cmp    eax,0x20
   140002252:	74 41                	je     140002295 <do_pseudo_reloc+0x333>
   140002254:	83 f8 20             	cmp    eax,0x20
   140002257:	77 6b                	ja     1400022c4 <do_pseudo_reloc+0x362>
   140002259:	83 f8 08             	cmp    eax,0x8
   14000225c:	74 07                	je     140002265 <do_pseudo_reloc+0x303>
   14000225e:	83 f8 10             	cmp    eax,0x10
   140002261:	74 1a                	je     14000227d <do_pseudo_reloc+0x31b>
   140002263:	eb 5f                	jmp    1400022c4 <do_pseudo_reloc+0x362>
   140002265:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002269:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000226d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002273:	48 89 c1             	mov    rcx,rax
   140002276:	e8 a0 fc ff ff       	call   140001f1b <__write_memory>
   14000227b:	eb 47                	jmp    1400022c4 <do_pseudo_reloc+0x362>
   14000227d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002281:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002285:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000228b:	48 89 c1             	mov    rcx,rax
   14000228e:	e8 88 fc ff ff       	call   140001f1b <__write_memory>
   140002293:	eb 2f                	jmp    1400022c4 <do_pseudo_reloc+0x362>
   140002295:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002299:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000229d:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400022a3:	48 89 c1             	mov    rcx,rax
   1400022a6:	e8 70 fc ff ff       	call   140001f1b <__write_memory>
   1400022ab:	eb 17                	jmp    1400022c4 <do_pseudo_reloc+0x362>
   1400022ad:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022b1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022b5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400022bb:	48 89 c1             	mov    rcx,rax
   1400022be:	e8 58 fc ff ff       	call   140001f1b <__write_memory>
   1400022c3:	90                   	nop
   1400022c4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400022c9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022cd:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400022d1:	0f 82 8d fd ff ff    	jb     140002064 <do_pseudo_reloc+0x102>
   1400022d7:	eb 01                	jmp    1400022da <do_pseudo_reloc+0x378>
   1400022d9:	90                   	nop
   1400022da:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400022de:	5d                   	pop    rbp
   1400022df:	c3                   	ret

00000001400022e0 <_pei386_runtime_relocator>:
   1400022e0:	55                   	push   rbp
   1400022e1:	48 89 e5             	mov    rbp,rsp
   1400022e4:	48 83 ec 30          	sub    rsp,0x30
   1400022e8:	8b 05 fe cd 00 00    	mov    eax,DWORD PTR [rip+0xcdfe]        # 14000f0ec <was_init.0>
   1400022ee:	85 c0                	test   eax,eax
   1400022f0:	0f 85 88 00 00 00    	jne    14000237e <_pei386_runtime_relocator+0x9e>
   1400022f6:	8b 05 f0 cd 00 00    	mov    eax,DWORD PTR [rip+0xcdf0]        # 14000f0ec <was_init.0>
   1400022fc:	83 c0 01             	add    eax,0x1
   1400022ff:	89 05 e7 cd 00 00    	mov    DWORD PTR [rip+0xcde7],eax        # 14000f0ec <was_init.0>
   140002305:	e8 21 0b 00 00       	call   140002e2b <__mingw_GetSectionCount>
   14000230a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000230d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002310:	48 63 d0             	movsxd rdx,eax
   140002313:	48 89 d0             	mov    rax,rdx
   140002316:	48 c1 e0 02          	shl    rax,0x2
   14000231a:	48 01 d0             	add    rax,rdx
   14000231d:	48 c1 e0 03          	shl    rax,0x3
   140002321:	48 83 c0 0f          	add    rax,0xf
   140002325:	48 c1 e8 04          	shr    rax,0x4
   140002329:	48 c1 e0 04          	shl    rax,0x4
   14000232d:	e8 7e 0d 00 00       	call   1400030b0 <___chkstk_ms>
   140002332:	48 29 c4             	sub    rsp,rax
   140002335:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000233a:	48 83 c0 0f          	add    rax,0xf
   14000233e:	48 c1 e8 04          	shr    rax,0x4
   140002342:	48 c1 e0 04          	shl    rax,0x4
   140002346:	48 89 05 93 cd 00 00 	mov    QWORD PTR [rip+0xcd93],rax        # 14000f0e0 <the_secs>
   14000234d:	c7 05 91 cd 00 00 00 	mov    DWORD PTR [rip+0xcd91],0x0        # 14000f0e8 <maxSections>
   140002354:	00 00 00 
   140002357:	48 8b 0d 22 92 00 00 	mov    rcx,QWORD PTR [rip+0x9222]        # 14000b580 <.refptr.__ImageBase>
   14000235e:	48 8b 15 2b 92 00 00 	mov    rdx,QWORD PTR [rip+0x922b]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002365:	48 8b 05 34 92 00 00 	mov    rax,QWORD PTR [rip+0x9234]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000236c:	49 89 c8             	mov    r8,rcx
   14000236f:	48 89 c1             	mov    rcx,rax
   140002372:	e8 eb fb ff ff       	call   140001f62 <do_pseudo_reloc>
   140002377:	e8 c7 fa ff ff       	call   140001e43 <restore_modified_sections>
   14000237c:	eb 01                	jmp    14000237f <_pei386_runtime_relocator+0x9f>
   14000237e:	90                   	nop
   14000237f:	48 89 ec             	mov    rsp,rbp
   140002382:	5d                   	pop    rbp
   140002383:	c3                   	ret
   140002384:	90                   	nop
   140002385:	90                   	nop
   140002386:	90                   	nop
   140002387:	90                   	nop
   140002388:	90                   	nop
   140002389:	90                   	nop
   14000238a:	90                   	nop
   14000238b:	90                   	nop
   14000238c:	90                   	nop
   14000238d:	90                   	nop
   14000238e:	90                   	nop
   14000238f:	90                   	nop

0000000140002390 <__mingw_raise_matherr>:
   140002390:	55                   	push   rbp
   140002391:	48 89 e5             	mov    rbp,rsp
   140002394:	48 83 ec 50          	sub    rsp,0x50
   140002398:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000239b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000239f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   1400023a4:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   1400023a9:	48 8b 05 40 cd 00 00 	mov    rax,QWORD PTR [rip+0xcd40]        # 14000f0f0 <stUserMathErr>
   1400023b0:	48 85 c0             	test   rax,rax
   1400023b3:	74 3e                	je     1400023f3 <__mingw_raise_matherr+0x63>
   1400023b5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400023b8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400023bb:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400023bf:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400023c3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400023c8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400023cd:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400023d2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400023d7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400023dc:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400023e1:	48 8b 15 08 cd 00 00 	mov    rdx,QWORD PTR [rip+0xcd08]        # 14000f0f0 <stUserMathErr>
   1400023e8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400023ec:	48 89 c1             	mov    rcx,rax
   1400023ef:	ff d2                	call   rdx
   1400023f1:	eb 01                	jmp    1400023f4 <__mingw_raise_matherr+0x64>
   1400023f3:	90                   	nop
   1400023f4:	48 83 c4 50          	add    rsp,0x50
   1400023f8:	5d                   	pop    rbp
   1400023f9:	c3                   	ret

00000001400023fa <__mingw_setusermatherr>:
   1400023fa:	55                   	push   rbp
   1400023fb:	48 89 e5             	mov    rbp,rsp
   1400023fe:	48 83 ec 20          	sub    rsp,0x20
   140002402:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002406:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000240a:	48 89 05 df cc 00 00 	mov    QWORD PTR [rip+0xccdf],rax        # 14000f0f0 <stUserMathErr>
   140002411:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002415:	48 89 c1             	mov    rcx,rax
   140002418:	e8 83 71 00 00       	call   1400095a0 <__setusermatherr>
   14000241d:	90                   	nop
   14000241e:	48 83 c4 20          	add    rsp,0x20
   140002422:	5d                   	pop    rbp
   140002423:	c3                   	ret
   140002424:	90                   	nop
   140002425:	90                   	nop
   140002426:	90                   	nop
   140002427:	90                   	nop
   140002428:	90                   	nop
   140002429:	90                   	nop
   14000242a:	90                   	nop
   14000242b:	90                   	nop
   14000242c:	90                   	nop
   14000242d:	90                   	nop
   14000242e:	90                   	nop
   14000242f:	90                   	nop

0000000140002430 <__mingw_SEH_error_handler>:
   140002430:	55                   	push   rbp
   140002431:	48 89 e5             	mov    rbp,rsp
   140002434:	48 83 ec 30          	sub    rsp,0x30
   140002438:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000243c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002440:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002444:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002448:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000244f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002456:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000245a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000245d:	83 e0 02             	and    eax,0x2
   140002460:	85 c0                	test   eax,eax
   140002462:	74 0a                	je     14000246e <__mingw_SEH_error_handler+0x3e>
   140002464:	b8 01 00 00 00       	mov    eax,0x1
   140002469:	e9 16 02 00 00       	jmp    140002684 <__mingw_SEH_error_handler+0x254>
   14000246e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002472:	8b 00                	mov    eax,DWORD PTR [rax]
   140002474:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002479:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000247e:	75 18                	jne    140002498 <__mingw_SEH_error_handler+0x68>
   140002480:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002484:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002487:	83 e0 01             	and    eax,0x1
   14000248a:	85 c0                	test   eax,eax
   14000248c:	75 0a                	jne    140002498 <__mingw_SEH_error_handler+0x68>
   14000248e:	b8 00 00 00 00       	mov    eax,0x0
   140002493:	e9 ec 01 00 00       	jmp    140002684 <__mingw_SEH_error_handler+0x254>
   140002498:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000249c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000249e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024a3:	0f 84 12 01 00 00    	je     1400025bb <__mingw_SEH_error_handler+0x18b>
   1400024a9:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024ae:	0f 87 c3 01 00 00    	ja     140002677 <__mingw_SEH_error_handler+0x247>
   1400024b4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400024b9:	0f 87 b8 01 00 00    	ja     140002677 <__mingw_SEH_error_handler+0x247>
   1400024bf:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400024c4:	0f 83 4c 01 00 00    	jae    140002616 <__mingw_SEH_error_handler+0x1e6>
   1400024ca:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024cf:	0f 84 3a 01 00 00    	je     14000260f <__mingw_SEH_error_handler+0x1df>
   1400024d5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024da:	0f 87 97 01 00 00    	ja     140002677 <__mingw_SEH_error_handler+0x247>
   1400024e0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024e5:	0f 84 83 01 00 00    	je     14000266e <__mingw_SEH_error_handler+0x23e>
   1400024eb:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024f0:	0f 87 81 01 00 00    	ja     140002677 <__mingw_SEH_error_handler+0x247>
   1400024f6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400024fb:	0f 87 76 01 00 00    	ja     140002677 <__mingw_SEH_error_handler+0x247>
   140002501:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002506:	0f 83 03 01 00 00    	jae    14000260f <__mingw_SEH_error_handler+0x1df>
   14000250c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002511:	0f 84 57 01 00 00    	je     14000266e <__mingw_SEH_error_handler+0x23e>
   140002517:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000251c:	0f 87 55 01 00 00    	ja     140002677 <__mingw_SEH_error_handler+0x247>
   140002522:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002527:	0f 84 8e 00 00 00    	je     1400025bb <__mingw_SEH_error_handler+0x18b>
   14000252d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002532:	0f 87 3f 01 00 00    	ja     140002677 <__mingw_SEH_error_handler+0x247>
   140002538:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000253d:	0f 84 2b 01 00 00    	je     14000266e <__mingw_SEH_error_handler+0x23e>
   140002543:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002548:	0f 87 29 01 00 00    	ja     140002677 <__mingw_SEH_error_handler+0x247>
   14000254e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002553:	0f 84 15 01 00 00    	je     14000266e <__mingw_SEH_error_handler+0x23e>
   140002559:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000255e:	0f 85 13 01 00 00    	jne    140002677 <__mingw_SEH_error_handler+0x247>
   140002564:	ba 00 00 00 00       	mov    edx,0x0
   140002569:	b9 0b 00 00 00       	mov    ecx,0xb
   14000256e:	e8 c5 70 00 00       	call   140009638 <signal>
   140002573:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002577:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000257c:	75 1b                	jne    140002599 <__mingw_SEH_error_handler+0x169>
   14000257e:	ba 01 00 00 00       	mov    edx,0x1
   140002583:	b9 0b 00 00 00       	mov    ecx,0xb
   140002588:	e8 ab 70 00 00       	call   140009638 <signal>
   14000258d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002594:	e9 e1 00 00 00       	jmp    14000267a <__mingw_SEH_error_handler+0x24a>
   140002599:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000259e:	0f 84 d6 00 00 00    	je     14000267a <__mingw_SEH_error_handler+0x24a>
   1400025a4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025a8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025ad:	ff d0                	call   rax
   1400025af:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025b6:	e9 bf 00 00 00       	jmp    14000267a <__mingw_SEH_error_handler+0x24a>
   1400025bb:	ba 00 00 00 00       	mov    edx,0x0
   1400025c0:	b9 04 00 00 00       	mov    ecx,0x4
   1400025c5:	e8 6e 70 00 00       	call   140009638 <signal>
   1400025ca:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025ce:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025d3:	75 1b                	jne    1400025f0 <__mingw_SEH_error_handler+0x1c0>
   1400025d5:	ba 01 00 00 00       	mov    edx,0x1
   1400025da:	b9 04 00 00 00       	mov    ecx,0x4
   1400025df:	e8 54 70 00 00       	call   140009638 <signal>
   1400025e4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025eb:	e9 8d 00 00 00       	jmp    14000267d <__mingw_SEH_error_handler+0x24d>
   1400025f0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025f5:	0f 84 82 00 00 00    	je     14000267d <__mingw_SEH_error_handler+0x24d>
   1400025fb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025ff:	b9 04 00 00 00       	mov    ecx,0x4
   140002604:	ff d0                	call   rax
   140002606:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000260d:	eb 6e                	jmp    14000267d <__mingw_SEH_error_handler+0x24d>
   14000260f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002616:	ba 00 00 00 00       	mov    edx,0x0
   14000261b:	b9 08 00 00 00       	mov    ecx,0x8
   140002620:	e8 13 70 00 00       	call   140009638 <signal>
   140002625:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002629:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000262e:	75 23                	jne    140002653 <__mingw_SEH_error_handler+0x223>
   140002630:	ba 01 00 00 00       	mov    edx,0x1
   140002635:	b9 08 00 00 00       	mov    ecx,0x8
   14000263a:	e8 f9 6f 00 00       	call   140009638 <signal>
   14000263f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002643:	74 05                	je     14000264a <__mingw_SEH_error_handler+0x21a>
   140002645:	e8 a6 05 00 00       	call   140002bf0 <_fpreset>
   14000264a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002651:	eb 2d                	jmp    140002680 <__mingw_SEH_error_handler+0x250>
   140002653:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002658:	74 26                	je     140002680 <__mingw_SEH_error_handler+0x250>
   14000265a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000265e:	b9 08 00 00 00       	mov    ecx,0x8
   140002663:	ff d0                	call   rax
   140002665:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000266c:	eb 12                	jmp    140002680 <__mingw_SEH_error_handler+0x250>
   14000266e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002675:	eb 0a                	jmp    140002681 <__mingw_SEH_error_handler+0x251>
   140002677:	90                   	nop
   140002678:	eb 07                	jmp    140002681 <__mingw_SEH_error_handler+0x251>
   14000267a:	90                   	nop
   14000267b:	eb 04                	jmp    140002681 <__mingw_SEH_error_handler+0x251>
   14000267d:	90                   	nop
   14000267e:	eb 01                	jmp    140002681 <__mingw_SEH_error_handler+0x251>
   140002680:	90                   	nop
   140002681:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002684:	48 83 c4 30          	add    rsp,0x30
   140002688:	5d                   	pop    rbp
   140002689:	c3                   	ret

000000014000268a <_gnu_exception_handler>:
   14000268a:	55                   	push   rbp
   14000268b:	48 89 e5             	mov    rbp,rsp
   14000268e:	48 83 ec 30          	sub    rsp,0x30
   140002692:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002696:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000269d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400026a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026a8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026ad:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400026b2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400026b7:	75 1b                	jne    1400026d4 <_gnu_exception_handler+0x4a>
   1400026b9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026bd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026c0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400026c3:	83 e0 01             	and    eax,0x1
   1400026c6:	85 c0                	test   eax,eax
   1400026c8:	75 0a                	jne    1400026d4 <_gnu_exception_handler+0x4a>
   1400026ca:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400026cf:	e9 14 02 00 00       	jmp    1400028e8 <_gnu_exception_handler+0x25e>
   1400026d4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026d8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026db:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026dd:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026e2:	0f 84 12 01 00 00    	je     1400027fa <_gnu_exception_handler+0x170>
   1400026e8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026ed:	0f 87 c3 01 00 00    	ja     1400028b6 <_gnu_exception_handler+0x22c>
   1400026f3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400026f8:	0f 87 b8 01 00 00    	ja     1400028b6 <_gnu_exception_handler+0x22c>
   1400026fe:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002703:	0f 83 4c 01 00 00    	jae    140002855 <_gnu_exception_handler+0x1cb>
   140002709:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000270e:	0f 84 3a 01 00 00    	je     14000284e <_gnu_exception_handler+0x1c4>
   140002714:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002719:	0f 87 97 01 00 00    	ja     1400028b6 <_gnu_exception_handler+0x22c>
   14000271f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002724:	0f 84 83 01 00 00    	je     1400028ad <_gnu_exception_handler+0x223>
   14000272a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000272f:	0f 87 81 01 00 00    	ja     1400028b6 <_gnu_exception_handler+0x22c>
   140002735:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000273a:	0f 87 76 01 00 00    	ja     1400028b6 <_gnu_exception_handler+0x22c>
   140002740:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002745:	0f 83 03 01 00 00    	jae    14000284e <_gnu_exception_handler+0x1c4>
   14000274b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002750:	0f 84 57 01 00 00    	je     1400028ad <_gnu_exception_handler+0x223>
   140002756:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000275b:	0f 87 55 01 00 00    	ja     1400028b6 <_gnu_exception_handler+0x22c>
   140002761:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002766:	0f 84 8e 00 00 00    	je     1400027fa <_gnu_exception_handler+0x170>
   14000276c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002771:	0f 87 3f 01 00 00    	ja     1400028b6 <_gnu_exception_handler+0x22c>
   140002777:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000277c:	0f 84 2b 01 00 00    	je     1400028ad <_gnu_exception_handler+0x223>
   140002782:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002787:	0f 87 29 01 00 00    	ja     1400028b6 <_gnu_exception_handler+0x22c>
   14000278d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002792:	0f 84 15 01 00 00    	je     1400028ad <_gnu_exception_handler+0x223>
   140002798:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000279d:	0f 85 13 01 00 00    	jne    1400028b6 <_gnu_exception_handler+0x22c>
   1400027a3:	ba 00 00 00 00       	mov    edx,0x0
   1400027a8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027ad:	e8 86 6e 00 00       	call   140009638 <signal>
   1400027b2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027b6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027bb:	75 1b                	jne    1400027d8 <_gnu_exception_handler+0x14e>
   1400027bd:	ba 01 00 00 00       	mov    edx,0x1
   1400027c2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027c7:	e8 6c 6e 00 00       	call   140009638 <signal>
   1400027cc:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027d3:	e9 e1 00 00 00       	jmp    1400028b9 <_gnu_exception_handler+0x22f>
   1400027d8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027dd:	0f 84 d6 00 00 00    	je     1400028b9 <_gnu_exception_handler+0x22f>
   1400027e3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027e7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027ec:	ff d0                	call   rax
   1400027ee:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027f5:	e9 bf 00 00 00       	jmp    1400028b9 <_gnu_exception_handler+0x22f>
   1400027fa:	ba 00 00 00 00       	mov    edx,0x0
   1400027ff:	b9 04 00 00 00       	mov    ecx,0x4
   140002804:	e8 2f 6e 00 00       	call   140009638 <signal>
   140002809:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000280d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002812:	75 1b                	jne    14000282f <_gnu_exception_handler+0x1a5>
   140002814:	ba 01 00 00 00       	mov    edx,0x1
   140002819:	b9 04 00 00 00       	mov    ecx,0x4
   14000281e:	e8 15 6e 00 00       	call   140009638 <signal>
   140002823:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000282a:	e9 8d 00 00 00       	jmp    1400028bc <_gnu_exception_handler+0x232>
   14000282f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002834:	0f 84 82 00 00 00    	je     1400028bc <_gnu_exception_handler+0x232>
   14000283a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000283e:	b9 04 00 00 00       	mov    ecx,0x4
   140002843:	ff d0                	call   rax
   140002845:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000284c:	eb 6e                	jmp    1400028bc <_gnu_exception_handler+0x232>
   14000284e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002855:	ba 00 00 00 00       	mov    edx,0x0
   14000285a:	b9 08 00 00 00       	mov    ecx,0x8
   14000285f:	e8 d4 6d 00 00       	call   140009638 <signal>
   140002864:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002868:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000286d:	75 23                	jne    140002892 <_gnu_exception_handler+0x208>
   14000286f:	ba 01 00 00 00       	mov    edx,0x1
   140002874:	b9 08 00 00 00       	mov    ecx,0x8
   140002879:	e8 ba 6d 00 00       	call   140009638 <signal>
   14000287e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002882:	74 05                	je     140002889 <_gnu_exception_handler+0x1ff>
   140002884:	e8 67 03 00 00       	call   140002bf0 <_fpreset>
   140002889:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002890:	eb 2d                	jmp    1400028bf <_gnu_exception_handler+0x235>
   140002892:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002897:	74 26                	je     1400028bf <_gnu_exception_handler+0x235>
   140002899:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000289d:	b9 08 00 00 00       	mov    ecx,0x8
   1400028a2:	ff d0                	call   rax
   1400028a4:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028ab:	eb 12                	jmp    1400028bf <_gnu_exception_handler+0x235>
   1400028ad:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028b4:	eb 0a                	jmp    1400028c0 <_gnu_exception_handler+0x236>
   1400028b6:	90                   	nop
   1400028b7:	eb 07                	jmp    1400028c0 <_gnu_exception_handler+0x236>
   1400028b9:	90                   	nop
   1400028ba:	eb 04                	jmp    1400028c0 <_gnu_exception_handler+0x236>
   1400028bc:	90                   	nop
   1400028bd:	eb 01                	jmp    1400028c0 <_gnu_exception_handler+0x236>
   1400028bf:	90                   	nop
   1400028c0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400028c4:	75 1f                	jne    1400028e5 <_gnu_exception_handler+0x25b>
   1400028c6:	48 8b 05 43 c8 00 00 	mov    rax,QWORD PTR [rip+0xc843]        # 14000f110 <__mingw_oldexcpt_handler>
   1400028cd:	48 85 c0             	test   rax,rax
   1400028d0:	74 13                	je     1400028e5 <_gnu_exception_handler+0x25b>
   1400028d2:	48 8b 15 37 c8 00 00 	mov    rdx,QWORD PTR [rip+0xc837]        # 14000f110 <__mingw_oldexcpt_handler>
   1400028d9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028dd:	48 89 c1             	mov    rcx,rax
   1400028e0:	ff d2                	call   rdx
   1400028e2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400028e5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400028e8:	48 83 c4 30          	add    rsp,0x30
   1400028ec:	5d                   	pop    rbp
   1400028ed:	c3                   	ret
   1400028ee:	90                   	nop
   1400028ef:	90                   	nop

00000001400028f0 <___w64_mingwthr_add_key_dtor>:
   1400028f0:	55                   	push   rbp
   1400028f1:	48 89 e5             	mov    rbp,rsp
   1400028f4:	48 83 ec 30          	sub    rsp,0x30
   1400028f8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400028fb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400028ff:	8b 05 43 c8 00 00    	mov    eax,DWORD PTR [rip+0xc843]        # 14000f148 <__mingwthr_cs_init>
   140002905:	85 c0                	test   eax,eax
   140002907:	75 07                	jne    140002910 <___w64_mingwthr_add_key_dtor+0x20>
   140002909:	b8 00 00 00 00       	mov    eax,0x0
   14000290e:	eb 7b                	jmp    14000298b <___w64_mingwthr_add_key_dtor+0x9b>
   140002910:	ba 18 00 00 00       	mov    edx,0x18
   140002915:	b9 01 00 00 00       	mov    ecx,0x1
   14000291a:	e8 c9 6c 00 00       	call   1400095e8 <calloc>
   14000291f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002923:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002928:	75 07                	jne    140002931 <___w64_mingwthr_add_key_dtor+0x41>
   14000292a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000292f:	eb 5a                	jmp    14000298b <___w64_mingwthr_add_key_dtor+0x9b>
   140002931:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002935:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002938:	89 10                	mov    DWORD PTR [rax],edx
   14000293a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000293e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002942:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002946:	48 8d 05 d3 c7 00 00 	lea    rax,[rip+0xc7d3]        # 14000f120 <__mingwthr_cs>
   14000294d:	48 89 c1             	mov    rcx,rax
   140002950:	48 8b 05 99 d8 00 00 	mov    rax,QWORD PTR [rip+0xd899]        # 1400101f0 <__imp_EnterCriticalSection>
   140002957:	ff d0                	call   rax
   140002959:	48 8b 15 f0 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc7f0]        # 14000f150 <key_dtor_list>
   140002960:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002964:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002968:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000296c:	48 89 05 dd c7 00 00 	mov    QWORD PTR [rip+0xc7dd],rax        # 14000f150 <key_dtor_list>
   140002973:	48 8d 05 a6 c7 00 00 	lea    rax,[rip+0xc7a6]        # 14000f120 <__mingwthr_cs>
   14000297a:	48 89 c1             	mov    rcx,rax
   14000297d:	48 8b 05 a4 d8 00 00 	mov    rax,QWORD PTR [rip+0xd8a4]        # 140010228 <__imp_LeaveCriticalSection>
   140002984:	ff d0                	call   rax
   140002986:	b8 00 00 00 00       	mov    eax,0x0
   14000298b:	48 83 c4 30          	add    rsp,0x30
   14000298f:	5d                   	pop    rbp
   140002990:	c3                   	ret

0000000140002991 <___w64_mingwthr_remove_key_dtor>:
   140002991:	55                   	push   rbp
   140002992:	48 89 e5             	mov    rbp,rsp
   140002995:	48 83 ec 30          	sub    rsp,0x30
   140002999:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000299c:	8b 05 a6 c7 00 00    	mov    eax,DWORD PTR [rip+0xc7a6]        # 14000f148 <__mingwthr_cs_init>
   1400029a2:	85 c0                	test   eax,eax
   1400029a4:	75 0a                	jne    1400029b0 <___w64_mingwthr_remove_key_dtor+0x1f>
   1400029a6:	b8 00 00 00 00       	mov    eax,0x0
   1400029ab:	e9 9c 00 00 00       	jmp    140002a4c <___w64_mingwthr_remove_key_dtor+0xbb>
   1400029b0:	48 8d 05 69 c7 00 00 	lea    rax,[rip+0xc769]        # 14000f120 <__mingwthr_cs>
   1400029b7:	48 89 c1             	mov    rcx,rax
   1400029ba:	48 8b 05 2f d8 00 00 	mov    rax,QWORD PTR [rip+0xd82f]        # 1400101f0 <__imp_EnterCriticalSection>
   1400029c1:	ff d0                	call   rax
   1400029c3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400029ca:	00 
   1400029cb:	48 8b 05 7e c7 00 00 	mov    rax,QWORD PTR [rip+0xc77e]        # 14000f150 <key_dtor_list>
   1400029d2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029d6:	eb 55                	jmp    140002a2d <___w64_mingwthr_remove_key_dtor+0x9c>
   1400029d8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029dc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400029de:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   1400029e1:	75 36                	jne    140002a19 <___w64_mingwthr_remove_key_dtor+0x88>
   1400029e3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029e8:	75 11                	jne    1400029fb <___w64_mingwthr_remove_key_dtor+0x6a>
   1400029ea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ee:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   1400029f2:	48 89 05 57 c7 00 00 	mov    QWORD PTR [rip+0xc757],rax        # 14000f150 <key_dtor_list>
   1400029f9:	eb 10                	jmp    140002a0b <___w64_mingwthr_remove_key_dtor+0x7a>
   1400029fb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ff:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a03:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a07:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a0b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a0f:	48 89 c1             	mov    rcx,rax
   140002a12:	e8 f9 6b 00 00       	call   140009610 <free>
   140002a17:	eb 1b                	jmp    140002a34 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a19:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a1d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a21:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a25:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a29:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a2d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a32:	75 a4                	jne    1400029d8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a34:	48 8d 05 e5 c6 00 00 	lea    rax,[rip+0xc6e5]        # 14000f120 <__mingwthr_cs>
   140002a3b:	48 89 c1             	mov    rcx,rax
   140002a3e:	48 8b 05 e3 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7e3]        # 140010228 <__imp_LeaveCriticalSection>
   140002a45:	ff d0                	call   rax
   140002a47:	b8 00 00 00 00       	mov    eax,0x0
   140002a4c:	48 83 c4 30          	add    rsp,0x30
   140002a50:	5d                   	pop    rbp
   140002a51:	c3                   	ret

0000000140002a52 <__mingwthr_run_key_dtors>:
   140002a52:	55                   	push   rbp
   140002a53:	48 89 e5             	mov    rbp,rsp
   140002a56:	48 83 ec 30          	sub    rsp,0x30
   140002a5a:	8b 05 e8 c6 00 00    	mov    eax,DWORD PTR [rip+0xc6e8]        # 14000f148 <__mingwthr_cs_init>
   140002a60:	85 c0                	test   eax,eax
   140002a62:	0f 84 82 00 00 00    	je     140002aea <__mingwthr_run_key_dtors+0x98>
   140002a68:	48 8d 05 b1 c6 00 00 	lea    rax,[rip+0xc6b1]        # 14000f120 <__mingwthr_cs>
   140002a6f:	48 89 c1             	mov    rcx,rax
   140002a72:	48 8b 05 77 d7 00 00 	mov    rax,QWORD PTR [rip+0xd777]        # 1400101f0 <__imp_EnterCriticalSection>
   140002a79:	ff d0                	call   rax
   140002a7b:	48 8b 05 ce c6 00 00 	mov    rax,QWORD PTR [rip+0xc6ce]        # 14000f150 <key_dtor_list>
   140002a82:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a86:	eb 46                	jmp    140002ace <__mingwthr_run_key_dtors+0x7c>
   140002a88:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a8c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a8e:	89 c1                	mov    ecx,eax
   140002a90:	48 8b 05 b9 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7b9]        # 140010250 <__imp_TlsGetValue>
   140002a97:	ff d0                	call   rax
   140002a99:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a9d:	48 8b 05 64 d7 00 00 	mov    rax,QWORD PTR [rip+0xd764]        # 140010208 <__imp_GetLastError>
   140002aa4:	ff d0                	call   rax
   140002aa6:	85 c0                	test   eax,eax
   140002aa8:	75 18                	jne    140002ac2 <__mingwthr_run_key_dtors+0x70>
   140002aaa:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002aaf:	74 11                	je     140002ac2 <__mingwthr_run_key_dtors+0x70>
   140002ab1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ab5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002ab9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002abd:	48 89 c1             	mov    rcx,rax
   140002ac0:	ff d2                	call   rdx
   140002ac2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ac6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002aca:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ace:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ad3:	75 b3                	jne    140002a88 <__mingwthr_run_key_dtors+0x36>
   140002ad5:	48 8d 05 44 c6 00 00 	lea    rax,[rip+0xc644]        # 14000f120 <__mingwthr_cs>
   140002adc:	48 89 c1             	mov    rcx,rax
   140002adf:	48 8b 05 42 d7 00 00 	mov    rax,QWORD PTR [rip+0xd742]        # 140010228 <__imp_LeaveCriticalSection>
   140002ae6:	ff d0                	call   rax
   140002ae8:	eb 01                	jmp    140002aeb <__mingwthr_run_key_dtors+0x99>
   140002aea:	90                   	nop
   140002aeb:	48 83 c4 30          	add    rsp,0x30
   140002aef:	5d                   	pop    rbp
   140002af0:	c3                   	ret

0000000140002af1 <__mingw_TLScallback>:
   140002af1:	55                   	push   rbp
   140002af2:	48 89 e5             	mov    rbp,rsp
   140002af5:	48 83 ec 30          	sub    rsp,0x30
   140002af9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002afd:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b00:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b04:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b08:	0f 84 cc 00 00 00    	je     140002bda <__mingw_TLScallback+0xe9>
   140002b0e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b12:	0f 87 ca 00 00 00    	ja     140002be2 <__mingw_TLScallback+0xf1>
   140002b18:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b1c:	0f 84 b1 00 00 00    	je     140002bd3 <__mingw_TLScallback+0xe2>
   140002b22:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b26:	0f 87 b6 00 00 00    	ja     140002be2 <__mingw_TLScallback+0xf1>
   140002b2c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b30:	74 33                	je     140002b65 <__mingw_TLScallback+0x74>
   140002b32:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b36:	0f 85 a6 00 00 00    	jne    140002be2 <__mingw_TLScallback+0xf1>
   140002b3c:	8b 05 06 c6 00 00    	mov    eax,DWORD PTR [rip+0xc606]        # 14000f148 <__mingwthr_cs_init>
   140002b42:	85 c0                	test   eax,eax
   140002b44:	75 13                	jne    140002b59 <__mingw_TLScallback+0x68>
   140002b46:	48 8d 05 d3 c5 00 00 	lea    rax,[rip+0xc5d3]        # 14000f120 <__mingwthr_cs>
   140002b4d:	48 89 c1             	mov    rcx,rax
   140002b50:	48 8b 05 c9 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6c9]        # 140010220 <__imp_InitializeCriticalSection>
   140002b57:	ff d0                	call   rax
   140002b59:	c7 05 e5 c5 00 00 01 	mov    DWORD PTR [rip+0xc5e5],0x1        # 14000f148 <__mingwthr_cs_init>
   140002b60:	00 00 00 
   140002b63:	eb 7d                	jmp    140002be2 <__mingw_TLScallback+0xf1>
   140002b65:	e8 e8 fe ff ff       	call   140002a52 <__mingwthr_run_key_dtors>
   140002b6a:	8b 05 d8 c5 00 00    	mov    eax,DWORD PTR [rip+0xc5d8]        # 14000f148 <__mingwthr_cs_init>
   140002b70:	83 f8 01             	cmp    eax,0x1
   140002b73:	75 6c                	jne    140002be1 <__mingw_TLScallback+0xf0>
   140002b75:	48 8b 05 d4 c5 00 00 	mov    rax,QWORD PTR [rip+0xc5d4]        # 14000f150 <key_dtor_list>
   140002b7c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b80:	eb 20                	jmp    140002ba2 <__mingw_TLScallback+0xb1>
   140002b82:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b86:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b8a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b8e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b92:	48 89 c1             	mov    rcx,rax
   140002b95:	e8 76 6a 00 00       	call   140009610 <free>
   140002b9a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b9e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ba2:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ba7:	75 d9                	jne    140002b82 <__mingw_TLScallback+0x91>
   140002ba9:	48 c7 05 9c c5 00 00 	mov    QWORD PTR [rip+0xc59c],0x0        # 14000f150 <key_dtor_list>
   140002bb0:	00 00 00 00 
   140002bb4:	c7 05 8a c5 00 00 00 	mov    DWORD PTR [rip+0xc58a],0x0        # 14000f148 <__mingwthr_cs_init>
   140002bbb:	00 00 00 
   140002bbe:	48 8d 05 5b c5 00 00 	lea    rax,[rip+0xc55b]        # 14000f120 <__mingwthr_cs>
   140002bc5:	48 89 c1             	mov    rcx,rax
   140002bc8:	48 8b 05 19 d6 00 00 	mov    rax,QWORD PTR [rip+0xd619]        # 1400101e8 <__IAT_start__>
   140002bcf:	ff d0                	call   rax
   140002bd1:	eb 0e                	jmp    140002be1 <__mingw_TLScallback+0xf0>
   140002bd3:	e8 18 00 00 00       	call   140002bf0 <_fpreset>
   140002bd8:	eb 08                	jmp    140002be2 <__mingw_TLScallback+0xf1>
   140002bda:	e8 73 fe ff ff       	call   140002a52 <__mingwthr_run_key_dtors>
   140002bdf:	eb 01                	jmp    140002be2 <__mingw_TLScallback+0xf1>
   140002be1:	90                   	nop
   140002be2:	b8 01 00 00 00       	mov    eax,0x1
   140002be7:	48 83 c4 30          	add    rsp,0x30
   140002beb:	5d                   	pop    rbp
   140002bec:	c3                   	ret
   140002bed:	90                   	nop
   140002bee:	90                   	nop
   140002bef:	90                   	nop

0000000140002bf0 <_fpreset>:
   140002bf0:	55                   	push   rbp
   140002bf1:	48 89 e5             	mov    rbp,rsp
   140002bf4:	db e3                	fninit
   140002bf6:	90                   	nop
   140002bf7:	5d                   	pop    rbp
   140002bf8:	c3                   	ret
   140002bf9:	90                   	nop
   140002bfa:	90                   	nop
   140002bfb:	90                   	nop
   140002bfc:	90                   	nop
   140002bfd:	90                   	nop
   140002bfe:	90                   	nop
   140002bff:	90                   	nop

0000000140002c00 <_ValidateImageBase>:
   140002c00:	55                   	push   rbp
   140002c01:	48 89 e5             	mov    rbp,rsp
   140002c04:	48 83 ec 20          	sub    rsp,0x20
   140002c08:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c0c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c10:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c14:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c18:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c1b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c1f:	74 07                	je     140002c28 <_ValidateImageBase+0x28>
   140002c21:	b8 00 00 00 00       	mov    eax,0x0
   140002c26:	eb 4e                	jmp    140002c76 <_ValidateImageBase+0x76>
   140002c28:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c2c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c2f:	48 63 d0             	movsxd rdx,eax
   140002c32:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c36:	48 01 d0             	add    rax,rdx
   140002c39:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c3d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c41:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c43:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c48:	74 07                	je     140002c51 <_ValidateImageBase+0x51>
   140002c4a:	b8 00 00 00 00       	mov    eax,0x0
   140002c4f:	eb 25                	jmp    140002c76 <_ValidateImageBase+0x76>
   140002c51:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c55:	48 83 c0 18          	add    rax,0x18
   140002c59:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c5d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c61:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c64:	66 3d 0b 02          	cmp    ax,0x20b
   140002c68:	74 07                	je     140002c71 <_ValidateImageBase+0x71>
   140002c6a:	b8 00 00 00 00       	mov    eax,0x0
   140002c6f:	eb 05                	jmp    140002c76 <_ValidateImageBase+0x76>
   140002c71:	b8 01 00 00 00       	mov    eax,0x1
   140002c76:	48 83 c4 20          	add    rsp,0x20
   140002c7a:	5d                   	pop    rbp
   140002c7b:	c3                   	ret

0000000140002c7c <_FindPESection>:
   140002c7c:	55                   	push   rbp
   140002c7d:	48 89 e5             	mov    rbp,rsp
   140002c80:	48 83 ec 20          	sub    rsp,0x20
   140002c84:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c88:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002c8c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c90:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c93:	48 63 d0             	movsxd rdx,eax
   140002c96:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c9a:	48 01 d0             	add    rax,rdx
   140002c9d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ca1:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ca8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cac:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002cb0:	0f b7 d0             	movzx  edx,ax
   140002cb3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cb7:	48 01 d0             	add    rax,rdx
   140002cba:	48 83 c0 18          	add    rax,0x18
   140002cbe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cc2:	eb 36                	jmp    140002cfa <_FindPESection+0x7e>
   140002cc4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cc8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002ccb:	89 c0                	mov    eax,eax
   140002ccd:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cd1:	72 1e                	jb     140002cf1 <_FindPESection+0x75>
   140002cd3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cd7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002cda:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cde:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002ce1:	01 d0                	add    eax,edx
   140002ce3:	89 c0                	mov    eax,eax
   140002ce5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002ce9:	73 06                	jae    140002cf1 <_FindPESection+0x75>
   140002ceb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cef:	eb 1e                	jmp    140002d0f <_FindPESection+0x93>
   140002cf1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002cf5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002cfa:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cfe:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d02:	0f b7 c0             	movzx  eax,ax
   140002d05:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d08:	72 ba                	jb     140002cc4 <_FindPESection+0x48>
   140002d0a:	b8 00 00 00 00       	mov    eax,0x0
   140002d0f:	48 83 c4 20          	add    rsp,0x20
   140002d13:	5d                   	pop    rbp
   140002d14:	c3                   	ret

0000000140002d15 <_FindPESectionByName>:
   140002d15:	55                   	push   rbp
   140002d16:	48 89 e5             	mov    rbp,rsp
   140002d19:	48 83 ec 40          	sub    rsp,0x40
   140002d1d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d21:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d25:	48 89 c1             	mov    rcx,rax
   140002d28:	e8 1b 69 00 00       	call   140009648 <strlen>
   140002d2d:	48 83 f8 08          	cmp    rax,0x8
   140002d31:	76 0a                	jbe    140002d3d <_FindPESectionByName+0x28>
   140002d33:	b8 00 00 00 00       	mov    eax,0x0
   140002d38:	e9 98 00 00 00       	jmp    140002dd5 <_FindPESectionByName+0xc0>
   140002d3d:	48 8b 05 3c 88 00 00 	mov    rax,QWORD PTR [rip+0x883c]        # 14000b580 <.refptr.__ImageBase>
   140002d44:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d48:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d4c:	48 89 c1             	mov    rcx,rax
   140002d4f:	e8 ac fe ff ff       	call   140002c00 <_ValidateImageBase>
   140002d54:	85 c0                	test   eax,eax
   140002d56:	75 07                	jne    140002d5f <_FindPESectionByName+0x4a>
   140002d58:	b8 00 00 00 00       	mov    eax,0x0
   140002d5d:	eb 76                	jmp    140002dd5 <_FindPESectionByName+0xc0>
   140002d5f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d63:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d66:	48 63 d0             	movsxd rdx,eax
   140002d69:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d6d:	48 01 d0             	add    rax,rdx
   140002d70:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002d74:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d7b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d7f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d83:	0f b7 d0             	movzx  edx,ax
   140002d86:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d8a:	48 01 d0             	add    rax,rdx
   140002d8d:	48 83 c0 18          	add    rax,0x18
   140002d91:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d95:	eb 29                	jmp    140002dc0 <_FindPESectionByName+0xab>
   140002d97:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d9b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002d9f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002da5:	48 89 c1             	mov    rcx,rax
   140002da8:	e8 a3 68 00 00       	call   140009650 <strncmp>
   140002dad:	85 c0                	test   eax,eax
   140002daf:	75 06                	jne    140002db7 <_FindPESectionByName+0xa2>
   140002db1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002db5:	eb 1e                	jmp    140002dd5 <_FindPESectionByName+0xc0>
   140002db7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002dbb:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002dc0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dc4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002dc8:	0f b7 c0             	movzx  eax,ax
   140002dcb:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002dce:	72 c7                	jb     140002d97 <_FindPESectionByName+0x82>
   140002dd0:	b8 00 00 00 00       	mov    eax,0x0
   140002dd5:	48 83 c4 40          	add    rsp,0x40
   140002dd9:	5d                   	pop    rbp
   140002dda:	c3                   	ret

0000000140002ddb <__mingw_GetSectionForAddress>:
   140002ddb:	55                   	push   rbp
   140002ddc:	48 89 e5             	mov    rbp,rsp
   140002ddf:	48 83 ec 30          	sub    rsp,0x30
   140002de3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002de7:	48 8b 05 92 87 00 00 	mov    rax,QWORD PTR [rip+0x8792]        # 14000b580 <.refptr.__ImageBase>
   140002dee:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002df2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002df6:	48 89 c1             	mov    rcx,rax
   140002df9:	e8 02 fe ff ff       	call   140002c00 <_ValidateImageBase>
   140002dfe:	85 c0                	test   eax,eax
   140002e00:	75 07                	jne    140002e09 <__mingw_GetSectionForAddress+0x2e>
   140002e02:	b8 00 00 00 00       	mov    eax,0x0
   140002e07:	eb 1c                	jmp    140002e25 <__mingw_GetSectionForAddress+0x4a>
   140002e09:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e0d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e11:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e15:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e19:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e1d:	48 89 c1             	mov    rcx,rax
   140002e20:	e8 57 fe ff ff       	call   140002c7c <_FindPESection>
   140002e25:	48 83 c4 30          	add    rsp,0x30
   140002e29:	5d                   	pop    rbp
   140002e2a:	c3                   	ret

0000000140002e2b <__mingw_GetSectionCount>:
   140002e2b:	55                   	push   rbp
   140002e2c:	48 89 e5             	mov    rbp,rsp
   140002e2f:	48 83 ec 30          	sub    rsp,0x30
   140002e33:	48 8b 05 46 87 00 00 	mov    rax,QWORD PTR [rip+0x8746]        # 14000b580 <.refptr.__ImageBase>
   140002e3a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e3e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e42:	48 89 c1             	mov    rcx,rax
   140002e45:	e8 b6 fd ff ff       	call   140002c00 <_ValidateImageBase>
   140002e4a:	85 c0                	test   eax,eax
   140002e4c:	75 07                	jne    140002e55 <__mingw_GetSectionCount+0x2a>
   140002e4e:	b8 00 00 00 00       	mov    eax,0x0
   140002e53:	eb 20                	jmp    140002e75 <__mingw_GetSectionCount+0x4a>
   140002e55:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e59:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e5c:	48 63 d0             	movsxd rdx,eax
   140002e5f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e63:	48 01 d0             	add    rax,rdx
   140002e66:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e6a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e6e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e72:	0f b7 c0             	movzx  eax,ax
   140002e75:	48 83 c4 30          	add    rsp,0x30
   140002e79:	5d                   	pop    rbp
   140002e7a:	c3                   	ret

0000000140002e7b <_FindPESectionExec>:
   140002e7b:	55                   	push   rbp
   140002e7c:	48 89 e5             	mov    rbp,rsp
   140002e7f:	48 83 ec 40          	sub    rsp,0x40
   140002e83:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e87:	48 8b 05 f2 86 00 00 	mov    rax,QWORD PTR [rip+0x86f2]        # 14000b580 <.refptr.__ImageBase>
   140002e8e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e92:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e96:	48 89 c1             	mov    rcx,rax
   140002e99:	e8 62 fd ff ff       	call   140002c00 <_ValidateImageBase>
   140002e9e:	85 c0                	test   eax,eax
   140002ea0:	75 07                	jne    140002ea9 <_FindPESectionExec+0x2e>
   140002ea2:	b8 00 00 00 00       	mov    eax,0x0
   140002ea7:	eb 78                	jmp    140002f21 <_FindPESectionExec+0xa6>
   140002ea9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ead:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002eb0:	48 63 d0             	movsxd rdx,eax
   140002eb3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002eb7:	48 01 d0             	add    rax,rdx
   140002eba:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002ebe:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ec5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ec9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002ecd:	0f b7 d0             	movzx  edx,ax
   140002ed0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ed4:	48 01 d0             	add    rax,rdx
   140002ed7:	48 83 c0 18          	add    rax,0x18
   140002edb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002edf:	eb 2b                	jmp    140002f0c <_FindPESectionExec+0x91>
   140002ee1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ee5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002ee8:	25 00 00 00 20       	and    eax,0x20000000
   140002eed:	85 c0                	test   eax,eax
   140002eef:	74 12                	je     140002f03 <_FindPESectionExec+0x88>
   140002ef1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002ef6:	75 06                	jne    140002efe <_FindPESectionExec+0x83>
   140002ef8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002efc:	eb 23                	jmp    140002f21 <_FindPESectionExec+0xa6>
   140002efe:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f03:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f07:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f0c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f10:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f14:	0f b7 c0             	movzx  eax,ax
   140002f17:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f1a:	72 c5                	jb     140002ee1 <_FindPESectionExec+0x66>
   140002f1c:	b8 00 00 00 00       	mov    eax,0x0
   140002f21:	48 83 c4 40          	add    rsp,0x40
   140002f25:	5d                   	pop    rbp
   140002f26:	c3                   	ret

0000000140002f27 <_GetPEImageBase>:
   140002f27:	55                   	push   rbp
   140002f28:	48 89 e5             	mov    rbp,rsp
   140002f2b:	48 83 ec 30          	sub    rsp,0x30
   140002f2f:	48 8b 05 4a 86 00 00 	mov    rax,QWORD PTR [rip+0x864a]        # 14000b580 <.refptr.__ImageBase>
   140002f36:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f3a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f3e:	48 89 c1             	mov    rcx,rax
   140002f41:	e8 ba fc ff ff       	call   140002c00 <_ValidateImageBase>
   140002f46:	85 c0                	test   eax,eax
   140002f48:	75 07                	jne    140002f51 <_GetPEImageBase+0x2a>
   140002f4a:	b8 00 00 00 00       	mov    eax,0x0
   140002f4f:	eb 04                	jmp    140002f55 <_GetPEImageBase+0x2e>
   140002f51:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f55:	48 83 c4 30          	add    rsp,0x30
   140002f59:	5d                   	pop    rbp
   140002f5a:	c3                   	ret

0000000140002f5b <_IsNonwritableInCurrentImage>:
   140002f5b:	55                   	push   rbp
   140002f5c:	48 89 e5             	mov    rbp,rsp
   140002f5f:	48 83 ec 40          	sub    rsp,0x40
   140002f63:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f67:	48 8b 05 12 86 00 00 	mov    rax,QWORD PTR [rip+0x8612]        # 14000b580 <.refptr.__ImageBase>
   140002f6e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f76:	48 89 c1             	mov    rcx,rax
   140002f79:	e8 82 fc ff ff       	call   140002c00 <_ValidateImageBase>
   140002f7e:	85 c0                	test   eax,eax
   140002f80:	75 07                	jne    140002f89 <_IsNonwritableInCurrentImage+0x2e>
   140002f82:	b8 00 00 00 00       	mov    eax,0x0
   140002f87:	eb 3d                	jmp    140002fc6 <_IsNonwritableInCurrentImage+0x6b>
   140002f89:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f8d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002f91:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f95:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002f99:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f9d:	48 89 c1             	mov    rcx,rax
   140002fa0:	e8 d7 fc ff ff       	call   140002c7c <_FindPESection>
   140002fa5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002fa9:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002fae:	75 07                	jne    140002fb7 <_IsNonwritableInCurrentImage+0x5c>
   140002fb0:	b8 00 00 00 00       	mov    eax,0x0
   140002fb5:	eb 0f                	jmp    140002fc6 <_IsNonwritableInCurrentImage+0x6b>
   140002fb7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002fbb:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fbe:	f7 d0                	not    eax
   140002fc0:	c1 e8 1f             	shr    eax,0x1f
   140002fc3:	0f b6 c0             	movzx  eax,al
   140002fc6:	48 83 c4 40          	add    rsp,0x40
   140002fca:	5d                   	pop    rbp
   140002fcb:	c3                   	ret

0000000140002fcc <__mingw_enum_import_library_names>:
   140002fcc:	55                   	push   rbp
   140002fcd:	48 89 e5             	mov    rbp,rsp
   140002fd0:	48 83 ec 50          	sub    rsp,0x50
   140002fd4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002fd7:	48 8b 05 a2 85 00 00 	mov    rax,QWORD PTR [rip+0x85a2]        # 14000b580 <.refptr.__ImageBase>
   140002fde:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fe2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002fe6:	48 89 c1             	mov    rcx,rax
   140002fe9:	e8 12 fc ff ff       	call   140002c00 <_ValidateImageBase>
   140002fee:	85 c0                	test   eax,eax
   140002ff0:	75 0a                	jne    140002ffc <__mingw_enum_import_library_names+0x30>
   140002ff2:	b8 00 00 00 00       	mov    eax,0x0
   140002ff7:	e9 ab 00 00 00       	jmp    1400030a7 <__mingw_enum_import_library_names+0xdb>
   140002ffc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003000:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003003:	48 63 d0             	movsxd rdx,eax
   140003006:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000300a:	48 01 d0             	add    rax,rdx
   14000300d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003011:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003015:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000301b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000301e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003022:	75 07                	jne    14000302b <__mingw_enum_import_library_names+0x5f>
   140003024:	b8 00 00 00 00       	mov    eax,0x0
   140003029:	eb 7c                	jmp    1400030a7 <__mingw_enum_import_library_names+0xdb>
   14000302b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000302e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003032:	48 89 c1             	mov    rcx,rax
   140003035:	e8 42 fc ff ff       	call   140002c7c <_FindPESection>
   14000303a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000303e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003043:	75 07                	jne    14000304c <__mingw_enum_import_library_names+0x80>
   140003045:	b8 00 00 00 00       	mov    eax,0x0
   14000304a:	eb 5b                	jmp    1400030a7 <__mingw_enum_import_library_names+0xdb>
   14000304c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000304f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003053:	48 01 d0             	add    rax,rdx
   140003056:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000305a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000305f:	75 07                	jne    140003068 <__mingw_enum_import_library_names+0x9c>
   140003061:	b8 00 00 00 00       	mov    eax,0x0
   140003066:	eb 3f                	jmp    1400030a7 <__mingw_enum_import_library_names+0xdb>
   140003068:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000306c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000306f:	85 c0                	test   eax,eax
   140003071:	75 0b                	jne    14000307e <__mingw_enum_import_library_names+0xb2>
   140003073:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003077:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000307a:	85 c0                	test   eax,eax
   14000307c:	74 23                	je     1400030a1 <__mingw_enum_import_library_names+0xd5>
   14000307e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003082:	7f 12                	jg     140003096 <__mingw_enum_import_library_names+0xca>
   140003084:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003088:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000308b:	89 c2                	mov    edx,eax
   14000308d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003091:	48 01 d0             	add    rax,rdx
   140003094:	eb 11                	jmp    1400030a7 <__mingw_enum_import_library_names+0xdb>
   140003096:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000309a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000309f:	eb c7                	jmp    140003068 <__mingw_enum_import_library_names+0x9c>
   1400030a1:	90                   	nop
   1400030a2:	b8 00 00 00 00       	mov    eax,0x0
   1400030a7:	48 83 c4 50          	add    rsp,0x50
   1400030ab:	5d                   	pop    rbp
   1400030ac:	c3                   	ret
   1400030ad:	90                   	nop
   1400030ae:	90                   	nop
   1400030af:	90                   	nop

00000001400030b0 <___chkstk_ms>:
   1400030b0:	51                   	push   rcx
   1400030b1:	50                   	push   rax
   1400030b2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030b8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400030bd:	72 19                	jb     1400030d8 <___chkstk_ms+0x28>
   1400030bf:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400030c6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030ca:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400030d0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030d6:	77 e7                	ja     1400030bf <___chkstk_ms+0xf>
   1400030d8:	48 29 c1             	sub    rcx,rax
   1400030db:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030df:	58                   	pop    rax
   1400030e0:	59                   	pop    rcx
   1400030e1:	c3                   	ret
   1400030e2:	90                   	nop
   1400030e3:	90                   	nop
   1400030e4:	90                   	nop
   1400030e5:	90                   	nop
   1400030e6:	90                   	nop
   1400030e7:	90                   	nop
   1400030e8:	90                   	nop
   1400030e9:	90                   	nop
   1400030ea:	90                   	nop
   1400030eb:	90                   	nop
   1400030ec:	90                   	nop
   1400030ed:	90                   	nop
   1400030ee:	90                   	nop
   1400030ef:	90                   	nop

00000001400030f0 <__mingw_vprintf>:
   1400030f0:	55                   	push   rbp
   1400030f1:	53                   	push   rbx
   1400030f2:	48 83 ec 38          	sub    rsp,0x38
   1400030f6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   1400030fb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400030ff:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140003103:	b9 01 00 00 00       	mov    ecx,0x1
   140003108:	e8 c3 5e 00 00       	call   140008fd0 <__acrt_iob_func>
   14000310d:	48 89 c1             	mov    rcx,rax
   140003110:	e8 3b 5d 00 00       	call   140008e50 <_lock_file>
   140003115:	b9 01 00 00 00       	mov    ecx,0x1
   14000311a:	e8 b1 5e 00 00       	call   140008fd0 <__acrt_iob_func>
   14000311f:	48 89 c2             	mov    rdx,rax
   140003122:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003126:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000312a:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
   14000312f:	49 89 c9             	mov    r9,rcx
   140003132:	41 b8 00 00 00 00    	mov    r8d,0x0
   140003138:	b9 00 60 00 00       	mov    ecx,0x6000
   14000313d:	e8 b1 1f 00 00       	call   1400050f3 <__mingw_pformat>
   140003142:	89 c3                	mov    ebx,eax
   140003144:	b9 01 00 00 00       	mov    ecx,0x1
   140003149:	e8 82 5e 00 00       	call   140008fd0 <__acrt_iob_func>
   14000314e:	48 89 c1             	mov    rcx,rax
   140003151:	e8 84 5d 00 00       	call   140008eda <_unlock_file>
   140003156:	89 d8                	mov    eax,ebx
   140003158:	48 83 c4 38          	add    rsp,0x38
   14000315c:	5b                   	pop    rbx
   14000315d:	5d                   	pop    rbp
   14000315e:	c3                   	ret
   14000315f:	90                   	nop

0000000140003160 <__pformat_putc>:
   140003160:	55                   	push   rbp
   140003161:	48 89 e5             	mov    rbp,rsp
   140003164:	48 83 ec 20          	sub    rsp,0x20
   140003168:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000316b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000316f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003173:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003176:	25 00 40 00 00       	and    eax,0x4000
   14000317b:	85 c0                	test   eax,eax
   14000317d:	75 12                	jne    140003191 <__pformat_putc+0x31>
   14000317f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003183:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   140003186:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000318a:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000318d:	39 c2                	cmp    edx,eax
   14000318f:	7e 3b                	jle    1400031cc <__pformat_putc+0x6c>
   140003191:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003195:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003198:	25 00 20 00 00       	and    eax,0x2000
   14000319d:	85 c0                	test   eax,eax
   14000319f:	74 13                	je     1400031b4 <__pformat_putc+0x54>
   1400031a1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031a5:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400031a8:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400031ab:	89 c1                	mov    ecx,eax
   1400031ad:	e8 56 64 00 00       	call   140009608 <fputc>
   1400031b2:	eb 18                	jmp    1400031cc <__pformat_putc+0x6c>
   1400031b4:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031b8:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400031bb:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031bf:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031c2:	48 98                	cdqe
   1400031c4:	48 01 d0             	add    rax,rdx
   1400031c7:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400031ca:	88 10                	mov    BYTE PTR [rax],dl
   1400031cc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031d0:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031d3:	8d 50 01             	lea    edx,[rax+0x1]
   1400031d6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031da:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   1400031dd:	90                   	nop
   1400031de:	48 83 c4 20          	add    rsp,0x20
   1400031e2:	5d                   	pop    rbp
   1400031e3:	c3                   	ret

00000001400031e4 <__pformat_putchars>:
   1400031e4:	55                   	push   rbp
   1400031e5:	48 89 e5             	mov    rbp,rsp
   1400031e8:	48 83 ec 20          	sub    rsp,0x20
   1400031ec:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400031f0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400031f3:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400031f7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400031fb:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400031fe:	85 c0                	test   eax,eax
   140003200:	78 16                	js     140003218 <__pformat_putchars+0x34>
   140003202:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003206:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003209:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000320c:	7e 0a                	jle    140003218 <__pformat_putchars+0x34>
   14000320e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003212:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003215:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003218:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000321c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000321f:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003222:	7d 15                	jge    140003239 <__pformat_putchars+0x55>
   140003224:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003228:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000322b:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000322e:	89 c2                	mov    edx,eax
   140003230:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003234:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003237:	eb 0b                	jmp    140003244 <__pformat_putchars+0x60>
   140003239:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000323d:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003244:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003248:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000324b:	85 c0                	test   eax,eax
   14000324d:	7e 57                	jle    1400032a6 <__pformat_putchars+0xc2>
   14000324f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003253:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003256:	25 00 04 00 00       	and    eax,0x400
   14000325b:	85 c0                	test   eax,eax
   14000325d:	75 47                	jne    1400032a6 <__pformat_putchars+0xc2>
   14000325f:	eb 11                	jmp    140003272 <__pformat_putchars+0x8e>
   140003261:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003265:	48 89 c2             	mov    rdx,rax
   140003268:	b9 20 00 00 00       	mov    ecx,0x20
   14000326d:	e8 ee fe ff ff       	call   140003160 <__pformat_putc>
   140003272:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003276:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003279:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000327c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003280:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003283:	85 c0                	test   eax,eax
   140003285:	75 da                	jne    140003261 <__pformat_putchars+0x7d>
   140003287:	eb 1d                	jmp    1400032a6 <__pformat_putchars+0xc2>
   140003289:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000328d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003291:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003295:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003298:	0f be c0             	movsx  eax,al
   14000329b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000329f:	89 c1                	mov    ecx,eax
   1400032a1:	e8 ba fe ff ff       	call   140003160 <__pformat_putc>
   1400032a6:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400032a9:	8d 50 ff             	lea    edx,[rax-0x1]
   1400032ac:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400032af:	85 c0                	test   eax,eax
   1400032b1:	75 d6                	jne    140003289 <__pformat_putchars+0xa5>
   1400032b3:	eb 11                	jmp    1400032c6 <__pformat_putchars+0xe2>
   1400032b5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032b9:	48 89 c2             	mov    rdx,rax
   1400032bc:	b9 20 00 00 00       	mov    ecx,0x20
   1400032c1:	e8 9a fe ff ff       	call   140003160 <__pformat_putc>
   1400032c6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032ca:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032cd:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400032d0:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400032d4:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400032d7:	85 c0                	test   eax,eax
   1400032d9:	7f da                	jg     1400032b5 <__pformat_putchars+0xd1>
   1400032db:	90                   	nop
   1400032dc:	90                   	nop
   1400032dd:	48 83 c4 20          	add    rsp,0x20
   1400032e1:	5d                   	pop    rbp
   1400032e2:	c3                   	ret

00000001400032e3 <__pformat_puts>:
   1400032e3:	55                   	push   rbp
   1400032e4:	48 89 e5             	mov    rbp,rsp
   1400032e7:	48 83 ec 20          	sub    rsp,0x20
   1400032eb:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400032ef:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400032f3:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400032f8:	75 0b                	jne    140003305 <__pformat_puts+0x22>
   1400032fa:	48 8d 05 2f 80 00 00 	lea    rax,[rip+0x802f]        # 14000b330 <.rdata>
   140003301:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003305:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003309:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000330c:	85 c0                	test   eax,eax
   14000330e:	78 2f                	js     14000333f <__pformat_puts+0x5c>
   140003310:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003314:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003317:	48 63 d0             	movsxd rdx,eax
   14000331a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000331e:	48 89 c1             	mov    rcx,rax
   140003321:	e8 4a 5a 00 00       	call   140008d70 <strnlen>
   140003326:	89 c1                	mov    ecx,eax
   140003328:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000332c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003330:	49 89 d0             	mov    r8,rdx
   140003333:	89 ca                	mov    edx,ecx
   140003335:	48 89 c1             	mov    rcx,rax
   140003338:	e8 a7 fe ff ff       	call   1400031e4 <__pformat_putchars>
   14000333d:	eb 23                	jmp    140003362 <__pformat_puts+0x7f>
   14000333f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003343:	48 89 c1             	mov    rcx,rax
   140003346:	e8 fd 62 00 00       	call   140009648 <strlen>
   14000334b:	89 c1                	mov    ecx,eax
   14000334d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003351:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003355:	49 89 d0             	mov    r8,rdx
   140003358:	89 ca                	mov    edx,ecx
   14000335a:	48 89 c1             	mov    rcx,rax
   14000335d:	e8 82 fe ff ff       	call   1400031e4 <__pformat_putchars>
   140003362:	90                   	nop
   140003363:	48 83 c4 20          	add    rsp,0x20
   140003367:	5d                   	pop    rbp
   140003368:	c3                   	ret

0000000140003369 <__pformat_wputchars>:
   140003369:	55                   	push   rbp
   14000336a:	48 89 e5             	mov    rbp,rsp
   14000336d:	48 83 ec 50          	sub    rsp,0x50
   140003371:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003375:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003378:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000337c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   140003383:	00 
   140003384:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003388:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000338b:	85 c0                	test   eax,eax
   14000338d:	78 16                	js     1400033a5 <__pformat_wputchars+0x3c>
   14000338f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003393:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003396:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003399:	7e 0a                	jle    1400033a5 <__pformat_wputchars+0x3c>
   14000339b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000339f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033a2:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400033a5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033a9:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033ac:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400033af:	7d 15                	jge    1400033c6 <__pformat_wputchars+0x5d>
   1400033b1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033b5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033b8:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400033bb:	89 c2                	mov    edx,eax
   1400033bd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033c1:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400033c4:	eb 0b                	jmp    1400033d1 <__pformat_wputchars+0x68>
   1400033c6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033ca:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400033d1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033d5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033d8:	85 c0                	test   eax,eax
   1400033da:	7e 6e                	jle    14000344a <__pformat_wputchars+0xe1>
   1400033dc:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033e0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400033e3:	25 00 04 00 00       	and    eax,0x400
   1400033e8:	85 c0                	test   eax,eax
   1400033ea:	75 5e                	jne    14000344a <__pformat_wputchars+0xe1>
   1400033ec:	eb 11                	jmp    1400033ff <__pformat_wputchars+0x96>
   1400033ee:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033f2:	48 89 c2             	mov    rdx,rax
   1400033f5:	b9 20 00 00 00       	mov    ecx,0x20
   1400033fa:	e8 61 fd ff ff       	call   140003160 <__pformat_putc>
   1400033ff:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003403:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003406:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003409:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000340d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003410:	85 c0                	test   eax,eax
   140003412:	75 da                	jne    1400033ee <__pformat_wputchars+0x85>
   140003414:	eb 34                	jmp    14000344a <__pformat_wputchars+0xe1>
   140003416:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   14000341a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000341e:	eb 1d                	jmp    14000343d <__pformat_wputchars+0xd4>
   140003420:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003424:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003428:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000342c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000342f:	0f be c0             	movsx  eax,al
   140003432:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003436:	89 c1                	mov    ecx,eax
   140003438:	e8 23 fd ff ff       	call   140003160 <__pformat_putc>
   14000343d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003440:	8d 50 ff             	lea    edx,[rax-0x1]
   140003443:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003446:	85 c0                	test   eax,eax
   140003448:	7f d6                	jg     140003420 <__pformat_wputchars+0xb7>
   14000344a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000344d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003450:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003453:	85 c0                	test   eax,eax
   140003455:	7e 41                	jle    140003498 <__pformat_wputchars+0x12f>
   140003457:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000345b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000345f:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003463:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140003466:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   14000346a:	0f b7 d0             	movzx  edx,ax
   14000346d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003471:	49 89 c8             	mov    r8,rcx
   140003474:	48 89 c1             	mov    rcx,rax
   140003477:	e8 84 5b 00 00       	call   140009000 <wcrtomb>
   14000347c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000347f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003483:	7f 91                	jg     140003416 <__pformat_wputchars+0xad>
   140003485:	eb 11                	jmp    140003498 <__pformat_wputchars+0x12f>
   140003487:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000348b:	48 89 c2             	mov    rdx,rax
   14000348e:	b9 20 00 00 00       	mov    ecx,0x20
   140003493:	e8 c8 fc ff ff       	call   140003160 <__pformat_putc>
   140003498:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000349c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000349f:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400034a2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034a6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400034a9:	85 c0                	test   eax,eax
   1400034ab:	7f da                	jg     140003487 <__pformat_wputchars+0x11e>
   1400034ad:	90                   	nop
   1400034ae:	90                   	nop
   1400034af:	48 83 c4 50          	add    rsp,0x50
   1400034b3:	5d                   	pop    rbp
   1400034b4:	c3                   	ret

00000001400034b5 <__pformat_wcputs>:
   1400034b5:	55                   	push   rbp
   1400034b6:	48 89 e5             	mov    rbp,rsp
   1400034b9:	48 83 ec 20          	sub    rsp,0x20
   1400034bd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400034c1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400034c5:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400034ca:	75 0b                	jne    1400034d7 <__pformat_wcputs+0x22>
   1400034cc:	48 8d 05 65 7e 00 00 	lea    rax,[rip+0x7e65]        # 14000b338 <.rdata+0x8>
   1400034d3:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400034d7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400034db:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400034de:	85 c0                	test   eax,eax
   1400034e0:	78 2f                	js     140003511 <__pformat_wcputs+0x5c>
   1400034e2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400034e6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400034e9:	48 63 d0             	movsxd rdx,eax
   1400034ec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400034f0:	48 89 c1             	mov    rcx,rax
   1400034f3:	e8 28 58 00 00       	call   140008d20 <wcsnlen>
   1400034f8:	89 c1                	mov    ecx,eax
   1400034fa:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400034fe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003502:	49 89 d0             	mov    r8,rdx
   140003505:	89 ca                	mov    edx,ecx
   140003507:	48 89 c1             	mov    rcx,rax
   14000350a:	e8 5a fe ff ff       	call   140003369 <__pformat_wputchars>
   14000350f:	eb 23                	jmp    140003534 <__pformat_wcputs+0x7f>
   140003511:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003515:	48 89 c1             	mov    rcx,rax
   140003518:	e8 43 61 00 00       	call   140009660 <wcslen>
   14000351d:	89 c1                	mov    ecx,eax
   14000351f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003523:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003527:	49 89 d0             	mov    r8,rdx
   14000352a:	89 ca                	mov    edx,ecx
   14000352c:	48 89 c1             	mov    rcx,rax
   14000352f:	e8 35 fe ff ff       	call   140003369 <__pformat_wputchars>
   140003534:	90                   	nop
   140003535:	48 83 c4 20          	add    rsp,0x20
   140003539:	5d                   	pop    rbp
   14000353a:	c3                   	ret

000000014000353b <__pformat_int_bufsiz>:
   14000353b:	55                   	push   rbp
   14000353c:	48 89 e5             	mov    rbp,rsp
   14000353f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003542:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003545:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003549:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000354c:	83 e8 01             	sub    eax,0x1
   14000354f:	48 98                	cdqe
   140003551:	48 83 c0 40          	add    rax,0x40
   140003555:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140003558:	48 63 ca             	movsxd rcx,edx
   14000355b:	ba 00 00 00 00       	mov    edx,0x0
   140003560:	48 f7 f1             	div    rcx
   140003563:	89 c2                	mov    edx,eax
   140003565:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140003568:	01 d0                	add    eax,edx
   14000356a:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   14000356d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003571:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003574:	ba 00 00 00 00       	mov    edx,0x0
   140003579:	85 c0                	test   eax,eax
   14000357b:	0f 48 c2             	cmovs  eax,edx
   14000357e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   140003581:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003585:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003588:	25 00 10 00 00       	and    eax,0x1000
   14000358d:	85 c0                	test   eax,eax
   14000358f:	74 29                	je     1400035ba <__pformat_int_bufsiz+0x7f>
   140003591:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003595:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003599:	66 85 c0             	test   ax,ax
   14000359c:	74 1c                	je     1400035ba <__pformat_int_bufsiz+0x7f>
   14000359e:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035a1:	48 63 d0             	movsxd rdx,eax
   1400035a4:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   1400035ab:	48 89 d1             	mov    rcx,rdx
   1400035ae:	48 c1 e9 20          	shr    rcx,0x20
   1400035b2:	99                   	cdq
   1400035b3:	89 c8                	mov    eax,ecx
   1400035b5:	29 d0                	sub    eax,edx
   1400035b7:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   1400035ba:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035be:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400035c1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035c4:	39 c2                	cmp    edx,eax
   1400035c6:	0f 4d c2             	cmovge eax,edx
   1400035c9:	5d                   	pop    rbp
   1400035ca:	c3                   	ret

00000001400035cb <__pformat_int>:
   1400035cb:	55                   	push   rbp
   1400035cc:	53                   	push   rbx
   1400035cd:	48 83 ec 58          	sub    rsp,0x58
   1400035d1:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400035d6:	48 89 cb             	mov    rbx,rcx
   1400035d9:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   1400035dc:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   1400035e0:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   1400035e4:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   1400035e8:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400035ec:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400035f0:	49 89 c0             	mov    r8,rax
   1400035f3:	ba 03 00 00 00       	mov    edx,0x3
   1400035f8:	b9 01 00 00 00       	mov    ecx,0x1
   1400035fd:	e8 39 ff ff ff       	call   14000353b <__pformat_int_bufsiz>
   140003602:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140003605:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   14000360c:	00 
   14000360d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140003610:	48 98                	cdqe
   140003612:	48 83 c0 0f          	add    rax,0xf
   140003616:	48 c1 e8 04          	shr    rax,0x4
   14000361a:	48 c1 e0 04          	shl    rax,0x4
   14000361e:	e8 8d fa ff ff       	call   1400030b0 <___chkstk_ms>
   140003623:	48 29 c4             	sub    rsp,rax
   140003626:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000362b:	48 83 c0 0f          	add    rax,0xf
   14000362f:	48 c1 e8 04          	shr    rax,0x4
   140003633:	48 c1 e0 04          	shl    rax,0x4
   140003637:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000363b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000363f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003643:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003647:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000364a:	25 80 00 00 00       	and    eax,0x80
   14000364f:	85 c0                	test   eax,eax
   140003651:	0f 84 ea 00 00 00    	je     140003741 <__pformat_int+0x176>
   140003657:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000365b:	48 85 c0             	test   rax,rax
   14000365e:	79 10                	jns    140003670 <__pformat_int+0xa5>
   140003660:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003664:	48 f7 d8             	neg    rax
   140003667:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000366b:	e9 d1 00 00 00       	jmp    140003741 <__pformat_int+0x176>
   140003670:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003674:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003677:	24 7f                	and    al,0x7f
   140003679:	89 c2                	mov    edx,eax
   14000367b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000367f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003682:	e9 ba 00 00 00       	jmp    140003741 <__pformat_int+0x176>
   140003687:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000368b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000368f:	74 54                	je     1400036e5 <__pformat_int+0x11a>
   140003691:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003695:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003698:	25 00 10 00 00       	and    eax,0x1000
   14000369d:	85 c0                	test   eax,eax
   14000369f:	74 44                	je     1400036e5 <__pformat_int+0x11a>
   1400036a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036a5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400036a9:	66 85 c0             	test   ax,ax
   1400036ac:	74 37                	je     1400036e5 <__pformat_int+0x11a>
   1400036ae:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036b2:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400036b6:	48 89 c2             	mov    rdx,rax
   1400036b9:	48 89 d0             	mov    rax,rdx
   1400036bc:	48 c1 f8 3f          	sar    rax,0x3f
   1400036c0:	48 c1 e8 3e          	shr    rax,0x3e
   1400036c4:	48 01 c2             	add    rdx,rax
   1400036c7:	83 e2 03             	and    edx,0x3
   1400036ca:	48 29 c2             	sub    rdx,rax
   1400036cd:	48 89 d0             	mov    rax,rdx
   1400036d0:	48 83 f8 03          	cmp    rax,0x3
   1400036d4:	75 0f                	jne    1400036e5 <__pformat_int+0x11a>
   1400036d6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036da:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400036de:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400036e2:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   1400036e5:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   1400036e9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400036f0:	cc cc cc 
   1400036f3:	48 89 c8             	mov    rax,rcx
   1400036f6:	48 f7 e2             	mul    rdx
   1400036f9:	48 c1 ea 03          	shr    rdx,0x3
   1400036fd:	48 89 d0             	mov    rax,rdx
   140003700:	48 c1 e0 02          	shl    rax,0x2
   140003704:	48 01 d0             	add    rax,rdx
   140003707:	48 01 c0             	add    rax,rax
   14000370a:	48 29 c1             	sub    rcx,rax
   14000370d:	48 89 ca             	mov    rdx,rcx
   140003710:	89 d0                	mov    eax,edx
   140003712:	8d 48 30             	lea    ecx,[rax+0x30]
   140003715:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003719:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000371d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003721:	89 ca                	mov    edx,ecx
   140003723:	88 10                	mov    BYTE PTR [rax],dl
   140003725:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003729:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003730:	cc cc cc 
   140003733:	48 f7 e2             	mul    rdx
   140003736:	48 89 d0             	mov    rax,rdx
   140003739:	48 c1 e8 03          	shr    rax,0x3
   14000373d:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140003741:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003745:	48 85 c0             	test   rax,rax
   140003748:	0f 85 39 ff ff ff    	jne    140003687 <__pformat_int+0xbc>
   14000374e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003752:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003755:	85 c0                	test   eax,eax
   140003757:	7e 3e                	jle    140003797 <__pformat_int+0x1cc>
   140003759:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000375d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003760:	89 c1                	mov    ecx,eax
   140003762:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003766:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000376a:	89 c2                	mov    edx,eax
   14000376c:	89 c8                	mov    eax,ecx
   14000376e:	29 d0                	sub    eax,edx
   140003770:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003773:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003777:	7e 1e                	jle    140003797 <__pformat_int+0x1cc>
   140003779:	eb 0f                	jmp    14000378a <__pformat_int+0x1bf>
   14000377b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000377f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003783:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003787:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000378a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000378d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003790:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   140003793:	85 c0                	test   eax,eax
   140003795:	7f e4                	jg     14000377b <__pformat_int+0x1b0>
   140003797:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000379b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000379f:	75 1a                	jne    1400037bb <__pformat_int+0x1f0>
   1400037a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037a5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400037a8:	85 c0                	test   eax,eax
   1400037aa:	74 0f                	je     1400037bb <__pformat_int+0x1f0>
   1400037ac:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037b0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037b4:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037b8:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400037bb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037bf:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037c2:	85 c0                	test   eax,eax
   1400037c4:	0f 8e ce 00 00 00    	jle    140003898 <__pformat_int+0x2cd>
   1400037ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037ce:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037d1:	89 c1                	mov    ecx,eax
   1400037d3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037d7:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400037db:	89 c2                	mov    edx,eax
   1400037dd:	89 c8                	mov    eax,ecx
   1400037df:	29 d0                	sub    eax,edx
   1400037e1:	89 c2                	mov    edx,eax
   1400037e3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037e7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400037ea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037ee:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037f1:	85 c0                	test   eax,eax
   1400037f3:	0f 8e 9f 00 00 00    	jle    140003898 <__pformat_int+0x2cd>
   1400037f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037fd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003800:	25 c0 01 00 00       	and    eax,0x1c0
   140003805:	85 c0                	test   eax,eax
   140003807:	74 11                	je     14000381a <__pformat_int+0x24f>
   140003809:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000380d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003810:	8d 50 ff             	lea    edx,[rax-0x1]
   140003813:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003817:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000381a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000381e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003821:	85 c0                	test   eax,eax
   140003823:	79 3b                	jns    140003860 <__pformat_int+0x295>
   140003825:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003829:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000382c:	25 00 06 00 00       	and    eax,0x600
   140003831:	3d 00 02 00 00       	cmp    eax,0x200
   140003836:	75 28                	jne    140003860 <__pformat_int+0x295>
   140003838:	eb 0f                	jmp    140003849 <__pformat_int+0x27e>
   14000383a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000383e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003842:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003846:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003849:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000384d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003850:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003853:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003857:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000385a:	85 c0                	test   eax,eax
   14000385c:	7f dc                	jg     14000383a <__pformat_int+0x26f>
   14000385e:	eb 38                	jmp    140003898 <__pformat_int+0x2cd>
   140003860:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003864:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003867:	25 00 04 00 00       	and    eax,0x400
   14000386c:	85 c0                	test   eax,eax
   14000386e:	75 28                	jne    140003898 <__pformat_int+0x2cd>
   140003870:	eb 11                	jmp    140003883 <__pformat_int+0x2b8>
   140003872:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003876:	48 89 c2             	mov    rdx,rax
   140003879:	b9 20 00 00 00       	mov    ecx,0x20
   14000387e:	e8 dd f8 ff ff       	call   140003160 <__pformat_putc>
   140003883:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003887:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000388a:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000388d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003891:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003894:	85 c0                	test   eax,eax
   140003896:	7f da                	jg     140003872 <__pformat_int+0x2a7>
   140003898:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000389c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000389f:	25 80 00 00 00       	and    eax,0x80
   1400038a4:	85 c0                	test   eax,eax
   1400038a6:	74 11                	je     1400038b9 <__pformat_int+0x2ee>
   1400038a8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038ac:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038b0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038b4:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   1400038b7:	eb 5a                	jmp    140003913 <__pformat_int+0x348>
   1400038b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038bd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038c0:	25 00 01 00 00       	and    eax,0x100
   1400038c5:	85 c0                	test   eax,eax
   1400038c7:	74 11                	je     1400038da <__pformat_int+0x30f>
   1400038c9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038cd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038d1:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038d5:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400038d8:	eb 39                	jmp    140003913 <__pformat_int+0x348>
   1400038da:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038de:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038e1:	83 e0 40             	and    eax,0x40
   1400038e4:	85 c0                	test   eax,eax
   1400038e6:	74 2b                	je     140003913 <__pformat_int+0x348>
   1400038e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038ec:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038f0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038f4:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400038f7:	eb 1a                	jmp    140003913 <__pformat_int+0x348>
   1400038f9:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   1400038fe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003902:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003905:	0f be c0             	movsx  eax,al
   140003908:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000390c:	89 c1                	mov    ecx,eax
   14000390e:	e8 4d f8 ff ff       	call   140003160 <__pformat_putc>
   140003913:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003917:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   14000391b:	72 dc                	jb     1400038f9 <__pformat_int+0x32e>
   14000391d:	eb 11                	jmp    140003930 <__pformat_int+0x365>
   14000391f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003923:	48 89 c2             	mov    rdx,rax
   140003926:	b9 20 00 00 00       	mov    ecx,0x20
   14000392b:	e8 30 f8 ff ff       	call   140003160 <__pformat_putc>
   140003930:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003934:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003937:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000393a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000393e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003941:	85 c0                	test   eax,eax
   140003943:	7f da                	jg     14000391f <__pformat_int+0x354>
   140003945:	90                   	nop
   140003946:	90                   	nop
   140003947:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   14000394b:	5b                   	pop    rbx
   14000394c:	5d                   	pop    rbp
   14000394d:	c3                   	ret

000000014000394e <__pformat_xint>:
   14000394e:	55                   	push   rbp
   14000394f:	53                   	push   rbx
   140003950:	48 83 ec 68          	sub    rsp,0x68
   140003954:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003959:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   14000395c:	48 89 d3             	mov    rbx,rdx
   14000395f:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140003962:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   140003966:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   14000396a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   14000396e:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003972:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003976:	74 1e                	je     140003996 <__pformat_xint+0x48>
   140003978:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   14000397c:	74 06                	je     140003984 <__pformat_xint+0x36>
   14000397e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003982:	75 09                	jne    14000398d <__pformat_xint+0x3f>
   140003984:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000398b:	eb 10                	jmp    14000399d <__pformat_xint+0x4f>
   14000398d:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003994:	eb 07                	jmp    14000399d <__pformat_xint+0x4f>
   140003996:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   14000399d:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   1400039a1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400039a4:	49 89 d0             	mov    r8,rdx
   1400039a7:	89 c2                	mov    edx,eax
   1400039a9:	b9 02 00 00 00       	mov    ecx,0x2
   1400039ae:	e8 88 fb ff ff       	call   14000353b <__pformat_int_bufsiz>
   1400039b3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400039b6:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   1400039bd:	00 
   1400039be:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400039c1:	48 98                	cdqe
   1400039c3:	48 83 c0 0f          	add    rax,0xf
   1400039c7:	48 c1 e8 04          	shr    rax,0x4
   1400039cb:	48 c1 e0 04          	shl    rax,0x4
   1400039cf:	e8 dc f6 ff ff       	call   1400030b0 <___chkstk_ms>
   1400039d4:	48 29 c4             	sub    rsp,rax
   1400039d7:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400039dc:	48 83 c0 0f          	add    rax,0xf
   1400039e0:	48 c1 e8 04          	shr    rax,0x4
   1400039e4:	48 c1 e0 04          	shl    rax,0x4
   1400039e8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400039ec:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400039f0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400039f4:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   1400039f8:	74 1e                	je     140003a18 <__pformat_xint+0xca>
   1400039fa:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   1400039fe:	74 06                	je     140003a06 <__pformat_xint+0xb8>
   140003a00:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a04:	75 09                	jne    140003a0f <__pformat_xint+0xc1>
   140003a06:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003a0d:	eb 10                	jmp    140003a1f <__pformat_xint+0xd1>
   140003a0f:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003a16:	eb 67                	jmp    140003a7f <__pformat_xint+0x131>
   140003a18:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003a1f:	eb 5e                	jmp    140003a7f <__pformat_xint+0x131>
   140003a21:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003a25:	89 c2                	mov    edx,eax
   140003a27:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003a2a:	21 d0                	and    eax,edx
   140003a2c:	8d 48 30             	lea    ecx,[rax+0x30]
   140003a2f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003a33:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003a37:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003a3b:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003a3f:	89 ca                	mov    edx,ecx
   140003a41:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a45:	88 10                	mov    BYTE PTR [rax],dl
   140003a47:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a4b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a4e:	3c 39                	cmp    al,0x39
   140003a50:	7e 1a                	jle    140003a6c <__pformat_xint+0x11e>
   140003a52:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a56:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a59:	83 c0 07             	add    eax,0x7
   140003a5c:	89 c2                	mov    edx,eax
   140003a5e:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003a61:	83 e0 20             	and    eax,0x20
   140003a64:	09 c2                	or     edx,eax
   140003a66:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a6a:	88 10                	mov    BYTE PTR [rax],dl
   140003a6c:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003a70:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003a73:	89 c1                	mov    ecx,eax
   140003a75:	48 d3 ea             	shr    rdx,cl
   140003a78:	48 89 d0             	mov    rax,rdx
   140003a7b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003a7f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003a83:	48 85 c0             	test   rax,rax
   140003a86:	75 99                	jne    140003a21 <__pformat_xint+0xd3>
   140003a88:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003a8c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003a90:	75 13                	jne    140003aa5 <__pformat_xint+0x157>
   140003a92:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003a96:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003a99:	80 e4 f7             	and    ah,0xf7
   140003a9c:	89 c2                	mov    edx,eax
   140003a9e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003aa2:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003aa5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003aa9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003aac:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003aaf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003ab3:	7e 3a                	jle    140003aef <__pformat_xint+0x1a1>
   140003ab5:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003ab8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003abc:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003ac0:	89 c1                	mov    ecx,eax
   140003ac2:	89 d0                	mov    eax,edx
   140003ac4:	29 c8                	sub    eax,ecx
   140003ac6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003ac9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003acd:	7e 20                	jle    140003aef <__pformat_xint+0x1a1>
   140003acf:	eb 0f                	jmp    140003ae0 <__pformat_xint+0x192>
   140003ad1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ad5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ad9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003add:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003ae0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ae3:	8d 50 ff             	lea    edx,[rax-0x1]
   140003ae6:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003ae9:	85 c0                	test   eax,eax
   140003aeb:	7f e4                	jg     140003ad1 <__pformat_xint+0x183>
   140003aed:	eb 25                	jmp    140003b14 <__pformat_xint+0x1c6>
   140003aef:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003af3:	75 1f                	jne    140003b14 <__pformat_xint+0x1c6>
   140003af5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003af9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003afc:	25 00 08 00 00       	and    eax,0x800
   140003b01:	85 c0                	test   eax,eax
   140003b03:	74 0f                	je     140003b14 <__pformat_xint+0x1c6>
   140003b05:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b09:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b0d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b11:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b14:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b18:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b1c:	75 1a                	jne    140003b38 <__pformat_xint+0x1ea>
   140003b1e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b22:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b25:	85 c0                	test   eax,eax
   140003b27:	74 0f                	je     140003b38 <__pformat_xint+0x1ea>
   140003b29:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b2d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b31:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b35:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b38:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b3c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b3f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003b43:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003b47:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b4a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003b4d:	7d 15                	jge    140003b64 <__pformat_xint+0x216>
   140003b4f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b53:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b56:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003b59:	89 c2                	mov    edx,eax
   140003b5b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b5f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003b62:	eb 0b                	jmp    140003b6f <__pformat_xint+0x221>
   140003b64:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b68:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003b6f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b73:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b76:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b79:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b7d:	7e 1a                	jle    140003b99 <__pformat_xint+0x24b>
   140003b7f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003b83:	74 14                	je     140003b99 <__pformat_xint+0x24b>
   140003b85:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b89:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b8c:	25 00 08 00 00       	and    eax,0x800
   140003b91:	85 c0                	test   eax,eax
   140003b93:	74 04                	je     140003b99 <__pformat_xint+0x24b>
   140003b95:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003b99:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b9d:	7e 3c                	jle    140003bdb <__pformat_xint+0x28d>
   140003b9f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ba3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003ba6:	85 c0                	test   eax,eax
   140003ba8:	79 31                	jns    140003bdb <__pformat_xint+0x28d>
   140003baa:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bae:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bb1:	25 00 06 00 00       	and    eax,0x600
   140003bb6:	3d 00 02 00 00       	cmp    eax,0x200
   140003bbb:	75 1e                	jne    140003bdb <__pformat_xint+0x28d>
   140003bbd:	eb 0f                	jmp    140003bce <__pformat_xint+0x280>
   140003bbf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bc3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bc7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bcb:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bce:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003bd1:	8d 50 ff             	lea    edx,[rax-0x1]
   140003bd4:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bd7:	85 c0                	test   eax,eax
   140003bd9:	7f e4                	jg     140003bbf <__pformat_xint+0x271>
   140003bdb:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003bdf:	74 30                	je     140003c11 <__pformat_xint+0x2c3>
   140003be1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003be5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003be8:	25 00 08 00 00       	and    eax,0x800
   140003bed:	85 c0                	test   eax,eax
   140003bef:	74 20                	je     140003c11 <__pformat_xint+0x2c3>
   140003bf1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bf5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bf9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bfd:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003c00:	88 10                	mov    BYTE PTR [rax],dl
   140003c02:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c06:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c0a:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c0e:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c11:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c15:	7e 4c                	jle    140003c63 <__pformat_xint+0x315>
   140003c17:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c1b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c1e:	25 00 04 00 00       	and    eax,0x400
   140003c23:	85 c0                	test   eax,eax
   140003c25:	75 3c                	jne    140003c63 <__pformat_xint+0x315>
   140003c27:	eb 11                	jmp    140003c3a <__pformat_xint+0x2ec>
   140003c29:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c2d:	48 89 c2             	mov    rdx,rax
   140003c30:	b9 20 00 00 00       	mov    ecx,0x20
   140003c35:	e8 26 f5 ff ff       	call   140003160 <__pformat_putc>
   140003c3a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c3d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c40:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c43:	85 c0                	test   eax,eax
   140003c45:	7f e2                	jg     140003c29 <__pformat_xint+0x2db>
   140003c47:	eb 1a                	jmp    140003c63 <__pformat_xint+0x315>
   140003c49:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003c4e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c52:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003c55:	0f be c0             	movsx  eax,al
   140003c58:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003c5c:	89 c1                	mov    ecx,eax
   140003c5e:	e8 fd f4 ff ff       	call   140003160 <__pformat_putc>
   140003c63:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c67:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003c6b:	72 dc                	jb     140003c49 <__pformat_xint+0x2fb>
   140003c6d:	eb 11                	jmp    140003c80 <__pformat_xint+0x332>
   140003c6f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c73:	48 89 c2             	mov    rdx,rax
   140003c76:	b9 20 00 00 00       	mov    ecx,0x20
   140003c7b:	e8 e0 f4 ff ff       	call   140003160 <__pformat_putc>
   140003c80:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c83:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c86:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c89:	85 c0                	test   eax,eax
   140003c8b:	7f e2                	jg     140003c6f <__pformat_xint+0x321>
   140003c8d:	90                   	nop
   140003c8e:	90                   	nop
   140003c8f:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003c93:	5b                   	pop    rbx
   140003c94:	5d                   	pop    rbp
   140003c95:	c3                   	ret

0000000140003c96 <init_fpreg_ldouble>:
   140003c96:	55                   	push   rbp
   140003c97:	53                   	push   rbx
   140003c98:	48 83 ec 28          	sub    rsp,0x28
   140003c9c:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003ca1:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003ca5:	48 89 d3             	mov    rbx,rdx
   140003ca8:	db 2b                	fld    TBYTE PTR [rbx]
   140003caa:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003cad:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003cb0:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003cb3:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003cb7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cbb:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003cbf:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003cc2:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003cc6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003cca:	48 83 c4 28          	add    rsp,0x28
   140003cce:	5b                   	pop    rbx
   140003ccf:	5d                   	pop    rbp
   140003cd0:	c3                   	ret

0000000140003cd1 <__pformat_cvt>:
   140003cd1:	55                   	push   rbp
   140003cd2:	53                   	push   rbx
   140003cd3:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003cda:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003ce1:	00 
   140003ce2:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003ce5:	48 89 d3             	mov    rbx,rdx
   140003ce8:	db 2b                	fld    TBYTE PTR [rbx]
   140003cea:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003ced:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003cf1:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003cf5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003cfc:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003d00:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003d03:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003d06:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003d0a:	48 89 c1             	mov    rcx,rax
   140003d0d:	e8 84 ff ff ff       	call   140003c96 <init_fpreg_ldouble>
   140003d12:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003d15:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003d18:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003d1c:	48 89 c1             	mov    rcx,rax
   140003d1f:	e8 9c 4e 00 00       	call   140008bc0 <__fpclassifyl>
   140003d24:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d27:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d2a:	25 00 01 00 00       	and    eax,0x100
   140003d2f:	85 c0                	test   eax,eax
   140003d31:	74 1d                	je     140003d50 <__pformat_cvt+0x7f>
   140003d33:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d36:	25 00 04 00 00       	and    eax,0x400
   140003d3b:	85 c0                	test   eax,eax
   140003d3d:	74 07                	je     140003d46 <__pformat_cvt+0x75>
   140003d3f:	b8 03 00 00 00       	mov    eax,0x3
   140003d44:	eb 05                	jmp    140003d4b <__pformat_cvt+0x7a>
   140003d46:	b8 04 00 00 00       	mov    eax,0x4
   140003d4b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d4e:	eb 4a                	jmp    140003d9a <__pformat_cvt+0xc9>
   140003d50:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d53:	25 00 04 00 00       	and    eax,0x400
   140003d58:	85 c0                	test   eax,eax
   140003d5a:	74 37                	je     140003d93 <__pformat_cvt+0xc2>
   140003d5c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d5f:	25 00 40 00 00       	and    eax,0x4000
   140003d64:	85 c0                	test   eax,eax
   140003d66:	74 10                	je     140003d78 <__pformat_cvt+0xa7>
   140003d68:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003d6f:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003d76:	eb 22                	jmp    140003d9a <__pformat_cvt+0xc9>
   140003d78:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003d7f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003d83:	98                   	cwde
   140003d84:	25 ff 7f 00 00       	and    eax,0x7fff
   140003d89:	2d 3e 40 00 00       	sub    eax,0x403e
   140003d8e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003d91:	eb 07                	jmp    140003d9a <__pformat_cvt+0xc9>
   140003d93:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003d9a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d9d:	83 f8 04             	cmp    eax,0x4
   140003da0:	74 0e                	je     140003db0 <__pformat_cvt+0xdf>
   140003da2:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003da6:	98                   	cwde
   140003da7:	25 00 80 00 00       	and    eax,0x8000
   140003dac:	89 c2                	mov    edx,eax
   140003dae:	eb 05                	jmp    140003db5 <__pformat_cvt+0xe4>
   140003db0:	ba 00 00 00 00       	mov    edx,0x0
   140003db5:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003db9:	89 10                	mov    DWORD PTR [rax],edx
   140003dbb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003dbe:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003dc2:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003dc6:	48 8d 0d a3 62 00 00 	lea    rcx,[rip+0x62a3]        # 14000a070 <fpi.0>
   140003dcd:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003dd1:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003dd6:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003dda:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003ddf:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003de2:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003de6:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003de9:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003ded:	89 c2                	mov    edx,eax
   140003def:	e8 96 24 00 00       	call   14000628a <__gdtoa>
   140003df4:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003dfb:	5b                   	pop    rbx
   140003dfc:	5d                   	pop    rbp
   140003dfd:	c3                   	ret

0000000140003dfe <__pformat_ecvt>:
   140003dfe:	55                   	push   rbp
   140003dff:	53                   	push   rbx
   140003e00:	48 83 ec 58          	sub    rsp,0x58
   140003e04:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003e09:	48 89 cb             	mov    rbx,rcx
   140003e0c:	db 2b                	fld    TBYTE PTR [rbx]
   140003e0e:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003e11:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003e14:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003e18:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003e1c:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003e1f:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003e22:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003e26:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003e29:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e2d:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e31:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003e36:	4d 89 c1             	mov    r9,r8
   140003e39:	41 89 c8             	mov    r8d,ecx
   140003e3c:	48 89 c2             	mov    rdx,rax
   140003e3f:	b9 02 00 00 00       	mov    ecx,0x2
   140003e44:	e8 88 fe ff ff       	call   140003cd1 <__pformat_cvt>
   140003e49:	48 83 c4 58          	add    rsp,0x58
   140003e4d:	5b                   	pop    rbx
   140003e4e:	5d                   	pop    rbp
   140003e4f:	c3                   	ret

0000000140003e50 <__pformat_fcvt>:
   140003e50:	55                   	push   rbp
   140003e51:	53                   	push   rbx
   140003e52:	48 83 ec 58          	sub    rsp,0x58
   140003e56:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003e5b:	48 89 cb             	mov    rbx,rcx
   140003e5e:	db 2b                	fld    TBYTE PTR [rbx]
   140003e60:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003e63:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003e66:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003e6a:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003e6e:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003e71:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003e74:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003e78:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003e7b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e7f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e83:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003e88:	4d 89 c1             	mov    r9,r8
   140003e8b:	41 89 c8             	mov    r8d,ecx
   140003e8e:	48 89 c2             	mov    rdx,rax
   140003e91:	b9 03 00 00 00       	mov    ecx,0x3
   140003e96:	e8 36 fe ff ff       	call   140003cd1 <__pformat_cvt>
   140003e9b:	48 83 c4 58          	add    rsp,0x58
   140003e9f:	5b                   	pop    rbx
   140003ea0:	5d                   	pop    rbp
   140003ea1:	c3                   	ret

0000000140003ea2 <__pformat_emit_radix_point>:
   140003ea2:	55                   	push   rbp
   140003ea3:	53                   	push   rbx
   140003ea4:	48 83 ec 68          	sub    rsp,0x68
   140003ea8:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003ead:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003eb1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003eb5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003eb8:	83 f8 fd             	cmp    eax,0xfffffffd
   140003ebb:	75 48                	jne    140003f05 <__pformat_emit_radix_point+0x63>
   140003ebd:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003ec4:	00 
   140003ec5:	e8 4e 57 00 00       	call   140009618 <localeconv>
   140003eca:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003ecd:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003ed1:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003ed5:	49 89 c9             	mov    r9,rcx
   140003ed8:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003ede:	48 89 c1             	mov    rcx,rax
   140003ee1:	e8 6a 51 00 00       	call   140009050 <mbrtowc>
   140003ee6:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003ee9:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003eed:	7e 0c                	jle    140003efb <__pformat_emit_radix_point+0x59>
   140003eef:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003ef3:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003ef7:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003efb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003eff:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003f02:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003f05:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f09:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003f0d:	66 85 c0             	test   ax,ax
   140003f10:	0f 84 b8 00 00 00    	je     140003fce <__pformat_emit_radix_point+0x12c>
   140003f16:	48 89 e0             	mov    rax,rsp
   140003f19:	48 89 c3             	mov    rbx,rax
   140003f1c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f20:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f23:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003f26:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003f29:	48 63 d0             	movsxd rdx,eax
   140003f2c:	48 83 ea 01          	sub    rdx,0x1
   140003f30:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140003f34:	48 98                	cdqe
   140003f36:	48 83 c0 0f          	add    rax,0xf
   140003f3a:	48 c1 e8 04          	shr    rax,0x4
   140003f3e:	48 c1 e0 04          	shl    rax,0x4
   140003f42:	e8 69 f1 ff ff       	call   1400030b0 <___chkstk_ms>
   140003f47:	48 29 c4             	sub    rsp,rax
   140003f4a:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003f4f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003f53:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   140003f5a:	00 
   140003f5b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f5f:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003f63:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140003f67:	0f b7 d0             	movzx  edx,ax
   140003f6a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003f6e:	49 89 c8             	mov    r8,rcx
   140003f71:	48 89 c1             	mov    rcx,rax
   140003f74:	e8 87 50 00 00       	call   140009000 <wcrtomb>
   140003f79:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003f7c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003f80:	7e 36                	jle    140003fb8 <__pformat_emit_radix_point+0x116>
   140003f82:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003f86:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003f8a:	eb 1d                	jmp    140003fa9 <__pformat_emit_radix_point+0x107>
   140003f8c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003f90:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003f94:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003f98:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003f9b:	0f be c0             	movsx  eax,al
   140003f9e:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003fa2:	89 c1                	mov    ecx,eax
   140003fa4:	e8 b7 f1 ff ff       	call   140003160 <__pformat_putc>
   140003fa9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003fac:	8d 50 ff             	lea    edx,[rax-0x1]
   140003faf:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003fb2:	85 c0                	test   eax,eax
   140003fb4:	7f d6                	jg     140003f8c <__pformat_emit_radix_point+0xea>
   140003fb6:	eb 11                	jmp    140003fc9 <__pformat_emit_radix_point+0x127>
   140003fb8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fbc:	48 89 c2             	mov    rdx,rax
   140003fbf:	b9 2e 00 00 00       	mov    ecx,0x2e
   140003fc4:	e8 97 f1 ff ff       	call   140003160 <__pformat_putc>
   140003fc9:	48 89 dc             	mov    rsp,rbx
   140003fcc:	eb 11                	jmp    140003fdf <__pformat_emit_radix_point+0x13d>
   140003fce:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fd2:	48 89 c2             	mov    rdx,rax
   140003fd5:	b9 2e 00 00 00       	mov    ecx,0x2e
   140003fda:	e8 81 f1 ff ff       	call   140003160 <__pformat_putc>
   140003fdf:	90                   	nop
   140003fe0:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003fe4:	5b                   	pop    rbx
   140003fe5:	5d                   	pop    rbp
   140003fe6:	c3                   	ret

0000000140003fe7 <__pformat_emit_numeric_value>:
   140003fe7:	55                   	push   rbp
   140003fe8:	48 89 e5             	mov    rbp,rsp
   140003feb:	48 83 ec 30          	sub    rsp,0x30
   140003fef:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003ff2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003ff6:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   140003ffa:	75 0e                	jne    14000400a <__pformat_emit_numeric_value+0x23>
   140003ffc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004000:	48 89 c1             	mov    rcx,rax
   140004003:	e8 9a fe ff ff       	call   140003ea2 <__pformat_emit_radix_point>
   140004008:	eb 43                	jmp    14000404d <__pformat_emit_numeric_value+0x66>
   14000400a:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   14000400e:	75 2f                	jne    14000403f <__pformat_emit_numeric_value+0x58>
   140004010:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004014:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004018:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   14000401c:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   140004020:	66 85 c0             	test   ax,ax
   140004023:	74 28                	je     14000404d <__pformat_emit_numeric_value+0x66>
   140004025:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004029:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   14000402d:	49 89 d0             	mov    r8,rdx
   140004030:	ba 01 00 00 00       	mov    edx,0x1
   140004035:	48 89 c1             	mov    rcx,rax
   140004038:	e8 2c f3 ff ff       	call   140003369 <__pformat_wputchars>
   14000403d:	eb 0e                	jmp    14000404d <__pformat_emit_numeric_value+0x66>
   14000403f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004043:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140004046:	89 c1                	mov    ecx,eax
   140004048:	e8 13 f1 ff ff       	call   140003160 <__pformat_putc>
   14000404d:	90                   	nop
   14000404e:	48 83 c4 30          	add    rsp,0x30
   140004052:	5d                   	pop    rbp
   140004053:	c3                   	ret

0000000140004054 <__pformat_emit_inf_or_nan>:
   140004054:	55                   	push   rbp
   140004055:	48 89 e5             	mov    rbp,rsp
   140004058:	48 83 ec 40          	sub    rsp,0x40
   14000405c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000405f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004063:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140004067:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000406b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000406f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004073:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000407a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000407e:	74 11                	je     140004091 <__pformat_emit_inf_or_nan+0x3d>
   140004080:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004084:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004088:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000408c:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   14000408f:	eb 3e                	jmp    1400040cf <__pformat_emit_inf_or_nan+0x7b>
   140004091:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004095:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004098:	25 00 01 00 00       	and    eax,0x100
   14000409d:	85 c0                	test   eax,eax
   14000409f:	74 11                	je     1400040b2 <__pformat_emit_inf_or_nan+0x5e>
   1400040a1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040a5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040a9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040ad:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400040b0:	eb 1d                	jmp    1400040cf <__pformat_emit_inf_or_nan+0x7b>
   1400040b2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040b6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400040b9:	83 e0 40             	and    eax,0x40
   1400040bc:	85 c0                	test   eax,eax
   1400040be:	74 0f                	je     1400040cf <__pformat_emit_inf_or_nan+0x7b>
   1400040c0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040c4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040c8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040cc:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400040cf:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   1400040d6:	eb 38                	jmp    140004110 <__pformat_emit_inf_or_nan+0xbc>
   1400040d8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040dc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040e0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400040e4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400040e7:	83 e0 df             	and    eax,0xffffffdf
   1400040ea:	41 89 c0             	mov    r8d,eax
   1400040ed:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040f1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400040f4:	83 e0 20             	and    eax,0x20
   1400040f7:	89 c1                	mov    ecx,eax
   1400040f9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040fd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004101:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004105:	44 89 c2             	mov    edx,r8d
   140004108:	09 ca                	or     edx,ecx
   14000410a:	88 10                	mov    BYTE PTR [rax],dl
   14000410c:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004110:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004114:	7f c2                	jg     1400040d8 <__pformat_emit_inf_or_nan+0x84>
   140004116:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000411a:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   14000411e:	48 29 c2             	sub    rdx,rax
   140004121:	89 d1                	mov    ecx,edx
   140004123:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004127:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000412b:	49 89 d0             	mov    r8,rdx
   14000412e:	89 ca                	mov    edx,ecx
   140004130:	48 89 c1             	mov    rcx,rax
   140004133:	e8 ac f0 ff ff       	call   1400031e4 <__pformat_putchars>
   140004138:	90                   	nop
   140004139:	48 83 c4 40          	add    rsp,0x40
   14000413d:	5d                   	pop    rbp
   14000413e:	c3                   	ret

000000014000413f <__pformat_emit_float>:
   14000413f:	55                   	push   rbp
   140004140:	48 89 e5             	mov    rbp,rsp
   140004143:	48 83 ec 30          	sub    rsp,0x30
   140004147:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000414a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000414e:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140004152:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004156:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000415a:	7e 2e                	jle    14000418a <__pformat_emit_float+0x4b>
   14000415c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004160:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004163:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   140004166:	7f 15                	jg     14000417d <__pformat_emit_float+0x3e>
   140004168:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000416c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000416f:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004172:	89 c2                	mov    edx,eax
   140004174:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004178:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000417b:	eb 29                	jmp    1400041a6 <__pformat_emit_float+0x67>
   14000417d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004181:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004188:	eb 1c                	jmp    1400041a6 <__pformat_emit_float+0x67>
   14000418a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000418e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004191:	85 c0                	test   eax,eax
   140004193:	7e 11                	jle    1400041a6 <__pformat_emit_float+0x67>
   140004195:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004199:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000419c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000419f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041a3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400041a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041aa:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041ad:	85 c0                	test   eax,eax
   1400041af:	78 2b                	js     1400041dc <__pformat_emit_float+0x9d>
   1400041b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041b5:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400041b8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041bc:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400041bf:	39 c2                	cmp    edx,eax
   1400041c1:	7e 19                	jle    1400041dc <__pformat_emit_float+0x9d>
   1400041c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041c7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400041ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041ce:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400041d1:	29 c2                	sub    edx,eax
   1400041d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041d7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400041da:	eb 0b                	jmp    1400041e7 <__pformat_emit_float+0xa8>
   1400041dc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041e0:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400041e7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041eb:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041ee:	85 c0                	test   eax,eax
   1400041f0:	7e 2c                	jle    14000421e <__pformat_emit_float+0xdf>
   1400041f2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041f6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400041f9:	85 c0                	test   eax,eax
   1400041fb:	7f 10                	jg     14000420d <__pformat_emit_float+0xce>
   1400041fd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004201:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004204:	25 00 08 00 00       	and    eax,0x800
   140004209:	85 c0                	test   eax,eax
   14000420b:	74 11                	je     14000421e <__pformat_emit_float+0xdf>
   14000420d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004211:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004214:	8d 50 ff             	lea    edx,[rax-0x1]
   140004217:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000421b:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000421e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004222:	7e 64                	jle    140004288 <__pformat_emit_float+0x149>
   140004224:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004228:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000422b:	25 00 10 00 00       	and    eax,0x1000
   140004230:	85 c0                	test   eax,eax
   140004232:	74 54                	je     140004288 <__pformat_emit_float+0x149>
   140004234:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004238:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   14000423c:	66 85 c0             	test   ax,ax
   14000423f:	74 47                	je     140004288 <__pformat_emit_float+0x149>
   140004241:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004244:	83 c0 02             	add    eax,0x2
   140004247:	48 63 d0             	movsxd rdx,eax
   14000424a:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   140004251:	48 c1 ea 20          	shr    rdx,0x20
   140004255:	c1 f8 1f             	sar    eax,0x1f
   140004258:	29 c2                	sub    edx,eax
   14000425a:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000425d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004260:	eb 15                	jmp    140004277 <__pformat_emit_float+0x138>
   140004262:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004266:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000426a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000426d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004270:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004274:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004277:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000427b:	7e 0b                	jle    140004288 <__pformat_emit_float+0x149>
   14000427d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004281:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004284:	85 c0                	test   eax,eax
   140004286:	7f da                	jg     140004262 <__pformat_emit_float+0x123>
   140004288:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000428c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000428f:	85 c0                	test   eax,eax
   140004291:	7e 27                	jle    1400042ba <__pformat_emit_float+0x17b>
   140004293:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004297:	75 10                	jne    1400042a9 <__pformat_emit_float+0x16a>
   140004299:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000429d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042a0:	25 c0 01 00 00       	and    eax,0x1c0
   1400042a5:	85 c0                	test   eax,eax
   1400042a7:	74 11                	je     1400042ba <__pformat_emit_float+0x17b>
   1400042a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042ad:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042b0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042b7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042be:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042c1:	85 c0                	test   eax,eax
   1400042c3:	7e 38                	jle    1400042fd <__pformat_emit_float+0x1be>
   1400042c5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042c9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042cc:	25 00 06 00 00       	and    eax,0x600
   1400042d1:	85 c0                	test   eax,eax
   1400042d3:	75 28                	jne    1400042fd <__pformat_emit_float+0x1be>
   1400042d5:	eb 11                	jmp    1400042e8 <__pformat_emit_float+0x1a9>
   1400042d7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042db:	48 89 c2             	mov    rdx,rax
   1400042de:	b9 20 00 00 00       	mov    ecx,0x20
   1400042e3:	e8 78 ee ff ff       	call   140003160 <__pformat_putc>
   1400042e8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042ec:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042ef:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400042f2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400042f6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400042f9:	85 c0                	test   eax,eax
   1400042fb:	7f da                	jg     1400042d7 <__pformat_emit_float+0x198>
   1400042fd:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004301:	74 13                	je     140004316 <__pformat_emit_float+0x1d7>
   140004303:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004307:	48 89 c2             	mov    rdx,rax
   14000430a:	b9 2d 00 00 00       	mov    ecx,0x2d
   14000430f:	e8 4c ee ff ff       	call   140003160 <__pformat_putc>
   140004314:	eb 42                	jmp    140004358 <__pformat_emit_float+0x219>
   140004316:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000431a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000431d:	25 00 01 00 00       	and    eax,0x100
   140004322:	85 c0                	test   eax,eax
   140004324:	74 13                	je     140004339 <__pformat_emit_float+0x1fa>
   140004326:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000432a:	48 89 c2             	mov    rdx,rax
   14000432d:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004332:	e8 29 ee ff ff       	call   140003160 <__pformat_putc>
   140004337:	eb 1f                	jmp    140004358 <__pformat_emit_float+0x219>
   140004339:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000433d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004340:	83 e0 40             	and    eax,0x40
   140004343:	85 c0                	test   eax,eax
   140004345:	74 11                	je     140004358 <__pformat_emit_float+0x219>
   140004347:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000434b:	48 89 c2             	mov    rdx,rax
   14000434e:	b9 20 00 00 00       	mov    ecx,0x20
   140004353:	e8 08 ee ff ff       	call   140003160 <__pformat_putc>
   140004358:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000435c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000435f:	85 c0                	test   eax,eax
   140004361:	7e 3b                	jle    14000439e <__pformat_emit_float+0x25f>
   140004363:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004367:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000436a:	25 00 06 00 00       	and    eax,0x600
   14000436f:	3d 00 02 00 00       	cmp    eax,0x200
   140004374:	75 28                	jne    14000439e <__pformat_emit_float+0x25f>
   140004376:	eb 11                	jmp    140004389 <__pformat_emit_float+0x24a>
   140004378:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000437c:	48 89 c2             	mov    rdx,rax
   14000437f:	b9 30 00 00 00       	mov    ecx,0x30
   140004384:	e8 d7 ed ff ff       	call   140003160 <__pformat_putc>
   140004389:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000438d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004390:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004393:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004397:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000439a:	85 c0                	test   eax,eax
   14000439c:	7f da                	jg     140004378 <__pformat_emit_float+0x239>
   14000439e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400043a2:	0f 8e a7 00 00 00    	jle    14000444f <__pformat_emit_float+0x310>
   1400043a8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400043ac:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400043af:	84 c0                	test   al,al
   1400043b1:	74 14                	je     1400043c7 <__pformat_emit_float+0x288>
   1400043b3:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400043b7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400043bb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400043bf:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400043c2:	0f be c0             	movsx  eax,al
   1400043c5:	eb 05                	jmp    1400043cc <__pformat_emit_float+0x28d>
   1400043c7:	b8 30 00 00 00       	mov    eax,0x30
   1400043cc:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400043d0:	89 c1                	mov    ecx,eax
   1400043d2:	e8 89 ed ff ff       	call   140003160 <__pformat_putc>
   1400043d7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400043db:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400043df:	74 62                	je     140004443 <__pformat_emit_float+0x304>
   1400043e1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043e5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043e8:	25 00 10 00 00       	and    eax,0x1000
   1400043ed:	85 c0                	test   eax,eax
   1400043ef:	74 52                	je     140004443 <__pformat_emit_float+0x304>
   1400043f1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043f5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400043f9:	66 85 c0             	test   ax,ax
   1400043fc:	74 45                	je     140004443 <__pformat_emit_float+0x304>
   1400043fe:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   140004401:	48 63 c1             	movsxd rax,ecx
   140004404:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   14000440b:	48 c1 e8 20          	shr    rax,0x20
   14000440f:	48 89 c2             	mov    rdx,rax
   140004412:	89 c8                	mov    eax,ecx
   140004414:	c1 f8 1f             	sar    eax,0x1f
   140004417:	29 c2                	sub    edx,eax
   140004419:	89 d0                	mov    eax,edx
   14000441b:	01 c0                	add    eax,eax
   14000441d:	01 d0                	add    eax,edx
   14000441f:	29 c1                	sub    ecx,eax
   140004421:	89 ca                	mov    edx,ecx
   140004423:	85 d2                	test   edx,edx
   140004425:	75 1c                	jne    140004443 <__pformat_emit_float+0x304>
   140004427:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000442b:	48 83 c0 20          	add    rax,0x20
   14000442f:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004433:	49 89 d0             	mov    r8,rdx
   140004436:	ba 01 00 00 00       	mov    edx,0x1
   14000443b:	48 89 c1             	mov    rcx,rax
   14000443e:	e8 26 ef ff ff       	call   140003369 <__pformat_wputchars>
   140004443:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004447:	0f 8f 5b ff ff ff    	jg     1400043a8 <__pformat_emit_float+0x269>
   14000444d:	eb 11                	jmp    140004460 <__pformat_emit_float+0x321>
   14000444f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004453:	48 89 c2             	mov    rdx,rax
   140004456:	b9 30 00 00 00       	mov    ecx,0x30
   14000445b:	e8 00 ed ff ff       	call   140003160 <__pformat_putc>
   140004460:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004464:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004467:	85 c0                	test   eax,eax
   140004469:	7f 10                	jg     14000447b <__pformat_emit_float+0x33c>
   14000446b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000446f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004472:	25 00 08 00 00       	and    eax,0x800
   140004477:	85 c0                	test   eax,eax
   140004479:	74 0c                	je     140004487 <__pformat_emit_float+0x348>
   14000447b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000447f:	48 89 c1             	mov    rcx,rax
   140004482:	e8 1b fa ff ff       	call   140003ea2 <__pformat_emit_radix_point>
   140004487:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000448b:	79 5f                	jns    1400044ec <__pformat_emit_float+0x3ad>
   14000448d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004491:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004494:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004497:	01 c2                	add    edx,eax
   140004499:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000449d:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400044a0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044a4:	48 89 c2             	mov    rdx,rax
   1400044a7:	b9 30 00 00 00       	mov    ecx,0x30
   1400044ac:	e8 af ec ff ff       	call   140003160 <__pformat_putc>
   1400044b1:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   1400044b5:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044b9:	78 e5                	js     1400044a0 <__pformat_emit_float+0x361>
   1400044bb:	eb 2f                	jmp    1400044ec <__pformat_emit_float+0x3ad>
   1400044bd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044c1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044c4:	84 c0                	test   al,al
   1400044c6:	74 14                	je     1400044dc <__pformat_emit_float+0x39d>
   1400044c8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044cc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400044d0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400044d4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044d7:	0f be c0             	movsx  eax,al
   1400044da:	eb 05                	jmp    1400044e1 <__pformat_emit_float+0x3a2>
   1400044dc:	b8 30 00 00 00       	mov    eax,0x30
   1400044e1:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044e5:	89 c1                	mov    ecx,eax
   1400044e7:	e8 74 ec ff ff       	call   140003160 <__pformat_putc>
   1400044ec:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044f0:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400044f3:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400044f6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044fa:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   1400044fd:	85 c0                	test   eax,eax
   1400044ff:	7f bc                	jg     1400044bd <__pformat_emit_float+0x37e>
   140004501:	90                   	nop
   140004502:	90                   	nop
   140004503:	48 83 c4 30          	add    rsp,0x30
   140004507:	5d                   	pop    rbp
   140004508:	c3                   	ret

0000000140004509 <__pformat_emit_efloat>:
   140004509:	55                   	push   rbp
   14000450a:	48 89 e5             	mov    rbp,rsp
   14000450d:	48 83 ec 50          	sub    rsp,0x50
   140004511:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004514:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004518:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   14000451c:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004520:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140004527:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000452b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000452f:	79 09                	jns    14000453a <__pformat_emit_efloat+0x31>
   140004531:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004538:	eb 05                	jmp    14000453f <__pformat_emit_efloat+0x36>
   14000453a:	b8 00 00 00 00       	mov    eax,0x0
   14000453f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140004543:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004546:	48 98                	cdqe
   140004548:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000454c:	eb 04                	jmp    140004552 <__pformat_emit_efloat+0x49>
   14000454e:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140004552:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004555:	48 63 d0             	movsxd rdx,eax
   140004558:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   14000455f:	48 c1 ea 20          	shr    rdx,0x20
   140004563:	89 d1                	mov    ecx,edx
   140004565:	c1 f9 02             	sar    ecx,0x2
   140004568:	99                   	cdq
   140004569:	89 c8                	mov    eax,ecx
   14000456b:	29 d0                	sub    eax,edx
   14000456d:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004570:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004574:	75 d8                	jne    14000454e <__pformat_emit_efloat+0x45>
   140004576:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000457a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000457d:	83 f8 ff             	cmp    eax,0xffffffff
   140004580:	75 0b                	jne    14000458d <__pformat_emit_efloat+0x84>
   140004582:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004586:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   14000458d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004591:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004594:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004597:	7d 0a                	jge    1400045a3 <__pformat_emit_efloat+0x9a>
   140004599:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000459d:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   1400045a0:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400045a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045a7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400045aa:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400045ae:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   1400045b1:	7d 15                	jge    1400045c8 <__pformat_emit_efloat+0xbf>
   1400045b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045b7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400045ba:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   1400045bd:	89 c2                	mov    edx,eax
   1400045bf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045c3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400045c6:	eb 0b                	jmp    1400045d3 <__pformat_emit_efloat+0xca>
   1400045c8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045cc:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400045d3:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400045d7:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400045db:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400045de:	49 89 c9             	mov    r9,rcx
   1400045e1:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400045e7:	89 c1                	mov    ecx,eax
   1400045e9:	e8 51 fb ff ff       	call   14000413f <__pformat_emit_float>
   1400045ee:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045f2:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   1400045f5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045f9:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400045fc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004600:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004603:	0d c0 01 00 00       	or     eax,0x1c0
   140004608:	89 c2                	mov    edx,eax
   14000460a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000460e:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004611:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004615:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004618:	83 e0 20             	and    eax,0x20
   14000461b:	83 c8 45             	or     eax,0x45
   14000461e:	89 c1                	mov    ecx,eax
   140004620:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004624:	48 89 c2             	mov    rdx,rax
   140004627:	e8 34 eb ff ff       	call   140003160 <__pformat_putc>
   14000462c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004630:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004633:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140004636:	83 ea 01             	sub    edx,0x1
   140004639:	01 c2                	add    edx,eax
   14000463b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000463f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004642:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004646:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   14000464a:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000464e:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140004652:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004656:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000465a:	48 89 c1             	mov    rcx,rax
   14000465d:	e8 69 ef ff ff       	call   1400035cb <__pformat_int>
   140004662:	90                   	nop
   140004663:	48 83 c4 50          	add    rsp,0x50
   140004667:	5d                   	pop    rbp
   140004668:	c3                   	ret

0000000140004669 <__pformat_float>:
   140004669:	55                   	push   rbp
   14000466a:	53                   	push   rbx
   14000466b:	48 83 ec 58          	sub    rsp,0x58
   14000466f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004674:	48 89 cb             	mov    rbx,rcx
   140004677:	db 2b                	fld    TBYTE PTR [rbx]
   140004679:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000467c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004680:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004684:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004687:	85 c0                	test   eax,eax
   140004689:	79 0b                	jns    140004696 <__pformat_float+0x2d>
   14000468b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000468f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004696:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000469a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000469d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400046a0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400046a3:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400046a7:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400046ab:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400046af:	4d 89 c1             	mov    r9,r8
   1400046b2:	49 89 c8             	mov    r8,rcx
   1400046b5:	48 89 c1             	mov    rcx,rax
   1400046b8:	e8 93 f7 ff ff       	call   140003e50 <__pformat_fcvt>
   1400046bd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400046c1:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400046c4:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400046c9:	75 17                	jne    1400046e2 <__pformat_float+0x79>
   1400046cb:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400046ce:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400046d2:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400046d6:	49 89 c8             	mov    r8,rcx
   1400046d9:	89 c1                	mov    ecx,eax
   1400046db:	e8 74 f9 ff ff       	call   140004054 <__pformat_emit_inf_or_nan>
   1400046e0:	eb 43                	jmp    140004725 <__pformat_float+0xbc>
   1400046e2:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400046e5:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400046e8:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400046ec:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400046f0:	4d 89 c1             	mov    r9,r8
   1400046f3:	41 89 c8             	mov    r8d,ecx
   1400046f6:	89 c1                	mov    ecx,eax
   1400046f8:	e8 42 fa ff ff       	call   14000413f <__pformat_emit_float>
   1400046fd:	eb 11                	jmp    140004710 <__pformat_float+0xa7>
   1400046ff:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004703:	48 89 c2             	mov    rdx,rax
   140004706:	b9 20 00 00 00       	mov    ecx,0x20
   14000470b:	e8 50 ea ff ff       	call   140003160 <__pformat_putc>
   140004710:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004714:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004717:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000471a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000471e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004721:	85 c0                	test   eax,eax
   140004723:	7f da                	jg     1400046ff <__pformat_float+0x96>
   140004725:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004729:	48 89 c1             	mov    rcx,rax
   14000472c:	e8 4e 17 00 00       	call   140005e7f <__freedtoa>
   140004731:	90                   	nop
   140004732:	48 83 c4 58          	add    rsp,0x58
   140004736:	5b                   	pop    rbx
   140004737:	5d                   	pop    rbp
   140004738:	c3                   	ret

0000000140004739 <__pformat_efloat>:
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
   140004759:	79 0b                	jns    140004766 <__pformat_efloat+0x2d>
   14000475b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000475f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004766:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000476a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000476d:	8d 50 01             	lea    edx,[rax+0x1]
   140004770:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004773:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004776:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000477a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000477e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004782:	4d 89 c1             	mov    r9,r8
   140004785:	49 89 c8             	mov    r8,rcx
   140004788:	48 89 c1             	mov    rcx,rax
   14000478b:	e8 6e f6 ff ff       	call   140003dfe <__pformat_ecvt>
   140004790:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004794:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004797:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000479c:	75 17                	jne    1400047b5 <__pformat_efloat+0x7c>
   14000479e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047a1:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400047a5:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047a9:	49 89 c8             	mov    r8,rcx
   1400047ac:	89 c1                	mov    ecx,eax
   1400047ae:	e8 a1 f8 ff ff       	call   140004054 <__pformat_emit_inf_or_nan>
   1400047b3:	eb 1b                	jmp    1400047d0 <__pformat_efloat+0x97>
   1400047b5:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400047b8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047bb:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400047bf:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047c3:	4d 89 c1             	mov    r9,r8
   1400047c6:	41 89 c8             	mov    r8d,ecx
   1400047c9:	89 c1                	mov    ecx,eax
   1400047cb:	e8 39 fd ff ff       	call   140004509 <__pformat_emit_efloat>
   1400047d0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400047d4:	48 89 c1             	mov    rcx,rax
   1400047d7:	e8 a3 16 00 00       	call   140005e7f <__freedtoa>
   1400047dc:	90                   	nop
   1400047dd:	48 83 c4 58          	add    rsp,0x58
   1400047e1:	5b                   	pop    rbx
   1400047e2:	5d                   	pop    rbp
   1400047e3:	c3                   	ret

00000001400047e4 <__pformat_gfloat>:
   1400047e4:	55                   	push   rbp
   1400047e5:	53                   	push   rbx
   1400047e6:	48 83 ec 58          	sub    rsp,0x58
   1400047ea:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400047ef:	48 89 cb             	mov    rbx,rcx
   1400047f2:	db 2b                	fld    TBYTE PTR [rbx]
   1400047f4:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400047f7:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400047fb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047ff:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004802:	85 c0                	test   eax,eax
   140004804:	79 0d                	jns    140004813 <__pformat_gfloat+0x2f>
   140004806:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000480a:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004811:	eb 16                	jmp    140004829 <__pformat_gfloat+0x45>
   140004813:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004817:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000481a:	85 c0                	test   eax,eax
   14000481c:	75 0b                	jne    140004829 <__pformat_gfloat+0x45>
   14000481e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004822:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   140004829:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000482d:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004830:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004833:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004836:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000483a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000483e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004842:	4d 89 c1             	mov    r9,r8
   140004845:	49 89 c8             	mov    r8,rcx
   140004848:	48 89 c1             	mov    rcx,rax
   14000484b:	e8 ae f5 ff ff       	call   140003dfe <__pformat_ecvt>
   140004850:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004854:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004857:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000485c:	75 1a                	jne    140004878 <__pformat_gfloat+0x94>
   14000485e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004861:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004865:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004869:	49 89 c8             	mov    r8,rcx
   14000486c:	89 c1                	mov    ecx,eax
   14000486e:	e8 e1 f7 ff ff       	call   140004054 <__pformat_emit_inf_or_nan>
   140004873:	e9 14 01 00 00       	jmp    14000498c <__pformat_gfloat+0x1a8>
   140004878:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000487b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000487e:	0f 8c b2 00 00 00    	jl     140004936 <__pformat_gfloat+0x152>
   140004884:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004888:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000488b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000488e:	39 c2                	cmp    edx,eax
   140004890:	0f 8c a0 00 00 00    	jl     140004936 <__pformat_gfloat+0x152>
   140004896:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000489a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000489d:	25 00 08 00 00       	and    eax,0x800
   1400048a2:	85 c0                	test   eax,eax
   1400048a4:	74 15                	je     1400048bb <__pformat_gfloat+0xd7>
   1400048a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048aa:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400048ad:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048b0:	29 c2                	sub    edx,eax
   1400048b2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048b6:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400048b9:	eb 20                	jmp    1400048db <__pformat_gfloat+0xf7>
   1400048bb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400048bf:	48 89 c1             	mov    rcx,rax
   1400048c2:	e8 81 4d 00 00       	call   140009648 <strlen>
   1400048c7:	89 c1                	mov    ecx,eax
   1400048c9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048cc:	89 c2                	mov    edx,eax
   1400048ce:	89 c8                	mov    eax,ecx
   1400048d0:	29 d0                	sub    eax,edx
   1400048d2:	89 c2                	mov    edx,eax
   1400048d4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048d8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400048db:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048df:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048e2:	85 c0                	test   eax,eax
   1400048e4:	79 0b                	jns    1400048f1 <__pformat_gfloat+0x10d>
   1400048e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048ea:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   1400048f1:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400048f4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400048f7:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400048fb:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048ff:	4d 89 c1             	mov    r9,r8
   140004902:	41 89 c8             	mov    r8d,ecx
   140004905:	89 c1                	mov    ecx,eax
   140004907:	e8 33 f8 ff ff       	call   14000413f <__pformat_emit_float>
   14000490c:	eb 11                	jmp    14000491f <__pformat_gfloat+0x13b>
   14000490e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004912:	48 89 c2             	mov    rdx,rax
   140004915:	b9 20 00 00 00       	mov    ecx,0x20
   14000491a:	e8 41 e8 ff ff       	call   140003160 <__pformat_putc>
   14000491f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004923:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004926:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004929:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000492d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004930:	85 c0                	test   eax,eax
   140004932:	7f da                	jg     14000490e <__pformat_gfloat+0x12a>
   140004934:	eb 56                	jmp    14000498c <__pformat_gfloat+0x1a8>
   140004936:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000493a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000493d:	25 00 08 00 00       	and    eax,0x800
   140004942:	85 c0                	test   eax,eax
   140004944:	74 13                	je     140004959 <__pformat_gfloat+0x175>
   140004946:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000494a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000494d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004950:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004954:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004957:	eb 18                	jmp    140004971 <__pformat_gfloat+0x18d>
   140004959:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000495d:	48 89 c1             	mov    rcx,rax
   140004960:	e8 e3 4c 00 00       	call   140009648 <strlen>
   140004965:	83 e8 01             	sub    eax,0x1
   140004968:	89 c2                	mov    edx,eax
   14000496a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000496e:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004971:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004974:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004977:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000497b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   14000497f:	4d 89 c1             	mov    r9,r8
   140004982:	41 89 c8             	mov    r8d,ecx
   140004985:	89 c1                	mov    ecx,eax
   140004987:	e8 7d fb ff ff       	call   140004509 <__pformat_emit_efloat>
   14000498c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004990:	48 89 c1             	mov    rcx,rax
   140004993:	e8 e7 14 00 00       	call   140005e7f <__freedtoa>
   140004998:	90                   	nop
   140004999:	48 83 c4 58          	add    rsp,0x58
   14000499d:	5b                   	pop    rbx
   14000499e:	5d                   	pop    rbp
   14000499f:	c3                   	ret

00000001400049a0 <__pformat_emit_xfloat>:
   1400049a0:	55                   	push   rbp
   1400049a1:	53                   	push   rbx
   1400049a2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400049a9:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   1400049b0:	00 
   1400049b1:	48 89 cb             	mov    rbx,rcx
   1400049b4:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400049b8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   1400049bc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400049c0:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   1400049c6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   1400049c9:	48 85 c0             	test   rax,rax
   1400049cc:	75 09                	jne    1400049d7 <__pformat_emit_xfloat+0x37>
   1400049ce:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   1400049d2:	66 85 c0             	test   ax,ax
   1400049d5:	74 0b                	je     1400049e2 <__pformat_emit_xfloat+0x42>
   1400049d7:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   1400049db:	83 e8 03             	sub    eax,0x3
   1400049de:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   1400049e2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049e6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049e9:	85 c0                	test   eax,eax
   1400049eb:	0f 88 90 00 00 00    	js     140004a81 <__pformat_emit_xfloat+0xe1>
   1400049f1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049f5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049f8:	83 f8 0e             	cmp    eax,0xe
   1400049fb:	0f 8f 80 00 00 00    	jg     140004a81 <__pformat_emit_xfloat+0xe1>
   140004a01:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a04:	48 d1 e8             	shr    rax,1
   140004a07:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a0a:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004a0d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a11:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a14:	b9 0e 00 00 00       	mov    ecx,0xe
   140004a19:	29 c1                	sub    ecx,eax
   140004a1b:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004a22:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004a28:	89 c1                	mov    ecx,eax
   140004a2a:	49 d3 e0             	shl    r8,cl
   140004a2d:	4c 89 c0             	mov    rax,r8
   140004a30:	48 01 d0             	add    rax,rdx
   140004a33:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a36:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a39:	48 85 c0             	test   rax,rax
   140004a3c:	78 0b                	js     140004a49 <__pformat_emit_xfloat+0xa9>
   140004a3e:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a41:	48 01 c0             	add    rax,rax
   140004a44:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a47:	eb 15                	jmp    140004a5e <__pformat_emit_xfloat+0xbe>
   140004a49:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a4d:	83 c0 04             	add    eax,0x4
   140004a50:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004a54:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a57:	48 c1 e8 03          	shr    rax,0x3
   140004a5b:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a5e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004a61:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a65:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a68:	b9 0f 00 00 00       	mov    ecx,0xf
   140004a6d:	29 c1                	sub    ecx,eax
   140004a6f:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004a76:	89 c1                	mov    ecx,eax
   140004a78:	48 d3 ea             	shr    rdx,cl
   140004a7b:	48 89 d0             	mov    rax,rdx
   140004a7e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a81:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a84:	48 85 c0             	test   rax,rax
   140004a87:	75 0f                	jne    140004a98 <__pformat_emit_xfloat+0xf8>
   140004a89:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a8d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a90:	85 c0                	test   eax,eax
   140004a92:	0f 8e f8 00 00 00    	jle    140004b90 <__pformat_emit_xfloat+0x1f0>
   140004a98:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a9c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a9f:	83 f8 0e             	cmp    eax,0xe
   140004aa2:	7f 1a                	jg     140004abe <__pformat_emit_xfloat+0x11e>
   140004aa4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004aa8:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004aab:	85 c0                	test   eax,eax
   140004aad:	78 0f                	js     140004abe <__pformat_emit_xfloat+0x11e>
   140004aaf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ab3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ab6:	83 c0 01             	add    eax,0x1
   140004ab9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004abc:	eb 07                	jmp    140004ac5 <__pformat_emit_xfloat+0x125>
   140004abe:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004ac5:	e9 bc 00 00 00       	jmp    140004b86 <__pformat_emit_xfloat+0x1e6>
   140004aca:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004acd:	83 e0 0f             	and    eax,0xf
   140004ad0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004ad3:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004ad7:	75 36                	jne    140004b0f <__pformat_emit_xfloat+0x16f>
   140004ad9:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004add:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004ae1:	72 1b                	jb     140004afe <__pformat_emit_xfloat+0x15e>
   140004ae3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ae7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004aea:	25 00 08 00 00       	and    eax,0x800
   140004aef:	85 c0                	test   eax,eax
   140004af1:	75 0b                	jne    140004afe <__pformat_emit_xfloat+0x15e>
   140004af3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004af7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004afa:	85 c0                	test   eax,eax
   140004afc:	7e 2d                	jle    140004b2b <__pformat_emit_xfloat+0x18b>
   140004afe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004b02:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004b06:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004b0a:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004b0d:	eb 1c                	jmp    140004b2b <__pformat_emit_xfloat+0x18b>
   140004b0f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b13:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b16:	85 c0                	test   eax,eax
   140004b18:	7e 11                	jle    140004b2b <__pformat_emit_xfloat+0x18b>
   140004b1a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b1e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b21:	8d 50 ff             	lea    edx,[rax-0x1]
   140004b24:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b28:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004b2b:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004b2f:	75 15                	jne    140004b46 <__pformat_emit_xfloat+0x1a6>
   140004b31:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b35:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b39:	72 0b                	jb     140004b46 <__pformat_emit_xfloat+0x1a6>
   140004b3b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b3f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b42:	85 c0                	test   eax,eax
   140004b44:	78 32                	js     140004b78 <__pformat_emit_xfloat+0x1d8>
   140004b46:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004b4a:	76 16                	jbe    140004b62 <__pformat_emit_xfloat+0x1c2>
   140004b4c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004b4f:	8d 50 37             	lea    edx,[rax+0x37]
   140004b52:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b56:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b59:	83 e0 20             	and    eax,0x20
   140004b5c:	09 d0                	or     eax,edx
   140004b5e:	89 c1                	mov    ecx,eax
   140004b60:	eb 08                	jmp    140004b6a <__pformat_emit_xfloat+0x1ca>
   140004b62:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004b65:	83 c0 30             	add    eax,0x30
   140004b68:	89 c1                	mov    ecx,eax
   140004b6a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004b6e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004b72:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004b76:	88 08                	mov    BYTE PTR [rax],cl
   140004b78:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b7b:	48 c1 e8 04          	shr    rax,0x4
   140004b7f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b82:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004b86:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004b8a:	0f 8f 3a ff ff ff    	jg     140004aca <__pformat_emit_xfloat+0x12a>
   140004b90:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b94:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004b98:	75 39                	jne    140004bd3 <__pformat_emit_xfloat+0x233>
   140004b9a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b9e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ba1:	85 c0                	test   eax,eax
   140004ba3:	7f 10                	jg     140004bb5 <__pformat_emit_xfloat+0x215>
   140004ba5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ba9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004bac:	25 00 08 00 00       	and    eax,0x800
   140004bb1:	85 c0                	test   eax,eax
   140004bb3:	74 0f                	je     140004bc4 <__pformat_emit_xfloat+0x224>
   140004bb5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004bb9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004bbd:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004bc1:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004bc4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004bc8:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004bcc:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004bd0:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004bd3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bd7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004bda:	85 c0                	test   eax,eax
   140004bdc:	0f 8e e3 00 00 00    	jle    140004cc5 <__pformat_emit_xfloat+0x325>
   140004be2:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004be6:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004bea:	48 29 c2             	sub    rdx,rax
   140004bed:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004bf0:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004bf4:	98                   	cwde
   140004bf5:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004bf8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bfc:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bff:	85 c0                	test   eax,eax
   140004c01:	7e 0a                	jle    140004c0d <__pformat_emit_xfloat+0x26d>
   140004c03:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c07:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c0a:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c0d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c11:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c14:	25 c0 01 00 00       	and    eax,0x1c0
   140004c19:	85 c0                	test   eax,eax
   140004c1b:	74 07                	je     140004c24 <__pformat_emit_xfloat+0x284>
   140004c1d:	b8 06 00 00 00       	mov    eax,0x6
   140004c22:	eb 05                	jmp    140004c29 <__pformat_emit_xfloat+0x289>
   140004c24:	b8 05 00 00 00       	mov    eax,0x5
   140004c29:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c2c:	eb 0f                	jmp    140004c3d <__pformat_emit_xfloat+0x29d>
   140004c2e:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004c32:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004c36:	83 c0 01             	add    eax,0x1
   140004c39:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004c3d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004c40:	48 63 d0             	movsxd rdx,eax
   140004c43:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004c4a:	48 c1 ea 20          	shr    rdx,0x20
   140004c4e:	89 d1                	mov    ecx,edx
   140004c50:	c1 f9 02             	sar    ecx,0x2
   140004c53:	99                   	cdq
   140004c54:	89 c8                	mov    eax,ecx
   140004c56:	29 d0                	sub    eax,edx
   140004c58:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004c5b:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004c5f:	75 cd                	jne    140004c2e <__pformat_emit_xfloat+0x28e>
   140004c61:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c65:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c68:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004c6b:	7d 4d                	jge    140004cba <__pformat_emit_xfloat+0x31a>
   140004c6d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c71:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c74:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004c77:	89 c2                	mov    edx,eax
   140004c79:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c7d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004c80:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c84:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c87:	25 00 06 00 00       	and    eax,0x600
   140004c8c:	85 c0                	test   eax,eax
   140004c8e:	75 35                	jne    140004cc5 <__pformat_emit_xfloat+0x325>
   140004c90:	eb 11                	jmp    140004ca3 <__pformat_emit_xfloat+0x303>
   140004c92:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c96:	48 89 c2             	mov    rdx,rax
   140004c99:	b9 20 00 00 00       	mov    ecx,0x20
   140004c9e:	e8 bd e4 ff ff       	call   140003160 <__pformat_putc>
   140004ca3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ca7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004caa:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004cad:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004cb1:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004cb4:	85 c0                	test   eax,eax
   140004cb6:	7f da                	jg     140004c92 <__pformat_emit_xfloat+0x2f2>
   140004cb8:	eb 0b                	jmp    140004cc5 <__pformat_emit_xfloat+0x325>
   140004cba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cbe:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004cc5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cc9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ccc:	25 80 00 00 00       	and    eax,0x80
   140004cd1:	85 c0                	test   eax,eax
   140004cd3:	74 13                	je     140004ce8 <__pformat_emit_xfloat+0x348>
   140004cd5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cd9:	48 89 c2             	mov    rdx,rax
   140004cdc:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004ce1:	e8 7a e4 ff ff       	call   140003160 <__pformat_putc>
   140004ce6:	eb 42                	jmp    140004d2a <__pformat_emit_xfloat+0x38a>
   140004ce8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cec:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cef:	25 00 01 00 00       	and    eax,0x100
   140004cf4:	85 c0                	test   eax,eax
   140004cf6:	74 13                	je     140004d0b <__pformat_emit_xfloat+0x36b>
   140004cf8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cfc:	48 89 c2             	mov    rdx,rax
   140004cff:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004d04:	e8 57 e4 ff ff       	call   140003160 <__pformat_putc>
   140004d09:	eb 1f                	jmp    140004d2a <__pformat_emit_xfloat+0x38a>
   140004d0b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d0f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d12:	83 e0 40             	and    eax,0x40
   140004d15:	85 c0                	test   eax,eax
   140004d17:	74 11                	je     140004d2a <__pformat_emit_xfloat+0x38a>
   140004d19:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d1d:	48 89 c2             	mov    rdx,rax
   140004d20:	b9 20 00 00 00       	mov    ecx,0x20
   140004d25:	e8 36 e4 ff ff       	call   140003160 <__pformat_putc>
   140004d2a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d2e:	48 89 c2             	mov    rdx,rax
   140004d31:	b9 30 00 00 00       	mov    ecx,0x30
   140004d36:	e8 25 e4 ff ff       	call   140003160 <__pformat_putc>
   140004d3b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d3f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d42:	83 e0 20             	and    eax,0x20
   140004d45:	83 c8 58             	or     eax,0x58
   140004d48:	89 c1                	mov    ecx,eax
   140004d4a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d4e:	48 89 c2             	mov    rdx,rax
   140004d51:	e8 0a e4 ff ff       	call   140003160 <__pformat_putc>
   140004d56:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d5a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d5d:	85 c0                	test   eax,eax
   140004d5f:	7e 54                	jle    140004db5 <__pformat_emit_xfloat+0x415>
   140004d61:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d65:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d68:	25 00 02 00 00       	and    eax,0x200
   140004d6d:	85 c0                	test   eax,eax
   140004d6f:	74 44                	je     140004db5 <__pformat_emit_xfloat+0x415>
   140004d71:	eb 11                	jmp    140004d84 <__pformat_emit_xfloat+0x3e4>
   140004d73:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d77:	48 89 c2             	mov    rdx,rax
   140004d7a:	b9 30 00 00 00       	mov    ecx,0x30
   140004d7f:	e8 dc e3 ff ff       	call   140003160 <__pformat_putc>
   140004d84:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d88:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d8b:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004d8e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d92:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004d95:	85 c0                	test   eax,eax
   140004d97:	7f da                	jg     140004d73 <__pformat_emit_xfloat+0x3d3>
   140004d99:	eb 1a                	jmp    140004db5 <__pformat_emit_xfloat+0x415>
   140004d9b:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004da0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004da4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004da7:	0f be c0             	movsx  eax,al
   140004daa:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004dae:	89 c1                	mov    ecx,eax
   140004db0:	e8 32 f2 ff ff       	call   140003fe7 <__pformat_emit_numeric_value>
   140004db5:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004db9:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004dbd:	72 dc                	jb     140004d9b <__pformat_emit_xfloat+0x3fb>
   140004dbf:	eb 11                	jmp    140004dd2 <__pformat_emit_xfloat+0x432>
   140004dc1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dc5:	48 89 c2             	mov    rdx,rax
   140004dc8:	b9 30 00 00 00       	mov    ecx,0x30
   140004dcd:	e8 8e e3 ff ff       	call   140003160 <__pformat_putc>
   140004dd2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dd6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004dd9:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004ddc:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004de0:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004de3:	85 c0                	test   eax,eax
   140004de5:	7f da                	jg     140004dc1 <__pformat_emit_xfloat+0x421>
   140004de7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004deb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dee:	83 e0 20             	and    eax,0x20
   140004df1:	83 c8 50             	or     eax,0x50
   140004df4:	89 c1                	mov    ecx,eax
   140004df6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dfa:	48 89 c2             	mov    rdx,rax
   140004dfd:	e8 5e e3 ff ff       	call   140003160 <__pformat_putc>
   140004e02:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e06:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004e09:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004e0d:	01 c2                	add    edx,eax
   140004e0f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e13:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004e16:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e1a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e1d:	0d c0 01 00 00       	or     eax,0x1c0
   140004e22:	89 c2                	mov    edx,eax
   140004e24:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e28:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004e2b:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e2f:	66 85 c0             	test   ax,ax
   140004e32:	79 09                	jns    140004e3d <__pformat_emit_xfloat+0x49d>
   140004e34:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004e3b:	eb 05                	jmp    140004e42 <__pformat_emit_xfloat+0x4a2>
   140004e3d:	b8 00 00 00 00       	mov    eax,0x0
   140004e42:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004e46:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e4a:	48 0f bf c0          	movsx  rax,ax
   140004e4e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004e52:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004e56:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004e5a:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004e5e:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004e62:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e66:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004e6a:	48 89 c1             	mov    rcx,rax
   140004e6d:	e8 59 e7 ff ff       	call   1400035cb <__pformat_int>
   140004e72:	90                   	nop
   140004e73:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004e7a:	5b                   	pop    rbx
   140004e7b:	5d                   	pop    rbp
   140004e7c:	c3                   	ret

0000000140004e7d <__pformat_xldouble>:
   140004e7d:	55                   	push   rbp
   140004e7e:	53                   	push   rbx
   140004e7f:	48 83 ec 78          	sub    rsp,0x78
   140004e83:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004e88:	48 89 cb             	mov    rbx,rcx
   140004e8b:	db 2b                	fld    TBYTE PTR [rbx]
   140004e8d:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004e90:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004e94:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004e9b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004e9f:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004ea2:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004ea5:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004ea9:	48 89 c1             	mov    rcx,rax
   140004eac:	e8 e5 ed ff ff       	call   140003c96 <init_fpreg_ldouble>
   140004eb1:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004eb4:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004eb7:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004ebb:	48 89 c1             	mov    rcx,rax
   140004ebe:	e8 ed 3d 00 00       	call   140008cb0 <__isnanl>
   140004ec3:	85 c0                	test   eax,eax
   140004ec5:	74 1d                	je     140004ee4 <__pformat_xldouble+0x67>
   140004ec7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004eca:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004ece:	48 8d 15 71 64 00 00 	lea    rdx,[rip+0x6471]        # 14000b346 <.rdata+0x16>
   140004ed5:	49 89 c8             	mov    r8,rcx
   140004ed8:	89 c1                	mov    ecx,eax
   140004eda:	e8 75 f1 ff ff       	call   140004054 <__pformat_emit_inf_or_nan>
   140004edf:	e9 aa 00 00 00       	jmp    140004f8e <__pformat_xldouble+0x111>
   140004ee4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004ee8:	98                   	cwde
   140004ee9:	25 00 80 00 00       	and    eax,0x8000
   140004eee:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004ef1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004ef5:	74 12                	je     140004f09 <__pformat_xldouble+0x8c>
   140004ef7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004efb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004efe:	0c 80                	or     al,0x80
   140004f00:	89 c2                	mov    edx,eax
   140004f02:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f06:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004f09:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f0c:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f0f:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f13:	48 89 c1             	mov    rcx,rax
   140004f16:	e8 a5 3c 00 00       	call   140008bc0 <__fpclassifyl>
   140004f1b:	3d 00 05 00 00       	cmp    eax,0x500
   140004f20:	75 1a                	jne    140004f3c <__pformat_xldouble+0xbf>
   140004f22:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f25:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f29:	48 8d 15 1a 64 00 00 	lea    rdx,[rip+0x641a]        # 14000b34a <.rdata+0x1a>
   140004f30:	49 89 c8             	mov    r8,rcx
   140004f33:	89 c1                	mov    ecx,eax
   140004f35:	e8 1a f1 ff ff       	call   140004054 <__pformat_emit_inf_or_nan>
   140004f3a:	eb 52                	jmp    140004f8e <__pformat_xldouble+0x111>
   140004f3c:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f40:	66 25 ff 7f          	and    ax,0x7fff
   140004f44:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004f48:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f4c:	66 85 c0             	test   ax,ax
   140004f4f:	75 11                	jne    140004f62 <__pformat_xldouble+0xe5>
   140004f51:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004f55:	48 85 c0             	test   rax,rax
   140004f58:	74 14                	je     140004f6e <__pformat_xldouble+0xf1>
   140004f5a:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140004f60:	eb 0c                	jmp    140004f6e <__pformat_xldouble+0xf1>
   140004f62:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f66:	66 2d ff 3f          	sub    ax,0x3fff
   140004f6a:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004f6e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004f72:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140004f76:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004f7a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   140004f7e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004f82:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140004f86:	48 89 c1             	mov    rcx,rax
   140004f89:	e8 12 fa ff ff       	call   1400049a0 <__pformat_emit_xfloat>
   140004f8e:	90                   	nop
   140004f8f:	48 83 c4 78          	add    rsp,0x78
   140004f93:	5b                   	pop    rbx
   140004f94:	5d                   	pop    rbp
   140004f95:	c3                   	ret

0000000140004f96 <__pformat_xdouble>:
   140004f96:	55                   	push   rbp
   140004f97:	48 89 e5             	mov    rbp,rsp
   140004f9a:	48 83 ec 60          	sub    rsp,0x60
   140004f9e:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140004fa3:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004fa7:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004fae:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140004fb1:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004fb5:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004fb8:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   140004fbc:	48 89 c1             	mov    rcx,rax
   140004fbf:	e8 d2 ec ff ff       	call   140003c96 <init_fpreg_ldouble>
   140004fc4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140004fc8:	66 48 0f 6e c0       	movq   xmm0,rax
   140004fcd:	e8 7e 3c 00 00       	call   140008c50 <__isnan>
   140004fd2:	85 c0                	test   eax,eax
   140004fd4:	74 1d                	je     140004ff3 <__pformat_xdouble+0x5d>
   140004fd6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004fd9:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140004fdd:	48 8d 15 62 63 00 00 	lea    rdx,[rip+0x6362]        # 14000b346 <.rdata+0x16>
   140004fe4:	49 89 c8             	mov    r8,rcx
   140004fe7:	89 c1                	mov    ecx,eax
   140004fe9:	e8 66 f0 ff ff       	call   140004054 <__pformat_emit_inf_or_nan>
   140004fee:	e9 f9 00 00 00       	jmp    1400050ec <__pformat_xdouble+0x156>
   140004ff3:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004ff7:	98                   	cwde
   140004ff8:	25 00 80 00 00       	and    eax,0x8000
   140004ffd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005000:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005004:	74 12                	je     140005018 <__pformat_xdouble+0x82>
   140005006:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000500a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000500d:	0c 80                	or     al,0x80
   14000500f:	89 c2                	mov    edx,eax
   140005011:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005015:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005018:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000501c:	66 48 0f 6e c0       	movq   xmm0,rax
   140005021:	e8 1a 3b 00 00       	call   140008b40 <__fpclassify>
   140005026:	3d 00 05 00 00       	cmp    eax,0x500
   14000502b:	75 1d                	jne    14000504a <__pformat_xdouble+0xb4>
   14000502d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005030:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140005034:	48 8d 15 0f 63 00 00 	lea    rdx,[rip+0x630f]        # 14000b34a <.rdata+0x1a>
   14000503b:	49 89 c8             	mov    r8,rcx
   14000503e:	89 c1                	mov    ecx,eax
   140005040:	e8 0f f0 ff ff       	call   140004054 <__pformat_emit_inf_or_nan>
   140005045:	e9 a2 00 00 00       	jmp    1400050ec <__pformat_xdouble+0x156>
   14000504a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000504e:	66 25 ff 7f          	and    ax,0x7fff
   140005052:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005056:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000505a:	66 85 c0             	test   ax,ax
   14000505d:	74 3b                	je     14000509a <__pformat_xdouble+0x104>
   14000505f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005063:	66 3d 00 3c          	cmp    ax,0x3c00
   140005067:	7f 31                	jg     14000509a <__pformat_xdouble+0x104>
   140005069:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000506d:	98                   	cwde
   14000506e:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005073:	29 c2                	sub    edx,eax
   140005075:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005078:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000507c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000507f:	89 c1                	mov    ecx,eax
   140005081:	48 d3 ea             	shr    rdx,cl
   140005084:	48 89 d0             	mov    rax,rdx
   140005087:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000508b:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000508f:	89 c2                	mov    edx,eax
   140005091:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005094:	01 d0                	add    eax,edx
   140005096:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000509a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000509e:	66 85 c0             	test   ax,ax
   1400050a1:	75 11                	jne    1400050b4 <__pformat_xdouble+0x11e>
   1400050a3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050a7:	48 85 c0             	test   rax,rax
   1400050aa:	74 14                	je     1400050c0 <__pformat_xdouble+0x12a>
   1400050ac:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   1400050b2:	eb 0c                	jmp    1400050c0 <__pformat_xdouble+0x12a>
   1400050b4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050b8:	66 2d fc 3f          	sub    ax,0x3ffc
   1400050bc:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400050c0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050c4:	48 c1 e8 03          	shr    rax,0x3
   1400050c8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400050cc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050d0:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400050d4:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400050d8:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400050dc:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400050e0:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   1400050e4:	48 89 c1             	mov    rcx,rax
   1400050e7:	e8 b4 f8 ff ff       	call   1400049a0 <__pformat_emit_xfloat>
   1400050ec:	90                   	nop
   1400050ed:	48 83 c4 60          	add    rsp,0x60
   1400050f1:	5d                   	pop    rbp
   1400050f2:	c3                   	ret

00000001400050f3 <__mingw_pformat>:
   1400050f3:	55                   	push   rbp
   1400050f4:	48 89 e5             	mov    rbp,rsp
   1400050f7:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   1400050fe:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005101:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005105:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005109:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   14000510d:	e8 a6 44 00 00       	call   1400095b8 <_errno>
   140005112:	8b 00                	mov    eax,DWORD PTR [rax]
   140005114:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140005117:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000511b:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   14000511f:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   140005126:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140005129:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000512c:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   140005133:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   14000513a:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   140005141:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   140005147:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   14000514e:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   140005154:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   14000515b:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   14000515e:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   140005161:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   140005168:	e9 27 0c 00 00       	jmp    140005d94 <__mingw_pformat+0xca1>
   14000516d:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005171:	0f 85 0f 0c 00 00    	jne    140005d86 <__mingw_pformat+0xc93>
   140005177:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000517e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005185:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005189:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000518d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005191:	48 83 c0 0c          	add    rax,0xc
   140005195:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005199:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000519c:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000519f:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400051a6:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400051a9:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400051ac:	e9 c4 0b 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   1400051b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400051b5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400051b9:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400051bd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400051c0:	0f be c0             	movsx  eax,al
   1400051c3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400051c6:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400051ca:	0f 84 94 09 00 00    	je     140005b64 <__mingw_pformat+0xa71>
   1400051d0:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400051d4:	0f 8f 02 0b 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400051da:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400051de:	0f 84 eb 03 00 00    	je     1400055cf <__mingw_pformat+0x4dc>
   1400051e4:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400051e8:	0f 8f ee 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400051ee:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400051f2:	0f 84 31 09 00 00    	je     140005b29 <__mingw_pformat+0xa36>
   1400051f8:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400051fc:	0f 8f da 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005202:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005206:	0f 84 c3 03 00 00    	je     1400055cf <__mingw_pformat+0x4dc>
   14000520c:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005210:	0f 8f c6 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005216:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   14000521a:	0f 84 31 09 00 00    	je     140005b51 <__mingw_pformat+0xa5e>
   140005220:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   140005224:	0f 8f b2 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000522a:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   14000522e:	0f 84 31 03 00 00    	je     140005565 <__mingw_pformat+0x472>
   140005234:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   140005238:	0f 8f 9e 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000523e:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   140005242:	0f 84 28 05 00 00    	je     140005770 <__mingw_pformat+0x67d>
   140005248:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   14000524c:	0f 8f 8a 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005252:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005256:	0f 84 73 03 00 00    	je     1400055cf <__mingw_pformat+0x4dc>
   14000525c:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005260:	0f 8f 76 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005266:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   14000526a:	0f 84 4d 07 00 00    	je     1400059bd <__mingw_pformat+0x8ca>
   140005270:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005274:	0f 8f 62 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000527a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000527e:	0f 84 2d 03 00 00    	je     1400055b1 <__mingw_pformat+0x4be>
   140005284:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   140005288:	0f 8f 4e 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000528e:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   140005292:	0f 84 65 08 00 00    	je     140005afd <__mingw_pformat+0xa0a>
   140005298:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   14000529c:	0f 8f 3a 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400052a2:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   1400052a6:	0f 84 db 07 00 00    	je     140005a87 <__mingw_pformat+0x994>
   1400052ac:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   1400052b0:	0f 8f 26 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400052b6:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400052ba:	0f 84 ee 03 00 00    	je     1400056ae <__mingw_pformat+0x5bb>
   1400052c0:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400052c4:	0f 8f 12 0a 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400052ca:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400052ce:	0f 84 87 07 00 00    	je     140005a5b <__mingw_pformat+0x968>
   1400052d4:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400052d8:	0f 8f fe 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400052de:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400052e2:	0f 84 f3 05 00 00    	je     1400058db <__mingw_pformat+0x7e8>
   1400052e8:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400052ec:	0f 8f ea 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400052f2:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400052f6:	0f 84 61 05 00 00    	je     14000585d <__mingw_pformat+0x76a>
   1400052fc:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005300:	0f 8f d6 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005306:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   14000530a:	0f 84 cf 04 00 00    	je     1400057df <__mingw_pformat+0x6ec>
   140005310:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   140005314:	0f 8f c2 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000531a:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   14000531e:	0f 84 8a 03 00 00    	je     1400056ae <__mingw_pformat+0x5bb>
   140005324:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   140005328:	0f 8f ae 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000532e:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   140005332:	0f 84 b5 01 00 00    	je     1400054ed <__mingw_pformat+0x3fa>
   140005338:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   14000533c:	0f 8f 9a 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005342:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005346:	0f 84 83 02 00 00    	je     1400055cf <__mingw_pformat+0x4dc>
   14000534c:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005350:	0f 8f 86 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005356:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   14000535a:	0f 84 f9 05 00 00    	je     140005959 <__mingw_pformat+0x866>
   140005360:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   140005364:	0f 8f 72 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000536a:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   14000536e:	0f 84 5b 02 00 00    	je     1400055cf <__mingw_pformat+0x4dc>
   140005374:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005378:	0f 8f 5e 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000537e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   140005382:	0f 84 d6 01 00 00    	je     14000555e <__mingw_pformat+0x46b>
   140005388:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   14000538c:	0f 8f 4a 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005392:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005396:	0f 84 a0 07 00 00    	je     140005b3c <__mingw_pformat+0xa49>
   14000539c:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   1400053a0:	0f 8f 36 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400053a6:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   1400053aa:	0f 84 ea 06 00 00    	je     140005a9a <__mingw_pformat+0x9a7>
   1400053b0:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   1400053b4:	0f 8f 22 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400053ba:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400053be:	0f 84 20 05 00 00    	je     1400058e4 <__mingw_pformat+0x7f1>
   1400053c4:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400053c8:	0f 8f 0e 09 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400053ce:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400053d2:	0f 84 8e 04 00 00    	je     140005866 <__mingw_pformat+0x773>
   1400053d8:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400053dc:	0f 8f fa 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400053e2:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400053e6:	0f 84 fc 03 00 00    	je     1400057e8 <__mingw_pformat+0x6f5>
   1400053ec:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400053f0:	0f 8f e6 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400053f6:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400053fa:	0f 84 e6 00 00 00    	je     1400054e6 <__mingw_pformat+0x3f3>
   140005400:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   140005404:	0f 8f d2 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000540a:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   14000540e:	0f 84 bb 01 00 00    	je     1400055cf <__mingw_pformat+0x4dc>
   140005414:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   140005418:	0f 8f be 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000541e:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   140005422:	0f 84 3a 05 00 00    	je     140005962 <__mingw_pformat+0x86f>
   140005428:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   14000542c:	0f 8f aa 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005432:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005436:	0f 84 8c 08 00 00    	je     140005cc8 <__mingw_pformat+0xbd5>
   14000543c:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005440:	0f 8f 96 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005446:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   14000544a:	0f 84 27 07 00 00    	je     140005b77 <__mingw_pformat+0xa84>
   140005450:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   140005454:	0f 8f 82 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000545a:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   14000545e:	0f 84 db 07 00 00    	je     140005c3f <__mingw_pformat+0xb4c>
   140005464:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   140005468:	0f 8f 6e 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   14000546e:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005472:	0f 84 af 07 00 00    	je     140005c27 <__mingw_pformat+0xb34>
   140005478:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000547c:	0f 8f 5a 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005482:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005486:	0f 84 1c 07 00 00    	je     140005ba8 <__mingw_pformat+0xab5>
   14000548c:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005490:	0f 8f 46 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   140005496:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   14000549a:	0f 84 b7 07 00 00    	je     140005c57 <__mingw_pformat+0xb64>
   1400054a0:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   1400054a4:	0f 8f 32 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400054aa:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400054ae:	74 23                	je     1400054d3 <__mingw_pformat+0x3e0>
   1400054b0:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400054b4:	0f 8f 22 08 00 00    	jg     140005cdc <__mingw_pformat+0xbe9>
   1400054ba:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   1400054be:	0f 84 ec 07 00 00    	je     140005cb0 <__mingw_pformat+0xbbd>
   1400054c4:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   1400054c8:	0f 84 41 07 00 00    	je     140005c0f <__mingw_pformat+0xb1c>
   1400054ce:	e9 09 08 00 00       	jmp    140005cdc <__mingw_pformat+0xbe9>
   1400054d3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400054d7:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400054da:	89 c1                	mov    ecx,eax
   1400054dc:	e8 7f dc ff ff       	call   140003160 <__pformat_putc>
   1400054e1:	e9 82 fc ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   1400054e6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400054ed:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400054f4:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400054f8:	74 06                	je     140005500 <__mingw_pformat+0x40d>
   1400054fa:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400054fe:	75 30                	jne    140005530 <__mingw_pformat+0x43d>
   140005500:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005504:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005508:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000550c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000550e:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   140005512:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005516:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   14000551a:	49 89 d0             	mov    r8,rdx
   14000551d:	ba 01 00 00 00       	mov    edx,0x1
   140005522:	48 89 c1             	mov    rcx,rax
   140005525:	e8 3f de ff ff       	call   140003369 <__pformat_wputchars>
   14000552a:	90                   	nop
   14000552b:	e9 38 fc ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   140005530:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005534:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005538:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000553c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000553e:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   140005541:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005545:	48 8d 45 90          	lea    rax,[rbp-0x70]
   140005549:	49 89 d0             	mov    r8,rdx
   14000554c:	ba 01 00 00 00       	mov    edx,0x1
   140005551:	48 89 c1             	mov    rcx,rax
   140005554:	e8 8b dc ff ff       	call   1400031e4 <__pformat_putchars>
   140005559:	e9 0a fc ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   14000555e:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005565:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005569:	74 06                	je     140005571 <__mingw_pformat+0x47e>
   14000556b:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000556f:	75 20                	jne    140005591 <__mingw_pformat+0x49e>
   140005571:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005575:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005579:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000557d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005580:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005584:	48 89 c1             	mov    rcx,rax
   140005587:	e8 29 df ff ff       	call   1400034b5 <__pformat_wcputs>
   14000558c:	e9 d7 fb ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   140005591:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005595:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005599:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000559d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400055a0:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055a4:	48 89 c1             	mov    rcx,rax
   1400055a7:	e8 37 dd ff ff       	call   1400032e3 <__pformat_puts>
   1400055ac:	e9 b7 fb ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   1400055b1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400055b4:	89 c1                	mov    ecx,eax
   1400055b6:	e8 85 40 00 00       	call   140009640 <strerror>
   1400055bb:	48 89 c1             	mov    rcx,rax
   1400055be:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400055c2:	48 89 c2             	mov    rdx,rax
   1400055c5:	e8 19 dd ff ff       	call   1400032e3 <__pformat_puts>
   1400055ca:	e9 99 fb ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   1400055cf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400055d2:	80 e4 fe             	and    ah,0xfe
   1400055d5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400055d8:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055dc:	75 15                	jne    1400055f3 <__mingw_pformat+0x500>
   1400055de:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055e2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055e6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055ea:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400055ed:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400055f1:	eb 54                	jmp    140005647 <__mingw_pformat+0x554>
   1400055f3:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400055f7:	75 16                	jne    14000560f <__mingw_pformat+0x51c>
   1400055f9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055fd:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005601:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005605:	8b 00                	mov    eax,DWORD PTR [rax]
   140005607:	89 c0                	mov    eax,eax
   140005609:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000560d:	eb 38                	jmp    140005647 <__mingw_pformat+0x554>
   14000560f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005613:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005617:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000561b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000561d:	89 c0                	mov    eax,eax
   14000561f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005623:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005627:	75 0d                	jne    140005636 <__mingw_pformat+0x543>
   140005629:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000562d:	0f b7 c0             	movzx  eax,ax
   140005630:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005634:	eb 11                	jmp    140005647 <__mingw_pformat+0x554>
   140005636:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   14000563a:	75 0b                	jne    140005647 <__mingw_pformat+0x554>
   14000563c:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   140005640:	0f b6 c0             	movzx  eax,al
   140005643:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005647:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   14000564b:	75 2e                	jne    14000567b <__mingw_pformat+0x588>
   14000564d:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005651:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005655:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000565c:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005663:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005667:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000566e:	48 89 c1             	mov    rcx,rax
   140005671:	e8 55 df ff ff       	call   1400035cb <__pformat_int>
   140005676:	e9 ed fa ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   14000567b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000567f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005683:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000568a:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005691:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140005695:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   14000569c:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000569f:	49 89 c8             	mov    r8,rcx
   1400056a2:	89 c1                	mov    ecx,eax
   1400056a4:	e8 a5 e2 ff ff       	call   14000394e <__pformat_xint>
   1400056a9:	e9 ba fa ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   1400056ae:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400056b1:	0c 80                	or     al,0x80
   1400056b3:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400056b6:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400056ba:	75 15                	jne    1400056d1 <__mingw_pformat+0x5de>
   1400056bc:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056c0:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056c4:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056c8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400056cb:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056cf:	eb 56                	jmp    140005727 <__mingw_pformat+0x634>
   1400056d1:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400056d5:	75 16                	jne    1400056ed <__mingw_pformat+0x5fa>
   1400056d7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056db:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056df:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056e3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056e5:	48 98                	cdqe
   1400056e7:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056eb:	eb 3a                	jmp    140005727 <__mingw_pformat+0x634>
   1400056ed:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056f1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056f5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056f9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056fb:	48 98                	cdqe
   1400056fd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005701:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005705:	75 0e                	jne    140005715 <__mingw_pformat+0x622>
   140005707:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000570b:	48 0f bf c0          	movsx  rax,ax
   14000570f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005713:	eb 12                	jmp    140005727 <__mingw_pformat+0x634>
   140005715:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005719:	75 0c                	jne    140005727 <__mingw_pformat+0x634>
   14000571b:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   14000571f:	48 0f be c0          	movsx  rax,al
   140005723:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005727:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000572b:	48 85 c0             	test   rax,rax
   14000572e:	79 09                	jns    140005739 <__mingw_pformat+0x646>
   140005730:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140005737:	eb 05                	jmp    14000573e <__mingw_pformat+0x64b>
   140005739:	b8 00 00 00 00       	mov    eax,0x0
   14000573e:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140005742:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005746:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   14000574a:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005751:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005758:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000575c:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   140005763:	48 89 c1             	mov    rcx,rax
   140005766:	e8 60 de ff ff       	call   1400035cb <__pformat_int>
   14000576b:	e9 f8 f9 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   140005770:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005774:	75 18                	jne    14000578e <__mingw_pformat+0x69b>
   140005776:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005779:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000577c:	75 10                	jne    14000578e <__mingw_pformat+0x69b>
   14000577e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005781:	80 cc 02             	or     ah,0x2
   140005784:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005787:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   14000578e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005792:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005796:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000579a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000579d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057a1:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   1400057a8:	00 
   1400057a9:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057ad:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400057b1:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400057b8:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400057bf:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400057c3:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400057ca:	49 89 d0             	mov    r8,rdx
   1400057cd:	48 89 c2             	mov    rdx,rax
   1400057d0:	b9 78 00 00 00       	mov    ecx,0x78
   1400057d5:	e8 74 e1 ff ff       	call   14000394e <__pformat_xint>
   1400057da:	e9 89 f9 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   1400057df:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057e2:	83 c8 20             	or     eax,0x20
   1400057e5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400057e8:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057eb:	83 e0 04             	and    eax,0x4
   1400057ee:	85 c0                	test   eax,eax
   1400057f0:	74 2f                	je     140005821 <__mingw_pformat+0x72e>
   1400057f2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057f6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057fa:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057fe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005801:	db 28                	fld    TBYTE PTR [rax]
   140005803:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005809:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000580d:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005814:	48 89 c1             	mov    rcx,rax
   140005817:	e8 1d ef ff ff       	call   140004739 <__pformat_efloat>
   14000581c:	e9 47 f9 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   140005821:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005825:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005829:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000582d:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   140005831:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   140005838:	ff 
   140005839:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000583f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005845:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005849:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005850:	48 89 c1             	mov    rcx,rax
   140005853:	e8 e1 ee ff ff       	call   140004739 <__pformat_efloat>
   140005858:	e9 0b f9 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   14000585d:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005860:	83 c8 20             	or     eax,0x20
   140005863:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005866:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005869:	83 e0 04             	and    eax,0x4
   14000586c:	85 c0                	test   eax,eax
   14000586e:	74 2f                	je     14000589f <__mingw_pformat+0x7ac>
   140005870:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005874:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005878:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000587c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000587f:	db 28                	fld    TBYTE PTR [rax]
   140005881:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005887:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000588b:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005892:	48 89 c1             	mov    rcx,rax
   140005895:	e8 cf ed ff ff       	call   140004669 <__pformat_float>
   14000589a:	e9 c9 f8 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   14000589f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058a3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058a7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058ab:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   1400058af:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   1400058b6:	ff 
   1400058b7:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400058bd:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058c3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058c7:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058ce:	48 89 c1             	mov    rcx,rax
   1400058d1:	e8 93 ed ff ff       	call   140004669 <__pformat_float>
   1400058d6:	e9 8d f8 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   1400058db:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058de:	83 c8 20             	or     eax,0x20
   1400058e1:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400058e4:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058e7:	83 e0 04             	and    eax,0x4
   1400058ea:	85 c0                	test   eax,eax
   1400058ec:	74 2f                	je     14000591d <__mingw_pformat+0x82a>
   1400058ee:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058f2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058f6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058fa:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400058fd:	db 28                	fld    TBYTE PTR [rax]
   1400058ff:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005905:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005909:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005910:	48 89 c1             	mov    rcx,rax
   140005913:	e8 cc ee ff ff       	call   1400047e4 <__pformat_gfloat>
   140005918:	e9 4b f8 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   14000591d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005921:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005925:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005929:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   14000592d:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   140005934:	ff 
   140005935:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000593b:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005941:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005945:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000594c:	48 89 c1             	mov    rcx,rax
   14000594f:	e8 90 ee ff ff       	call   1400047e4 <__pformat_gfloat>
   140005954:	e9 0f f8 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   140005959:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000595c:	83 c8 20             	or     eax,0x20
   14000595f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005962:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005965:	83 e0 04             	and    eax,0x4
   140005968:	85 c0                	test   eax,eax
   14000596a:	74 2f                	je     14000599b <__mingw_pformat+0x8a8>
   14000596c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005970:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005974:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005978:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000597b:	db 28                	fld    TBYTE PTR [rax]
   14000597d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005983:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005987:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000598e:	48 89 c1             	mov    rcx,rax
   140005991:	e8 e7 f4 ff ff       	call   140004e7d <__pformat_xldouble>
   140005996:	e9 cd f7 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   14000599b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000599f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059a3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059a7:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059aa:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059ae:	66 48 0f 6e c0       	movq   xmm0,rax
   1400059b3:	e8 de f5 ff ff       	call   140004f96 <__pformat_xdouble>
   1400059b8:	e9 ab f7 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   1400059bd:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400059c1:	75 1b                	jne    1400059de <__mingw_pformat+0x8eb>
   1400059c3:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   1400059c6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059ca:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059ce:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059d2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059d5:	89 ca                	mov    edx,ecx
   1400059d7:	88 10                	mov    BYTE PTR [rax],dl
   1400059d9:	e9 8a f7 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   1400059de:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400059e2:	75 1c                	jne    140005a00 <__mingw_pformat+0x90d>
   1400059e4:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   1400059e7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059eb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059ef:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059f3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059f6:	89 ca                	mov    edx,ecx
   1400059f8:	66 89 10             	mov    WORD PTR [rax],dx
   1400059fb:	e9 68 f7 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   140005a00:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005a04:	75 19                	jne    140005a1f <__mingw_pformat+0x92c>
   140005a06:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a0a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a0e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a12:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a15:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005a18:	89 10                	mov    DWORD PTR [rax],edx
   140005a1a:	e9 49 f7 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   140005a1f:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005a23:	75 1d                	jne    140005a42 <__mingw_pformat+0x94f>
   140005a25:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a28:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a2c:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a30:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a34:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a37:	48 63 d1             	movsxd rdx,ecx
   140005a3a:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005a3d:	e9 26 f7 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   140005a42:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a46:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a4a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a4e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a51:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005a54:	89 10                	mov    DWORD PTR [rax],edx
   140005a56:	e9 0d f7 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   140005a5b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005a5f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005a62:	3c 68                	cmp    al,0x68
   140005a64:	75 0e                	jne    140005a74 <__mingw_pformat+0x981>
   140005a66:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005a6b:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005a72:	eb 07                	jmp    140005a7b <__mingw_pformat+0x988>
   140005a74:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005a7b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005a82:	e9 ee 02 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005a87:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005a8e:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005a95:	e9 db 02 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005a9a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005a9e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005aa1:	3c 36                	cmp    al,0x36
   140005aa3:	75 1d                	jne    140005ac2 <__mingw_pformat+0x9cf>
   140005aa5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005aa9:	48 83 c0 01          	add    rax,0x1
   140005aad:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ab0:	3c 34                	cmp    al,0x34
   140005ab2:	75 0e                	jne    140005ac2 <__mingw_pformat+0x9cf>
   140005ab4:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005abb:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005ac0:	eb 2f                	jmp    140005af1 <__mingw_pformat+0x9fe>
   140005ac2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ac6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ac9:	3c 33                	cmp    al,0x33
   140005acb:	75 1d                	jne    140005aea <__mingw_pformat+0x9f7>
   140005acd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ad1:	48 83 c0 01          	add    rax,0x1
   140005ad5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ad8:	3c 32                	cmp    al,0x32
   140005ada:	75 0e                	jne    140005aea <__mingw_pformat+0x9f7>
   140005adc:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005ae3:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005ae8:	eb 07                	jmp    140005af1 <__mingw_pformat+0x9fe>
   140005aea:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005af1:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005af8:	e9 78 02 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005afd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b01:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b04:	3c 6c                	cmp    al,0x6c
   140005b06:	75 0e                	jne    140005b16 <__mingw_pformat+0xa23>
   140005b08:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b0d:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b14:	eb 07                	jmp    140005b1d <__mingw_pformat+0xa2a>
   140005b16:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b1d:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b24:	e9 4c 02 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005b29:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b30:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b37:	e9 39 02 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005b3c:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005b3f:	83 c8 04             	or     eax,0x4
   140005b42:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005b45:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b4c:	e9 24 02 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005b51:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b58:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b5f:	e9 11 02 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005b64:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b6b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b72:	e9 fe 01 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005b77:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005b7b:	77 1f                	ja     140005b9c <__mingw_pformat+0xaa9>
   140005b7d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005b84:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005b88:	48 83 c0 10          	add    rax,0x10
   140005b8c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005b90:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005b97:	e9 d9 01 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005b9c:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ba3:	e9 cd 01 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005ba8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005bad:	74 4c                	je     140005bfb <__mingw_pformat+0xb08>
   140005baf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005bb3:	74 06                	je     140005bbb <__mingw_pformat+0xac8>
   140005bb5:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005bb9:	75 40                	jne    140005bfb <__mingw_pformat+0xb08>
   140005bbb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005bbf:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005bc3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005bc7:	8b 10                	mov    edx,DWORD PTR [rax]
   140005bc9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005bcd:	89 10                	mov    DWORD PTR [rax],edx
   140005bcf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005bd3:	8b 00                	mov    eax,DWORD PTR [rax]
   140005bd5:	85 c0                	test   eax,eax
   140005bd7:	79 29                	jns    140005c02 <__mingw_pformat+0xb0f>
   140005bd9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005bdd:	75 13                	jne    140005bf2 <__mingw_pformat+0xaff>
   140005bdf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005be2:	80 cc 04             	or     ah,0x4
   140005be5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005be8:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005beb:	f7 d8                	neg    eax
   140005bed:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005bf0:	eb 10                	jmp    140005c02 <__mingw_pformat+0xb0f>
   140005bf2:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005bf9:	eb 07                	jmp    140005c02 <__mingw_pformat+0xb0f>
   140005bfb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c02:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005c09:	00 
   140005c0a:	e9 66 01 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005c0f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c13:	0f 85 4f 01 00 00    	jne    140005d68 <__mingw_pformat+0xc75>
   140005c19:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c1c:	80 cc 08             	or     ah,0x8
   140005c1f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c22:	e9 41 01 00 00       	jmp    140005d68 <__mingw_pformat+0xc75>
   140005c27:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c2b:	0f 85 3a 01 00 00    	jne    140005d6b <__mingw_pformat+0xc78>
   140005c31:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c34:	80 cc 01             	or     ah,0x1
   140005c37:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c3a:	e9 2c 01 00 00       	jmp    140005d6b <__mingw_pformat+0xc78>
   140005c3f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c43:	0f 85 25 01 00 00    	jne    140005d6e <__mingw_pformat+0xc7b>
   140005c49:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c4c:	80 cc 04             	or     ah,0x4
   140005c4f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c52:	e9 17 01 00 00       	jmp    140005d6e <__mingw_pformat+0xc7b>
   140005c57:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c5b:	0f 85 10 01 00 00    	jne    140005d71 <__mingw_pformat+0xc7e>
   140005c61:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c64:	80 cc 10             	or     ah,0x10
   140005c67:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c6a:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005c71:	00 
   140005c72:	e8 a1 39 00 00       	call   140009618 <localeconv>
   140005c77:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005c7b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005c7f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005c83:	49 89 c9             	mov    r9,rcx
   140005c86:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005c8c:	48 89 c1             	mov    rcx,rax
   140005c8f:	e8 bc 33 00 00       	call   140009050 <mbrtowc>
   140005c94:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005c97:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005c9b:	7e 08                	jle    140005ca5 <__mingw_pformat+0xbb2>
   140005c9d:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005ca1:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005ca5:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005ca8:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005cab:	e9 c1 00 00 00       	jmp    140005d71 <__mingw_pformat+0xc7e>
   140005cb0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cb4:	0f 85 ba 00 00 00    	jne    140005d74 <__mingw_pformat+0xc81>
   140005cba:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cbd:	83 c8 40             	or     eax,0x40
   140005cc0:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cc3:	e9 ac 00 00 00       	jmp    140005d74 <__mingw_pformat+0xc81>
   140005cc8:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ccc:	75 0e                	jne    140005cdc <__mingw_pformat+0xbe9>
   140005cce:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cd1:	80 cc 02             	or     ah,0x2
   140005cd4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cd7:	e9 99 00 00 00       	jmp    140005d75 <__mingw_pformat+0xc82>
   140005cdc:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005ce0:	77 68                	ja     140005d4a <__mingw_pformat+0xc57>
   140005ce2:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005ce6:	7f 62                	jg     140005d4a <__mingw_pformat+0xc57>
   140005ce8:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005cec:	7e 5c                	jle    140005d4a <__mingw_pformat+0xc57>
   140005cee:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cf2:	75 09                	jne    140005cfd <__mingw_pformat+0xc0a>
   140005cf4:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005cfb:	eb 0d                	jmp    140005d0a <__mingw_pformat+0xc17>
   140005cfd:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005d01:	75 07                	jne    140005d0a <__mingw_pformat+0xc17>
   140005d03:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005d0a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005d0f:	74 64                	je     140005d75 <__mingw_pformat+0xc82>
   140005d11:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d15:	8b 00                	mov    eax,DWORD PTR [rax]
   140005d17:	85 c0                	test   eax,eax
   140005d19:	79 0e                	jns    140005d29 <__mingw_pformat+0xc36>
   140005d1b:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d1e:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d21:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d25:	89 10                	mov    DWORD PTR [rax],edx
   140005d27:	eb 4c                	jmp    140005d75 <__mingw_pformat+0xc82>
   140005d29:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d2d:	8b 10                	mov    edx,DWORD PTR [rax]
   140005d2f:	89 d0                	mov    eax,edx
   140005d31:	c1 e0 02             	shl    eax,0x2
   140005d34:	01 d0                	add    eax,edx
   140005d36:	01 c0                	add    eax,eax
   140005d38:	89 c2                	mov    edx,eax
   140005d3a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d3d:	01 d0                	add    eax,edx
   140005d3f:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d42:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d46:	89 10                	mov    DWORD PTR [rax],edx
   140005d48:	eb 2b                	jmp    140005d75 <__mingw_pformat+0xc82>
   140005d4a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005d4e:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005d52:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005d56:	48 89 c2             	mov    rdx,rax
   140005d59:	b9 25 00 00 00       	mov    ecx,0x25
   140005d5e:	e8 fd d3 ff ff       	call   140003160 <__pformat_putc>
   140005d63:	e9 00 f4 ff ff       	jmp    140005168 <__mingw_pformat+0x75>
   140005d68:	90                   	nop
   140005d69:	eb 0a                	jmp    140005d75 <__mingw_pformat+0xc82>
   140005d6b:	90                   	nop
   140005d6c:	eb 07                	jmp    140005d75 <__mingw_pformat+0xc82>
   140005d6e:	90                   	nop
   140005d6f:	eb 04                	jmp    140005d75 <__mingw_pformat+0xc82>
   140005d71:	90                   	nop
   140005d72:	eb 01                	jmp    140005d75 <__mingw_pformat+0xc82>
   140005d74:	90                   	nop
   140005d75:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005d79:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005d7c:	84 c0                	test   al,al
   140005d7e:	0f 85 2d f4 ff ff    	jne    1400051b1 <__mingw_pformat+0xbe>
   140005d84:	eb 0e                	jmp    140005d94 <__mingw_pformat+0xca1>
   140005d86:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005d8a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d8d:	89 c1                	mov    ecx,eax
   140005d8f:	e8 cc d3 ff ff       	call   140003160 <__pformat_putc>
   140005d94:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005d98:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005d9c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005da0:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005da3:	0f be c0             	movsx  eax,al
   140005da6:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005da9:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005dad:	0f 85 ba f3 ff ff    	jne    14000516d <__mingw_pformat+0x7a>
   140005db3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005db6:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005dbd:	5d                   	pop    rbp
   140005dbe:	c3                   	ret
   140005dbf:	90                   	nop

0000000140005dc0 <__rv_alloc_D2A>:
   140005dc0:	55                   	push   rbp
   140005dc1:	48 89 e5             	mov    rbp,rsp
   140005dc4:	48 83 ec 30          	sub    rsp,0x30
   140005dc8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005dcb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005dd2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005dd9:	eb 07                	jmp    140005de2 <__rv_alloc_D2A+0x22>
   140005ddb:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005ddf:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005de2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005de5:	83 c0 17             	add    eax,0x17
   140005de8:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005deb:	7f ee                	jg     140005ddb <__rv_alloc_D2A+0x1b>
   140005ded:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005df0:	89 c1                	mov    ecx,eax
   140005df2:	e8 56 1e 00 00       	call   140007c4d <__Balloc_D2A>
   140005df7:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005dfb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005dff:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005e02:	89 10                	mov    DWORD PTR [rax],edx
   140005e04:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e08:	48 83 c0 04          	add    rax,0x4
   140005e0c:	48 83 c4 30          	add    rsp,0x30
   140005e10:	5d                   	pop    rbp
   140005e11:	c3                   	ret

0000000140005e12 <__nrv_alloc_D2A>:
   140005e12:	55                   	push   rbp
   140005e13:	48 89 e5             	mov    rbp,rsp
   140005e16:	48 83 ec 30          	sub    rsp,0x30
   140005e1a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005e1e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005e22:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005e26:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005e29:	89 c1                	mov    ecx,eax
   140005e2b:	e8 90 ff ff ff       	call   140005dc0 <__rv_alloc_D2A>
   140005e30:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005e34:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e38:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005e3c:	eb 05                	jmp    140005e43 <__nrv_alloc_D2A+0x31>
   140005e3e:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005e43:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005e47:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e4b:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005e4f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005e52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e56:	88 10                	mov    BYTE PTR [rax],dl
   140005e58:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e5c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e5f:	84 c0                	test   al,al
   140005e61:	75 db                	jne    140005e3e <__nrv_alloc_D2A+0x2c>
   140005e63:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005e68:	74 0b                	je     140005e75 <__nrv_alloc_D2A+0x63>
   140005e6a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005e6e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005e72:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005e75:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e79:	48 83 c4 30          	add    rsp,0x30
   140005e7d:	5d                   	pop    rbp
   140005e7e:	c3                   	ret

0000000140005e7f <__freedtoa>:
   140005e7f:	55                   	push   rbp
   140005e80:	48 89 e5             	mov    rbp,rsp
   140005e83:	48 83 ec 30          	sub    rsp,0x30
   140005e87:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005e8b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005e8f:	48 83 e8 04          	sub    rax,0x4
   140005e93:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005e97:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e9b:	8b 10                	mov    edx,DWORD PTR [rax]
   140005e9d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ea1:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005ea4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ea8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005eab:	ba 01 00 00 00       	mov    edx,0x1
   140005eb0:	89 c1                	mov    ecx,eax
   140005eb2:	d3 e2                	shl    edx,cl
   140005eb4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005eb8:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005ebb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ebf:	48 89 c1             	mov    rcx,rax
   140005ec2:	e8 c7 1e 00 00       	call   140007d8e <__Bfree_D2A>
   140005ec7:	90                   	nop
   140005ec8:	48 83 c4 30          	add    rsp,0x30
   140005ecc:	5d                   	pop    rbp
   140005ecd:	c3                   	ret

0000000140005ece <__quorem_D2A>:
   140005ece:	55                   	push   rbp
   140005ecf:	48 89 e5             	mov    rbp,rsp
   140005ed2:	48 83 ec 70          	sub    rsp,0x70
   140005ed6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005eda:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005ede:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005ee2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005ee5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005ee8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005eec:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005eef:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005ef2:	7e 0a                	jle    140005efe <__quorem_D2A+0x30>
   140005ef4:	b8 00 00 00 00       	mov    eax,0x0
   140005ef9:	e9 3f 02 00 00       	jmp    14000613d <__quorem_D2A+0x26f>
   140005efe:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f02:	48 83 c0 18          	add    rax,0x18
   140005f06:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005f0a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005f0e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005f11:	48 98                	cdqe
   140005f13:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005f1a:	00 
   140005f1b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005f1f:	48 01 d0             	add    rax,rdx
   140005f22:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005f26:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f2a:	48 83 c0 18          	add    rax,0x18
   140005f2e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005f32:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005f35:	48 98                	cdqe
   140005f37:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005f3e:	00 
   140005f3f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f43:	48 01 d0             	add    rax,rdx
   140005f46:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140005f4a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005f4e:	8b 00                	mov    eax,DWORD PTR [rax]
   140005f50:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140005f54:	8b 12                	mov    edx,DWORD PTR [rdx]
   140005f56:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140005f59:	ba 00 00 00 00       	mov    edx,0x0
   140005f5e:	f7 f1                	div    ecx
   140005f60:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140005f63:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140005f67:	0f 84 c4 00 00 00    	je     140006031 <__quorem_D2A+0x163>
   140005f6d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140005f74:	00 
   140005f75:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   140005f7c:	00 
   140005f7d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005f81:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140005f85:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140005f89:	8b 00                	mov    eax,DWORD PTR [rax]
   140005f8b:	89 c2                	mov    edx,eax
   140005f8d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140005f90:	48 0f af d0          	imul   rdx,rax
   140005f94:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140005f98:	48 01 d0             	add    rax,rdx
   140005f9b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140005f9f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140005fa3:	48 c1 e8 20          	shr    rax,0x20
   140005fa7:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140005fab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005faf:	8b 00                	mov    eax,DWORD PTR [rax]
   140005fb1:	89 c1                	mov    ecx,eax
   140005fb3:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140005fb7:	89 c2                	mov    edx,eax
   140005fb9:	48 89 c8             	mov    rax,rcx
   140005fbc:	48 29 d0             	sub    rax,rdx
   140005fbf:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140005fc3:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140005fc7:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140005fcb:	48 c1 e8 20          	shr    rax,0x20
   140005fcf:	83 e0 01             	and    eax,0x1
   140005fd2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140005fd6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005fda:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140005fde:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140005fe2:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140005fe6:	89 10                	mov    DWORD PTR [rax],edx
   140005fe8:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005fec:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140005ff0:	73 8b                	jae    140005f7d <__quorem_D2A+0xaf>
   140005ff2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005ff6:	8b 00                	mov    eax,DWORD PTR [rax]
   140005ff8:	85 c0                	test   eax,eax
   140005ffa:	75 35                	jne    140006031 <__quorem_D2A+0x163>
   140005ffc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006000:	48 83 c0 18          	add    rax,0x18
   140006004:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006008:	eb 04                	jmp    14000600e <__quorem_D2A+0x140>
   14000600a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000600e:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   140006013:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006017:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   14000601b:	73 0a                	jae    140006027 <__quorem_D2A+0x159>
   14000601d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006021:	8b 00                	mov    eax,DWORD PTR [rax]
   140006023:	85 c0                	test   eax,eax
   140006025:	74 e3                	je     14000600a <__quorem_D2A+0x13c>
   140006027:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000602b:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000602e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006031:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140006035:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006039:	48 89 c1             	mov    rcx,rax
   14000603c:	e8 bc 24 00 00       	call   1400084fd <__cmp_D2A>
   140006041:	85 c0                	test   eax,eax
   140006043:	0f 88 f1 00 00 00    	js     14000613a <__quorem_D2A+0x26c>
   140006049:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   14000604d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006054:	00 
   140006055:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000605c:	00 
   14000605d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006061:	48 83 c0 18          	add    rax,0x18
   140006065:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006069:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000606d:	48 83 c0 18          	add    rax,0x18
   140006071:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006075:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006079:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000607d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006081:	8b 00                	mov    eax,DWORD PTR [rax]
   140006083:	89 c2                	mov    edx,eax
   140006085:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006089:	48 01 d0             	add    rax,rdx
   14000608c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140006090:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006094:	48 c1 e8 20          	shr    rax,0x20
   140006098:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000609c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060a0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060a2:	89 c1                	mov    ecx,eax
   1400060a4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400060a8:	89 c2                	mov    edx,eax
   1400060aa:	48 89 c8             	mov    rax,rcx
   1400060ad:	48 29 d0             	sub    rax,rdx
   1400060b0:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   1400060b4:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400060b8:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400060bc:	48 c1 e8 20          	shr    rax,0x20
   1400060c0:	83 e0 01             	and    eax,0x1
   1400060c3:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400060c7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060cb:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400060cf:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400060d3:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400060d7:	89 10                	mov    DWORD PTR [rax],edx
   1400060d9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400060dd:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400060e1:	73 92                	jae    140006075 <__quorem_D2A+0x1a7>
   1400060e3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060e7:	48 83 c0 18          	add    rax,0x18
   1400060eb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400060ef:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400060f2:	48 98                	cdqe
   1400060f4:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400060fb:	00 
   1400060fc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006100:	48 01 d0             	add    rax,rdx
   140006103:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006107:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000610b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000610d:	85 c0                	test   eax,eax
   14000610f:	75 29                	jne    14000613a <__quorem_D2A+0x26c>
   140006111:	eb 04                	jmp    140006117 <__quorem_D2A+0x249>
   140006113:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140006117:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   14000611c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006120:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   140006124:	73 0a                	jae    140006130 <__quorem_D2A+0x262>
   140006126:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000612a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000612c:	85 c0                	test   eax,eax
   14000612e:	74 e3                	je     140006113 <__quorem_D2A+0x245>
   140006130:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006134:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006137:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000613a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   14000613d:	48 83 c4 70          	add    rsp,0x70
   140006141:	5d                   	pop    rbp
   140006142:	c3                   	ret
   140006143:	90                   	nop
   140006144:	90                   	nop
   140006145:	90                   	nop
   140006146:	90                   	nop
   140006147:	90                   	nop
   140006148:	90                   	nop
   140006149:	90                   	nop
   14000614a:	90                   	nop
   14000614b:	90                   	nop
   14000614c:	90                   	nop
   14000614d:	90                   	nop
   14000614e:	90                   	nop
   14000614f:	90                   	nop

0000000140006150 <__hi0bits_D2A>:
   140006150:	55                   	push   rbp
   140006151:	48 89 e5             	mov    rbp,rsp
   140006154:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140006157:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   14000615b:	83 f0 1f             	xor    eax,0x1f
   14000615e:	5d                   	pop    rbp
   14000615f:	c3                   	ret

0000000140006160 <bitstob>:
   140006160:	55                   	push   rbp
   140006161:	53                   	push   rbx
   140006162:	48 83 ec 58          	sub    rsp,0x58
   140006166:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000616b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000616f:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006172:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006176:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000617d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140006184:	eb 07                	jmp    14000618d <bitstob+0x2d>
   140006186:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140006189:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   14000618d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006190:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   140006193:	7c f1                	jl     140006186 <bitstob+0x26>
   140006195:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140006198:	89 c1                	mov    ecx,eax
   14000619a:	e8 ae 1a 00 00       	call   140007c4d <__Balloc_D2A>
   14000619f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400061a3:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   1400061a6:	83 e8 01             	sub    eax,0x1
   1400061a9:	c1 f8 05             	sar    eax,0x5
   1400061ac:	48 98                	cdqe
   1400061ae:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400061b5:	00 
   1400061b6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400061ba:	48 01 d0             	add    rax,rdx
   1400061bd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400061c1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061c5:	48 83 c0 18          	add    rax,0x18
   1400061c9:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400061cd:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400061d1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400061d5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061d9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400061dd:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400061e1:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400061e5:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400061e7:	89 10                	mov    DWORD PTR [rax],edx
   1400061e9:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   1400061ee:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400061f2:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400061f6:	73 dd                	jae    1400061d5 <bitstob+0x75>
   1400061f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061fc:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140006200:	48 c1 f8 02          	sar    rax,0x2
   140006204:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140006207:	eb 1d                	jmp    140006226 <bitstob+0xc6>
   140006209:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000620d:	75 17                	jne    140006226 <bitstob+0xc6>
   14000620f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006213:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   14000621a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000621e:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140006224:	eb 59                	jmp    14000627f <bitstob+0x11f>
   140006226:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000622a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000622d:	48 98                	cdqe
   14000622f:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006236:	00 
   140006237:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000623b:	48 01 d0             	add    rax,rdx
   14000623e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006240:	85 c0                	test   eax,eax
   140006242:	74 c5                	je     140006209 <bitstob+0xa9>
   140006244:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006247:	8d 50 01             	lea    edx,[rax+0x1]
   14000624a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000624e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006251:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006254:	83 c0 01             	add    eax,0x1
   140006257:	c1 e0 05             	shl    eax,0x5
   14000625a:	89 c3                	mov    ebx,eax
   14000625c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006260:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006263:	48 63 d2             	movsxd rdx,edx
   140006266:	48 83 c2 04          	add    rdx,0x4
   14000626a:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   14000626e:	89 c1                	mov    ecx,eax
   140006270:	e8 db fe ff ff       	call   140006150 <__hi0bits_D2A>
   140006275:	29 c3                	sub    ebx,eax
   140006277:	89 da                	mov    edx,ebx
   140006279:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000627d:	89 10                	mov    DWORD PTR [rax],edx
   14000627f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006283:	48 83 c4 58          	add    rsp,0x58
   140006287:	5b                   	pop    rbx
   140006288:	5d                   	pop    rbp
   140006289:	c3                   	ret

000000014000628a <__gdtoa>:
   14000628a:	55                   	push   rbp
   14000628b:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   140006292:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140006299:	00 
   14000629a:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   1400062a1:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   1400062a7:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   1400062ae:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   1400062b5:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   1400062bc:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062c3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062c5:	83 e0 cf             	and    eax,0xffffffcf
   1400062c8:	89 c2                	mov    edx,eax
   1400062ca:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062d1:	89 10                	mov    DWORD PTR [rax],edx
   1400062d3:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062da:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062dc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400062df:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062e2:	83 e0 07             	and    eax,0x7
   1400062e5:	83 f8 04             	cmp    eax,0x4
   1400062e8:	0f 84 b0 00 00 00    	je     14000639e <__gdtoa+0x114>
   1400062ee:	83 f8 04             	cmp    eax,0x4
   1400062f1:	0f 8f d5 00 00 00    	jg     1400063cc <__gdtoa+0x142>
   1400062f7:	83 f8 03             	cmp    eax,0x3
   1400062fa:	74 74                	je     140006370 <__gdtoa+0xe6>
   1400062fc:	83 f8 03             	cmp    eax,0x3
   1400062ff:	0f 8f c7 00 00 00    	jg     1400063cc <__gdtoa+0x142>
   140006305:	85 c0                	test   eax,eax
   140006307:	0f 84 05 01 00 00    	je     140006412 <__gdtoa+0x188>
   14000630d:	85 c0                	test   eax,eax
   14000630f:	0f 88 b7 00 00 00    	js     1400063cc <__gdtoa+0x142>
   140006315:	83 e8 01             	sub    eax,0x1
   140006318:	83 f8 01             	cmp    eax,0x1
   14000631b:	0f 87 ab 00 00 00    	ja     1400063cc <__gdtoa+0x142>
   140006321:	90                   	nop
   140006322:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006329:	8b 00                	mov    eax,DWORD PTR [rax]
   14000632b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000632e:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   140006332:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006335:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   14000633c:	49 89 c8             	mov    r8,rcx
   14000633f:	48 89 c1             	mov    rcx,rax
   140006342:	e8 19 fe ff ff       	call   140006160 <bitstob>
   140006347:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000634b:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006351:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140006354:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006358:	48 89 c1             	mov    rcx,rax
   14000635b:	e8 31 16 00 00       	call   140007991 <__trailz_D2A>
   140006360:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006363:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006366:	85 c0                	test   eax,eax
   140006368:	0f 84 8b 00 00 00    	je     1400063f9 <__gdtoa+0x16f>
   14000636e:	eb 66                	jmp    1400063d6 <__gdtoa+0x14c>
   140006370:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006377:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000637d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006384:	48 8d 0d c5 4f 00 00 	lea    rcx,[rip+0x4fc5]        # 14000b350 <.rdata>
   14000638b:	41 b8 08 00 00 00    	mov    r8d,0x8
   140006391:	48 89 c2             	mov    rdx,rax
   140006394:	e8 79 fa ff ff       	call   140005e12 <__nrv_alloc_D2A>
   140006399:	e9 4d 14 00 00       	jmp    1400077eb <__gdtoa+0x1561>
   14000639e:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400063a5:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   1400063ab:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400063b2:	48 8d 0d a0 4f 00 00 	lea    rcx,[rip+0x4fa0]        # 14000b359 <.rdata+0x9>
   1400063b9:	41 b8 03 00 00 00    	mov    r8d,0x3
   1400063bf:	48 89 c2             	mov    rdx,rax
   1400063c2:	e8 4b fa ff ff       	call   140005e12 <__nrv_alloc_D2A>
   1400063c7:	e9 1f 14 00 00       	jmp    1400077eb <__gdtoa+0x1561>
   1400063cc:	b8 00 00 00 00       	mov    eax,0x0
   1400063d1:	e9 15 14 00 00       	jmp    1400077eb <__gdtoa+0x1561>
   1400063d6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400063d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063dd:	48 89 c1             	mov    rcx,rax
   1400063e0:	e8 50 14 00 00       	call   140007835 <__rshift_D2A>
   1400063e5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400063e8:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   1400063ee:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400063f1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400063f4:	29 c2                	sub    edx,eax
   1400063f6:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   1400063f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063fd:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006400:	85 c0                	test   eax,eax
   140006402:	75 3d                	jne    140006441 <__gdtoa+0x1b7>
   140006404:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006408:	48 89 c1             	mov    rcx,rax
   14000640b:	e8 7e 19 00 00       	call   140007d8e <__Bfree_D2A>
   140006410:	eb 01                	jmp    140006413 <__gdtoa+0x189>
   140006412:	90                   	nop
   140006413:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   14000641a:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140006420:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006427:	48 8d 0d 2f 4f 00 00 	lea    rcx,[rip+0x4f2f]        # 14000b35d <.rdata+0xd>
   14000642e:	41 b8 01 00 00 00    	mov    r8d,0x1
   140006434:	48 89 c2             	mov    rdx,rax
   140006437:	e8 d6 f9 ff ff       	call   140005e12 <__nrv_alloc_D2A>
   14000643c:	e9 aa 13 00 00       	jmp    1400077eb <__gdtoa+0x1561>
   140006441:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   140006445:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006449:	48 89 c1             	mov    rcx,rax
   14000644c:	e8 75 23 00 00       	call   1400087c6 <__b2d_D2A>
   140006451:	66 48 0f 7e c0       	movq   rax,xmm0
   140006456:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   14000645a:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   14000645d:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006463:	01 d0                	add    eax,edx
   140006465:	83 e8 01             	sub    eax,0x1
   140006468:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000646b:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   14000646e:	25 ff ff 0f 00       	and    eax,0xfffff
   140006473:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006476:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006479:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000647e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006481:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006486:	f2 0f 10 15 d2 4e 00 	movsd  xmm2,QWORD PTR [rip+0x4ed2]        # 14000b360 <.rdata+0x10>
   14000648d:	00 
   14000648e:	66 0f 28 c8          	movapd xmm1,xmm0
   140006492:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006496:	f2 0f 10 05 ca 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4eca]        # 14000b368 <.rdata+0x18>
   14000649d:	00 
   14000649e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   1400064a2:	f2 0f 10 05 c6 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4ec6]        # 14000b370 <.rdata+0x20>
   1400064a9:	00 
   1400064aa:	f2 0f 58 c8          	addsd  xmm1,xmm0
   1400064ae:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064b1:	66 0f ef d2          	pxor   xmm2,xmm2
   1400064b5:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   1400064b9:	f2 0f 10 05 b7 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4eb7]        # 14000b378 <.rdata+0x28>
   1400064c0:	00 
   1400064c1:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   1400064c5:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400064c9:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400064ce:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064d1:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400064d4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400064d8:	79 03                	jns    1400064dd <__gdtoa+0x253>
   1400064da:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   1400064dd:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   1400064e4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400064e8:	7e 23                	jle    14000650d <__gdtoa+0x283>
   1400064ea:	66 0f ef c9          	pxor   xmm1,xmm1
   1400064ee:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   1400064f3:	f2 0f 10 05 85 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e85]        # 14000b380 <.rdata+0x30>
   1400064fa:	00 
   1400064fb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400064ff:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006504:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006508:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000650d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006512:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006516:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006519:	66 0f ef c0          	pxor   xmm0,xmm0
   14000651d:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006522:	76 1b                	jbe    14000653f <__gdtoa+0x2b5>
   140006524:	66 0f ef c0          	pxor   xmm0,xmm0
   140006528:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   14000652d:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006532:	7a 07                	jp     14000653b <__gdtoa+0x2b1>
   140006534:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006539:	74 04                	je     14000653f <__gdtoa+0x2b5>
   14000653b:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000653f:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   140006546:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006549:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   14000654c:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006552:	01 ca                	add    edx,ecx
   140006554:	83 ea 01             	sub    edx,0x1
   140006557:	c1 e2 14             	shl    edx,0x14
   14000655a:	01 d0                	add    eax,edx
   14000655c:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000655f:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006563:	78 2e                	js     140006593 <__gdtoa+0x309>
   140006565:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   140006569:	7f 28                	jg     140006593 <__gdtoa+0x309>
   14000656b:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006570:	48 8b 05 09 51 00 00 	mov    rax,QWORD PTR [rip+0x5109]        # 14000b680 <.refptr.__tens_D2A>
   140006577:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000657a:	48 63 d2             	movsxd rdx,edx
   14000657d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006582:	66 0f 2f c1          	comisd xmm0,xmm1
   140006586:	76 04                	jbe    14000658c <__gdtoa+0x302>
   140006588:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000658c:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   140006593:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006596:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006599:	29 c2                	sub    edx,eax
   14000659b:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000659e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400065a1:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065a5:	78 0f                	js     1400065b6 <__gdtoa+0x32c>
   1400065a7:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   1400065ae:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400065b1:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   1400065b4:	eb 0f                	jmp    1400065c5 <__gdtoa+0x33b>
   1400065b6:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400065b9:	f7 d8                	neg    eax
   1400065bb:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   1400065be:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   1400065c5:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400065c9:	78 15                	js     1400065e0 <__gdtoa+0x356>
   1400065cb:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   1400065d2:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065d5:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   1400065d8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065db:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400065de:	eb 15                	jmp    1400065f5 <__gdtoa+0x36b>
   1400065e0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065e3:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   1400065e6:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065e9:	f7 d8                	neg    eax
   1400065eb:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   1400065ee:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   1400065f5:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400065fc:	78 09                	js     140006607 <__gdtoa+0x37d>
   1400065fe:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   140006605:	7e 0a                	jle    140006611 <__gdtoa+0x387>
   140006607:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   14000660e:	00 00 00 
   140006611:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   140006618:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   14000661f:	7e 10                	jle    140006631 <__gdtoa+0x3a7>
   140006621:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   140006628:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000662f:	eb 1b                	jmp    14000664c <__gdtoa+0x3c2>
   140006631:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006634:	3d f9 03 00 00       	cmp    eax,0x3f9
   140006639:	7f 0a                	jg     140006645 <__gdtoa+0x3bb>
   14000663b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000663e:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   140006643:	7d 07                	jge    14000664c <__gdtoa+0x3c2>
   140006645:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000664c:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   140006653:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   14000665a:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000665d:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006660:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006667:	0f 84 c5 00 00 00    	je     140006732 <__gdtoa+0x4a8>
   14000666d:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006674:	0f 8f e6 00 00 00    	jg     140006760 <__gdtoa+0x4d6>
   14000667a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   140006681:	74 7e                	je     140006701 <__gdtoa+0x477>
   140006683:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   14000668a:	0f 8f d0 00 00 00    	jg     140006760 <__gdtoa+0x4d6>
   140006690:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006697:	0f 84 8e 00 00 00    	je     14000672b <__gdtoa+0x4a1>
   14000669d:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   1400066a4:	0f 8f b6 00 00 00    	jg     140006760 <__gdtoa+0x4d6>
   1400066aa:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400066b1:	7f 0e                	jg     1400066c1 <__gdtoa+0x437>
   1400066b3:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400066ba:	79 13                	jns    1400066cf <__gdtoa+0x445>
   1400066bc:	e9 9f 00 00 00       	jmp    140006760 <__gdtoa+0x4d6>
   1400066c1:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400066c8:	74 30                	je     1400066fa <__gdtoa+0x470>
   1400066ca:	e9 91 00 00 00       	jmp    140006760 <__gdtoa+0x4d6>
   1400066cf:	66 0f ef c9          	pxor   xmm1,xmm1
   1400066d3:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   1400066d8:	f2 0f 10 05 a8 4c 00 	movsd  xmm0,QWORD PTR [rip+0x4ca8]        # 14000b388 <.rdata+0x38>
   1400066df:	00 
   1400066e0:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400066e4:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400066e8:	83 c0 03             	add    eax,0x3
   1400066eb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400066ee:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   1400066f5:	00 00 00 
   1400066f8:	eb 66                	jmp    140006760 <__gdtoa+0x4d6>
   1400066fa:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006701:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006708:	7f 0a                	jg     140006714 <__gdtoa+0x48a>
   14000670a:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   140006711:	00 00 00 
   140006714:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   14000671a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000671d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006720:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006723:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006726:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006729:	eb 35                	jmp    140006760 <__gdtoa+0x4d6>
   14000672b:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006732:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   140006738:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000673b:	01 d0                	add    eax,edx
   14000673d:	83 c0 01             	add    eax,0x1
   140006740:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006743:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006746:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006749:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000674c:	83 e8 01             	sub    eax,0x1
   14000674f:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006752:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006755:	85 c0                	test   eax,eax
   140006757:	7f 07                	jg     140006760 <__gdtoa+0x4d6>
   140006759:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006760:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006763:	89 c1                	mov    ecx,eax
   140006765:	e8 56 f6 ff ff       	call   140005dc0 <__rv_alloc_D2A>
   14000676a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000676e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006772:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006776:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000677d:	7f 09                	jg     140006788 <__gdtoa+0x4fe>
   14000677f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   140006786:	eb 38                	jmp    1400067c0 <__gdtoa+0x536>
   140006788:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000678f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140006792:	83 e8 01             	sub    eax,0x1
   140006795:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006798:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000679c:	74 22                	je     1400067c0 <__gdtoa+0x536>
   14000679e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400067a2:	79 07                	jns    1400067ab <__gdtoa+0x521>
   1400067a4:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   1400067ab:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400067ae:	83 e0 08             	and    eax,0x8
   1400067b1:	85 c0                	test   eax,eax
   1400067b3:	74 0b                	je     1400067c0 <__gdtoa+0x536>
   1400067b5:	b8 03 00 00 00       	mov    eax,0x3
   1400067ba:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   1400067bd:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   1400067c0:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400067c4:	0f 88 b9 04 00 00    	js     140006c83 <__gdtoa+0x9f9>
   1400067ca:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   1400067ce:	0f 8f af 04 00 00    	jg     140006c83 <__gdtoa+0x9f9>
   1400067d4:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   1400067d8:	0f 84 a5 04 00 00    	je     140006c83 <__gdtoa+0x9f9>
   1400067de:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400067e2:	0f 85 9b 04 00 00    	jne    140006c83 <__gdtoa+0x9f9>
   1400067e8:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400067ec:	0f 85 91 04 00 00    	jne    140006c83 <__gdtoa+0x9f9>
   1400067f2:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   1400067f9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400067fe:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   140006803:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006806:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140006809:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   14000680c:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   14000680f:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   140006816:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000681a:	0f 8e 98 00 00 00    	jle    1400068b8 <__gdtoa+0x62e>
   140006820:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006823:	83 e0 0f             	and    eax,0xf
   140006826:	89 c2                	mov    edx,eax
   140006828:	48 8b 05 51 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e51]        # 14000b680 <.refptr.__tens_D2A>
   14000682f:	48 63 d2             	movsxd rdx,edx
   140006832:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006837:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000683c:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000683f:	c1 f8 04             	sar    eax,0x4
   140006842:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006845:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006848:	83 e0 10             	and    eax,0x10
   14000684b:	85 c0                	test   eax,eax
   14000684d:	74 5e                	je     1400068ad <__gdtoa+0x623>
   14000684f:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   140006853:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006858:	48 8b 05 51 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d51]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000685f:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   140006864:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006868:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000686d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006871:	eb 3a                	jmp    1400068ad <__gdtoa+0x623>
   140006873:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006876:	83 e0 01             	and    eax,0x1
   140006879:	85 c0                	test   eax,eax
   14000687b:	74 24                	je     1400068a1 <__gdtoa+0x617>
   14000687d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006881:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006884:	48 8b 05 25 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d25]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000688b:	48 63 d2             	movsxd rdx,edx
   14000688e:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006893:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006898:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000689c:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068a1:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   1400068a4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400068a7:	83 c0 01             	add    eax,0x1
   1400068aa:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400068ad:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400068b1:	75 c0                	jne    140006873 <__gdtoa+0x5e9>
   1400068b3:	e9 8b 00 00 00       	jmp    140006943 <__gdtoa+0x6b9>
   1400068b8:	f2 0f 10 05 d0 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4ad0]        # 14000b390 <.rdata+0x40>
   1400068bf:	00 
   1400068c0:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068c5:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068c8:	f7 d8                	neg    eax
   1400068ca:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400068cd:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400068d1:	74 70                	je     140006943 <__gdtoa+0x6b9>
   1400068d3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400068d8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400068db:	83 e0 0f             	and    eax,0xf
   1400068de:	89 c2                	mov    edx,eax
   1400068e0:	48 8b 05 99 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d99]        # 14000b680 <.refptr.__tens_D2A>
   1400068e7:	48 63 d2             	movsxd rdx,edx
   1400068ea:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400068ef:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400068f3:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400068f8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400068fb:	c1 f8 04             	sar    eax,0x4
   1400068fe:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006901:	eb 3a                	jmp    14000693d <__gdtoa+0x6b3>
   140006903:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006906:	83 e0 01             	and    eax,0x1
   140006909:	85 c0                	test   eax,eax
   14000690b:	74 24                	je     140006931 <__gdtoa+0x6a7>
   14000690d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006911:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006916:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006919:	48 8b 05 90 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c90]        # 14000b5b0 <.refptr.__bigtens_D2A>
   140006920:	48 63 d2             	movsxd rdx,edx
   140006923:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006928:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000692c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006931:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006934:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006937:	83 c0 01             	add    eax,0x1
   14000693a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000693d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006941:	75 c0                	jne    140006903 <__gdtoa+0x679>
   140006943:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140006947:	74 47                	je     140006990 <__gdtoa+0x706>
   140006949:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   14000694e:	f2 0f 10 05 3a 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a3a]        # 14000b390 <.rdata+0x40>
   140006955:	00 
   140006956:	66 0f 2f c1          	comisd xmm0,xmm1
   14000695a:	76 34                	jbe    140006990 <__gdtoa+0x706>
   14000695c:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006960:	7e 2e                	jle    140006990 <__gdtoa+0x706>
   140006962:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   140006966:	0f 8e f5 02 00 00    	jle    140006c61 <__gdtoa+0x9d7>
   14000696c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000696f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006972:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006976:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   14000697b:	f2 0f 10 05 15 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a15]        # 14000b398 <.rdata+0x48>
   140006982:	00 
   140006983:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006987:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000698c:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006990:	66 0f ef c9          	pxor   xmm1,xmm1
   140006994:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006999:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   14000699e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   1400069a2:	f2 0f 10 05 f6 49 00 	movsd  xmm0,QWORD PTR [rip+0x49f6]        # 14000b3a0 <.rdata+0x50>
   1400069a9:	00 
   1400069aa:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400069ae:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   1400069b3:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   1400069b6:	2d 00 00 40 03       	sub    eax,0x3400000
   1400069bb:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   1400069be:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400069c2:	75 5f                	jne    140006a23 <__gdtoa+0x799>
   1400069c4:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   1400069cb:	00 
   1400069cc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400069d0:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400069d4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400069d9:	f2 0f 10 0d c7 49 00 	movsd  xmm1,QWORD PTR [rip+0x49c7]        # 14000b3a8 <.rdata+0x58>
   1400069e0:	00 
   1400069e1:	f2 0f 5c c1          	subsd  xmm0,xmm1
   1400069e5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069ea:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400069ef:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   1400069f4:	66 0f 2f c1          	comisd xmm0,xmm1
   1400069f8:	0f 87 ac 07 00 00    	ja     1400071aa <__gdtoa+0xf20>
   1400069fe:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a03:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006a08:	f3 0f 7e 15 a0 49 00 	movq   xmm2,QWORD PTR [rip+0x49a0]        # 14000b3b0 <.rdata+0x60>
   140006a0f:	00 
   140006a10:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006a14:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a18:	0f 87 6e 07 00 00    	ja     14000718c <__gdtoa+0xf02>
   140006a1e:	e9 42 02 00 00       	jmp    140006c65 <__gdtoa+0x9db>
   140006a23:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006a27:	0f 84 22 01 00 00    	je     140006b4f <__gdtoa+0x8c5>
   140006a2d:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006a32:	f2 0f 10 05 86 49 00 	movsd  xmm0,QWORD PTR [rip+0x4986]        # 14000b3c0 <.rdata+0x70>
   140006a39:	00 
   140006a3a:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a3e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006a41:	8d 50 ff             	lea    edx,[rax-0x1]
   140006a44:	48 8b 05 35 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c35]        # 14000b680 <.refptr.__tens_D2A>
   140006a4b:	48 63 d2             	movsxd rdx,edx
   140006a4e:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006a53:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006a57:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006a5c:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a60:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a65:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006a6c:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a71:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006a76:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006a7a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006a7d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a82:	66 0f ef c9          	pxor   xmm1,xmm1
   140006a86:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006a8b:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006a90:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a94:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a99:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006a9c:	8d 48 30             	lea    ecx,[rax+0x30]
   140006a9f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006aa3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006aa7:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006aab:	89 ca                	mov    edx,ecx
   140006aad:	88 10                	mov    BYTE PTR [rax],dl
   140006aaf:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ab4:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006ab9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006abd:	76 29                	jbe    140006ae8 <__gdtoa+0x85e>
   140006abf:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ac4:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ac8:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006acc:	7a 0e                	jp     140006adc <__gdtoa+0x852>
   140006ace:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ad2:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006ad6:	0f 84 93 0c 00 00    	je     14000776f <__gdtoa+0x14e5>
   140006adc:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006ae3:	e9 87 0c 00 00       	jmp    14000776f <__gdtoa+0x14e5>
   140006ae8:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006aed:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006af2:	66 0f 28 c8          	movapd xmm1,xmm0
   140006af6:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006afa:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006aff:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b03:	0f 87 c3 02 00 00    	ja     140006dcc <__gdtoa+0xb42>
   140006b09:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006b0c:	83 c0 01             	add    eax,0x1
   140006b0f:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006b12:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006b15:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006b18:	0f 8e 46 01 00 00    	jle    140006c64 <__gdtoa+0x9da>
   140006b1e:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b23:	f2 0f 10 05 6d 48 00 	movsd  xmm0,QWORD PTR [rip+0x486d]        # 14000b398 <.rdata+0x48>
   140006b2a:	00 
   140006b2b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b2f:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b34:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b39:	f2 0f 10 05 57 48 00 	movsd  xmm0,QWORD PTR [rip+0x4857]        # 14000b398 <.rdata+0x48>
   140006b40:	00 
   140006b41:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b45:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b4a:	e9 1d ff ff ff       	jmp    140006a6c <__gdtoa+0x7e2>
   140006b4f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b54:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006b57:	8d 50 ff             	lea    edx,[rax-0x1]
   140006b5a:	48 8b 05 1f 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b1f]        # 14000b680 <.refptr.__tens_D2A>
   140006b61:	48 63 d2             	movsxd rdx,edx
   140006b64:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006b69:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b6d:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b72:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006b79:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b7e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006b83:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006b87:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006b8a:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006b8e:	74 1c                	je     140006bac <__gdtoa+0x922>
   140006b90:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b95:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b99:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006b9e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006ba3:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006ba7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006bac:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006baf:	8d 48 30             	lea    ecx,[rax+0x30]
   140006bb2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006bb6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006bba:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006bbe:	89 ca                	mov    edx,ecx
   140006bc0:	88 10                	mov    BYTE PTR [rax],dl
   140006bc2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006bc5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006bc8:	75 73                	jne    140006c3d <__gdtoa+0x9b3>
   140006bca:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006bcf:	f2 0f 10 05 e9 47 00 	movsd  xmm0,QWORD PTR [rip+0x47e9]        # 14000b3c0 <.rdata+0x70>
   140006bd6:	00 
   140006bd7:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bdb:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006be0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006be5:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006bea:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006bef:	66 0f 2f c1          	comisd xmm0,xmm1
   140006bf3:	0f 87 d6 01 00 00    	ja     140006dcf <__gdtoa+0xb45>
   140006bf9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006bfe:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006c03:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006c08:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006c0c:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c10:	77 02                	ja     140006c14 <__gdtoa+0x98a>
   140006c12:	eb 51                	jmp    140006c65 <__gdtoa+0x9db>
   140006c14:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c19:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c1d:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c21:	7a 0e                	jp     140006c31 <__gdtoa+0x9a7>
   140006c23:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c27:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c2b:	0f 84 41 0b 00 00    	je     140007772 <__gdtoa+0x14e8>
   140006c31:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006c38:	e9 35 0b 00 00       	jmp    140007772 <__gdtoa+0x14e8>
   140006c3d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c40:	83 c0 01             	add    eax,0x1
   140006c43:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006c46:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c4b:	f2 0f 10 05 45 47 00 	movsd  xmm0,QWORD PTR [rip+0x4745]        # 14000b398 <.rdata+0x48>
   140006c52:	00 
   140006c53:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c57:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c5c:	e9 18 ff ff ff       	jmp    140006b79 <__gdtoa+0x8ef>
   140006c61:	90                   	nop
   140006c62:	eb 01                	jmp    140006c65 <__gdtoa+0x9db>
   140006c64:	90                   	nop
   140006c65:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006c69:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006c6d:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006c72:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c77:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006c7a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006c7d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006c80:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006c83:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006c8a:	0f 88 bf 01 00 00    	js     140006e4f <__gdtoa+0xbc5>
   140006c90:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006c97:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006c9a:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006c9d:	0f 8f ac 01 00 00    	jg     140006e4f <__gdtoa+0xbc5>
   140006ca3:	48 8b 05 d6 49 00 00 	mov    rax,QWORD PTR [rip+0x49d6]        # 14000b680 <.refptr.__tens_D2A>
   140006caa:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006cad:	48 63 d2             	movsxd rdx,edx
   140006cb0:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006cb5:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006cba:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006cc1:	79 45                	jns    140006d08 <__gdtoa+0xa7e>
   140006cc3:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006cc7:	7f 3f                	jg     140006d08 <__gdtoa+0xa7e>
   140006cc9:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006cd0:	00 
   140006cd1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006cd5:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006cd9:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006cdd:	0f 88 ac 04 00 00    	js     14000718f <__gdtoa+0xf05>
   140006ce3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ce8:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006ced:	f2 0f 10 05 b3 46 00 	movsd  xmm0,QWORD PTR [rip+0x46b3]        # 14000b3a8 <.rdata+0x58>
   140006cf4:	00 
   140006cf5:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006cf9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006cfd:	0f 83 8c 04 00 00    	jae    14000718f <__gdtoa+0xf05>
   140006d03:	e9 a6 04 00 00       	jmp    1400071ae <__gdtoa+0xf24>
   140006d08:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006d0f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d14:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006d19:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006d1d:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006d20:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d25:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d29:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006d2e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006d33:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006d37:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d3c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006d3f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006d42:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006d46:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006d4a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006d4e:	89 ca                	mov    edx,ecx
   140006d50:	88 10                	mov    BYTE PTR [rax],dl
   140006d52:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d57:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d5b:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d5f:	7a 0e                	jp     140006d6f <__gdtoa+0xae5>
   140006d61:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d65:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d69:	0f 84 da 00 00 00    	je     140006e49 <__gdtoa+0xbbf>
   140006d6f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006d72:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006d75:	0f 85 aa 00 00 00    	jne    140006e25 <__gdtoa+0xb9b>
   140006d7b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006d7f:	74 12                	je     140006d93 <__gdtoa+0xb09>
   140006d81:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006d85:	74 4b                	je     140006dd2 <__gdtoa+0xb48>
   140006d87:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006d8e:	e9 e3 09 00 00       	jmp    140007776 <__gdtoa+0x14ec>
   140006d93:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d98:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006d9c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006da1:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006da6:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006dab:	77 28                	ja     140006dd5 <__gdtoa+0xb4b>
   140006dad:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006db2:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006db7:	7a 63                	jp     140006e1c <__gdtoa+0xb92>
   140006db9:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006dbe:	75 5c                	jne    140006e1c <__gdtoa+0xb92>
   140006dc0:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006dc3:	83 e0 01             	and    eax,0x1
   140006dc6:	85 c0                	test   eax,eax
   140006dc8:	74 52                	je     140006e1c <__gdtoa+0xb92>
   140006dca:	eb 0a                	jmp    140006dd6 <__gdtoa+0xb4c>
   140006dcc:	90                   	nop
   140006dcd:	eb 07                	jmp    140006dd6 <__gdtoa+0xb4c>
   140006dcf:	90                   	nop
   140006dd0:	eb 04                	jmp    140006dd6 <__gdtoa+0xb4c>
   140006dd2:	90                   	nop
   140006dd3:	eb 01                	jmp    140006dd6 <__gdtoa+0xb4c>
   140006dd5:	90                   	nop
   140006dd6:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006ddd:	eb 17                	jmp    140006df6 <__gdtoa+0xb6c>
   140006ddf:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006de3:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006de7:	75 0d                	jne    140006df6 <__gdtoa+0xb6c>
   140006de9:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006ded:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006df1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006df4:	eb 10                	jmp    140006e06 <__gdtoa+0xb7c>
   140006df6:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006dfb:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006dff:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006e02:	3c 39                	cmp    al,0x39
   140006e04:	74 d9                	je     140006ddf <__gdtoa+0xb55>
   140006e06:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e0a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006e0e:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006e12:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006e15:	83 c2 01             	add    edx,0x1
   140006e18:	88 10                	mov    BYTE PTR [rax],dl
   140006e1a:	eb 2e                	jmp    140006e4a <__gdtoa+0xbc0>
   140006e1c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e23:	eb 25                	jmp    140006e4a <__gdtoa+0xbc0>
   140006e25:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e28:	83 c0 01             	add    eax,0x1
   140006e2b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006e2e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006e33:	f2 0f 10 05 5d 45 00 	movsd  xmm0,QWORD PTR [rip+0x455d]        # 14000b398 <.rdata+0x48>
   140006e3a:	00 
   140006e3b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006e3f:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e44:	e9 c6 fe ff ff       	jmp    140006d0f <__gdtoa+0xa85>
   140006e49:	90                   	nop
   140006e4a:	e9 27 09 00 00       	jmp    140007776 <__gdtoa+0x14ec>
   140006e4f:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006e52:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006e55:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006e58:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006e5b:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006e62:	00 
   140006e63:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006e67:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006e6b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006e6f:	0f 84 e0 00 00 00    	je     140006f55 <__gdtoa+0xccb>
   140006e75:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006e78:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006e7b:	29 c2                	sub    edx,eax
   140006e7d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006e80:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e83:	8d 50 01             	lea    edx,[rax+0x1]
   140006e86:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006e89:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006e8f:	29 c2                	sub    edx,eax
   140006e91:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006e98:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006e9b:	39 c2                	cmp    edx,eax
   140006e9d:	7d 43                	jge    140006ee2 <__gdtoa+0xc58>
   140006e9f:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006ea6:	74 3a                	je     140006ee2 <__gdtoa+0xc58>
   140006ea8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006eaf:	74 31                	je     140006ee2 <__gdtoa+0xc58>
   140006eb1:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006eb8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006ebb:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006ec1:	29 c2                	sub    edx,eax
   140006ec3:	8d 42 01             	lea    eax,[rdx+0x1]
   140006ec6:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006ec9:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006ed0:	7e 68                	jle    140006f3a <__gdtoa+0xcb0>
   140006ed2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006ed6:	7e 62                	jle    140006f3a <__gdtoa+0xcb0>
   140006ed8:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006edb:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006ede:	7d 5a                	jge    140006f3a <__gdtoa+0xcb0>
   140006ee0:	eb 0a                	jmp    140006eec <__gdtoa+0xc62>
   140006ee2:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006ee9:	7e 50                	jle    140006f3b <__gdtoa+0xcb1>
   140006eeb:	90                   	nop
   140006eec:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006eef:	83 e8 01             	sub    eax,0x1
   140006ef2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006ef5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006ef8:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006efb:	7c 08                	jl     140006f05 <__gdtoa+0xc7b>
   140006efd:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f00:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006f03:	eb 19                	jmp    140006f1e <__gdtoa+0xc94>
   140006f05:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006f08:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006f0b:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f0e:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006f11:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f14:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006f17:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006f1e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f21:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f24:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f27:	85 c0                	test   eax,eax
   140006f29:	79 10                	jns    140006f3b <__gdtoa+0xcb1>
   140006f2b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f2e:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006f31:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006f38:	eb 01                	jmp    140006f3b <__gdtoa+0xcb1>
   140006f3a:	90                   	nop
   140006f3b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f3e:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140006f41:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f44:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140006f47:	b9 01 00 00 00       	mov    ecx,0x1
   140006f4c:	e8 f6 0f 00 00       	call   140007f47 <__i2b_D2A>
   140006f51:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f55:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140006f59:	7e 26                	jle    140006f81 <__gdtoa+0xcf7>
   140006f5b:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   140006f5f:	7e 20                	jle    140006f81 <__gdtoa+0xcf7>
   140006f61:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140006f64:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140006f67:	39 c2                	cmp    edx,eax
   140006f69:	0f 4e c2             	cmovle eax,edx
   140006f6c:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f6f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f72:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006f75:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f78:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006f7b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f7e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140006f81:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140006f85:	7e 7e                	jle    140007005 <__gdtoa+0xd7b>
   140006f87:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006f8b:	74 65                	je     140006ff2 <__gdtoa+0xd68>
   140006f8d:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140006f91:	7e 3b                	jle    140006fce <__gdtoa+0xd44>
   140006f93:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140006f96:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006f9a:	48 89 c1             	mov    rcx,rax
   140006f9d:	e8 11 12 00 00       	call   1400081b3 <__pow5mult_D2A>
   140006fa2:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006fa6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140006faa:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006fae:	48 89 c1             	mov    rcx,rax
   140006fb1:	e8 d7 0f 00 00       	call   140007f8d <__mult_D2A>
   140006fb6:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140006fba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006fbe:	48 89 c1             	mov    rcx,rax
   140006fc1:	e8 c8 0d 00 00       	call   140007d8e <__Bfree_D2A>
   140006fc6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006fca:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140006fce:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006fd1:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   140006fd4:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006fd7:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006fdb:	74 28                	je     140007005 <__gdtoa+0xd7b>
   140006fdd:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   140006fe0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006fe4:	48 89 c1             	mov    rcx,rax
   140006fe7:	e8 c7 11 00 00       	call   1400081b3 <__pow5mult_D2A>
   140006fec:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140006ff0:	eb 13                	jmp    140007005 <__gdtoa+0xd7b>
   140006ff2:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   140006ff5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006ff9:	48 89 c1             	mov    rcx,rax
   140006ffc:	e8 b2 11 00 00       	call   1400081b3 <__pow5mult_D2A>
   140007001:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007005:	b9 01 00 00 00       	mov    ecx,0x1
   14000700a:	e8 38 0f 00 00       	call   140007f47 <__i2b_D2A>
   14000700f:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007013:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007017:	7e 13                	jle    14000702c <__gdtoa+0xda2>
   140007019:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   14000701c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007020:	48 89 c1             	mov    rcx,rax
   140007023:	e8 8b 11 00 00       	call   1400081b3 <__pow5mult_D2A>
   140007028:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000702c:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   140007033:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000703a:	7f 29                	jg     140007065 <__gdtoa+0xddb>
   14000703c:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   14000703f:	83 f8 01             	cmp    eax,0x1
   140007042:	75 21                	jne    140007065 <__gdtoa+0xddb>
   140007044:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000704b:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000704e:	83 c0 01             	add    eax,0x1
   140007051:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140007054:	7e 0f                	jle    140007065 <__gdtoa+0xddb>
   140007056:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   14000705a:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   14000705e:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   140007065:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007069:	74 22                	je     14000708d <__gdtoa+0xe03>
   14000706b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000706f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007072:	8d 50 ff             	lea    edx,[rax-0x1]
   140007075:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007079:	48 63 d2             	movsxd rdx,edx
   14000707c:	48 83 c2 04          	add    rdx,0x4
   140007080:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   140007084:	89 c1                	mov    ecx,eax
   140007086:	e8 c5 f0 ff ff       	call   140006150 <__hi0bits_D2A>
   14000708b:	eb 05                	jmp    140007092 <__gdtoa+0xe08>
   14000708d:	b8 1f 00 00 00       	mov    eax,0x1f
   140007092:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   140007095:	83 e8 04             	sub    eax,0x4
   140007098:	83 e0 1f             	and    eax,0x1f
   14000709b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000709e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400070a1:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   1400070a4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400070a7:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   1400070aa:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   1400070ae:	7e 13                	jle    1400070c3 <__gdtoa+0xe39>
   1400070b0:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   1400070b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070b7:	48 89 c1             	mov    rcx,rax
   1400070ba:	e8 b1 12 00 00       	call   140008370 <__lshift_D2A>
   1400070bf:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070c3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400070c6:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400070c9:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   1400070cd:	7e 13                	jle    1400070e2 <__gdtoa+0xe58>
   1400070cf:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   1400070d2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070d6:	48 89 c1             	mov    rcx,rax
   1400070d9:	e8 92 12 00 00       	call   140008370 <__lshift_D2A>
   1400070de:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070e2:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400070e6:	74 5a                	je     140007142 <__gdtoa+0xeb8>
   1400070e8:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400070ec:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070f0:	48 89 c1             	mov    rcx,rax
   1400070f3:	e8 05 14 00 00       	call   1400084fd <__cmp_D2A>
   1400070f8:	85 c0                	test   eax,eax
   1400070fa:	79 46                	jns    140007142 <__gdtoa+0xeb8>
   1400070fc:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140007100:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007104:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000710a:	ba 0a 00 00 00       	mov    edx,0xa
   14000710f:	48 89 c1             	mov    rcx,rax
   140007112:	e8 02 0d 00 00       	call   140007e19 <__multadd_D2A>
   140007117:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000711b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000711f:	74 1b                	je     14000713c <__gdtoa+0xeb2>
   140007121:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007125:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000712b:	ba 0a 00 00 00       	mov    edx,0xa
   140007130:	48 89 c1             	mov    rcx,rax
   140007133:	e8 e1 0c 00 00       	call   140007e19 <__multadd_D2A>
   140007138:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000713c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000713f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140007142:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007146:	0f 8f 81 00 00 00    	jg     1400071cd <__gdtoa+0xf43>
   14000714c:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140007153:	7e 78                	jle    1400071cd <__gdtoa+0xf43>
   140007155:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007159:	78 37                	js     140007192 <__gdtoa+0xf08>
   14000715b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000715f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007165:	ba 05 00 00 00       	mov    edx,0x5
   14000716a:	48 89 c1             	mov    rcx,rax
   14000716d:	e8 a7 0c 00 00       	call   140007e19 <__multadd_D2A>
   140007172:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007176:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000717a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000717e:	48 89 c1             	mov    rcx,rax
   140007181:	e8 77 13 00 00       	call   1400084fd <__cmp_D2A>
   140007186:	85 c0                	test   eax,eax
   140007188:	7f 23                	jg     1400071ad <__gdtoa+0xf23>
   14000718a:	eb 07                	jmp    140007193 <__gdtoa+0xf09>
   14000718c:	90                   	nop
   14000718d:	eb 04                	jmp    140007193 <__gdtoa+0xf09>
   14000718f:	90                   	nop
   140007190:	eb 01                	jmp    140007193 <__gdtoa+0xf09>
   140007192:	90                   	nop
   140007193:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   140007199:	f7 d0                	not    eax
   14000719b:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   14000719e:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400071a5:	e9 87 05 00 00       	jmp    140007731 <__gdtoa+0x14a7>
   1400071aa:	90                   	nop
   1400071ab:	eb 01                	jmp    1400071ae <__gdtoa+0xf24>
   1400071ad:	90                   	nop
   1400071ae:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400071b5:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400071b9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400071bd:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400071c1:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400071c4:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400071c8:	e9 64 05 00 00       	jmp    140007731 <__gdtoa+0x14a7>
   1400071cd:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400071d1:	0f 84 14 04 00 00    	je     1400075eb <__gdtoa+0x1361>
   1400071d7:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   1400071db:	7e 13                	jle    1400071f0 <__gdtoa+0xf66>
   1400071dd:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   1400071e0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071e4:	48 89 c1             	mov    rcx,rax
   1400071e7:	e8 84 11 00 00       	call   140008370 <__lshift_D2A>
   1400071ec:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400071f0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071f4:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400071f8:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   1400071fc:	74 57                	je     140007255 <__gdtoa+0xfcb>
   1400071fe:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007202:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007205:	89 c1                	mov    ecx,eax
   140007207:	e8 41 0a 00 00       	call   140007c4d <__Balloc_D2A>
   14000720c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007210:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007214:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007217:	48 98                	cdqe
   140007219:	48 83 c0 02          	add    rax,0x2
   14000721d:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007224:	00 
   140007225:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007229:	48 8d 50 10          	lea    rdx,[rax+0x10]
   14000722d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007231:	48 83 c0 10          	add    rax,0x10
   140007235:	49 89 c8             	mov    r8,rcx
   140007238:	48 89 c1             	mov    rcx,rax
   14000723b:	e8 e8 23 00 00       	call   140009628 <memcpy>
   140007240:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007244:	ba 01 00 00 00       	mov    edx,0x1
   140007249:	48 89 c1             	mov    rcx,rax
   14000724c:	e8 1f 11 00 00       	call   140008370 <__lshift_D2A>
   140007251:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007255:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   14000725c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007260:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007264:	48 89 c1             	mov    rcx,rax
   140007267:	e8 62 ec ff ff       	call   140005ece <__quorem_D2A>
   14000726c:	83 c0 30             	add    eax,0x30
   14000726f:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007272:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007276:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000727a:	48 89 c1             	mov    rcx,rax
   14000727d:	e8 7b 12 00 00       	call   1400084fd <__cmp_D2A>
   140007282:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007285:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007289:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000728d:	48 89 c1             	mov    rcx,rax
   140007290:	e8 38 13 00 00       	call   1400085cd <__diff_D2A>
   140007295:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140007299:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   14000729d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400072a0:	85 c0                	test   eax,eax
   1400072a2:	75 15                	jne    1400072b9 <__gdtoa+0x102f>
   1400072a4:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   1400072a8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072ac:	48 89 c1             	mov    rcx,rax
   1400072af:	e8 49 12 00 00       	call   1400084fd <__cmp_D2A>
   1400072b4:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400072b7:	eb 07                	jmp    1400072c0 <__gdtoa+0x1036>
   1400072b9:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   1400072c0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   1400072c4:	48 89 c1             	mov    rcx,rax
   1400072c7:	e8 c2 0a 00 00       	call   140007d8e <__Bfree_D2A>
   1400072cc:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400072d0:	75 70                	jne    140007342 <__gdtoa+0x10b8>
   1400072d2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400072d9:	75 67                	jne    140007342 <__gdtoa+0x10b8>
   1400072db:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400072e2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400072e4:	83 e0 01             	and    eax,0x1
   1400072e7:	85 c0                	test   eax,eax
   1400072e9:	75 57                	jne    140007342 <__gdtoa+0x10b8>
   1400072eb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400072ef:	75 51                	jne    140007342 <__gdtoa+0x10b8>
   1400072f1:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400072f5:	0f 84 01 02 00 00    	je     1400074fc <__gdtoa+0x1272>
   1400072fb:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400072ff:	7f 20                	jg     140007321 <__gdtoa+0x1097>
   140007301:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007305:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007308:	83 f8 01             	cmp    eax,0x1
   14000730b:	7f 0b                	jg     140007318 <__gdtoa+0x108e>
   14000730d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007311:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007314:	85 c0                	test   eax,eax
   140007316:	74 14                	je     14000732c <__gdtoa+0x10a2>
   140007318:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000731f:	eb 0b                	jmp    14000732c <__gdtoa+0x10a2>
   140007321:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   140007325:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   14000732c:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007330:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007334:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007338:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000733b:	88 10                	mov    BYTE PTR [rax],dl
   14000733d:	e9 ef 03 00 00       	jmp    140007731 <__gdtoa+0x14a7>
   140007342:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007346:	78 2b                	js     140007373 <__gdtoa+0x10e9>
   140007348:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000734c:	0f 85 96 01 00 00    	jne    1400074e8 <__gdtoa+0x125e>
   140007352:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007359:	0f 85 89 01 00 00    	jne    1400074e8 <__gdtoa+0x125e>
   14000735f:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007366:	8b 00                	mov    eax,DWORD PTR [rax]
   140007368:	83 e0 01             	and    eax,0x1
   14000736b:	85 c0                	test   eax,eax
   14000736d:	0f 85 75 01 00 00    	jne    1400074e8 <__gdtoa+0x125e>
   140007373:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007377:	0f 84 db 00 00 00    	je     140007458 <__gdtoa+0x11ce>
   14000737d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007381:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007384:	83 f8 01             	cmp    eax,0x1
   140007387:	7f 0f                	jg     140007398 <__gdtoa+0x110e>
   140007389:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000738d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007390:	85 c0                	test   eax,eax
   140007392:	0f 84 c0 00 00 00    	je     140007458 <__gdtoa+0x11ce>
   140007398:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   14000739c:	0f 85 83 00 00 00    	jne    140007425 <__gdtoa+0x119b>
   1400073a2:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400073a9:	e9 24 01 00 00       	jmp    1400074d2 <__gdtoa+0x1248>
   1400073ae:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400073b2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400073b6:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400073ba:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400073bd:	88 10                	mov    BYTE PTR [rax],dl
   1400073bf:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400073c3:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400073c9:	ba 0a 00 00 00       	mov    edx,0xa
   1400073ce:	48 89 c1             	mov    rcx,rax
   1400073d1:	e8 43 0a 00 00       	call   140007e19 <__multadd_D2A>
   1400073d6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400073da:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400073de:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400073e2:	75 08                	jne    1400073ec <__gdtoa+0x1162>
   1400073e4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400073e8:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400073ec:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400073f0:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400073f4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073f8:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400073fe:	ba 0a 00 00 00       	mov    edx,0xa
   140007403:	48 89 c1             	mov    rcx,rax
   140007406:	e8 0e 0a 00 00       	call   140007e19 <__multadd_D2A>
   14000740b:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000740f:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007413:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007417:	48 89 c1             	mov    rcx,rax
   14000741a:	e8 af ea ff ff       	call   140005ece <__quorem_D2A>
   14000741f:	83 c0 30             	add    eax,0x30
   140007422:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007425:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007429:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000742d:	48 89 c1             	mov    rcx,rax
   140007430:	e8 c8 10 00 00       	call   1400084fd <__cmp_D2A>
   140007435:	85 c0                	test   eax,eax
   140007437:	0f 8f 71 ff ff ff    	jg     1400073ae <__gdtoa+0x1124>
   14000743d:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007440:	8d 50 01             	lea    edx,[rax+0x1]
   140007443:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007446:	83 f8 39             	cmp    eax,0x39
   140007449:	0f 84 b0 00 00 00    	je     1400074ff <__gdtoa+0x1275>
   14000744f:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007456:	eb 7a                	jmp    1400074d2 <__gdtoa+0x1248>
   140007458:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000745c:	7e 53                	jle    1400074b1 <__gdtoa+0x1227>
   14000745e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007462:	ba 01 00 00 00       	mov    edx,0x1
   140007467:	48 89 c1             	mov    rcx,rax
   14000746a:	e8 01 0f 00 00       	call   140008370 <__lshift_D2A>
   14000746f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007473:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007477:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000747b:	48 89 c1             	mov    rcx,rax
   14000747e:	e8 7a 10 00 00       	call   1400084fd <__cmp_D2A>
   140007483:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007486:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000748a:	7f 10                	jg     14000749c <__gdtoa+0x1212>
   14000748c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007490:	75 18                	jne    1400074aa <__gdtoa+0x1220>
   140007492:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007495:	83 e0 01             	and    eax,0x1
   140007498:	85 c0                	test   eax,eax
   14000749a:	74 0e                	je     1400074aa <__gdtoa+0x1220>
   14000749c:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000749f:	8d 50 01             	lea    edx,[rax+0x1]
   1400074a2:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   1400074a5:	83 f8 39             	cmp    eax,0x39
   1400074a8:	74 58                	je     140007502 <__gdtoa+0x1278>
   1400074aa:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400074b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074b5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400074b8:	83 f8 01             	cmp    eax,0x1
   1400074bb:	7f 0b                	jg     1400074c8 <__gdtoa+0x123e>
   1400074bd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074c1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400074c4:	85 c0                	test   eax,eax
   1400074c6:	74 09                	je     1400074d1 <__gdtoa+0x1247>
   1400074c8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400074cf:	eb 01                	jmp    1400074d2 <__gdtoa+0x1248>
   1400074d1:	90                   	nop
   1400074d2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400074d6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400074da:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400074de:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400074e1:	88 10                	mov    BYTE PTR [rax],dl
   1400074e3:	e9 49 02 00 00       	jmp    140007731 <__gdtoa+0x14a7>
   1400074e8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074ec:	7e 52                	jle    140007540 <__gdtoa+0x12b6>
   1400074ee:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400074f2:	74 4c                	je     140007540 <__gdtoa+0x12b6>
   1400074f4:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400074f8:	75 24                	jne    14000751e <__gdtoa+0x1294>
   1400074fa:	eb 07                	jmp    140007503 <__gdtoa+0x1279>
   1400074fc:	90                   	nop
   1400074fd:	eb 04                	jmp    140007503 <__gdtoa+0x1279>
   1400074ff:	90                   	nop
   140007500:	eb 01                	jmp    140007503 <__gdtoa+0x1279>
   140007502:	90                   	nop
   140007503:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007507:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000750b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000750f:	c6 00 39             	mov    BYTE PTR [rax],0x39
   140007512:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007519:	e9 9d 01 00 00       	jmp    1400076bb <__gdtoa+0x1431>
   14000751e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007525:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007528:	8d 48 01             	lea    ecx,[rax+0x1]
   14000752b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000752f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007533:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007537:	89 ca                	mov    edx,ecx
   140007539:	88 10                	mov    BYTE PTR [rax],dl
   14000753b:	e9 f1 01 00 00       	jmp    140007731 <__gdtoa+0x14a7>
   140007540:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007544:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007548:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000754c:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000754f:	88 10                	mov    BYTE PTR [rax],dl
   140007551:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007554:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140007557:	0f 84 ea 00 00 00    	je     140007647 <__gdtoa+0x13bd>
   14000755d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007561:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007567:	ba 0a 00 00 00       	mov    edx,0xa
   14000756c:	48 89 c1             	mov    rcx,rax
   14000756f:	e8 a5 08 00 00       	call   140007e19 <__multadd_D2A>
   140007574:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007578:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000757c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007580:	75 25                	jne    1400075a7 <__gdtoa+0x131d>
   140007582:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007586:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000758c:	ba 0a 00 00 00       	mov    edx,0xa
   140007591:	48 89 c1             	mov    rcx,rax
   140007594:	e8 80 08 00 00       	call   140007e19 <__multadd_D2A>
   140007599:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000759d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400075a1:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400075a5:	eb 36                	jmp    1400075dd <__gdtoa+0x1353>
   1400075a7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400075ab:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075b1:	ba 0a 00 00 00       	mov    edx,0xa
   1400075b6:	48 89 c1             	mov    rcx,rax
   1400075b9:	e8 5b 08 00 00       	call   140007e19 <__multadd_D2A>
   1400075be:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400075c2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400075c6:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075cc:	ba 0a 00 00 00       	mov    edx,0xa
   1400075d1:	48 89 c1             	mov    rcx,rax
   1400075d4:	e8 40 08 00 00       	call   140007e19 <__multadd_D2A>
   1400075d9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400075dd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400075e0:	83 c0 01             	add    eax,0x1
   1400075e3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400075e6:	e9 71 fc ff ff       	jmp    14000725c <__gdtoa+0xfd2>
   1400075eb:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400075f2:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400075f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075fa:	48 89 c1             	mov    rcx,rax
   1400075fd:	e8 cc e8 ff ff       	call   140005ece <__quorem_D2A>
   140007602:	83 c0 30             	add    eax,0x30
   140007605:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007608:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000760c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007610:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007614:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007617:	88 10                	mov    BYTE PTR [rax],dl
   140007619:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000761c:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   14000761f:	7e 29                	jle    14000764a <__gdtoa+0x13c0>
   140007621:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007625:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000762b:	ba 0a 00 00 00       	mov    edx,0xa
   140007630:	48 89 c1             	mov    rcx,rax
   140007633:	e8 e1 07 00 00       	call   140007e19 <__multadd_D2A>
   140007638:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000763c:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000763f:	83 c0 01             	add    eax,0x1
   140007642:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007645:	eb ab                	jmp    1400075f2 <__gdtoa+0x1368>
   140007647:	90                   	nop
   140007648:	eb 01                	jmp    14000764b <__gdtoa+0x13c1>
   14000764a:	90                   	nop
   14000764b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000764f:	74 26                	je     140007677 <__gdtoa+0x13ed>
   140007651:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007655:	0f 84 ae 00 00 00    	je     140007709 <__gdtoa+0x147f>
   14000765b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000765f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007662:	83 f8 01             	cmp    eax,0x1
   140007665:	7f 50                	jg     1400076b7 <__gdtoa+0x142d>
   140007667:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000766b:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000766e:	85 c0                	test   eax,eax
   140007670:	75 45                	jne    1400076b7 <__gdtoa+0x142d>
   140007672:	e9 92 00 00 00       	jmp    140007709 <__gdtoa+0x147f>
   140007677:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000767b:	ba 01 00 00 00       	mov    edx,0x1
   140007680:	48 89 c1             	mov    rcx,rax
   140007683:	e8 e8 0c 00 00       	call   140008370 <__lshift_D2A>
   140007688:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000768c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007690:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007694:	48 89 c1             	mov    rcx,rax
   140007697:	e8 61 0e 00 00       	call   1400084fd <__cmp_D2A>
   14000769c:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   14000769f:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400076a3:	7f 15                	jg     1400076ba <__gdtoa+0x1430>
   1400076a5:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400076a9:	75 61                	jne    14000770c <__gdtoa+0x1482>
   1400076ab:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400076ae:	83 e0 01             	and    eax,0x1
   1400076b1:	85 c0                	test   eax,eax
   1400076b3:	74 5a                	je     14000770f <__gdtoa+0x1485>
   1400076b5:	eb 04                	jmp    1400076bb <__gdtoa+0x1431>
   1400076b7:	90                   	nop
   1400076b8:	eb 01                	jmp    1400076bb <__gdtoa+0x1431>
   1400076ba:	90                   	nop
   1400076bb:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400076c2:	eb 1f                	jmp    1400076e3 <__gdtoa+0x1459>
   1400076c4:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076c8:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400076cc:	75 15                	jne    1400076e3 <__gdtoa+0x1459>
   1400076ce:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400076d2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076d6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076da:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076de:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400076e1:	eb 4e                	jmp    140007731 <__gdtoa+0x14a7>
   1400076e3:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   1400076e8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076ec:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400076ef:	3c 39                	cmp    al,0x39
   1400076f1:	74 d1                	je     1400076c4 <__gdtoa+0x143a>
   1400076f3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076f7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076fb:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076ff:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140007702:	83 c2 01             	add    edx,0x1
   140007705:	88 10                	mov    BYTE PTR [rax],dl
   140007707:	eb 28                	jmp    140007731 <__gdtoa+0x14a7>
   140007709:	90                   	nop
   14000770a:	eb 04                	jmp    140007710 <__gdtoa+0x1486>
   14000770c:	90                   	nop
   14000770d:	eb 01                	jmp    140007710 <__gdtoa+0x1486>
   14000770f:	90                   	nop
   140007710:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007714:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007717:	83 f8 01             	cmp    eax,0x1
   14000771a:	7f 0b                	jg     140007727 <__gdtoa+0x149d>
   14000771c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007720:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007723:	85 c0                	test   eax,eax
   140007725:	74 09                	je     140007730 <__gdtoa+0x14a6>
   140007727:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000772e:	eb 01                	jmp    140007731 <__gdtoa+0x14a7>
   140007730:	90                   	nop
   140007731:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007735:	48 89 c1             	mov    rcx,rax
   140007738:	e8 51 06 00 00       	call   140007d8e <__Bfree_D2A>
   14000773d:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140007742:	74 31                	je     140007775 <__gdtoa+0x14eb>
   140007744:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140007749:	74 16                	je     140007761 <__gdtoa+0x14d7>
   14000774b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000774f:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007753:	74 0c                	je     140007761 <__gdtoa+0x14d7>
   140007755:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007759:	48 89 c1             	mov    rcx,rax
   14000775c:	e8 2d 06 00 00       	call   140007d8e <__Bfree_D2A>
   140007761:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007765:	48 89 c1             	mov    rcx,rax
   140007768:	e8 21 06 00 00       	call   140007d8e <__Bfree_D2A>
   14000776d:	eb 0e                	jmp    14000777d <__gdtoa+0x14f3>
   14000776f:	90                   	nop
   140007770:	eb 0b                	jmp    14000777d <__gdtoa+0x14f3>
   140007772:	90                   	nop
   140007773:	eb 08                	jmp    14000777d <__gdtoa+0x14f3>
   140007775:	90                   	nop
   140007776:	eb 05                	jmp    14000777d <__gdtoa+0x14f3>
   140007778:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000777d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007781:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140007785:	73 0f                	jae    140007796 <__gdtoa+0x150c>
   140007787:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000778b:	48 83 e8 01          	sub    rax,0x1
   14000778f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140007792:	3c 30                	cmp    al,0x30
   140007794:	74 e2                	je     140007778 <__gdtoa+0x14ee>
   140007796:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000779a:	48 89 c1             	mov    rcx,rax
   14000779d:	e8 ec 05 00 00       	call   140007d8e <__Bfree_D2A>
   1400077a2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077a6:	c6 00 00             	mov    BYTE PTR [rax],0x0
   1400077a9:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400077ac:	8d 50 01             	lea    edx,[rax+0x1]
   1400077af:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400077b6:	89 10                	mov    DWORD PTR [rax],edx
   1400077b8:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   1400077bf:	00 
   1400077c0:	74 0e                	je     1400077d0 <__gdtoa+0x1546>
   1400077c2:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400077c9:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   1400077cd:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400077d0:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400077d7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400077d9:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   1400077dc:	89 c2                	mov    edx,eax
   1400077de:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400077e5:	89 10                	mov    DWORD PTR [rax],edx
   1400077e7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400077eb:	48 81 c4 00 01 00 00 	add    rsp,0x100
   1400077f2:	5d                   	pop    rbp
   1400077f3:	c3                   	ret
   1400077f4:	90                   	nop
   1400077f5:	90                   	nop
   1400077f6:	90                   	nop
   1400077f7:	90                   	nop
   1400077f8:	90                   	nop
   1400077f9:	90                   	nop
   1400077fa:	90                   	nop
   1400077fb:	90                   	nop
   1400077fc:	90                   	nop
   1400077fd:	90                   	nop
   1400077fe:	90                   	nop
   1400077ff:	90                   	nop

0000000140007800 <__lo0bits_D2A>:
   140007800:	55                   	push   rbp
   140007801:	48 89 e5             	mov    rbp,rsp
   140007804:	48 83 ec 10          	sub    rsp,0x10
   140007808:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000780c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007810:	8b 00                	mov    eax,DWORD PTR [rax]
   140007812:	f3 0f bc c0          	tzcnt  eax,eax
   140007816:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007819:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000781d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000781f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007822:	89 c1                	mov    ecx,eax
   140007824:	d3 ea                	shr    edx,cl
   140007826:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000782a:	89 10                	mov    DWORD PTR [rax],edx
   14000782c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000782f:	48 83 c4 10          	add    rsp,0x10
   140007833:	5d                   	pop    rbp
   140007834:	c3                   	ret

0000000140007835 <__rshift_D2A>:
   140007835:	55                   	push   rbp
   140007836:	48 89 e5             	mov    rbp,rsp
   140007839:	48 83 ec 20          	sub    rsp,0x20
   14000783d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007841:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007844:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007848:	48 83 c0 18          	add    rax,0x18
   14000784c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007850:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007854:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007858:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000785b:	c1 f8 05             	sar    eax,0x5
   14000785e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007861:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007865:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007868:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   14000786b:	0f 8d e4 00 00 00    	jge    140007955 <__rshift_D2A+0x120>
   140007871:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007875:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007878:	48 98                	cdqe
   14000787a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007881:	00 
   140007882:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007886:	48 01 d0             	add    rax,rdx
   140007889:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000788d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007890:	48 98                	cdqe
   140007892:	48 c1 e0 02          	shl    rax,0x2
   140007896:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   14000789a:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000789e:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400078a2:	0f 84 a3 00 00 00    	je     14000794b <__rshift_D2A+0x116>
   1400078a8:	b8 20 00 00 00       	mov    eax,0x20
   1400078ad:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400078b0:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400078b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078b7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400078bb:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400078bf:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078c1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400078c4:	89 c1                	mov    ecx,eax
   1400078c6:	d3 ea                	shr    edx,cl
   1400078c8:	89 d0                	mov    eax,edx
   1400078ca:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400078cd:	eb 3c                	jmp    14000790b <__rshift_D2A+0xd6>
   1400078cf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078d3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078d5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400078d8:	89 c1                	mov    ecx,eax
   1400078da:	d3 e2                	shl    edx,cl
   1400078dc:	89 d1                	mov    ecx,edx
   1400078de:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400078e2:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400078e6:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400078ea:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   1400078ed:	89 ca                	mov    edx,ecx
   1400078ef:	89 10                	mov    DWORD PTR [rax],edx
   1400078f1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078f5:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400078f9:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400078fd:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078ff:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007902:	89 c1                	mov    ecx,eax
   140007904:	d3 ea                	shr    edx,cl
   140007906:	89 d0                	mov    eax,edx
   140007908:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000790b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000790f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007913:	72 ba                	jb     1400078cf <__rshift_D2A+0x9a>
   140007915:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007919:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   14000791c:	89 10                	mov    DWORD PTR [rax],edx
   14000791e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007922:	8b 00                	mov    eax,DWORD PTR [rax]
   140007924:	85 c0                	test   eax,eax
   140007926:	74 2d                	je     140007955 <__rshift_D2A+0x120>
   140007928:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   14000792d:	eb 26                	jmp    140007955 <__rshift_D2A+0x120>
   14000792f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140007933:	48 8d 42 04          	lea    rax,[rdx+0x4]
   140007937:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000793b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000793f:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140007943:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   140007947:	8b 12                	mov    edx,DWORD PTR [rdx]
   140007949:	89 10                	mov    DWORD PTR [rax],edx
   14000794b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000794f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007953:	72 da                	jb     14000792f <__rshift_D2A+0xfa>
   140007955:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007959:	48 83 c0 18          	add    rax,0x18
   14000795d:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140007961:	48 29 c2             	sub    rdx,rax
   140007964:	48 89 d0             	mov    rax,rdx
   140007967:	48 c1 f8 02          	sar    rax,0x2
   14000796b:	89 c2                	mov    edx,eax
   14000796d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007971:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007974:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007978:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000797b:	85 c0                	test   eax,eax
   14000797d:	75 0b                	jne    14000798a <__rshift_D2A+0x155>
   14000797f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007983:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000798a:	90                   	nop
   14000798b:	48 83 c4 20          	add    rsp,0x20
   14000798f:	5d                   	pop    rbp
   140007990:	c3                   	ret

0000000140007991 <__trailz_D2A>:
   140007991:	55                   	push   rbp
   140007992:	48 89 e5             	mov    rbp,rsp
   140007995:	48 83 ec 40          	sub    rsp,0x40
   140007999:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000799d:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400079a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079a8:	48 83 c0 18          	add    rax,0x18
   1400079ac:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400079b0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079b4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400079b7:	48 98                	cdqe
   1400079b9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400079c0:	00 
   1400079c1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079c5:	48 01 d0             	add    rax,rdx
   1400079c8:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400079cc:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400079d3:	eb 09                	jmp    1400079de <__trailz_D2A+0x4d>
   1400079d5:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   1400079d9:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   1400079de:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079e2:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400079e6:	73 0a                	jae    1400079f2 <__trailz_D2A+0x61>
   1400079e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079ec:	8b 00                	mov    eax,DWORD PTR [rax]
   1400079ee:	85 c0                	test   eax,eax
   1400079f0:	74 e3                	je     1400079d5 <__trailz_D2A+0x44>
   1400079f2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079f6:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400079fa:	73 18                	jae    140007a14 <__trailz_D2A+0x83>
   1400079fc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a00:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a02:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007a05:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007a09:	48 89 c1             	mov    rcx,rax
   140007a0c:	e8 ef fd ff ff       	call   140007800 <__lo0bits_D2A>
   140007a11:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007a14:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007a17:	48 83 c4 40          	add    rsp,0x40
   140007a1b:	5d                   	pop    rbp
   140007a1c:	c3                   	ret
   140007a1d:	90                   	nop
   140007a1e:	90                   	nop
   140007a1f:	90                   	nop

0000000140007a20 <dtoa_lock_cleanup>:
   140007a20:	55                   	push   rbp
   140007a21:	48 89 e5             	mov    rbp,rsp
   140007a24:	48 83 ec 40          	sub    rsp,0x40
   140007a28:	48 8d 05 c1 77 00 00 	lea    rax,[rip+0x77c1]        # 14000f1f0 <dtoa_CS_init>
   140007a2f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007a33:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007a3a:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007a3d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a41:	87 10                	xchg   DWORD PTR [rax],edx
   140007a43:	89 d0                	mov    eax,edx
   140007a45:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007a48:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007a4c:	75 3d                	jne    140007a8b <dtoa_lock_cleanup+0x6b>
   140007a4e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007a55:	eb 2e                	jmp    140007a85 <dtoa_lock_cleanup+0x65>
   140007a57:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007a5a:	48 63 d0             	movsxd rdx,eax
   140007a5d:	48 89 d0             	mov    rax,rdx
   140007a60:	48 c1 e0 02          	shl    rax,0x2
   140007a64:	48 01 d0             	add    rax,rdx
   140007a67:	48 c1 e0 03          	shl    rax,0x3
   140007a6b:	48 8d 15 2e 77 00 00 	lea    rdx,[rip+0x772e]        # 14000f1a0 <dtoa_CritSec>
   140007a72:	48 01 d0             	add    rax,rdx
   140007a75:	48 89 c1             	mov    rcx,rax
   140007a78:	48 8b 05 69 87 00 00 	mov    rax,QWORD PTR [rip+0x8769]        # 1400101e8 <__IAT_start__>
   140007a7f:	ff d0                	call   rax
   140007a81:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007a85:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007a89:	7e cc                	jle    140007a57 <dtoa_lock_cleanup+0x37>
   140007a8b:	90                   	nop
   140007a8c:	48 83 c4 40          	add    rsp,0x40
   140007a90:	5d                   	pop    rbp
   140007a91:	c3                   	ret

0000000140007a92 <dtoa_lock>:
   140007a92:	55                   	push   rbp
   140007a93:	48 89 e5             	mov    rbp,rsp
   140007a96:	48 83 ec 40          	sub    rsp,0x40
   140007a9a:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007a9d:	8b 05 4d 77 00 00    	mov    eax,DWORD PTR [rip+0x774d]        # 14000f1f0 <dtoa_CS_init>
   140007aa3:	83 f8 02             	cmp    eax,0x2
   140007aa6:	75 2c                	jne    140007ad4 <dtoa_lock+0x42>
   140007aa8:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007aab:	48 89 d0             	mov    rax,rdx
   140007aae:	48 c1 e0 02          	shl    rax,0x2
   140007ab2:	48 01 d0             	add    rax,rdx
   140007ab5:	48 c1 e0 03          	shl    rax,0x3
   140007ab9:	48 8d 15 e0 76 00 00 	lea    rdx,[rip+0x76e0]        # 14000f1a0 <dtoa_CritSec>
   140007ac0:	48 01 d0             	add    rax,rdx
   140007ac3:	48 89 c1             	mov    rcx,rax
   140007ac6:	48 8b 05 23 87 00 00 	mov    rax,QWORD PTR [rip+0x8723]        # 1400101f0 <__imp_EnterCriticalSection>
   140007acd:	ff d0                	call   rax
   140007acf:	e9 ea 00 00 00       	jmp    140007bbe <dtoa_lock+0x12c>
   140007ad4:	8b 05 16 77 00 00    	mov    eax,DWORD PTR [rip+0x7716]        # 14000f1f0 <dtoa_CS_init>
   140007ada:	85 c0                	test   eax,eax
   140007adc:	0f 85 9e 00 00 00    	jne    140007b80 <dtoa_lock+0xee>
   140007ae2:	48 8d 05 07 77 00 00 	lea    rax,[rip+0x7707]        # 14000f1f0 <dtoa_CS_init>
   140007ae9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007aed:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007af4:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007af7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007afb:	87 10                	xchg   DWORD PTR [rax],edx
   140007afd:	89 d0                	mov    eax,edx
   140007aff:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007b02:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007b06:	75 58                	jne    140007b60 <dtoa_lock+0xce>
   140007b08:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007b0f:	eb 2e                	jmp    140007b3f <dtoa_lock+0xad>
   140007b11:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007b14:	48 63 d0             	movsxd rdx,eax
   140007b17:	48 89 d0             	mov    rax,rdx
   140007b1a:	48 c1 e0 02          	shl    rax,0x2
   140007b1e:	48 01 d0             	add    rax,rdx
   140007b21:	48 c1 e0 03          	shl    rax,0x3
   140007b25:	48 8d 15 74 76 00 00 	lea    rdx,[rip+0x7674]        # 14000f1a0 <dtoa_CritSec>
   140007b2c:	48 01 d0             	add    rax,rdx
   140007b2f:	48 89 c1             	mov    rcx,rax
   140007b32:	48 8b 05 e7 86 00 00 	mov    rax,QWORD PTR [rip+0x86e7]        # 140010220 <__imp_InitializeCriticalSection>
   140007b39:	ff d0                	call   rax
   140007b3b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b3f:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b43:	7e cc                	jle    140007b11 <dtoa_lock+0x7f>
   140007b45:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007a20 <dtoa_lock_cleanup>
   140007b4c:	48 89 c1             	mov    rcx,rax
   140007b4f:	e8 db 9a ff ff       	call   14000162f <atexit>
   140007b54:	c7 05 92 76 00 00 02 	mov    DWORD PTR [rip+0x7692],0x2        # 14000f1f0 <dtoa_CS_init>
   140007b5b:	00 00 00 
   140007b5e:	eb 20                	jmp    140007b80 <dtoa_lock+0xee>
   140007b60:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007b64:	75 1a                	jne    140007b80 <dtoa_lock+0xee>
   140007b66:	c7 05 80 76 00 00 02 	mov    DWORD PTR [rip+0x7680],0x2        # 14000f1f0 <dtoa_CS_init>
   140007b6d:	00 00 00 
   140007b70:	eb 0e                	jmp    140007b80 <dtoa_lock+0xee>
   140007b72:	b9 01 00 00 00       	mov    ecx,0x1
   140007b77:	48 8b 05 ca 86 00 00 	mov    rax,QWORD PTR [rip+0x86ca]        # 140010248 <__imp_Sleep>
   140007b7e:	ff d0                	call   rax
   140007b80:	8b 05 6a 76 00 00    	mov    eax,DWORD PTR [rip+0x766a]        # 14000f1f0 <dtoa_CS_init>
   140007b86:	83 f8 01             	cmp    eax,0x1
   140007b89:	74 e7                	je     140007b72 <dtoa_lock+0xe0>
   140007b8b:	8b 05 5f 76 00 00    	mov    eax,DWORD PTR [rip+0x765f]        # 14000f1f0 <dtoa_CS_init>
   140007b91:	83 f8 02             	cmp    eax,0x2
   140007b94:	75 28                	jne    140007bbe <dtoa_lock+0x12c>
   140007b96:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007b99:	48 89 d0             	mov    rax,rdx
   140007b9c:	48 c1 e0 02          	shl    rax,0x2
   140007ba0:	48 01 d0             	add    rax,rdx
   140007ba3:	48 c1 e0 03          	shl    rax,0x3
   140007ba7:	48 8d 15 f2 75 00 00 	lea    rdx,[rip+0x75f2]        # 14000f1a0 <dtoa_CritSec>
   140007bae:	48 01 d0             	add    rax,rdx
   140007bb1:	48 89 c1             	mov    rcx,rax
   140007bb4:	48 8b 05 35 86 00 00 	mov    rax,QWORD PTR [rip+0x8635]        # 1400101f0 <__imp_EnterCriticalSection>
   140007bbb:	ff d0                	call   rax
   140007bbd:	90                   	nop
   140007bbe:	48 83 c4 40          	add    rsp,0x40
   140007bc2:	5d                   	pop    rbp
   140007bc3:	c3                   	ret

0000000140007bc4 <dtoa_unlock>:
   140007bc4:	55                   	push   rbp
   140007bc5:	48 89 e5             	mov    rbp,rsp
   140007bc8:	48 83 ec 20          	sub    rsp,0x20
   140007bcc:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007bcf:	8b 05 1b 76 00 00    	mov    eax,DWORD PTR [rip+0x761b]        # 14000f1f0 <dtoa_CS_init>
   140007bd5:	83 f8 02             	cmp    eax,0x2
   140007bd8:	75 27                	jne    140007c01 <dtoa_unlock+0x3d>
   140007bda:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007bdd:	48 89 d0             	mov    rax,rdx
   140007be0:	48 c1 e0 02          	shl    rax,0x2
   140007be4:	48 01 d0             	add    rax,rdx
   140007be7:	48 c1 e0 03          	shl    rax,0x3
   140007beb:	48 8d 15 ae 75 00 00 	lea    rdx,[rip+0x75ae]        # 14000f1a0 <dtoa_CritSec>
   140007bf2:	48 01 d0             	add    rax,rdx
   140007bf5:	48 89 c1             	mov    rcx,rax
   140007bf8:	48 8b 05 29 86 00 00 	mov    rax,QWORD PTR [rip+0x8629]        # 140010228 <__imp_LeaveCriticalSection>
   140007bff:	ff d0                	call   rax
   140007c01:	90                   	nop
   140007c02:	48 83 c4 20          	add    rsp,0x20
   140007c06:	5d                   	pop    rbp
   140007c07:	c3                   	ret

0000000140007c08 <__lo0bits_D2A>:
   140007c08:	55                   	push   rbp
   140007c09:	48 89 e5             	mov    rbp,rsp
   140007c0c:	48 83 ec 10          	sub    rsp,0x10
   140007c10:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007c14:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c18:	8b 00                	mov    eax,DWORD PTR [rax]
   140007c1a:	f3 0f bc c0          	tzcnt  eax,eax
   140007c1e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007c21:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c25:	8b 10                	mov    edx,DWORD PTR [rax]
   140007c27:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c2a:	89 c1                	mov    ecx,eax
   140007c2c:	d3 ea                	shr    edx,cl
   140007c2e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c32:	89 10                	mov    DWORD PTR [rax],edx
   140007c34:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c37:	48 83 c4 10          	add    rsp,0x10
   140007c3b:	5d                   	pop    rbp
   140007c3c:	c3                   	ret

0000000140007c3d <__hi0bits_D2A>:
   140007c3d:	55                   	push   rbp
   140007c3e:	48 89 e5             	mov    rbp,rsp
   140007c41:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c44:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007c48:	83 f0 1f             	xor    eax,0x1f
   140007c4b:	5d                   	pop    rbp
   140007c4c:	c3                   	ret

0000000140007c4d <__Balloc_D2A>:
   140007c4d:	55                   	push   rbp
   140007c4e:	48 89 e5             	mov    rbp,rsp
   140007c51:	48 83 ec 30          	sub    rsp,0x30
   140007c55:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c58:	b9 00 00 00 00       	mov    ecx,0x0
   140007c5d:	e8 30 fe ff ff       	call   140007a92 <dtoa_lock>
   140007c62:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007c66:	7f 48                	jg     140007cb0 <__Balloc_D2A+0x63>
   140007c68:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007c6b:	48 98                	cdqe
   140007c6d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007c74:	00 
   140007c75:	48 8d 05 84 75 00 00 	lea    rax,[rip+0x7584]        # 14000f200 <freelist>
   140007c7c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007c80:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007c84:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007c89:	74 25                	je     140007cb0 <__Balloc_D2A+0x63>
   140007c8b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007c8f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007c92:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c95:	48 63 d2             	movsxd rdx,edx
   140007c98:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007c9f:	00 
   140007ca0:	48 8d 15 59 75 00 00 	lea    rdx,[rip+0x7559]        # 14000f200 <freelist>
   140007ca7:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007cab:	e9 b1 00 00 00       	jmp    140007d61 <__Balloc_D2A+0x114>
   140007cb0:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007cb3:	ba 01 00 00 00       	mov    edx,0x1
   140007cb8:	89 c1                	mov    ecx,eax
   140007cba:	d3 e2                	shl    edx,cl
   140007cbc:	89 d0                	mov    eax,edx
   140007cbe:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007cc1:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007cc4:	83 e8 01             	sub    eax,0x1
   140007cc7:	48 98                	cdqe
   140007cc9:	48 c1 e0 02          	shl    rax,0x2
   140007ccd:	48 83 c0 27          	add    rax,0x27
   140007cd1:	48 c1 e8 03          	shr    rax,0x3
   140007cd5:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007cd8:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007cdc:	7f 4e                	jg     140007d2c <__Balloc_D2A+0xdf>
   140007cde:	48 8b 15 ab 23 00 00 	mov    rdx,QWORD PTR [rip+0x23ab]        # 14000a090 <pmem_next>
   140007ce5:	48 8d 05 74 75 00 00 	lea    rax,[rip+0x7574]        # 14000f260 <private_mem>
   140007cec:	48 29 c2             	sub    rdx,rax
   140007cef:	48 89 d0             	mov    rax,rdx
   140007cf2:	48 c1 f8 03          	sar    rax,0x3
   140007cf6:	48 89 c2             	mov    rdx,rax
   140007cf9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007cfc:	48 01 d0             	add    rax,rdx
   140007cff:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007d05:	77 25                	ja     140007d2c <__Balloc_D2A+0xdf>
   140007d07:	48 8b 05 82 23 00 00 	mov    rax,QWORD PTR [rip+0x2382]        # 14000a090 <pmem_next>
   140007d0e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d12:	48 8b 05 77 23 00 00 	mov    rax,QWORD PTR [rip+0x2377]        # 14000a090 <pmem_next>
   140007d19:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007d1c:	48 c1 e2 03          	shl    rdx,0x3
   140007d20:	48 01 d0             	add    rax,rdx
   140007d23:	48 89 05 66 23 00 00 	mov    QWORD PTR [rip+0x2366],rax        # 14000a090 <pmem_next>
   140007d2a:	eb 21                	jmp    140007d4d <__Balloc_D2A+0x100>
   140007d2c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d2f:	48 c1 e0 03          	shl    rax,0x3
   140007d33:	48 89 c1             	mov    rcx,rax
   140007d36:	e8 e5 18 00 00       	call   140009620 <malloc>
   140007d3b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d3f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d44:	75 07                	jne    140007d4d <__Balloc_D2A+0x100>
   140007d46:	b8 00 00 00 00       	mov    eax,0x0
   140007d4b:	eb 3b                	jmp    140007d88 <__Balloc_D2A+0x13b>
   140007d4d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d51:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d54:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007d57:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d5b:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007d5e:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007d61:	b9 00 00 00 00       	mov    ecx,0x0
   140007d66:	e8 59 fe ff ff       	call   140007bc4 <dtoa_unlock>
   140007d6b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d6f:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007d76:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d7a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007d7d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d81:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007d84:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d88:	48 83 c4 30          	add    rsp,0x30
   140007d8c:	5d                   	pop    rbp
   140007d8d:	c3                   	ret

0000000140007d8e <__Bfree_D2A>:
   140007d8e:	55                   	push   rbp
   140007d8f:	48 89 e5             	mov    rbp,rsp
   140007d92:	48 83 ec 20          	sub    rsp,0x20
   140007d96:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007d9a:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007d9f:	74 71                	je     140007e12 <__Bfree_D2A+0x84>
   140007da1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007da5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007da8:	83 f8 09             	cmp    eax,0x9
   140007dab:	7e 0e                	jle    140007dbb <__Bfree_D2A+0x2d>
   140007dad:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007db1:	48 89 c1             	mov    rcx,rax
   140007db4:	e8 57 18 00 00       	call   140009610 <free>
   140007db9:	eb 57                	jmp    140007e12 <__Bfree_D2A+0x84>
   140007dbb:	b9 00 00 00 00       	mov    ecx,0x0
   140007dc0:	e8 cd fc ff ff       	call   140007a92 <dtoa_lock>
   140007dc5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007dc9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007dcc:	48 98                	cdqe
   140007dce:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007dd5:	00 
   140007dd6:	48 8d 05 23 74 00 00 	lea    rax,[rip+0x7423]        # 14000f200 <freelist>
   140007ddd:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007de1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007de5:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007de8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007dec:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007def:	48 98                	cdqe
   140007df1:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007df8:	00 
   140007df9:	48 8d 15 00 74 00 00 	lea    rdx,[rip+0x7400]        # 14000f200 <freelist>
   140007e00:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e04:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007e08:	b9 00 00 00 00       	mov    ecx,0x0
   140007e0d:	e8 b2 fd ff ff       	call   140007bc4 <dtoa_unlock>
   140007e12:	90                   	nop
   140007e13:	48 83 c4 20          	add    rsp,0x20
   140007e17:	5d                   	pop    rbp
   140007e18:	c3                   	ret

0000000140007e19 <__multadd_D2A>:
   140007e19:	55                   	push   rbp
   140007e1a:	48 89 e5             	mov    rbp,rsp
   140007e1d:	48 83 ec 50          	sub    rsp,0x50
   140007e21:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e25:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007e28:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007e2c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e30:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007e33:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007e36:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e3a:	48 83 c0 18          	add    rax,0x18
   140007e3e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007e42:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007e49:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007e4c:	48 98                	cdqe
   140007e4e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007e52:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007e56:	8b 00                	mov    eax,DWORD PTR [rax]
   140007e58:	89 c2                	mov    edx,eax
   140007e5a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007e5d:	48 98                	cdqe
   140007e5f:	48 0f af d0          	imul   rdx,rax
   140007e63:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007e67:	48 01 d0             	add    rax,rdx
   140007e6a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007e6e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007e72:	48 c1 e8 20          	shr    rax,0x20
   140007e76:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007e7a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007e7e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007e82:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007e86:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007e8a:	89 10                	mov    DWORD PTR [rax],edx
   140007e8c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007e90:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007e93:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007e96:	7c ba                	jl     140007e52 <__multadd_D2A+0x39>
   140007e98:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007e9d:	0f 84 9a 00 00 00    	je     140007f3d <__multadd_D2A+0x124>
   140007ea3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ea7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007eaa:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007ead:	7c 67                	jl     140007f16 <__multadd_D2A+0xfd>
   140007eaf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eb3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007eb6:	83 c0 01             	add    eax,0x1
   140007eb9:	89 c1                	mov    ecx,eax
   140007ebb:	e8 8d fd ff ff       	call   140007c4d <__Balloc_D2A>
   140007ec0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007ec4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007ec9:	75 07                	jne    140007ed2 <__multadd_D2A+0xb9>
   140007ecb:	b8 00 00 00 00       	mov    eax,0x0
   140007ed0:	eb 6f                	jmp    140007f41 <__multadd_D2A+0x128>
   140007ed2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ed6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ed9:	48 98                	cdqe
   140007edb:	48 83 c0 02          	add    rax,0x2
   140007edf:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007ee6:	00 
   140007ee7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eeb:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007eef:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007ef3:	48 83 c0 10          	add    rax,0x10
   140007ef7:	49 89 c8             	mov    r8,rcx
   140007efa:	48 89 c1             	mov    rcx,rax
   140007efd:	e8 26 17 00 00       	call   140009628 <memcpy>
   140007f02:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f06:	48 89 c1             	mov    rcx,rax
   140007f09:	e8 80 fe ff ff       	call   140007d8e <__Bfree_D2A>
   140007f0e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007f12:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007f16:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007f19:	8d 50 01             	lea    edx,[rax+0x1]
   140007f1c:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007f1f:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140007f23:	89 d1                	mov    ecx,edx
   140007f25:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007f29:	48 98                	cdqe
   140007f2b:	48 83 c0 04          	add    rax,0x4
   140007f2f:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140007f33:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f37:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140007f3a:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007f3d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f41:	48 83 c4 50          	add    rsp,0x50
   140007f45:	5d                   	pop    rbp
   140007f46:	c3                   	ret

0000000140007f47 <__i2b_D2A>:
   140007f47:	55                   	push   rbp
   140007f48:	48 89 e5             	mov    rbp,rsp
   140007f4b:	48 83 ec 30          	sub    rsp,0x30
   140007f4f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007f52:	b9 01 00 00 00       	mov    ecx,0x1
   140007f57:	e8 f1 fc ff ff       	call   140007c4d <__Balloc_D2A>
   140007f5c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007f60:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007f65:	75 07                	jne    140007f6e <__i2b_D2A+0x27>
   140007f67:	b8 00 00 00 00       	mov    eax,0x0
   140007f6c:	eb 19                	jmp    140007f87 <__i2b_D2A+0x40>
   140007f6e:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007f71:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f75:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140007f78:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f7c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140007f83:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f87:	48 83 c4 30          	add    rsp,0x30
   140007f8b:	5d                   	pop    rbp
   140007f8c:	c3                   	ret

0000000140007f8d <__mult_D2A>:
   140007f8d:	55                   	push   rbp
   140007f8e:	48 89 e5             	mov    rbp,rsp
   140007f91:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140007f98:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007f9c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140007fa0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fa4:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007fa7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007fab:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fae:	39 c2                	cmp    edx,eax
   140007fb0:	7d 18                	jge    140007fca <__mult_D2A+0x3d>
   140007fb2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fb6:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140007fba:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007fbe:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007fc2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140007fc6:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007fca:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fce:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007fd1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007fd4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fd8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fdb:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   140007fde:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007fe2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fe5:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   140007fe8:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140007feb:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140007fee:	01 d0                	add    eax,edx
   140007ff0:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007ff3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ff7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007ffa:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   140007ffd:	7e 04                	jle    140008003 <__mult_D2A+0x76>
   140007fff:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008003:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008006:	89 c1                	mov    ecx,eax
   140008008:	e8 40 fc ff ff       	call   140007c4d <__Balloc_D2A>
   14000800d:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008011:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   140008016:	75 0a                	jne    140008022 <__mult_D2A+0x95>
   140008018:	b8 00 00 00 00       	mov    eax,0x0
   14000801d:	e9 88 01 00 00       	jmp    1400081aa <__mult_D2A+0x21d>
   140008022:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008026:	48 83 c0 18          	add    rax,0x18
   14000802a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000802e:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008031:	48 98                	cdqe
   140008033:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000803a:	00 
   14000803b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000803f:	48 01 d0             	add    rax,rdx
   140008042:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140008046:	eb 0f                	jmp    140008057 <__mult_D2A+0xca>
   140008048:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000804c:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008052:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140008057:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000805b:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   14000805f:	72 e7                	jb     140008048 <__mult_D2A+0xbb>
   140008061:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008065:	48 83 c0 18          	add    rax,0x18
   140008069:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000806d:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008070:	48 98                	cdqe
   140008072:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008079:	00 
   14000807a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000807e:	48 01 d0             	add    rax,rdx
   140008081:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008085:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008089:	48 83 c0 18          	add    rax,0x18
   14000808d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008091:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140008094:	48 98                	cdqe
   140008096:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000809d:	00 
   14000809e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400080a2:	48 01 d0             	add    rax,rdx
   1400080a5:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   1400080a9:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400080ad:	48 83 c0 18          	add    rax,0x18
   1400080b1:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400080b5:	e9 95 00 00 00       	jmp    14000814f <__mult_D2A+0x1c2>
   1400080ba:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400080be:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400080c2:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400080c6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400080c8:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   1400080cb:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   1400080cf:	74 79                	je     14000814a <__mult_D2A+0x1bd>
   1400080d1:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400080d5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400080d9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400080dd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400080e1:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400080e8:	00 
   1400080e9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080ed:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400080f1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400080f5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400080f7:	89 c2                	mov    edx,eax
   1400080f9:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   1400080fc:	48 0f af d0          	imul   rdx,rax
   140008100:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008104:	8b 00                	mov    eax,DWORD PTR [rax]
   140008106:	89 c0                	mov    eax,eax
   140008108:	48 01 c2             	add    rdx,rax
   14000810b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000810f:	48 01 d0             	add    rax,rdx
   140008112:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140008116:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   14000811a:	48 c1 e8 20          	shr    rax,0x20
   14000811e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008122:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008126:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000812a:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000812e:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140008132:	89 10                	mov    DWORD PTR [rax],edx
   140008134:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008138:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   14000813c:	72 ab                	jb     1400080e9 <__mult_D2A+0x15c>
   14000813e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008142:	89 c2                	mov    edx,eax
   140008144:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008148:	89 10                	mov    DWORD PTR [rax],edx
   14000814a:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   14000814f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008153:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   140008157:	0f 82 5d ff ff ff    	jb     1400080ba <__mult_D2A+0x12d>
   14000815d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008161:	48 83 c0 18          	add    rax,0x18
   140008165:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008169:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000816c:	48 98                	cdqe
   14000816e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008175:	00 
   140008176:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000817a:	48 01 d0             	add    rax,rdx
   14000817d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008181:	eb 04                	jmp    140008187 <__mult_D2A+0x1fa>
   140008183:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008187:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000818b:	7e 0f                	jle    14000819c <__mult_D2A+0x20f>
   14000818d:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008192:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008196:	8b 00                	mov    eax,DWORD PTR [rax]
   140008198:	85 c0                	test   eax,eax
   14000819a:	74 e7                	je     140008183 <__mult_D2A+0x1f6>
   14000819c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081a0:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400081a3:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400081a6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081aa:	48 81 c4 90 00 00 00 	add    rsp,0x90
   1400081b1:	5d                   	pop    rbp
   1400081b2:	c3                   	ret

00000001400081b3 <__pow5mult_D2A>:
   1400081b3:	55                   	push   rbp
   1400081b4:	48 89 e5             	mov    rbp,rsp
   1400081b7:	48 83 ec 40          	sub    rsp,0x40
   1400081bb:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400081bf:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400081c2:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400081c5:	83 e0 03             	and    eax,0x3
   1400081c8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400081cb:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400081cf:	74 41                	je     140008212 <__pow5mult_D2A+0x5f>
   1400081d1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400081d4:	83 e8 01             	sub    eax,0x1
   1400081d7:	48 98                	cdqe
   1400081d9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400081e0:	00 
   1400081e1:	48 8d 05 b0 1e 00 00 	lea    rax,[rip+0x1eb0]        # 14000a098 <p05.0>
   1400081e8:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   1400081eb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400081ef:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400081f5:	48 89 c1             	mov    rcx,rax
   1400081f8:	e8 1c fc ff ff       	call   140007e19 <__multadd_D2A>
   1400081fd:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008201:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140008206:	75 0a                	jne    140008212 <__pow5mult_D2A+0x5f>
   140008208:	b8 00 00 00 00       	mov    eax,0x0
   14000820d:	e9 58 01 00 00       	jmp    14000836a <__pow5mult_D2A+0x1b7>
   140008212:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   140008216:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000821a:	75 09                	jne    140008225 <__pow5mult_D2A+0x72>
   14000821c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008220:	e9 45 01 00 00       	jmp    14000836a <__pow5mult_D2A+0x1b7>
   140008225:	48 8b 05 34 79 00 00 	mov    rax,QWORD PTR [rip+0x7934]        # 14000fb60 <p5s>
   14000822c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008230:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008235:	75 5e                	jne    140008295 <__pow5mult_D2A+0xe2>
   140008237:	b9 01 00 00 00       	mov    ecx,0x1
   14000823c:	e8 51 f8 ff ff       	call   140007a92 <dtoa_lock>
   140008241:	48 8b 05 18 79 00 00 	mov    rax,QWORD PTR [rip+0x7918]        # 14000fb60 <p5s>
   140008248:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000824c:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008251:	75 38                	jne    14000828b <__pow5mult_D2A+0xd8>
   140008253:	b9 71 02 00 00       	mov    ecx,0x271
   140008258:	e8 ea fc ff ff       	call   140007f47 <__i2b_D2A>
   14000825d:	48 89 05 fc 78 00 00 	mov    QWORD PTR [rip+0x78fc],rax        # 14000fb60 <p5s>
   140008264:	48 8b 05 f5 78 00 00 	mov    rax,QWORD PTR [rip+0x78f5]        # 14000fb60 <p5s>
   14000826b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000826f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008274:	75 0a                	jne    140008280 <__pow5mult_D2A+0xcd>
   140008276:	b8 00 00 00 00       	mov    eax,0x0
   14000827b:	e9 ea 00 00 00       	jmp    14000836a <__pow5mult_D2A+0x1b7>
   140008280:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008284:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000828b:	b9 01 00 00 00       	mov    ecx,0x1
   140008290:	e8 2f f9 ff ff       	call   140007bc4 <dtoa_unlock>
   140008295:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008298:	83 e0 01             	and    eax,0x1
   14000829b:	85 c0                	test   eax,eax
   14000829d:	74 39                	je     1400082d8 <__pow5mult_D2A+0x125>
   14000829f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400082a3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082a7:	48 89 c1             	mov    rcx,rax
   1400082aa:	e8 de fc ff ff       	call   140007f8d <__mult_D2A>
   1400082af:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400082b3:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   1400082b8:	75 0a                	jne    1400082c4 <__pow5mult_D2A+0x111>
   1400082ba:	b8 00 00 00 00       	mov    eax,0x0
   1400082bf:	e9 a6 00 00 00       	jmp    14000836a <__pow5mult_D2A+0x1b7>
   1400082c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082c8:	48 89 c1             	mov    rcx,rax
   1400082cb:	e8 be fa ff ff       	call   140007d8e <__Bfree_D2A>
   1400082d0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400082d4:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400082d8:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   1400082db:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400082df:	0f 84 80 00 00 00    	je     140008365 <__pow5mult_D2A+0x1b2>
   1400082e5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400082e9:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400082ec:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400082f0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400082f5:	75 61                	jne    140008358 <__pow5mult_D2A+0x1a5>
   1400082f7:	b9 01 00 00 00       	mov    ecx,0x1
   1400082fc:	e8 91 f7 ff ff       	call   140007a92 <dtoa_lock>
   140008301:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008305:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008308:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000830c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008311:	75 3b                	jne    14000834e <__pow5mult_D2A+0x19b>
   140008313:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008317:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000831b:	48 89 c1             	mov    rcx,rax
   14000831e:	e8 6a fc ff ff       	call   140007f8d <__mult_D2A>
   140008323:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008327:	48 89 02             	mov    QWORD PTR [rdx],rax
   14000832a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000832e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008331:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008335:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000833a:	75 07                	jne    140008343 <__pow5mult_D2A+0x190>
   14000833c:	b8 00 00 00 00       	mov    eax,0x0
   140008341:	eb 27                	jmp    14000836a <__pow5mult_D2A+0x1b7>
   140008343:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008347:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000834e:	b9 01 00 00 00       	mov    ecx,0x1
   140008353:	e8 6c f8 ff ff       	call   140007bc4 <dtoa_unlock>
   140008358:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000835c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008360:	e9 30 ff ff ff       	jmp    140008295 <__pow5mult_D2A+0xe2>
   140008365:	90                   	nop
   140008366:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000836a:	48 83 c4 40          	add    rsp,0x40
   14000836e:	5d                   	pop    rbp
   14000836f:	c3                   	ret

0000000140008370 <__lshift_D2A>:
   140008370:	55                   	push   rbp
   140008371:	48 89 e5             	mov    rbp,rsp
   140008374:	48 83 ec 60          	sub    rsp,0x60
   140008378:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000837c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000837f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008382:	c1 f8 05             	sar    eax,0x5
   140008385:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   140008388:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000838c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000838f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008392:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008396:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008399:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   14000839c:	01 d0                	add    eax,edx
   14000839e:	83 c0 01             	add    eax,0x1
   1400083a1:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400083a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083a8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400083ab:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400083ae:	eb 07                	jmp    1400083b7 <__lshift_D2A+0x47>
   1400083b0:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   1400083b4:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   1400083b7:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400083ba:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   1400083bd:	7f f1                	jg     1400083b0 <__lshift_D2A+0x40>
   1400083bf:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400083c2:	89 c1                	mov    ecx,eax
   1400083c4:	e8 84 f8 ff ff       	call   140007c4d <__Balloc_D2A>
   1400083c9:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400083cd:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400083d2:	75 0a                	jne    1400083de <__lshift_D2A+0x6e>
   1400083d4:	b8 00 00 00 00       	mov    eax,0x0
   1400083d9:	e9 19 01 00 00       	jmp    1400084f7 <__lshift_D2A+0x187>
   1400083de:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400083e2:	48 83 c0 18          	add    rax,0x18
   1400083e6:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400083ea:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400083f1:	eb 16                	jmp    140008409 <__lshift_D2A+0x99>
   1400083f3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400083f7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400083fb:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400083ff:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008405:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008409:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000840c:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   14000840f:	7c e2                	jl     1400083f3 <__lshift_D2A+0x83>
   140008411:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008415:	48 83 c0 18          	add    rax,0x18
   140008419:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000841d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008421:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008424:	48 98                	cdqe
   140008426:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000842d:	00 
   14000842e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008432:	48 01 d0             	add    rax,rdx
   140008435:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008439:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000843d:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140008441:	74 71                	je     1400084b4 <__lshift_D2A+0x144>
   140008443:	b8 20 00 00 00       	mov    eax,0x20
   140008448:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000844b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000844e:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   140008455:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008459:	8b 10                	mov    edx,DWORD PTR [rax]
   14000845b:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000845e:	89 c1                	mov    ecx,eax
   140008460:	d3 e2                	shl    edx,cl
   140008462:	89 d1                	mov    ecx,edx
   140008464:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008468:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000846c:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008470:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008473:	89 ca                	mov    edx,ecx
   140008475:	89 10                	mov    DWORD PTR [rax],edx
   140008477:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000847b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000847f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008483:	8b 10                	mov    edx,DWORD PTR [rax]
   140008485:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008488:	89 c1                	mov    ecx,eax
   14000848a:	d3 ea                	shr    edx,cl
   14000848c:	89 d0                	mov    eax,edx
   14000848e:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008491:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008495:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008499:	72 ba                	jb     140008455 <__lshift_D2A+0xe5>
   14000849b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000849f:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   1400084a2:	89 10                	mov    DWORD PTR [rax],edx
   1400084a4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084a8:	8b 00                	mov    eax,DWORD PTR [rax]
   1400084aa:	85 c0                	test   eax,eax
   1400084ac:	74 2c                	je     1400084da <__lshift_D2A+0x16a>
   1400084ae:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   1400084b2:	eb 26                	jmp    1400084da <__lshift_D2A+0x16a>
   1400084b4:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400084b8:	48 8d 42 04          	lea    rax,[rdx+0x4]
   1400084bc:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400084c0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084c4:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400084c8:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   1400084cc:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400084ce:	89 10                	mov    DWORD PTR [rax],edx
   1400084d0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084d4:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400084d8:	72 da                	jb     1400084b4 <__lshift_D2A+0x144>
   1400084da:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400084dd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400084e0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400084e4:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400084e7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084eb:	48 89 c1             	mov    rcx,rax
   1400084ee:	e8 9b f8 ff ff       	call   140007d8e <__Bfree_D2A>
   1400084f3:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400084f7:	48 83 c4 60          	add    rsp,0x60
   1400084fb:	5d                   	pop    rbp
   1400084fc:	c3                   	ret

00000001400084fd <__cmp_D2A>:
   1400084fd:	55                   	push   rbp
   1400084fe:	48 89 e5             	mov    rbp,rsp
   140008501:	48 83 ec 30          	sub    rsp,0x30
   140008505:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008509:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000850d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008511:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008514:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140008517:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000851b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000851e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140008521:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008524:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   140008527:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000852b:	74 08                	je     140008535 <__cmp_D2A+0x38>
   14000852d:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008530:	e9 92 00 00 00       	jmp    1400085c7 <__cmp_D2A+0xca>
   140008535:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008539:	48 83 c0 18          	add    rax,0x18
   14000853d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008541:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008544:	48 98                	cdqe
   140008546:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000854d:	00 
   14000854e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008552:	48 01 d0             	add    rax,rdx
   140008555:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008559:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000855d:	48 83 c0 18          	add    rax,0x18
   140008561:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008565:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008568:	48 98                	cdqe
   14000856a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008571:	00 
   140008572:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008576:	48 01 d0             	add    rax,rdx
   140008579:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000857d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008582:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008586:	8b 10                	mov    edx,DWORD PTR [rax]
   140008588:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   14000858d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008591:	8b 00                	mov    eax,DWORD PTR [rax]
   140008593:	39 c2                	cmp    edx,eax
   140008595:	74 1e                	je     1400085b5 <__cmp_D2A+0xb8>
   140008597:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000859b:	8b 10                	mov    edx,DWORD PTR [rax]
   14000859d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400085a1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400085a3:	39 c2                	cmp    edx,eax
   1400085a5:	73 07                	jae    1400085ae <__cmp_D2A+0xb1>
   1400085a7:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400085ac:	eb 19                	jmp    1400085c7 <__cmp_D2A+0xca>
   1400085ae:	b8 01 00 00 00       	mov    eax,0x1
   1400085b3:	eb 12                	jmp    1400085c7 <__cmp_D2A+0xca>
   1400085b5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400085b9:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400085bd:	73 02                	jae    1400085c1 <__cmp_D2A+0xc4>
   1400085bf:	eb bc                	jmp    14000857d <__cmp_D2A+0x80>
   1400085c1:	90                   	nop
   1400085c2:	b8 00 00 00 00       	mov    eax,0x0
   1400085c7:	48 83 c4 30          	add    rsp,0x30
   1400085cb:	5d                   	pop    rbp
   1400085cc:	c3                   	ret

00000001400085cd <__diff_D2A>:
   1400085cd:	55                   	push   rbp
   1400085ce:	48 89 e5             	mov    rbp,rsp
   1400085d1:	48 83 ec 70          	sub    rsp,0x70
   1400085d5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400085d9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400085dd:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400085e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085e5:	48 89 c1             	mov    rcx,rax
   1400085e8:	e8 10 ff ff ff       	call   1400084fd <__cmp_D2A>
   1400085ed:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400085f0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400085f4:	75 3e                	jne    140008634 <__diff_D2A+0x67>
   1400085f6:	b9 00 00 00 00       	mov    ecx,0x0
   1400085fb:	e8 4d f6 ff ff       	call   140007c4d <__Balloc_D2A>
   140008600:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008604:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008609:	75 0a                	jne    140008615 <__diff_D2A+0x48>
   14000860b:	b8 00 00 00 00       	mov    eax,0x0
   140008610:	e9 ab 01 00 00       	jmp    1400087c0 <__diff_D2A+0x1f3>
   140008615:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008619:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008620:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008624:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000862b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000862f:	e9 8c 01 00 00       	jmp    1400087c0 <__diff_D2A+0x1f3>
   140008634:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008638:	79 21                	jns    14000865b <__diff_D2A+0x8e>
   14000863a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000863e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008642:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008646:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000864a:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000864e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140008652:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140008659:	eb 07                	jmp    140008662 <__diff_D2A+0x95>
   14000865b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008662:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008666:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008669:	89 c1                	mov    ecx,eax
   14000866b:	e8 dd f5 ff ff       	call   140007c4d <__Balloc_D2A>
   140008670:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008674:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008679:	75 0a                	jne    140008685 <__diff_D2A+0xb8>
   14000867b:	b8 00 00 00 00       	mov    eax,0x0
   140008680:	e9 3b 01 00 00       	jmp    1400087c0 <__diff_D2A+0x1f3>
   140008685:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008689:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000868c:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000868f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008693:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008696:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008699:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000869d:	48 83 c0 18          	add    rax,0x18
   1400086a1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400086a5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400086a8:	48 98                	cdqe
   1400086aa:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400086b1:	00 
   1400086b2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400086b6:	48 01 d0             	add    rax,rdx
   1400086b9:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400086bd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086c1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400086c4:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400086c7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086cb:	48 83 c0 18          	add    rax,0x18
   1400086cf:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400086d3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   1400086d6:	48 98                	cdqe
   1400086d8:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400086df:	00 
   1400086e0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400086e4:	48 01 d0             	add    rax,rdx
   1400086e7:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400086eb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086ef:	48 83 c0 18          	add    rax,0x18
   1400086f3:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400086f7:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   1400086fe:	00 
   1400086ff:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008703:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008707:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000870b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000870d:	89 c1                	mov    ecx,eax
   14000870f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008713:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008717:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   14000871b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000871d:	89 c2                	mov    edx,eax
   14000871f:	48 89 c8             	mov    rax,rcx
   140008722:	48 29 d0             	sub    rax,rdx
   140008725:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140008729:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000872d:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008731:	48 c1 e8 20          	shr    rax,0x20
   140008735:	83 e0 01             	and    eax,0x1
   140008738:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000873c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008740:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008744:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008748:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000874c:	89 10                	mov    DWORD PTR [rax],edx
   14000874e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008752:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   140008756:	72 a7                	jb     1400086ff <__diff_D2A+0x132>
   140008758:	eb 39                	jmp    140008793 <__diff_D2A+0x1c6>
   14000875a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000875e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008762:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008766:	8b 00                	mov    eax,DWORD PTR [rax]
   140008768:	89 c0                	mov    eax,eax
   14000876a:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   14000876e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008772:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008776:	48 c1 e8 20          	shr    rax,0x20
   14000877a:	83 e0 01             	and    eax,0x1
   14000877d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008781:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008785:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008789:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000878d:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140008791:	89 10                	mov    DWORD PTR [rax],edx
   140008793:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008797:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   14000879b:	72 bd                	jb     14000875a <__diff_D2A+0x18d>
   14000879d:	eb 04                	jmp    1400087a3 <__diff_D2A+0x1d6>
   14000879f:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400087a3:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   1400087a8:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087ac:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087ae:	85 c0                	test   eax,eax
   1400087b0:	74 ed                	je     14000879f <__diff_D2A+0x1d2>
   1400087b2:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087b6:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400087b9:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400087bc:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087c0:	48 83 c4 70          	add    rsp,0x70
   1400087c4:	5d                   	pop    rbp
   1400087c5:	c3                   	ret

00000001400087c6 <__b2d_D2A>:
   1400087c6:	55                   	push   rbp
   1400087c7:	48 89 e5             	mov    rbp,rsp
   1400087ca:	48 83 ec 50          	sub    rsp,0x50
   1400087ce:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400087d2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400087d6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400087da:	48 83 c0 18          	add    rax,0x18
   1400087de:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400087e2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400087e6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400087e9:	48 98                	cdqe
   1400087eb:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400087f2:	00 
   1400087f3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087f7:	48 01 d0             	add    rax,rdx
   1400087fa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400087fe:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008803:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008807:	8b 00                	mov    eax,DWORD PTR [rax]
   140008809:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   14000880c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000880f:	89 c1                	mov    ecx,eax
   140008811:	e8 27 f4 ff ff       	call   140007c3d <__hi0bits_D2A>
   140008816:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008819:	b8 20 00 00 00       	mov    eax,0x20
   14000881e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008821:	89 c2                	mov    edx,eax
   140008823:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008827:	89 10                	mov    DWORD PTR [rax],edx
   140008829:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   14000882d:	7f 66                	jg     140008895 <__b2d_D2A+0xcf>
   14000882f:	b8 0b 00 00 00       	mov    eax,0xb
   140008834:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008837:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000883a:	89 c1                	mov    ecx,eax
   14000883c:	d3 ea                	shr    edx,cl
   14000883e:	89 d0                	mov    eax,edx
   140008840:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008845:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008848:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000884c:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008850:	73 10                	jae    140008862 <__b2d_D2A+0x9c>
   140008852:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008857:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000885b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000885d:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008860:	eb 07                	jmp    140008869 <__b2d_D2A+0xa3>
   140008862:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140008869:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000886c:	83 c0 15             	add    eax,0x15
   14000886f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008872:	89 c1                	mov    ecx,eax
   140008874:	d3 e2                	shl    edx,cl
   140008876:	41 89 d0             	mov    r8d,edx
   140008879:	b8 0b 00 00 00       	mov    eax,0xb
   14000887e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008881:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140008884:	89 c1                	mov    ecx,eax
   140008886:	d3 ea                	shr    edx,cl
   140008888:	89 d0                	mov    eax,edx
   14000888a:	44 09 c0             	or     eax,r8d
   14000888d:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008890:	e9 ac 00 00 00       	jmp    140008941 <__b2d_D2A+0x17b>
   140008895:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008899:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000889d:	73 10                	jae    1400088af <__b2d_D2A+0xe9>
   14000889f:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088a4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088a8:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088aa:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400088ad:	eb 07                	jmp    1400088b6 <__b2d_D2A+0xf0>
   1400088af:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   1400088b6:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   1400088ba:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   1400088be:	74 70                	je     140008930 <__b2d_D2A+0x16a>
   1400088c0:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400088c3:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400088c6:	89 c1                	mov    ecx,eax
   1400088c8:	d3 e2                	shl    edx,cl
   1400088ca:	41 89 d0             	mov    r8d,edx
   1400088cd:	b8 20 00 00 00       	mov    eax,0x20
   1400088d2:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088d5:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400088d8:	89 c1                	mov    ecx,eax
   1400088da:	d3 ea                	shr    edx,cl
   1400088dc:	89 d0                	mov    eax,edx
   1400088de:	44 09 c0             	or     eax,r8d
   1400088e1:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400088e6:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400088e9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088ed:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400088f1:	73 10                	jae    140008903 <__b2d_D2A+0x13d>
   1400088f3:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088fc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088fe:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140008901:	eb 07                	jmp    14000890a <__b2d_D2A+0x144>
   140008903:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   14000890a:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000890d:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008910:	89 c1                	mov    ecx,eax
   140008912:	d3 e2                	shl    edx,cl
   140008914:	41 89 d0             	mov    r8d,edx
   140008917:	b8 20 00 00 00       	mov    eax,0x20
   14000891c:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   14000891f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008922:	89 c1                	mov    ecx,eax
   140008924:	d3 ea                	shr    edx,cl
   140008926:	89 d0                	mov    eax,edx
   140008928:	44 09 c0             	or     eax,r8d
   14000892b:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000892e:	eb 11                	jmp    140008941 <__b2d_D2A+0x17b>
   140008930:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008933:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008938:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000893b:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   14000893e:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008941:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   140008946:	48 83 c4 50          	add    rsp,0x50
   14000894a:	5d                   	pop    rbp
   14000894b:	c3                   	ret

000000014000894c <__d2b_D2A>:
   14000894c:	55                   	push   rbp
   14000894d:	53                   	push   rbx
   14000894e:	48 83 ec 58          	sub    rsp,0x58
   140008952:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140008957:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   14000895c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140008960:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140008964:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140008969:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   14000896e:	b9 01 00 00 00       	mov    ecx,0x1
   140008973:	e8 d5 f2 ff ff       	call   140007c4d <__Balloc_D2A>
   140008978:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000897c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008981:	75 0a                	jne    14000898d <__d2b_D2A+0x41>
   140008983:	b8 00 00 00 00       	mov    eax,0x0
   140008988:	e9 68 01 00 00       	jmp    140008af5 <__d2b_D2A+0x1a9>
   14000898d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008991:	48 83 c0 18          	add    rax,0x18
   140008995:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008999:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000899c:	25 ff ff 0f 00       	and    eax,0xfffff
   1400089a1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089a4:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089a7:	25 ff ff ff 7f       	and    eax,0x7fffffff
   1400089ac:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400089af:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089b2:	c1 e8 14             	shr    eax,0x14
   1400089b5:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400089b8:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400089bc:	74 0b                	je     1400089c9 <__d2b_D2A+0x7d>
   1400089be:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   1400089c1:	0d 00 00 10 00       	or     eax,0x100000
   1400089c6:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089c9:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   1400089cc:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089cf:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400089d2:	85 c0                	test   eax,eax
   1400089d4:	74 7b                	je     140008a51 <__d2b_D2A+0x105>
   1400089d6:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   1400089da:	48 89 c1             	mov    rcx,rax
   1400089dd:	e8 26 f2 ff ff       	call   140007c08 <__lo0bits_D2A>
   1400089e2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400089e5:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400089e9:	74 2b                	je     140008a16 <__d2b_D2A+0xca>
   1400089eb:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   1400089ee:	b8 20 00 00 00       	mov    eax,0x20
   1400089f3:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   1400089f6:	89 c1                	mov    ecx,eax
   1400089f8:	d3 e2                	shl    edx,cl
   1400089fa:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400089fd:	09 c2                	or     edx,eax
   1400089ff:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a03:	89 10                	mov    DWORD PTR [rax],edx
   140008a05:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a08:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008a0b:	89 c1                	mov    ecx,eax
   140008a0d:	d3 ea                	shr    edx,cl
   140008a0f:	89 d0                	mov    eax,edx
   140008a11:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a14:	eb 09                	jmp    140008a1f <__d2b_D2A+0xd3>
   140008a16:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008a19:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a1d:	89 10                	mov    DWORD PTR [rax],edx
   140008a1f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a23:	48 83 c0 04          	add    rax,0x4
   140008a27:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a2a:	89 10                	mov    DWORD PTR [rax],edx
   140008a2c:	8b 00                	mov    eax,DWORD PTR [rax]
   140008a2e:	85 c0                	test   eax,eax
   140008a30:	74 07                	je     140008a39 <__d2b_D2A+0xed>
   140008a32:	ba 02 00 00 00       	mov    edx,0x2
   140008a37:	eb 05                	jmp    140008a3e <__d2b_D2A+0xf2>
   140008a39:	ba 01 00 00 00       	mov    edx,0x1
   140008a3e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a42:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008a45:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a49:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008a4c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008a4f:	eb 31                	jmp    140008a82 <__d2b_D2A+0x136>
   140008a51:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008a55:	48 89 c1             	mov    rcx,rax
   140008a58:	e8 ab f1 ff ff       	call   140007c08 <__lo0bits_D2A>
   140008a5d:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008a60:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a63:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a67:	89 10                	mov    DWORD PTR [rax],edx
   140008a69:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a6d:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008a74:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a78:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008a7b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008a7e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008a82:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008a86:	74 26                	je     140008aae <__d2b_D2A+0x162>
   140008a88:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008a8b:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008a91:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008a94:	01 c2                	add    edx,eax
   140008a96:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008a9a:	89 10                	mov    DWORD PTR [rax],edx
   140008a9c:	b8 35 00 00 00       	mov    eax,0x35
   140008aa1:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008aa4:	89 c2                	mov    edx,eax
   140008aa6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008aaa:	89 10                	mov    DWORD PTR [rax],edx
   140008aac:	eb 43                	jmp    140008af1 <__d2b_D2A+0x1a5>
   140008aae:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008ab1:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008ab7:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008aba:	01 c2                	add    edx,eax
   140008abc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008ac0:	89 10                	mov    DWORD PTR [rax],edx
   140008ac2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008ac5:	c1 e0 05             	shl    eax,0x5
   140008ac8:	89 c3                	mov    ebx,eax
   140008aca:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008acd:	48 98                	cdqe
   140008acf:	48 c1 e0 02          	shl    rax,0x2
   140008ad3:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008ad7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008adb:	48 01 d0             	add    rax,rdx
   140008ade:	8b 00                	mov    eax,DWORD PTR [rax]
   140008ae0:	89 c1                	mov    ecx,eax
   140008ae2:	e8 56 f1 ff ff       	call   140007c3d <__hi0bits_D2A>
   140008ae7:	29 c3                	sub    ebx,eax
   140008ae9:	89 da                	mov    edx,ebx
   140008aeb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008aef:	89 10                	mov    DWORD PTR [rax],edx
   140008af1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008af5:	48 83 c4 58          	add    rsp,0x58
   140008af9:	5b                   	pop    rbx
   140008afa:	5d                   	pop    rbp
   140008afb:	c3                   	ret

0000000140008afc <__strcp_D2A>:
   140008afc:	55                   	push   rbp
   140008afd:	48 89 e5             	mov    rbp,rsp
   140008b00:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008b04:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008b08:	eb 05                	jmp    140008b0f <__strcp_D2A+0x13>
   140008b0a:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008b0f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008b13:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008b17:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008b1b:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008b1e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b22:	88 10                	mov    BYTE PTR [rax],dl
   140008b24:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b28:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008b2b:	84 c0                	test   al,al
   140008b2d:	75 db                	jne    140008b0a <__strcp_D2A+0xe>
   140008b2f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b33:	5d                   	pop    rbp
   140008b34:	c3                   	ret
   140008b35:	90                   	nop
   140008b36:	90                   	nop
   140008b37:	90                   	nop
   140008b38:	90                   	nop
   140008b39:	90                   	nop
   140008b3a:	90                   	nop
   140008b3b:	90                   	nop
   140008b3c:	90                   	nop
   140008b3d:	90                   	nop
   140008b3e:	90                   	nop
   140008b3f:	90                   	nop

0000000140008b40 <__fpclassify>:
   140008b40:	55                   	push   rbp
   140008b41:	48 89 e5             	mov    rbp,rsp
   140008b44:	48 83 ec 10          	sub    rsp,0x10
   140008b48:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008b4d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008b52:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008b57:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008b5a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b5d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008b60:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008b63:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008b69:	09 d0                	or     eax,edx
   140008b6b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008b6e:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008b75:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b78:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008b7b:	85 c0                	test   eax,eax
   140008b7d:	75 07                	jne    140008b86 <__fpclassify+0x46>
   140008b7f:	b8 00 40 00 00       	mov    eax,0x4000
   140008b84:	eb 2f                	jmp    140008bb5 <__fpclassify+0x75>
   140008b86:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008b8a:	75 07                	jne    140008b93 <__fpclassify+0x53>
   140008b8c:	b8 00 44 00 00       	mov    eax,0x4400
   140008b91:	eb 22                	jmp    140008bb5 <__fpclassify+0x75>
   140008b93:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008b9a:	75 14                	jne    140008bb0 <__fpclassify+0x70>
   140008b9c:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008ba0:	74 07                	je     140008ba9 <__fpclassify+0x69>
   140008ba2:	b8 00 01 00 00       	mov    eax,0x100
   140008ba7:	eb 0c                	jmp    140008bb5 <__fpclassify+0x75>
   140008ba9:	b8 00 05 00 00       	mov    eax,0x500
   140008bae:	eb 05                	jmp    140008bb5 <__fpclassify+0x75>
   140008bb0:	b8 00 04 00 00       	mov    eax,0x400
   140008bb5:	48 83 c4 10          	add    rsp,0x10
   140008bb9:	5d                   	pop    rbp
   140008bba:	c3                   	ret
   140008bbb:	90                   	nop
   140008bbc:	90                   	nop
   140008bbd:	90                   	nop
   140008bbe:	90                   	nop
   140008bbf:	90                   	nop

0000000140008bc0 <__fpclassifyl>:
   140008bc0:	55                   	push   rbp
   140008bc1:	53                   	push   rbx
   140008bc2:	48 83 ec 38          	sub    rsp,0x38
   140008bc6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008bcb:	48 89 cb             	mov    rbx,rcx
   140008bce:	db 2b                	fld    TBYTE PTR [rbx]
   140008bd0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008bd3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008bd6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008bd9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008bdd:	98                   	cwde
   140008bde:	25 ff 7f 00 00       	and    eax,0x7fff
   140008be3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008be6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008bea:	75 25                	jne    140008c11 <__fpclassifyl+0x51>
   140008bec:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008bef:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008bf2:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008bf5:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008bf8:	85 c0                	test   eax,eax
   140008bfa:	75 07                	jne    140008c03 <__fpclassifyl+0x43>
   140008bfc:	b8 00 40 00 00       	mov    eax,0x4000
   140008c01:	eb 3d                	jmp    140008c40 <__fpclassifyl+0x80>
   140008c03:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c06:	85 c0                	test   eax,eax
   140008c08:	78 31                	js     140008c3b <__fpclassifyl+0x7b>
   140008c0a:	b8 00 44 00 00       	mov    eax,0x4400
   140008c0f:	eb 2f                	jmp    140008c40 <__fpclassifyl+0x80>
   140008c11:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008c18:	75 21                	jne    140008c3b <__fpclassifyl+0x7b>
   140008c1a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c1d:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008c22:	89 c2                	mov    edx,eax
   140008c24:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c27:	09 d0                	or     eax,edx
   140008c29:	85 c0                	test   eax,eax
   140008c2b:	75 07                	jne    140008c34 <__fpclassifyl+0x74>
   140008c2d:	b8 00 05 00 00       	mov    eax,0x500
   140008c32:	eb 0c                	jmp    140008c40 <__fpclassifyl+0x80>
   140008c34:	b8 00 01 00 00       	mov    eax,0x100
   140008c39:	eb 05                	jmp    140008c40 <__fpclassifyl+0x80>
   140008c3b:	b8 00 04 00 00       	mov    eax,0x400
   140008c40:	48 83 c4 38          	add    rsp,0x38
   140008c44:	5b                   	pop    rbx
   140008c45:	5d                   	pop    rbp
   140008c46:	c3                   	ret
   140008c47:	90                   	nop
   140008c48:	90                   	nop
   140008c49:	90                   	nop
   140008c4a:	90                   	nop
   140008c4b:	90                   	nop
   140008c4c:	90                   	nop
   140008c4d:	90                   	nop
   140008c4e:	90                   	nop
   140008c4f:	90                   	nop

0000000140008c50 <__isnan>:
   140008c50:	55                   	push   rbp
   140008c51:	48 89 e5             	mov    rbp,rsp
   140008c54:	48 83 ec 10          	sub    rsp,0x10
   140008c58:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008c5d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008c62:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008c67:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008c6a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c6d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008c70:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008c75:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c78:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c7b:	f7 d8                	neg    eax
   140008c7d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008c80:	c1 e8 1f             	shr    eax,0x1f
   140008c83:	89 c2                	mov    edx,eax
   140008c85:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c88:	09 d0                	or     eax,edx
   140008c8a:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c8d:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008c92:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008c95:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c98:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c9b:	c1 f8 1f             	sar    eax,0x1f
   140008c9e:	48 83 c4 10          	add    rsp,0x10
   140008ca2:	5d                   	pop    rbp
   140008ca3:	c3                   	ret
   140008ca4:	90                   	nop
   140008ca5:	90                   	nop
   140008ca6:	90                   	nop
   140008ca7:	90                   	nop
   140008ca8:	90                   	nop
   140008ca9:	90                   	nop
   140008caa:	90                   	nop
   140008cab:	90                   	nop
   140008cac:	90                   	nop
   140008cad:	90                   	nop
   140008cae:	90                   	nop
   140008caf:	90                   	nop

0000000140008cb0 <__isnanl>:
   140008cb0:	55                   	push   rbp
   140008cb1:	53                   	push   rbx
   140008cb2:	48 83 ec 38          	sub    rsp,0x38
   140008cb6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008cbb:	48 89 cb             	mov    rbx,rcx
   140008cbe:	db 2b                	fld    TBYTE PTR [rbx]
   140008cc0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008cc3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008cc6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008cc9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008ccd:	98                   	cwde
   140008cce:	01 c0                	add    eax,eax
   140008cd0:	25 ff ff 00 00       	and    eax,0xffff
   140008cd5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cd8:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008cdb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008cde:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008ce4:	09 d0                	or     eax,edx
   140008ce6:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008ce9:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008cec:	f7 d8                	neg    eax
   140008cee:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008cf1:	c1 e8 1f             	shr    eax,0x1f
   140008cf4:	89 c2                	mov    edx,eax
   140008cf6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008cf9:	09 d0                	or     eax,edx
   140008cfb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cfe:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008d03:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008d06:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d09:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d0c:	c1 f8 10             	sar    eax,0x10
   140008d0f:	48 83 c4 38          	add    rsp,0x38
   140008d13:	5b                   	pop    rbx
   140008d14:	5d                   	pop    rbp
   140008d15:	c3                   	ret
   140008d16:	90                   	nop
   140008d17:	90                   	nop
   140008d18:	90                   	nop
   140008d19:	90                   	nop
   140008d1a:	90                   	nop
   140008d1b:	90                   	nop
   140008d1c:	90                   	nop
   140008d1d:	90                   	nop
   140008d1e:	90                   	nop
   140008d1f:	90                   	nop

0000000140008d20 <wcsnlen>:
   140008d20:	55                   	push   rbp
   140008d21:	48 89 e5             	mov    rbp,rsp
   140008d24:	48 83 ec 10          	sub    rsp,0x10
   140008d28:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008d2c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008d30:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008d37:	00 
   140008d38:	eb 0a                	jmp    140008d44 <wcsnlen+0x24>
   140008d3a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008d3f:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008d44:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d48:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008d4c:	73 0c                	jae    140008d5a <wcsnlen+0x3a>
   140008d4e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008d52:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008d55:	66 85 c0             	test   ax,ax
   140008d58:	75 e0                	jne    140008d3a <wcsnlen+0x1a>
   140008d5a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d5e:	48 83 c4 10          	add    rsp,0x10
   140008d62:	5d                   	pop    rbp
   140008d63:	c3                   	ret
   140008d64:	90                   	nop
   140008d65:	90                   	nop
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

0000000140008d70 <strnlen>:
   140008d70:	55                   	push   rbp
   140008d71:	48 89 e5             	mov    rbp,rsp
   140008d74:	48 83 ec 10          	sub    rsp,0x10
   140008d78:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008d7c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008d80:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008d84:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008d88:	eb 05                	jmp    140008d8f <strnlen+0x1f>
   140008d8a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008d8f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d93:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008d97:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008d9b:	73 0b                	jae    140008da8 <strnlen+0x38>
   140008d9d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008da1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008da4:	84 c0                	test   al,al
   140008da6:	75 e2                	jne    140008d8a <strnlen+0x1a>
   140008da8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dac:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008db0:	48 83 c4 10          	add    rsp,0x10
   140008db4:	5d                   	pop    rbp
   140008db5:	c3                   	ret
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

0000000140008dc0 <_initterm_e>:
   140008dc0:	55                   	push   rbp
   140008dc1:	48 89 e5             	mov    rbp,rsp
   140008dc4:	48 83 ec 30          	sub    rsp,0x30
   140008dc8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008dcc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008dd0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008dd4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008dd8:	eb 29                	jmp    140008e03 <_initterm_e+0x43>
   140008dda:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dde:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008de1:	48 85 c0             	test   rax,rax
   140008de4:	74 17                	je     140008dfd <_initterm_e+0x3d>
   140008de6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dea:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ded:	ff d0                	call   rax
   140008def:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008df2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008df6:	74 06                	je     140008dfe <_initterm_e+0x3e>
   140008df8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008dfb:	eb 15                	jmp    140008e12 <_initterm_e+0x52>
   140008dfd:	90                   	nop
   140008dfe:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008e03:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e07:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e0b:	72 cd                	jb     140008dda <_initterm_e+0x1a>
   140008e0d:	b8 00 00 00 00       	mov    eax,0x0
   140008e12:	48 83 c4 30          	add    rsp,0x30
   140008e16:	5d                   	pop    rbp
   140008e17:	c3                   	ret
   140008e18:	90                   	nop
   140008e19:	90                   	nop
   140008e1a:	90                   	nop
   140008e1b:	90                   	nop
   140008e1c:	90                   	nop
   140008e1d:	90                   	nop
   140008e1e:	90                   	nop
   140008e1f:	90                   	nop

0000000140008e20 <__p__fmode>:
   140008e20:	55                   	push   rbp
   140008e21:	48 89 e5             	mov    rbp,rsp
   140008e24:	48 8b 05 d5 27 00 00 	mov    rax,QWORD PTR [rip+0x27d5]        # 14000b600 <.refptr.__imp__fmode>
   140008e2b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e2e:	5d                   	pop    rbp
   140008e2f:	c3                   	ret

0000000140008e30 <__p__commode>:
   140008e30:	55                   	push   rbp
   140008e31:	48 89 e5             	mov    rbp,rsp
   140008e34:	48 8b 05 b5 27 00 00 	mov    rax,QWORD PTR [rip+0x27b5]        # 14000b5f0 <.refptr.__imp__commode>
   140008e3b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e3e:	5d                   	pop    rbp
   140008e3f:	c3                   	ret

0000000140008e40 <__p___initenv>:
   140008e40:	55                   	push   rbp
   140008e41:	48 89 e5             	mov    rbp,rsp
   140008e44:	48 8b 05 95 27 00 00 	mov    rax,QWORD PTR [rip+0x2795]        # 14000b5e0 <.refptr.__imp___initenv>
   140008e4b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e4e:	5d                   	pop    rbp
   140008e4f:	c3                   	ret

0000000140008e50 <_lock_file>:
   140008e50:	55                   	push   rbp
   140008e51:	48 89 e5             	mov    rbp,rsp
   140008e54:	48 83 ec 20          	sub    rsp,0x20
   140008e58:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e5c:	b9 00 00 00 00       	mov    ecx,0x0
   140008e61:	e8 6a 01 00 00       	call   140008fd0 <__acrt_iob_func>
   140008e66:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008e6a:	72 52                	jb     140008ebe <_lock_file+0x6e>
   140008e6c:	b9 13 00 00 00       	mov    ecx,0x13
   140008e71:	e8 5a 01 00 00       	call   140008fd0 <__acrt_iob_func>
   140008e76:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008e7a:	72 42                	jb     140008ebe <_lock_file+0x6e>
   140008e7c:	b9 00 00 00 00       	mov    ecx,0x0
   140008e81:	e8 4a 01 00 00       	call   140008fd0 <__acrt_iob_func>
   140008e86:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008e8a:	48 29 c2             	sub    rdx,rax
   140008e8d:	48 c1 fa 04          	sar    rdx,0x4
   140008e91:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008e98:	aa aa aa 
   140008e9b:	48 0f af c2          	imul   rax,rdx
   140008e9f:	83 c0 10             	add    eax,0x10
   140008ea2:	89 c1                	mov    ecx,eax
   140008ea4:	e8 1f 07 00 00       	call   1400095c8 <_lock>
   140008ea9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ead:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008eb0:	80 cc 80             	or     ah,0x80
   140008eb3:	89 c2                	mov    edx,eax
   140008eb5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008eb9:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008ebc:	eb 15                	jmp    140008ed3 <_lock_file+0x83>
   140008ebe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ec2:	48 83 c0 30          	add    rax,0x30
   140008ec6:	48 89 c1             	mov    rcx,rax
   140008ec9:	48 8b 05 20 73 00 00 	mov    rax,QWORD PTR [rip+0x7320]        # 1400101f0 <__imp_EnterCriticalSection>
   140008ed0:	ff d0                	call   rax
   140008ed2:	90                   	nop
   140008ed3:	90                   	nop
   140008ed4:	48 83 c4 20          	add    rsp,0x20
   140008ed8:	5d                   	pop    rbp
   140008ed9:	c3                   	ret

0000000140008eda <_unlock_file>:
   140008eda:	55                   	push   rbp
   140008edb:	48 89 e5             	mov    rbp,rsp
   140008ede:	48 83 ec 20          	sub    rsp,0x20
   140008ee2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008ee6:	b9 00 00 00 00       	mov    ecx,0x0
   140008eeb:	e8 e0 00 00 00       	call   140008fd0 <__acrt_iob_func>
   140008ef0:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008ef4:	72 52                	jb     140008f48 <_unlock_file+0x6e>
   140008ef6:	b9 13 00 00 00       	mov    ecx,0x13
   140008efb:	e8 d0 00 00 00       	call   140008fd0 <__acrt_iob_func>
   140008f00:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f04:	72 42                	jb     140008f48 <_unlock_file+0x6e>
   140008f06:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f0a:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008f0d:	80 e4 7f             	and    ah,0x7f
   140008f10:	89 c2                	mov    edx,eax
   140008f12:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f16:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008f19:	b9 00 00 00 00       	mov    ecx,0x0
   140008f1e:	e8 ad 00 00 00       	call   140008fd0 <__acrt_iob_func>
   140008f23:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f27:	48 29 c2             	sub    rdx,rax
   140008f2a:	48 c1 fa 04          	sar    rdx,0x4
   140008f2e:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008f35:	aa aa aa 
   140008f38:	48 0f af c2          	imul   rax,rdx
   140008f3c:	83 c0 10             	add    eax,0x10
   140008f3f:	89 c1                	mov    ecx,eax
   140008f41:	e8 8a 06 00 00       	call   1400095d0 <_unlock>
   140008f46:	eb 15                	jmp    140008f5d <_unlock_file+0x83>
   140008f48:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f4c:	48 83 c0 30          	add    rax,0x30
   140008f50:	48 89 c1             	mov    rcx,rax
   140008f53:	48 8b 05 ce 72 00 00 	mov    rax,QWORD PTR [rip+0x72ce]        # 140010228 <__imp_LeaveCriticalSection>
   140008f5a:	ff d0                	call   rax
   140008f5c:	90                   	nop
   140008f5d:	90                   	nop
   140008f5e:	48 83 c4 20          	add    rsp,0x20
   140008f62:	5d                   	pop    rbp
   140008f63:	c3                   	ret
   140008f64:	90                   	nop
   140008f65:	90                   	nop
   140008f66:	90                   	nop
   140008f67:	90                   	nop
   140008f68:	90                   	nop
   140008f69:	90                   	nop
   140008f6a:	90                   	nop
   140008f6b:	90                   	nop
   140008f6c:	90                   	nop
   140008f6d:	90                   	nop
   140008f6e:	90                   	nop
   140008f6f:	90                   	nop

0000000140008f70 <_set_invalid_parameter_handler>:
   140008f70:	55                   	push   rbp
   140008f71:	48 89 e5             	mov    rbp,rsp
   140008f74:	48 83 ec 10          	sub    rsp,0x10
   140008f78:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f7c:	48 8d 05 fd 6b 00 00 	lea    rax,[rip+0x6bfd]        # 14000fb80 <handler>
   140008f83:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008f87:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f8b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008f8f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140008f93:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008f97:	48 87 10             	xchg   QWORD PTR [rax],rdx
   140008f9a:	48 89 d0             	mov    rax,rdx
   140008f9d:	48 83 c4 10          	add    rsp,0x10
   140008fa1:	5d                   	pop    rbp
   140008fa2:	c3                   	ret

0000000140008fa3 <_get_invalid_parameter_handler>:
   140008fa3:	55                   	push   rbp
   140008fa4:	48 89 e5             	mov    rbp,rsp
   140008fa7:	48 8b 05 d2 6b 00 00 	mov    rax,QWORD PTR [rip+0x6bd2]        # 14000fb80 <handler>
   140008fae:	5d                   	pop    rbp
   140008faf:	c3                   	ret

0000000140008fb0 <_configthreadlocale>:
   140008fb0:	55                   	push   rbp
   140008fb1:	48 89 e5             	mov    rbp,rsp
   140008fb4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008fb7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   140008fbb:	75 07                	jne    140008fc4 <_configthreadlocale+0x14>
   140008fbd:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140008fc2:	eb 05                	jmp    140008fc9 <_configthreadlocale+0x19>
   140008fc4:	b8 02 00 00 00       	mov    eax,0x2
   140008fc9:	5d                   	pop    rbp
   140008fca:	c3                   	ret
   140008fcb:	90                   	nop
   140008fcc:	90                   	nop
   140008fcd:	90                   	nop
   140008fce:	90                   	nop
   140008fcf:	90                   	nop

0000000140008fd0 <__acrt_iob_func>:
   140008fd0:	55                   	push   rbp
   140008fd1:	48 89 e5             	mov    rbp,rsp
   140008fd4:	48 83 ec 20          	sub    rsp,0x20
   140008fd8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008fdb:	e8 b0 05 00 00       	call   140009590 <__iob_func>
   140008fe0:	48 89 c1             	mov    rcx,rax
   140008fe3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008fe6:	48 89 d0             	mov    rax,rdx
   140008fe9:	48 01 c0             	add    rax,rax
   140008fec:	48 01 d0             	add    rax,rdx
   140008fef:	48 c1 e0 04          	shl    rax,0x4
   140008ff3:	48 01 c8             	add    rax,rcx
   140008ff6:	48 83 c4 20          	add    rsp,0x20
   140008ffa:	5d                   	pop    rbp
   140008ffb:	c3                   	ret
   140008ffc:	90                   	nop
   140008ffd:	90                   	nop
   140008ffe:	90                   	nop
   140008fff:	90                   	nop

0000000140009000 <wcrtomb>:
   140009000:	55                   	push   rbp
   140009001:	48 89 e5             	mov    rbp,rsp
   140009004:	48 83 ec 40          	sub    rsp,0x40
   140009008:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000900c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009010:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009014:	e8 5f 05 00 00       	call   140009578 <___lc_codepage_func>
   140009019:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000901c:	e8 5f 05 00 00       	call   140009580 <___mb_cur_max_func>
   140009021:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140009024:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   140009028:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   14000902c:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   140009030:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009034:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140009037:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   14000903b:	48 89 c1             	mov    rcx,rax
   14000903e:	e8 7d 00 00 00       	call   1400090c0 <__mingw_wcrtomb_cp>
   140009043:	48 83 c4 40          	add    rsp,0x40
   140009047:	5d                   	pop    rbp
   140009048:	c3                   	ret
   140009049:	90                   	nop
   14000904a:	90                   	nop
   14000904b:	90                   	nop
   14000904c:	90                   	nop
   14000904d:	90                   	nop
   14000904e:	90                   	nop
   14000904f:	90                   	nop

0000000140009050 <mbrtowc>:
   140009050:	55                   	push   rbp
   140009051:	48 89 e5             	mov    rbp,rsp
   140009054:	48 83 ec 40          	sub    rsp,0x40
   140009058:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000905c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009060:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009064:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009068:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   14000906d:	75 0b                	jne    14000907a <mbrtowc+0x2a>
   14000906f:	48 8d 05 1a 6b 00 00 	lea    rax,[rip+0x6b1a]        # 14000fb90 <state_mbrtowc.0>
   140009076:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000907a:	e8 f9 04 00 00       	call   140009578 <___lc_codepage_func>
   14000907f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009082:	e8 f9 04 00 00       	call   140009580 <___mb_cur_max_func>
   140009087:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000908a:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   14000908e:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140009092:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140009096:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000909a:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   14000909d:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   1400090a1:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   1400090a4:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   1400090a8:	48 89 c1             	mov    rcx,rax
   1400090ab:	e8 70 01 00 00       	call   140009220 <__mingw_mbrtowc_cp>
   1400090b0:	48 83 c4 40          	add    rsp,0x40
   1400090b4:	5d                   	pop    rbp
   1400090b5:	c3                   	ret
   1400090b6:	90                   	nop
   1400090b7:	90                   	nop
   1400090b8:	90                   	nop
   1400090b9:	90                   	nop
   1400090ba:	90                   	nop
   1400090bb:	90                   	nop
   1400090bc:	90                   	nop
   1400090bd:	90                   	nop
   1400090be:	90                   	nop
   1400090bf:	90                   	nop

00000001400090c0 <__mingw_wcrtomb_cp>:
   1400090c0:	55                   	push   rbp
   1400090c1:	48 89 e5             	mov    rbp,rsp
   1400090c4:	48 83 ec 50          	sub    rsp,0x50
   1400090c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090cc:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400090d0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090d4:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   1400090d8:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400090dd:	75 1b                	jne    1400090fa <__mingw_wcrtomb_cp+0x3a>
   1400090df:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400090e4:	74 0a                	je     1400090f0 <__mingw_wcrtomb_cp+0x30>
   1400090e6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400090ea:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400090f0:	b8 01 00 00 00       	mov    eax,0x1
   1400090f5:	e9 17 01 00 00       	jmp    140009211 <__mingw_wcrtomb_cp+0x151>
   1400090fa:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400090ff:	74 21                	je     140009122 <__mingw_wcrtomb_cp+0x62>
   140009101:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140009105:	8b 00                	mov    eax,DWORD PTR [rax]
   140009107:	85 c0                	test   eax,eax
   140009109:	74 17                	je     140009122 <__mingw_wcrtomb_cp+0x62>
   14000910b:	e8 a8 04 00 00       	call   1400095b8 <_errno>
   140009110:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009116:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000911d:	e9 ef 00 00 00       	jmp    140009211 <__mingw_wcrtomb_cp+0x151>
   140009122:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009126:	66 85 c0             	test   ax,ax
   140009129:	75 18                	jne    140009143 <__mingw_wcrtomb_cp+0x83>
   14000912b:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009130:	74 07                	je     140009139 <__mingw_wcrtomb_cp+0x79>
   140009132:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009136:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140009139:	b8 01 00 00 00       	mov    eax,0x1
   14000913e:	e9 ce 00 00 00       	jmp    140009211 <__mingw_wcrtomb_cp+0x151>
   140009143:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   140009147:	75 2b                	jne    140009174 <__mingw_wcrtomb_cp+0xb4>
   140009149:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   14000914d:	66 3d ff 00          	cmp    ax,0xff
   140009151:	0f 87 a4 00 00 00    	ja     1400091fb <__mingw_wcrtomb_cp+0x13b>
   140009157:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000915c:	74 0c                	je     14000916a <__mingw_wcrtomb_cp+0xaa>
   14000915e:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009162:	89 c2                	mov    edx,eax
   140009164:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009168:	88 10                	mov    BYTE PTR [rax],dl
   14000916a:	b8 01 00 00 00       	mov    eax,0x1
   14000916f:	e9 9d 00 00 00       	jmp    140009211 <__mingw_wcrtomb_cp+0x151>
   140009174:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000917b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   140009181:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   140009185:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140009188:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   14000918c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140009191:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   140009198:	00 00 
   14000919a:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000919d:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   1400091a1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400091a5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400091aa:	41 b9 01 00 00 00    	mov    r9d,0x1
   1400091b0:	49 89 c8             	mov    r8,rcx
   1400091b3:	ba 00 00 00 00       	mov    edx,0x0
   1400091b8:	89 c1                	mov    ecx,eax
   1400091ba:	48 8b 05 a7 70 00 00 	mov    rax,QWORD PTR [rip+0x70a7]        # 140010268 <__imp_WideCharToMultiByte>
   1400091c1:	ff d0                	call   rax
   1400091c3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400091c6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400091ca:	74 32                	je     1400091fe <__mingw_wcrtomb_cp+0x13e>
   1400091cc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400091cf:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   1400091d2:	7f 2a                	jg     1400091fe <__mingw_wcrtomb_cp+0x13e>
   1400091d4:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400091d7:	85 c0                	test   eax,eax
   1400091d9:	75 23                	jne    1400091fe <__mingw_wcrtomb_cp+0x13e>
   1400091db:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400091de:	48 63 c8             	movsxd rcx,eax
   1400091e1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400091e5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400091e9:	49 89 c8             	mov    r8,rcx
   1400091ec:	48 89 c1             	mov    rcx,rax
   1400091ef:	e8 34 04 00 00       	call   140009628 <memcpy>
   1400091f4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400091f7:	48 98                	cdqe
   1400091f9:	eb 16                	jmp    140009211 <__mingw_wcrtomb_cp+0x151>
   1400091fb:	90                   	nop
   1400091fc:	eb 01                	jmp    1400091ff <__mingw_wcrtomb_cp+0x13f>
   1400091fe:	90                   	nop
   1400091ff:	e8 b4 03 00 00       	call   1400095b8 <_errno>
   140009204:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000920a:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009211:	48 83 c4 50          	add    rsp,0x50
   140009215:	5d                   	pop    rbp
   140009216:	c3                   	ret
   140009217:	90                   	nop
   140009218:	90                   	nop
   140009219:	90                   	nop
   14000921a:	90                   	nop
   14000921b:	90                   	nop
   14000921c:	90                   	nop
   14000921d:	90                   	nop
   14000921e:	90                   	nop
   14000921f:	90                   	nop

0000000140009220 <__mingw_mbrtowc_cp>:
   140009220:	55                   	push   rbp
   140009221:	48 89 e5             	mov    rbp,rsp
   140009224:	48 83 ec 50          	sub    rsp,0x50
   140009228:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000922c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009230:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009234:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009238:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   14000923d:	75 1b                	jne    14000925a <__mingw_mbrtowc_cp+0x3a>
   14000923f:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   140009246:	00 
   140009247:	48 8d 05 d2 22 00 00 	lea    rax,[rip+0x22d2]        # 14000b520 <.rdata>
   14000924e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140009252:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   140009259:	00 
   14000925a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000925e:	8b 00                	mov    eax,DWORD PTR [rax]
   140009260:	3d ff 00 00 00       	cmp    eax,0xff
   140009265:	0f 87 b9 01 00 00    	ja     140009424 <__mingw_mbrtowc_cp+0x204>
   14000926b:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009270:	75 0c                	jne    14000927e <__mingw_mbrtowc_cp+0x5e>
   140009272:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009279:	e9 bc 01 00 00       	jmp    14000943a <__mingw_mbrtowc_cp+0x21a>
   14000927e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009282:	8b 00                	mov    eax,DWORD PTR [rax]
   140009284:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140009287:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   14000928b:	75 0c                	jne    140009299 <__mingw_mbrtowc_cp+0x79>
   14000928d:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009291:	84 c0                	test   al,al
   140009293:	0f 85 8e 01 00 00    	jne    140009427 <__mingw_mbrtowc_cp+0x207>
   140009299:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   14000929d:	75 2c                	jne    1400092cb <__mingw_mbrtowc_cp+0xab>
   14000929f:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400092a4:	74 11                	je     1400092b7 <__mingw_mbrtowc_cp+0x97>
   1400092a6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400092aa:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400092ad:	0f b6 d0             	movzx  edx,al
   1400092b0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400092b4:	66 89 10             	mov    WORD PTR [rax],dx
   1400092b7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400092bb:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400092be:	84 c0                	test   al,al
   1400092c0:	0f 95 c0             	setne  al
   1400092c3:	0f b6 c0             	movzx  eax,al
   1400092c6:	e9 6f 01 00 00       	jmp    14000943a <__mingw_mbrtowc_cp+0x21a>
   1400092cb:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400092d2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400092d9:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400092dd:	84 c0                	test   al,al
   1400092df:	74 1a                	je     1400092fb <__mingw_mbrtowc_cp+0xdb>
   1400092e1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400092e5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400092e8:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   1400092eb:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400092f2:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400092f9:	eb 73                	jmp    14000936e <__mingw_mbrtowc_cp+0x14e>
   1400092fb:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   1400092ff:	75 5c                	jne    14000935d <__mingw_mbrtowc_cp+0x13d>
   140009301:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009305:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009308:	0f b6 c0             	movzx  eax,al
   14000930b:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000930e:	89 c1                	mov    ecx,eax
   140009310:	e8 ab 01 00 00       	call   1400094c0 <__mingw_isleadbyte_cp>
   140009315:	85 c0                	test   eax,eax
   140009317:	74 44                	je     14000935d <__mingw_mbrtowc_cp+0x13d>
   140009319:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000931d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009320:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009323:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   140009328:	77 15                	ja     14000933f <__mingw_mbrtowc_cp+0x11f>
   14000932a:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000932d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009331:	89 10                	mov    DWORD PTR [rax],edx
   140009333:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   14000933a:	e9 fb 00 00 00       	jmp    14000943a <__mingw_mbrtowc_cp+0x21a>
   14000933f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009343:	48 83 c0 01          	add    rax,0x1
   140009347:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000934a:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000934d:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140009354:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   14000935b:	eb 11                	jmp    14000936e <__mingw_mbrtowc_cp+0x14e>
   14000935d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009361:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009364:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009367:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000936e:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009372:	84 c0                	test   al,al
   140009374:	75 24                	jne    14000939a <__mingw_mbrtowc_cp+0x17a>
   140009376:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000937b:	74 09                	je     140009386 <__mingw_mbrtowc_cp+0x166>
   14000937d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009381:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   140009386:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000938a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009390:	b8 00 00 00 00       	mov    eax,0x0
   140009395:	e9 a0 00 00 00       	jmp    14000943a <__mingw_mbrtowc_cp+0x21a>
   14000939a:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   14000939e:	75 08                	jne    1400093a8 <__mingw_mbrtowc_cp+0x188>
   1400093a0:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   1400093a4:	84 c0                	test   al,al
   1400093a6:	74 64                	je     14000940c <__mingw_mbrtowc_cp+0x1ec>
   1400093a8:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   1400093ae:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   1400093b2:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400093b6:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   1400093b9:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   1400093c0:	00 
   1400093c1:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   1400093c5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400093ca:	45 89 c1             	mov    r9d,r8d
   1400093cd:	49 89 c8             	mov    r8,rcx
   1400093d0:	ba 08 00 00 00       	mov    edx,0x8
   1400093d5:	89 c1                	mov    ecx,eax
   1400093d7:	48 8b 05 5a 6e 00 00 	mov    rax,QWORD PTR [rip+0x6e5a]        # 140010238 <__imp_MultiByteToWideChar>
   1400093de:	ff d0                	call   rax
   1400093e0:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400093e3:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   1400093e7:	75 26                	jne    14000940f <__mingw_mbrtowc_cp+0x1ef>
   1400093e9:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400093ee:	74 0b                	je     1400093fb <__mingw_mbrtowc_cp+0x1db>
   1400093f0:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   1400093f4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400093f8:	66 89 10             	mov    WORD PTR [rax],dx
   1400093fb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400093ff:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009405:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009408:	48 98                	cdqe
   14000940a:	eb 2e                	jmp    14000943a <__mingw_mbrtowc_cp+0x21a>
   14000940c:	90                   	nop
   14000940d:	eb 01                	jmp    140009410 <__mingw_mbrtowc_cp+0x1f0>
   14000940f:	90                   	nop
   140009410:	e8 a3 01 00 00       	call   1400095b8 <_errno>
   140009415:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000941b:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009422:	eb 16                	jmp    14000943a <__mingw_mbrtowc_cp+0x21a>
   140009424:	90                   	nop
   140009425:	eb 01                	jmp    140009428 <__mingw_mbrtowc_cp+0x208>
   140009427:	90                   	nop
   140009428:	e8 8b 01 00 00       	call   1400095b8 <_errno>
   14000942d:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009433:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000943a:	48 83 c4 50          	add    rsp,0x50
   14000943e:	5d                   	pop    rbp
   14000943f:	c3                   	ret

0000000140009440 <fallback_IsDBCSLeadByteEx>:
   140009440:	55                   	push   rbp
   140009441:	48 89 e5             	mov    rbp,rsp
   140009444:	48 83 ec 40          	sub    rsp,0x40
   140009448:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000944b:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   14000944e:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   140009452:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009455:	89 c1                	mov    ecx,eax
   140009457:	48 8b 05 a2 6d 00 00 	mov    rax,QWORD PTR [rip+0x6da2]        # 140010200 <__imp_GetCPInfo>
   14000945e:	ff d0                	call   rax
   140009460:	85 c0                	test   eax,eax
   140009462:	74 51                	je     1400094b5 <fallback_IsDBCSLeadByteEx+0x75>
   140009464:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140009467:	83 f8 02             	cmp    eax,0x2
   14000946a:	75 49                	jne    1400094b5 <fallback_IsDBCSLeadByteEx+0x75>
   14000946c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009473:	eb 2c                	jmp    1400094a1 <fallback_IsDBCSLeadByteEx+0x61>
   140009475:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009478:	48 98                	cdqe
   14000947a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000947f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   140009482:	72 19                	jb     14000949d <fallback_IsDBCSLeadByteEx+0x5d>
   140009484:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009487:	83 c0 01             	add    eax,0x1
   14000948a:	48 98                	cdqe
   14000948c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009491:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   140009494:	72 07                	jb     14000949d <fallback_IsDBCSLeadByteEx+0x5d>
   140009496:	b8 01 00 00 00       	mov    eax,0x1
   14000949b:	eb 1d                	jmp    1400094ba <fallback_IsDBCSLeadByteEx+0x7a>
   14000949d:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400094a1:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   1400094a5:	7f 0e                	jg     1400094b5 <fallback_IsDBCSLeadByteEx+0x75>
   1400094a7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400094aa:	48 98                	cdqe
   1400094ac:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400094b1:	84 c0                	test   al,al
   1400094b3:	75 c0                	jne    140009475 <fallback_IsDBCSLeadByteEx+0x35>
   1400094b5:	b8 00 00 00 00       	mov    eax,0x0
   1400094ba:	48 83 c4 40          	add    rsp,0x40
   1400094be:	5d                   	pop    rbp
   1400094bf:	c3                   	ret

00000001400094c0 <__mingw_isleadbyte_cp>:
   1400094c0:	55                   	push   rbp
   1400094c1:	48 89 e5             	mov    rbp,rsp
   1400094c4:	48 83 ec 40          	sub    rsp,0x40
   1400094c8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400094cb:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400094ce:	48 8b 05 cb 66 00 00 	mov    rax,QWORD PTR [rip+0x66cb]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400094d5:	48 85 c0             	test   rax,rax
   1400094d8:	75 71                	jne    14000954b <__mingw_isleadbyte_cp+0x8b>
   1400094da:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400094e1:	00 
   1400094e2:	48 8d 05 47 20 00 00 	lea    rax,[rip+0x2047]        # 14000b530 <.rdata>
   1400094e9:	48 89 c1             	mov    rcx,rax
   1400094ec:	48 8b 05 1d 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d1d]        # 140010210 <__imp_GetModuleHandleA>
   1400094f3:	ff d0                	call   rax
   1400094f5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400094f9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400094fe:	74 1b                	je     14000951b <__mingw_isleadbyte_cp+0x5b>
   140009500:	48 8d 15 36 20 00 00 	lea    rdx,[rip+0x2036]        # 14000b53d <.rdata+0xd>
   140009507:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000950b:	48 89 c1             	mov    rcx,rax
   14000950e:	48 8b 05 03 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d03]        # 140010218 <__imp_GetProcAddress>
   140009515:	ff d0                	call   rax
   140009517:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000951b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140009520:	75 0b                	jne    14000952d <__mingw_isleadbyte_cp+0x6d>
   140009522:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 140009440 <fallback_IsDBCSLeadByteEx>
   140009529:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000952d:	48 8d 05 6c 66 00 00 	lea    rax,[rip+0x666c]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009534:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140009538:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000953c:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140009540:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140009544:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140009548:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000954b:	4c 8b 05 4e 66 00 00 	mov    r8,QWORD PTR [rip+0x664e]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009552:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009555:	0f b6 d0             	movzx  edx,al
   140009558:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000955b:	89 c1                	mov    ecx,eax
   14000955d:	41 ff d0             	call   r8
   140009560:	48 83 c4 40          	add    rsp,0x40
   140009564:	5d                   	pop    rbp
   140009565:	c3                   	ret
   140009566:	90                   	nop
   140009567:	90                   	nop
   140009568:	90                   	nop
   140009569:	90                   	nop
   14000956a:	90                   	nop
   14000956b:	90                   	nop
   14000956c:	90                   	nop
   14000956d:	90                   	nop
   14000956e:	90                   	nop
   14000956f:	90                   	nop

0000000140009570 <__C_specific_handler>:
   140009570:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010278 <__imp___C_specific_handler>
   140009576:	90                   	nop
   140009577:	90                   	nop

0000000140009578 <___lc_codepage_func>:
   140009578:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010280 <__imp____lc_codepage_func>
   14000957e:	90                   	nop
   14000957f:	90                   	nop

0000000140009580 <___mb_cur_max_func>:
   140009580:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010288 <__imp____mb_cur_max_func>
   140009586:	90                   	nop
   140009587:	90                   	nop

0000000140009588 <__getmainargs>:
   140009588:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010290 <__imp___getmainargs>
   14000958e:	90                   	nop
   14000958f:	90                   	nop

0000000140009590 <__iob_func>:
   140009590:	ff 25 0a 6d 00 00    	jmp    QWORD PTR [rip+0x6d0a]        # 1400102a0 <__imp___iob_func>
   140009596:	90                   	nop
   140009597:	90                   	nop

0000000140009598 <__set_app_type>:
   140009598:	ff 25 0a 6d 00 00    	jmp    QWORD PTR [rip+0x6d0a]        # 1400102a8 <__imp___set_app_type>
   14000959e:	90                   	nop
   14000959f:	90                   	nop

00000001400095a0 <__setusermatherr>:
   1400095a0:	ff 25 0a 6d 00 00    	jmp    QWORD PTR [rip+0x6d0a]        # 1400102b0 <__imp___setusermatherr>
   1400095a6:	90                   	nop
   1400095a7:	90                   	nop

00000001400095a8 <_amsg_exit>:
   1400095a8:	ff 25 0a 6d 00 00    	jmp    QWORD PTR [rip+0x6d0a]        # 1400102b8 <__imp__amsg_exit>
   1400095ae:	90                   	nop
   1400095af:	90                   	nop

00000001400095b0 <_cexit>:
   1400095b0:	ff 25 0a 6d 00 00    	jmp    QWORD PTR [rip+0x6d0a]        # 1400102c0 <__imp__cexit>
   1400095b6:	90                   	nop
   1400095b7:	90                   	nop

00000001400095b8 <_errno>:
   1400095b8:	ff 25 12 6d 00 00    	jmp    QWORD PTR [rip+0x6d12]        # 1400102d0 <__imp__errno>
   1400095be:	90                   	nop
   1400095bf:	90                   	nop

00000001400095c0 <_initterm>:
   1400095c0:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 1400102e0 <__imp__initterm>
   1400095c6:	90                   	nop
   1400095c7:	90                   	nop

00000001400095c8 <_lock>:
   1400095c8:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 1400102e8 <__imp__lock>
   1400095ce:	90                   	nop
   1400095cf:	90                   	nop

00000001400095d0 <_unlock>:
   1400095d0:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 1400102f0 <__imp__unlock>
   1400095d6:	90                   	nop
   1400095d7:	90                   	nop

00000001400095d8 <_crt_atexit>:
   1400095d8:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 1400102f8 <__imp__crt_atexit>
   1400095de:	90                   	nop
   1400095df:	90                   	nop

00000001400095e0 <abort>:
   1400095e0:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010300 <__imp_abort>
   1400095e6:	90                   	nop
   1400095e7:	90                   	nop

00000001400095e8 <calloc>:
   1400095e8:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010308 <__imp_calloc>
   1400095ee:	90                   	nop
   1400095ef:	90                   	nop

00000001400095f0 <exit>:
   1400095f0:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010310 <__imp_exit>
   1400095f6:	90                   	nop
   1400095f7:	90                   	nop

00000001400095f8 <fflush>:
   1400095f8:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010318 <__imp_fflush>
   1400095fe:	90                   	nop
   1400095ff:	90                   	nop

0000000140009600 <fprintf>:
   140009600:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010320 <__imp_fprintf>
   140009606:	90                   	nop
   140009607:	90                   	nop

0000000140009608 <fputc>:
   140009608:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010328 <__imp_fputc>
   14000960e:	90                   	nop
   14000960f:	90                   	nop

0000000140009610 <free>:
   140009610:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010330 <__imp_free>
   140009616:	90                   	nop
   140009617:	90                   	nop

0000000140009618 <localeconv>:
   140009618:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010338 <__imp_localeconv>
   14000961e:	90                   	nop
   14000961f:	90                   	nop

0000000140009620 <malloc>:
   140009620:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010340 <__imp_malloc>
   140009626:	90                   	nop
   140009627:	90                   	nop

0000000140009628 <memcpy>:
   140009628:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010348 <__imp_memcpy>
   14000962e:	90                   	nop
   14000962f:	90                   	nop

0000000140009630 <setvbuf>:
   140009630:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010350 <__imp_setvbuf>
   140009636:	90                   	nop
   140009637:	90                   	nop

0000000140009638 <signal>:
   140009638:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010358 <__imp_signal>
   14000963e:	90                   	nop
   14000963f:	90                   	nop

0000000140009640 <strerror>:
   140009640:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010360 <__imp_strerror>
   140009646:	90                   	nop
   140009647:	90                   	nop

0000000140009648 <strlen>:
   140009648:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010368 <__imp_strlen>
   14000964e:	90                   	nop
   14000964f:	90                   	nop

0000000140009650 <strncmp>:
   140009650:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010370 <__imp_strncmp>
   140009656:	90                   	nop
   140009657:	90                   	nop

0000000140009658 <vfprintf>:
   140009658:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010378 <__imp_vfprintf>
   14000965e:	90                   	nop
   14000965f:	90                   	nop

0000000140009660 <wcslen>:
   140009660:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010380 <__imp_wcslen>
   140009666:	90                   	nop
   140009667:	90                   	nop
   140009668:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000966f:	00 

0000000140009670 <WideCharToMultiByte>:
   140009670:	ff 25 f2 6b 00 00    	jmp    QWORD PTR [rip+0x6bf2]        # 140010268 <__imp_WideCharToMultiByte>
   140009676:	90                   	nop
   140009677:	90                   	nop

0000000140009678 <VirtualQuery>:
   140009678:	ff 25 e2 6b 00 00    	jmp    QWORD PTR [rip+0x6be2]        # 140010260 <__imp_VirtualQuery>
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <VirtualProtect>:
   140009680:	ff 25 d2 6b 00 00    	jmp    QWORD PTR [rip+0x6bd2]        # 140010258 <__imp_VirtualProtect>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <TlsGetValue>:
   140009688:	ff 25 c2 6b 00 00    	jmp    QWORD PTR [rip+0x6bc2]        # 140010250 <__imp_TlsGetValue>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <Sleep>:
   140009690:	ff 25 b2 6b 00 00    	jmp    QWORD PTR [rip+0x6bb2]        # 140010248 <__imp_Sleep>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <SetUnhandledExceptionFilter>:
   140009698:	ff 25 a2 6b 00 00    	jmp    QWORD PTR [rip+0x6ba2]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <MultiByteToWideChar>:
   1400096a0:	ff 25 92 6b 00 00    	jmp    QWORD PTR [rip+0x6b92]        # 140010238 <__imp_MultiByteToWideChar>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <LoadLibraryA>:
   1400096a8:	ff 25 82 6b 00 00    	jmp    QWORD PTR [rip+0x6b82]        # 140010230 <__imp_LoadLibraryA>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <LeaveCriticalSection>:
   1400096b0:	ff 25 72 6b 00 00    	jmp    QWORD PTR [rip+0x6b72]        # 140010228 <__imp_LeaveCriticalSection>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <InitializeCriticalSection>:
   1400096b8:	ff 25 62 6b 00 00    	jmp    QWORD PTR [rip+0x6b62]        # 140010220 <__imp_InitializeCriticalSection>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <GetProcAddress>:
   1400096c0:	ff 25 52 6b 00 00    	jmp    QWORD PTR [rip+0x6b52]        # 140010218 <__imp_GetProcAddress>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <GetModuleHandleA>:
   1400096c8:	ff 25 42 6b 00 00    	jmp    QWORD PTR [rip+0x6b42]        # 140010210 <__imp_GetModuleHandleA>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <GetLastError>:
   1400096d0:	ff 25 32 6b 00 00    	jmp    QWORD PTR [rip+0x6b32]        # 140010208 <__imp_GetLastError>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <GetCPInfo>:
   1400096d8:	ff 25 22 6b 00 00    	jmp    QWORD PTR [rip+0x6b22]        # 140010200 <__imp_GetCPInfo>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <FreeLibrary>:
   1400096e0:	ff 25 12 6b 00 00    	jmp    QWORD PTR [rip+0x6b12]        # 1400101f8 <__imp_FreeLibrary>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop

00000001400096e8 <EnterCriticalSection>:
   1400096e8:	ff 25 02 6b 00 00    	jmp    QWORD PTR [rip+0x6b02]        # 1400101f0 <__imp_EnterCriticalSection>
   1400096ee:	90                   	nop
   1400096ef:	90                   	nop

00000001400096f0 <DeleteCriticalSection>:
   1400096f0:	ff 25 f2 6a 00 00    	jmp    QWORD PTR [rip+0x6af2]        # 1400101e8 <__IAT_start__>
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop
   1400096f8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   1400096ff:	00 

0000000140009700 <register_frame_ctor>:
   140009700:	e9 6b 7f ff ff       	jmp    140001670 <__gcc_register_frame>
   140009705:	90                   	nop
   140009706:	90                   	nop
   140009707:	90                   	nop
   140009708:	90                   	nop
   140009709:	90                   	nop
   14000970a:	90                   	nop
   14000970b:	90                   	nop
   14000970c:	90                   	nop
   14000970d:	90                   	nop
   14000970e:	90                   	nop
   14000970f:	90                   	nop
