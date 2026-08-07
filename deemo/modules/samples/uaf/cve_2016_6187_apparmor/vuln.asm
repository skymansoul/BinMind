
C:\Users\Administrator\Desktop\BinMind\round2\samples\uaf\cve_2016_6187_apparmor\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 6f 86 00 00       	call   140009698 <fflush>
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
   14000113b:	e8 08 85 00 00       	call   140009648 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 08 7f 00 00       	call   140009070 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 4f 85 00 00       	call   1400096d0 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 e7 84 00 00       	call   140009680 <abort>
   140001199:	e8 d2 11 00 00       	call   140002370 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 91 f0 00 00 	mov    rax,QWORD PTR [rip+0xf091]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 46 7e 00 00       	call   140009010 <_set_invalid_parameter_handler>
   1400011ca:	e8 b1 1a 00 00       	call   140002c80 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 47 84 00 00       	call   140009638 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 3b 84 00 00       	call   140009638 <__set_app_type>
   1400011fd:	e8 be 7c 00 00       	call   140008ec0 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 be 7c 00 00       	call   140008ed0 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 2e 07 00 00       	call   140001950 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 13 84 00 00       	call   140009648 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 38 12 00 00       	call   14000248a <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 e6 7d 00 00       	call   140009050 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 e0 7b 00 00       	call   140008e60 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 ba 83 00 00       	call   140009648 <_amsg_exit>
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
   1400012cb:	e8 58 83 00 00       	call   140009628 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 65 83 00 00       	call   140009648 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 3e 83 00 00       	call   140009648 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 40 83 00 00       	call   140009660 <_initterm>
   140001320:	e8 02 06 00 00       	call   140001927 <__main>
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
   14000138d:	e8 4e 7b 00 00       	call   140008ee0 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 0a 04 00 00       	call   1400017c4 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 bf 82 00 00       	call   140009690 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 70 82 00 00       	call   140009650 <_cexit>
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
   140001511:	e8 aa 81 00 00       	call   1400096c0 <malloc>
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
   14000155c:	e8 87 81 00 00       	call   1400096e8 <strlen>
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
   140001585:	e8 36 81 00 00       	call   1400096c0 <malloc>
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
   1400015e8:	e8 db 80 00 00       	call   1400096c8 <memcpy>
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
   140001642:	e8 31 80 00 00       	call   140009678 <_crt_atexit>
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

0000000140001760 <aa_profile_free>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 20          	sub    rsp,0x20
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001770:	48 89 c1             	mov    rcx,rax
   140001773:	e8 38 7f 00 00       	call   1400096b0 <free>
   140001778:	90                   	nop
   140001779:	48 83 c4 20          	add    rsp,0x20
   14000177d:	5d                   	pop    rbp
   14000177e:	c3                   	ret

000000014000177f <aa_exec_update>:
   14000177f:	55                   	push   rbp
   140001780:	48 89 e5             	mov    rbp,rsp
   140001783:	48 83 ec 20          	sub    rsp,0x20
   140001787:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000178b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000178f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001792:	48 89 c1             	mov    rcx,rax
   140001795:	e8 c6 ff ff ff       	call   140001760 <aa_profile_free>
   14000179a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000179e:	c7 40 08 01 00 00 00 	mov    DWORD PTR [rax+0x8],0x1
   1400017a5:	b8 00 00 00 00       	mov    eax,0x0
   1400017aa:	48 83 c4 20          	add    rsp,0x20
   1400017ae:	5d                   	pop    rbp
   1400017af:	c3                   	ret

00000001400017b0 <aa_get_profile_flags>:
   1400017b0:	55                   	push   rbp
   1400017b1:	48 89 e5             	mov    rbp,rsp
   1400017b4:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400017b8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017bc:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017bf:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400017c2:	5d                   	pop    rbp
   1400017c3:	c3                   	ret

00000001400017c4 <main>:
   1400017c4:	55                   	push   rbp
   1400017c5:	48 89 e5             	mov    rbp,rsp
   1400017c8:	48 83 ec 30          	sub    rsp,0x30
   1400017cc:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400017cf:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400017d3:	e8 4f 01 00 00       	call   140001927 <__main>
   1400017d8:	b9 10 00 00 00       	mov    ecx,0x10
   1400017dd:	e8 de 7e 00 00       	call   1400096c0 <malloc>
   1400017e2:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400017e6:	b9 18 00 00 00       	mov    ecx,0x18
   1400017eb:	e8 d0 7e 00 00       	call   1400096c0 <malloc>
   1400017f0:	48 89 c2             	mov    rdx,rax
   1400017f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017f7:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400017fa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017fe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001801:	c7 40 14 02 00 00 00 	mov    DWORD PTR [rax+0x14],0x2
   140001808:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000180c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000180f:	48 ba 61 70 70 61 72 	movabs rdx,0x726f6d7261707061
   140001816:	6d 6f 72 
   140001819:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000181c:	c6 40 08 00          	mov    BYTE PTR [rax+0x8],0x0
   140001820:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001824:	c7 40 08 00 00 00 00 	mov    DWORD PTR [rax+0x8],0x0
   14000182b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000182f:	48 89 c1             	mov    rcx,rax
   140001832:	e8 48 ff ff ff       	call   14000177f <aa_exec_update>
   140001837:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000183b:	48 89 c1             	mov    rcx,rax
   14000183e:	e8 6d ff ff ff       	call   1400017b0 <aa_get_profile_flags>
   140001843:	89 c2                	mov    edx,eax
   140001845:	48 8d 05 04 98 00 00 	lea    rax,[rip+0x9804]        # 14000b050 <.rdata>
   14000184c:	48 89 c1             	mov    rcx,rax
   14000184f:	e8 2c 19 00 00       	call   140003180 <__mingw_printf>
   140001854:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001858:	48 89 c1             	mov    rcx,rax
   14000185b:	e8 50 7e 00 00       	call   1400096b0 <free>
   140001860:	b8 00 00 00 00       	mov    eax,0x0
   140001865:	48 83 c4 30          	add    rsp,0x30
   140001869:	5d                   	pop    rbp
   14000186a:	c3                   	ret
   14000186b:	90                   	nop
   14000186c:	90                   	nop
   14000186d:	90                   	nop
   14000186e:	90                   	nop
   14000186f:	90                   	nop

0000000140001870 <__do_global_dtors>:
   140001870:	55                   	push   rbp
   140001871:	48 89 e5             	mov    rbp,rsp
   140001874:	48 83 ec 20          	sub    rsp,0x20
   140001878:	eb 1e                	jmp    140001898 <__do_global_dtors+0x28>
   14000187a:	48 8b 05 8f 87 00 00 	mov    rax,QWORD PTR [rip+0x878f]        # 14000a010 <p.0>
   140001881:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001884:	ff d0                	call   rax
   140001886:	48 8b 05 83 87 00 00 	mov    rax,QWORD PTR [rip+0x8783]        # 14000a010 <p.0>
   14000188d:	48 83 c0 08          	add    rax,0x8
   140001891:	48 89 05 78 87 00 00 	mov    QWORD PTR [rip+0x8778],rax        # 14000a010 <p.0>
   140001898:	48 8b 05 71 87 00 00 	mov    rax,QWORD PTR [rip+0x8771]        # 14000a010 <p.0>
   14000189f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018a2:	48 85 c0             	test   rax,rax
   1400018a5:	75 d3                	jne    14000187a <__do_global_dtors+0xa>
   1400018a7:	90                   	nop
   1400018a8:	90                   	nop
   1400018a9:	48 83 c4 20          	add    rsp,0x20
   1400018ad:	5d                   	pop    rbp
   1400018ae:	c3                   	ret

00000001400018af <__do_global_ctors>:
   1400018af:	55                   	push   rbp
   1400018b0:	48 89 e5             	mov    rbp,rsp
   1400018b3:	48 83 ec 30          	sub    rsp,0x30
   1400018b7:	48 8b 05 b2 9c 00 00 	mov    rax,QWORD PTR [rip+0x9cb2]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018be:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018c1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400018c4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400018c8:	75 25                	jne    1400018ef <__do_global_ctors+0x40>
   1400018ca:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400018d1:	eb 04                	jmp    1400018d7 <__do_global_ctors+0x28>
   1400018d3:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400018d7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018da:	8d 50 01             	lea    edx,[rax+0x1]
   1400018dd:	48 8b 05 8c 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c8c]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018e4:	89 d2                	mov    edx,edx
   1400018e6:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018ea:	48 85 c0             	test   rax,rax
   1400018ed:	75 e4                	jne    1400018d3 <__do_global_ctors+0x24>
   1400018ef:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018f2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400018f5:	eb 14                	jmp    14000190b <__do_global_ctors+0x5c>
   1400018f7:	48 8b 05 72 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c72]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018fe:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001901:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001905:	ff d0                	call   rax
   140001907:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000190b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000190f:	75 e6                	jne    1400018f7 <__do_global_ctors+0x48>
   140001911:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001870 <__do_global_dtors>
   140001918:	48 89 c1             	mov    rcx,rax
   14000191b:	e8 0f fd ff ff       	call   14000162f <atexit>
   140001920:	90                   	nop
   140001921:	48 83 c4 30          	add    rsp,0x30
   140001925:	5d                   	pop    rbp
   140001926:	c3                   	ret

0000000140001927 <__main>:
   140001927:	55                   	push   rbp
   140001928:	48 89 e5             	mov    rbp,rsp
   14000192b:	48 83 ec 20          	sub    rsp,0x20
   14000192f:	8b 05 4b d7 00 00    	mov    eax,DWORD PTR [rip+0xd74b]        # 14000f080 <initialized>
   140001935:	85 c0                	test   eax,eax
   140001937:	75 0f                	jne    140001948 <__main+0x21>
   140001939:	c7 05 3d d7 00 00 01 	mov    DWORD PTR [rip+0xd73d],0x1        # 14000f080 <initialized>
   140001940:	00 00 00 
   140001943:	e8 67 ff ff ff       	call   1400018af <__do_global_ctors>
   140001948:	90                   	nop
   140001949:	48 83 c4 20          	add    rsp,0x20
   14000194d:	5d                   	pop    rbp
   14000194e:	c3                   	ret
   14000194f:	90                   	nop

0000000140001950 <_setargv>:
   140001950:	55                   	push   rbp
   140001951:	48 89 e5             	mov    rbp,rsp
   140001954:	b8 00 00 00 00       	mov    eax,0x0
   140001959:	5d                   	pop    rbp
   14000195a:	c3                   	ret
   14000195b:	90                   	nop
   14000195c:	90                   	nop
   14000195d:	90                   	nop
   14000195e:	90                   	nop
   14000195f:	90                   	nop

0000000140001960 <__dyn_tls_init>:
   140001960:	55                   	push   rbp
   140001961:	48 89 e5             	mov    rbp,rsp
   140001964:	48 83 ec 30          	sub    rsp,0x30
   140001968:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000196c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000196f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001973:	48 8b 05 d6 9b 00 00 	mov    rax,QWORD PTR [rip+0x9bd6]        # 14000b550 <.refptr._CRT_MT>
   14000197a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000197c:	83 f8 02             	cmp    eax,0x2
   14000197f:	74 0d                	je     14000198e <__dyn_tls_init+0x2e>
   140001981:	48 8b 05 c8 9b 00 00 	mov    rax,QWORD PTR [rip+0x9bc8]        # 14000b550 <.refptr._CRT_MT>
   140001988:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000198e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001992:	74 1e                	je     1400019b2 <__dyn_tls_init+0x52>
   140001994:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001998:	75 5b                	jne    1400019f5 <__dyn_tls_init+0x95>
   14000199a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000199e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019a1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019a5:	49 89 c8             	mov    r8,rcx
   1400019a8:	48 89 c1             	mov    rcx,rax
   1400019ab:	e8 d1 11 00 00       	call   140002b81 <__mingw_TLScallback>
   1400019b0:	eb 43                	jmp    1400019f5 <__dyn_tls_init+0x95>
   1400019b2:	48 8d 05 1f 9f 00 00 	lea    rax,[rip+0x9f1f]        # 14000b8d8 <___crt_xd_start__>
   1400019b9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400019bd:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019c2:	eb 22                	jmp    1400019e6 <__dyn_tls_init+0x86>
   1400019c4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400019c8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400019cc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019d0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019d3:	48 85 c0             	test   rax,rax
   1400019d6:	74 09                	je     1400019e1 <__dyn_tls_init+0x81>
   1400019d8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019dc:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019df:	ff d0                	call   rax
   1400019e1:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019e6:	48 8d 05 f3 9e 00 00 	lea    rax,[rip+0x9ef3]        # 14000b8e0 <__xd_z>
   1400019ed:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   1400019f1:	75 d1                	jne    1400019c4 <__dyn_tls_init+0x64>
   1400019f3:	eb 01                	jmp    1400019f6 <__dyn_tls_init+0x96>
   1400019f5:	90                   	nop
   1400019f6:	48 83 c4 30          	add    rsp,0x30
   1400019fa:	5d                   	pop    rbp
   1400019fb:	c3                   	ret

00000001400019fc <__tlregdtor>:
   1400019fc:	55                   	push   rbp
   1400019fd:	48 89 e5             	mov    rbp,rsp
   140001a00:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a04:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001a09:	75 07                	jne    140001a12 <__tlregdtor+0x16>
   140001a0b:	b8 00 00 00 00       	mov    eax,0x0
   140001a10:	eb 05                	jmp    140001a17 <__tlregdtor+0x1b>
   140001a12:	b8 00 00 00 00       	mov    eax,0x0
   140001a17:	5d                   	pop    rbp
   140001a18:	c3                   	ret

0000000140001a19 <__dyn_tls_dtor>:
   140001a19:	55                   	push   rbp
   140001a1a:	48 89 e5             	mov    rbp,rsp
   140001a1d:	48 83 ec 20          	sub    rsp,0x20
   140001a21:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a25:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a28:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a2c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a30:	74 06                	je     140001a38 <__dyn_tls_dtor+0x1f>
   140001a32:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a36:	75 18                	jne    140001a50 <__dyn_tls_dtor+0x37>
   140001a38:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a3c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a3f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a43:	49 89 c8             	mov    r8,rcx
   140001a46:	48 89 c1             	mov    rcx,rax
   140001a49:	e8 33 11 00 00       	call   140002b81 <__mingw_TLScallback>
   140001a4e:	eb 01                	jmp    140001a51 <__dyn_tls_dtor+0x38>
   140001a50:	90                   	nop
   140001a51:	48 83 c4 20          	add    rsp,0x20
   140001a55:	5d                   	pop    rbp
   140001a56:	c3                   	ret
   140001a57:	90                   	nop
   140001a58:	90                   	nop
   140001a59:	90                   	nop
   140001a5a:	90                   	nop
   140001a5b:	90                   	nop
   140001a5c:	90                   	nop
   140001a5d:	90                   	nop
   140001a5e:	90                   	nop
   140001a5f:	90                   	nop

0000000140001a60 <_matherr>:
   140001a60:	55                   	push   rbp
   140001a61:	53                   	push   rbx
   140001a62:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a69:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a6e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a72:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a76:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a7b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a7f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a83:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a85:	83 f8 06             	cmp    eax,0x6
   140001a88:	74 56                	je     140001ae0 <_matherr+0x80>
   140001a8a:	83 f8 06             	cmp    eax,0x6
   140001a8d:	7f 78                	jg     140001b07 <_matherr+0xa7>
   140001a8f:	83 f8 05             	cmp    eax,0x5
   140001a92:	74 59                	je     140001aed <_matherr+0x8d>
   140001a94:	83 f8 05             	cmp    eax,0x5
   140001a97:	7f 6e                	jg     140001b07 <_matherr+0xa7>
   140001a99:	83 f8 04             	cmp    eax,0x4
   140001a9c:	74 5c                	je     140001afa <_matherr+0x9a>
   140001a9e:	83 f8 04             	cmp    eax,0x4
   140001aa1:	7f 64                	jg     140001b07 <_matherr+0xa7>
   140001aa3:	83 f8 03             	cmp    eax,0x3
   140001aa6:	74 2b                	je     140001ad3 <_matherr+0x73>
   140001aa8:	83 f8 03             	cmp    eax,0x3
   140001aab:	7f 5a                	jg     140001b07 <_matherr+0xa7>
   140001aad:	83 f8 01             	cmp    eax,0x1
   140001ab0:	74 07                	je     140001ab9 <_matherr+0x59>
   140001ab2:	83 f8 02             	cmp    eax,0x2
   140001ab5:	74 0f                	je     140001ac6 <_matherr+0x66>
   140001ab7:	eb 4e                	jmp    140001b07 <_matherr+0xa7>
   140001ab9:	48 8d 05 e0 95 00 00 	lea    rax,[rip+0x95e0]        # 14000b0a0 <.rdata>
   140001ac0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ac4:	eb 4d                	jmp    140001b13 <_matherr+0xb3>
   140001ac6:	48 8d 05 f2 95 00 00 	lea    rax,[rip+0x95f2]        # 14000b0bf <.rdata+0x1f>
   140001acd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ad1:	eb 40                	jmp    140001b13 <_matherr+0xb3>
   140001ad3:	48 8d 05 06 96 00 00 	lea    rax,[rip+0x9606]        # 14000b0e0 <.rdata+0x40>
   140001ada:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ade:	eb 33                	jmp    140001b13 <_matherr+0xb3>
   140001ae0:	48 8d 05 19 96 00 00 	lea    rax,[rip+0x9619]        # 14000b100 <.rdata+0x60>
   140001ae7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001aeb:	eb 26                	jmp    140001b13 <_matherr+0xb3>
   140001aed:	48 8d 05 34 96 00 00 	lea    rax,[rip+0x9634]        # 14000b128 <.rdata+0x88>
   140001af4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001af8:	eb 19                	jmp    140001b13 <_matherr+0xb3>
   140001afa:	48 8d 05 4f 96 00 00 	lea    rax,[rip+0x964f]        # 14000b150 <.rdata+0xb0>
   140001b01:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b05:	eb 0c                	jmp    140001b13 <_matherr+0xb3>
   140001b07:	48 8d 05 78 96 00 00 	lea    rax,[rip+0x9678]        # 14000b186 <.rdata+0xe6>
   140001b0e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b12:	90                   	nop
   140001b13:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b17:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b1d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b21:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b26:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b2a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b2f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b33:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b37:	b9 02 00 00 00       	mov    ecx,0x2
   140001b3c:	e8 2f 75 00 00       	call   140009070 <__acrt_iob_func>
   140001b41:	48 89 c1             	mov    rcx,rax
   140001b44:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b48:	48 8d 05 49 96 00 00 	lea    rax,[rip+0x9649]        # 14000b198 <.rdata+0xf8>
   140001b4f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b56:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b5c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b62:	49 89 d9             	mov    r9,rbx
   140001b65:	49 89 d0             	mov    r8,rdx
   140001b68:	48 89 c2             	mov    rdx,rax
   140001b6b:	e8 30 7b 00 00       	call   1400096a0 <fprintf>
   140001b70:	b8 00 00 00 00       	mov    eax,0x0
   140001b75:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b79:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b7d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b82:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b89:	5b                   	pop    rbx
   140001b8a:	5d                   	pop    rbp
   140001b8b:	c3                   	ret
   140001b8c:	90                   	nop
   140001b8d:	90                   	nop
   140001b8e:	90                   	nop
   140001b8f:	90                   	nop

0000000140001b90 <__report_error>:
   140001b90:	55                   	push   rbp
   140001b91:	53                   	push   rbx
   140001b92:	48 83 ec 38          	sub    rsp,0x38
   140001b96:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b9b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b9f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001ba3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001ba7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001bab:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001baf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bb3:	b9 02 00 00 00       	mov    ecx,0x2
   140001bb8:	e8 b3 74 00 00       	call   140009070 <__acrt_iob_func>
   140001bbd:	48 89 c1             	mov    rcx,rax
   140001bc0:	48 8d 05 09 96 00 00 	lea    rax,[rip+0x9609]        # 14000b1d0 <.rdata>
   140001bc7:	48 89 c2             	mov    rdx,rax
   140001bca:	e8 d1 7a 00 00       	call   1400096a0 <fprintf>
   140001bcf:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001bd3:	b9 02 00 00 00       	mov    ecx,0x2
   140001bd8:	e8 93 74 00 00       	call   140009070 <__acrt_iob_func>
   140001bdd:	48 89 c1             	mov    rcx,rax
   140001be0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001be4:	49 89 d8             	mov    r8,rbx
   140001be7:	48 89 c2             	mov    rdx,rax
   140001bea:	e8 09 7b 00 00       	call   1400096f8 <vfprintf>
   140001bef:	e8 8c 7a 00 00       	call   140009680 <abort>
   140001bf4:	90                   	nop

0000000140001bf5 <mark_section_writable>:
   140001bf5:	55                   	push   rbp
   140001bf6:	48 89 e5             	mov    rbp,rsp
   140001bf9:	48 83 ec 60          	sub    rsp,0x60
   140001bfd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001c01:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001c08:	e9 82 00 00 00       	jmp    140001c8f <mark_section_writable+0x9a>
   140001c0d:	48 8b 0d cc d4 00 00 	mov    rcx,QWORD PTR [rip+0xd4cc]        # 14000f0e0 <the_secs>
   140001c14:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c17:	48 63 d0             	movsxd rdx,eax
   140001c1a:	48 89 d0             	mov    rax,rdx
   140001c1d:	48 c1 e0 02          	shl    rax,0x2
   140001c21:	48 01 d0             	add    rax,rdx
   140001c24:	48 c1 e0 03          	shl    rax,0x3
   140001c28:	48 01 c8             	add    rax,rcx
   140001c2b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c2f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c33:	72 56                	jb     140001c8b <mark_section_writable+0x96>
   140001c35:	48 8b 0d a4 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd4a4]        # 14000f0e0 <the_secs>
   140001c3c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c3f:	48 63 d0             	movsxd rdx,eax
   140001c42:	48 89 d0             	mov    rax,rdx
   140001c45:	48 c1 e0 02          	shl    rax,0x2
   140001c49:	48 01 d0             	add    rax,rdx
   140001c4c:	48 c1 e0 03          	shl    rax,0x3
   140001c50:	48 01 c8             	add    rax,rcx
   140001c53:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c57:	4c 8b 05 82 d4 00 00 	mov    r8,QWORD PTR [rip+0xd482]        # 14000f0e0 <the_secs>
   140001c5e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c61:	48 63 d0             	movsxd rdx,eax
   140001c64:	48 89 d0             	mov    rax,rdx
   140001c67:	48 c1 e0 02          	shl    rax,0x2
   140001c6b:	48 01 d0             	add    rax,rdx
   140001c6e:	48 c1 e0 03          	shl    rax,0x3
   140001c72:	4c 01 c0             	add    rax,r8
   140001c75:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c79:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c7c:	89 c0                	mov    eax,eax
   140001c7e:	48 01 c8             	add    rax,rcx
   140001c81:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c85:	0f 82 41 02 00 00    	jb     140001ecc <mark_section_writable+0x2d7>
   140001c8b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c8f:	8b 05 53 d4 00 00    	mov    eax,DWORD PTR [rip+0xd453]        # 14000f0e8 <maxSections>
   140001c95:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c98:	0f 8c 6f ff ff ff    	jl     140001c0d <mark_section_writable+0x18>
   140001c9e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001ca2:	48 89 c1             	mov    rcx,rax
   140001ca5:	e8 c1 11 00 00       	call   140002e6b <__mingw_GetSectionForAddress>
   140001caa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001cae:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001cb3:	75 13                	jne    140001cc8 <mark_section_writable+0xd3>
   140001cb5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001cb9:	48 8d 0d 30 95 00 00 	lea    rcx,[rip+0x9530]        # 14000b1f0 <.rdata+0x20>
   140001cc0:	48 89 c2             	mov    rdx,rax
   140001cc3:	e8 c8 fe ff ff       	call   140001b90 <__report_error>
   140001cc8:	48 8b 0d 11 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd411]        # 14000f0e0 <the_secs>
   140001ccf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cd2:	48 63 d0             	movsxd rdx,eax
   140001cd5:	48 89 d0             	mov    rax,rdx
   140001cd8:	48 c1 e0 02          	shl    rax,0x2
   140001cdc:	48 01 d0             	add    rax,rdx
   140001cdf:	48 c1 e0 03          	shl    rax,0x3
   140001ce3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001ce7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001ceb:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001cef:	48 8b 0d ea d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3ea]        # 14000f0e0 <the_secs>
   140001cf6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cf9:	48 63 d0             	movsxd rdx,eax
   140001cfc:	48 89 d0             	mov    rax,rdx
   140001cff:	48 c1 e0 02          	shl    rax,0x2
   140001d03:	48 01 d0             	add    rax,rdx
   140001d06:	48 c1 e0 03          	shl    rax,0x3
   140001d0a:	48 01 c8             	add    rax,rcx
   140001d0d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d13:	e8 9f 12 00 00       	call   140002fb7 <_GetPEImageBase>
   140001d18:	48 89 c1             	mov    rcx,rax
   140001d1b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d1f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d22:	41 89 c1             	mov    r9d,eax
   140001d25:	4c 8b 05 b4 d3 00 00 	mov    r8,QWORD PTR [rip+0xd3b4]        # 14000f0e0 <the_secs>
   140001d2c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d2f:	48 63 d0             	movsxd rdx,eax
   140001d32:	48 89 d0             	mov    rax,rdx
   140001d35:	48 c1 e0 02          	shl    rax,0x2
   140001d39:	48 01 d0             	add    rax,rdx
   140001d3c:	48 c1 e0 03          	shl    rax,0x3
   140001d40:	4c 01 c0             	add    rax,r8
   140001d43:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d47:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d4b:	48 8b 0d 8e d3 00 00 	mov    rcx,QWORD PTR [rip+0xd38e]        # 14000f0e0 <the_secs>
   140001d52:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d55:	48 63 d0             	movsxd rdx,eax
   140001d58:	48 89 d0             	mov    rax,rdx
   140001d5b:	48 c1 e0 02          	shl    rax,0x2
   140001d5f:	48 01 d0             	add    rax,rdx
   140001d62:	48 c1 e0 03          	shl    rax,0x3
   140001d66:	48 01 c8             	add    rax,rcx
   140001d69:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d6d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d71:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d77:	48 89 c1             	mov    rcx,rax
   140001d7a:	48 8b 05 df e4 00 00 	mov    rax,QWORD PTR [rip+0xe4df]        # 140010260 <__imp_VirtualQuery>
   140001d81:	ff d0                	call   rax
   140001d83:	48 85 c0             	test   rax,rax
   140001d86:	75 3f                	jne    140001dc7 <mark_section_writable+0x1d2>
   140001d88:	48 8b 0d 51 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd351]        # 14000f0e0 <the_secs>
   140001d8f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d92:	48 63 d0             	movsxd rdx,eax
   140001d95:	48 89 d0             	mov    rax,rdx
   140001d98:	48 c1 e0 02          	shl    rax,0x2
   140001d9c:	48 01 d0             	add    rax,rdx
   140001d9f:	48 c1 e0 03          	shl    rax,0x3
   140001da3:	48 01 c8             	add    rax,rcx
   140001da6:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001daa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001dae:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001db1:	89 c1                	mov    ecx,eax
   140001db3:	48 8d 05 56 94 00 00 	lea    rax,[rip+0x9456]        # 14000b210 <.rdata+0x40>
   140001dba:	49 89 d0             	mov    r8,rdx
   140001dbd:	89 ca                	mov    edx,ecx
   140001dbf:	48 89 c1             	mov    rcx,rax
   140001dc2:	e8 c9 fd ff ff       	call   140001b90 <__report_error>
   140001dc7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dca:	83 f8 40             	cmp    eax,0x40
   140001dcd:	0f 84 e8 00 00 00    	je     140001ebb <mark_section_writable+0x2c6>
   140001dd3:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dd6:	83 f8 04             	cmp    eax,0x4
   140001dd9:	0f 84 dc 00 00 00    	je     140001ebb <mark_section_writable+0x2c6>
   140001ddf:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001de2:	3d 80 00 00 00       	cmp    eax,0x80
   140001de7:	0f 84 ce 00 00 00    	je     140001ebb <mark_section_writable+0x2c6>
   140001ded:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001df0:	83 f8 08             	cmp    eax,0x8
   140001df3:	0f 84 c2 00 00 00    	je     140001ebb <mark_section_writable+0x2c6>
   140001df9:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dfc:	83 f8 02             	cmp    eax,0x2
   140001dff:	75 09                	jne    140001e0a <mark_section_writable+0x215>
   140001e01:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001e08:	eb 07                	jmp    140001e11 <mark_section_writable+0x21c>
   140001e0a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e11:	48 8b 0d c8 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2c8]        # 14000f0e0 <the_secs>
   140001e18:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e1b:	48 63 d0             	movsxd rdx,eax
   140001e1e:	48 89 d0             	mov    rax,rdx
   140001e21:	48 c1 e0 02          	shl    rax,0x2
   140001e25:	48 01 d0             	add    rax,rdx
   140001e28:	48 c1 e0 03          	shl    rax,0x3
   140001e2c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e30:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e34:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e38:	48 8b 0d a1 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2a1]        # 14000f0e0 <the_secs>
   140001e3f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e42:	48 63 d0             	movsxd rdx,eax
   140001e45:	48 89 d0             	mov    rax,rdx
   140001e48:	48 c1 e0 02          	shl    rax,0x2
   140001e4c:	48 01 d0             	add    rax,rdx
   140001e4f:	48 c1 e0 03          	shl    rax,0x3
   140001e53:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e57:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e5b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e5f:	48 8b 0d 7a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd27a]        # 14000f0e0 <the_secs>
   140001e66:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e69:	48 63 d0             	movsxd rdx,eax
   140001e6c:	48 89 d0             	mov    rax,rdx
   140001e6f:	48 c1 e0 02          	shl    rax,0x2
   140001e73:	48 01 d0             	add    rax,rdx
   140001e76:	48 c1 e0 03          	shl    rax,0x3
   140001e7a:	48 01 c8             	add    rax,rcx
   140001e7d:	49 89 c0             	mov    r8,rax
   140001e80:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e84:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e88:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e8b:	4d 89 c1             	mov    r9,r8
   140001e8e:	41 89 c8             	mov    r8d,ecx
   140001e91:	48 89 c1             	mov    rcx,rax
   140001e94:	48 8b 05 bd e3 00 00 	mov    rax,QWORD PTR [rip+0xe3bd]        # 140010258 <__imp_VirtualProtect>
   140001e9b:	ff d0                	call   rax
   140001e9d:	85 c0                	test   eax,eax
   140001e9f:	75 1a                	jne    140001ebb <mark_section_writable+0x2c6>
   140001ea1:	48 8b 05 60 e3 00 00 	mov    rax,QWORD PTR [rip+0xe360]        # 140010208 <__imp_GetLastError>
   140001ea8:	ff d0                	call   rax
   140001eaa:	89 c2                	mov    edx,eax
   140001eac:	48 8d 05 95 93 00 00 	lea    rax,[rip+0x9395]        # 14000b248 <.rdata+0x78>
   140001eb3:	48 89 c1             	mov    rcx,rax
   140001eb6:	e8 d5 fc ff ff       	call   140001b90 <__report_error>
   140001ebb:	8b 05 27 d2 00 00    	mov    eax,DWORD PTR [rip+0xd227]        # 14000f0e8 <maxSections>
   140001ec1:	83 c0 01             	add    eax,0x1
   140001ec4:	89 05 1e d2 00 00    	mov    DWORD PTR [rip+0xd21e],eax        # 14000f0e8 <maxSections>
   140001eca:	eb 01                	jmp    140001ecd <mark_section_writable+0x2d8>
   140001ecc:	90                   	nop
   140001ecd:	48 83 c4 60          	add    rsp,0x60
   140001ed1:	5d                   	pop    rbp
   140001ed2:	c3                   	ret

0000000140001ed3 <restore_modified_sections>:
   140001ed3:	55                   	push   rbp
   140001ed4:	48 89 e5             	mov    rbp,rsp
   140001ed7:	48 83 ec 30          	sub    rsp,0x30
   140001edb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001ee2:	e9 ad 00 00 00       	jmp    140001f94 <restore_modified_sections+0xc1>
   140001ee7:	48 8b 0d f2 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd1f2]        # 14000f0e0 <the_secs>
   140001eee:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ef1:	48 63 d0             	movsxd rdx,eax
   140001ef4:	48 89 d0             	mov    rax,rdx
   140001ef7:	48 c1 e0 02          	shl    rax,0x2
   140001efb:	48 01 d0             	add    rax,rdx
   140001efe:	48 c1 e0 03          	shl    rax,0x3
   140001f02:	48 01 c8             	add    rax,rcx
   140001f05:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f07:	85 c0                	test   eax,eax
   140001f09:	0f 84 80 00 00 00    	je     140001f8f <restore_modified_sections+0xbc>
   140001f0f:	48 8b 0d ca d1 00 00 	mov    rcx,QWORD PTR [rip+0xd1ca]        # 14000f0e0 <the_secs>
   140001f16:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f19:	48 63 d0             	movsxd rdx,eax
   140001f1c:	48 89 d0             	mov    rax,rdx
   140001f1f:	48 c1 e0 02          	shl    rax,0x2
   140001f23:	48 01 d0             	add    rax,rdx
   140001f26:	48 c1 e0 03          	shl    rax,0x3
   140001f2a:	48 01 c8             	add    rax,rcx
   140001f2d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f30:	48 8b 0d a9 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd1a9]        # 14000f0e0 <the_secs>
   140001f37:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f3a:	48 63 d0             	movsxd rdx,eax
   140001f3d:	48 89 d0             	mov    rax,rdx
   140001f40:	48 c1 e0 02          	shl    rax,0x2
   140001f44:	48 01 d0             	add    rax,rdx
   140001f47:	48 c1 e0 03          	shl    rax,0x3
   140001f4b:	48 01 c8             	add    rax,rcx
   140001f4e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f52:	4c 8b 05 87 d1 00 00 	mov    r8,QWORD PTR [rip+0xd187]        # 14000f0e0 <the_secs>
   140001f59:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f5c:	48 63 d0             	movsxd rdx,eax
   140001f5f:	48 89 d0             	mov    rax,rdx
   140001f62:	48 c1 e0 02          	shl    rax,0x2
   140001f66:	48 01 d0             	add    rax,rdx
   140001f69:	48 c1 e0 03          	shl    rax,0x3
   140001f6d:	4c 01 c0             	add    rax,r8
   140001f70:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f74:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f78:	49 89 d1             	mov    r9,rdx
   140001f7b:	45 89 d0             	mov    r8d,r10d
   140001f7e:	48 89 ca             	mov    rdx,rcx
   140001f81:	48 89 c1             	mov    rcx,rax
   140001f84:	48 8b 05 cd e2 00 00 	mov    rax,QWORD PTR [rip+0xe2cd]        # 140010258 <__imp_VirtualProtect>
   140001f8b:	ff d0                	call   rax
   140001f8d:	eb 01                	jmp    140001f90 <restore_modified_sections+0xbd>
   140001f8f:	90                   	nop
   140001f90:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f94:	8b 05 4e d1 00 00    	mov    eax,DWORD PTR [rip+0xd14e]        # 14000f0e8 <maxSections>
   140001f9a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f9d:	0f 8c 44 ff ff ff    	jl     140001ee7 <restore_modified_sections+0x14>
   140001fa3:	90                   	nop
   140001fa4:	90                   	nop
   140001fa5:	48 83 c4 30          	add    rsp,0x30
   140001fa9:	5d                   	pop    rbp
   140001faa:	c3                   	ret

0000000140001fab <__write_memory>:
   140001fab:	55                   	push   rbp
   140001fac:	48 89 e5             	mov    rbp,rsp
   140001faf:	48 83 ec 20          	sub    rsp,0x20
   140001fb3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fb7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001fbb:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001fbf:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001fc4:	74 25                	je     140001feb <__write_memory+0x40>
   140001fc6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fca:	48 89 c1             	mov    rcx,rax
   140001fcd:	e8 23 fc ff ff       	call   140001bf5 <mark_section_writable>
   140001fd2:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001fd6:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001fda:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fde:	49 89 c8             	mov    r8,rcx
   140001fe1:	48 89 c1             	mov    rcx,rax
   140001fe4:	e8 df 76 00 00       	call   1400096c8 <memcpy>
   140001fe9:	eb 01                	jmp    140001fec <__write_memory+0x41>
   140001feb:	90                   	nop
   140001fec:	48 83 c4 20          	add    rsp,0x20
   140001ff0:	5d                   	pop    rbp
   140001ff1:	c3                   	ret

0000000140001ff2 <do_pseudo_reloc>:
   140001ff2:	55                   	push   rbp
   140001ff3:	48 89 e5             	mov    rbp,rsp
   140001ff6:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001ffa:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001ffe:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002002:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002006:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000200a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000200e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002012:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002016:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000201a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000201f:	0f 8e 44 03 00 00    	jle    140002369 <do_pseudo_reloc+0x377>
   140002025:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000202a:	7e 25                	jle    140002051 <do_pseudo_reloc+0x5f>
   14000202c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002030:	8b 00                	mov    eax,DWORD PTR [rax]
   140002032:	85 c0                	test   eax,eax
   140002034:	75 1b                	jne    140002051 <do_pseudo_reloc+0x5f>
   140002036:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000203a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000203d:	85 c0                	test   eax,eax
   14000203f:	75 10                	jne    140002051 <do_pseudo_reloc+0x5f>
   140002041:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002045:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002048:	85 c0                	test   eax,eax
   14000204a:	75 05                	jne    140002051 <do_pseudo_reloc+0x5f>
   14000204c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002051:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002055:	8b 00                	mov    eax,DWORD PTR [rax]
   140002057:	85 c0                	test   eax,eax
   140002059:	75 0b                	jne    140002066 <do_pseudo_reloc+0x74>
   14000205b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000205f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002062:	85 c0                	test   eax,eax
   140002064:	74 59                	je     1400020bf <do_pseudo_reloc+0xcd>
   140002066:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000206a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000206e:	eb 40                	jmp    1400020b0 <do_pseudo_reloc+0xbe>
   140002070:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002074:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002077:	89 c2                	mov    edx,eax
   140002079:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000207d:	48 01 d0             	add    rax,rdx
   140002080:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002084:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002088:	8b 10                	mov    edx,DWORD PTR [rax]
   14000208a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000208e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002090:	01 d0                	add    eax,edx
   140002092:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002095:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002099:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000209d:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400020a3:	48 89 c1             	mov    rcx,rax
   1400020a6:	e8 00 ff ff ff       	call   140001fab <__write_memory>
   1400020ab:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   1400020b0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020b4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400020b8:	72 b6                	jb     140002070 <do_pseudo_reloc+0x7e>
   1400020ba:	e9 ab 02 00 00       	jmp    14000236a <do_pseudo_reloc+0x378>
   1400020bf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020c3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020c6:	83 f8 01             	cmp    eax,0x1
   1400020c9:	74 18                	je     1400020e3 <do_pseudo_reloc+0xf1>
   1400020cb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020cf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020d2:	89 c2                	mov    edx,eax
   1400020d4:	48 8d 05 95 91 00 00 	lea    rax,[rip+0x9195]        # 14000b270 <.rdata+0xa0>
   1400020db:	48 89 c1             	mov    rcx,rax
   1400020de:	e8 ad fa ff ff       	call   140001b90 <__report_error>
   1400020e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020e7:	48 83 c0 0c          	add    rax,0xc
   1400020eb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400020ef:	e9 65 02 00 00       	jmp    140002359 <do_pseudo_reloc+0x367>
   1400020f4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020f8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020fb:	89 c2                	mov    edx,eax
   1400020fd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002101:	48 01 d0             	add    rax,rdx
   140002104:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002108:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000210c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000210e:	89 c2                	mov    edx,eax
   140002110:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002114:	48 01 d0             	add    rax,rdx
   140002117:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000211b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000211f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002122:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002126:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000212a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000212d:	0f b6 c0             	movzx  eax,al
   140002130:	83 f8 40             	cmp    eax,0x40
   140002133:	0f 84 b6 00 00 00    	je     1400021ef <do_pseudo_reloc+0x1fd>
   140002139:	83 f8 40             	cmp    eax,0x40
   14000213c:	0f 87 ba 00 00 00    	ja     1400021fc <do_pseudo_reloc+0x20a>
   140002142:	83 f8 20             	cmp    eax,0x20
   140002145:	74 77                	je     1400021be <do_pseudo_reloc+0x1cc>
   140002147:	83 f8 20             	cmp    eax,0x20
   14000214a:	0f 87 ac 00 00 00    	ja     1400021fc <do_pseudo_reloc+0x20a>
   140002150:	83 f8 08             	cmp    eax,0x8
   140002153:	74 0a                	je     14000215f <do_pseudo_reloc+0x16d>
   140002155:	83 f8 10             	cmp    eax,0x10
   140002158:	74 38                	je     140002192 <do_pseudo_reloc+0x1a0>
   14000215a:	e9 9d 00 00 00       	jmp    1400021fc <do_pseudo_reloc+0x20a>
   14000215f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002163:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002166:	0f b6 c0             	movzx  eax,al
   140002169:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000216d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002171:	25 80 00 00 00       	and    eax,0x80
   140002176:	48 85 c0             	test   rax,rax
   140002179:	0f 84 9d 00 00 00    	je     14000221c <do_pseudo_reloc+0x22a>
   14000217f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002183:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002189:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000218d:	e9 8a 00 00 00       	jmp    14000221c <do_pseudo_reloc+0x22a>
   140002192:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002196:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002199:	0f b7 c0             	movzx  eax,ax
   14000219c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021a0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021a4:	25 00 80 00 00       	and    eax,0x8000
   1400021a9:	48 85 c0             	test   rax,rax
   1400021ac:	74 71                	je     14000221f <do_pseudo_reloc+0x22d>
   1400021ae:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021b2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400021b8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021bc:	eb 61                	jmp    14000221f <do_pseudo_reloc+0x22d>
   1400021be:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021c2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021c4:	89 c0                	mov    eax,eax
   1400021c6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ca:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021ce:	25 00 00 00 80       	and    eax,0x80000000
   1400021d3:	48 85 c0             	test   rax,rax
   1400021d6:	74 4a                	je     140002222 <do_pseudo_reloc+0x230>
   1400021d8:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021dc:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   1400021e3:	ff ff ff 
   1400021e6:	48 09 d0             	or     rax,rdx
   1400021e9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ed:	eb 33                	jmp    140002222 <do_pseudo_reloc+0x230>
   1400021ef:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021f3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400021f6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021fa:	eb 27                	jmp    140002223 <do_pseudo_reloc+0x231>
   1400021fc:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002203:	00 
   140002204:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002208:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000220b:	0f b6 c0             	movzx  eax,al
   14000220e:	48 8d 0d 93 90 00 00 	lea    rcx,[rip+0x9093]        # 14000b2a8 <.rdata+0xd8>
   140002215:	89 c2                	mov    edx,eax
   140002217:	e8 74 f9 ff ff       	call   140001b90 <__report_error>
   14000221c:	90                   	nop
   14000221d:	eb 04                	jmp    140002223 <do_pseudo_reloc+0x231>
   14000221f:	90                   	nop
   140002220:	eb 01                	jmp    140002223 <do_pseudo_reloc+0x231>
   140002222:	90                   	nop
   140002223:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002227:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000222b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000222d:	89 c2                	mov    edx,eax
   14000222f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002233:	48 01 c2             	add    rdx,rax
   140002236:	48 89 c8             	mov    rax,rcx
   140002239:	48 29 d0             	sub    rax,rdx
   14000223c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002240:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002244:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002248:	48 01 d0             	add    rax,rdx
   14000224b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000224f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002253:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002256:	25 ff 00 00 00       	and    eax,0xff
   14000225b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000225e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002262:	77 67                	ja     1400022cb <do_pseudo_reloc+0x2d9>
   140002264:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002267:	ba 01 00 00 00       	mov    edx,0x1
   14000226c:	89 c1                	mov    ecx,eax
   14000226e:	48 d3 e2             	shl    rdx,cl
   140002271:	48 89 d0             	mov    rax,rdx
   140002274:	48 83 e8 01          	sub    rax,0x1
   140002278:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000227c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000227f:	83 e8 01             	sub    eax,0x1
   140002282:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002289:	89 c1                	mov    ecx,eax
   14000228b:	48 d3 e2             	shl    rdx,cl
   14000228e:	48 89 d0             	mov    rax,rdx
   140002291:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002295:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002299:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000229d:	7c 0a                	jl     1400022a9 <do_pseudo_reloc+0x2b7>
   14000229f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022a3:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400022a7:	7e 22                	jle    1400022cb <do_pseudo_reloc+0x2d9>
   1400022a9:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400022ad:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400022b1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400022b5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022b8:	48 8d 0d 19 90 00 00 	lea    rcx,[rip+0x9019]        # 14000b2d8 <.rdata+0x108>
   1400022bf:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400022c4:	89 c2                	mov    edx,eax
   1400022c6:	e8 c5 f8 ff ff       	call   140001b90 <__report_error>
   1400022cb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022cf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022d2:	0f b6 c0             	movzx  eax,al
   1400022d5:	83 f8 40             	cmp    eax,0x40
   1400022d8:	74 63                	je     14000233d <do_pseudo_reloc+0x34b>
   1400022da:	83 f8 40             	cmp    eax,0x40
   1400022dd:	77 75                	ja     140002354 <do_pseudo_reloc+0x362>
   1400022df:	83 f8 20             	cmp    eax,0x20
   1400022e2:	74 41                	je     140002325 <do_pseudo_reloc+0x333>
   1400022e4:	83 f8 20             	cmp    eax,0x20
   1400022e7:	77 6b                	ja     140002354 <do_pseudo_reloc+0x362>
   1400022e9:	83 f8 08             	cmp    eax,0x8
   1400022ec:	74 07                	je     1400022f5 <do_pseudo_reloc+0x303>
   1400022ee:	83 f8 10             	cmp    eax,0x10
   1400022f1:	74 1a                	je     14000230d <do_pseudo_reloc+0x31b>
   1400022f3:	eb 5f                	jmp    140002354 <do_pseudo_reloc+0x362>
   1400022f5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022f9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022fd:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002303:	48 89 c1             	mov    rcx,rax
   140002306:	e8 a0 fc ff ff       	call   140001fab <__write_memory>
   14000230b:	eb 47                	jmp    140002354 <do_pseudo_reloc+0x362>
   14000230d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002311:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002315:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000231b:	48 89 c1             	mov    rcx,rax
   14000231e:	e8 88 fc ff ff       	call   140001fab <__write_memory>
   140002323:	eb 2f                	jmp    140002354 <do_pseudo_reloc+0x362>
   140002325:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002329:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000232d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002333:	48 89 c1             	mov    rcx,rax
   140002336:	e8 70 fc ff ff       	call   140001fab <__write_memory>
   14000233b:	eb 17                	jmp    140002354 <do_pseudo_reloc+0x362>
   14000233d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002341:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002345:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000234b:	48 89 c1             	mov    rcx,rax
   14000234e:	e8 58 fc ff ff       	call   140001fab <__write_memory>
   140002353:	90                   	nop
   140002354:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002359:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000235d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002361:	0f 82 8d fd ff ff    	jb     1400020f4 <do_pseudo_reloc+0x102>
   140002367:	eb 01                	jmp    14000236a <do_pseudo_reloc+0x378>
   140002369:	90                   	nop
   14000236a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000236e:	5d                   	pop    rbp
   14000236f:	c3                   	ret

0000000140002370 <_pei386_runtime_relocator>:
   140002370:	55                   	push   rbp
   140002371:	48 89 e5             	mov    rbp,rsp
   140002374:	48 83 ec 30          	sub    rsp,0x30
   140002378:	8b 05 6e cd 00 00    	mov    eax,DWORD PTR [rip+0xcd6e]        # 14000f0ec <was_init.0>
   14000237e:	85 c0                	test   eax,eax
   140002380:	0f 85 88 00 00 00    	jne    14000240e <_pei386_runtime_relocator+0x9e>
   140002386:	8b 05 60 cd 00 00    	mov    eax,DWORD PTR [rip+0xcd60]        # 14000f0ec <was_init.0>
   14000238c:	83 c0 01             	add    eax,0x1
   14000238f:	89 05 57 cd 00 00    	mov    DWORD PTR [rip+0xcd57],eax        # 14000f0ec <was_init.0>
   140002395:	e8 21 0b 00 00       	call   140002ebb <__mingw_GetSectionCount>
   14000239a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000239d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400023a0:	48 63 d0             	movsxd rdx,eax
   1400023a3:	48 89 d0             	mov    rax,rdx
   1400023a6:	48 c1 e0 02          	shl    rax,0x2
   1400023aa:	48 01 d0             	add    rax,rdx
   1400023ad:	48 c1 e0 03          	shl    rax,0x3
   1400023b1:	48 83 c0 0f          	add    rax,0xf
   1400023b5:	48 c1 e8 04          	shr    rax,0x4
   1400023b9:	48 c1 e0 04          	shl    rax,0x4
   1400023bd:	e8 7e 0d 00 00       	call   140003140 <___chkstk_ms>
   1400023c2:	48 29 c4             	sub    rsp,rax
   1400023c5:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400023ca:	48 83 c0 0f          	add    rax,0xf
   1400023ce:	48 c1 e8 04          	shr    rax,0x4
   1400023d2:	48 c1 e0 04          	shl    rax,0x4
   1400023d6:	48 89 05 03 cd 00 00 	mov    QWORD PTR [rip+0xcd03],rax        # 14000f0e0 <the_secs>
   1400023dd:	c7 05 01 cd 00 00 00 	mov    DWORD PTR [rip+0xcd01],0x0        # 14000f0e8 <maxSections>
   1400023e4:	00 00 00 
   1400023e7:	48 8b 0d 92 91 00 00 	mov    rcx,QWORD PTR [rip+0x9192]        # 14000b580 <.refptr.__ImageBase>
   1400023ee:	48 8b 15 9b 91 00 00 	mov    rdx,QWORD PTR [rip+0x919b]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   1400023f5:	48 8b 05 a4 91 00 00 	mov    rax,QWORD PTR [rip+0x91a4]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   1400023fc:	49 89 c8             	mov    r8,rcx
   1400023ff:	48 89 c1             	mov    rcx,rax
   140002402:	e8 eb fb ff ff       	call   140001ff2 <do_pseudo_reloc>
   140002407:	e8 c7 fa ff ff       	call   140001ed3 <restore_modified_sections>
   14000240c:	eb 01                	jmp    14000240f <_pei386_runtime_relocator+0x9f>
   14000240e:	90                   	nop
   14000240f:	48 89 ec             	mov    rsp,rbp
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

0000000140002420 <__mingw_raise_matherr>:
   140002420:	55                   	push   rbp
   140002421:	48 89 e5             	mov    rbp,rsp
   140002424:	48 83 ec 50          	sub    rsp,0x50
   140002428:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000242b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000242f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002434:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002439:	48 8b 05 b0 cc 00 00 	mov    rax,QWORD PTR [rip+0xccb0]        # 14000f0f0 <stUserMathErr>
   140002440:	48 85 c0             	test   rax,rax
   140002443:	74 3e                	je     140002483 <__mingw_raise_matherr+0x63>
   140002445:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002448:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000244b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000244f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002453:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002458:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000245d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002462:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002467:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000246c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002471:	48 8b 15 78 cc 00 00 	mov    rdx,QWORD PTR [rip+0xcc78]        # 14000f0f0 <stUserMathErr>
   140002478:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000247c:	48 89 c1             	mov    rcx,rax
   14000247f:	ff d2                	call   rdx
   140002481:	eb 01                	jmp    140002484 <__mingw_raise_matherr+0x64>
   140002483:	90                   	nop
   140002484:	48 83 c4 50          	add    rsp,0x50
   140002488:	5d                   	pop    rbp
   140002489:	c3                   	ret

000000014000248a <__mingw_setusermatherr>:
   14000248a:	55                   	push   rbp
   14000248b:	48 89 e5             	mov    rbp,rsp
   14000248e:	48 83 ec 20          	sub    rsp,0x20
   140002492:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002496:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000249a:	48 89 05 4f cc 00 00 	mov    QWORD PTR [rip+0xcc4f],rax        # 14000f0f0 <stUserMathErr>
   1400024a1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024a5:	48 89 c1             	mov    rcx,rax
   1400024a8:	e8 93 71 00 00       	call   140009640 <__setusermatherr>
   1400024ad:	90                   	nop
   1400024ae:	48 83 c4 20          	add    rsp,0x20
   1400024b2:	5d                   	pop    rbp
   1400024b3:	c3                   	ret
   1400024b4:	90                   	nop
   1400024b5:	90                   	nop
   1400024b6:	90                   	nop
   1400024b7:	90                   	nop
   1400024b8:	90                   	nop
   1400024b9:	90                   	nop
   1400024ba:	90                   	nop
   1400024bb:	90                   	nop
   1400024bc:	90                   	nop
   1400024bd:	90                   	nop
   1400024be:	90                   	nop
   1400024bf:	90                   	nop

00000001400024c0 <__mingw_SEH_error_handler>:
   1400024c0:	55                   	push   rbp
   1400024c1:	48 89 e5             	mov    rbp,rsp
   1400024c4:	48 83 ec 30          	sub    rsp,0x30
   1400024c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024cc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400024d0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400024d4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400024d8:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400024df:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400024e6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024ea:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024ed:	83 e0 02             	and    eax,0x2
   1400024f0:	85 c0                	test   eax,eax
   1400024f2:	74 0a                	je     1400024fe <__mingw_SEH_error_handler+0x3e>
   1400024f4:	b8 01 00 00 00       	mov    eax,0x1
   1400024f9:	e9 16 02 00 00       	jmp    140002714 <__mingw_SEH_error_handler+0x254>
   1400024fe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002502:	8b 00                	mov    eax,DWORD PTR [rax]
   140002504:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002509:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000250e:	75 18                	jne    140002528 <__mingw_SEH_error_handler+0x68>
   140002510:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002514:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002517:	83 e0 01             	and    eax,0x1
   14000251a:	85 c0                	test   eax,eax
   14000251c:	75 0a                	jne    140002528 <__mingw_SEH_error_handler+0x68>
   14000251e:	b8 00 00 00 00       	mov    eax,0x0
   140002523:	e9 ec 01 00 00       	jmp    140002714 <__mingw_SEH_error_handler+0x254>
   140002528:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000252c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000252e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002533:	0f 84 12 01 00 00    	je     14000264b <__mingw_SEH_error_handler+0x18b>
   140002539:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000253e:	0f 87 c3 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   140002544:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002549:	0f 87 b8 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   14000254f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002554:	0f 83 4c 01 00 00    	jae    1400026a6 <__mingw_SEH_error_handler+0x1e6>
   14000255a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000255f:	0f 84 3a 01 00 00    	je     14000269f <__mingw_SEH_error_handler+0x1df>
   140002565:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000256a:	0f 87 97 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   140002570:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002575:	0f 84 83 01 00 00    	je     1400026fe <__mingw_SEH_error_handler+0x23e>
   14000257b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002580:	0f 87 81 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   140002586:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000258b:	0f 87 76 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   140002591:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002596:	0f 83 03 01 00 00    	jae    14000269f <__mingw_SEH_error_handler+0x1df>
   14000259c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025a1:	0f 84 57 01 00 00    	je     1400026fe <__mingw_SEH_error_handler+0x23e>
   1400025a7:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025ac:	0f 87 55 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   1400025b2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025b7:	0f 84 8e 00 00 00    	je     14000264b <__mingw_SEH_error_handler+0x18b>
   1400025bd:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025c2:	0f 87 3f 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   1400025c8:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025cd:	0f 84 2b 01 00 00    	je     1400026fe <__mingw_SEH_error_handler+0x23e>
   1400025d3:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025d8:	0f 87 29 01 00 00    	ja     140002707 <__mingw_SEH_error_handler+0x247>
   1400025de:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400025e3:	0f 84 15 01 00 00    	je     1400026fe <__mingw_SEH_error_handler+0x23e>
   1400025e9:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400025ee:	0f 85 13 01 00 00    	jne    140002707 <__mingw_SEH_error_handler+0x247>
   1400025f4:	ba 00 00 00 00       	mov    edx,0x0
   1400025f9:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025fe:	e8 d5 70 00 00       	call   1400096d8 <signal>
   140002603:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002607:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000260c:	75 1b                	jne    140002629 <__mingw_SEH_error_handler+0x169>
   14000260e:	ba 01 00 00 00       	mov    edx,0x1
   140002613:	b9 0b 00 00 00       	mov    ecx,0xb
   140002618:	e8 bb 70 00 00       	call   1400096d8 <signal>
   14000261d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002624:	e9 e1 00 00 00       	jmp    14000270a <__mingw_SEH_error_handler+0x24a>
   140002629:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000262e:	0f 84 d6 00 00 00    	je     14000270a <__mingw_SEH_error_handler+0x24a>
   140002634:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002638:	b9 0b 00 00 00       	mov    ecx,0xb
   14000263d:	ff d0                	call   rax
   14000263f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002646:	e9 bf 00 00 00       	jmp    14000270a <__mingw_SEH_error_handler+0x24a>
   14000264b:	ba 00 00 00 00       	mov    edx,0x0
   140002650:	b9 04 00 00 00       	mov    ecx,0x4
   140002655:	e8 7e 70 00 00       	call   1400096d8 <signal>
   14000265a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000265e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002663:	75 1b                	jne    140002680 <__mingw_SEH_error_handler+0x1c0>
   140002665:	ba 01 00 00 00       	mov    edx,0x1
   14000266a:	b9 04 00 00 00       	mov    ecx,0x4
   14000266f:	e8 64 70 00 00       	call   1400096d8 <signal>
   140002674:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000267b:	e9 8d 00 00 00       	jmp    14000270d <__mingw_SEH_error_handler+0x24d>
   140002680:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002685:	0f 84 82 00 00 00    	je     14000270d <__mingw_SEH_error_handler+0x24d>
   14000268b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000268f:	b9 04 00 00 00       	mov    ecx,0x4
   140002694:	ff d0                	call   rax
   140002696:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000269d:	eb 6e                	jmp    14000270d <__mingw_SEH_error_handler+0x24d>
   14000269f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400026a6:	ba 00 00 00 00       	mov    edx,0x0
   1400026ab:	b9 08 00 00 00       	mov    ecx,0x8
   1400026b0:	e8 23 70 00 00       	call   1400096d8 <signal>
   1400026b5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026b9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026be:	75 23                	jne    1400026e3 <__mingw_SEH_error_handler+0x223>
   1400026c0:	ba 01 00 00 00       	mov    edx,0x1
   1400026c5:	b9 08 00 00 00       	mov    ecx,0x8
   1400026ca:	e8 09 70 00 00       	call   1400096d8 <signal>
   1400026cf:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400026d3:	74 05                	je     1400026da <__mingw_SEH_error_handler+0x21a>
   1400026d5:	e8 a6 05 00 00       	call   140002c80 <_fpreset>
   1400026da:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026e1:	eb 2d                	jmp    140002710 <__mingw_SEH_error_handler+0x250>
   1400026e3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026e8:	74 26                	je     140002710 <__mingw_SEH_error_handler+0x250>
   1400026ea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026ee:	b9 08 00 00 00       	mov    ecx,0x8
   1400026f3:	ff d0                	call   rax
   1400026f5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026fc:	eb 12                	jmp    140002710 <__mingw_SEH_error_handler+0x250>
   1400026fe:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002705:	eb 0a                	jmp    140002711 <__mingw_SEH_error_handler+0x251>
   140002707:	90                   	nop
   140002708:	eb 07                	jmp    140002711 <__mingw_SEH_error_handler+0x251>
   14000270a:	90                   	nop
   14000270b:	eb 04                	jmp    140002711 <__mingw_SEH_error_handler+0x251>
   14000270d:	90                   	nop
   14000270e:	eb 01                	jmp    140002711 <__mingw_SEH_error_handler+0x251>
   140002710:	90                   	nop
   140002711:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002714:	48 83 c4 30          	add    rsp,0x30
   140002718:	5d                   	pop    rbp
   140002719:	c3                   	ret

000000014000271a <_gnu_exception_handler>:
   14000271a:	55                   	push   rbp
   14000271b:	48 89 e5             	mov    rbp,rsp
   14000271e:	48 83 ec 30          	sub    rsp,0x30
   140002722:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002726:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000272d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002734:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002738:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000273b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000273d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002742:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002747:	75 1b                	jne    140002764 <_gnu_exception_handler+0x4a>
   140002749:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000274d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002750:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002753:	83 e0 01             	and    eax,0x1
   140002756:	85 c0                	test   eax,eax
   140002758:	75 0a                	jne    140002764 <_gnu_exception_handler+0x4a>
   14000275a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000275f:	e9 14 02 00 00       	jmp    140002978 <_gnu_exception_handler+0x25e>
   140002764:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002768:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000276b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000276d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002772:	0f 84 12 01 00 00    	je     14000288a <_gnu_exception_handler+0x170>
   140002778:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000277d:	0f 87 c3 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   140002783:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002788:	0f 87 b8 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   14000278e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002793:	0f 83 4c 01 00 00    	jae    1400028e5 <_gnu_exception_handler+0x1cb>
   140002799:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000279e:	0f 84 3a 01 00 00    	je     1400028de <_gnu_exception_handler+0x1c4>
   1400027a4:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027a9:	0f 87 97 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   1400027af:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027b4:	0f 84 83 01 00 00    	je     14000293d <_gnu_exception_handler+0x223>
   1400027ba:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027bf:	0f 87 81 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   1400027c5:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400027ca:	0f 87 76 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   1400027d0:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400027d5:	0f 83 03 01 00 00    	jae    1400028de <_gnu_exception_handler+0x1c4>
   1400027db:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027e0:	0f 84 57 01 00 00    	je     14000293d <_gnu_exception_handler+0x223>
   1400027e6:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027eb:	0f 87 55 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   1400027f1:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027f6:	0f 84 8e 00 00 00    	je     14000288a <_gnu_exception_handler+0x170>
   1400027fc:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002801:	0f 87 3f 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   140002807:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000280c:	0f 84 2b 01 00 00    	je     14000293d <_gnu_exception_handler+0x223>
   140002812:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002817:	0f 87 29 01 00 00    	ja     140002946 <_gnu_exception_handler+0x22c>
   14000281d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002822:	0f 84 15 01 00 00    	je     14000293d <_gnu_exception_handler+0x223>
   140002828:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000282d:	0f 85 13 01 00 00    	jne    140002946 <_gnu_exception_handler+0x22c>
   140002833:	ba 00 00 00 00       	mov    edx,0x0
   140002838:	b9 0b 00 00 00       	mov    ecx,0xb
   14000283d:	e8 96 6e 00 00       	call   1400096d8 <signal>
   140002842:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002846:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000284b:	75 1b                	jne    140002868 <_gnu_exception_handler+0x14e>
   14000284d:	ba 01 00 00 00       	mov    edx,0x1
   140002852:	b9 0b 00 00 00       	mov    ecx,0xb
   140002857:	e8 7c 6e 00 00       	call   1400096d8 <signal>
   14000285c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002863:	e9 e1 00 00 00       	jmp    140002949 <_gnu_exception_handler+0x22f>
   140002868:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000286d:	0f 84 d6 00 00 00    	je     140002949 <_gnu_exception_handler+0x22f>
   140002873:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002877:	b9 0b 00 00 00       	mov    ecx,0xb
   14000287c:	ff d0                	call   rax
   14000287e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002885:	e9 bf 00 00 00       	jmp    140002949 <_gnu_exception_handler+0x22f>
   14000288a:	ba 00 00 00 00       	mov    edx,0x0
   14000288f:	b9 04 00 00 00       	mov    ecx,0x4
   140002894:	e8 3f 6e 00 00       	call   1400096d8 <signal>
   140002899:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000289d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028a2:	75 1b                	jne    1400028bf <_gnu_exception_handler+0x1a5>
   1400028a4:	ba 01 00 00 00       	mov    edx,0x1
   1400028a9:	b9 04 00 00 00       	mov    ecx,0x4
   1400028ae:	e8 25 6e 00 00       	call   1400096d8 <signal>
   1400028b3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028ba:	e9 8d 00 00 00       	jmp    14000294c <_gnu_exception_handler+0x232>
   1400028bf:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028c4:	0f 84 82 00 00 00    	je     14000294c <_gnu_exception_handler+0x232>
   1400028ca:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028ce:	b9 04 00 00 00       	mov    ecx,0x4
   1400028d3:	ff d0                	call   rax
   1400028d5:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028dc:	eb 6e                	jmp    14000294c <_gnu_exception_handler+0x232>
   1400028de:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400028e5:	ba 00 00 00 00       	mov    edx,0x0
   1400028ea:	b9 08 00 00 00       	mov    ecx,0x8
   1400028ef:	e8 e4 6d 00 00       	call   1400096d8 <signal>
   1400028f4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028f8:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028fd:	75 23                	jne    140002922 <_gnu_exception_handler+0x208>
   1400028ff:	ba 01 00 00 00       	mov    edx,0x1
   140002904:	b9 08 00 00 00       	mov    ecx,0x8
   140002909:	e8 ca 6d 00 00       	call   1400096d8 <signal>
   14000290e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002912:	74 05                	je     140002919 <_gnu_exception_handler+0x1ff>
   140002914:	e8 67 03 00 00       	call   140002c80 <_fpreset>
   140002919:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002920:	eb 2d                	jmp    14000294f <_gnu_exception_handler+0x235>
   140002922:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002927:	74 26                	je     14000294f <_gnu_exception_handler+0x235>
   140002929:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000292d:	b9 08 00 00 00       	mov    ecx,0x8
   140002932:	ff d0                	call   rax
   140002934:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000293b:	eb 12                	jmp    14000294f <_gnu_exception_handler+0x235>
   14000293d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002944:	eb 0a                	jmp    140002950 <_gnu_exception_handler+0x236>
   140002946:	90                   	nop
   140002947:	eb 07                	jmp    140002950 <_gnu_exception_handler+0x236>
   140002949:	90                   	nop
   14000294a:	eb 04                	jmp    140002950 <_gnu_exception_handler+0x236>
   14000294c:	90                   	nop
   14000294d:	eb 01                	jmp    140002950 <_gnu_exception_handler+0x236>
   14000294f:	90                   	nop
   140002950:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002954:	75 1f                	jne    140002975 <_gnu_exception_handler+0x25b>
   140002956:	48 8b 05 b3 c7 00 00 	mov    rax,QWORD PTR [rip+0xc7b3]        # 14000f110 <__mingw_oldexcpt_handler>
   14000295d:	48 85 c0             	test   rax,rax
   140002960:	74 13                	je     140002975 <_gnu_exception_handler+0x25b>
   140002962:	48 8b 15 a7 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc7a7]        # 14000f110 <__mingw_oldexcpt_handler>
   140002969:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000296d:	48 89 c1             	mov    rcx,rax
   140002970:	ff d2                	call   rdx
   140002972:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002975:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002978:	48 83 c4 30          	add    rsp,0x30
   14000297c:	5d                   	pop    rbp
   14000297d:	c3                   	ret
   14000297e:	90                   	nop
   14000297f:	90                   	nop

0000000140002980 <___w64_mingwthr_add_key_dtor>:
   140002980:	55                   	push   rbp
   140002981:	48 89 e5             	mov    rbp,rsp
   140002984:	48 83 ec 30          	sub    rsp,0x30
   140002988:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000298b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000298f:	8b 05 b3 c7 00 00    	mov    eax,DWORD PTR [rip+0xc7b3]        # 14000f148 <__mingwthr_cs_init>
   140002995:	85 c0                	test   eax,eax
   140002997:	75 07                	jne    1400029a0 <___w64_mingwthr_add_key_dtor+0x20>
   140002999:	b8 00 00 00 00       	mov    eax,0x0
   14000299e:	eb 7b                	jmp    140002a1b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029a0:	ba 18 00 00 00       	mov    edx,0x18
   1400029a5:	b9 01 00 00 00       	mov    ecx,0x1
   1400029aa:	e8 d9 6c 00 00       	call   140009688 <calloc>
   1400029af:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400029b3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029b8:	75 07                	jne    1400029c1 <___w64_mingwthr_add_key_dtor+0x41>
   1400029ba:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400029bf:	eb 5a                	jmp    140002a1b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029c1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029c5:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400029c8:	89 10                	mov    DWORD PTR [rax],edx
   1400029ca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029ce:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400029d2:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   1400029d6:	48 8d 05 43 c7 00 00 	lea    rax,[rip+0xc743]        # 14000f120 <__mingwthr_cs>
   1400029dd:	48 89 c1             	mov    rcx,rax
   1400029e0:	48 8b 05 09 d8 00 00 	mov    rax,QWORD PTR [rip+0xd809]        # 1400101f0 <__imp_EnterCriticalSection>
   1400029e7:	ff d0                	call   rax
   1400029e9:	48 8b 15 60 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc760]        # 14000f150 <key_dtor_list>
   1400029f0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029f4:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029fc:	48 89 05 4d c7 00 00 	mov    QWORD PTR [rip+0xc74d],rax        # 14000f150 <key_dtor_list>
   140002a03:	48 8d 05 16 c7 00 00 	lea    rax,[rip+0xc716]        # 14000f120 <__mingwthr_cs>
   140002a0a:	48 89 c1             	mov    rcx,rax
   140002a0d:	48 8b 05 14 d8 00 00 	mov    rax,QWORD PTR [rip+0xd814]        # 140010228 <__imp_LeaveCriticalSection>
   140002a14:	ff d0                	call   rax
   140002a16:	b8 00 00 00 00       	mov    eax,0x0
   140002a1b:	48 83 c4 30          	add    rsp,0x30
   140002a1f:	5d                   	pop    rbp
   140002a20:	c3                   	ret

0000000140002a21 <___w64_mingwthr_remove_key_dtor>:
   140002a21:	55                   	push   rbp
   140002a22:	48 89 e5             	mov    rbp,rsp
   140002a25:	48 83 ec 30          	sub    rsp,0x30
   140002a29:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a2c:	8b 05 16 c7 00 00    	mov    eax,DWORD PTR [rip+0xc716]        # 14000f148 <__mingwthr_cs_init>
   140002a32:	85 c0                	test   eax,eax
   140002a34:	75 0a                	jne    140002a40 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a36:	b8 00 00 00 00       	mov    eax,0x0
   140002a3b:	e9 9c 00 00 00       	jmp    140002adc <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a40:	48 8d 05 d9 c6 00 00 	lea    rax,[rip+0xc6d9]        # 14000f120 <__mingwthr_cs>
   140002a47:	48 89 c1             	mov    rcx,rax
   140002a4a:	48 8b 05 9f d7 00 00 	mov    rax,QWORD PTR [rip+0xd79f]        # 1400101f0 <__imp_EnterCriticalSection>
   140002a51:	ff d0                	call   rax
   140002a53:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a5a:	00 
   140002a5b:	48 8b 05 ee c6 00 00 	mov    rax,QWORD PTR [rip+0xc6ee]        # 14000f150 <key_dtor_list>
   140002a62:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a66:	eb 55                	jmp    140002abd <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a68:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a6c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a6e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a71:	75 36                	jne    140002aa9 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a73:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a78:	75 11                	jne    140002a8b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a7a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a7e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a82:	48 89 05 c7 c6 00 00 	mov    QWORD PTR [rip+0xc6c7],rax        # 14000f150 <key_dtor_list>
   140002a89:	eb 10                	jmp    140002a9b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a8b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a8f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a93:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a97:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a9b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a9f:	48 89 c1             	mov    rcx,rax
   140002aa2:	e8 09 6c 00 00       	call   1400096b0 <free>
   140002aa7:	eb 1b                	jmp    140002ac4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002aa9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aad:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ab1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ab5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ab9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002abd:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002ac2:	75 a4                	jne    140002a68 <___w64_mingwthr_remove_key_dtor+0x47>
   140002ac4:	48 8d 05 55 c6 00 00 	lea    rax,[rip+0xc655]        # 14000f120 <__mingwthr_cs>
   140002acb:	48 89 c1             	mov    rcx,rax
   140002ace:	48 8b 05 53 d7 00 00 	mov    rax,QWORD PTR [rip+0xd753]        # 140010228 <__imp_LeaveCriticalSection>
   140002ad5:	ff d0                	call   rax
   140002ad7:	b8 00 00 00 00       	mov    eax,0x0
   140002adc:	48 83 c4 30          	add    rsp,0x30
   140002ae0:	5d                   	pop    rbp
   140002ae1:	c3                   	ret

0000000140002ae2 <__mingwthr_run_key_dtors>:
   140002ae2:	55                   	push   rbp
   140002ae3:	48 89 e5             	mov    rbp,rsp
   140002ae6:	48 83 ec 30          	sub    rsp,0x30
   140002aea:	8b 05 58 c6 00 00    	mov    eax,DWORD PTR [rip+0xc658]        # 14000f148 <__mingwthr_cs_init>
   140002af0:	85 c0                	test   eax,eax
   140002af2:	0f 84 82 00 00 00    	je     140002b7a <__mingwthr_run_key_dtors+0x98>
   140002af8:	48 8d 05 21 c6 00 00 	lea    rax,[rip+0xc621]        # 14000f120 <__mingwthr_cs>
   140002aff:	48 89 c1             	mov    rcx,rax
   140002b02:	48 8b 05 e7 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6e7]        # 1400101f0 <__imp_EnterCriticalSection>
   140002b09:	ff d0                	call   rax
   140002b0b:	48 8b 05 3e c6 00 00 	mov    rax,QWORD PTR [rip+0xc63e]        # 14000f150 <key_dtor_list>
   140002b12:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b16:	eb 46                	jmp    140002b5e <__mingwthr_run_key_dtors+0x7c>
   140002b18:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b1c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b1e:	89 c1                	mov    ecx,eax
   140002b20:	48 8b 05 29 d7 00 00 	mov    rax,QWORD PTR [rip+0xd729]        # 140010250 <__imp_TlsGetValue>
   140002b27:	ff d0                	call   rax
   140002b29:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b2d:	48 8b 05 d4 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6d4]        # 140010208 <__imp_GetLastError>
   140002b34:	ff d0                	call   rax
   140002b36:	85 c0                	test   eax,eax
   140002b38:	75 18                	jne    140002b52 <__mingwthr_run_key_dtors+0x70>
   140002b3a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b3f:	74 11                	je     140002b52 <__mingwthr_run_key_dtors+0x70>
   140002b41:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b45:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002b49:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b4d:	48 89 c1             	mov    rcx,rax
   140002b50:	ff d2                	call   rdx
   140002b52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b56:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b5a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b5e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b63:	75 b3                	jne    140002b18 <__mingwthr_run_key_dtors+0x36>
   140002b65:	48 8d 05 b4 c5 00 00 	lea    rax,[rip+0xc5b4]        # 14000f120 <__mingwthr_cs>
   140002b6c:	48 89 c1             	mov    rcx,rax
   140002b6f:	48 8b 05 b2 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6b2]        # 140010228 <__imp_LeaveCriticalSection>
   140002b76:	ff d0                	call   rax
   140002b78:	eb 01                	jmp    140002b7b <__mingwthr_run_key_dtors+0x99>
   140002b7a:	90                   	nop
   140002b7b:	48 83 c4 30          	add    rsp,0x30
   140002b7f:	5d                   	pop    rbp
   140002b80:	c3                   	ret

0000000140002b81 <__mingw_TLScallback>:
   140002b81:	55                   	push   rbp
   140002b82:	48 89 e5             	mov    rbp,rsp
   140002b85:	48 83 ec 30          	sub    rsp,0x30
   140002b89:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b8d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b90:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b94:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b98:	0f 84 cc 00 00 00    	je     140002c6a <__mingw_TLScallback+0xe9>
   140002b9e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002ba2:	0f 87 ca 00 00 00    	ja     140002c72 <__mingw_TLScallback+0xf1>
   140002ba8:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bac:	0f 84 b1 00 00 00    	je     140002c63 <__mingw_TLScallback+0xe2>
   140002bb2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bb6:	0f 87 b6 00 00 00    	ja     140002c72 <__mingw_TLScallback+0xf1>
   140002bbc:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002bc0:	74 33                	je     140002bf5 <__mingw_TLScallback+0x74>
   140002bc2:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002bc6:	0f 85 a6 00 00 00    	jne    140002c72 <__mingw_TLScallback+0xf1>
   140002bcc:	8b 05 76 c5 00 00    	mov    eax,DWORD PTR [rip+0xc576]        # 14000f148 <__mingwthr_cs_init>
   140002bd2:	85 c0                	test   eax,eax
   140002bd4:	75 13                	jne    140002be9 <__mingw_TLScallback+0x68>
   140002bd6:	48 8d 05 43 c5 00 00 	lea    rax,[rip+0xc543]        # 14000f120 <__mingwthr_cs>
   140002bdd:	48 89 c1             	mov    rcx,rax
   140002be0:	48 8b 05 39 d6 00 00 	mov    rax,QWORD PTR [rip+0xd639]        # 140010220 <__imp_InitializeCriticalSection>
   140002be7:	ff d0                	call   rax
   140002be9:	c7 05 55 c5 00 00 01 	mov    DWORD PTR [rip+0xc555],0x1        # 14000f148 <__mingwthr_cs_init>
   140002bf0:	00 00 00 
   140002bf3:	eb 7d                	jmp    140002c72 <__mingw_TLScallback+0xf1>
   140002bf5:	e8 e8 fe ff ff       	call   140002ae2 <__mingwthr_run_key_dtors>
   140002bfa:	8b 05 48 c5 00 00    	mov    eax,DWORD PTR [rip+0xc548]        # 14000f148 <__mingwthr_cs_init>
   140002c00:	83 f8 01             	cmp    eax,0x1
   140002c03:	75 6c                	jne    140002c71 <__mingw_TLScallback+0xf0>
   140002c05:	48 8b 05 44 c5 00 00 	mov    rax,QWORD PTR [rip+0xc544]        # 14000f150 <key_dtor_list>
   140002c0c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c10:	eb 20                	jmp    140002c32 <__mingw_TLScallback+0xb1>
   140002c12:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c16:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c1a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c1e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c22:	48 89 c1             	mov    rcx,rax
   140002c25:	e8 86 6a 00 00       	call   1400096b0 <free>
   140002c2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c2e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c32:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c37:	75 d9                	jne    140002c12 <__mingw_TLScallback+0x91>
   140002c39:	48 c7 05 0c c5 00 00 	mov    QWORD PTR [rip+0xc50c],0x0        # 14000f150 <key_dtor_list>
   140002c40:	00 00 00 00 
   140002c44:	c7 05 fa c4 00 00 00 	mov    DWORD PTR [rip+0xc4fa],0x0        # 14000f148 <__mingwthr_cs_init>
   140002c4b:	00 00 00 
   140002c4e:	48 8d 05 cb c4 00 00 	lea    rax,[rip+0xc4cb]        # 14000f120 <__mingwthr_cs>
   140002c55:	48 89 c1             	mov    rcx,rax
   140002c58:	48 8b 05 89 d5 00 00 	mov    rax,QWORD PTR [rip+0xd589]        # 1400101e8 <__IAT_start__>
   140002c5f:	ff d0                	call   rax
   140002c61:	eb 0e                	jmp    140002c71 <__mingw_TLScallback+0xf0>
   140002c63:	e8 18 00 00 00       	call   140002c80 <_fpreset>
   140002c68:	eb 08                	jmp    140002c72 <__mingw_TLScallback+0xf1>
   140002c6a:	e8 73 fe ff ff       	call   140002ae2 <__mingwthr_run_key_dtors>
   140002c6f:	eb 01                	jmp    140002c72 <__mingw_TLScallback+0xf1>
   140002c71:	90                   	nop
   140002c72:	b8 01 00 00 00       	mov    eax,0x1
   140002c77:	48 83 c4 30          	add    rsp,0x30
   140002c7b:	5d                   	pop    rbp
   140002c7c:	c3                   	ret
   140002c7d:	90                   	nop
   140002c7e:	90                   	nop
   140002c7f:	90                   	nop

0000000140002c80 <_fpreset>:
   140002c80:	55                   	push   rbp
   140002c81:	48 89 e5             	mov    rbp,rsp
   140002c84:	db e3                	fninit
   140002c86:	90                   	nop
   140002c87:	5d                   	pop    rbp
   140002c88:	c3                   	ret
   140002c89:	90                   	nop
   140002c8a:	90                   	nop
   140002c8b:	90                   	nop
   140002c8c:	90                   	nop
   140002c8d:	90                   	nop
   140002c8e:	90                   	nop
   140002c8f:	90                   	nop

0000000140002c90 <_ValidateImageBase>:
   140002c90:	55                   	push   rbp
   140002c91:	48 89 e5             	mov    rbp,rsp
   140002c94:	48 83 ec 20          	sub    rsp,0x20
   140002c98:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c9c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ca0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ca4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ca8:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002cab:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002caf:	74 07                	je     140002cb8 <_ValidateImageBase+0x28>
   140002cb1:	b8 00 00 00 00       	mov    eax,0x0
   140002cb6:	eb 4e                	jmp    140002d06 <_ValidateImageBase+0x76>
   140002cb8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cbc:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002cbf:	48 63 d0             	movsxd rdx,eax
   140002cc2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cc6:	48 01 d0             	add    rax,rdx
   140002cc9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ccd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002cd1:	8b 00                	mov    eax,DWORD PTR [rax]
   140002cd3:	3d 50 45 00 00       	cmp    eax,0x4550
   140002cd8:	74 07                	je     140002ce1 <_ValidateImageBase+0x51>
   140002cda:	b8 00 00 00 00       	mov    eax,0x0
   140002cdf:	eb 25                	jmp    140002d06 <_ValidateImageBase+0x76>
   140002ce1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ce5:	48 83 c0 18          	add    rax,0x18
   140002ce9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ced:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cf1:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002cf4:	66 3d 0b 02          	cmp    ax,0x20b
   140002cf8:	74 07                	je     140002d01 <_ValidateImageBase+0x71>
   140002cfa:	b8 00 00 00 00       	mov    eax,0x0
   140002cff:	eb 05                	jmp    140002d06 <_ValidateImageBase+0x76>
   140002d01:	b8 01 00 00 00       	mov    eax,0x1
   140002d06:	48 83 c4 20          	add    rsp,0x20
   140002d0a:	5d                   	pop    rbp
   140002d0b:	c3                   	ret

0000000140002d0c <_FindPESection>:
   140002d0c:	55                   	push   rbp
   140002d0d:	48 89 e5             	mov    rbp,rsp
   140002d10:	48 83 ec 20          	sub    rsp,0x20
   140002d14:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d18:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d1c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d20:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d23:	48 63 d0             	movsxd rdx,eax
   140002d26:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d2a:	48 01 d0             	add    rax,rdx
   140002d2d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d31:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d38:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d3c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d40:	0f b7 d0             	movzx  edx,ax
   140002d43:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d47:	48 01 d0             	add    rax,rdx
   140002d4a:	48 83 c0 18          	add    rax,0x18
   140002d4e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d52:	eb 36                	jmp    140002d8a <_FindPESection+0x7e>
   140002d54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d58:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d5b:	89 c0                	mov    eax,eax
   140002d5d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d61:	72 1e                	jb     140002d81 <_FindPESection+0x75>
   140002d63:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d67:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d6a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d6e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d71:	01 d0                	add    eax,edx
   140002d73:	89 c0                	mov    eax,eax
   140002d75:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d79:	73 06                	jae    140002d81 <_FindPESection+0x75>
   140002d7b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d7f:	eb 1e                	jmp    140002d9f <_FindPESection+0x93>
   140002d81:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d85:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d8a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d8e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d92:	0f b7 c0             	movzx  eax,ax
   140002d95:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d98:	72 ba                	jb     140002d54 <_FindPESection+0x48>
   140002d9a:	b8 00 00 00 00       	mov    eax,0x0
   140002d9f:	48 83 c4 20          	add    rsp,0x20
   140002da3:	5d                   	pop    rbp
   140002da4:	c3                   	ret

0000000140002da5 <_FindPESectionByName>:
   140002da5:	55                   	push   rbp
   140002da6:	48 89 e5             	mov    rbp,rsp
   140002da9:	48 83 ec 40          	sub    rsp,0x40
   140002dad:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002db1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002db5:	48 89 c1             	mov    rcx,rax
   140002db8:	e8 2b 69 00 00       	call   1400096e8 <strlen>
   140002dbd:	48 83 f8 08          	cmp    rax,0x8
   140002dc1:	76 0a                	jbe    140002dcd <_FindPESectionByName+0x28>
   140002dc3:	b8 00 00 00 00       	mov    eax,0x0
   140002dc8:	e9 98 00 00 00       	jmp    140002e65 <_FindPESectionByName+0xc0>
   140002dcd:	48 8b 05 ac 87 00 00 	mov    rax,QWORD PTR [rip+0x87ac]        # 14000b580 <.refptr.__ImageBase>
   140002dd4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002dd8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ddc:	48 89 c1             	mov    rcx,rax
   140002ddf:	e8 ac fe ff ff       	call   140002c90 <_ValidateImageBase>
   140002de4:	85 c0                	test   eax,eax
   140002de6:	75 07                	jne    140002def <_FindPESectionByName+0x4a>
   140002de8:	b8 00 00 00 00       	mov    eax,0x0
   140002ded:	eb 76                	jmp    140002e65 <_FindPESectionByName+0xc0>
   140002def:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002df3:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002df6:	48 63 d0             	movsxd rdx,eax
   140002df9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dfd:	48 01 d0             	add    rax,rdx
   140002e00:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e04:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e0b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e0f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e13:	0f b7 d0             	movzx  edx,ax
   140002e16:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e1a:	48 01 d0             	add    rax,rdx
   140002e1d:	48 83 c0 18          	add    rax,0x18
   140002e21:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e25:	eb 29                	jmp    140002e50 <_FindPESectionByName+0xab>
   140002e27:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e2b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e2f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e35:	48 89 c1             	mov    rcx,rax
   140002e38:	e8 b3 68 00 00       	call   1400096f0 <strncmp>
   140002e3d:	85 c0                	test   eax,eax
   140002e3f:	75 06                	jne    140002e47 <_FindPESectionByName+0xa2>
   140002e41:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e45:	eb 1e                	jmp    140002e65 <_FindPESectionByName+0xc0>
   140002e47:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e4b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e50:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e54:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e58:	0f b7 c0             	movzx  eax,ax
   140002e5b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e5e:	72 c7                	jb     140002e27 <_FindPESectionByName+0x82>
   140002e60:	b8 00 00 00 00       	mov    eax,0x0
   140002e65:	48 83 c4 40          	add    rsp,0x40
   140002e69:	5d                   	pop    rbp
   140002e6a:	c3                   	ret

0000000140002e6b <__mingw_GetSectionForAddress>:
   140002e6b:	55                   	push   rbp
   140002e6c:	48 89 e5             	mov    rbp,rsp
   140002e6f:	48 83 ec 30          	sub    rsp,0x30
   140002e73:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e77:	48 8b 05 02 87 00 00 	mov    rax,QWORD PTR [rip+0x8702]        # 14000b580 <.refptr.__ImageBase>
   140002e7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e82:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e86:	48 89 c1             	mov    rcx,rax
   140002e89:	e8 02 fe ff ff       	call   140002c90 <_ValidateImageBase>
   140002e8e:	85 c0                	test   eax,eax
   140002e90:	75 07                	jne    140002e99 <__mingw_GetSectionForAddress+0x2e>
   140002e92:	b8 00 00 00 00       	mov    eax,0x0
   140002e97:	eb 1c                	jmp    140002eb5 <__mingw_GetSectionForAddress+0x4a>
   140002e99:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e9d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002ea1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ea5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002ea9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ead:	48 89 c1             	mov    rcx,rax
   140002eb0:	e8 57 fe ff ff       	call   140002d0c <_FindPESection>
   140002eb5:	48 83 c4 30          	add    rsp,0x30
   140002eb9:	5d                   	pop    rbp
   140002eba:	c3                   	ret

0000000140002ebb <__mingw_GetSectionCount>:
   140002ebb:	55                   	push   rbp
   140002ebc:	48 89 e5             	mov    rbp,rsp
   140002ebf:	48 83 ec 30          	sub    rsp,0x30
   140002ec3:	48 8b 05 b6 86 00 00 	mov    rax,QWORD PTR [rip+0x86b6]        # 14000b580 <.refptr.__ImageBase>
   140002eca:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ece:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ed2:	48 89 c1             	mov    rcx,rax
   140002ed5:	e8 b6 fd ff ff       	call   140002c90 <_ValidateImageBase>
   140002eda:	85 c0                	test   eax,eax
   140002edc:	75 07                	jne    140002ee5 <__mingw_GetSectionCount+0x2a>
   140002ede:	b8 00 00 00 00       	mov    eax,0x0
   140002ee3:	eb 20                	jmp    140002f05 <__mingw_GetSectionCount+0x4a>
   140002ee5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ee9:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002eec:	48 63 d0             	movsxd rdx,eax
   140002eef:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ef3:	48 01 d0             	add    rax,rdx
   140002ef6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002efa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002efe:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f02:	0f b7 c0             	movzx  eax,ax
   140002f05:	48 83 c4 30          	add    rsp,0x30
   140002f09:	5d                   	pop    rbp
   140002f0a:	c3                   	ret

0000000140002f0b <_FindPESectionExec>:
   140002f0b:	55                   	push   rbp
   140002f0c:	48 89 e5             	mov    rbp,rsp
   140002f0f:	48 83 ec 40          	sub    rsp,0x40
   140002f13:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f17:	48 8b 05 62 86 00 00 	mov    rax,QWORD PTR [rip+0x8662]        # 14000b580 <.refptr.__ImageBase>
   140002f1e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f22:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f26:	48 89 c1             	mov    rcx,rax
   140002f29:	e8 62 fd ff ff       	call   140002c90 <_ValidateImageBase>
   140002f2e:	85 c0                	test   eax,eax
   140002f30:	75 07                	jne    140002f39 <_FindPESectionExec+0x2e>
   140002f32:	b8 00 00 00 00       	mov    eax,0x0
   140002f37:	eb 78                	jmp    140002fb1 <_FindPESectionExec+0xa6>
   140002f39:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f3d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f40:	48 63 d0             	movsxd rdx,eax
   140002f43:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f47:	48 01 d0             	add    rax,rdx
   140002f4a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f4e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f55:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f59:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f5d:	0f b7 d0             	movzx  edx,ax
   140002f60:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f64:	48 01 d0             	add    rax,rdx
   140002f67:	48 83 c0 18          	add    rax,0x18
   140002f6b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f6f:	eb 2b                	jmp    140002f9c <_FindPESectionExec+0x91>
   140002f71:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f75:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f78:	25 00 00 00 20       	and    eax,0x20000000
   140002f7d:	85 c0                	test   eax,eax
   140002f7f:	74 12                	je     140002f93 <_FindPESectionExec+0x88>
   140002f81:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f86:	75 06                	jne    140002f8e <_FindPESectionExec+0x83>
   140002f88:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f8c:	eb 23                	jmp    140002fb1 <_FindPESectionExec+0xa6>
   140002f8e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f93:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f97:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f9c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fa0:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002fa4:	0f b7 c0             	movzx  eax,ax
   140002fa7:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002faa:	72 c5                	jb     140002f71 <_FindPESectionExec+0x66>
   140002fac:	b8 00 00 00 00       	mov    eax,0x0
   140002fb1:	48 83 c4 40          	add    rsp,0x40
   140002fb5:	5d                   	pop    rbp
   140002fb6:	c3                   	ret

0000000140002fb7 <_GetPEImageBase>:
   140002fb7:	55                   	push   rbp
   140002fb8:	48 89 e5             	mov    rbp,rsp
   140002fbb:	48 83 ec 30          	sub    rsp,0x30
   140002fbf:	48 8b 05 ba 85 00 00 	mov    rax,QWORD PTR [rip+0x85ba]        # 14000b580 <.refptr.__ImageBase>
   140002fc6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fce:	48 89 c1             	mov    rcx,rax
   140002fd1:	e8 ba fc ff ff       	call   140002c90 <_ValidateImageBase>
   140002fd6:	85 c0                	test   eax,eax
   140002fd8:	75 07                	jne    140002fe1 <_GetPEImageBase+0x2a>
   140002fda:	b8 00 00 00 00       	mov    eax,0x0
   140002fdf:	eb 04                	jmp    140002fe5 <_GetPEImageBase+0x2e>
   140002fe1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fe5:	48 83 c4 30          	add    rsp,0x30
   140002fe9:	5d                   	pop    rbp
   140002fea:	c3                   	ret

0000000140002feb <_IsNonwritableInCurrentImage>:
   140002feb:	55                   	push   rbp
   140002fec:	48 89 e5             	mov    rbp,rsp
   140002fef:	48 83 ec 40          	sub    rsp,0x40
   140002ff3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ff7:	48 8b 05 82 85 00 00 	mov    rax,QWORD PTR [rip+0x8582]        # 14000b580 <.refptr.__ImageBase>
   140002ffe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003002:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003006:	48 89 c1             	mov    rcx,rax
   140003009:	e8 82 fc ff ff       	call   140002c90 <_ValidateImageBase>
   14000300e:	85 c0                	test   eax,eax
   140003010:	75 07                	jne    140003019 <_IsNonwritableInCurrentImage+0x2e>
   140003012:	b8 00 00 00 00       	mov    eax,0x0
   140003017:	eb 3d                	jmp    140003056 <_IsNonwritableInCurrentImage+0x6b>
   140003019:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000301d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003021:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003025:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003029:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000302d:	48 89 c1             	mov    rcx,rax
   140003030:	e8 d7 fc ff ff       	call   140002d0c <_FindPESection>
   140003035:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003039:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000303e:	75 07                	jne    140003047 <_IsNonwritableInCurrentImage+0x5c>
   140003040:	b8 00 00 00 00       	mov    eax,0x0
   140003045:	eb 0f                	jmp    140003056 <_IsNonwritableInCurrentImage+0x6b>
   140003047:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000304b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000304e:	f7 d0                	not    eax
   140003050:	c1 e8 1f             	shr    eax,0x1f
   140003053:	0f b6 c0             	movzx  eax,al
   140003056:	48 83 c4 40          	add    rsp,0x40
   14000305a:	5d                   	pop    rbp
   14000305b:	c3                   	ret

000000014000305c <__mingw_enum_import_library_names>:
   14000305c:	55                   	push   rbp
   14000305d:	48 89 e5             	mov    rbp,rsp
   140003060:	48 83 ec 50          	sub    rsp,0x50
   140003064:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003067:	48 8b 05 12 85 00 00 	mov    rax,QWORD PTR [rip+0x8512]        # 14000b580 <.refptr.__ImageBase>
   14000306e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003072:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003076:	48 89 c1             	mov    rcx,rax
   140003079:	e8 12 fc ff ff       	call   140002c90 <_ValidateImageBase>
   14000307e:	85 c0                	test   eax,eax
   140003080:	75 0a                	jne    14000308c <__mingw_enum_import_library_names+0x30>
   140003082:	b8 00 00 00 00       	mov    eax,0x0
   140003087:	e9 ab 00 00 00       	jmp    140003137 <__mingw_enum_import_library_names+0xdb>
   14000308c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003090:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003093:	48 63 d0             	movsxd rdx,eax
   140003096:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000309a:	48 01 d0             	add    rax,rdx
   14000309d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400030a1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030a5:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   1400030ab:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400030ae:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400030b2:	75 07                	jne    1400030bb <__mingw_enum_import_library_names+0x5f>
   1400030b4:	b8 00 00 00 00       	mov    eax,0x0
   1400030b9:	eb 7c                	jmp    140003137 <__mingw_enum_import_library_names+0xdb>
   1400030bb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030be:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030c2:	48 89 c1             	mov    rcx,rax
   1400030c5:	e8 42 fc ff ff       	call   140002d0c <_FindPESection>
   1400030ca:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400030ce:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   1400030d3:	75 07                	jne    1400030dc <__mingw_enum_import_library_names+0x80>
   1400030d5:	b8 00 00 00 00       	mov    eax,0x0
   1400030da:	eb 5b                	jmp    140003137 <__mingw_enum_import_library_names+0xdb>
   1400030dc:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030df:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030e3:	48 01 d0             	add    rax,rdx
   1400030e6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030ea:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400030ef:	75 07                	jne    1400030f8 <__mingw_enum_import_library_names+0x9c>
   1400030f1:	b8 00 00 00 00       	mov    eax,0x0
   1400030f6:	eb 3f                	jmp    140003137 <__mingw_enum_import_library_names+0xdb>
   1400030f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030fc:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400030ff:	85 c0                	test   eax,eax
   140003101:	75 0b                	jne    14000310e <__mingw_enum_import_library_names+0xb2>
   140003103:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003107:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000310a:	85 c0                	test   eax,eax
   14000310c:	74 23                	je     140003131 <__mingw_enum_import_library_names+0xd5>
   14000310e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003112:	7f 12                	jg     140003126 <__mingw_enum_import_library_names+0xca>
   140003114:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003118:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000311b:	89 c2                	mov    edx,eax
   14000311d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003121:	48 01 d0             	add    rax,rdx
   140003124:	eb 11                	jmp    140003137 <__mingw_enum_import_library_names+0xdb>
   140003126:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000312a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000312f:	eb c7                	jmp    1400030f8 <__mingw_enum_import_library_names+0x9c>
   140003131:	90                   	nop
   140003132:	b8 00 00 00 00       	mov    eax,0x0
   140003137:	48 83 c4 50          	add    rsp,0x50
   14000313b:	5d                   	pop    rbp
   14000313c:	c3                   	ret
   14000313d:	90                   	nop
   14000313e:	90                   	nop
   14000313f:	90                   	nop

0000000140003140 <___chkstk_ms>:
   140003140:	51                   	push   rcx
   140003141:	50                   	push   rax
   140003142:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003148:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000314d:	72 19                	jb     140003168 <___chkstk_ms+0x28>
   14000314f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003156:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000315a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003160:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003166:	77 e7                	ja     14000314f <___chkstk_ms+0xf>
   140003168:	48 29 c1             	sub    rcx,rax
   14000316b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000316f:	58                   	pop    rax
   140003170:	59                   	pop    rcx
   140003171:	c3                   	ret
   140003172:	90                   	nop
   140003173:	90                   	nop
   140003174:	90                   	nop
   140003175:	90                   	nop
   140003176:	90                   	nop
   140003177:	90                   	nop
   140003178:	90                   	nop
   140003179:	90                   	nop
   14000317a:	90                   	nop
   14000317b:	90                   	nop
   14000317c:	90                   	nop
   14000317d:	90                   	nop
   14000317e:	90                   	nop
   14000317f:	90                   	nop

0000000140003180 <__mingw_printf>:
   140003180:	55                   	push   rbp
   140003181:	53                   	push   rbx
   140003182:	48 83 ec 48          	sub    rsp,0x48
   140003186:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   14000318b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000318f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140003193:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003197:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   14000319b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   14000319f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031a3:	b9 01 00 00 00       	mov    ecx,0x1
   1400031a8:	e8 c3 5e 00 00       	call   140009070 <__acrt_iob_func>
   1400031ad:	48 89 c1             	mov    rcx,rax
   1400031b0:	e8 3b 5d 00 00       	call   140008ef0 <_lock_file>
   1400031b5:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   1400031b9:	b9 01 00 00 00       	mov    ecx,0x1
   1400031be:	e8 ad 5e 00 00       	call   140009070 <__acrt_iob_func>
   1400031c3:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400031c7:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
   1400031cc:	49 89 d1             	mov    r9,rdx
   1400031cf:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400031d5:	48 89 c2             	mov    rdx,rax
   1400031d8:	b9 00 60 00 00       	mov    ecx,0x6000
   1400031dd:	e8 b1 1f 00 00       	call   140005193 <__mingw_pformat>
   1400031e2:	89 c3                	mov    ebx,eax
   1400031e4:	b9 01 00 00 00       	mov    ecx,0x1
   1400031e9:	e8 82 5e 00 00       	call   140009070 <__acrt_iob_func>
   1400031ee:	48 89 c1             	mov    rcx,rax
   1400031f1:	e8 84 5d 00 00       	call   140008f7a <_unlock_file>
   1400031f6:	89 d8                	mov    eax,ebx
   1400031f8:	48 83 c4 48          	add    rsp,0x48
   1400031fc:	5b                   	pop    rbx
   1400031fd:	5d                   	pop    rbp
   1400031fe:	c3                   	ret
   1400031ff:	90                   	nop

0000000140003200 <__pformat_putc>:
   140003200:	55                   	push   rbp
   140003201:	48 89 e5             	mov    rbp,rsp
   140003204:	48 83 ec 20          	sub    rsp,0x20
   140003208:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000320b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000320f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003213:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003216:	25 00 40 00 00       	and    eax,0x4000
   14000321b:	85 c0                	test   eax,eax
   14000321d:	75 12                	jne    140003231 <__pformat_putc+0x31>
   14000321f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003223:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   140003226:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000322a:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000322d:	39 c2                	cmp    edx,eax
   14000322f:	7e 3b                	jle    14000326c <__pformat_putc+0x6c>
   140003231:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003235:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003238:	25 00 20 00 00       	and    eax,0x2000
   14000323d:	85 c0                	test   eax,eax
   14000323f:	74 13                	je     140003254 <__pformat_putc+0x54>
   140003241:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003245:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003248:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000324b:	89 c1                	mov    ecx,eax
   14000324d:	e8 56 64 00 00       	call   1400096a8 <fputc>
   140003252:	eb 18                	jmp    14000326c <__pformat_putc+0x6c>
   140003254:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003258:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   14000325b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000325f:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003262:	48 98                	cdqe
   140003264:	48 01 d0             	add    rax,rdx
   140003267:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   14000326a:	88 10                	mov    BYTE PTR [rax],dl
   14000326c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003270:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003273:	8d 50 01             	lea    edx,[rax+0x1]
   140003276:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000327a:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   14000327d:	90                   	nop
   14000327e:	48 83 c4 20          	add    rsp,0x20
   140003282:	5d                   	pop    rbp
   140003283:	c3                   	ret

0000000140003284 <__pformat_putchars>:
   140003284:	55                   	push   rbp
   140003285:	48 89 e5             	mov    rbp,rsp
   140003288:	48 83 ec 20          	sub    rsp,0x20
   14000328c:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003290:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003293:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003297:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000329b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000329e:	85 c0                	test   eax,eax
   1400032a0:	78 16                	js     1400032b8 <__pformat_putchars+0x34>
   1400032a2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032a6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032a9:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400032ac:	7e 0a                	jle    1400032b8 <__pformat_putchars+0x34>
   1400032ae:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032b2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032b5:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400032b8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032bc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032bf:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400032c2:	7d 15                	jge    1400032d9 <__pformat_putchars+0x55>
   1400032c4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032c8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032cb:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400032ce:	89 c2                	mov    edx,eax
   1400032d0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032d4:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400032d7:	eb 0b                	jmp    1400032e4 <__pformat_putchars+0x60>
   1400032d9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032dd:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400032e4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032e8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032eb:	85 c0                	test   eax,eax
   1400032ed:	7e 57                	jle    140003346 <__pformat_putchars+0xc2>
   1400032ef:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032f3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400032f6:	25 00 04 00 00       	and    eax,0x400
   1400032fb:	85 c0                	test   eax,eax
   1400032fd:	75 47                	jne    140003346 <__pformat_putchars+0xc2>
   1400032ff:	eb 11                	jmp    140003312 <__pformat_putchars+0x8e>
   140003301:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003305:	48 89 c2             	mov    rdx,rax
   140003308:	b9 20 00 00 00       	mov    ecx,0x20
   14000330d:	e8 ee fe ff ff       	call   140003200 <__pformat_putc>
   140003312:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003316:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003319:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000331c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003320:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003323:	85 c0                	test   eax,eax
   140003325:	75 da                	jne    140003301 <__pformat_putchars+0x7d>
   140003327:	eb 1d                	jmp    140003346 <__pformat_putchars+0xc2>
   140003329:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000332d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003331:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003335:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003338:	0f be c0             	movsx  eax,al
   14000333b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000333f:	89 c1                	mov    ecx,eax
   140003341:	e8 ba fe ff ff       	call   140003200 <__pformat_putc>
   140003346:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003349:	8d 50 ff             	lea    edx,[rax-0x1]
   14000334c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000334f:	85 c0                	test   eax,eax
   140003351:	75 d6                	jne    140003329 <__pformat_putchars+0xa5>
   140003353:	eb 11                	jmp    140003366 <__pformat_putchars+0xe2>
   140003355:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003359:	48 89 c2             	mov    rdx,rax
   14000335c:	b9 20 00 00 00       	mov    ecx,0x20
   140003361:	e8 9a fe ff ff       	call   140003200 <__pformat_putc>
   140003366:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000336a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000336d:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003370:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003374:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003377:	85 c0                	test   eax,eax
   140003379:	7f da                	jg     140003355 <__pformat_putchars+0xd1>
   14000337b:	90                   	nop
   14000337c:	90                   	nop
   14000337d:	48 83 c4 20          	add    rsp,0x20
   140003381:	5d                   	pop    rbp
   140003382:	c3                   	ret

0000000140003383 <__pformat_puts>:
   140003383:	55                   	push   rbp
   140003384:	48 89 e5             	mov    rbp,rsp
   140003387:	48 83 ec 20          	sub    rsp,0x20
   14000338b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000338f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003393:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140003398:	75 0b                	jne    1400033a5 <__pformat_puts+0x22>
   14000339a:	48 8d 05 8f 7f 00 00 	lea    rax,[rip+0x7f8f]        # 14000b330 <.rdata>
   1400033a1:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400033a5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400033a9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033ac:	85 c0                	test   eax,eax
   1400033ae:	78 2f                	js     1400033df <__pformat_puts+0x5c>
   1400033b0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400033b4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033b7:	48 63 d0             	movsxd rdx,eax
   1400033ba:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033be:	48 89 c1             	mov    rcx,rax
   1400033c1:	e8 4a 5a 00 00       	call   140008e10 <strnlen>
   1400033c6:	89 c1                	mov    ecx,eax
   1400033c8:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400033cc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033d0:	49 89 d0             	mov    r8,rdx
   1400033d3:	89 ca                	mov    edx,ecx
   1400033d5:	48 89 c1             	mov    rcx,rax
   1400033d8:	e8 a7 fe ff ff       	call   140003284 <__pformat_putchars>
   1400033dd:	eb 23                	jmp    140003402 <__pformat_puts+0x7f>
   1400033df:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033e3:	48 89 c1             	mov    rcx,rax
   1400033e6:	e8 fd 62 00 00       	call   1400096e8 <strlen>
   1400033eb:	89 c1                	mov    ecx,eax
   1400033ed:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400033f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033f5:	49 89 d0             	mov    r8,rdx
   1400033f8:	89 ca                	mov    edx,ecx
   1400033fa:	48 89 c1             	mov    rcx,rax
   1400033fd:	e8 82 fe ff ff       	call   140003284 <__pformat_putchars>
   140003402:	90                   	nop
   140003403:	48 83 c4 20          	add    rsp,0x20
   140003407:	5d                   	pop    rbp
   140003408:	c3                   	ret

0000000140003409 <__pformat_wputchars>:
   140003409:	55                   	push   rbp
   14000340a:	48 89 e5             	mov    rbp,rsp
   14000340d:	48 83 ec 50          	sub    rsp,0x50
   140003411:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003415:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003418:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000341c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   140003423:	00 
   140003424:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003428:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000342b:	85 c0                	test   eax,eax
   14000342d:	78 16                	js     140003445 <__pformat_wputchars+0x3c>
   14000342f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003433:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003436:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003439:	7e 0a                	jle    140003445 <__pformat_wputchars+0x3c>
   14000343b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000343f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003442:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003445:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003449:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000344c:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000344f:	7d 15                	jge    140003466 <__pformat_wputchars+0x5d>
   140003451:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003455:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003458:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000345b:	89 c2                	mov    edx,eax
   14000345d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003461:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003464:	eb 0b                	jmp    140003471 <__pformat_wputchars+0x68>
   140003466:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000346a:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003471:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003475:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003478:	85 c0                	test   eax,eax
   14000347a:	7e 6e                	jle    1400034ea <__pformat_wputchars+0xe1>
   14000347c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003480:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003483:	25 00 04 00 00       	and    eax,0x400
   140003488:	85 c0                	test   eax,eax
   14000348a:	75 5e                	jne    1400034ea <__pformat_wputchars+0xe1>
   14000348c:	eb 11                	jmp    14000349f <__pformat_wputchars+0x96>
   14000348e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003492:	48 89 c2             	mov    rdx,rax
   140003495:	b9 20 00 00 00       	mov    ecx,0x20
   14000349a:	e8 61 fd ff ff       	call   140003200 <__pformat_putc>
   14000349f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034a3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034a6:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400034a9:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034ad:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400034b0:	85 c0                	test   eax,eax
   1400034b2:	75 da                	jne    14000348e <__pformat_wputchars+0x85>
   1400034b4:	eb 34                	jmp    1400034ea <__pformat_wputchars+0xe1>
   1400034b6:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400034ba:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400034be:	eb 1d                	jmp    1400034dd <__pformat_wputchars+0xd4>
   1400034c0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400034c4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400034c8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400034cc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400034cf:	0f be c0             	movsx  eax,al
   1400034d2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034d6:	89 c1                	mov    ecx,eax
   1400034d8:	e8 23 fd ff ff       	call   140003200 <__pformat_putc>
   1400034dd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400034e0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400034e3:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   1400034e6:	85 c0                	test   eax,eax
   1400034e8:	7f d6                	jg     1400034c0 <__pformat_wputchars+0xb7>
   1400034ea:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400034ed:	8d 50 ff             	lea    edx,[rax-0x1]
   1400034f0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400034f3:	85 c0                	test   eax,eax
   1400034f5:	7e 41                	jle    140003538 <__pformat_wputchars+0x12f>
   1400034f7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400034fb:	48 8d 50 02          	lea    rdx,[rax+0x2]
   1400034ff:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003503:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140003506:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   14000350a:	0f b7 d0             	movzx  edx,ax
   14000350d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003511:	49 89 c8             	mov    r8,rcx
   140003514:	48 89 c1             	mov    rcx,rax
   140003517:	e8 84 5b 00 00       	call   1400090a0 <wcrtomb>
   14000351c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000351f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003523:	7f 91                	jg     1400034b6 <__pformat_wputchars+0xad>
   140003525:	eb 11                	jmp    140003538 <__pformat_wputchars+0x12f>
   140003527:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000352b:	48 89 c2             	mov    rdx,rax
   14000352e:	b9 20 00 00 00       	mov    ecx,0x20
   140003533:	e8 c8 fc ff ff       	call   140003200 <__pformat_putc>
   140003538:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000353c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000353f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003542:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003546:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003549:	85 c0                	test   eax,eax
   14000354b:	7f da                	jg     140003527 <__pformat_wputchars+0x11e>
   14000354d:	90                   	nop
   14000354e:	90                   	nop
   14000354f:	48 83 c4 50          	add    rsp,0x50
   140003553:	5d                   	pop    rbp
   140003554:	c3                   	ret

0000000140003555 <__pformat_wcputs>:
   140003555:	55                   	push   rbp
   140003556:	48 89 e5             	mov    rbp,rsp
   140003559:	48 83 ec 20          	sub    rsp,0x20
   14000355d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003561:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003565:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000356a:	75 0b                	jne    140003577 <__pformat_wcputs+0x22>
   14000356c:	48 8d 05 c5 7d 00 00 	lea    rax,[rip+0x7dc5]        # 14000b338 <.rdata+0x8>
   140003573:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003577:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000357b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000357e:	85 c0                	test   eax,eax
   140003580:	78 2f                	js     1400035b1 <__pformat_wcputs+0x5c>
   140003582:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003586:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003589:	48 63 d0             	movsxd rdx,eax
   14000358c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003590:	48 89 c1             	mov    rcx,rax
   140003593:	e8 28 58 00 00       	call   140008dc0 <wcsnlen>
   140003598:	89 c1                	mov    ecx,eax
   14000359a:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000359e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035a2:	49 89 d0             	mov    r8,rdx
   1400035a5:	89 ca                	mov    edx,ecx
   1400035a7:	48 89 c1             	mov    rcx,rax
   1400035aa:	e8 5a fe ff ff       	call   140003409 <__pformat_wputchars>
   1400035af:	eb 23                	jmp    1400035d4 <__pformat_wcputs+0x7f>
   1400035b1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035b5:	48 89 c1             	mov    rcx,rax
   1400035b8:	e8 43 61 00 00       	call   140009700 <wcslen>
   1400035bd:	89 c1                	mov    ecx,eax
   1400035bf:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400035c3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035c7:	49 89 d0             	mov    r8,rdx
   1400035ca:	89 ca                	mov    edx,ecx
   1400035cc:	48 89 c1             	mov    rcx,rax
   1400035cf:	e8 35 fe ff ff       	call   140003409 <__pformat_wputchars>
   1400035d4:	90                   	nop
   1400035d5:	48 83 c4 20          	add    rsp,0x20
   1400035d9:	5d                   	pop    rbp
   1400035da:	c3                   	ret

00000001400035db <__pformat_int_bufsiz>:
   1400035db:	55                   	push   rbp
   1400035dc:	48 89 e5             	mov    rbp,rsp
   1400035df:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400035e2:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400035e5:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400035e9:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035ec:	83 e8 01             	sub    eax,0x1
   1400035ef:	48 98                	cdqe
   1400035f1:	48 83 c0 40          	add    rax,0x40
   1400035f5:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400035f8:	48 63 ca             	movsxd rcx,edx
   1400035fb:	ba 00 00 00 00       	mov    edx,0x0
   140003600:	48 f7 f1             	div    rcx
   140003603:	89 c2                	mov    edx,eax
   140003605:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140003608:	01 d0                	add    eax,edx
   14000360a:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   14000360d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003611:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003614:	ba 00 00 00 00       	mov    edx,0x0
   140003619:	85 c0                	test   eax,eax
   14000361b:	0f 48 c2             	cmovs  eax,edx
   14000361e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   140003621:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003625:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003628:	25 00 10 00 00       	and    eax,0x1000
   14000362d:	85 c0                	test   eax,eax
   14000362f:	74 29                	je     14000365a <__pformat_int_bufsiz+0x7f>
   140003631:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003635:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003639:	66 85 c0             	test   ax,ax
   14000363c:	74 1c                	je     14000365a <__pformat_int_bufsiz+0x7f>
   14000363e:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003641:	48 63 d0             	movsxd rdx,eax
   140003644:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   14000364b:	48 89 d1             	mov    rcx,rdx
   14000364e:	48 c1 e9 20          	shr    rcx,0x20
   140003652:	99                   	cdq
   140003653:	89 c8                	mov    eax,ecx
   140003655:	29 d0                	sub    eax,edx
   140003657:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   14000365a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000365e:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140003661:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003664:	39 c2                	cmp    edx,eax
   140003666:	0f 4d c2             	cmovge eax,edx
   140003669:	5d                   	pop    rbp
   14000366a:	c3                   	ret

000000014000366b <__pformat_int>:
   14000366b:	55                   	push   rbp
   14000366c:	53                   	push   rbx
   14000366d:	48 83 ec 58          	sub    rsp,0x58
   140003671:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003676:	48 89 cb             	mov    rbx,rcx
   140003679:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   14000367c:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   140003680:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   140003684:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   140003688:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000368c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003690:	49 89 c0             	mov    r8,rax
   140003693:	ba 03 00 00 00       	mov    edx,0x3
   140003698:	b9 01 00 00 00       	mov    ecx,0x1
   14000369d:	e8 39 ff ff ff       	call   1400035db <__pformat_int_bufsiz>
   1400036a2:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400036a5:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   1400036ac:	00 
   1400036ad:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400036b0:	48 98                	cdqe
   1400036b2:	48 83 c0 0f          	add    rax,0xf
   1400036b6:	48 c1 e8 04          	shr    rax,0x4
   1400036ba:	48 c1 e0 04          	shl    rax,0x4
   1400036be:	e8 7d fa ff ff       	call   140003140 <___chkstk_ms>
   1400036c3:	48 29 c4             	sub    rsp,rax
   1400036c6:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400036cb:	48 83 c0 0f          	add    rax,0xf
   1400036cf:	48 c1 e8 04          	shr    rax,0x4
   1400036d3:	48 c1 e0 04          	shl    rax,0x4
   1400036d7:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400036db:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400036df:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400036e3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036e7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400036ea:	25 80 00 00 00       	and    eax,0x80
   1400036ef:	85 c0                	test   eax,eax
   1400036f1:	0f 84 ea 00 00 00    	je     1400037e1 <__pformat_int+0x176>
   1400036f7:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400036fb:	48 85 c0             	test   rax,rax
   1400036fe:	79 10                	jns    140003710 <__pformat_int+0xa5>
   140003700:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003704:	48 f7 d8             	neg    rax
   140003707:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000370b:	e9 d1 00 00 00       	jmp    1400037e1 <__pformat_int+0x176>
   140003710:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003714:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003717:	24 7f                	and    al,0x7f
   140003719:	89 c2                	mov    edx,eax
   14000371b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000371f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003722:	e9 ba 00 00 00       	jmp    1400037e1 <__pformat_int+0x176>
   140003727:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000372b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000372f:	74 54                	je     140003785 <__pformat_int+0x11a>
   140003731:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003735:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003738:	25 00 10 00 00       	and    eax,0x1000
   14000373d:	85 c0                	test   eax,eax
   14000373f:	74 44                	je     140003785 <__pformat_int+0x11a>
   140003741:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003745:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003749:	66 85 c0             	test   ax,ax
   14000374c:	74 37                	je     140003785 <__pformat_int+0x11a>
   14000374e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003752:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   140003756:	48 89 c2             	mov    rdx,rax
   140003759:	48 89 d0             	mov    rax,rdx
   14000375c:	48 c1 f8 3f          	sar    rax,0x3f
   140003760:	48 c1 e8 3e          	shr    rax,0x3e
   140003764:	48 01 c2             	add    rdx,rax
   140003767:	83 e2 03             	and    edx,0x3
   14000376a:	48 29 c2             	sub    rdx,rax
   14000376d:	48 89 d0             	mov    rax,rdx
   140003770:	48 83 f8 03          	cmp    rax,0x3
   140003774:	75 0f                	jne    140003785 <__pformat_int+0x11a>
   140003776:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000377a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000377e:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003782:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   140003785:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   140003789:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003790:	cc cc cc 
   140003793:	48 89 c8             	mov    rax,rcx
   140003796:	48 f7 e2             	mul    rdx
   140003799:	48 c1 ea 03          	shr    rdx,0x3
   14000379d:	48 89 d0             	mov    rax,rdx
   1400037a0:	48 c1 e0 02          	shl    rax,0x2
   1400037a4:	48 01 d0             	add    rax,rdx
   1400037a7:	48 01 c0             	add    rax,rax
   1400037aa:	48 29 c1             	sub    rcx,rax
   1400037ad:	48 89 ca             	mov    rdx,rcx
   1400037b0:	89 d0                	mov    eax,edx
   1400037b2:	8d 48 30             	lea    ecx,[rax+0x30]
   1400037b5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037b9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037bd:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037c1:	89 ca                	mov    edx,ecx
   1400037c3:	88 10                	mov    BYTE PTR [rax],dl
   1400037c5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400037c9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400037d0:	cc cc cc 
   1400037d3:	48 f7 e2             	mul    rdx
   1400037d6:	48 89 d0             	mov    rax,rdx
   1400037d9:	48 c1 e8 03          	shr    rax,0x3
   1400037dd:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400037e1:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400037e5:	48 85 c0             	test   rax,rax
   1400037e8:	0f 85 39 ff ff ff    	jne    140003727 <__pformat_int+0xbc>
   1400037ee:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037f2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400037f5:	85 c0                	test   eax,eax
   1400037f7:	7e 3e                	jle    140003837 <__pformat_int+0x1cc>
   1400037f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037fd:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003800:	89 c1                	mov    ecx,eax
   140003802:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003806:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000380a:	89 c2                	mov    edx,eax
   14000380c:	89 c8                	mov    eax,ecx
   14000380e:	29 d0                	sub    eax,edx
   140003810:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003813:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003817:	7e 1e                	jle    140003837 <__pformat_int+0x1cc>
   140003819:	eb 0f                	jmp    14000382a <__pformat_int+0x1bf>
   14000381b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000381f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003823:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003827:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000382a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000382d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003830:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   140003833:	85 c0                	test   eax,eax
   140003835:	7f e4                	jg     14000381b <__pformat_int+0x1b0>
   140003837:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000383b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000383f:	75 1a                	jne    14000385b <__pformat_int+0x1f0>
   140003841:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003845:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003848:	85 c0                	test   eax,eax
   14000384a:	74 0f                	je     14000385b <__pformat_int+0x1f0>
   14000384c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003850:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003854:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003858:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000385b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000385f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003862:	85 c0                	test   eax,eax
   140003864:	0f 8e ce 00 00 00    	jle    140003938 <__pformat_int+0x2cd>
   14000386a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000386e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003871:	89 c1                	mov    ecx,eax
   140003873:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003877:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000387b:	89 c2                	mov    edx,eax
   14000387d:	89 c8                	mov    eax,ecx
   14000387f:	29 d0                	sub    eax,edx
   140003881:	89 c2                	mov    edx,eax
   140003883:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003887:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000388a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000388e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003891:	85 c0                	test   eax,eax
   140003893:	0f 8e 9f 00 00 00    	jle    140003938 <__pformat_int+0x2cd>
   140003899:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000389d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038a0:	25 c0 01 00 00       	and    eax,0x1c0
   1400038a5:	85 c0                	test   eax,eax
   1400038a7:	74 11                	je     1400038ba <__pformat_int+0x24f>
   1400038a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ad:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038b0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400038b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038b7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400038ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038be:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400038c1:	85 c0                	test   eax,eax
   1400038c3:	79 3b                	jns    140003900 <__pformat_int+0x295>
   1400038c5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038c9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038cc:	25 00 06 00 00       	and    eax,0x600
   1400038d1:	3d 00 02 00 00       	cmp    eax,0x200
   1400038d6:	75 28                	jne    140003900 <__pformat_int+0x295>
   1400038d8:	eb 0f                	jmp    1400038e9 <__pformat_int+0x27e>
   1400038da:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038de:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038e2:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038e6:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400038e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ed:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038f0:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400038f3:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400038f7:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400038fa:	85 c0                	test   eax,eax
   1400038fc:	7f dc                	jg     1400038da <__pformat_int+0x26f>
   1400038fe:	eb 38                	jmp    140003938 <__pformat_int+0x2cd>
   140003900:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003904:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003907:	25 00 04 00 00       	and    eax,0x400
   14000390c:	85 c0                	test   eax,eax
   14000390e:	75 28                	jne    140003938 <__pformat_int+0x2cd>
   140003910:	eb 11                	jmp    140003923 <__pformat_int+0x2b8>
   140003912:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003916:	48 89 c2             	mov    rdx,rax
   140003919:	b9 20 00 00 00       	mov    ecx,0x20
   14000391e:	e8 dd f8 ff ff       	call   140003200 <__pformat_putc>
   140003923:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003927:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000392a:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000392d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003931:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003934:	85 c0                	test   eax,eax
   140003936:	7f da                	jg     140003912 <__pformat_int+0x2a7>
   140003938:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000393c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000393f:	25 80 00 00 00       	and    eax,0x80
   140003944:	85 c0                	test   eax,eax
   140003946:	74 11                	je     140003959 <__pformat_int+0x2ee>
   140003948:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000394c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003950:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003954:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   140003957:	eb 5a                	jmp    1400039b3 <__pformat_int+0x348>
   140003959:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000395d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003960:	25 00 01 00 00       	and    eax,0x100
   140003965:	85 c0                	test   eax,eax
   140003967:	74 11                	je     14000397a <__pformat_int+0x30f>
   140003969:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000396d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003971:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003975:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140003978:	eb 39                	jmp    1400039b3 <__pformat_int+0x348>
   14000397a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000397e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003981:	83 e0 40             	and    eax,0x40
   140003984:	85 c0                	test   eax,eax
   140003986:	74 2b                	je     1400039b3 <__pformat_int+0x348>
   140003988:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000398c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003990:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003994:	c6 00 20             	mov    BYTE PTR [rax],0x20
   140003997:	eb 1a                	jmp    1400039b3 <__pformat_int+0x348>
   140003999:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   14000399e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039a2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400039a5:	0f be c0             	movsx  eax,al
   1400039a8:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400039ac:	89 c1                	mov    ecx,eax
   1400039ae:	e8 4d f8 ff ff       	call   140003200 <__pformat_putc>
   1400039b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039b7:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   1400039bb:	72 dc                	jb     140003999 <__pformat_int+0x32e>
   1400039bd:	eb 11                	jmp    1400039d0 <__pformat_int+0x365>
   1400039bf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039c3:	48 89 c2             	mov    rdx,rax
   1400039c6:	b9 20 00 00 00       	mov    ecx,0x20
   1400039cb:	e8 30 f8 ff ff       	call   140003200 <__pformat_putc>
   1400039d0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039d4:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400039d7:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400039da:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400039de:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400039e1:	85 c0                	test   eax,eax
   1400039e3:	7f da                	jg     1400039bf <__pformat_int+0x354>
   1400039e5:	90                   	nop
   1400039e6:	90                   	nop
   1400039e7:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   1400039eb:	5b                   	pop    rbx
   1400039ec:	5d                   	pop    rbp
   1400039ed:	c3                   	ret

00000001400039ee <__pformat_xint>:
   1400039ee:	55                   	push   rbp
   1400039ef:	53                   	push   rbx
   1400039f0:	48 83 ec 68          	sub    rsp,0x68
   1400039f4:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   1400039f9:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   1400039fc:	48 89 d3             	mov    rbx,rdx
   1400039ff:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140003a02:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   140003a06:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003a0a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   140003a0e:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003a12:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a16:	74 1e                	je     140003a36 <__pformat_xint+0x48>
   140003a18:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a1c:	74 06                	je     140003a24 <__pformat_xint+0x36>
   140003a1e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a22:	75 09                	jne    140003a2d <__pformat_xint+0x3f>
   140003a24:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003a2b:	eb 10                	jmp    140003a3d <__pformat_xint+0x4f>
   140003a2d:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003a34:	eb 07                	jmp    140003a3d <__pformat_xint+0x4f>
   140003a36:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140003a3d:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003a41:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003a44:	49 89 d0             	mov    r8,rdx
   140003a47:	89 c2                	mov    edx,eax
   140003a49:	b9 02 00 00 00       	mov    ecx,0x2
   140003a4e:	e8 88 fb ff ff       	call   1400035db <__pformat_int_bufsiz>
   140003a53:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140003a56:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   140003a5d:	00 
   140003a5e:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140003a61:	48 98                	cdqe
   140003a63:	48 83 c0 0f          	add    rax,0xf
   140003a67:	48 c1 e8 04          	shr    rax,0x4
   140003a6b:	48 c1 e0 04          	shl    rax,0x4
   140003a6f:	e8 cc f6 ff ff       	call   140003140 <___chkstk_ms>
   140003a74:	48 29 c4             	sub    rsp,rax
   140003a77:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003a7c:	48 83 c0 0f          	add    rax,0xf
   140003a80:	48 c1 e8 04          	shr    rax,0x4
   140003a84:	48 c1 e0 04          	shl    rax,0x4
   140003a88:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140003a8c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003a90:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003a94:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a98:	74 1e                	je     140003ab8 <__pformat_xint+0xca>
   140003a9a:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a9e:	74 06                	je     140003aa6 <__pformat_xint+0xb8>
   140003aa0:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003aa4:	75 09                	jne    140003aaf <__pformat_xint+0xc1>
   140003aa6:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003aad:	eb 10                	jmp    140003abf <__pformat_xint+0xd1>
   140003aaf:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003ab6:	eb 67                	jmp    140003b1f <__pformat_xint+0x131>
   140003ab8:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003abf:	eb 5e                	jmp    140003b1f <__pformat_xint+0x131>
   140003ac1:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003ac5:	89 c2                	mov    edx,eax
   140003ac7:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003aca:	21 d0                	and    eax,edx
   140003acc:	8d 48 30             	lea    ecx,[rax+0x30]
   140003acf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ad3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ad7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003adb:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003adf:	89 ca                	mov    edx,ecx
   140003ae1:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003ae5:	88 10                	mov    BYTE PTR [rax],dl
   140003ae7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003aeb:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003aee:	3c 39                	cmp    al,0x39
   140003af0:	7e 1a                	jle    140003b0c <__pformat_xint+0x11e>
   140003af2:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003af6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003af9:	83 c0 07             	add    eax,0x7
   140003afc:	89 c2                	mov    edx,eax
   140003afe:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003b01:	83 e0 20             	and    eax,0x20
   140003b04:	09 c2                	or     edx,eax
   140003b06:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b0a:	88 10                	mov    BYTE PTR [rax],dl
   140003b0c:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003b10:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003b13:	89 c1                	mov    ecx,eax
   140003b15:	48 d3 ea             	shr    rdx,cl
   140003b18:	48 89 d0             	mov    rax,rdx
   140003b1b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003b1f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003b23:	48 85 c0             	test   rax,rax
   140003b26:	75 99                	jne    140003ac1 <__pformat_xint+0xd3>
   140003b28:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b2c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b30:	75 13                	jne    140003b45 <__pformat_xint+0x157>
   140003b32:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b36:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b39:	80 e4 f7             	and    ah,0xf7
   140003b3c:	89 c2                	mov    edx,eax
   140003b3e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b42:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003b45:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b49:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b4c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b4f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b53:	7e 3a                	jle    140003b8f <__pformat_xint+0x1a1>
   140003b55:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003b58:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b5c:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003b60:	89 c1                	mov    ecx,eax
   140003b62:	89 d0                	mov    eax,edx
   140003b64:	29 c8                	sub    eax,ecx
   140003b66:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b69:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b6d:	7e 20                	jle    140003b8f <__pformat_xint+0x1a1>
   140003b6f:	eb 0f                	jmp    140003b80 <__pformat_xint+0x192>
   140003b71:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b75:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b79:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b7d:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b80:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003b83:	8d 50 ff             	lea    edx,[rax-0x1]
   140003b86:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b89:	85 c0                	test   eax,eax
   140003b8b:	7f e4                	jg     140003b71 <__pformat_xint+0x183>
   140003b8d:	eb 25                	jmp    140003bb4 <__pformat_xint+0x1c6>
   140003b8f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003b93:	75 1f                	jne    140003bb4 <__pformat_xint+0x1c6>
   140003b95:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b99:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b9c:	25 00 08 00 00       	and    eax,0x800
   140003ba1:	85 c0                	test   eax,eax
   140003ba3:	74 0f                	je     140003bb4 <__pformat_xint+0x1c6>
   140003ba5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ba9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bad:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bb1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bb4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bb8:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003bbc:	75 1a                	jne    140003bd8 <__pformat_xint+0x1ea>
   140003bbe:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bc2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003bc5:	85 c0                	test   eax,eax
   140003bc7:	74 0f                	je     140003bd8 <__pformat_xint+0x1ea>
   140003bc9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bcd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bd1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bd5:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bd8:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bdc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003bdf:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003be3:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003be7:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bea:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003bed:	7d 15                	jge    140003c04 <__pformat_xint+0x216>
   140003bef:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bf3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003bf6:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003bf9:	89 c2                	mov    edx,eax
   140003bfb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bff:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003c02:	eb 0b                	jmp    140003c0f <__pformat_xint+0x221>
   140003c04:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c08:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003c0f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c13:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c16:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003c19:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c1d:	7e 1a                	jle    140003c39 <__pformat_xint+0x24b>
   140003c1f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c23:	74 14                	je     140003c39 <__pformat_xint+0x24b>
   140003c25:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c29:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c2c:	25 00 08 00 00       	and    eax,0x800
   140003c31:	85 c0                	test   eax,eax
   140003c33:	74 04                	je     140003c39 <__pformat_xint+0x24b>
   140003c35:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003c39:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c3d:	7e 3c                	jle    140003c7b <__pformat_xint+0x28d>
   140003c3f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c43:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003c46:	85 c0                	test   eax,eax
   140003c48:	79 31                	jns    140003c7b <__pformat_xint+0x28d>
   140003c4a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c4e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c51:	25 00 06 00 00       	and    eax,0x600
   140003c56:	3d 00 02 00 00       	cmp    eax,0x200
   140003c5b:	75 1e                	jne    140003c7b <__pformat_xint+0x28d>
   140003c5d:	eb 0f                	jmp    140003c6e <__pformat_xint+0x280>
   140003c5f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c63:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c67:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c6b:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c6e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c71:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c74:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c77:	85 c0                	test   eax,eax
   140003c79:	7f e4                	jg     140003c5f <__pformat_xint+0x271>
   140003c7b:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c7f:	74 30                	je     140003cb1 <__pformat_xint+0x2c3>
   140003c81:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c85:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c88:	25 00 08 00 00       	and    eax,0x800
   140003c8d:	85 c0                	test   eax,eax
   140003c8f:	74 20                	je     140003cb1 <__pformat_xint+0x2c3>
   140003c91:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c95:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c99:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c9d:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003ca0:	88 10                	mov    BYTE PTR [rax],dl
   140003ca2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ca6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003caa:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003cae:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003cb1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003cb5:	7e 4c                	jle    140003d03 <__pformat_xint+0x315>
   140003cb7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cbb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003cbe:	25 00 04 00 00       	and    eax,0x400
   140003cc3:	85 c0                	test   eax,eax
   140003cc5:	75 3c                	jne    140003d03 <__pformat_xint+0x315>
   140003cc7:	eb 11                	jmp    140003cda <__pformat_xint+0x2ec>
   140003cc9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ccd:	48 89 c2             	mov    rdx,rax
   140003cd0:	b9 20 00 00 00       	mov    ecx,0x20
   140003cd5:	e8 26 f5 ff ff       	call   140003200 <__pformat_putc>
   140003cda:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003cdd:	8d 50 ff             	lea    edx,[rax-0x1]
   140003ce0:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003ce3:	85 c0                	test   eax,eax
   140003ce5:	7f e2                	jg     140003cc9 <__pformat_xint+0x2db>
   140003ce7:	eb 1a                	jmp    140003d03 <__pformat_xint+0x315>
   140003ce9:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003cee:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cf2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003cf5:	0f be c0             	movsx  eax,al
   140003cf8:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003cfc:	89 c1                	mov    ecx,eax
   140003cfe:	e8 fd f4 ff ff       	call   140003200 <__pformat_putc>
   140003d03:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d07:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003d0b:	72 dc                	jb     140003ce9 <__pformat_xint+0x2fb>
   140003d0d:	eb 11                	jmp    140003d20 <__pformat_xint+0x332>
   140003d0f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d13:	48 89 c2             	mov    rdx,rax
   140003d16:	b9 20 00 00 00       	mov    ecx,0x20
   140003d1b:	e8 e0 f4 ff ff       	call   140003200 <__pformat_putc>
   140003d20:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d23:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d26:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d29:	85 c0                	test   eax,eax
   140003d2b:	7f e2                	jg     140003d0f <__pformat_xint+0x321>
   140003d2d:	90                   	nop
   140003d2e:	90                   	nop
   140003d2f:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003d33:	5b                   	pop    rbx
   140003d34:	5d                   	pop    rbp
   140003d35:	c3                   	ret

0000000140003d36 <init_fpreg_ldouble>:
   140003d36:	55                   	push   rbp
   140003d37:	53                   	push   rbx
   140003d38:	48 83 ec 28          	sub    rsp,0x28
   140003d3c:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003d41:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003d45:	48 89 d3             	mov    rbx,rdx
   140003d48:	db 2b                	fld    TBYTE PTR [rbx]
   140003d4a:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003d4d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003d50:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003d53:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003d57:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d5b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003d5f:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003d62:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003d66:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003d6a:	48 83 c4 28          	add    rsp,0x28
   140003d6e:	5b                   	pop    rbx
   140003d6f:	5d                   	pop    rbp
   140003d70:	c3                   	ret

0000000140003d71 <__pformat_cvt>:
   140003d71:	55                   	push   rbp
   140003d72:	53                   	push   rbx
   140003d73:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003d7a:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003d81:	00 
   140003d82:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003d85:	48 89 d3             	mov    rbx,rdx
   140003d88:	db 2b                	fld    TBYTE PTR [rbx]
   140003d8a:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003d8d:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003d91:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003d95:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003d9c:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003da0:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003da3:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003da6:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003daa:	48 89 c1             	mov    rcx,rax
   140003dad:	e8 84 ff ff ff       	call   140003d36 <init_fpreg_ldouble>
   140003db2:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003db5:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003db8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003dbc:	48 89 c1             	mov    rcx,rax
   140003dbf:	e8 9c 4e 00 00       	call   140008c60 <__fpclassifyl>
   140003dc4:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003dc7:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003dca:	25 00 01 00 00       	and    eax,0x100
   140003dcf:	85 c0                	test   eax,eax
   140003dd1:	74 1d                	je     140003df0 <__pformat_cvt+0x7f>
   140003dd3:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003dd6:	25 00 04 00 00       	and    eax,0x400
   140003ddb:	85 c0                	test   eax,eax
   140003ddd:	74 07                	je     140003de6 <__pformat_cvt+0x75>
   140003ddf:	b8 03 00 00 00       	mov    eax,0x3
   140003de4:	eb 05                	jmp    140003deb <__pformat_cvt+0x7a>
   140003de6:	b8 04 00 00 00       	mov    eax,0x4
   140003deb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003dee:	eb 4a                	jmp    140003e3a <__pformat_cvt+0xc9>
   140003df0:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003df3:	25 00 04 00 00       	and    eax,0x400
   140003df8:	85 c0                	test   eax,eax
   140003dfa:	74 37                	je     140003e33 <__pformat_cvt+0xc2>
   140003dfc:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003dff:	25 00 40 00 00       	and    eax,0x4000
   140003e04:	85 c0                	test   eax,eax
   140003e06:	74 10                	je     140003e18 <__pformat_cvt+0xa7>
   140003e08:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003e0f:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003e16:	eb 22                	jmp    140003e3a <__pformat_cvt+0xc9>
   140003e18:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003e1f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e23:	98                   	cwde
   140003e24:	25 ff 7f 00 00       	and    eax,0x7fff
   140003e29:	2d 3e 40 00 00       	sub    eax,0x403e
   140003e2e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003e31:	eb 07                	jmp    140003e3a <__pformat_cvt+0xc9>
   140003e33:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003e3a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e3d:	83 f8 04             	cmp    eax,0x4
   140003e40:	74 0e                	je     140003e50 <__pformat_cvt+0xdf>
   140003e42:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e46:	98                   	cwde
   140003e47:	25 00 80 00 00       	and    eax,0x8000
   140003e4c:	89 c2                	mov    edx,eax
   140003e4e:	eb 05                	jmp    140003e55 <__pformat_cvt+0xe4>
   140003e50:	ba 00 00 00 00       	mov    edx,0x0
   140003e55:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003e59:	89 10                	mov    DWORD PTR [rax],edx
   140003e5b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003e5e:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003e62:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003e66:	48 8d 0d 03 62 00 00 	lea    rcx,[rip+0x6203]        # 14000a070 <fpi.0>
   140003e6d:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003e71:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003e76:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e7a:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003e7f:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003e82:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003e86:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003e89:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003e8d:	89 c2                	mov    edx,eax
   140003e8f:	e8 96 24 00 00       	call   14000632a <__gdtoa>
   140003e94:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003e9b:	5b                   	pop    rbx
   140003e9c:	5d                   	pop    rbp
   140003e9d:	c3                   	ret

0000000140003e9e <__pformat_ecvt>:
   140003e9e:	55                   	push   rbp
   140003e9f:	53                   	push   rbx
   140003ea0:	48 83 ec 58          	sub    rsp,0x58
   140003ea4:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003ea9:	48 89 cb             	mov    rbx,rcx
   140003eac:	db 2b                	fld    TBYTE PTR [rbx]
   140003eae:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003eb1:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003eb4:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003eb8:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003ebc:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003ebf:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003ec2:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003ec6:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003ec9:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003ecd:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003ed1:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003ed6:	4d 89 c1             	mov    r9,r8
   140003ed9:	41 89 c8             	mov    r8d,ecx
   140003edc:	48 89 c2             	mov    rdx,rax
   140003edf:	b9 02 00 00 00       	mov    ecx,0x2
   140003ee4:	e8 88 fe ff ff       	call   140003d71 <__pformat_cvt>
   140003ee9:	48 83 c4 58          	add    rsp,0x58
   140003eed:	5b                   	pop    rbx
   140003eee:	5d                   	pop    rbp
   140003eef:	c3                   	ret

0000000140003ef0 <__pformat_fcvt>:
   140003ef0:	55                   	push   rbp
   140003ef1:	53                   	push   rbx
   140003ef2:	48 83 ec 58          	sub    rsp,0x58
   140003ef6:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003efb:	48 89 cb             	mov    rbx,rcx
   140003efe:	db 2b                	fld    TBYTE PTR [rbx]
   140003f00:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003f03:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003f06:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003f0a:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003f0e:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003f11:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003f14:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003f18:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003f1b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003f1f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f23:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f28:	4d 89 c1             	mov    r9,r8
   140003f2b:	41 89 c8             	mov    r8d,ecx
   140003f2e:	48 89 c2             	mov    rdx,rax
   140003f31:	b9 03 00 00 00       	mov    ecx,0x3
   140003f36:	e8 36 fe ff ff       	call   140003d71 <__pformat_cvt>
   140003f3b:	48 83 c4 58          	add    rsp,0x58
   140003f3f:	5b                   	pop    rbx
   140003f40:	5d                   	pop    rbp
   140003f41:	c3                   	ret

0000000140003f42 <__pformat_emit_radix_point>:
   140003f42:	55                   	push   rbp
   140003f43:	53                   	push   rbx
   140003f44:	48 83 ec 68          	sub    rsp,0x68
   140003f48:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003f4d:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003f51:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f55:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f58:	83 f8 fd             	cmp    eax,0xfffffffd
   140003f5b:	75 48                	jne    140003fa5 <__pformat_emit_radix_point+0x63>
   140003f5d:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003f64:	00 
   140003f65:	e8 4e 57 00 00       	call   1400096b8 <localeconv>
   140003f6a:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003f6d:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003f71:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003f75:	49 89 c9             	mov    r9,rcx
   140003f78:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003f7e:	48 89 c1             	mov    rcx,rax
   140003f81:	e8 6a 51 00 00       	call   1400090f0 <mbrtowc>
   140003f86:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003f89:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003f8d:	7e 0c                	jle    140003f9b <__pformat_emit_radix_point+0x59>
   140003f8f:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003f93:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f97:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003f9b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f9f:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003fa2:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003fa5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fa9:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003fad:	66 85 c0             	test   ax,ax
   140003fb0:	0f 84 b8 00 00 00    	je     14000406e <__pformat_emit_radix_point+0x12c>
   140003fb6:	48 89 e0             	mov    rax,rsp
   140003fb9:	48 89 c3             	mov    rbx,rax
   140003fbc:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fc0:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003fc3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003fc6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003fc9:	48 63 d0             	movsxd rdx,eax
   140003fcc:	48 83 ea 01          	sub    rdx,0x1
   140003fd0:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140003fd4:	48 98                	cdqe
   140003fd6:	48 83 c0 0f          	add    rax,0xf
   140003fda:	48 c1 e8 04          	shr    rax,0x4
   140003fde:	48 c1 e0 04          	shl    rax,0x4
   140003fe2:	e8 59 f1 ff ff       	call   140003140 <___chkstk_ms>
   140003fe7:	48 29 c4             	sub    rsp,rax
   140003fea:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003fef:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003ff3:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   140003ffa:	00 
   140003ffb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fff:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140004003:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140004007:	0f b7 d0             	movzx  edx,ax
   14000400a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000400e:	49 89 c8             	mov    r8,rcx
   140004011:	48 89 c1             	mov    rcx,rax
   140004014:	e8 87 50 00 00       	call   1400090a0 <wcrtomb>
   140004019:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000401c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004020:	7e 36                	jle    140004058 <__pformat_emit_radix_point+0x116>
   140004022:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140004026:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000402a:	eb 1d                	jmp    140004049 <__pformat_emit_radix_point+0x107>
   14000402c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004030:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004034:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004038:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000403b:	0f be c0             	movsx  eax,al
   14000403e:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004042:	89 c1                	mov    ecx,eax
   140004044:	e8 b7 f1 ff ff       	call   140003200 <__pformat_putc>
   140004049:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000404c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000404f:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140004052:	85 c0                	test   eax,eax
   140004054:	7f d6                	jg     14000402c <__pformat_emit_radix_point+0xea>
   140004056:	eb 11                	jmp    140004069 <__pformat_emit_radix_point+0x127>
   140004058:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000405c:	48 89 c2             	mov    rdx,rax
   14000405f:	b9 2e 00 00 00       	mov    ecx,0x2e
   140004064:	e8 97 f1 ff ff       	call   140003200 <__pformat_putc>
   140004069:	48 89 dc             	mov    rsp,rbx
   14000406c:	eb 11                	jmp    14000407f <__pformat_emit_radix_point+0x13d>
   14000406e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004072:	48 89 c2             	mov    rdx,rax
   140004075:	b9 2e 00 00 00       	mov    ecx,0x2e
   14000407a:	e8 81 f1 ff ff       	call   140003200 <__pformat_putc>
   14000407f:	90                   	nop
   140004080:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140004084:	5b                   	pop    rbx
   140004085:	5d                   	pop    rbp
   140004086:	c3                   	ret

0000000140004087 <__pformat_emit_numeric_value>:
   140004087:	55                   	push   rbp
   140004088:	48 89 e5             	mov    rbp,rsp
   14000408b:	48 83 ec 30          	sub    rsp,0x30
   14000408f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004092:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004096:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   14000409a:	75 0e                	jne    1400040aa <__pformat_emit_numeric_value+0x23>
   14000409c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040a0:	48 89 c1             	mov    rcx,rax
   1400040a3:	e8 9a fe ff ff       	call   140003f42 <__pformat_emit_radix_point>
   1400040a8:	eb 43                	jmp    1400040ed <__pformat_emit_numeric_value+0x66>
   1400040aa:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   1400040ae:	75 2f                	jne    1400040df <__pformat_emit_numeric_value+0x58>
   1400040b0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040b4:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400040b8:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   1400040bc:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   1400040c0:	66 85 c0             	test   ax,ax
   1400040c3:	74 28                	je     1400040ed <__pformat_emit_numeric_value+0x66>
   1400040c5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400040c9:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   1400040cd:	49 89 d0             	mov    r8,rdx
   1400040d0:	ba 01 00 00 00       	mov    edx,0x1
   1400040d5:	48 89 c1             	mov    rcx,rax
   1400040d8:	e8 2c f3 ff ff       	call   140003409 <__pformat_wputchars>
   1400040dd:	eb 0e                	jmp    1400040ed <__pformat_emit_numeric_value+0x66>
   1400040df:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400040e3:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400040e6:	89 c1                	mov    ecx,eax
   1400040e8:	e8 13 f1 ff ff       	call   140003200 <__pformat_putc>
   1400040ed:	90                   	nop
   1400040ee:	48 83 c4 30          	add    rsp,0x30
   1400040f2:	5d                   	pop    rbp
   1400040f3:	c3                   	ret

00000001400040f4 <__pformat_emit_inf_or_nan>:
   1400040f4:	55                   	push   rbp
   1400040f5:	48 89 e5             	mov    rbp,rsp
   1400040f8:	48 83 ec 40          	sub    rsp,0x40
   1400040fc:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400040ff:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004103:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140004107:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000410b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000410f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004113:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000411a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000411e:	74 11                	je     140004131 <__pformat_emit_inf_or_nan+0x3d>
   140004120:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004124:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004128:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000412c:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   14000412f:	eb 3e                	jmp    14000416f <__pformat_emit_inf_or_nan+0x7b>
   140004131:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004135:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004138:	25 00 01 00 00       	and    eax,0x100
   14000413d:	85 c0                	test   eax,eax
   14000413f:	74 11                	je     140004152 <__pformat_emit_inf_or_nan+0x5e>
   140004141:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004145:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004149:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000414d:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140004150:	eb 1d                	jmp    14000416f <__pformat_emit_inf_or_nan+0x7b>
   140004152:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004156:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004159:	83 e0 40             	and    eax,0x40
   14000415c:	85 c0                	test   eax,eax
   14000415e:	74 0f                	je     14000416f <__pformat_emit_inf_or_nan+0x7b>
   140004160:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004164:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004168:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000416c:	c6 00 20             	mov    BYTE PTR [rax],0x20
   14000416f:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140004176:	eb 38                	jmp    1400041b0 <__pformat_emit_inf_or_nan+0xbc>
   140004178:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000417c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004180:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004184:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004187:	83 e0 df             	and    eax,0xffffffdf
   14000418a:	41 89 c0             	mov    r8d,eax
   14000418d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004191:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004194:	83 e0 20             	and    eax,0x20
   140004197:	89 c1                	mov    ecx,eax
   140004199:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000419d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041a1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400041a5:	44 89 c2             	mov    edx,r8d
   1400041a8:	09 ca                	or     edx,ecx
   1400041aa:	88 10                	mov    BYTE PTR [rax],dl
   1400041ac:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400041b0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400041b4:	7f c2                	jg     140004178 <__pformat_emit_inf_or_nan+0x84>
   1400041b6:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400041ba:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400041be:	48 29 c2             	sub    rdx,rax
   1400041c1:	89 d1                	mov    ecx,edx
   1400041c3:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400041c7:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400041cb:	49 89 d0             	mov    r8,rdx
   1400041ce:	89 ca                	mov    edx,ecx
   1400041d0:	48 89 c1             	mov    rcx,rax
   1400041d3:	e8 ac f0 ff ff       	call   140003284 <__pformat_putchars>
   1400041d8:	90                   	nop
   1400041d9:	48 83 c4 40          	add    rsp,0x40
   1400041dd:	5d                   	pop    rbp
   1400041de:	c3                   	ret

00000001400041df <__pformat_emit_float>:
   1400041df:	55                   	push   rbp
   1400041e0:	48 89 e5             	mov    rbp,rsp
   1400041e3:	48 83 ec 30          	sub    rsp,0x30
   1400041e7:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400041ea:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400041ee:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400041f2:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400041f6:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400041fa:	7e 2e                	jle    14000422a <__pformat_emit_float+0x4b>
   1400041fc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004200:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004203:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   140004206:	7f 15                	jg     14000421d <__pformat_emit_float+0x3e>
   140004208:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000420c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000420f:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004212:	89 c2                	mov    edx,eax
   140004214:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004218:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000421b:	eb 29                	jmp    140004246 <__pformat_emit_float+0x67>
   14000421d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004221:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004228:	eb 1c                	jmp    140004246 <__pformat_emit_float+0x67>
   14000422a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000422e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004231:	85 c0                	test   eax,eax
   140004233:	7e 11                	jle    140004246 <__pformat_emit_float+0x67>
   140004235:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004239:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000423c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000423f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004243:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004246:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000424a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000424d:	85 c0                	test   eax,eax
   14000424f:	78 2b                	js     14000427c <__pformat_emit_float+0x9d>
   140004251:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004255:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004258:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000425c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000425f:	39 c2                	cmp    edx,eax
   140004261:	7e 19                	jle    14000427c <__pformat_emit_float+0x9d>
   140004263:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004267:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   14000426a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000426e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004271:	29 c2                	sub    edx,eax
   140004273:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004277:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000427a:	eb 0b                	jmp    140004287 <__pformat_emit_float+0xa8>
   14000427c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004280:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004287:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000428b:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000428e:	85 c0                	test   eax,eax
   140004290:	7e 2c                	jle    1400042be <__pformat_emit_float+0xdf>
   140004292:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004296:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004299:	85 c0                	test   eax,eax
   14000429b:	7f 10                	jg     1400042ad <__pformat_emit_float+0xce>
   14000429d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042a4:	25 00 08 00 00       	and    eax,0x800
   1400042a9:	85 c0                	test   eax,eax
   1400042ab:	74 11                	je     1400042be <__pformat_emit_float+0xdf>
   1400042ad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042b1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042b4:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042b7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042bb:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042be:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400042c2:	7e 64                	jle    140004328 <__pformat_emit_float+0x149>
   1400042c4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042c8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042cb:	25 00 10 00 00       	and    eax,0x1000
   1400042d0:	85 c0                	test   eax,eax
   1400042d2:	74 54                	je     140004328 <__pformat_emit_float+0x149>
   1400042d4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042d8:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400042dc:	66 85 c0             	test   ax,ax
   1400042df:	74 47                	je     140004328 <__pformat_emit_float+0x149>
   1400042e1:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400042e4:	83 c0 02             	add    eax,0x2
   1400042e7:	48 63 d0             	movsxd rdx,eax
   1400042ea:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   1400042f1:	48 c1 ea 20          	shr    rdx,0x20
   1400042f5:	c1 f8 1f             	sar    eax,0x1f
   1400042f8:	29 c2                	sub    edx,eax
   1400042fa:	8d 42 ff             	lea    eax,[rdx-0x1]
   1400042fd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004300:	eb 15                	jmp    140004317 <__pformat_emit_float+0x138>
   140004302:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004306:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000430a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000430d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004310:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004314:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004317:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000431b:	7e 0b                	jle    140004328 <__pformat_emit_float+0x149>
   14000431d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004321:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004324:	85 c0                	test   eax,eax
   140004326:	7f da                	jg     140004302 <__pformat_emit_float+0x123>
   140004328:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000432c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000432f:	85 c0                	test   eax,eax
   140004331:	7e 27                	jle    14000435a <__pformat_emit_float+0x17b>
   140004333:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004337:	75 10                	jne    140004349 <__pformat_emit_float+0x16a>
   140004339:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000433d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004340:	25 c0 01 00 00       	and    eax,0x1c0
   140004345:	85 c0                	test   eax,eax
   140004347:	74 11                	je     14000435a <__pformat_emit_float+0x17b>
   140004349:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000434d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004350:	8d 50 ff             	lea    edx,[rax-0x1]
   140004353:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004357:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000435a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000435e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004361:	85 c0                	test   eax,eax
   140004363:	7e 38                	jle    14000439d <__pformat_emit_float+0x1be>
   140004365:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004369:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000436c:	25 00 06 00 00       	and    eax,0x600
   140004371:	85 c0                	test   eax,eax
   140004373:	75 28                	jne    14000439d <__pformat_emit_float+0x1be>
   140004375:	eb 11                	jmp    140004388 <__pformat_emit_float+0x1a9>
   140004377:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000437b:	48 89 c2             	mov    rdx,rax
   14000437e:	b9 20 00 00 00       	mov    ecx,0x20
   140004383:	e8 78 ee ff ff       	call   140003200 <__pformat_putc>
   140004388:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000438c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000438f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004392:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004396:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004399:	85 c0                	test   eax,eax
   14000439b:	7f da                	jg     140004377 <__pformat_emit_float+0x198>
   14000439d:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400043a1:	74 13                	je     1400043b6 <__pformat_emit_float+0x1d7>
   1400043a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043a7:	48 89 c2             	mov    rdx,rax
   1400043aa:	b9 2d 00 00 00       	mov    ecx,0x2d
   1400043af:	e8 4c ee ff ff       	call   140003200 <__pformat_putc>
   1400043b4:	eb 42                	jmp    1400043f8 <__pformat_emit_float+0x219>
   1400043b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ba:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043bd:	25 00 01 00 00       	and    eax,0x100
   1400043c2:	85 c0                	test   eax,eax
   1400043c4:	74 13                	je     1400043d9 <__pformat_emit_float+0x1fa>
   1400043c6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ca:	48 89 c2             	mov    rdx,rax
   1400043cd:	b9 2b 00 00 00       	mov    ecx,0x2b
   1400043d2:	e8 29 ee ff ff       	call   140003200 <__pformat_putc>
   1400043d7:	eb 1f                	jmp    1400043f8 <__pformat_emit_float+0x219>
   1400043d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043dd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043e0:	83 e0 40             	and    eax,0x40
   1400043e3:	85 c0                	test   eax,eax
   1400043e5:	74 11                	je     1400043f8 <__pformat_emit_float+0x219>
   1400043e7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043eb:	48 89 c2             	mov    rdx,rax
   1400043ee:	b9 20 00 00 00       	mov    ecx,0x20
   1400043f3:	e8 08 ee ff ff       	call   140003200 <__pformat_putc>
   1400043f8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043fc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043ff:	85 c0                	test   eax,eax
   140004401:	7e 3b                	jle    14000443e <__pformat_emit_float+0x25f>
   140004403:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004407:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000440a:	25 00 06 00 00       	and    eax,0x600
   14000440f:	3d 00 02 00 00       	cmp    eax,0x200
   140004414:	75 28                	jne    14000443e <__pformat_emit_float+0x25f>
   140004416:	eb 11                	jmp    140004429 <__pformat_emit_float+0x24a>
   140004418:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000441c:	48 89 c2             	mov    rdx,rax
   14000441f:	b9 30 00 00 00       	mov    ecx,0x30
   140004424:	e8 d7 ed ff ff       	call   140003200 <__pformat_putc>
   140004429:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000442d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004430:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004433:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004437:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000443a:	85 c0                	test   eax,eax
   14000443c:	7f da                	jg     140004418 <__pformat_emit_float+0x239>
   14000443e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004442:	0f 8e a7 00 00 00    	jle    1400044ef <__pformat_emit_float+0x310>
   140004448:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000444c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000444f:	84 c0                	test   al,al
   140004451:	74 14                	je     140004467 <__pformat_emit_float+0x288>
   140004453:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004457:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000445b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000445f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004462:	0f be c0             	movsx  eax,al
   140004465:	eb 05                	jmp    14000446c <__pformat_emit_float+0x28d>
   140004467:	b8 30 00 00 00       	mov    eax,0x30
   14000446c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004470:	89 c1                	mov    ecx,eax
   140004472:	e8 89 ed ff ff       	call   140003200 <__pformat_putc>
   140004477:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000447b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000447f:	74 62                	je     1400044e3 <__pformat_emit_float+0x304>
   140004481:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004485:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004488:	25 00 10 00 00       	and    eax,0x1000
   14000448d:	85 c0                	test   eax,eax
   14000448f:	74 52                	je     1400044e3 <__pformat_emit_float+0x304>
   140004491:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004495:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004499:	66 85 c0             	test   ax,ax
   14000449c:	74 45                	je     1400044e3 <__pformat_emit_float+0x304>
   14000449e:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   1400044a1:	48 63 c1             	movsxd rax,ecx
   1400044a4:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   1400044ab:	48 c1 e8 20          	shr    rax,0x20
   1400044af:	48 89 c2             	mov    rdx,rax
   1400044b2:	89 c8                	mov    eax,ecx
   1400044b4:	c1 f8 1f             	sar    eax,0x1f
   1400044b7:	29 c2                	sub    edx,eax
   1400044b9:	89 d0                	mov    eax,edx
   1400044bb:	01 c0                	add    eax,eax
   1400044bd:	01 d0                	add    eax,edx
   1400044bf:	29 c1                	sub    ecx,eax
   1400044c1:	89 ca                	mov    edx,ecx
   1400044c3:	85 d2                	test   edx,edx
   1400044c5:	75 1c                	jne    1400044e3 <__pformat_emit_float+0x304>
   1400044c7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044cb:	48 83 c0 20          	add    rax,0x20
   1400044cf:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044d3:	49 89 d0             	mov    r8,rdx
   1400044d6:	ba 01 00 00 00       	mov    edx,0x1
   1400044db:	48 89 c1             	mov    rcx,rax
   1400044de:	e8 26 ef ff ff       	call   140003409 <__pformat_wputchars>
   1400044e3:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044e7:	0f 8f 5b ff ff ff    	jg     140004448 <__pformat_emit_float+0x269>
   1400044ed:	eb 11                	jmp    140004500 <__pformat_emit_float+0x321>
   1400044ef:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044f3:	48 89 c2             	mov    rdx,rax
   1400044f6:	b9 30 00 00 00       	mov    ecx,0x30
   1400044fb:	e8 00 ed ff ff       	call   140003200 <__pformat_putc>
   140004500:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004504:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004507:	85 c0                	test   eax,eax
   140004509:	7f 10                	jg     14000451b <__pformat_emit_float+0x33c>
   14000450b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000450f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004512:	25 00 08 00 00       	and    eax,0x800
   140004517:	85 c0                	test   eax,eax
   140004519:	74 0c                	je     140004527 <__pformat_emit_float+0x348>
   14000451b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000451f:	48 89 c1             	mov    rcx,rax
   140004522:	e8 1b fa ff ff       	call   140003f42 <__pformat_emit_radix_point>
   140004527:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000452b:	79 5f                	jns    14000458c <__pformat_emit_float+0x3ad>
   14000452d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004531:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004534:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004537:	01 c2                	add    edx,eax
   140004539:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000453d:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004540:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004544:	48 89 c2             	mov    rdx,rax
   140004547:	b9 30 00 00 00       	mov    ecx,0x30
   14000454c:	e8 af ec ff ff       	call   140003200 <__pformat_putc>
   140004551:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   140004555:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004559:	78 e5                	js     140004540 <__pformat_emit_float+0x361>
   14000455b:	eb 2f                	jmp    14000458c <__pformat_emit_float+0x3ad>
   14000455d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004561:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004564:	84 c0                	test   al,al
   140004566:	74 14                	je     14000457c <__pformat_emit_float+0x39d>
   140004568:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000456c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004570:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004574:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004577:	0f be c0             	movsx  eax,al
   14000457a:	eb 05                	jmp    140004581 <__pformat_emit_float+0x3a2>
   14000457c:	b8 30 00 00 00       	mov    eax,0x30
   140004581:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004585:	89 c1                	mov    ecx,eax
   140004587:	e8 74 ec ff ff       	call   140003200 <__pformat_putc>
   14000458c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004590:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004593:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004596:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000459a:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   14000459d:	85 c0                	test   eax,eax
   14000459f:	7f bc                	jg     14000455d <__pformat_emit_float+0x37e>
   1400045a1:	90                   	nop
   1400045a2:	90                   	nop
   1400045a3:	48 83 c4 30          	add    rsp,0x30
   1400045a7:	5d                   	pop    rbp
   1400045a8:	c3                   	ret

00000001400045a9 <__pformat_emit_efloat>:
   1400045a9:	55                   	push   rbp
   1400045aa:	48 89 e5             	mov    rbp,rsp
   1400045ad:	48 83 ec 50          	sub    rsp,0x50
   1400045b1:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400045b4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400045b8:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400045bc:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400045c0:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400045c7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400045cb:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400045cf:	79 09                	jns    1400045da <__pformat_emit_efloat+0x31>
   1400045d1:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400045d8:	eb 05                	jmp    1400045df <__pformat_emit_efloat+0x36>
   1400045da:	b8 00 00 00 00       	mov    eax,0x0
   1400045df:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400045e3:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400045e6:	48 98                	cdqe
   1400045e8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400045ec:	eb 04                	jmp    1400045f2 <__pformat_emit_efloat+0x49>
   1400045ee:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400045f2:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400045f5:	48 63 d0             	movsxd rdx,eax
   1400045f8:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   1400045ff:	48 c1 ea 20          	shr    rdx,0x20
   140004603:	89 d1                	mov    ecx,edx
   140004605:	c1 f9 02             	sar    ecx,0x2
   140004608:	99                   	cdq
   140004609:	89 c8                	mov    eax,ecx
   14000460b:	29 d0                	sub    eax,edx
   14000460d:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004610:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004614:	75 d8                	jne    1400045ee <__pformat_emit_efloat+0x45>
   140004616:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000461a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000461d:	83 f8 ff             	cmp    eax,0xffffffff
   140004620:	75 0b                	jne    14000462d <__pformat_emit_efloat+0x84>
   140004622:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004626:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   14000462d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004631:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004634:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004637:	7d 0a                	jge    140004643 <__pformat_emit_efloat+0x9a>
   140004639:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000463d:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004640:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004643:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004647:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000464a:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   14000464e:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004651:	7d 15                	jge    140004668 <__pformat_emit_efloat+0xbf>
   140004653:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004657:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000465a:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   14000465d:	89 c2                	mov    edx,eax
   14000465f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004663:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004666:	eb 0b                	jmp    140004673 <__pformat_emit_efloat+0xca>
   140004668:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000466c:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004673:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004677:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000467b:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000467e:	49 89 c9             	mov    r9,rcx
   140004681:	41 b8 01 00 00 00    	mov    r8d,0x1
   140004687:	89 c1                	mov    ecx,eax
   140004689:	e8 51 fb ff ff       	call   1400041df <__pformat_emit_float>
   14000468e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004692:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   140004695:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004699:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000469c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046a0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400046a3:	0d c0 01 00 00       	or     eax,0x1c0
   1400046a8:	89 c2                	mov    edx,eax
   1400046aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046ae:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400046b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046b5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400046b8:	83 e0 20             	and    eax,0x20
   1400046bb:	83 c8 45             	or     eax,0x45
   1400046be:	89 c1                	mov    ecx,eax
   1400046c0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046c4:	48 89 c2             	mov    rdx,rax
   1400046c7:	e8 34 eb ff ff       	call   140003200 <__pformat_putc>
   1400046cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046d0:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400046d3:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400046d6:	83 ea 01             	sub    edx,0x1
   1400046d9:	01 c2                	add    edx,eax
   1400046db:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046df:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400046e2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400046e6:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400046ea:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400046ee:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   1400046f2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400046f6:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400046fa:	48 89 c1             	mov    rcx,rax
   1400046fd:	e8 69 ef ff ff       	call   14000366b <__pformat_int>
   140004702:	90                   	nop
   140004703:	48 83 c4 50          	add    rsp,0x50
   140004707:	5d                   	pop    rbp
   140004708:	c3                   	ret

0000000140004709 <__pformat_float>:
   140004709:	55                   	push   rbp
   14000470a:	53                   	push   rbx
   14000470b:	48 83 ec 58          	sub    rsp,0x58
   14000470f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004714:	48 89 cb             	mov    rbx,rcx
   140004717:	db 2b                	fld    TBYTE PTR [rbx]
   140004719:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000471c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004720:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004724:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004727:	85 c0                	test   eax,eax
   140004729:	79 0b                	jns    140004736 <__pformat_float+0x2d>
   14000472b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000472f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004736:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000473a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000473d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004740:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004743:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   140004747:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000474b:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000474f:	4d 89 c1             	mov    r9,r8
   140004752:	49 89 c8             	mov    r8,rcx
   140004755:	48 89 c1             	mov    rcx,rax
   140004758:	e8 93 f7 ff ff       	call   140003ef0 <__pformat_fcvt>
   14000475d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004761:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004764:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   140004769:	75 17                	jne    140004782 <__pformat_float+0x79>
   14000476b:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000476e:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004772:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004776:	49 89 c8             	mov    r8,rcx
   140004779:	89 c1                	mov    ecx,eax
   14000477b:	e8 74 f9 ff ff       	call   1400040f4 <__pformat_emit_inf_or_nan>
   140004780:	eb 43                	jmp    1400047c5 <__pformat_float+0xbc>
   140004782:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004785:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004788:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000478c:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004790:	4d 89 c1             	mov    r9,r8
   140004793:	41 89 c8             	mov    r8d,ecx
   140004796:	89 c1                	mov    ecx,eax
   140004798:	e8 42 fa ff ff       	call   1400041df <__pformat_emit_float>
   14000479d:	eb 11                	jmp    1400047b0 <__pformat_float+0xa7>
   14000479f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047a3:	48 89 c2             	mov    rdx,rax
   1400047a6:	b9 20 00 00 00       	mov    ecx,0x20
   1400047ab:	e8 50 ea ff ff       	call   140003200 <__pformat_putc>
   1400047b0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047b4:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400047b7:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400047ba:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400047be:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400047c1:	85 c0                	test   eax,eax
   1400047c3:	7f da                	jg     14000479f <__pformat_float+0x96>
   1400047c5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400047c9:	48 89 c1             	mov    rcx,rax
   1400047cc:	e8 4e 17 00 00       	call   140005f1f <__freedtoa>
   1400047d1:	90                   	nop
   1400047d2:	48 83 c4 58          	add    rsp,0x58
   1400047d6:	5b                   	pop    rbx
   1400047d7:	5d                   	pop    rbp
   1400047d8:	c3                   	ret

00000001400047d9 <__pformat_efloat>:
   1400047d9:	55                   	push   rbp
   1400047da:	53                   	push   rbx
   1400047db:	48 83 ec 58          	sub    rsp,0x58
   1400047df:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400047e4:	48 89 cb             	mov    rbx,rcx
   1400047e7:	db 2b                	fld    TBYTE PTR [rbx]
   1400047e9:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400047ec:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400047f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047f4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400047f7:	85 c0                	test   eax,eax
   1400047f9:	79 0b                	jns    140004806 <__pformat_efloat+0x2d>
   1400047fb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047ff:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004806:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000480a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000480d:	8d 50 01             	lea    edx,[rax+0x1]
   140004810:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004813:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004816:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000481a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000481e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004822:	4d 89 c1             	mov    r9,r8
   140004825:	49 89 c8             	mov    r8,rcx
   140004828:	48 89 c1             	mov    rcx,rax
   14000482b:	e8 6e f6 ff ff       	call   140003e9e <__pformat_ecvt>
   140004830:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004834:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004837:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000483c:	75 17                	jne    140004855 <__pformat_efloat+0x7c>
   14000483e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004841:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004845:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004849:	49 89 c8             	mov    r8,rcx
   14000484c:	89 c1                	mov    ecx,eax
   14000484e:	e8 a1 f8 ff ff       	call   1400040f4 <__pformat_emit_inf_or_nan>
   140004853:	eb 1b                	jmp    140004870 <__pformat_efloat+0x97>
   140004855:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004858:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000485b:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000485f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004863:	4d 89 c1             	mov    r9,r8
   140004866:	41 89 c8             	mov    r8d,ecx
   140004869:	89 c1                	mov    ecx,eax
   14000486b:	e8 39 fd ff ff       	call   1400045a9 <__pformat_emit_efloat>
   140004870:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004874:	48 89 c1             	mov    rcx,rax
   140004877:	e8 a3 16 00 00       	call   140005f1f <__freedtoa>
   14000487c:	90                   	nop
   14000487d:	48 83 c4 58          	add    rsp,0x58
   140004881:	5b                   	pop    rbx
   140004882:	5d                   	pop    rbp
   140004883:	c3                   	ret

0000000140004884 <__pformat_gfloat>:
   140004884:	55                   	push   rbp
   140004885:	53                   	push   rbx
   140004886:	48 83 ec 58          	sub    rsp,0x58
   14000488a:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000488f:	48 89 cb             	mov    rbx,rcx
   140004892:	db 2b                	fld    TBYTE PTR [rbx]
   140004894:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140004897:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000489b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000489f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048a2:	85 c0                	test   eax,eax
   1400048a4:	79 0d                	jns    1400048b3 <__pformat_gfloat+0x2f>
   1400048a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048aa:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400048b1:	eb 16                	jmp    1400048c9 <__pformat_gfloat+0x45>
   1400048b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048b7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048ba:	85 c0                	test   eax,eax
   1400048bc:	75 0b                	jne    1400048c9 <__pformat_gfloat+0x45>
   1400048be:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048c2:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   1400048c9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048cd:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400048d0:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400048d3:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400048d6:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400048da:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400048de:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400048e2:	4d 89 c1             	mov    r9,r8
   1400048e5:	49 89 c8             	mov    r8,rcx
   1400048e8:	48 89 c1             	mov    rcx,rax
   1400048eb:	e8 ae f5 ff ff       	call   140003e9e <__pformat_ecvt>
   1400048f0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400048f4:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048f7:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400048fc:	75 1a                	jne    140004918 <__pformat_gfloat+0x94>
   1400048fe:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004901:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004905:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004909:	49 89 c8             	mov    r8,rcx
   14000490c:	89 c1                	mov    ecx,eax
   14000490e:	e8 e1 f7 ff ff       	call   1400040f4 <__pformat_emit_inf_or_nan>
   140004913:	e9 14 01 00 00       	jmp    140004a2c <__pformat_gfloat+0x1a8>
   140004918:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000491b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000491e:	0f 8c b2 00 00 00    	jl     1400049d6 <__pformat_gfloat+0x152>
   140004924:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004928:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000492b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000492e:	39 c2                	cmp    edx,eax
   140004930:	0f 8c a0 00 00 00    	jl     1400049d6 <__pformat_gfloat+0x152>
   140004936:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000493a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000493d:	25 00 08 00 00       	and    eax,0x800
   140004942:	85 c0                	test   eax,eax
   140004944:	74 15                	je     14000495b <__pformat_gfloat+0xd7>
   140004946:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000494a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000494d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004950:	29 c2                	sub    edx,eax
   140004952:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004956:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004959:	eb 20                	jmp    14000497b <__pformat_gfloat+0xf7>
   14000495b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000495f:	48 89 c1             	mov    rcx,rax
   140004962:	e8 81 4d 00 00       	call   1400096e8 <strlen>
   140004967:	89 c1                	mov    ecx,eax
   140004969:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000496c:	89 c2                	mov    edx,eax
   14000496e:	89 c8                	mov    eax,ecx
   140004970:	29 d0                	sub    eax,edx
   140004972:	89 c2                	mov    edx,eax
   140004974:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004978:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000497b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000497f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004982:	85 c0                	test   eax,eax
   140004984:	79 0b                	jns    140004991 <__pformat_gfloat+0x10d>
   140004986:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000498a:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   140004991:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004994:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004997:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000499b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   14000499f:	4d 89 c1             	mov    r9,r8
   1400049a2:	41 89 c8             	mov    r8d,ecx
   1400049a5:	89 c1                	mov    ecx,eax
   1400049a7:	e8 33 f8 ff ff       	call   1400041df <__pformat_emit_float>
   1400049ac:	eb 11                	jmp    1400049bf <__pformat_gfloat+0x13b>
   1400049ae:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049b2:	48 89 c2             	mov    rdx,rax
   1400049b5:	b9 20 00 00 00       	mov    ecx,0x20
   1400049ba:	e8 41 e8 ff ff       	call   140003200 <__pformat_putc>
   1400049bf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049c3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400049c6:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400049c9:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400049cd:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400049d0:	85 c0                	test   eax,eax
   1400049d2:	7f da                	jg     1400049ae <__pformat_gfloat+0x12a>
   1400049d4:	eb 56                	jmp    140004a2c <__pformat_gfloat+0x1a8>
   1400049d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049da:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400049dd:	25 00 08 00 00       	and    eax,0x800
   1400049e2:	85 c0                	test   eax,eax
   1400049e4:	74 13                	je     1400049f9 <__pformat_gfloat+0x175>
   1400049e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049ea:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049ed:	8d 50 ff             	lea    edx,[rax-0x1]
   1400049f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049f4:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049f7:	eb 18                	jmp    140004a11 <__pformat_gfloat+0x18d>
   1400049f9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400049fd:	48 89 c1             	mov    rcx,rax
   140004a00:	e8 e3 4c 00 00       	call   1400096e8 <strlen>
   140004a05:	83 e8 01             	sub    eax,0x1
   140004a08:	89 c2                	mov    edx,eax
   140004a0a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a0e:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a11:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004a14:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004a17:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   140004a1b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004a1f:	4d 89 c1             	mov    r9,r8
   140004a22:	41 89 c8             	mov    r8d,ecx
   140004a25:	89 c1                	mov    ecx,eax
   140004a27:	e8 7d fb ff ff       	call   1400045a9 <__pformat_emit_efloat>
   140004a2c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a30:	48 89 c1             	mov    rcx,rax
   140004a33:	e8 e7 14 00 00       	call   140005f1f <__freedtoa>
   140004a38:	90                   	nop
   140004a39:	48 83 c4 58          	add    rsp,0x58
   140004a3d:	5b                   	pop    rbx
   140004a3e:	5d                   	pop    rbp
   140004a3f:	c3                   	ret

0000000140004a40 <__pformat_emit_xfloat>:
   140004a40:	55                   	push   rbp
   140004a41:	53                   	push   rbx
   140004a42:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140004a49:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140004a50:	00 
   140004a51:	48 89 cb             	mov    rbx,rcx
   140004a54:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004a58:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004a5c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004a60:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   140004a66:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a69:	48 85 c0             	test   rax,rax
   140004a6c:	75 09                	jne    140004a77 <__pformat_emit_xfloat+0x37>
   140004a6e:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a72:	66 85 c0             	test   ax,ax
   140004a75:	74 0b                	je     140004a82 <__pformat_emit_xfloat+0x42>
   140004a77:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a7b:	83 e8 03             	sub    eax,0x3
   140004a7e:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004a82:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a86:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a89:	85 c0                	test   eax,eax
   140004a8b:	0f 88 90 00 00 00    	js     140004b21 <__pformat_emit_xfloat+0xe1>
   140004a91:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a95:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a98:	83 f8 0e             	cmp    eax,0xe
   140004a9b:	0f 8f 80 00 00 00    	jg     140004b21 <__pformat_emit_xfloat+0xe1>
   140004aa1:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004aa4:	48 d1 e8             	shr    rax,1
   140004aa7:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004aaa:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004aad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ab1:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ab4:	b9 0e 00 00 00       	mov    ecx,0xe
   140004ab9:	29 c1                	sub    ecx,eax
   140004abb:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004ac2:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004ac8:	89 c1                	mov    ecx,eax
   140004aca:	49 d3 e0             	shl    r8,cl
   140004acd:	4c 89 c0             	mov    rax,r8
   140004ad0:	48 01 d0             	add    rax,rdx
   140004ad3:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004ad6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ad9:	48 85 c0             	test   rax,rax
   140004adc:	78 0b                	js     140004ae9 <__pformat_emit_xfloat+0xa9>
   140004ade:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ae1:	48 01 c0             	add    rax,rax
   140004ae4:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004ae7:	eb 15                	jmp    140004afe <__pformat_emit_xfloat+0xbe>
   140004ae9:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004aed:	83 c0 04             	add    eax,0x4
   140004af0:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004af4:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004af7:	48 c1 e8 03          	shr    rax,0x3
   140004afb:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004afe:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004b01:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b05:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b08:	b9 0f 00 00 00       	mov    ecx,0xf
   140004b0d:	29 c1                	sub    ecx,eax
   140004b0f:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004b16:	89 c1                	mov    ecx,eax
   140004b18:	48 d3 ea             	shr    rdx,cl
   140004b1b:	48 89 d0             	mov    rax,rdx
   140004b1e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b21:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b24:	48 85 c0             	test   rax,rax
   140004b27:	75 0f                	jne    140004b38 <__pformat_emit_xfloat+0xf8>
   140004b29:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b2d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b30:	85 c0                	test   eax,eax
   140004b32:	0f 8e f8 00 00 00    	jle    140004c30 <__pformat_emit_xfloat+0x1f0>
   140004b38:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b3c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b3f:	83 f8 0e             	cmp    eax,0xe
   140004b42:	7f 1a                	jg     140004b5e <__pformat_emit_xfloat+0x11e>
   140004b44:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b48:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b4b:	85 c0                	test   eax,eax
   140004b4d:	78 0f                	js     140004b5e <__pformat_emit_xfloat+0x11e>
   140004b4f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b53:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b56:	83 c0 01             	add    eax,0x1
   140004b59:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004b5c:	eb 07                	jmp    140004b65 <__pformat_emit_xfloat+0x125>
   140004b5e:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004b65:	e9 bc 00 00 00       	jmp    140004c26 <__pformat_emit_xfloat+0x1e6>
   140004b6a:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b6d:	83 e0 0f             	and    eax,0xf
   140004b70:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004b73:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004b77:	75 36                	jne    140004baf <__pformat_emit_xfloat+0x16f>
   140004b79:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b7d:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b81:	72 1b                	jb     140004b9e <__pformat_emit_xfloat+0x15e>
   140004b83:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b87:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b8a:	25 00 08 00 00       	and    eax,0x800
   140004b8f:	85 c0                	test   eax,eax
   140004b91:	75 0b                	jne    140004b9e <__pformat_emit_xfloat+0x15e>
   140004b93:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b97:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b9a:	85 c0                	test   eax,eax
   140004b9c:	7e 2d                	jle    140004bcb <__pformat_emit_xfloat+0x18b>
   140004b9e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004ba2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004ba6:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004baa:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004bad:	eb 1c                	jmp    140004bcb <__pformat_emit_xfloat+0x18b>
   140004baf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bb3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bb6:	85 c0                	test   eax,eax
   140004bb8:	7e 11                	jle    140004bcb <__pformat_emit_xfloat+0x18b>
   140004bba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bbe:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bc1:	8d 50 ff             	lea    edx,[rax-0x1]
   140004bc4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bc8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004bcb:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004bcf:	75 15                	jne    140004be6 <__pformat_emit_xfloat+0x1a6>
   140004bd1:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004bd5:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004bd9:	72 0b                	jb     140004be6 <__pformat_emit_xfloat+0x1a6>
   140004bdb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bdf:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004be2:	85 c0                	test   eax,eax
   140004be4:	78 32                	js     140004c18 <__pformat_emit_xfloat+0x1d8>
   140004be6:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004bea:	76 16                	jbe    140004c02 <__pformat_emit_xfloat+0x1c2>
   140004bec:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004bef:	8d 50 37             	lea    edx,[rax+0x37]
   140004bf2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bf6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004bf9:	83 e0 20             	and    eax,0x20
   140004bfc:	09 d0                	or     eax,edx
   140004bfe:	89 c1                	mov    ecx,eax
   140004c00:	eb 08                	jmp    140004c0a <__pformat_emit_xfloat+0x1ca>
   140004c02:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004c05:	83 c0 30             	add    eax,0x30
   140004c08:	89 c1                	mov    ecx,eax
   140004c0a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c0e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c12:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c16:	88 08                	mov    BYTE PTR [rax],cl
   140004c18:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004c1b:	48 c1 e8 04          	shr    rax,0x4
   140004c1f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004c22:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004c26:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004c2a:	0f 8f 3a ff ff ff    	jg     140004b6a <__pformat_emit_xfloat+0x12a>
   140004c30:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c34:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004c38:	75 39                	jne    140004c73 <__pformat_emit_xfloat+0x233>
   140004c3a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c3e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c41:	85 c0                	test   eax,eax
   140004c43:	7f 10                	jg     140004c55 <__pformat_emit_xfloat+0x215>
   140004c45:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c49:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c4c:	25 00 08 00 00       	and    eax,0x800
   140004c51:	85 c0                	test   eax,eax
   140004c53:	74 0f                	je     140004c64 <__pformat_emit_xfloat+0x224>
   140004c55:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c59:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c5d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c61:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004c64:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c68:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c6c:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c70:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004c73:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c77:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c7a:	85 c0                	test   eax,eax
   140004c7c:	0f 8e e3 00 00 00    	jle    140004d65 <__pformat_emit_xfloat+0x325>
   140004c82:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c86:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004c8a:	48 29 c2             	sub    rdx,rax
   140004c8d:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004c90:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004c94:	98                   	cwde
   140004c95:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004c98:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c9c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c9f:	85 c0                	test   eax,eax
   140004ca1:	7e 0a                	jle    140004cad <__pformat_emit_xfloat+0x26d>
   140004ca3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ca7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004caa:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004cad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cb1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cb4:	25 c0 01 00 00       	and    eax,0x1c0
   140004cb9:	85 c0                	test   eax,eax
   140004cbb:	74 07                	je     140004cc4 <__pformat_emit_xfloat+0x284>
   140004cbd:	b8 06 00 00 00       	mov    eax,0x6
   140004cc2:	eb 05                	jmp    140004cc9 <__pformat_emit_xfloat+0x289>
   140004cc4:	b8 05 00 00 00       	mov    eax,0x5
   140004cc9:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004ccc:	eb 0f                	jmp    140004cdd <__pformat_emit_xfloat+0x29d>
   140004cce:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004cd2:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004cd6:	83 c0 01             	add    eax,0x1
   140004cd9:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004cdd:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004ce0:	48 63 d0             	movsxd rdx,eax
   140004ce3:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004cea:	48 c1 ea 20          	shr    rdx,0x20
   140004cee:	89 d1                	mov    ecx,edx
   140004cf0:	c1 f9 02             	sar    ecx,0x2
   140004cf3:	99                   	cdq
   140004cf4:	89 c8                	mov    eax,ecx
   140004cf6:	29 d0                	sub    eax,edx
   140004cf8:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004cfb:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004cff:	75 cd                	jne    140004cce <__pformat_emit_xfloat+0x28e>
   140004d01:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d05:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d08:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004d0b:	7d 4d                	jge    140004d5a <__pformat_emit_xfloat+0x31a>
   140004d0d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d11:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d14:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004d17:	89 c2                	mov    edx,eax
   140004d19:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d1d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004d20:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d24:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d27:	25 00 06 00 00       	and    eax,0x600
   140004d2c:	85 c0                	test   eax,eax
   140004d2e:	75 35                	jne    140004d65 <__pformat_emit_xfloat+0x325>
   140004d30:	eb 11                	jmp    140004d43 <__pformat_emit_xfloat+0x303>
   140004d32:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d36:	48 89 c2             	mov    rdx,rax
   140004d39:	b9 20 00 00 00       	mov    ecx,0x20
   140004d3e:	e8 bd e4 ff ff       	call   140003200 <__pformat_putc>
   140004d43:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d47:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d4a:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004d4d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d51:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004d54:	85 c0                	test   eax,eax
   140004d56:	7f da                	jg     140004d32 <__pformat_emit_xfloat+0x2f2>
   140004d58:	eb 0b                	jmp    140004d65 <__pformat_emit_xfloat+0x325>
   140004d5a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d5e:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004d65:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d69:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d6c:	25 80 00 00 00       	and    eax,0x80
   140004d71:	85 c0                	test   eax,eax
   140004d73:	74 13                	je     140004d88 <__pformat_emit_xfloat+0x348>
   140004d75:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d79:	48 89 c2             	mov    rdx,rax
   140004d7c:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004d81:	e8 7a e4 ff ff       	call   140003200 <__pformat_putc>
   140004d86:	eb 42                	jmp    140004dca <__pformat_emit_xfloat+0x38a>
   140004d88:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d8c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d8f:	25 00 01 00 00       	and    eax,0x100
   140004d94:	85 c0                	test   eax,eax
   140004d96:	74 13                	je     140004dab <__pformat_emit_xfloat+0x36b>
   140004d98:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d9c:	48 89 c2             	mov    rdx,rax
   140004d9f:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004da4:	e8 57 e4 ff ff       	call   140003200 <__pformat_putc>
   140004da9:	eb 1f                	jmp    140004dca <__pformat_emit_xfloat+0x38a>
   140004dab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004daf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004db2:	83 e0 40             	and    eax,0x40
   140004db5:	85 c0                	test   eax,eax
   140004db7:	74 11                	je     140004dca <__pformat_emit_xfloat+0x38a>
   140004db9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dbd:	48 89 c2             	mov    rdx,rax
   140004dc0:	b9 20 00 00 00       	mov    ecx,0x20
   140004dc5:	e8 36 e4 ff ff       	call   140003200 <__pformat_putc>
   140004dca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dce:	48 89 c2             	mov    rdx,rax
   140004dd1:	b9 30 00 00 00       	mov    ecx,0x30
   140004dd6:	e8 25 e4 ff ff       	call   140003200 <__pformat_putc>
   140004ddb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ddf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004de2:	83 e0 20             	and    eax,0x20
   140004de5:	83 c8 58             	or     eax,0x58
   140004de8:	89 c1                	mov    ecx,eax
   140004dea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dee:	48 89 c2             	mov    rdx,rax
   140004df1:	e8 0a e4 ff ff       	call   140003200 <__pformat_putc>
   140004df6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dfa:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004dfd:	85 c0                	test   eax,eax
   140004dff:	7e 54                	jle    140004e55 <__pformat_emit_xfloat+0x415>
   140004e01:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e05:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e08:	25 00 02 00 00       	and    eax,0x200
   140004e0d:	85 c0                	test   eax,eax
   140004e0f:	74 44                	je     140004e55 <__pformat_emit_xfloat+0x415>
   140004e11:	eb 11                	jmp    140004e24 <__pformat_emit_xfloat+0x3e4>
   140004e13:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e17:	48 89 c2             	mov    rdx,rax
   140004e1a:	b9 30 00 00 00       	mov    ecx,0x30
   140004e1f:	e8 dc e3 ff ff       	call   140003200 <__pformat_putc>
   140004e24:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e28:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e2b:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e2e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e32:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004e35:	85 c0                	test   eax,eax
   140004e37:	7f da                	jg     140004e13 <__pformat_emit_xfloat+0x3d3>
   140004e39:	eb 1a                	jmp    140004e55 <__pformat_emit_xfloat+0x415>
   140004e3b:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004e40:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004e44:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004e47:	0f be c0             	movsx  eax,al
   140004e4a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e4e:	89 c1                	mov    ecx,eax
   140004e50:	e8 32 f2 ff ff       	call   140004087 <__pformat_emit_numeric_value>
   140004e55:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004e59:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004e5d:	72 dc                	jb     140004e3b <__pformat_emit_xfloat+0x3fb>
   140004e5f:	eb 11                	jmp    140004e72 <__pformat_emit_xfloat+0x432>
   140004e61:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e65:	48 89 c2             	mov    rdx,rax
   140004e68:	b9 30 00 00 00       	mov    ecx,0x30
   140004e6d:	e8 8e e3 ff ff       	call   140003200 <__pformat_putc>
   140004e72:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e76:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004e79:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e7c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e80:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004e83:	85 c0                	test   eax,eax
   140004e85:	7f da                	jg     140004e61 <__pformat_emit_xfloat+0x421>
   140004e87:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e8b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e8e:	83 e0 20             	and    eax,0x20
   140004e91:	83 c8 50             	or     eax,0x50
   140004e94:	89 c1                	mov    ecx,eax
   140004e96:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e9a:	48 89 c2             	mov    rdx,rax
   140004e9d:	e8 5e e3 ff ff       	call   140003200 <__pformat_putc>
   140004ea2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ea6:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004ea9:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004ead:	01 c2                	add    edx,eax
   140004eaf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eb3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004eb6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eba:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ebd:	0d c0 01 00 00       	or     eax,0x1c0
   140004ec2:	89 c2                	mov    edx,eax
   140004ec4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ec8:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004ecb:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004ecf:	66 85 c0             	test   ax,ax
   140004ed2:	79 09                	jns    140004edd <__pformat_emit_xfloat+0x49d>
   140004ed4:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004edb:	eb 05                	jmp    140004ee2 <__pformat_emit_xfloat+0x4a2>
   140004edd:	b8 00 00 00 00       	mov    eax,0x0
   140004ee2:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004ee6:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004eea:	48 0f bf c0          	movsx  rax,ax
   140004eee:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004ef2:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004ef6:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004efa:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004efe:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004f02:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004f06:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004f0a:	48 89 c1             	mov    rcx,rax
   140004f0d:	e8 59 e7 ff ff       	call   14000366b <__pformat_int>
   140004f12:	90                   	nop
   140004f13:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004f1a:	5b                   	pop    rbx
   140004f1b:	5d                   	pop    rbp
   140004f1c:	c3                   	ret

0000000140004f1d <__pformat_xldouble>:
   140004f1d:	55                   	push   rbp
   140004f1e:	53                   	push   rbx
   140004f1f:	48 83 ec 78          	sub    rsp,0x78
   140004f23:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004f28:	48 89 cb             	mov    rbx,rcx
   140004f2b:	db 2b                	fld    TBYTE PTR [rbx]
   140004f2d:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004f30:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004f34:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004f3b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004f3f:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f42:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f45:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004f49:	48 89 c1             	mov    rcx,rax
   140004f4c:	e8 e5 ed ff ff       	call   140003d36 <init_fpreg_ldouble>
   140004f51:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f54:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f57:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f5b:	48 89 c1             	mov    rcx,rax
   140004f5e:	e8 ed 3d 00 00       	call   140008d50 <__isnanl>
   140004f63:	85 c0                	test   eax,eax
   140004f65:	74 1d                	je     140004f84 <__pformat_xldouble+0x67>
   140004f67:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f6a:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f6e:	48 8d 15 d1 63 00 00 	lea    rdx,[rip+0x63d1]        # 14000b346 <.rdata+0x16>
   140004f75:	49 89 c8             	mov    r8,rcx
   140004f78:	89 c1                	mov    ecx,eax
   140004f7a:	e8 75 f1 ff ff       	call   1400040f4 <__pformat_emit_inf_or_nan>
   140004f7f:	e9 aa 00 00 00       	jmp    14000502e <__pformat_xldouble+0x111>
   140004f84:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f88:	98                   	cwde
   140004f89:	25 00 80 00 00       	and    eax,0x8000
   140004f8e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004f91:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004f95:	74 12                	je     140004fa9 <__pformat_xldouble+0x8c>
   140004f97:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f9b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004f9e:	0c 80                	or     al,0x80
   140004fa0:	89 c2                	mov    edx,eax
   140004fa2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004fa6:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004fa9:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004fac:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004faf:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004fb3:	48 89 c1             	mov    rcx,rax
   140004fb6:	e8 a5 3c 00 00       	call   140008c60 <__fpclassifyl>
   140004fbb:	3d 00 05 00 00       	cmp    eax,0x500
   140004fc0:	75 1a                	jne    140004fdc <__pformat_xldouble+0xbf>
   140004fc2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004fc5:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004fc9:	48 8d 15 7a 63 00 00 	lea    rdx,[rip+0x637a]        # 14000b34a <.rdata+0x1a>
   140004fd0:	49 89 c8             	mov    r8,rcx
   140004fd3:	89 c1                	mov    ecx,eax
   140004fd5:	e8 1a f1 ff ff       	call   1400040f4 <__pformat_emit_inf_or_nan>
   140004fda:	eb 52                	jmp    14000502e <__pformat_xldouble+0x111>
   140004fdc:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fe0:	66 25 ff 7f          	and    ax,0x7fff
   140004fe4:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004fe8:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fec:	66 85 c0             	test   ax,ax
   140004fef:	75 11                	jne    140005002 <__pformat_xldouble+0xe5>
   140004ff1:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004ff5:	48 85 c0             	test   rax,rax
   140004ff8:	74 14                	je     14000500e <__pformat_xldouble+0xf1>
   140004ffa:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140005000:	eb 0c                	jmp    14000500e <__pformat_xldouble+0xf1>
   140005002:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005006:	66 2d ff 3f          	sub    ax,0x3fff
   14000500a:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000500e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005012:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005016:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000501a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   14000501e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140005022:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140005026:	48 89 c1             	mov    rcx,rax
   140005029:	e8 12 fa ff ff       	call   140004a40 <__pformat_emit_xfloat>
   14000502e:	90                   	nop
   14000502f:	48 83 c4 78          	add    rsp,0x78
   140005033:	5b                   	pop    rbx
   140005034:	5d                   	pop    rbp
   140005035:	c3                   	ret

0000000140005036 <__pformat_xdouble>:
   140005036:	55                   	push   rbp
   140005037:	48 89 e5             	mov    rbp,rsp
   14000503a:	48 83 ec 60          	sub    rsp,0x60
   14000503e:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140005043:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005047:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000504e:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140005051:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140005055:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140005058:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   14000505c:	48 89 c1             	mov    rcx,rax
   14000505f:	e8 d2 ec ff ff       	call   140003d36 <init_fpreg_ldouble>
   140005064:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005068:	66 48 0f 6e c0       	movq   xmm0,rax
   14000506d:	e8 7e 3c 00 00       	call   140008cf0 <__isnan>
   140005072:	85 c0                	test   eax,eax
   140005074:	74 1d                	je     140005093 <__pformat_xdouble+0x5d>
   140005076:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005079:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   14000507d:	48 8d 15 c2 62 00 00 	lea    rdx,[rip+0x62c2]        # 14000b346 <.rdata+0x16>
   140005084:	49 89 c8             	mov    r8,rcx
   140005087:	89 c1                	mov    ecx,eax
   140005089:	e8 66 f0 ff ff       	call   1400040f4 <__pformat_emit_inf_or_nan>
   14000508e:	e9 f9 00 00 00       	jmp    14000518c <__pformat_xdouble+0x156>
   140005093:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005097:	98                   	cwde
   140005098:	25 00 80 00 00       	and    eax,0x8000
   14000509d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400050a0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400050a4:	74 12                	je     1400050b8 <__pformat_xdouble+0x82>
   1400050a6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400050aa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400050ad:	0c 80                	or     al,0x80
   1400050af:	89 c2                	mov    edx,eax
   1400050b1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400050b5:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400050b8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400050bc:	66 48 0f 6e c0       	movq   xmm0,rax
   1400050c1:	e8 1a 3b 00 00       	call   140008be0 <__fpclassify>
   1400050c6:	3d 00 05 00 00       	cmp    eax,0x500
   1400050cb:	75 1d                	jne    1400050ea <__pformat_xdouble+0xb4>
   1400050cd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400050d0:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   1400050d4:	48 8d 15 6f 62 00 00 	lea    rdx,[rip+0x626f]        # 14000b34a <.rdata+0x1a>
   1400050db:	49 89 c8             	mov    r8,rcx
   1400050de:	89 c1                	mov    ecx,eax
   1400050e0:	e8 0f f0 ff ff       	call   1400040f4 <__pformat_emit_inf_or_nan>
   1400050e5:	e9 a2 00 00 00       	jmp    14000518c <__pformat_xdouble+0x156>
   1400050ea:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050ee:	66 25 ff 7f          	and    ax,0x7fff
   1400050f2:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400050f6:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050fa:	66 85 c0             	test   ax,ax
   1400050fd:	74 3b                	je     14000513a <__pformat_xdouble+0x104>
   1400050ff:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005103:	66 3d 00 3c          	cmp    ax,0x3c00
   140005107:	7f 31                	jg     14000513a <__pformat_xdouble+0x104>
   140005109:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000510d:	98                   	cwde
   14000510e:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005113:	29 c2                	sub    edx,eax
   140005115:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005118:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000511c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000511f:	89 c1                	mov    ecx,eax
   140005121:	48 d3 ea             	shr    rdx,cl
   140005124:	48 89 d0             	mov    rax,rdx
   140005127:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000512b:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000512f:	89 c2                	mov    edx,eax
   140005131:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005134:	01 d0                	add    eax,edx
   140005136:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000513a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000513e:	66 85 c0             	test   ax,ax
   140005141:	75 11                	jne    140005154 <__pformat_xdouble+0x11e>
   140005143:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005147:	48 85 c0             	test   rax,rax
   14000514a:	74 14                	je     140005160 <__pformat_xdouble+0x12a>
   14000514c:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   140005152:	eb 0c                	jmp    140005160 <__pformat_xdouble+0x12a>
   140005154:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005158:	66 2d fc 3f          	sub    ax,0x3ffc
   14000515c:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005160:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005164:	48 c1 e8 03          	shr    rax,0x3
   140005168:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000516c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005170:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005174:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005178:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   14000517c:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140005180:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140005184:	48 89 c1             	mov    rcx,rax
   140005187:	e8 b4 f8 ff ff       	call   140004a40 <__pformat_emit_xfloat>
   14000518c:	90                   	nop
   14000518d:	48 83 c4 60          	add    rsp,0x60
   140005191:	5d                   	pop    rbp
   140005192:	c3                   	ret

0000000140005193 <__mingw_pformat>:
   140005193:	55                   	push   rbp
   140005194:	48 89 e5             	mov    rbp,rsp
   140005197:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   14000519e:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400051a1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400051a5:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400051a9:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400051ad:	e8 a6 44 00 00       	call   140009658 <_errno>
   1400051b2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400051b4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400051b7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400051bb:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   1400051bf:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   1400051c6:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400051c9:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400051cc:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   1400051d3:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400051da:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   1400051e1:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   1400051e7:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   1400051ee:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   1400051f4:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   1400051fb:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400051fe:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   140005201:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   140005208:	e9 27 0c 00 00       	jmp    140005e34 <__mingw_pformat+0xca1>
   14000520d:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005211:	0f 85 0f 0c 00 00    	jne    140005e26 <__mingw_pformat+0xc93>
   140005217:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000521e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005225:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005229:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000522d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005231:	48 83 c0 0c          	add    rax,0xc
   140005235:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005239:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000523c:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000523f:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005246:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140005249:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000524c:	e9 c4 0b 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005251:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005255:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005259:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000525d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005260:	0f be c0             	movsx  eax,al
   140005263:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005266:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   14000526a:	0f 84 94 09 00 00    	je     140005c04 <__mingw_pformat+0xa71>
   140005270:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   140005274:	0f 8f 02 0b 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000527a:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   14000527e:	0f 84 eb 03 00 00    	je     14000566f <__mingw_pformat+0x4dc>
   140005284:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   140005288:	0f 8f ee 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000528e:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   140005292:	0f 84 31 09 00 00    	je     140005bc9 <__mingw_pformat+0xa36>
   140005298:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   14000529c:	0f 8f da 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400052a2:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400052a6:	0f 84 c3 03 00 00    	je     14000566f <__mingw_pformat+0x4dc>
   1400052ac:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400052b0:	0f 8f c6 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400052b6:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   1400052ba:	0f 84 31 09 00 00    	je     140005bf1 <__mingw_pformat+0xa5e>
   1400052c0:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   1400052c4:	0f 8f b2 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400052ca:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   1400052ce:	0f 84 31 03 00 00    	je     140005605 <__mingw_pformat+0x472>
   1400052d4:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   1400052d8:	0f 8f 9e 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400052de:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   1400052e2:	0f 84 28 05 00 00    	je     140005810 <__mingw_pformat+0x67d>
   1400052e8:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   1400052ec:	0f 8f 8a 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400052f2:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   1400052f6:	0f 84 73 03 00 00    	je     14000566f <__mingw_pformat+0x4dc>
   1400052fc:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005300:	0f 8f 76 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   140005306:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   14000530a:	0f 84 4d 07 00 00    	je     140005a5d <__mingw_pformat+0x8ca>
   140005310:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005314:	0f 8f 62 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000531a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000531e:	0f 84 2d 03 00 00    	je     140005651 <__mingw_pformat+0x4be>
   140005324:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   140005328:	0f 8f 4e 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000532e:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   140005332:	0f 84 65 08 00 00    	je     140005b9d <__mingw_pformat+0xa0a>
   140005338:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   14000533c:	0f 8f 3a 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   140005342:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005346:	0f 84 db 07 00 00    	je     140005b27 <__mingw_pformat+0x994>
   14000534c:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005350:	0f 8f 26 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   140005356:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   14000535a:	0f 84 ee 03 00 00    	je     14000574e <__mingw_pformat+0x5bb>
   140005360:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   140005364:	0f 8f 12 0a 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000536a:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   14000536e:	0f 84 87 07 00 00    	je     140005afb <__mingw_pformat+0x968>
   140005374:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   140005378:	0f 8f fe 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000537e:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   140005382:	0f 84 f3 05 00 00    	je     14000597b <__mingw_pformat+0x7e8>
   140005388:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   14000538c:	0f 8f ea 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   140005392:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005396:	0f 84 61 05 00 00    	je     1400058fd <__mingw_pformat+0x76a>
   14000539c:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400053a0:	0f 8f d6 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400053a6:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400053aa:	0f 84 cf 04 00 00    	je     14000587f <__mingw_pformat+0x6ec>
   1400053b0:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400053b4:	0f 8f c2 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400053ba:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   1400053be:	0f 84 8a 03 00 00    	je     14000574e <__mingw_pformat+0x5bb>
   1400053c4:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   1400053c8:	0f 8f ae 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400053ce:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   1400053d2:	0f 84 b5 01 00 00    	je     14000558d <__mingw_pformat+0x3fa>
   1400053d8:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   1400053dc:	0f 8f 9a 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400053e2:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   1400053e6:	0f 84 83 02 00 00    	je     14000566f <__mingw_pformat+0x4dc>
   1400053ec:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   1400053f0:	0f 8f 86 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400053f6:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   1400053fa:	0f 84 f9 05 00 00    	je     1400059f9 <__mingw_pformat+0x866>
   140005400:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   140005404:	0f 8f 72 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000540a:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   14000540e:	0f 84 5b 02 00 00    	je     14000566f <__mingw_pformat+0x4dc>
   140005414:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005418:	0f 8f 5e 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000541e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   140005422:	0f 84 d6 01 00 00    	je     1400055fe <__mingw_pformat+0x46b>
   140005428:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   14000542c:	0f 8f 4a 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   140005432:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005436:	0f 84 a0 07 00 00    	je     140005bdc <__mingw_pformat+0xa49>
   14000543c:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005440:	0f 8f 36 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   140005446:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   14000544a:	0f 84 ea 06 00 00    	je     140005b3a <__mingw_pformat+0x9a7>
   140005450:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   140005454:	0f 8f 22 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000545a:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   14000545e:	0f 84 20 05 00 00    	je     140005984 <__mingw_pformat+0x7f1>
   140005464:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   140005468:	0f 8f 0e 09 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000546e:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   140005472:	0f 84 8e 04 00 00    	je     140005906 <__mingw_pformat+0x773>
   140005478:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   14000547c:	0f 8f fa 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   140005482:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005486:	0f 84 fc 03 00 00    	je     140005888 <__mingw_pformat+0x6f5>
   14000548c:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005490:	0f 8f e6 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   140005496:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   14000549a:	0f 84 e6 00 00 00    	je     140005586 <__mingw_pformat+0x3f3>
   1400054a0:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400054a4:	0f 8f d2 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400054aa:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400054ae:	0f 84 bb 01 00 00    	je     14000566f <__mingw_pformat+0x4dc>
   1400054b4:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400054b8:	0f 8f be 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400054be:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   1400054c2:	0f 84 3a 05 00 00    	je     140005a02 <__mingw_pformat+0x86f>
   1400054c8:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   1400054cc:	0f 8f aa 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400054d2:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   1400054d6:	0f 84 8c 08 00 00    	je     140005d68 <__mingw_pformat+0xbd5>
   1400054dc:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   1400054e0:	0f 8f 96 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400054e6:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   1400054ea:	0f 84 27 07 00 00    	je     140005c17 <__mingw_pformat+0xa84>
   1400054f0:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   1400054f4:	0f 8f 82 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   1400054fa:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   1400054fe:	0f 84 db 07 00 00    	je     140005cdf <__mingw_pformat+0xb4c>
   140005504:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   140005508:	0f 8f 6e 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000550e:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005512:	0f 84 af 07 00 00    	je     140005cc7 <__mingw_pformat+0xb34>
   140005518:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000551c:	0f 8f 5a 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   140005522:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005526:	0f 84 1c 07 00 00    	je     140005c48 <__mingw_pformat+0xab5>
   14000552c:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005530:	0f 8f 46 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   140005536:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   14000553a:	0f 84 b7 07 00 00    	je     140005cf7 <__mingw_pformat+0xb64>
   140005540:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   140005544:	0f 8f 32 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000554a:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   14000554e:	74 23                	je     140005573 <__mingw_pformat+0x3e0>
   140005550:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005554:	0f 8f 22 08 00 00    	jg     140005d7c <__mingw_pformat+0xbe9>
   14000555a:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   14000555e:	0f 84 ec 07 00 00    	je     140005d50 <__mingw_pformat+0xbbd>
   140005564:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   140005568:	0f 84 41 07 00 00    	je     140005caf <__mingw_pformat+0xb1c>
   14000556e:	e9 09 08 00 00       	jmp    140005d7c <__mingw_pformat+0xbe9>
   140005573:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005577:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000557a:	89 c1                	mov    ecx,eax
   14000557c:	e8 7f dc ff ff       	call   140003200 <__pformat_putc>
   140005581:	e9 82 fc ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005586:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   14000558d:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005594:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005598:	74 06                	je     1400055a0 <__mingw_pformat+0x40d>
   14000559a:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000559e:	75 30                	jne    1400055d0 <__mingw_pformat+0x43d>
   1400055a0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055a4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055a8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055ac:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055ae:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   1400055b2:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055b6:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   1400055ba:	49 89 d0             	mov    r8,rdx
   1400055bd:	ba 01 00 00 00       	mov    edx,0x1
   1400055c2:	48 89 c1             	mov    rcx,rax
   1400055c5:	e8 3f de ff ff       	call   140003409 <__pformat_wputchars>
   1400055ca:	90                   	nop
   1400055cb:	e9 38 fc ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   1400055d0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055d4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055d8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055dc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055de:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   1400055e1:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055e5:	48 8d 45 90          	lea    rax,[rbp-0x70]
   1400055e9:	49 89 d0             	mov    r8,rdx
   1400055ec:	ba 01 00 00 00       	mov    edx,0x1
   1400055f1:	48 89 c1             	mov    rcx,rax
   1400055f4:	e8 8b dc ff ff       	call   140003284 <__pformat_putchars>
   1400055f9:	e9 0a fc ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   1400055fe:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005605:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005609:	74 06                	je     140005611 <__mingw_pformat+0x47e>
   14000560b:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000560f:	75 20                	jne    140005631 <__mingw_pformat+0x49e>
   140005611:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005615:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005619:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000561d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005620:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005624:	48 89 c1             	mov    rcx,rax
   140005627:	e8 29 df ff ff       	call   140003555 <__pformat_wcputs>
   14000562c:	e9 d7 fb ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005631:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005635:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005639:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000563d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005640:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005644:	48 89 c1             	mov    rcx,rax
   140005647:	e8 37 dd ff ff       	call   140003383 <__pformat_puts>
   14000564c:	e9 b7 fb ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005651:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140005654:	89 c1                	mov    ecx,eax
   140005656:	e8 85 40 00 00       	call   1400096e0 <strerror>
   14000565b:	48 89 c1             	mov    rcx,rax
   14000565e:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005662:	48 89 c2             	mov    rdx,rax
   140005665:	e8 19 dd ff ff       	call   140003383 <__pformat_puts>
   14000566a:	e9 99 fb ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   14000566f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005672:	80 e4 fe             	and    ah,0xfe
   140005675:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005678:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000567c:	75 15                	jne    140005693 <__mingw_pformat+0x500>
   14000567e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005682:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005686:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000568a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000568d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005691:	eb 54                	jmp    1400056e7 <__mingw_pformat+0x554>
   140005693:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005697:	75 16                	jne    1400056af <__mingw_pformat+0x51c>
   140005699:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000569d:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056a1:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056a5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056a7:	89 c0                	mov    eax,eax
   1400056a9:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056ad:	eb 38                	jmp    1400056e7 <__mingw_pformat+0x554>
   1400056af:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056b3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056b7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056bb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056bd:	89 c0                	mov    eax,eax
   1400056bf:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056c3:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400056c7:	75 0d                	jne    1400056d6 <__mingw_pformat+0x543>
   1400056c9:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   1400056cd:	0f b7 c0             	movzx  eax,ax
   1400056d0:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056d4:	eb 11                	jmp    1400056e7 <__mingw_pformat+0x554>
   1400056d6:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400056da:	75 0b                	jne    1400056e7 <__mingw_pformat+0x554>
   1400056dc:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   1400056e0:	0f b6 c0             	movzx  eax,al
   1400056e3:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056e7:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400056eb:	75 2e                	jne    14000571b <__mingw_pformat+0x588>
   1400056ed:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400056f1:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400056f5:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400056fc:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005703:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005707:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000570e:	48 89 c1             	mov    rcx,rax
   140005711:	e8 55 df ff ff       	call   14000366b <__pformat_int>
   140005716:	e9 ed fa ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   14000571b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000571f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005723:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000572a:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005731:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140005735:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   14000573c:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000573f:	49 89 c8             	mov    r8,rcx
   140005742:	89 c1                	mov    ecx,eax
   140005744:	e8 a5 e2 ff ff       	call   1400039ee <__pformat_xint>
   140005749:	e9 ba fa ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   14000574e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005751:	0c 80                	or     al,0x80
   140005753:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005756:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000575a:	75 15                	jne    140005771 <__mingw_pformat+0x5de>
   14000575c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005760:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005764:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005768:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000576b:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000576f:	eb 56                	jmp    1400057c7 <__mingw_pformat+0x634>
   140005771:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005775:	75 16                	jne    14000578d <__mingw_pformat+0x5fa>
   140005777:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000577b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000577f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005783:	8b 00                	mov    eax,DWORD PTR [rax]
   140005785:	48 98                	cdqe
   140005787:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000578b:	eb 3a                	jmp    1400057c7 <__mingw_pformat+0x634>
   14000578d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005791:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005795:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005799:	8b 00                	mov    eax,DWORD PTR [rax]
   14000579b:	48 98                	cdqe
   14000579d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057a1:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400057a5:	75 0e                	jne    1400057b5 <__mingw_pformat+0x622>
   1400057a7:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   1400057ab:	48 0f bf c0          	movsx  rax,ax
   1400057af:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057b3:	eb 12                	jmp    1400057c7 <__mingw_pformat+0x634>
   1400057b5:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400057b9:	75 0c                	jne    1400057c7 <__mingw_pformat+0x634>
   1400057bb:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   1400057bf:	48 0f be c0          	movsx  rax,al
   1400057c3:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057c7:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057cb:	48 85 c0             	test   rax,rax
   1400057ce:	79 09                	jns    1400057d9 <__mingw_pformat+0x646>
   1400057d0:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400057d7:	eb 05                	jmp    1400057de <__mingw_pformat+0x64b>
   1400057d9:	b8 00 00 00 00       	mov    eax,0x0
   1400057de:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   1400057e2:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057e6:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400057ea:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400057f1:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400057f8:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400057fc:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   140005803:	48 89 c1             	mov    rcx,rax
   140005806:	e8 60 de ff ff       	call   14000366b <__pformat_int>
   14000580b:	e9 f8 f9 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005810:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005814:	75 18                	jne    14000582e <__mingw_pformat+0x69b>
   140005816:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005819:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000581c:	75 10                	jne    14000582e <__mingw_pformat+0x69b>
   14000581e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005821:	80 cc 02             	or     ah,0x2
   140005824:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005827:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   14000582e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005832:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005836:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000583a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000583d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005841:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   140005848:	00 
   140005849:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000584d:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005851:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005858:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   14000585f:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005863:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000586a:	49 89 d0             	mov    r8,rdx
   14000586d:	48 89 c2             	mov    rdx,rax
   140005870:	b9 78 00 00 00       	mov    ecx,0x78
   140005875:	e8 74 e1 ff ff       	call   1400039ee <__pformat_xint>
   14000587a:	e9 89 f9 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   14000587f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005882:	83 c8 20             	or     eax,0x20
   140005885:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005888:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000588b:	83 e0 04             	and    eax,0x4
   14000588e:	85 c0                	test   eax,eax
   140005890:	74 2f                	je     1400058c1 <__mingw_pformat+0x72e>
   140005892:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005896:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000589a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000589e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400058a1:	db 28                	fld    TBYTE PTR [rax]
   1400058a3:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058a9:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058ad:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058b4:	48 89 c1             	mov    rcx,rax
   1400058b7:	e8 1d ef ff ff       	call   1400047d9 <__pformat_efloat>
   1400058bc:	e9 47 f9 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   1400058c1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058c5:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058c9:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058cd:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   1400058d1:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   1400058d8:	ff 
   1400058d9:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400058df:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058e5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058e9:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058f0:	48 89 c1             	mov    rcx,rax
   1400058f3:	e8 e1 ee ff ff       	call   1400047d9 <__pformat_efloat>
   1400058f8:	e9 0b f9 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   1400058fd:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005900:	83 c8 20             	or     eax,0x20
   140005903:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005906:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005909:	83 e0 04             	and    eax,0x4
   14000590c:	85 c0                	test   eax,eax
   14000590e:	74 2f                	je     14000593f <__mingw_pformat+0x7ac>
   140005910:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005914:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005918:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000591c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000591f:	db 28                	fld    TBYTE PTR [rax]
   140005921:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005927:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000592b:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005932:	48 89 c1             	mov    rcx,rax
   140005935:	e8 cf ed ff ff       	call   140004709 <__pformat_float>
   14000593a:	e9 c9 f8 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   14000593f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005943:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005947:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000594b:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   14000594f:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   140005956:	ff 
   140005957:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000595d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005963:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005967:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000596e:	48 89 c1             	mov    rcx,rax
   140005971:	e8 93 ed ff ff       	call   140004709 <__pformat_float>
   140005976:	e9 8d f8 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   14000597b:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000597e:	83 c8 20             	or     eax,0x20
   140005981:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005984:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005987:	83 e0 04             	and    eax,0x4
   14000598a:	85 c0                	test   eax,eax
   14000598c:	74 2f                	je     1400059bd <__mingw_pformat+0x82a>
   14000598e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005992:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005996:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000599a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000599d:	db 28                	fld    TBYTE PTR [rax]
   14000599f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059a5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059a9:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059b0:	48 89 c1             	mov    rcx,rax
   1400059b3:	e8 cc ee ff ff       	call   140004884 <__pformat_gfloat>
   1400059b8:	e9 4b f8 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   1400059bd:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059c1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059c5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059c9:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   1400059cd:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   1400059d4:	ff 
   1400059d5:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400059db:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059e1:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059e5:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059ec:	48 89 c1             	mov    rcx,rax
   1400059ef:	e8 90 ee ff ff       	call   140004884 <__pformat_gfloat>
   1400059f4:	e9 0f f8 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   1400059f9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059fc:	83 c8 20             	or     eax,0x20
   1400059ff:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005a02:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a05:	83 e0 04             	and    eax,0x4
   140005a08:	85 c0                	test   eax,eax
   140005a0a:	74 2f                	je     140005a3b <__mingw_pformat+0x8a8>
   140005a0c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a10:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a14:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a18:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a1b:	db 28                	fld    TBYTE PTR [rax]
   140005a1d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a23:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a27:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a2e:	48 89 c1             	mov    rcx,rax
   140005a31:	e8 e7 f4 ff ff       	call   140004f1d <__pformat_xldouble>
   140005a36:	e9 cd f7 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005a3b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a3f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a43:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a47:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a4a:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a4e:	66 48 0f 6e c0       	movq   xmm0,rax
   140005a53:	e8 de f5 ff ff       	call   140005036 <__pformat_xdouble>
   140005a58:	e9 ab f7 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005a5d:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005a61:	75 1b                	jne    140005a7e <__mingw_pformat+0x8eb>
   140005a63:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a66:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a6a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a6e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a72:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a75:	89 ca                	mov    edx,ecx
   140005a77:	88 10                	mov    BYTE PTR [rax],dl
   140005a79:	e9 8a f7 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005a7e:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005a82:	75 1c                	jne    140005aa0 <__mingw_pformat+0x90d>
   140005a84:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a87:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a8b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a8f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a93:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a96:	89 ca                	mov    edx,ecx
   140005a98:	66 89 10             	mov    WORD PTR [rax],dx
   140005a9b:	e9 68 f7 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005aa0:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005aa4:	75 19                	jne    140005abf <__mingw_pformat+0x92c>
   140005aa6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005aaa:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005aae:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ab2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ab5:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005ab8:	89 10                	mov    DWORD PTR [rax],edx
   140005aba:	e9 49 f7 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005abf:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005ac3:	75 1d                	jne    140005ae2 <__mingw_pformat+0x94f>
   140005ac5:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005ac8:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005acc:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005ad0:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ad4:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ad7:	48 63 d1             	movsxd rdx,ecx
   140005ada:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005add:	e9 26 f7 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005ae2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005ae6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005aea:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005aee:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005af1:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005af4:	89 10                	mov    DWORD PTR [rax],edx
   140005af6:	e9 0d f7 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005afb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005aff:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b02:	3c 68                	cmp    al,0x68
   140005b04:	75 0e                	jne    140005b14 <__mingw_pformat+0x981>
   140005b06:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b0b:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005b12:	eb 07                	jmp    140005b1b <__mingw_pformat+0x988>
   140005b14:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005b1b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b22:	e9 ee 02 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005b27:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b2e:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b35:	e9 db 02 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005b3a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b3e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b41:	3c 36                	cmp    al,0x36
   140005b43:	75 1d                	jne    140005b62 <__mingw_pformat+0x9cf>
   140005b45:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b49:	48 83 c0 01          	add    rax,0x1
   140005b4d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b50:	3c 34                	cmp    al,0x34
   140005b52:	75 0e                	jne    140005b62 <__mingw_pformat+0x9cf>
   140005b54:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b5b:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b60:	eb 2f                	jmp    140005b91 <__mingw_pformat+0x9fe>
   140005b62:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b66:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b69:	3c 33                	cmp    al,0x33
   140005b6b:	75 1d                	jne    140005b8a <__mingw_pformat+0x9f7>
   140005b6d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b71:	48 83 c0 01          	add    rax,0x1
   140005b75:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b78:	3c 32                	cmp    al,0x32
   140005b7a:	75 0e                	jne    140005b8a <__mingw_pformat+0x9f7>
   140005b7c:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b83:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b88:	eb 07                	jmp    140005b91 <__mingw_pformat+0x9fe>
   140005b8a:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b91:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b98:	e9 78 02 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005b9d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ba1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ba4:	3c 6c                	cmp    al,0x6c
   140005ba6:	75 0e                	jne    140005bb6 <__mingw_pformat+0xa23>
   140005ba8:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005bad:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bb4:	eb 07                	jmp    140005bbd <__mingw_pformat+0xa2a>
   140005bb6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005bbd:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bc4:	e9 4c 02 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005bc9:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005bd0:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bd7:	e9 39 02 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005bdc:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005bdf:	83 c8 04             	or     eax,0x4
   140005be2:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005be5:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bec:	e9 24 02 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005bf1:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bf8:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bff:	e9 11 02 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005c04:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c0b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c12:	e9 fe 01 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005c17:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005c1b:	77 1f                	ja     140005c3c <__mingw_pformat+0xaa9>
   140005c1d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005c24:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005c28:	48 83 c0 10          	add    rax,0x10
   140005c2c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005c30:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005c37:	e9 d9 01 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005c3c:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c43:	e9 cd 01 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005c48:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005c4d:	74 4c                	je     140005c9b <__mingw_pformat+0xb08>
   140005c4f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c53:	74 06                	je     140005c5b <__mingw_pformat+0xac8>
   140005c55:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005c59:	75 40                	jne    140005c9b <__mingw_pformat+0xb08>
   140005c5b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005c5f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005c63:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005c67:	8b 10                	mov    edx,DWORD PTR [rax]
   140005c69:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c6d:	89 10                	mov    DWORD PTR [rax],edx
   140005c6f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c73:	8b 00                	mov    eax,DWORD PTR [rax]
   140005c75:	85 c0                	test   eax,eax
   140005c77:	79 29                	jns    140005ca2 <__mingw_pformat+0xb0f>
   140005c79:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c7d:	75 13                	jne    140005c92 <__mingw_pformat+0xaff>
   140005c7f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c82:	80 cc 04             	or     ah,0x4
   140005c85:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c88:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005c8b:	f7 d8                	neg    eax
   140005c8d:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005c90:	eb 10                	jmp    140005ca2 <__mingw_pformat+0xb0f>
   140005c92:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005c99:	eb 07                	jmp    140005ca2 <__mingw_pformat+0xb0f>
   140005c9b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ca2:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005ca9:	00 
   140005caa:	e9 66 01 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005caf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cb3:	0f 85 4f 01 00 00    	jne    140005e08 <__mingw_pformat+0xc75>
   140005cb9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cbc:	80 cc 08             	or     ah,0x8
   140005cbf:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cc2:	e9 41 01 00 00       	jmp    140005e08 <__mingw_pformat+0xc75>
   140005cc7:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ccb:	0f 85 3a 01 00 00    	jne    140005e0b <__mingw_pformat+0xc78>
   140005cd1:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cd4:	80 cc 01             	or     ah,0x1
   140005cd7:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cda:	e9 2c 01 00 00       	jmp    140005e0b <__mingw_pformat+0xc78>
   140005cdf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ce3:	0f 85 25 01 00 00    	jne    140005e0e <__mingw_pformat+0xc7b>
   140005ce9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cec:	80 cc 04             	or     ah,0x4
   140005cef:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cf2:	e9 17 01 00 00       	jmp    140005e0e <__mingw_pformat+0xc7b>
   140005cf7:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cfb:	0f 85 10 01 00 00    	jne    140005e11 <__mingw_pformat+0xc7e>
   140005d01:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d04:	80 cc 10             	or     ah,0x10
   140005d07:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d0a:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005d11:	00 
   140005d12:	e8 a1 39 00 00       	call   1400096b8 <localeconv>
   140005d17:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005d1b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005d1f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005d23:	49 89 c9             	mov    r9,rcx
   140005d26:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005d2c:	48 89 c1             	mov    rcx,rax
   140005d2f:	e8 bc 33 00 00       	call   1400090f0 <mbrtowc>
   140005d34:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005d37:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005d3b:	7e 08                	jle    140005d45 <__mingw_pformat+0xbb2>
   140005d3d:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005d41:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005d45:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005d48:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005d4b:	e9 c1 00 00 00       	jmp    140005e11 <__mingw_pformat+0xc7e>
   140005d50:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d54:	0f 85 ba 00 00 00    	jne    140005e14 <__mingw_pformat+0xc81>
   140005d5a:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d5d:	83 c8 40             	or     eax,0x40
   140005d60:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d63:	e9 ac 00 00 00       	jmp    140005e14 <__mingw_pformat+0xc81>
   140005d68:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d6c:	75 0e                	jne    140005d7c <__mingw_pformat+0xbe9>
   140005d6e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d71:	80 cc 02             	or     ah,0x2
   140005d74:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d77:	e9 99 00 00 00       	jmp    140005e15 <__mingw_pformat+0xc82>
   140005d7c:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005d80:	77 68                	ja     140005dea <__mingw_pformat+0xc57>
   140005d82:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005d86:	7f 62                	jg     140005dea <__mingw_pformat+0xc57>
   140005d88:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005d8c:	7e 5c                	jle    140005dea <__mingw_pformat+0xc57>
   140005d8e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d92:	75 09                	jne    140005d9d <__mingw_pformat+0xc0a>
   140005d94:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005d9b:	eb 0d                	jmp    140005daa <__mingw_pformat+0xc17>
   140005d9d:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005da1:	75 07                	jne    140005daa <__mingw_pformat+0xc17>
   140005da3:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005daa:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005daf:	74 64                	je     140005e15 <__mingw_pformat+0xc82>
   140005db1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005db5:	8b 00                	mov    eax,DWORD PTR [rax]
   140005db7:	85 c0                	test   eax,eax
   140005db9:	79 0e                	jns    140005dc9 <__mingw_pformat+0xc36>
   140005dbb:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005dbe:	8d 50 d0             	lea    edx,[rax-0x30]
   140005dc1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005dc5:	89 10                	mov    DWORD PTR [rax],edx
   140005dc7:	eb 4c                	jmp    140005e15 <__mingw_pformat+0xc82>
   140005dc9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005dcd:	8b 10                	mov    edx,DWORD PTR [rax]
   140005dcf:	89 d0                	mov    eax,edx
   140005dd1:	c1 e0 02             	shl    eax,0x2
   140005dd4:	01 d0                	add    eax,edx
   140005dd6:	01 c0                	add    eax,eax
   140005dd8:	89 c2                	mov    edx,eax
   140005dda:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005ddd:	01 d0                	add    eax,edx
   140005ddf:	8d 50 d0             	lea    edx,[rax-0x30]
   140005de2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005de6:	89 10                	mov    DWORD PTR [rax],edx
   140005de8:	eb 2b                	jmp    140005e15 <__mingw_pformat+0xc82>
   140005dea:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005dee:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005df2:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005df6:	48 89 c2             	mov    rdx,rax
   140005df9:	b9 25 00 00 00       	mov    ecx,0x25
   140005dfe:	e8 fd d3 ff ff       	call   140003200 <__pformat_putc>
   140005e03:	e9 00 f4 ff ff       	jmp    140005208 <__mingw_pformat+0x75>
   140005e08:	90                   	nop
   140005e09:	eb 0a                	jmp    140005e15 <__mingw_pformat+0xc82>
   140005e0b:	90                   	nop
   140005e0c:	eb 07                	jmp    140005e15 <__mingw_pformat+0xc82>
   140005e0e:	90                   	nop
   140005e0f:	eb 04                	jmp    140005e15 <__mingw_pformat+0xc82>
   140005e11:	90                   	nop
   140005e12:	eb 01                	jmp    140005e15 <__mingw_pformat+0xc82>
   140005e14:	90                   	nop
   140005e15:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e19:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e1c:	84 c0                	test   al,al
   140005e1e:	0f 85 2d f4 ff ff    	jne    140005251 <__mingw_pformat+0xbe>
   140005e24:	eb 0e                	jmp    140005e34 <__mingw_pformat+0xca1>
   140005e26:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005e2a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e2d:	89 c1                	mov    ecx,eax
   140005e2f:	e8 cc d3 ff ff       	call   140003200 <__pformat_putc>
   140005e34:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e38:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e3c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005e40:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e43:	0f be c0             	movsx  eax,al
   140005e46:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005e49:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005e4d:	0f 85 ba f3 ff ff    	jne    14000520d <__mingw_pformat+0x7a>
   140005e53:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005e56:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005e5d:	5d                   	pop    rbp
   140005e5e:	c3                   	ret
   140005e5f:	90                   	nop

0000000140005e60 <__rv_alloc_D2A>:
   140005e60:	55                   	push   rbp
   140005e61:	48 89 e5             	mov    rbp,rsp
   140005e64:	48 83 ec 30          	sub    rsp,0x30
   140005e68:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005e6b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005e72:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005e79:	eb 07                	jmp    140005e82 <__rv_alloc_D2A+0x22>
   140005e7b:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005e7f:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005e82:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005e85:	83 c0 17             	add    eax,0x17
   140005e88:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005e8b:	7f ee                	jg     140005e7b <__rv_alloc_D2A+0x1b>
   140005e8d:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005e90:	89 c1                	mov    ecx,eax
   140005e92:	e8 56 1e 00 00       	call   140007ced <__Balloc_D2A>
   140005e97:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005e9b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e9f:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005ea2:	89 10                	mov    DWORD PTR [rax],edx
   140005ea4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ea8:	48 83 c0 04          	add    rax,0x4
   140005eac:	48 83 c4 30          	add    rsp,0x30
   140005eb0:	5d                   	pop    rbp
   140005eb1:	c3                   	ret

0000000140005eb2 <__nrv_alloc_D2A>:
   140005eb2:	55                   	push   rbp
   140005eb3:	48 89 e5             	mov    rbp,rsp
   140005eb6:	48 83 ec 30          	sub    rsp,0x30
   140005eba:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005ebe:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005ec2:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005ec6:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005ec9:	89 c1                	mov    ecx,eax
   140005ecb:	e8 90 ff ff ff       	call   140005e60 <__rv_alloc_D2A>
   140005ed0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005ed4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ed8:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005edc:	eb 05                	jmp    140005ee3 <__nrv_alloc_D2A+0x31>
   140005ede:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005ee3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005ee7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005eeb:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005eef:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005ef2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ef6:	88 10                	mov    BYTE PTR [rax],dl
   140005ef8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005efc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005eff:	84 c0                	test   al,al
   140005f01:	75 db                	jne    140005ede <__nrv_alloc_D2A+0x2c>
   140005f03:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005f08:	74 0b                	je     140005f15 <__nrv_alloc_D2A+0x63>
   140005f0a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f0e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005f12:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005f15:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f19:	48 83 c4 30          	add    rsp,0x30
   140005f1d:	5d                   	pop    rbp
   140005f1e:	c3                   	ret

0000000140005f1f <__freedtoa>:
   140005f1f:	55                   	push   rbp
   140005f20:	48 89 e5             	mov    rbp,rsp
   140005f23:	48 83 ec 30          	sub    rsp,0x30
   140005f27:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f2b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f2f:	48 83 e8 04          	sub    rax,0x4
   140005f33:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f37:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f3b:	8b 10                	mov    edx,DWORD PTR [rax]
   140005f3d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f41:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005f44:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f48:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005f4b:	ba 01 00 00 00       	mov    edx,0x1
   140005f50:	89 c1                	mov    ecx,eax
   140005f52:	d3 e2                	shl    edx,cl
   140005f54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f58:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005f5b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f5f:	48 89 c1             	mov    rcx,rax
   140005f62:	e8 c7 1e 00 00       	call   140007e2e <__Bfree_D2A>
   140005f67:	90                   	nop
   140005f68:	48 83 c4 30          	add    rsp,0x30
   140005f6c:	5d                   	pop    rbp
   140005f6d:	c3                   	ret

0000000140005f6e <__quorem_D2A>:
   140005f6e:	55                   	push   rbp
   140005f6f:	48 89 e5             	mov    rbp,rsp
   140005f72:	48 83 ec 70          	sub    rsp,0x70
   140005f76:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f7a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005f7e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f82:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f85:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005f88:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f8c:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f8f:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005f92:	7e 0a                	jle    140005f9e <__quorem_D2A+0x30>
   140005f94:	b8 00 00 00 00       	mov    eax,0x0
   140005f99:	e9 3f 02 00 00       	jmp    1400061dd <__quorem_D2A+0x26f>
   140005f9e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005fa2:	48 83 c0 18          	add    rax,0x18
   140005fa6:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005faa:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005fae:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005fb1:	48 98                	cdqe
   140005fb3:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005fba:	00 
   140005fbb:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005fbf:	48 01 d0             	add    rax,rdx
   140005fc2:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005fc6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005fca:	48 83 c0 18          	add    rax,0x18
   140005fce:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005fd2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005fd5:	48 98                	cdqe
   140005fd7:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005fde:	00 
   140005fdf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005fe3:	48 01 d0             	add    rax,rdx
   140005fe6:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140005fea:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005fee:	8b 00                	mov    eax,DWORD PTR [rax]
   140005ff0:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140005ff4:	8b 12                	mov    edx,DWORD PTR [rdx]
   140005ff6:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140005ff9:	ba 00 00 00 00       	mov    edx,0x0
   140005ffe:	f7 f1                	div    ecx
   140006000:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140006003:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140006007:	0f 84 c4 00 00 00    	je     1400060d1 <__quorem_D2A+0x163>
   14000600d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006014:	00 
   140006015:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000601c:	00 
   14000601d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006021:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140006025:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006029:	8b 00                	mov    eax,DWORD PTR [rax]
   14000602b:	89 c2                	mov    edx,eax
   14000602d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140006030:	48 0f af d0          	imul   rdx,rax
   140006034:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006038:	48 01 d0             	add    rax,rdx
   14000603b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000603f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006043:	48 c1 e8 20          	shr    rax,0x20
   140006047:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000604b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000604f:	8b 00                	mov    eax,DWORD PTR [rax]
   140006051:	89 c1                	mov    ecx,eax
   140006053:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006057:	89 c2                	mov    edx,eax
   140006059:	48 89 c8             	mov    rax,rcx
   14000605c:	48 29 d0             	sub    rax,rdx
   14000605f:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006063:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006067:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000606b:	48 c1 e8 20          	shr    rax,0x20
   14000606f:	83 e0 01             	and    eax,0x1
   140006072:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006076:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000607a:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000607e:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006082:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006086:	89 10                	mov    DWORD PTR [rax],edx
   140006088:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000608c:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006090:	73 8b                	jae    14000601d <__quorem_D2A+0xaf>
   140006092:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006096:	8b 00                	mov    eax,DWORD PTR [rax]
   140006098:	85 c0                	test   eax,eax
   14000609a:	75 35                	jne    1400060d1 <__quorem_D2A+0x163>
   14000609c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060a0:	48 83 c0 18          	add    rax,0x18
   1400060a4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400060a8:	eb 04                	jmp    1400060ae <__quorem_D2A+0x140>
   1400060aa:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400060ae:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400060b3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060b7:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   1400060bb:	73 0a                	jae    1400060c7 <__quorem_D2A+0x159>
   1400060bd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060c1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060c3:	85 c0                	test   eax,eax
   1400060c5:	74 e3                	je     1400060aa <__quorem_D2A+0x13c>
   1400060c7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060cb:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400060ce:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400060d1:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400060d5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060d9:	48 89 c1             	mov    rcx,rax
   1400060dc:	e8 bc 24 00 00       	call   14000859d <__cmp_D2A>
   1400060e1:	85 c0                	test   eax,eax
   1400060e3:	0f 88 f1 00 00 00    	js     1400061da <__quorem_D2A+0x26c>
   1400060e9:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   1400060ed:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400060f4:	00 
   1400060f5:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   1400060fc:	00 
   1400060fd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006101:	48 83 c0 18          	add    rax,0x18
   140006105:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006109:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000610d:	48 83 c0 18          	add    rax,0x18
   140006111:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006115:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006119:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000611d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006121:	8b 00                	mov    eax,DWORD PTR [rax]
   140006123:	89 c2                	mov    edx,eax
   140006125:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006129:	48 01 d0             	add    rax,rdx
   14000612c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140006130:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006134:	48 c1 e8 20          	shr    rax,0x20
   140006138:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000613c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006140:	8b 00                	mov    eax,DWORD PTR [rax]
   140006142:	89 c1                	mov    ecx,eax
   140006144:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006148:	89 c2                	mov    edx,eax
   14000614a:	48 89 c8             	mov    rax,rcx
   14000614d:	48 29 d0             	sub    rax,rdx
   140006150:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006154:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006158:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000615c:	48 c1 e8 20          	shr    rax,0x20
   140006160:	83 e0 01             	and    eax,0x1
   140006163:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006167:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000616b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000616f:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006173:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006177:	89 10                	mov    DWORD PTR [rax],edx
   140006179:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000617d:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006181:	73 92                	jae    140006115 <__quorem_D2A+0x1a7>
   140006183:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006187:	48 83 c0 18          	add    rax,0x18
   14000618b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000618f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006192:	48 98                	cdqe
   140006194:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000619b:	00 
   14000619c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061a0:	48 01 d0             	add    rax,rdx
   1400061a3:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400061a7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400061ad:	85 c0                	test   eax,eax
   1400061af:	75 29                	jne    1400061da <__quorem_D2A+0x26c>
   1400061b1:	eb 04                	jmp    1400061b7 <__quorem_D2A+0x249>
   1400061b3:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400061b7:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400061bc:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061c0:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   1400061c4:	73 0a                	jae    1400061d0 <__quorem_D2A+0x262>
   1400061c6:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061ca:	8b 00                	mov    eax,DWORD PTR [rax]
   1400061cc:	85 c0                	test   eax,eax
   1400061ce:	74 e3                	je     1400061b3 <__quorem_D2A+0x245>
   1400061d0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400061d4:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400061d7:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400061da:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400061dd:	48 83 c4 70          	add    rsp,0x70
   1400061e1:	5d                   	pop    rbp
   1400061e2:	c3                   	ret
   1400061e3:	90                   	nop
   1400061e4:	90                   	nop
   1400061e5:	90                   	nop
   1400061e6:	90                   	nop
   1400061e7:	90                   	nop
   1400061e8:	90                   	nop
   1400061e9:	90                   	nop
   1400061ea:	90                   	nop
   1400061eb:	90                   	nop
   1400061ec:	90                   	nop
   1400061ed:	90                   	nop
   1400061ee:	90                   	nop
   1400061ef:	90                   	nop

00000001400061f0 <__hi0bits_D2A>:
   1400061f0:	55                   	push   rbp
   1400061f1:	48 89 e5             	mov    rbp,rsp
   1400061f4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400061f7:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   1400061fb:	83 f0 1f             	xor    eax,0x1f
   1400061fe:	5d                   	pop    rbp
   1400061ff:	c3                   	ret

0000000140006200 <bitstob>:
   140006200:	55                   	push   rbp
   140006201:	53                   	push   rbx
   140006202:	48 83 ec 58          	sub    rsp,0x58
   140006206:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000620b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000620f:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006212:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006216:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000621d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140006224:	eb 07                	jmp    14000622d <bitstob+0x2d>
   140006226:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140006229:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   14000622d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006230:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   140006233:	7c f1                	jl     140006226 <bitstob+0x26>
   140006235:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140006238:	89 c1                	mov    ecx,eax
   14000623a:	e8 ae 1a 00 00       	call   140007ced <__Balloc_D2A>
   14000623f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006243:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140006246:	83 e8 01             	sub    eax,0x1
   140006249:	c1 f8 05             	sar    eax,0x5
   14000624c:	48 98                	cdqe
   14000624e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006255:	00 
   140006256:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000625a:	48 01 d0             	add    rax,rdx
   14000625d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140006261:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006265:	48 83 c0 18          	add    rax,0x18
   140006269:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000626d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006271:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006275:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006279:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000627d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006281:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140006285:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006287:	89 10                	mov    DWORD PTR [rax],edx
   140006289:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   14000628e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006292:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140006296:	73 dd                	jae    140006275 <bitstob+0x75>
   140006298:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000629c:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400062a0:	48 c1 f8 02          	sar    rax,0x2
   1400062a4:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400062a7:	eb 1d                	jmp    1400062c6 <bitstob+0xc6>
   1400062a9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400062ad:	75 17                	jne    1400062c6 <bitstob+0xc6>
   1400062af:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062b3:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   1400062ba:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400062be:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400062c4:	eb 59                	jmp    14000631f <bitstob+0x11f>
   1400062c6:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400062ca:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062cd:	48 98                	cdqe
   1400062cf:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400062d6:	00 
   1400062d7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400062db:	48 01 d0             	add    rax,rdx
   1400062de:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062e0:	85 c0                	test   eax,eax
   1400062e2:	74 c5                	je     1400062a9 <bitstob+0xa9>
   1400062e4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062e7:	8d 50 01             	lea    edx,[rax+0x1]
   1400062ea:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062ee:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400062f1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062f4:	83 c0 01             	add    eax,0x1
   1400062f7:	c1 e0 05             	shl    eax,0x5
   1400062fa:	89 c3                	mov    ebx,eax
   1400062fc:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006300:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006303:	48 63 d2             	movsxd rdx,edx
   140006306:	48 83 c2 04          	add    rdx,0x4
   14000630a:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   14000630e:	89 c1                	mov    ecx,eax
   140006310:	e8 db fe ff ff       	call   1400061f0 <__hi0bits_D2A>
   140006315:	29 c3                	sub    ebx,eax
   140006317:	89 da                	mov    edx,ebx
   140006319:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000631d:	89 10                	mov    DWORD PTR [rax],edx
   14000631f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006323:	48 83 c4 58          	add    rsp,0x58
   140006327:	5b                   	pop    rbx
   140006328:	5d                   	pop    rbp
   140006329:	c3                   	ret

000000014000632a <__gdtoa>:
   14000632a:	55                   	push   rbp
   14000632b:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   140006332:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140006339:	00 
   14000633a:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   140006341:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   140006347:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   14000634e:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   140006355:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   14000635c:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006363:	8b 00                	mov    eax,DWORD PTR [rax]
   140006365:	83 e0 cf             	and    eax,0xffffffcf
   140006368:	89 c2                	mov    edx,eax
   14000636a:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006371:	89 10                	mov    DWORD PTR [rax],edx
   140006373:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   14000637a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000637c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000637f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006382:	83 e0 07             	and    eax,0x7
   140006385:	83 f8 04             	cmp    eax,0x4
   140006388:	0f 84 b0 00 00 00    	je     14000643e <__gdtoa+0x114>
   14000638e:	83 f8 04             	cmp    eax,0x4
   140006391:	0f 8f d5 00 00 00    	jg     14000646c <__gdtoa+0x142>
   140006397:	83 f8 03             	cmp    eax,0x3
   14000639a:	74 74                	je     140006410 <__gdtoa+0xe6>
   14000639c:	83 f8 03             	cmp    eax,0x3
   14000639f:	0f 8f c7 00 00 00    	jg     14000646c <__gdtoa+0x142>
   1400063a5:	85 c0                	test   eax,eax
   1400063a7:	0f 84 05 01 00 00    	je     1400064b2 <__gdtoa+0x188>
   1400063ad:	85 c0                	test   eax,eax
   1400063af:	0f 88 b7 00 00 00    	js     14000646c <__gdtoa+0x142>
   1400063b5:	83 e8 01             	sub    eax,0x1
   1400063b8:	83 f8 01             	cmp    eax,0x1
   1400063bb:	0f 87 ab 00 00 00    	ja     14000646c <__gdtoa+0x142>
   1400063c1:	90                   	nop
   1400063c2:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400063c9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063cb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400063ce:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   1400063d2:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400063d5:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400063dc:	49 89 c8             	mov    r8,rcx
   1400063df:	48 89 c1             	mov    rcx,rax
   1400063e2:	e8 19 fe ff ff       	call   140006200 <bitstob>
   1400063e7:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400063eb:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   1400063f1:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400063f4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063f8:	48 89 c1             	mov    rcx,rax
   1400063fb:	e8 31 16 00 00       	call   140007a31 <__trailz_D2A>
   140006400:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006403:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006406:	85 c0                	test   eax,eax
   140006408:	0f 84 8b 00 00 00    	je     140006499 <__gdtoa+0x16f>
   14000640e:	eb 66                	jmp    140006476 <__gdtoa+0x14c>
   140006410:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006417:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000641d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006424:	48 8d 0d 25 4f 00 00 	lea    rcx,[rip+0x4f25]        # 14000b350 <.rdata>
   14000642b:	41 b8 08 00 00 00    	mov    r8d,0x8
   140006431:	48 89 c2             	mov    rdx,rax
   140006434:	e8 79 fa ff ff       	call   140005eb2 <__nrv_alloc_D2A>
   140006439:	e9 4d 14 00 00       	jmp    14000788b <__gdtoa+0x1561>
   14000643e:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006445:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000644b:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006452:	48 8d 0d 00 4f 00 00 	lea    rcx,[rip+0x4f00]        # 14000b359 <.rdata+0x9>
   140006459:	41 b8 03 00 00 00    	mov    r8d,0x3
   14000645f:	48 89 c2             	mov    rdx,rax
   140006462:	e8 4b fa ff ff       	call   140005eb2 <__nrv_alloc_D2A>
   140006467:	e9 1f 14 00 00       	jmp    14000788b <__gdtoa+0x1561>
   14000646c:	b8 00 00 00 00       	mov    eax,0x0
   140006471:	e9 15 14 00 00       	jmp    14000788b <__gdtoa+0x1561>
   140006476:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006479:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000647d:	48 89 c1             	mov    rcx,rax
   140006480:	e8 50 14 00 00       	call   1400078d5 <__rshift_D2A>
   140006485:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006488:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   14000648e:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006491:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006494:	29 c2                	sub    edx,eax
   140006496:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   140006499:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000649d:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400064a0:	85 c0                	test   eax,eax
   1400064a2:	75 3d                	jne    1400064e1 <__gdtoa+0x1b7>
   1400064a4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064a8:	48 89 c1             	mov    rcx,rax
   1400064ab:	e8 7e 19 00 00       	call   140007e2e <__Bfree_D2A>
   1400064b0:	eb 01                	jmp    1400064b3 <__gdtoa+0x189>
   1400064b2:	90                   	nop
   1400064b3:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400064ba:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   1400064c0:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400064c7:	48 8d 0d 8f 4e 00 00 	lea    rcx,[rip+0x4e8f]        # 14000b35d <.rdata+0xd>
   1400064ce:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400064d4:	48 89 c2             	mov    rdx,rax
   1400064d7:	e8 d6 f9 ff ff       	call   140005eb2 <__nrv_alloc_D2A>
   1400064dc:	e9 aa 13 00 00       	jmp    14000788b <__gdtoa+0x1561>
   1400064e1:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   1400064e5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064e9:	48 89 c1             	mov    rcx,rax
   1400064ec:	e8 75 23 00 00       	call   140008866 <__b2d_D2A>
   1400064f1:	66 48 0f 7e c0       	movq   rax,xmm0
   1400064f6:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   1400064fa:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400064fd:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006503:	01 d0                	add    eax,edx
   140006505:	83 e8 01             	sub    eax,0x1
   140006508:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000650b:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   14000650e:	25 ff ff 0f 00       	and    eax,0xfffff
   140006513:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006516:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006519:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000651e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006521:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006526:	f2 0f 10 15 32 4e 00 	movsd  xmm2,QWORD PTR [rip+0x4e32]        # 14000b360 <.rdata+0x10>
   14000652d:	00 
   14000652e:	66 0f 28 c8          	movapd xmm1,xmm0
   140006532:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006536:	f2 0f 10 05 2a 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e2a]        # 14000b368 <.rdata+0x18>
   14000653d:	00 
   14000653e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006542:	f2 0f 10 05 26 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e26]        # 14000b370 <.rdata+0x20>
   140006549:	00 
   14000654a:	f2 0f 58 c8          	addsd  xmm1,xmm0
   14000654e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006551:	66 0f ef d2          	pxor   xmm2,xmm2
   140006555:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   140006559:	f2 0f 10 05 17 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e17]        # 14000b378 <.rdata+0x28>
   140006560:	00 
   140006561:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006565:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006569:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000656e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006571:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006574:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006578:	79 03                	jns    14000657d <__gdtoa+0x253>
   14000657a:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   14000657d:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   140006584:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006588:	7e 23                	jle    1400065ad <__gdtoa+0x283>
   14000658a:	66 0f ef c9          	pxor   xmm1,xmm1
   14000658e:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   140006593:	f2 0f 10 05 e5 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4de5]        # 14000b380 <.rdata+0x30>
   14000659a:	00 
   14000659b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000659f:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   1400065a4:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400065a8:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400065ad:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   1400065b2:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400065b6:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   1400065b9:	66 0f ef c0          	pxor   xmm0,xmm0
   1400065bd:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   1400065c2:	76 1b                	jbe    1400065df <__gdtoa+0x2b5>
   1400065c4:	66 0f ef c0          	pxor   xmm0,xmm0
   1400065c8:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   1400065cd:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   1400065d2:	7a 07                	jp     1400065db <__gdtoa+0x2b1>
   1400065d4:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   1400065d9:	74 04                	je     1400065df <__gdtoa+0x2b5>
   1400065db:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400065df:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   1400065e6:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   1400065e9:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   1400065ec:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   1400065f2:	01 ca                	add    edx,ecx
   1400065f4:	83 ea 01             	sub    edx,0x1
   1400065f7:	c1 e2 14             	shl    edx,0x14
   1400065fa:	01 d0                	add    eax,edx
   1400065fc:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400065ff:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006603:	78 2e                	js     140006633 <__gdtoa+0x309>
   140006605:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   140006609:	7f 28                	jg     140006633 <__gdtoa+0x309>
   14000660b:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006610:	48 8b 05 69 50 00 00 	mov    rax,QWORD PTR [rip+0x5069]        # 14000b680 <.refptr.__tens_D2A>
   140006617:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000661a:	48 63 d2             	movsxd rdx,edx
   14000661d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006622:	66 0f 2f c1          	comisd xmm0,xmm1
   140006626:	76 04                	jbe    14000662c <__gdtoa+0x302>
   140006628:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000662c:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   140006633:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006636:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006639:	29 c2                	sub    edx,eax
   14000663b:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000663e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006641:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006645:	78 0f                	js     140006656 <__gdtoa+0x32c>
   140006647:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   14000664e:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006651:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   140006654:	eb 0f                	jmp    140006665 <__gdtoa+0x33b>
   140006656:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006659:	f7 d8                	neg    eax
   14000665b:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   14000665e:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   140006665:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006669:	78 15                	js     140006680 <__gdtoa+0x356>
   14000666b:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   140006672:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006675:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   140006678:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000667b:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   14000667e:	eb 15                	jmp    140006695 <__gdtoa+0x36b>
   140006680:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006683:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006686:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006689:	f7 d8                	neg    eax
   14000668b:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   14000668e:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   140006695:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000669c:	78 09                	js     1400066a7 <__gdtoa+0x37d>
   14000669e:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   1400066a5:	7e 0a                	jle    1400066b1 <__gdtoa+0x387>
   1400066a7:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   1400066ae:	00 00 00 
   1400066b1:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   1400066b8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400066bf:	7e 10                	jle    1400066d1 <__gdtoa+0x3a7>
   1400066c1:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   1400066c8:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   1400066cf:	eb 1b                	jmp    1400066ec <__gdtoa+0x3c2>
   1400066d1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400066d4:	3d f9 03 00 00       	cmp    eax,0x3f9
   1400066d9:	7f 0a                	jg     1400066e5 <__gdtoa+0x3bb>
   1400066db:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400066de:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   1400066e3:	7d 07                	jge    1400066ec <__gdtoa+0x3c2>
   1400066e5:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   1400066ec:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   1400066f3:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   1400066fa:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400066fd:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006700:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006707:	0f 84 c5 00 00 00    	je     1400067d2 <__gdtoa+0x4a8>
   14000670d:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006714:	0f 8f e6 00 00 00    	jg     140006800 <__gdtoa+0x4d6>
   14000671a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   140006721:	74 7e                	je     1400067a1 <__gdtoa+0x477>
   140006723:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   14000672a:	0f 8f d0 00 00 00    	jg     140006800 <__gdtoa+0x4d6>
   140006730:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006737:	0f 84 8e 00 00 00    	je     1400067cb <__gdtoa+0x4a1>
   14000673d:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006744:	0f 8f b6 00 00 00    	jg     140006800 <__gdtoa+0x4d6>
   14000674a:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006751:	7f 0e                	jg     140006761 <__gdtoa+0x437>
   140006753:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000675a:	79 13                	jns    14000676f <__gdtoa+0x445>
   14000675c:	e9 9f 00 00 00       	jmp    140006800 <__gdtoa+0x4d6>
   140006761:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140006768:	74 30                	je     14000679a <__gdtoa+0x470>
   14000676a:	e9 91 00 00 00       	jmp    140006800 <__gdtoa+0x4d6>
   14000676f:	66 0f ef c9          	pxor   xmm1,xmm1
   140006773:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   140006778:	f2 0f 10 05 08 4c 00 	movsd  xmm0,QWORD PTR [rip+0x4c08]        # 14000b388 <.rdata+0x38>
   14000677f:	00 
   140006780:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006784:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006788:	83 c0 03             	add    eax,0x3
   14000678b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000678e:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   140006795:	00 00 00 
   140006798:	eb 66                	jmp    140006800 <__gdtoa+0x4d6>
   14000679a:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   1400067a1:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   1400067a8:	7f 0a                	jg     1400067b4 <__gdtoa+0x48a>
   1400067aa:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   1400067b1:	00 00 00 
   1400067b4:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   1400067ba:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067bd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067c0:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   1400067c3:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400067c6:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400067c9:	eb 35                	jmp    140006800 <__gdtoa+0x4d6>
   1400067cb:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   1400067d2:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   1400067d8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400067db:	01 d0                	add    eax,edx
   1400067dd:	83 c0 01             	add    eax,0x1
   1400067e0:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067e3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067e6:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400067e9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067ec:	83 e8 01             	sub    eax,0x1
   1400067ef:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   1400067f2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067f5:	85 c0                	test   eax,eax
   1400067f7:	7f 07                	jg     140006800 <__gdtoa+0x4d6>
   1400067f9:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006800:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006803:	89 c1                	mov    ecx,eax
   140006805:	e8 56 f6 ff ff       	call   140005e60 <__rv_alloc_D2A>
   14000680a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000680e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006812:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006816:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000681d:	7f 09                	jg     140006828 <__gdtoa+0x4fe>
   14000681f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   140006826:	eb 38                	jmp    140006860 <__gdtoa+0x536>
   140006828:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000682f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140006832:	83 e8 01             	sub    eax,0x1
   140006835:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006838:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000683c:	74 22                	je     140006860 <__gdtoa+0x536>
   14000683e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006842:	79 07                	jns    14000684b <__gdtoa+0x521>
   140006844:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   14000684b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000684e:	83 e0 08             	and    eax,0x8
   140006851:	85 c0                	test   eax,eax
   140006853:	74 0b                	je     140006860 <__gdtoa+0x536>
   140006855:	b8 03 00 00 00       	mov    eax,0x3
   14000685a:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   14000685d:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006860:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006864:	0f 88 b9 04 00 00    	js     140006d23 <__gdtoa+0x9f9>
   14000686a:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   14000686e:	0f 8f af 04 00 00    	jg     140006d23 <__gdtoa+0x9f9>
   140006874:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   140006878:	0f 84 a5 04 00 00    	je     140006d23 <__gdtoa+0x9f9>
   14000687e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006882:	0f 85 9b 04 00 00    	jne    140006d23 <__gdtoa+0x9f9>
   140006888:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000688c:	0f 85 91 04 00 00    	jne    140006d23 <__gdtoa+0x9f9>
   140006892:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006899:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   14000689e:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400068a3:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068a6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400068a9:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   1400068ac:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   1400068af:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   1400068b6:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400068ba:	0f 8e 98 00 00 00    	jle    140006958 <__gdtoa+0x62e>
   1400068c0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068c3:	83 e0 0f             	and    eax,0xf
   1400068c6:	89 c2                	mov    edx,eax
   1400068c8:	48 8b 05 b1 4d 00 00 	mov    rax,QWORD PTR [rip+0x4db1]        # 14000b680 <.refptr.__tens_D2A>
   1400068cf:	48 63 d2             	movsxd rdx,edx
   1400068d2:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400068d7:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068dc:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068df:	c1 f8 04             	sar    eax,0x4
   1400068e2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400068e5:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400068e8:	83 e0 10             	and    eax,0x10
   1400068eb:	85 c0                	test   eax,eax
   1400068ed:	74 5e                	je     14000694d <__gdtoa+0x623>
   1400068ef:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   1400068f3:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400068f8:	48 8b 05 b1 4c 00 00 	mov    rax,QWORD PTR [rip+0x4cb1]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400068ff:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   140006904:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006908:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000690d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006911:	eb 3a                	jmp    14000694d <__gdtoa+0x623>
   140006913:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006916:	83 e0 01             	and    eax,0x1
   140006919:	85 c0                	test   eax,eax
   14000691b:	74 24                	je     140006941 <__gdtoa+0x617>
   14000691d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006921:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006924:	48 8b 05 85 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c85]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000692b:	48 63 d2             	movsxd rdx,edx
   14000692e:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006933:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006938:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000693c:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006941:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006944:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006947:	83 c0 01             	add    eax,0x1
   14000694a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000694d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006951:	75 c0                	jne    140006913 <__gdtoa+0x5e9>
   140006953:	e9 8b 00 00 00       	jmp    1400069e3 <__gdtoa+0x6b9>
   140006958:	f2 0f 10 05 30 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a30]        # 14000b390 <.rdata+0x40>
   14000695f:	00 
   140006960:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006965:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006968:	f7 d8                	neg    eax
   14000696a:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   14000696d:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140006971:	74 70                	je     1400069e3 <__gdtoa+0x6b9>
   140006973:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006978:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   14000697b:	83 e0 0f             	and    eax,0xf
   14000697e:	89 c2                	mov    edx,eax
   140006980:	48 8b 05 f9 4c 00 00 	mov    rax,QWORD PTR [rip+0x4cf9]        # 14000b680 <.refptr.__tens_D2A>
   140006987:	48 63 d2             	movsxd rdx,edx
   14000698a:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   14000698f:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006993:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006998:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   14000699b:	c1 f8 04             	sar    eax,0x4
   14000699e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400069a1:	eb 3a                	jmp    1400069dd <__gdtoa+0x6b3>
   1400069a3:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400069a6:	83 e0 01             	and    eax,0x1
   1400069a9:	85 c0                	test   eax,eax
   1400069ab:	74 24                	je     1400069d1 <__gdtoa+0x6a7>
   1400069ad:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400069b1:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069b6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400069b9:	48 8b 05 f0 4b 00 00 	mov    rax,QWORD PTR [rip+0x4bf0]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400069c0:	48 63 d2             	movsxd rdx,edx
   1400069c3:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400069c8:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069cc:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069d1:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   1400069d4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400069d7:	83 c0 01             	add    eax,0x1
   1400069da:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400069dd:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400069e1:	75 c0                	jne    1400069a3 <__gdtoa+0x679>
   1400069e3:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400069e7:	74 47                	je     140006a30 <__gdtoa+0x706>
   1400069e9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069ee:	f2 0f 10 05 9a 49 00 	movsd  xmm0,QWORD PTR [rip+0x499a]        # 14000b390 <.rdata+0x40>
   1400069f5:	00 
   1400069f6:	66 0f 2f c1          	comisd xmm0,xmm1
   1400069fa:	76 34                	jbe    140006a30 <__gdtoa+0x706>
   1400069fc:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a00:	7e 2e                	jle    140006a30 <__gdtoa+0x706>
   140006a02:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   140006a06:	0f 8e f5 02 00 00    	jle    140006d01 <__gdtoa+0x9d7>
   140006a0c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006a0f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006a12:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006a16:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a1b:	f2 0f 10 05 75 49 00 	movsd  xmm0,QWORD PTR [rip+0x4975]        # 14000b398 <.rdata+0x48>
   140006a22:	00 
   140006a23:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a27:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a2c:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006a30:	66 0f ef c9          	pxor   xmm1,xmm1
   140006a34:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006a39:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a3e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006a42:	f2 0f 10 05 56 49 00 	movsd  xmm0,QWORD PTR [rip+0x4956]        # 14000b3a0 <.rdata+0x50>
   140006a49:	00 
   140006a4a:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006a4e:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a53:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   140006a56:	2d 00 00 40 03       	sub    eax,0x3400000
   140006a5b:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   140006a5e:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a62:	75 5f                	jne    140006ac3 <__gdtoa+0x799>
   140006a64:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006a6b:	00 
   140006a6c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006a70:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006a74:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a79:	f2 0f 10 0d 27 49 00 	movsd  xmm1,QWORD PTR [rip+0x4927]        # 14000b3a8 <.rdata+0x58>
   140006a80:	00 
   140006a81:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a85:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a8a:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a8f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006a94:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a98:	0f 87 ac 07 00 00    	ja     14000724a <__gdtoa+0xf20>
   140006a9e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006aa3:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006aa8:	f3 0f 7e 15 00 49 00 	movq   xmm2,QWORD PTR [rip+0x4900]        # 14000b3b0 <.rdata+0x60>
   140006aaf:	00 
   140006ab0:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006ab4:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ab8:	0f 87 6e 07 00 00    	ja     14000722c <__gdtoa+0xf02>
   140006abe:	e9 42 02 00 00       	jmp    140006d05 <__gdtoa+0x9db>
   140006ac3:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006ac7:	0f 84 22 01 00 00    	je     140006bef <__gdtoa+0x8c5>
   140006acd:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006ad2:	f2 0f 10 05 e6 48 00 	movsd  xmm0,QWORD PTR [rip+0x48e6]        # 14000b3c0 <.rdata+0x70>
   140006ad9:	00 
   140006ada:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006ade:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006ae1:	8d 50 ff             	lea    edx,[rax-0x1]
   140006ae4:	48 8b 05 95 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b95]        # 14000b680 <.refptr.__tens_D2A>
   140006aeb:	48 63 d2             	movsxd rdx,edx
   140006aee:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006af3:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006af7:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006afc:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b00:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b05:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006b0c:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b11:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006b16:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006b1a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006b1d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b22:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b26:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006b2b:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006b30:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b34:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b39:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006b3c:	8d 48 30             	lea    ecx,[rax+0x30]
   140006b3f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006b43:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006b47:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006b4b:	89 ca                	mov    edx,ecx
   140006b4d:	88 10                	mov    BYTE PTR [rax],dl
   140006b4f:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b54:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b59:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b5d:	76 29                	jbe    140006b88 <__gdtoa+0x85e>
   140006b5f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b64:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b68:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b6c:	7a 0e                	jp     140006b7c <__gdtoa+0x852>
   140006b6e:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b72:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b76:	0f 84 93 0c 00 00    	je     14000780f <__gdtoa+0x14e5>
   140006b7c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006b83:	e9 87 0c 00 00       	jmp    14000780f <__gdtoa+0x14e5>
   140006b88:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006b8d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006b92:	66 0f 28 c8          	movapd xmm1,xmm0
   140006b96:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006b9a:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b9f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ba3:	0f 87 c3 02 00 00    	ja     140006e6c <__gdtoa+0xb42>
   140006ba9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006bac:	83 c0 01             	add    eax,0x1
   140006baf:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006bb2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006bb5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006bb8:	0f 8e 46 01 00 00    	jle    140006d04 <__gdtoa+0x9da>
   140006bbe:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006bc3:	f2 0f 10 05 cd 47 00 	movsd  xmm0,QWORD PTR [rip+0x47cd]        # 14000b398 <.rdata+0x48>
   140006bca:	00 
   140006bcb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bcf:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006bd4:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006bd9:	f2 0f 10 05 b7 47 00 	movsd  xmm0,QWORD PTR [rip+0x47b7]        # 14000b398 <.rdata+0x48>
   140006be0:	00 
   140006be1:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006be5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006bea:	e9 1d ff ff ff       	jmp    140006b0c <__gdtoa+0x7e2>
   140006bef:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006bf4:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006bf7:	8d 50 ff             	lea    edx,[rax-0x1]
   140006bfa:	48 8b 05 7f 4a 00 00 	mov    rax,QWORD PTR [rip+0x4a7f]        # 14000b680 <.refptr.__tens_D2A>
   140006c01:	48 63 d2             	movsxd rdx,edx
   140006c04:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006c09:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c0d:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c12:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006c19:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c1e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006c23:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006c27:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006c2a:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006c2e:	74 1c                	je     140006c4c <__gdtoa+0x922>
   140006c30:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c35:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c39:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006c3e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006c43:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006c47:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c4c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006c4f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006c52:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006c56:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006c5a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006c5e:	89 ca                	mov    edx,ecx
   140006c60:	88 10                	mov    BYTE PTR [rax],dl
   140006c62:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c65:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006c68:	75 73                	jne    140006cdd <__gdtoa+0x9b3>
   140006c6a:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006c6f:	f2 0f 10 05 49 47 00 	movsd  xmm0,QWORD PTR [rip+0x4749]        # 14000b3c0 <.rdata+0x70>
   140006c76:	00 
   140006c77:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c7b:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006c80:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c85:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c8a:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006c8f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c93:	0f 87 d6 01 00 00    	ja     140006e6f <__gdtoa+0xb45>
   140006c99:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c9e:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006ca3:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006ca8:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006cac:	66 0f 2f c1          	comisd xmm0,xmm1
   140006cb0:	77 02                	ja     140006cb4 <__gdtoa+0x98a>
   140006cb2:	eb 51                	jmp    140006d05 <__gdtoa+0x9db>
   140006cb4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006cb9:	66 0f ef c9          	pxor   xmm1,xmm1
   140006cbd:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006cc1:	7a 0e                	jp     140006cd1 <__gdtoa+0x9a7>
   140006cc3:	66 0f ef c9          	pxor   xmm1,xmm1
   140006cc7:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006ccb:	0f 84 41 0b 00 00    	je     140007812 <__gdtoa+0x14e8>
   140006cd1:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006cd8:	e9 35 0b 00 00       	jmp    140007812 <__gdtoa+0x14e8>
   140006cdd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ce0:	83 c0 01             	add    eax,0x1
   140006ce3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006ce6:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ceb:	f2 0f 10 05 a5 46 00 	movsd  xmm0,QWORD PTR [rip+0x46a5]        # 14000b398 <.rdata+0x48>
   140006cf2:	00 
   140006cf3:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006cf7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006cfc:	e9 18 ff ff ff       	jmp    140006c19 <__gdtoa+0x8ef>
   140006d01:	90                   	nop
   140006d02:	eb 01                	jmp    140006d05 <__gdtoa+0x9db>
   140006d04:	90                   	nop
   140006d05:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006d09:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006d0d:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006d12:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d17:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006d1a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006d1d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006d20:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006d23:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006d2a:	0f 88 bf 01 00 00    	js     140006eef <__gdtoa+0xbc5>
   140006d30:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006d37:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006d3a:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006d3d:	0f 8f ac 01 00 00    	jg     140006eef <__gdtoa+0xbc5>
   140006d43:	48 8b 05 36 49 00 00 	mov    rax,QWORD PTR [rip+0x4936]        # 14000b680 <.refptr.__tens_D2A>
   140006d4a:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006d4d:	48 63 d2             	movsxd rdx,edx
   140006d50:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006d55:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006d5a:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006d61:	79 45                	jns    140006da8 <__gdtoa+0xa7e>
   140006d63:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d67:	7f 3f                	jg     140006da8 <__gdtoa+0xa7e>
   140006d69:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006d70:	00 
   140006d71:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006d75:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006d79:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d7d:	0f 88 ac 04 00 00    	js     14000722f <__gdtoa+0xf05>
   140006d83:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d88:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006d8d:	f2 0f 10 05 13 46 00 	movsd  xmm0,QWORD PTR [rip+0x4613]        # 14000b3a8 <.rdata+0x58>
   140006d94:	00 
   140006d95:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006d99:	66 0f 2f c1          	comisd xmm0,xmm1
   140006d9d:	0f 83 8c 04 00 00    	jae    14000722f <__gdtoa+0xf05>
   140006da3:	e9 a6 04 00 00       	jmp    14000724e <__gdtoa+0xf24>
   140006da8:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006daf:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006db4:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006db9:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006dbd:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006dc0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006dc5:	66 0f ef c9          	pxor   xmm1,xmm1
   140006dc9:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006dce:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006dd3:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006dd7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006ddc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006ddf:	8d 48 30             	lea    ecx,[rax+0x30]
   140006de2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006de6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006dea:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006dee:	89 ca                	mov    edx,ecx
   140006df0:	88 10                	mov    BYTE PTR [rax],dl
   140006df2:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006df7:	66 0f ef c9          	pxor   xmm1,xmm1
   140006dfb:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006dff:	7a 0e                	jp     140006e0f <__gdtoa+0xae5>
   140006e01:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e05:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e09:	0f 84 da 00 00 00    	je     140006ee9 <__gdtoa+0xbbf>
   140006e0f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e12:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006e15:	0f 85 aa 00 00 00    	jne    140006ec5 <__gdtoa+0xb9b>
   140006e1b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006e1f:	74 12                	je     140006e33 <__gdtoa+0xb09>
   140006e21:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006e25:	74 4b                	je     140006e72 <__gdtoa+0xb48>
   140006e27:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e2e:	e9 e3 09 00 00       	jmp    140007816 <__gdtoa+0x14ec>
   140006e33:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e38:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006e3c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e41:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e46:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006e4b:	77 28                	ja     140006e75 <__gdtoa+0xb4b>
   140006e4d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e52:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e57:	7a 63                	jp     140006ebc <__gdtoa+0xb92>
   140006e59:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e5e:	75 5c                	jne    140006ebc <__gdtoa+0xb92>
   140006e60:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006e63:	83 e0 01             	and    eax,0x1
   140006e66:	85 c0                	test   eax,eax
   140006e68:	74 52                	je     140006ebc <__gdtoa+0xb92>
   140006e6a:	eb 0a                	jmp    140006e76 <__gdtoa+0xb4c>
   140006e6c:	90                   	nop
   140006e6d:	eb 07                	jmp    140006e76 <__gdtoa+0xb4c>
   140006e6f:	90                   	nop
   140006e70:	eb 04                	jmp    140006e76 <__gdtoa+0xb4c>
   140006e72:	90                   	nop
   140006e73:	eb 01                	jmp    140006e76 <__gdtoa+0xb4c>
   140006e75:	90                   	nop
   140006e76:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006e7d:	eb 17                	jmp    140006e96 <__gdtoa+0xb6c>
   140006e7f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e83:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006e87:	75 0d                	jne    140006e96 <__gdtoa+0xb6c>
   140006e89:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006e8d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e91:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006e94:	eb 10                	jmp    140006ea6 <__gdtoa+0xb7c>
   140006e96:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006e9b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e9f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006ea2:	3c 39                	cmp    al,0x39
   140006ea4:	74 d9                	je     140006e7f <__gdtoa+0xb55>
   140006ea6:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006eaa:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006eae:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006eb2:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006eb5:	83 c2 01             	add    edx,0x1
   140006eb8:	88 10                	mov    BYTE PTR [rax],dl
   140006eba:	eb 2e                	jmp    140006eea <__gdtoa+0xbc0>
   140006ebc:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006ec3:	eb 25                	jmp    140006eea <__gdtoa+0xbc0>
   140006ec5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ec8:	83 c0 01             	add    eax,0x1
   140006ecb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006ece:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ed3:	f2 0f 10 05 bd 44 00 	movsd  xmm0,QWORD PTR [rip+0x44bd]        # 14000b398 <.rdata+0x48>
   140006eda:	00 
   140006edb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006edf:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006ee4:	e9 c6 fe ff ff       	jmp    140006daf <__gdtoa+0xa85>
   140006ee9:	90                   	nop
   140006eea:	e9 27 09 00 00       	jmp    140007816 <__gdtoa+0x14ec>
   140006eef:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006ef2:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006ef5:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006ef8:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006efb:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006f02:	00 
   140006f03:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006f07:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f0b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006f0f:	0f 84 e0 00 00 00    	je     140006ff5 <__gdtoa+0xccb>
   140006f15:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006f18:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006f1b:	29 c2                	sub    edx,eax
   140006f1d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f20:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f23:	8d 50 01             	lea    edx,[rax+0x1]
   140006f26:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f29:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f2f:	29 c2                	sub    edx,eax
   140006f31:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f38:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f3b:	39 c2                	cmp    edx,eax
   140006f3d:	7d 43                	jge    140006f82 <__gdtoa+0xc58>
   140006f3f:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006f46:	74 3a                	je     140006f82 <__gdtoa+0xc58>
   140006f48:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006f4f:	74 31                	je     140006f82 <__gdtoa+0xc58>
   140006f51:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f58:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f5b:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f61:	29 c2                	sub    edx,eax
   140006f63:	8d 42 01             	lea    eax,[rdx+0x1]
   140006f66:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f69:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f70:	7e 68                	jle    140006fda <__gdtoa+0xcb0>
   140006f72:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006f76:	7e 62                	jle    140006fda <__gdtoa+0xcb0>
   140006f78:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f7b:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006f7e:	7d 5a                	jge    140006fda <__gdtoa+0xcb0>
   140006f80:	eb 0a                	jmp    140006f8c <__gdtoa+0xc62>
   140006f82:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f89:	7e 50                	jle    140006fdb <__gdtoa+0xcb1>
   140006f8b:	90                   	nop
   140006f8c:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f8f:	83 e8 01             	sub    eax,0x1
   140006f92:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006f95:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006f98:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006f9b:	7c 08                	jl     140006fa5 <__gdtoa+0xc7b>
   140006f9d:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fa0:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006fa3:	eb 19                	jmp    140006fbe <__gdtoa+0xc94>
   140006fa5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006fa8:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006fab:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fae:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006fb1:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fb4:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006fb7:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006fbe:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006fc1:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006fc4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fc7:	85 c0                	test   eax,eax
   140006fc9:	79 10                	jns    140006fdb <__gdtoa+0xcb1>
   140006fcb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fce:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006fd1:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006fd8:	eb 01                	jmp    140006fdb <__gdtoa+0xcb1>
   140006fda:	90                   	nop
   140006fdb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fde:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140006fe1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fe4:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140006fe7:	b9 01 00 00 00       	mov    ecx,0x1
   140006fec:	e8 f6 0f 00 00       	call   140007fe7 <__i2b_D2A>
   140006ff1:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006ff5:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140006ff9:	7e 26                	jle    140007021 <__gdtoa+0xcf7>
   140006ffb:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   140006fff:	7e 20                	jle    140007021 <__gdtoa+0xcf7>
   140007001:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007004:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140007007:	39 c2                	cmp    edx,eax
   140007009:	0f 4e c2             	cmovle eax,edx
   14000700c:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000700f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007012:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140007015:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007018:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   14000701b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000701e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140007021:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140007025:	7e 7e                	jle    1400070a5 <__gdtoa+0xd7b>
   140007027:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000702b:	74 65                	je     140007092 <__gdtoa+0xd68>
   14000702d:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140007031:	7e 3b                	jle    14000706e <__gdtoa+0xd44>
   140007033:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140007036:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000703a:	48 89 c1             	mov    rcx,rax
   14000703d:	e8 11 12 00 00       	call   140008253 <__pow5mult_D2A>
   140007042:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007046:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000704a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000704e:	48 89 c1             	mov    rcx,rax
   140007051:	e8 d7 0f 00 00       	call   14000802d <__mult_D2A>
   140007056:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000705a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000705e:	48 89 c1             	mov    rcx,rax
   140007061:	e8 c8 0d 00 00       	call   140007e2e <__Bfree_D2A>
   140007066:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000706a:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000706e:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140007071:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   140007074:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007077:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000707b:	74 28                	je     1400070a5 <__gdtoa+0xd7b>
   14000707d:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   140007080:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007084:	48 89 c1             	mov    rcx,rax
   140007087:	e8 c7 11 00 00       	call   140008253 <__pow5mult_D2A>
   14000708c:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007090:	eb 13                	jmp    1400070a5 <__gdtoa+0xd7b>
   140007092:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   140007095:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007099:	48 89 c1             	mov    rcx,rax
   14000709c:	e8 b2 11 00 00       	call   140008253 <__pow5mult_D2A>
   1400070a1:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070a5:	b9 01 00 00 00       	mov    ecx,0x1
   1400070aa:	e8 38 0f 00 00       	call   140007fe7 <__i2b_D2A>
   1400070af:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070b3:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   1400070b7:	7e 13                	jle    1400070cc <__gdtoa+0xda2>
   1400070b9:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   1400070bc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070c0:	48 89 c1             	mov    rcx,rax
   1400070c3:	e8 8b 11 00 00       	call   140008253 <__pow5mult_D2A>
   1400070c8:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070cc:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   1400070d3:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400070da:	7f 29                	jg     140007105 <__gdtoa+0xddb>
   1400070dc:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   1400070df:	83 f8 01             	cmp    eax,0x1
   1400070e2:	75 21                	jne    140007105 <__gdtoa+0xddb>
   1400070e4:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400070eb:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400070ee:	83 c0 01             	add    eax,0x1
   1400070f1:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   1400070f4:	7e 0f                	jle    140007105 <__gdtoa+0xddb>
   1400070f6:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   1400070fa:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   1400070fe:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   140007105:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007109:	74 22                	je     14000712d <__gdtoa+0xe03>
   14000710b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000710f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007112:	8d 50 ff             	lea    edx,[rax-0x1]
   140007115:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007119:	48 63 d2             	movsxd rdx,edx
   14000711c:	48 83 c2 04          	add    rdx,0x4
   140007120:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   140007124:	89 c1                	mov    ecx,eax
   140007126:	e8 c5 f0 ff ff       	call   1400061f0 <__hi0bits_D2A>
   14000712b:	eb 05                	jmp    140007132 <__gdtoa+0xe08>
   14000712d:	b8 1f 00 00 00       	mov    eax,0x1f
   140007132:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   140007135:	83 e8 04             	sub    eax,0x4
   140007138:	83 e0 1f             	and    eax,0x1f
   14000713b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000713e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007141:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   140007144:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007147:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   14000714a:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   14000714e:	7e 13                	jle    140007163 <__gdtoa+0xe39>
   140007150:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   140007153:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007157:	48 89 c1             	mov    rcx,rax
   14000715a:	e8 b1 12 00 00       	call   140008410 <__lshift_D2A>
   14000715f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007163:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007166:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140007169:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000716d:	7e 13                	jle    140007182 <__gdtoa+0xe58>
   14000716f:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007172:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007176:	48 89 c1             	mov    rcx,rax
   140007179:	e8 92 12 00 00       	call   140008410 <__lshift_D2A>
   14000717e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007182:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140007186:	74 5a                	je     1400071e2 <__gdtoa+0xeb8>
   140007188:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000718c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007190:	48 89 c1             	mov    rcx,rax
   140007193:	e8 05 14 00 00       	call   14000859d <__cmp_D2A>
   140007198:	85 c0                	test   eax,eax
   14000719a:	79 46                	jns    1400071e2 <__gdtoa+0xeb8>
   14000719c:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400071a0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071a4:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071aa:	ba 0a 00 00 00       	mov    edx,0xa
   1400071af:	48 89 c1             	mov    rcx,rax
   1400071b2:	e8 02 0d 00 00       	call   140007eb9 <__multadd_D2A>
   1400071b7:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400071bb:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400071bf:	74 1b                	je     1400071dc <__gdtoa+0xeb2>
   1400071c1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071c5:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071cb:	ba 0a 00 00 00       	mov    edx,0xa
   1400071d0:	48 89 c1             	mov    rcx,rax
   1400071d3:	e8 e1 0c 00 00       	call   140007eb9 <__multadd_D2A>
   1400071d8:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400071dc:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400071df:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400071e2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400071e6:	0f 8f 81 00 00 00    	jg     14000726d <__gdtoa+0xf43>
   1400071ec:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400071f3:	7e 78                	jle    14000726d <__gdtoa+0xf43>
   1400071f5:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400071f9:	78 37                	js     140007232 <__gdtoa+0xf08>
   1400071fb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400071ff:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007205:	ba 05 00 00 00       	mov    edx,0x5
   14000720a:	48 89 c1             	mov    rcx,rax
   14000720d:	e8 a7 0c 00 00       	call   140007eb9 <__multadd_D2A>
   140007212:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007216:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000721a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000721e:	48 89 c1             	mov    rcx,rax
   140007221:	e8 77 13 00 00       	call   14000859d <__cmp_D2A>
   140007226:	85 c0                	test   eax,eax
   140007228:	7f 23                	jg     14000724d <__gdtoa+0xf23>
   14000722a:	eb 07                	jmp    140007233 <__gdtoa+0xf09>
   14000722c:	90                   	nop
   14000722d:	eb 04                	jmp    140007233 <__gdtoa+0xf09>
   14000722f:	90                   	nop
   140007230:	eb 01                	jmp    140007233 <__gdtoa+0xf09>
   140007232:	90                   	nop
   140007233:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   140007239:	f7 d0                	not    eax
   14000723b:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   14000723e:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007245:	e9 87 05 00 00       	jmp    1400077d1 <__gdtoa+0x14a7>
   14000724a:	90                   	nop
   14000724b:	eb 01                	jmp    14000724e <__gdtoa+0xf24>
   14000724d:	90                   	nop
   14000724e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007255:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007259:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000725d:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007261:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007264:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007268:	e9 64 05 00 00       	jmp    1400077d1 <__gdtoa+0x14a7>
   14000726d:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140007271:	0f 84 14 04 00 00    	je     14000768b <__gdtoa+0x1361>
   140007277:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   14000727b:	7e 13                	jle    140007290 <__gdtoa+0xf66>
   14000727d:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   140007280:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007284:	48 89 c1             	mov    rcx,rax
   140007287:	e8 84 11 00 00       	call   140008410 <__lshift_D2A>
   14000728c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007290:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007294:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007298:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   14000729c:	74 57                	je     1400072f5 <__gdtoa+0xfcb>
   14000729e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072a2:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400072a5:	89 c1                	mov    ecx,eax
   1400072a7:	e8 41 0a 00 00       	call   140007ced <__Balloc_D2A>
   1400072ac:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072b0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400072b4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400072b7:	48 98                	cdqe
   1400072b9:	48 83 c0 02          	add    rax,0x2
   1400072bd:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   1400072c4:	00 
   1400072c5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400072c9:	48 8d 50 10          	lea    rdx,[rax+0x10]
   1400072cd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072d1:	48 83 c0 10          	add    rax,0x10
   1400072d5:	49 89 c8             	mov    r8,rcx
   1400072d8:	48 89 c1             	mov    rcx,rax
   1400072db:	e8 e8 23 00 00       	call   1400096c8 <memcpy>
   1400072e0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072e4:	ba 01 00 00 00       	mov    edx,0x1
   1400072e9:	48 89 c1             	mov    rcx,rax
   1400072ec:	e8 1f 11 00 00       	call   140008410 <__lshift_D2A>
   1400072f1:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072f5:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400072fc:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007300:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007304:	48 89 c1             	mov    rcx,rax
   140007307:	e8 62 ec ff ff       	call   140005f6e <__quorem_D2A>
   14000730c:	83 c0 30             	add    eax,0x30
   14000730f:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007312:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007316:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000731a:	48 89 c1             	mov    rcx,rax
   14000731d:	e8 7b 12 00 00       	call   14000859d <__cmp_D2A>
   140007322:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007325:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007329:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000732d:	48 89 c1             	mov    rcx,rax
   140007330:	e8 38 13 00 00       	call   14000866d <__diff_D2A>
   140007335:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140007339:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   14000733d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140007340:	85 c0                	test   eax,eax
   140007342:	75 15                	jne    140007359 <__gdtoa+0x102f>
   140007344:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140007348:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000734c:	48 89 c1             	mov    rcx,rax
   14000734f:	e8 49 12 00 00       	call   14000859d <__cmp_D2A>
   140007354:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007357:	eb 07                	jmp    140007360 <__gdtoa+0x1036>
   140007359:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   140007360:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140007364:	48 89 c1             	mov    rcx,rax
   140007367:	e8 c2 0a 00 00       	call   140007e2e <__Bfree_D2A>
   14000736c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007370:	75 70                	jne    1400073e2 <__gdtoa+0x10b8>
   140007372:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007379:	75 67                	jne    1400073e2 <__gdtoa+0x10b8>
   14000737b:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007382:	8b 00                	mov    eax,DWORD PTR [rax]
   140007384:	83 e0 01             	and    eax,0x1
   140007387:	85 c0                	test   eax,eax
   140007389:	75 57                	jne    1400073e2 <__gdtoa+0x10b8>
   14000738b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000738f:	75 51                	jne    1400073e2 <__gdtoa+0x10b8>
   140007391:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007395:	0f 84 01 02 00 00    	je     14000759c <__gdtoa+0x1272>
   14000739b:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000739f:	7f 20                	jg     1400073c1 <__gdtoa+0x1097>
   1400073a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073a5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400073a8:	83 f8 01             	cmp    eax,0x1
   1400073ab:	7f 0b                	jg     1400073b8 <__gdtoa+0x108e>
   1400073ad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073b1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400073b4:	85 c0                	test   eax,eax
   1400073b6:	74 14                	je     1400073cc <__gdtoa+0x10a2>
   1400073b8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400073bf:	eb 0b                	jmp    1400073cc <__gdtoa+0x10a2>
   1400073c1:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   1400073c5:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400073cc:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400073d0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400073d4:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400073d8:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400073db:	88 10                	mov    BYTE PTR [rax],dl
   1400073dd:	e9 ef 03 00 00       	jmp    1400077d1 <__gdtoa+0x14a7>
   1400073e2:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073e6:	78 2b                	js     140007413 <__gdtoa+0x10e9>
   1400073e8:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073ec:	0f 85 96 01 00 00    	jne    140007588 <__gdtoa+0x125e>
   1400073f2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400073f9:	0f 85 89 01 00 00    	jne    140007588 <__gdtoa+0x125e>
   1400073ff:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007406:	8b 00                	mov    eax,DWORD PTR [rax]
   140007408:	83 e0 01             	and    eax,0x1
   14000740b:	85 c0                	test   eax,eax
   14000740d:	0f 85 75 01 00 00    	jne    140007588 <__gdtoa+0x125e>
   140007413:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007417:	0f 84 db 00 00 00    	je     1400074f8 <__gdtoa+0x11ce>
   14000741d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007421:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007424:	83 f8 01             	cmp    eax,0x1
   140007427:	7f 0f                	jg     140007438 <__gdtoa+0x110e>
   140007429:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000742d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007430:	85 c0                	test   eax,eax
   140007432:	0f 84 c0 00 00 00    	je     1400074f8 <__gdtoa+0x11ce>
   140007438:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   14000743c:	0f 85 83 00 00 00    	jne    1400074c5 <__gdtoa+0x119b>
   140007442:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007449:	e9 24 01 00 00       	jmp    140007572 <__gdtoa+0x1248>
   14000744e:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007452:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007456:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000745a:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000745d:	88 10                	mov    BYTE PTR [rax],dl
   14000745f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007463:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007469:	ba 0a 00 00 00       	mov    edx,0xa
   14000746e:	48 89 c1             	mov    rcx,rax
   140007471:	e8 43 0a 00 00       	call   140007eb9 <__multadd_D2A>
   140007476:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000747a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000747e:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007482:	75 08                	jne    14000748c <__gdtoa+0x1162>
   140007484:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007488:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   14000748c:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007490:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007494:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007498:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000749e:	ba 0a 00 00 00       	mov    edx,0xa
   1400074a3:	48 89 c1             	mov    rcx,rax
   1400074a6:	e8 0e 0a 00 00       	call   140007eb9 <__multadd_D2A>
   1400074ab:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400074af:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400074b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074b7:	48 89 c1             	mov    rcx,rax
   1400074ba:	e8 af ea ff ff       	call   140005f6e <__quorem_D2A>
   1400074bf:	83 c0 30             	add    eax,0x30
   1400074c2:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400074c5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400074c9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400074cd:	48 89 c1             	mov    rcx,rax
   1400074d0:	e8 c8 10 00 00       	call   14000859d <__cmp_D2A>
   1400074d5:	85 c0                	test   eax,eax
   1400074d7:	0f 8f 71 ff ff ff    	jg     14000744e <__gdtoa+0x1124>
   1400074dd:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400074e0:	8d 50 01             	lea    edx,[rax+0x1]
   1400074e3:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   1400074e6:	83 f8 39             	cmp    eax,0x39
   1400074e9:	0f 84 b0 00 00 00    	je     14000759f <__gdtoa+0x1275>
   1400074ef:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400074f6:	eb 7a                	jmp    140007572 <__gdtoa+0x1248>
   1400074f8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074fc:	7e 53                	jle    140007551 <__gdtoa+0x1227>
   1400074fe:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007502:	ba 01 00 00 00       	mov    edx,0x1
   140007507:	48 89 c1             	mov    rcx,rax
   14000750a:	e8 01 0f 00 00       	call   140008410 <__lshift_D2A>
   14000750f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007513:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007517:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000751b:	48 89 c1             	mov    rcx,rax
   14000751e:	e8 7a 10 00 00       	call   14000859d <__cmp_D2A>
   140007523:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007526:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000752a:	7f 10                	jg     14000753c <__gdtoa+0x1212>
   14000752c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007530:	75 18                	jne    14000754a <__gdtoa+0x1220>
   140007532:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007535:	83 e0 01             	and    eax,0x1
   140007538:	85 c0                	test   eax,eax
   14000753a:	74 0e                	je     14000754a <__gdtoa+0x1220>
   14000753c:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000753f:	8d 50 01             	lea    edx,[rax+0x1]
   140007542:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007545:	83 f8 39             	cmp    eax,0x39
   140007548:	74 58                	je     1400075a2 <__gdtoa+0x1278>
   14000754a:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007551:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007555:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007558:	83 f8 01             	cmp    eax,0x1
   14000755b:	7f 0b                	jg     140007568 <__gdtoa+0x123e>
   14000755d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007561:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007564:	85 c0                	test   eax,eax
   140007566:	74 09                	je     140007571 <__gdtoa+0x1247>
   140007568:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000756f:	eb 01                	jmp    140007572 <__gdtoa+0x1248>
   140007571:	90                   	nop
   140007572:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007576:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000757a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000757e:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007581:	88 10                	mov    BYTE PTR [rax],dl
   140007583:	e9 49 02 00 00       	jmp    1400077d1 <__gdtoa+0x14a7>
   140007588:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000758c:	7e 52                	jle    1400075e0 <__gdtoa+0x12b6>
   14000758e:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007592:	74 4c                	je     1400075e0 <__gdtoa+0x12b6>
   140007594:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007598:	75 24                	jne    1400075be <__gdtoa+0x1294>
   14000759a:	eb 07                	jmp    1400075a3 <__gdtoa+0x1279>
   14000759c:	90                   	nop
   14000759d:	eb 04                	jmp    1400075a3 <__gdtoa+0x1279>
   14000759f:	90                   	nop
   1400075a0:	eb 01                	jmp    1400075a3 <__gdtoa+0x1279>
   1400075a2:	90                   	nop
   1400075a3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075a7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075ab:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075af:	c6 00 39             	mov    BYTE PTR [rax],0x39
   1400075b2:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075b9:	e9 9d 01 00 00       	jmp    14000775b <__gdtoa+0x1431>
   1400075be:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075c5:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400075c8:	8d 48 01             	lea    ecx,[rax+0x1]
   1400075cb:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075cf:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075d3:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075d7:	89 ca                	mov    edx,ecx
   1400075d9:	88 10                	mov    BYTE PTR [rax],dl
   1400075db:	e9 f1 01 00 00       	jmp    1400077d1 <__gdtoa+0x14a7>
   1400075e0:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075e4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075e8:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075ec:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400075ef:	88 10                	mov    BYTE PTR [rax],dl
   1400075f1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400075f4:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   1400075f7:	0f 84 ea 00 00 00    	je     1400076e7 <__gdtoa+0x13bd>
   1400075fd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007601:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007607:	ba 0a 00 00 00       	mov    edx,0xa
   14000760c:	48 89 c1             	mov    rcx,rax
   14000760f:	e8 a5 08 00 00       	call   140007eb9 <__multadd_D2A>
   140007614:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007618:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000761c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007620:	75 25                	jne    140007647 <__gdtoa+0x131d>
   140007622:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007626:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000762c:	ba 0a 00 00 00       	mov    edx,0xa
   140007631:	48 89 c1             	mov    rcx,rax
   140007634:	e8 80 08 00 00       	call   140007eb9 <__multadd_D2A>
   140007639:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000763d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007641:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007645:	eb 36                	jmp    14000767d <__gdtoa+0x1353>
   140007647:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000764b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007651:	ba 0a 00 00 00       	mov    edx,0xa
   140007656:	48 89 c1             	mov    rcx,rax
   140007659:	e8 5b 08 00 00       	call   140007eb9 <__multadd_D2A>
   14000765e:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007662:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007666:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000766c:	ba 0a 00 00 00       	mov    edx,0xa
   140007671:	48 89 c1             	mov    rcx,rax
   140007674:	e8 40 08 00 00       	call   140007eb9 <__multadd_D2A>
   140007679:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000767d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007680:	83 c0 01             	add    eax,0x1
   140007683:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007686:	e9 71 fc ff ff       	jmp    1400072fc <__gdtoa+0xfd2>
   14000768b:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140007692:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007696:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000769a:	48 89 c1             	mov    rcx,rax
   14000769d:	e8 cc e8 ff ff       	call   140005f6e <__quorem_D2A>
   1400076a2:	83 c0 30             	add    eax,0x30
   1400076a5:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400076a8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076ac:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076b0:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076b4:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400076b7:	88 10                	mov    BYTE PTR [rax],dl
   1400076b9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076bc:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   1400076bf:	7e 29                	jle    1400076ea <__gdtoa+0x13c0>
   1400076c1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076c5:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400076cb:	ba 0a 00 00 00       	mov    edx,0xa
   1400076d0:	48 89 c1             	mov    rcx,rax
   1400076d3:	e8 e1 07 00 00       	call   140007eb9 <__multadd_D2A>
   1400076d8:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400076dc:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076df:	83 c0 01             	add    eax,0x1
   1400076e2:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400076e5:	eb ab                	jmp    140007692 <__gdtoa+0x1368>
   1400076e7:	90                   	nop
   1400076e8:	eb 01                	jmp    1400076eb <__gdtoa+0x13c1>
   1400076ea:	90                   	nop
   1400076eb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400076ef:	74 26                	je     140007717 <__gdtoa+0x13ed>
   1400076f1:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400076f5:	0f 84 ae 00 00 00    	je     1400077a9 <__gdtoa+0x147f>
   1400076fb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076ff:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007702:	83 f8 01             	cmp    eax,0x1
   140007705:	7f 50                	jg     140007757 <__gdtoa+0x142d>
   140007707:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000770b:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000770e:	85 c0                	test   eax,eax
   140007710:	75 45                	jne    140007757 <__gdtoa+0x142d>
   140007712:	e9 92 00 00 00       	jmp    1400077a9 <__gdtoa+0x147f>
   140007717:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000771b:	ba 01 00 00 00       	mov    edx,0x1
   140007720:	48 89 c1             	mov    rcx,rax
   140007723:	e8 e8 0c 00 00       	call   140008410 <__lshift_D2A>
   140007728:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000772c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007730:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007734:	48 89 c1             	mov    rcx,rax
   140007737:	e8 61 0e 00 00       	call   14000859d <__cmp_D2A>
   14000773c:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   14000773f:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007743:	7f 15                	jg     14000775a <__gdtoa+0x1430>
   140007745:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007749:	75 61                	jne    1400077ac <__gdtoa+0x1482>
   14000774b:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000774e:	83 e0 01             	and    eax,0x1
   140007751:	85 c0                	test   eax,eax
   140007753:	74 5a                	je     1400077af <__gdtoa+0x1485>
   140007755:	eb 04                	jmp    14000775b <__gdtoa+0x1431>
   140007757:	90                   	nop
   140007758:	eb 01                	jmp    14000775b <__gdtoa+0x1431>
   14000775a:	90                   	nop
   14000775b:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007762:	eb 1f                	jmp    140007783 <__gdtoa+0x1459>
   140007764:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007768:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000776c:	75 15                	jne    140007783 <__gdtoa+0x1459>
   14000776e:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007772:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007776:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000777a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000777e:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007781:	eb 4e                	jmp    1400077d1 <__gdtoa+0x14a7>
   140007783:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140007788:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000778c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000778f:	3c 39                	cmp    al,0x39
   140007791:	74 d1                	je     140007764 <__gdtoa+0x143a>
   140007793:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007797:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000779b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000779f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   1400077a2:	83 c2 01             	add    edx,0x1
   1400077a5:	88 10                	mov    BYTE PTR [rax],dl
   1400077a7:	eb 28                	jmp    1400077d1 <__gdtoa+0x14a7>
   1400077a9:	90                   	nop
   1400077aa:	eb 04                	jmp    1400077b0 <__gdtoa+0x1486>
   1400077ac:	90                   	nop
   1400077ad:	eb 01                	jmp    1400077b0 <__gdtoa+0x1486>
   1400077af:	90                   	nop
   1400077b0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077b4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400077b7:	83 f8 01             	cmp    eax,0x1
   1400077ba:	7f 0b                	jg     1400077c7 <__gdtoa+0x149d>
   1400077bc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077c0:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400077c3:	85 c0                	test   eax,eax
   1400077c5:	74 09                	je     1400077d0 <__gdtoa+0x14a6>
   1400077c7:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400077ce:	eb 01                	jmp    1400077d1 <__gdtoa+0x14a7>
   1400077d0:	90                   	nop
   1400077d1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400077d5:	48 89 c1             	mov    rcx,rax
   1400077d8:	e8 51 06 00 00       	call   140007e2e <__Bfree_D2A>
   1400077dd:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   1400077e2:	74 31                	je     140007815 <__gdtoa+0x14eb>
   1400077e4:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400077e9:	74 16                	je     140007801 <__gdtoa+0x14d7>
   1400077eb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400077ef:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400077f3:	74 0c                	je     140007801 <__gdtoa+0x14d7>
   1400077f5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400077f9:	48 89 c1             	mov    rcx,rax
   1400077fc:	e8 2d 06 00 00       	call   140007e2e <__Bfree_D2A>
   140007801:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007805:	48 89 c1             	mov    rcx,rax
   140007808:	e8 21 06 00 00       	call   140007e2e <__Bfree_D2A>
   14000780d:	eb 0e                	jmp    14000781d <__gdtoa+0x14f3>
   14000780f:	90                   	nop
   140007810:	eb 0b                	jmp    14000781d <__gdtoa+0x14f3>
   140007812:	90                   	nop
   140007813:	eb 08                	jmp    14000781d <__gdtoa+0x14f3>
   140007815:	90                   	nop
   140007816:	eb 05                	jmp    14000781d <__gdtoa+0x14f3>
   140007818:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000781d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007821:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140007825:	73 0f                	jae    140007836 <__gdtoa+0x150c>
   140007827:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000782b:	48 83 e8 01          	sub    rax,0x1
   14000782f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140007832:	3c 30                	cmp    al,0x30
   140007834:	74 e2                	je     140007818 <__gdtoa+0x14ee>
   140007836:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000783a:	48 89 c1             	mov    rcx,rax
   14000783d:	e8 ec 05 00 00       	call   140007e2e <__Bfree_D2A>
   140007842:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007846:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140007849:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000784c:	8d 50 01             	lea    edx,[rax+0x1]
   14000784f:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140007856:	89 10                	mov    DWORD PTR [rax],edx
   140007858:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   14000785f:	00 
   140007860:	74 0e                	je     140007870 <__gdtoa+0x1546>
   140007862:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140007869:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   14000786d:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007870:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007877:	8b 00                	mov    eax,DWORD PTR [rax]
   140007879:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   14000787c:	89 c2                	mov    edx,eax
   14000787e:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007885:	89 10                	mov    DWORD PTR [rax],edx
   140007887:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000788b:	48 81 c4 00 01 00 00 	add    rsp,0x100
   140007892:	5d                   	pop    rbp
   140007893:	c3                   	ret
   140007894:	90                   	nop
   140007895:	90                   	nop
   140007896:	90                   	nop
   140007897:	90                   	nop
   140007898:	90                   	nop
   140007899:	90                   	nop
   14000789a:	90                   	nop
   14000789b:	90                   	nop
   14000789c:	90                   	nop
   14000789d:	90                   	nop
   14000789e:	90                   	nop
   14000789f:	90                   	nop

00000001400078a0 <__lo0bits_D2A>:
   1400078a0:	55                   	push   rbp
   1400078a1:	48 89 e5             	mov    rbp,rsp
   1400078a4:	48 83 ec 10          	sub    rsp,0x10
   1400078a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400078ac:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078b0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400078b2:	f3 0f bc c0          	tzcnt  eax,eax
   1400078b6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400078b9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078bd:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078bf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400078c2:	89 c1                	mov    ecx,eax
   1400078c4:	d3 ea                	shr    edx,cl
   1400078c6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078ca:	89 10                	mov    DWORD PTR [rax],edx
   1400078cc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400078cf:	48 83 c4 10          	add    rsp,0x10
   1400078d3:	5d                   	pop    rbp
   1400078d4:	c3                   	ret

00000001400078d5 <__rshift_D2A>:
   1400078d5:	55                   	push   rbp
   1400078d6:	48 89 e5             	mov    rbp,rsp
   1400078d9:	48 83 ec 20          	sub    rsp,0x20
   1400078dd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400078e1:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400078e4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078e8:	48 83 c0 18          	add    rax,0x18
   1400078ec:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400078f0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400078f4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400078f8:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400078fb:	c1 f8 05             	sar    eax,0x5
   1400078fe:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007901:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007905:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007908:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   14000790b:	0f 8d e4 00 00 00    	jge    1400079f5 <__rshift_D2A+0x120>
   140007911:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007915:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007918:	48 98                	cdqe
   14000791a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007921:	00 
   140007922:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007926:	48 01 d0             	add    rax,rdx
   140007929:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000792d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007930:	48 98                	cdqe
   140007932:	48 c1 e0 02          	shl    rax,0x2
   140007936:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   14000793a:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000793e:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140007942:	0f 84 a3 00 00 00    	je     1400079eb <__rshift_D2A+0x116>
   140007948:	b8 20 00 00 00       	mov    eax,0x20
   14000794d:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   140007950:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007953:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007957:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000795b:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000795f:	8b 10                	mov    edx,DWORD PTR [rax]
   140007961:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007964:	89 c1                	mov    ecx,eax
   140007966:	d3 ea                	shr    edx,cl
   140007968:	89 d0                	mov    eax,edx
   14000796a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000796d:	eb 3c                	jmp    1400079ab <__rshift_D2A+0xd6>
   14000796f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007973:	8b 10                	mov    edx,DWORD PTR [rax]
   140007975:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007978:	89 c1                	mov    ecx,eax
   14000797a:	d3 e2                	shl    edx,cl
   14000797c:	89 d1                	mov    ecx,edx
   14000797e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007982:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007986:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000798a:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   14000798d:	89 ca                	mov    edx,ecx
   14000798f:	89 10                	mov    DWORD PTR [rax],edx
   140007991:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007995:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007999:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000799d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000799f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400079a2:	89 c1                	mov    ecx,eax
   1400079a4:	d3 ea                	shr    edx,cl
   1400079a6:	89 d0                	mov    eax,edx
   1400079a8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400079ab:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079af:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   1400079b3:	72 ba                	jb     14000796f <__rshift_D2A+0x9a>
   1400079b5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079b9:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400079bc:	89 10                	mov    DWORD PTR [rax],edx
   1400079be:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079c2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400079c4:	85 c0                	test   eax,eax
   1400079c6:	74 2d                	je     1400079f5 <__rshift_D2A+0x120>
   1400079c8:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   1400079cd:	eb 26                	jmp    1400079f5 <__rshift_D2A+0x120>
   1400079cf:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400079d3:	48 8d 42 04          	lea    rax,[rdx+0x4]
   1400079d7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400079db:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079df:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400079e3:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   1400079e7:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400079e9:	89 10                	mov    DWORD PTR [rax],edx
   1400079eb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079ef:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   1400079f3:	72 da                	jb     1400079cf <__rshift_D2A+0xfa>
   1400079f5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079f9:	48 83 c0 18          	add    rax,0x18
   1400079fd:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140007a01:	48 29 c2             	sub    rdx,rax
   140007a04:	48 89 d0             	mov    rax,rdx
   140007a07:	48 c1 f8 02          	sar    rax,0x2
   140007a0b:	89 c2                	mov    edx,eax
   140007a0d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a11:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007a14:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a18:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a1b:	85 c0                	test   eax,eax
   140007a1d:	75 0b                	jne    140007a2a <__rshift_D2A+0x155>
   140007a1f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a23:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   140007a2a:	90                   	nop
   140007a2b:	48 83 c4 20          	add    rsp,0x20
   140007a2f:	5d                   	pop    rbp
   140007a30:	c3                   	ret

0000000140007a31 <__trailz_D2A>:
   140007a31:	55                   	push   rbp
   140007a32:	48 89 e5             	mov    rbp,rsp
   140007a35:	48 83 ec 40          	sub    rsp,0x40
   140007a39:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007a3d:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a44:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a48:	48 83 c0 18          	add    rax,0x18
   140007a4c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a50:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a54:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a57:	48 98                	cdqe
   140007a59:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007a60:	00 
   140007a61:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a65:	48 01 d0             	add    rax,rdx
   140007a68:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007a6c:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a73:	eb 09                	jmp    140007a7e <__trailz_D2A+0x4d>
   140007a75:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   140007a79:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   140007a7e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a82:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a86:	73 0a                	jae    140007a92 <__trailz_D2A+0x61>
   140007a88:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a8c:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a8e:	85 c0                	test   eax,eax
   140007a90:	74 e3                	je     140007a75 <__trailz_D2A+0x44>
   140007a92:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a96:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a9a:	73 18                	jae    140007ab4 <__trailz_D2A+0x83>
   140007a9c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007aa0:	8b 00                	mov    eax,DWORD PTR [rax]
   140007aa2:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007aa5:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007aa9:	48 89 c1             	mov    rcx,rax
   140007aac:	e8 ef fd ff ff       	call   1400078a0 <__lo0bits_D2A>
   140007ab1:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007ab4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007ab7:	48 83 c4 40          	add    rsp,0x40
   140007abb:	5d                   	pop    rbp
   140007abc:	c3                   	ret
   140007abd:	90                   	nop
   140007abe:	90                   	nop
   140007abf:	90                   	nop

0000000140007ac0 <dtoa_lock_cleanup>:
   140007ac0:	55                   	push   rbp
   140007ac1:	48 89 e5             	mov    rbp,rsp
   140007ac4:	48 83 ec 40          	sub    rsp,0x40
   140007ac8:	48 8d 05 21 77 00 00 	lea    rax,[rip+0x7721]        # 14000f1f0 <dtoa_CS_init>
   140007acf:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007ad3:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007ada:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007add:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007ae1:	87 10                	xchg   DWORD PTR [rax],edx
   140007ae3:	89 d0                	mov    eax,edx
   140007ae5:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007ae8:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007aec:	75 3d                	jne    140007b2b <dtoa_lock_cleanup+0x6b>
   140007aee:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007af5:	eb 2e                	jmp    140007b25 <dtoa_lock_cleanup+0x65>
   140007af7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007afa:	48 63 d0             	movsxd rdx,eax
   140007afd:	48 89 d0             	mov    rax,rdx
   140007b00:	48 c1 e0 02          	shl    rax,0x2
   140007b04:	48 01 d0             	add    rax,rdx
   140007b07:	48 c1 e0 03          	shl    rax,0x3
   140007b0b:	48 8d 15 8e 76 00 00 	lea    rdx,[rip+0x768e]        # 14000f1a0 <dtoa_CritSec>
   140007b12:	48 01 d0             	add    rax,rdx
   140007b15:	48 89 c1             	mov    rcx,rax
   140007b18:	48 8b 05 c9 86 00 00 	mov    rax,QWORD PTR [rip+0x86c9]        # 1400101e8 <__IAT_start__>
   140007b1f:	ff d0                	call   rax
   140007b21:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b25:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b29:	7e cc                	jle    140007af7 <dtoa_lock_cleanup+0x37>
   140007b2b:	90                   	nop
   140007b2c:	48 83 c4 40          	add    rsp,0x40
   140007b30:	5d                   	pop    rbp
   140007b31:	c3                   	ret

0000000140007b32 <dtoa_lock>:
   140007b32:	55                   	push   rbp
   140007b33:	48 89 e5             	mov    rbp,rsp
   140007b36:	48 83 ec 40          	sub    rsp,0x40
   140007b3a:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007b3d:	8b 05 ad 76 00 00    	mov    eax,DWORD PTR [rip+0x76ad]        # 14000f1f0 <dtoa_CS_init>
   140007b43:	83 f8 02             	cmp    eax,0x2
   140007b46:	75 2c                	jne    140007b74 <dtoa_lock+0x42>
   140007b48:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007b4b:	48 89 d0             	mov    rax,rdx
   140007b4e:	48 c1 e0 02          	shl    rax,0x2
   140007b52:	48 01 d0             	add    rax,rdx
   140007b55:	48 c1 e0 03          	shl    rax,0x3
   140007b59:	48 8d 15 40 76 00 00 	lea    rdx,[rip+0x7640]        # 14000f1a0 <dtoa_CritSec>
   140007b60:	48 01 d0             	add    rax,rdx
   140007b63:	48 89 c1             	mov    rcx,rax
   140007b66:	48 8b 05 83 86 00 00 	mov    rax,QWORD PTR [rip+0x8683]        # 1400101f0 <__imp_EnterCriticalSection>
   140007b6d:	ff d0                	call   rax
   140007b6f:	e9 ea 00 00 00       	jmp    140007c5e <dtoa_lock+0x12c>
   140007b74:	8b 05 76 76 00 00    	mov    eax,DWORD PTR [rip+0x7676]        # 14000f1f0 <dtoa_CS_init>
   140007b7a:	85 c0                	test   eax,eax
   140007b7c:	0f 85 9e 00 00 00    	jne    140007c20 <dtoa_lock+0xee>
   140007b82:	48 8d 05 67 76 00 00 	lea    rax,[rip+0x7667]        # 14000f1f0 <dtoa_CS_init>
   140007b89:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007b8d:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007b94:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007b97:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007b9b:	87 10                	xchg   DWORD PTR [rax],edx
   140007b9d:	89 d0                	mov    eax,edx
   140007b9f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007ba2:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007ba6:	75 58                	jne    140007c00 <dtoa_lock+0xce>
   140007ba8:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007baf:	eb 2e                	jmp    140007bdf <dtoa_lock+0xad>
   140007bb1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007bb4:	48 63 d0             	movsxd rdx,eax
   140007bb7:	48 89 d0             	mov    rax,rdx
   140007bba:	48 c1 e0 02          	shl    rax,0x2
   140007bbe:	48 01 d0             	add    rax,rdx
   140007bc1:	48 c1 e0 03          	shl    rax,0x3
   140007bc5:	48 8d 15 d4 75 00 00 	lea    rdx,[rip+0x75d4]        # 14000f1a0 <dtoa_CritSec>
   140007bcc:	48 01 d0             	add    rax,rdx
   140007bcf:	48 89 c1             	mov    rcx,rax
   140007bd2:	48 8b 05 47 86 00 00 	mov    rax,QWORD PTR [rip+0x8647]        # 140010220 <__imp_InitializeCriticalSection>
   140007bd9:	ff d0                	call   rax
   140007bdb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007bdf:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007be3:	7e cc                	jle    140007bb1 <dtoa_lock+0x7f>
   140007be5:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007ac0 <dtoa_lock_cleanup>
   140007bec:	48 89 c1             	mov    rcx,rax
   140007bef:	e8 3b 9a ff ff       	call   14000162f <atexit>
   140007bf4:	c7 05 f2 75 00 00 02 	mov    DWORD PTR [rip+0x75f2],0x2        # 14000f1f0 <dtoa_CS_init>
   140007bfb:	00 00 00 
   140007bfe:	eb 20                	jmp    140007c20 <dtoa_lock+0xee>
   140007c00:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007c04:	75 1a                	jne    140007c20 <dtoa_lock+0xee>
   140007c06:	c7 05 e0 75 00 00 02 	mov    DWORD PTR [rip+0x75e0],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c0d:	00 00 00 
   140007c10:	eb 0e                	jmp    140007c20 <dtoa_lock+0xee>
   140007c12:	b9 01 00 00 00       	mov    ecx,0x1
   140007c17:	48 8b 05 2a 86 00 00 	mov    rax,QWORD PTR [rip+0x862a]        # 140010248 <__imp_Sleep>
   140007c1e:	ff d0                	call   rax
   140007c20:	8b 05 ca 75 00 00    	mov    eax,DWORD PTR [rip+0x75ca]        # 14000f1f0 <dtoa_CS_init>
   140007c26:	83 f8 01             	cmp    eax,0x1
   140007c29:	74 e7                	je     140007c12 <dtoa_lock+0xe0>
   140007c2b:	8b 05 bf 75 00 00    	mov    eax,DWORD PTR [rip+0x75bf]        # 14000f1f0 <dtoa_CS_init>
   140007c31:	83 f8 02             	cmp    eax,0x2
   140007c34:	75 28                	jne    140007c5e <dtoa_lock+0x12c>
   140007c36:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c39:	48 89 d0             	mov    rax,rdx
   140007c3c:	48 c1 e0 02          	shl    rax,0x2
   140007c40:	48 01 d0             	add    rax,rdx
   140007c43:	48 c1 e0 03          	shl    rax,0x3
   140007c47:	48 8d 15 52 75 00 00 	lea    rdx,[rip+0x7552]        # 14000f1a0 <dtoa_CritSec>
   140007c4e:	48 01 d0             	add    rax,rdx
   140007c51:	48 89 c1             	mov    rcx,rax
   140007c54:	48 8b 05 95 85 00 00 	mov    rax,QWORD PTR [rip+0x8595]        # 1400101f0 <__imp_EnterCriticalSection>
   140007c5b:	ff d0                	call   rax
   140007c5d:	90                   	nop
   140007c5e:	48 83 c4 40          	add    rsp,0x40
   140007c62:	5d                   	pop    rbp
   140007c63:	c3                   	ret

0000000140007c64 <dtoa_unlock>:
   140007c64:	55                   	push   rbp
   140007c65:	48 89 e5             	mov    rbp,rsp
   140007c68:	48 83 ec 20          	sub    rsp,0x20
   140007c6c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c6f:	8b 05 7b 75 00 00    	mov    eax,DWORD PTR [rip+0x757b]        # 14000f1f0 <dtoa_CS_init>
   140007c75:	83 f8 02             	cmp    eax,0x2
   140007c78:	75 27                	jne    140007ca1 <dtoa_unlock+0x3d>
   140007c7a:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c7d:	48 89 d0             	mov    rax,rdx
   140007c80:	48 c1 e0 02          	shl    rax,0x2
   140007c84:	48 01 d0             	add    rax,rdx
   140007c87:	48 c1 e0 03          	shl    rax,0x3
   140007c8b:	48 8d 15 0e 75 00 00 	lea    rdx,[rip+0x750e]        # 14000f1a0 <dtoa_CritSec>
   140007c92:	48 01 d0             	add    rax,rdx
   140007c95:	48 89 c1             	mov    rcx,rax
   140007c98:	48 8b 05 89 85 00 00 	mov    rax,QWORD PTR [rip+0x8589]        # 140010228 <__imp_LeaveCriticalSection>
   140007c9f:	ff d0                	call   rax
   140007ca1:	90                   	nop
   140007ca2:	48 83 c4 20          	add    rsp,0x20
   140007ca6:	5d                   	pop    rbp
   140007ca7:	c3                   	ret

0000000140007ca8 <__lo0bits_D2A>:
   140007ca8:	55                   	push   rbp
   140007ca9:	48 89 e5             	mov    rbp,rsp
   140007cac:	48 83 ec 10          	sub    rsp,0x10
   140007cb0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007cb4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007cb8:	8b 00                	mov    eax,DWORD PTR [rax]
   140007cba:	f3 0f bc c0          	tzcnt  eax,eax
   140007cbe:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007cc1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007cc5:	8b 10                	mov    edx,DWORD PTR [rax]
   140007cc7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007cca:	89 c1                	mov    ecx,eax
   140007ccc:	d3 ea                	shr    edx,cl
   140007cce:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007cd2:	89 10                	mov    DWORD PTR [rax],edx
   140007cd4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007cd7:	48 83 c4 10          	add    rsp,0x10
   140007cdb:	5d                   	pop    rbp
   140007cdc:	c3                   	ret

0000000140007cdd <__hi0bits_D2A>:
   140007cdd:	55                   	push   rbp
   140007cde:	48 89 e5             	mov    rbp,rsp
   140007ce1:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007ce4:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007ce8:	83 f0 1f             	xor    eax,0x1f
   140007ceb:	5d                   	pop    rbp
   140007cec:	c3                   	ret

0000000140007ced <__Balloc_D2A>:
   140007ced:	55                   	push   rbp
   140007cee:	48 89 e5             	mov    rbp,rsp
   140007cf1:	48 83 ec 30          	sub    rsp,0x30
   140007cf5:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007cf8:	b9 00 00 00 00       	mov    ecx,0x0
   140007cfd:	e8 30 fe ff ff       	call   140007b32 <dtoa_lock>
   140007d02:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d06:	7f 48                	jg     140007d50 <__Balloc_D2A+0x63>
   140007d08:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d0b:	48 98                	cdqe
   140007d0d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007d14:	00 
   140007d15:	48 8d 05 e4 74 00 00 	lea    rax,[rip+0x74e4]        # 14000f200 <freelist>
   140007d1c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007d20:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d24:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d29:	74 25                	je     140007d50 <__Balloc_D2A+0x63>
   140007d2b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d2f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007d32:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d35:	48 63 d2             	movsxd rdx,edx
   140007d38:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007d3f:	00 
   140007d40:	48 8d 15 b9 74 00 00 	lea    rdx,[rip+0x74b9]        # 14000f200 <freelist>
   140007d47:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007d4b:	e9 b1 00 00 00       	jmp    140007e01 <__Balloc_D2A+0x114>
   140007d50:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d53:	ba 01 00 00 00       	mov    edx,0x1
   140007d58:	89 c1                	mov    ecx,eax
   140007d5a:	d3 e2                	shl    edx,cl
   140007d5c:	89 d0                	mov    eax,edx
   140007d5e:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007d61:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007d64:	83 e8 01             	sub    eax,0x1
   140007d67:	48 98                	cdqe
   140007d69:	48 c1 e0 02          	shl    rax,0x2
   140007d6d:	48 83 c0 27          	add    rax,0x27
   140007d71:	48 c1 e8 03          	shr    rax,0x3
   140007d75:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007d78:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d7c:	7f 4e                	jg     140007dcc <__Balloc_D2A+0xdf>
   140007d7e:	48 8b 15 0b 23 00 00 	mov    rdx,QWORD PTR [rip+0x230b]        # 14000a090 <pmem_next>
   140007d85:	48 8d 05 d4 74 00 00 	lea    rax,[rip+0x74d4]        # 14000f260 <private_mem>
   140007d8c:	48 29 c2             	sub    rdx,rax
   140007d8f:	48 89 d0             	mov    rax,rdx
   140007d92:	48 c1 f8 03          	sar    rax,0x3
   140007d96:	48 89 c2             	mov    rdx,rax
   140007d99:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d9c:	48 01 d0             	add    rax,rdx
   140007d9f:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007da5:	77 25                	ja     140007dcc <__Balloc_D2A+0xdf>
   140007da7:	48 8b 05 e2 22 00 00 	mov    rax,QWORD PTR [rip+0x22e2]        # 14000a090 <pmem_next>
   140007dae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007db2:	48 8b 05 d7 22 00 00 	mov    rax,QWORD PTR [rip+0x22d7]        # 14000a090 <pmem_next>
   140007db9:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007dbc:	48 c1 e2 03          	shl    rdx,0x3
   140007dc0:	48 01 d0             	add    rax,rdx
   140007dc3:	48 89 05 c6 22 00 00 	mov    QWORD PTR [rip+0x22c6],rax        # 14000a090 <pmem_next>
   140007dca:	eb 21                	jmp    140007ded <__Balloc_D2A+0x100>
   140007dcc:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007dcf:	48 c1 e0 03          	shl    rax,0x3
   140007dd3:	48 89 c1             	mov    rcx,rax
   140007dd6:	e8 e5 18 00 00       	call   1400096c0 <malloc>
   140007ddb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007ddf:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007de4:	75 07                	jne    140007ded <__Balloc_D2A+0x100>
   140007de6:	b8 00 00 00 00       	mov    eax,0x0
   140007deb:	eb 3b                	jmp    140007e28 <__Balloc_D2A+0x13b>
   140007ded:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007df1:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007df4:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007df7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007dfb:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007dfe:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007e01:	b9 00 00 00 00       	mov    ecx,0x0
   140007e06:	e8 59 fe ff ff       	call   140007c64 <dtoa_unlock>
   140007e0b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e0f:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007e16:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e1a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007e1d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e21:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007e24:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e28:	48 83 c4 30          	add    rsp,0x30
   140007e2c:	5d                   	pop    rbp
   140007e2d:	c3                   	ret

0000000140007e2e <__Bfree_D2A>:
   140007e2e:	55                   	push   rbp
   140007e2f:	48 89 e5             	mov    rbp,rsp
   140007e32:	48 83 ec 20          	sub    rsp,0x20
   140007e36:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e3a:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007e3f:	74 71                	je     140007eb2 <__Bfree_D2A+0x84>
   140007e41:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e45:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e48:	83 f8 09             	cmp    eax,0x9
   140007e4b:	7e 0e                	jle    140007e5b <__Bfree_D2A+0x2d>
   140007e4d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e51:	48 89 c1             	mov    rcx,rax
   140007e54:	e8 57 18 00 00       	call   1400096b0 <free>
   140007e59:	eb 57                	jmp    140007eb2 <__Bfree_D2A+0x84>
   140007e5b:	b9 00 00 00 00       	mov    ecx,0x0
   140007e60:	e8 cd fc ff ff       	call   140007b32 <dtoa_lock>
   140007e65:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e69:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e6c:	48 98                	cdqe
   140007e6e:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007e75:	00 
   140007e76:	48 8d 05 83 73 00 00 	lea    rax,[rip+0x7383]        # 14000f200 <freelist>
   140007e7d:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007e81:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e85:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007e88:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e8c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e8f:	48 98                	cdqe
   140007e91:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007e98:	00 
   140007e99:	48 8d 15 60 73 00 00 	lea    rdx,[rip+0x7360]        # 14000f200 <freelist>
   140007ea0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ea4:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007ea8:	b9 00 00 00 00       	mov    ecx,0x0
   140007ead:	e8 b2 fd ff ff       	call   140007c64 <dtoa_unlock>
   140007eb2:	90                   	nop
   140007eb3:	48 83 c4 20          	add    rsp,0x20
   140007eb7:	5d                   	pop    rbp
   140007eb8:	c3                   	ret

0000000140007eb9 <__multadd_D2A>:
   140007eb9:	55                   	push   rbp
   140007eba:	48 89 e5             	mov    rbp,rsp
   140007ebd:	48 83 ec 50          	sub    rsp,0x50
   140007ec1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007ec5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007ec8:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007ecc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ed0:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ed3:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007ed6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eda:	48 83 c0 18          	add    rax,0x18
   140007ede:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007ee2:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007ee9:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007eec:	48 98                	cdqe
   140007eee:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007ef2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007ef6:	8b 00                	mov    eax,DWORD PTR [rax]
   140007ef8:	89 c2                	mov    edx,eax
   140007efa:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007efd:	48 98                	cdqe
   140007eff:	48 0f af d0          	imul   rdx,rax
   140007f03:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007f07:	48 01 d0             	add    rax,rdx
   140007f0a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007f0e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007f12:	48 c1 e8 20          	shr    rax,0x20
   140007f16:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f1a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f1e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007f22:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007f26:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007f2a:	89 10                	mov    DWORD PTR [rax],edx
   140007f2c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007f30:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007f33:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007f36:	7c ba                	jl     140007ef2 <__multadd_D2A+0x39>
   140007f38:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007f3d:	0f 84 9a 00 00 00    	je     140007fdd <__multadd_D2A+0x124>
   140007f43:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f47:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007f4a:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007f4d:	7c 67                	jl     140007fb6 <__multadd_D2A+0xfd>
   140007f4f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f53:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007f56:	83 c0 01             	add    eax,0x1
   140007f59:	89 c1                	mov    ecx,eax
   140007f5b:	e8 8d fd ff ff       	call   140007ced <__Balloc_D2A>
   140007f60:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007f64:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007f69:	75 07                	jne    140007f72 <__multadd_D2A+0xb9>
   140007f6b:	b8 00 00 00 00       	mov    eax,0x0
   140007f70:	eb 6f                	jmp    140007fe1 <__multadd_D2A+0x128>
   140007f72:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f76:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f79:	48 98                	cdqe
   140007f7b:	48 83 c0 02          	add    rax,0x2
   140007f7f:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007f86:	00 
   140007f87:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f8b:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007f8f:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007f93:	48 83 c0 10          	add    rax,0x10
   140007f97:	49 89 c8             	mov    r8,rcx
   140007f9a:	48 89 c1             	mov    rcx,rax
   140007f9d:	e8 26 17 00 00       	call   1400096c8 <memcpy>
   140007fa2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fa6:	48 89 c1             	mov    rcx,rax
   140007fa9:	e8 80 fe ff ff       	call   140007e2e <__Bfree_D2A>
   140007fae:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007fb2:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007fb6:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007fb9:	8d 50 01             	lea    edx,[rax+0x1]
   140007fbc:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007fbf:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140007fc3:	89 d1                	mov    ecx,edx
   140007fc5:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007fc9:	48 98                	cdqe
   140007fcb:	48 83 c0 04          	add    rax,0x4
   140007fcf:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140007fd3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fd7:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140007fda:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007fdd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fe1:	48 83 c4 50          	add    rsp,0x50
   140007fe5:	5d                   	pop    rbp
   140007fe6:	c3                   	ret

0000000140007fe7 <__i2b_D2A>:
   140007fe7:	55                   	push   rbp
   140007fe8:	48 89 e5             	mov    rbp,rsp
   140007feb:	48 83 ec 30          	sub    rsp,0x30
   140007fef:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007ff2:	b9 01 00 00 00       	mov    ecx,0x1
   140007ff7:	e8 f1 fc ff ff       	call   140007ced <__Balloc_D2A>
   140007ffc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008000:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008005:	75 07                	jne    14000800e <__i2b_D2A+0x27>
   140008007:	b8 00 00 00 00       	mov    eax,0x0
   14000800c:	eb 19                	jmp    140008027 <__i2b_D2A+0x40>
   14000800e:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008011:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008015:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008018:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000801c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008023:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008027:	48 83 c4 30          	add    rsp,0x30
   14000802b:	5d                   	pop    rbp
   14000802c:	c3                   	ret

000000014000802d <__mult_D2A>:
   14000802d:	55                   	push   rbp
   14000802e:	48 89 e5             	mov    rbp,rsp
   140008031:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140008038:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000803c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008040:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008044:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008047:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000804b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000804e:	39 c2                	cmp    edx,eax
   140008050:	7d 18                	jge    14000806a <__mult_D2A+0x3d>
   140008052:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008056:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000805a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000805e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008062:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008066:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000806a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000806e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008071:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008074:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008078:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000807b:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   14000807e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008082:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008085:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   140008088:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   14000808b:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   14000808e:	01 d0                	add    eax,edx
   140008090:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008093:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008097:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000809a:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   14000809d:	7e 04                	jle    1400080a3 <__mult_D2A+0x76>
   14000809f:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400080a3:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400080a6:	89 c1                	mov    ecx,eax
   1400080a8:	e8 40 fc ff ff       	call   140007ced <__Balloc_D2A>
   1400080ad:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400080b1:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   1400080b6:	75 0a                	jne    1400080c2 <__mult_D2A+0x95>
   1400080b8:	b8 00 00 00 00       	mov    eax,0x0
   1400080bd:	e9 88 01 00 00       	jmp    14000824a <__mult_D2A+0x21d>
   1400080c2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400080c6:	48 83 c0 18          	add    rax,0x18
   1400080ca:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400080ce:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400080d1:	48 98                	cdqe
   1400080d3:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400080da:	00 
   1400080db:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080df:	48 01 d0             	add    rax,rdx
   1400080e2:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400080e6:	eb 0f                	jmp    1400080f7 <__mult_D2A+0xca>
   1400080e8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080ec:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400080f2:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   1400080f7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080fb:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   1400080ff:	72 e7                	jb     1400080e8 <__mult_D2A+0xbb>
   140008101:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008105:	48 83 c0 18          	add    rax,0x18
   140008109:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000810d:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008110:	48 98                	cdqe
   140008112:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008119:	00 
   14000811a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000811e:	48 01 d0             	add    rax,rdx
   140008121:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008125:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008129:	48 83 c0 18          	add    rax,0x18
   14000812d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008131:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140008134:	48 98                	cdqe
   140008136:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000813d:	00 
   14000813e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008142:	48 01 d0             	add    rax,rdx
   140008145:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   140008149:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000814d:	48 83 c0 18          	add    rax,0x18
   140008151:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008155:	e9 95 00 00 00       	jmp    1400081ef <__mult_D2A+0x1c2>
   14000815a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000815e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008162:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008166:	8b 00                	mov    eax,DWORD PTR [rax]
   140008168:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   14000816b:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   14000816f:	74 79                	je     1400081ea <__mult_D2A+0x1bd>
   140008171:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140008175:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008179:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000817d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008181:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140008188:	00 
   140008189:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000818d:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008191:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008195:	8b 00                	mov    eax,DWORD PTR [rax]
   140008197:	89 c2                	mov    edx,eax
   140008199:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   14000819c:	48 0f af d0          	imul   rdx,rax
   1400081a0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081a4:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081a6:	89 c0                	mov    eax,eax
   1400081a8:	48 01 c2             	add    rdx,rax
   1400081ab:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400081af:	48 01 d0             	add    rax,rdx
   1400081b2:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   1400081b6:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   1400081ba:	48 c1 e8 20          	shr    rax,0x20
   1400081be:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400081c2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081c6:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081ca:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400081ce:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400081d2:	89 10                	mov    DWORD PTR [rax],edx
   1400081d4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400081d8:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   1400081dc:	72 ab                	jb     140008189 <__mult_D2A+0x15c>
   1400081de:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400081e2:	89 c2                	mov    edx,eax
   1400081e4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081e8:	89 10                	mov    DWORD PTR [rax],edx
   1400081ea:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   1400081ef:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400081f3:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   1400081f7:	0f 82 5d ff ff ff    	jb     14000815a <__mult_D2A+0x12d>
   1400081fd:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008201:	48 83 c0 18          	add    rax,0x18
   140008205:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008209:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000820c:	48 98                	cdqe
   14000820e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008215:	00 
   140008216:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000821a:	48 01 d0             	add    rax,rdx
   14000821d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008221:	eb 04                	jmp    140008227 <__mult_D2A+0x1fa>
   140008223:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008227:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000822b:	7e 0f                	jle    14000823c <__mult_D2A+0x20f>
   14000822d:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008232:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008236:	8b 00                	mov    eax,DWORD PTR [rax]
   140008238:	85 c0                	test   eax,eax
   14000823a:	74 e7                	je     140008223 <__mult_D2A+0x1f6>
   14000823c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008240:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008243:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008246:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000824a:	48 81 c4 90 00 00 00 	add    rsp,0x90
   140008251:	5d                   	pop    rbp
   140008252:	c3                   	ret

0000000140008253 <__pow5mult_D2A>:
   140008253:	55                   	push   rbp
   140008254:	48 89 e5             	mov    rbp,rsp
   140008257:	48 83 ec 40          	sub    rsp,0x40
   14000825b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000825f:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140008262:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008265:	83 e0 03             	and    eax,0x3
   140008268:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000826b:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000826f:	74 41                	je     1400082b2 <__pow5mult_D2A+0x5f>
   140008271:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008274:	83 e8 01             	sub    eax,0x1
   140008277:	48 98                	cdqe
   140008279:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008280:	00 
   140008281:	48 8d 05 10 1e 00 00 	lea    rax,[rip+0x1e10]        # 14000a098 <p05.0>
   140008288:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   14000828b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000828f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140008295:	48 89 c1             	mov    rcx,rax
   140008298:	e8 1c fc ff ff       	call   140007eb9 <__multadd_D2A>
   14000829d:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400082a1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400082a6:	75 0a                	jne    1400082b2 <__pow5mult_D2A+0x5f>
   1400082a8:	b8 00 00 00 00       	mov    eax,0x0
   1400082ad:	e9 58 01 00 00       	jmp    14000840a <__pow5mult_D2A+0x1b7>
   1400082b2:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   1400082b6:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400082ba:	75 09                	jne    1400082c5 <__pow5mult_D2A+0x72>
   1400082bc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082c0:	e9 45 01 00 00       	jmp    14000840a <__pow5mult_D2A+0x1b7>
   1400082c5:	48 8b 05 94 78 00 00 	mov    rax,QWORD PTR [rip+0x7894]        # 14000fb60 <p5s>
   1400082cc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082d0:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400082d5:	75 5e                	jne    140008335 <__pow5mult_D2A+0xe2>
   1400082d7:	b9 01 00 00 00       	mov    ecx,0x1
   1400082dc:	e8 51 f8 ff ff       	call   140007b32 <dtoa_lock>
   1400082e1:	48 8b 05 78 78 00 00 	mov    rax,QWORD PTR [rip+0x7878]        # 14000fb60 <p5s>
   1400082e8:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082ec:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400082f1:	75 38                	jne    14000832b <__pow5mult_D2A+0xd8>
   1400082f3:	b9 71 02 00 00       	mov    ecx,0x271
   1400082f8:	e8 ea fc ff ff       	call   140007fe7 <__i2b_D2A>
   1400082fd:	48 89 05 5c 78 00 00 	mov    QWORD PTR [rip+0x785c],rax        # 14000fb60 <p5s>
   140008304:	48 8b 05 55 78 00 00 	mov    rax,QWORD PTR [rip+0x7855]        # 14000fb60 <p5s>
   14000830b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000830f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008314:	75 0a                	jne    140008320 <__pow5mult_D2A+0xcd>
   140008316:	b8 00 00 00 00       	mov    eax,0x0
   14000831b:	e9 ea 00 00 00       	jmp    14000840a <__pow5mult_D2A+0x1b7>
   140008320:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008324:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000832b:	b9 01 00 00 00       	mov    ecx,0x1
   140008330:	e8 2f f9 ff ff       	call   140007c64 <dtoa_unlock>
   140008335:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008338:	83 e0 01             	and    eax,0x1
   14000833b:	85 c0                	test   eax,eax
   14000833d:	74 39                	je     140008378 <__pow5mult_D2A+0x125>
   14000833f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008343:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008347:	48 89 c1             	mov    rcx,rax
   14000834a:	e8 de fc ff ff       	call   14000802d <__mult_D2A>
   14000834f:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008353:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   140008358:	75 0a                	jne    140008364 <__pow5mult_D2A+0x111>
   14000835a:	b8 00 00 00 00       	mov    eax,0x0
   14000835f:	e9 a6 00 00 00       	jmp    14000840a <__pow5mult_D2A+0x1b7>
   140008364:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008368:	48 89 c1             	mov    rcx,rax
   14000836b:	e8 be fa ff ff       	call   140007e2e <__Bfree_D2A>
   140008370:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008374:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008378:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   14000837b:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000837f:	0f 84 80 00 00 00    	je     140008405 <__pow5mult_D2A+0x1b2>
   140008385:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008389:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000838c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008390:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008395:	75 61                	jne    1400083f8 <__pow5mult_D2A+0x1a5>
   140008397:	b9 01 00 00 00       	mov    ecx,0x1
   14000839c:	e8 91 f7 ff ff       	call   140007b32 <dtoa_lock>
   1400083a1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083a5:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083a8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083ac:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083b1:	75 3b                	jne    1400083ee <__pow5mult_D2A+0x19b>
   1400083b3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083b7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083bb:	48 89 c1             	mov    rcx,rax
   1400083be:	e8 6a fc ff ff       	call   14000802d <__mult_D2A>
   1400083c3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083c7:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400083ca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083ce:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083d1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083d5:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083da:	75 07                	jne    1400083e3 <__pow5mult_D2A+0x190>
   1400083dc:	b8 00 00 00 00       	mov    eax,0x0
   1400083e1:	eb 27                	jmp    14000840a <__pow5mult_D2A+0x1b7>
   1400083e3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400083e7:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   1400083ee:	b9 01 00 00 00       	mov    ecx,0x1
   1400083f3:	e8 6c f8 ff ff       	call   140007c64 <dtoa_unlock>
   1400083f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400083fc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008400:	e9 30 ff ff ff       	jmp    140008335 <__pow5mult_D2A+0xe2>
   140008405:	90                   	nop
   140008406:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000840a:	48 83 c4 40          	add    rsp,0x40
   14000840e:	5d                   	pop    rbp
   14000840f:	c3                   	ret

0000000140008410 <__lshift_D2A>:
   140008410:	55                   	push   rbp
   140008411:	48 89 e5             	mov    rbp,rsp
   140008414:	48 83 ec 60          	sub    rsp,0x60
   140008418:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000841c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000841f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008422:	c1 f8 05             	sar    eax,0x5
   140008425:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   140008428:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000842c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000842f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008432:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008436:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008439:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   14000843c:	01 d0                	add    eax,edx
   14000843e:	83 c0 01             	add    eax,0x1
   140008441:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008444:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008448:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000844b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000844e:	eb 07                	jmp    140008457 <__lshift_D2A+0x47>
   140008450:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140008454:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140008457:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000845a:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   14000845d:	7f f1                	jg     140008450 <__lshift_D2A+0x40>
   14000845f:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008462:	89 c1                	mov    ecx,eax
   140008464:	e8 84 f8 ff ff       	call   140007ced <__Balloc_D2A>
   140008469:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000846d:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008472:	75 0a                	jne    14000847e <__lshift_D2A+0x6e>
   140008474:	b8 00 00 00 00       	mov    eax,0x0
   140008479:	e9 19 01 00 00       	jmp    140008597 <__lshift_D2A+0x187>
   14000847e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008482:	48 83 c0 18          	add    rax,0x18
   140008486:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000848a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008491:	eb 16                	jmp    1400084a9 <__lshift_D2A+0x99>
   140008493:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008497:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000849b:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000849f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400084a5:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400084a9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400084ac:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   1400084af:	7c e2                	jl     140008493 <__lshift_D2A+0x83>
   1400084b1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084b5:	48 83 c0 18          	add    rax,0x18
   1400084b9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400084bd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084c1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400084c4:	48 98                	cdqe
   1400084c6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400084cd:	00 
   1400084ce:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084d2:	48 01 d0             	add    rax,rdx
   1400084d5:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400084d9:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   1400084dd:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400084e1:	74 71                	je     140008554 <__lshift_D2A+0x144>
   1400084e3:	b8 20 00 00 00       	mov    eax,0x20
   1400084e8:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400084eb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400084ee:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   1400084f5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084f9:	8b 10                	mov    edx,DWORD PTR [rax]
   1400084fb:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400084fe:	89 c1                	mov    ecx,eax
   140008500:	d3 e2                	shl    edx,cl
   140008502:	89 d1                	mov    ecx,edx
   140008504:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008508:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000850c:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008510:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008513:	89 ca                	mov    edx,ecx
   140008515:	89 10                	mov    DWORD PTR [rax],edx
   140008517:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000851b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000851f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008523:	8b 10                	mov    edx,DWORD PTR [rax]
   140008525:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008528:	89 c1                	mov    ecx,eax
   14000852a:	d3 ea                	shr    edx,cl
   14000852c:	89 d0                	mov    eax,edx
   14000852e:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008531:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008535:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008539:	72 ba                	jb     1400084f5 <__lshift_D2A+0xe5>
   14000853b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000853f:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   140008542:	89 10                	mov    DWORD PTR [rax],edx
   140008544:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008548:	8b 00                	mov    eax,DWORD PTR [rax]
   14000854a:	85 c0                	test   eax,eax
   14000854c:	74 2c                	je     14000857a <__lshift_D2A+0x16a>
   14000854e:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140008552:	eb 26                	jmp    14000857a <__lshift_D2A+0x16a>
   140008554:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008558:	48 8d 42 04          	lea    rax,[rdx+0x4]
   14000855c:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008560:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008564:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140008568:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   14000856c:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000856e:	89 10                	mov    DWORD PTR [rax],edx
   140008570:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008574:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008578:	72 da                	jb     140008554 <__lshift_D2A+0x144>
   14000857a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000857d:	8d 50 ff             	lea    edx,[rax-0x1]
   140008580:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008584:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008587:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000858b:	48 89 c1             	mov    rcx,rax
   14000858e:	e8 9b f8 ff ff       	call   140007e2e <__Bfree_D2A>
   140008593:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008597:	48 83 c4 60          	add    rsp,0x60
   14000859b:	5d                   	pop    rbp
   14000859c:	c3                   	ret

000000014000859d <__cmp_D2A>:
   14000859d:	55                   	push   rbp
   14000859e:	48 89 e5             	mov    rbp,rsp
   1400085a1:	48 83 ec 30          	sub    rsp,0x30
   1400085a5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400085a9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400085ad:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085b1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400085b4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400085b7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400085bb:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400085be:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400085c1:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085c4:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   1400085c7:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400085cb:	74 08                	je     1400085d5 <__cmp_D2A+0x38>
   1400085cd:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400085d0:	e9 92 00 00 00       	jmp    140008667 <__cmp_D2A+0xca>
   1400085d5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085d9:	48 83 c0 18          	add    rax,0x18
   1400085dd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400085e1:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085e4:	48 98                	cdqe
   1400085e6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400085ed:	00 
   1400085ee:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400085f2:	48 01 d0             	add    rax,rdx
   1400085f5:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400085f9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400085fd:	48 83 c0 18          	add    rax,0x18
   140008601:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008605:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008608:	48 98                	cdqe
   14000860a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008611:	00 
   140008612:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008616:	48 01 d0             	add    rax,rdx
   140008619:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000861d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008622:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008626:	8b 10                	mov    edx,DWORD PTR [rax]
   140008628:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   14000862d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008631:	8b 00                	mov    eax,DWORD PTR [rax]
   140008633:	39 c2                	cmp    edx,eax
   140008635:	74 1e                	je     140008655 <__cmp_D2A+0xb8>
   140008637:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000863b:	8b 10                	mov    edx,DWORD PTR [rax]
   14000863d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008641:	8b 00                	mov    eax,DWORD PTR [rax]
   140008643:	39 c2                	cmp    edx,eax
   140008645:	73 07                	jae    14000864e <__cmp_D2A+0xb1>
   140008647:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000864c:	eb 19                	jmp    140008667 <__cmp_D2A+0xca>
   14000864e:	b8 01 00 00 00       	mov    eax,0x1
   140008653:	eb 12                	jmp    140008667 <__cmp_D2A+0xca>
   140008655:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008659:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000865d:	73 02                	jae    140008661 <__cmp_D2A+0xc4>
   14000865f:	eb bc                	jmp    14000861d <__cmp_D2A+0x80>
   140008661:	90                   	nop
   140008662:	b8 00 00 00 00       	mov    eax,0x0
   140008667:	48 83 c4 30          	add    rsp,0x30
   14000866b:	5d                   	pop    rbp
   14000866c:	c3                   	ret

000000014000866d <__diff_D2A>:
   14000866d:	55                   	push   rbp
   14000866e:	48 89 e5             	mov    rbp,rsp
   140008671:	48 83 ec 70          	sub    rsp,0x70
   140008675:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008679:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000867d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140008681:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008685:	48 89 c1             	mov    rcx,rax
   140008688:	e8 10 ff ff ff       	call   14000859d <__cmp_D2A>
   14000868d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008690:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008694:	75 3e                	jne    1400086d4 <__diff_D2A+0x67>
   140008696:	b9 00 00 00 00       	mov    ecx,0x0
   14000869b:	e8 4d f6 ff ff       	call   140007ced <__Balloc_D2A>
   1400086a0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400086a4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400086a9:	75 0a                	jne    1400086b5 <__diff_D2A+0x48>
   1400086ab:	b8 00 00 00 00       	mov    eax,0x0
   1400086b0:	e9 ab 01 00 00       	jmp    140008860 <__diff_D2A+0x1f3>
   1400086b5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086b9:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   1400086c0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086c4:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   1400086cb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086cf:	e9 8c 01 00 00       	jmp    140008860 <__diff_D2A+0x1f3>
   1400086d4:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400086d8:	79 21                	jns    1400086fb <__diff_D2A+0x8e>
   1400086da:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086de:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400086e2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086e6:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400086ea:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086ee:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400086f2:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400086f9:	eb 07                	jmp    140008702 <__diff_D2A+0x95>
   1400086fb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008702:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008706:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008709:	89 c1                	mov    ecx,eax
   14000870b:	e8 dd f5 ff ff       	call   140007ced <__Balloc_D2A>
   140008710:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008714:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008719:	75 0a                	jne    140008725 <__diff_D2A+0xb8>
   14000871b:	b8 00 00 00 00       	mov    eax,0x0
   140008720:	e9 3b 01 00 00       	jmp    140008860 <__diff_D2A+0x1f3>
   140008725:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008729:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000872c:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000872f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008733:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008736:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008739:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000873d:	48 83 c0 18          	add    rax,0x18
   140008741:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008745:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008748:	48 98                	cdqe
   14000874a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008751:	00 
   140008752:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008756:	48 01 d0             	add    rax,rdx
   140008759:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000875d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008761:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008764:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   140008767:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000876b:	48 83 c0 18          	add    rax,0x18
   14000876f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008773:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008776:	48 98                	cdqe
   140008778:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000877f:	00 
   140008780:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008784:	48 01 d0             	add    rax,rdx
   140008787:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000878b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000878f:	48 83 c0 18          	add    rax,0x18
   140008793:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008797:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   14000879e:	00 
   14000879f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087a3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087a7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400087ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087ad:	89 c1                	mov    ecx,eax
   1400087af:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087b3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087b7:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400087bb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087bd:	89 c2                	mov    edx,eax
   1400087bf:	48 89 c8             	mov    rax,rcx
   1400087c2:	48 29 d0             	sub    rax,rdx
   1400087c5:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400087c9:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400087cd:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400087d1:	48 c1 e8 20          	shr    rax,0x20
   1400087d5:	83 e0 01             	and    eax,0x1
   1400087d8:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400087dc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087e0:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087e4:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400087e8:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400087ec:	89 10                	mov    DWORD PTR [rax],edx
   1400087ee:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087f2:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   1400087f6:	72 a7                	jb     14000879f <__diff_D2A+0x132>
   1400087f8:	eb 39                	jmp    140008833 <__diff_D2A+0x1c6>
   1400087fa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087fe:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008802:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008806:	8b 00                	mov    eax,DWORD PTR [rax]
   140008808:	89 c0                	mov    eax,eax
   14000880a:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   14000880e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008812:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008816:	48 c1 e8 20          	shr    rax,0x20
   14000881a:	83 e0 01             	and    eax,0x1
   14000881d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008821:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008825:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008829:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000882d:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140008831:	89 10                	mov    DWORD PTR [rax],edx
   140008833:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008837:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   14000883b:	72 bd                	jb     1400087fa <__diff_D2A+0x18d>
   14000883d:	eb 04                	jmp    140008843 <__diff_D2A+0x1d6>
   14000883f:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008843:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008848:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000884c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000884e:	85 c0                	test   eax,eax
   140008850:	74 ed                	je     14000883f <__diff_D2A+0x1d2>
   140008852:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008856:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008859:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000885c:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008860:	48 83 c4 70          	add    rsp,0x70
   140008864:	5d                   	pop    rbp
   140008865:	c3                   	ret

0000000140008866 <__b2d_D2A>:
   140008866:	55                   	push   rbp
   140008867:	48 89 e5             	mov    rbp,rsp
   14000886a:	48 83 ec 50          	sub    rsp,0x50
   14000886e:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008872:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008876:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000887a:	48 83 c0 18          	add    rax,0x18
   14000887e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008882:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008886:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008889:	48 98                	cdqe
   14000888b:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008892:	00 
   140008893:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008897:	48 01 d0             	add    rax,rdx
   14000889a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000889e:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088a3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088a7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088a9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400088ac:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400088af:	89 c1                	mov    ecx,eax
   1400088b1:	e8 27 f4 ff ff       	call   140007cdd <__hi0bits_D2A>
   1400088b6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400088b9:	b8 20 00 00 00       	mov    eax,0x20
   1400088be:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088c1:	89 c2                	mov    edx,eax
   1400088c3:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400088c7:	89 10                	mov    DWORD PTR [rax],edx
   1400088c9:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   1400088cd:	7f 66                	jg     140008935 <__b2d_D2A+0xcf>
   1400088cf:	b8 0b 00 00 00       	mov    eax,0xb
   1400088d4:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088d7:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400088da:	89 c1                	mov    ecx,eax
   1400088dc:	d3 ea                	shr    edx,cl
   1400088de:	89 d0                	mov    eax,edx
   1400088e0:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400088e5:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400088e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088ec:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400088f0:	73 10                	jae    140008902 <__b2d_D2A+0x9c>
   1400088f2:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088f7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088fb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088fd:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008900:	eb 07                	jmp    140008909 <__b2d_D2A+0xa3>
   140008902:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140008909:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000890c:	83 c0 15             	add    eax,0x15
   14000890f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008912:	89 c1                	mov    ecx,eax
   140008914:	d3 e2                	shl    edx,cl
   140008916:	41 89 d0             	mov    r8d,edx
   140008919:	b8 0b 00 00 00       	mov    eax,0xb
   14000891e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008921:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140008924:	89 c1                	mov    ecx,eax
   140008926:	d3 ea                	shr    edx,cl
   140008928:	89 d0                	mov    eax,edx
   14000892a:	44 09 c0             	or     eax,r8d
   14000892d:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008930:	e9 ac 00 00 00       	jmp    1400089e1 <__b2d_D2A+0x17b>
   140008935:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008939:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000893d:	73 10                	jae    14000894f <__b2d_D2A+0xe9>
   14000893f:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008944:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008948:	8b 00                	mov    eax,DWORD PTR [rax]
   14000894a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000894d:	eb 07                	jmp    140008956 <__b2d_D2A+0xf0>
   14000894f:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   140008956:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   14000895a:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   14000895e:	74 70                	je     1400089d0 <__b2d_D2A+0x16a>
   140008960:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008963:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008966:	89 c1                	mov    ecx,eax
   140008968:	d3 e2                	shl    edx,cl
   14000896a:	41 89 d0             	mov    r8d,edx
   14000896d:	b8 20 00 00 00       	mov    eax,0x20
   140008972:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008975:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008978:	89 c1                	mov    ecx,eax
   14000897a:	d3 ea                	shr    edx,cl
   14000897c:	89 d0                	mov    eax,edx
   14000897e:	44 09 c0             	or     eax,r8d
   140008981:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008986:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008989:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000898d:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008991:	73 10                	jae    1400089a3 <__b2d_D2A+0x13d>
   140008993:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008998:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000899c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000899e:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400089a1:	eb 07                	jmp    1400089aa <__b2d_D2A+0x144>
   1400089a3:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   1400089aa:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089ad:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400089b0:	89 c1                	mov    ecx,eax
   1400089b2:	d3 e2                	shl    edx,cl
   1400089b4:	41 89 d0             	mov    r8d,edx
   1400089b7:	b8 20 00 00 00       	mov    eax,0x20
   1400089bc:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400089bf:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400089c2:	89 c1                	mov    ecx,eax
   1400089c4:	d3 ea                	shr    edx,cl
   1400089c6:	89 d0                	mov    eax,edx
   1400089c8:	44 09 c0             	or     eax,r8d
   1400089cb:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089ce:	eb 11                	jmp    1400089e1 <__b2d_D2A+0x17b>
   1400089d0:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400089d3:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400089d8:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089db:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400089de:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089e1:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   1400089e6:	48 83 c4 50          	add    rsp,0x50
   1400089ea:	5d                   	pop    rbp
   1400089eb:	c3                   	ret

00000001400089ec <__d2b_D2A>:
   1400089ec:	55                   	push   rbp
   1400089ed:	53                   	push   rbx
   1400089ee:	48 83 ec 58          	sub    rsp,0x58
   1400089f2:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400089f7:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   1400089fc:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140008a00:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140008a04:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140008a09:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   140008a0e:	b9 01 00 00 00       	mov    ecx,0x1
   140008a13:	e8 d5 f2 ff ff       	call   140007ced <__Balloc_D2A>
   140008a18:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008a1c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008a21:	75 0a                	jne    140008a2d <__d2b_D2A+0x41>
   140008a23:	b8 00 00 00 00       	mov    eax,0x0
   140008a28:	e9 68 01 00 00       	jmp    140008b95 <__d2b_D2A+0x1a9>
   140008a2d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a31:	48 83 c0 18          	add    rax,0x18
   140008a35:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008a39:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a3c:	25 ff ff 0f 00       	and    eax,0xfffff
   140008a41:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a44:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a47:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008a4c:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008a4f:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a52:	c1 e8 14             	shr    eax,0x14
   140008a55:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140008a58:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008a5c:	74 0b                	je     140008a69 <__d2b_D2A+0x7d>
   140008a5e:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   140008a61:	0d 00 00 10 00       	or     eax,0x100000
   140008a66:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a69:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140008a6c:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008a6f:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008a72:	85 c0                	test   eax,eax
   140008a74:	74 7b                	je     140008af1 <__d2b_D2A+0x105>
   140008a76:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   140008a7a:	48 89 c1             	mov    rcx,rax
   140008a7d:	e8 26 f2 ff ff       	call   140007ca8 <__lo0bits_D2A>
   140008a82:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008a85:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008a89:	74 2b                	je     140008ab6 <__d2b_D2A+0xca>
   140008a8b:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a8e:	b8 20 00 00 00       	mov    eax,0x20
   140008a93:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008a96:	89 c1                	mov    ecx,eax
   140008a98:	d3 e2                	shl    edx,cl
   140008a9a:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008a9d:	09 c2                	or     edx,eax
   140008a9f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008aa3:	89 10                	mov    DWORD PTR [rax],edx
   140008aa5:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008aa8:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008aab:	89 c1                	mov    ecx,eax
   140008aad:	d3 ea                	shr    edx,cl
   140008aaf:	89 d0                	mov    eax,edx
   140008ab1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008ab4:	eb 09                	jmp    140008abf <__d2b_D2A+0xd3>
   140008ab6:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008ab9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008abd:	89 10                	mov    DWORD PTR [rax],edx
   140008abf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008ac3:	48 83 c0 04          	add    rax,0x4
   140008ac7:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008aca:	89 10                	mov    DWORD PTR [rax],edx
   140008acc:	8b 00                	mov    eax,DWORD PTR [rax]
   140008ace:	85 c0                	test   eax,eax
   140008ad0:	74 07                	je     140008ad9 <__d2b_D2A+0xed>
   140008ad2:	ba 02 00 00 00       	mov    edx,0x2
   140008ad7:	eb 05                	jmp    140008ade <__d2b_D2A+0xf2>
   140008ad9:	ba 01 00 00 00       	mov    edx,0x1
   140008ade:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ae2:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008ae5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ae9:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008aec:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008aef:	eb 31                	jmp    140008b22 <__d2b_D2A+0x136>
   140008af1:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008af5:	48 89 c1             	mov    rcx,rax
   140008af8:	e8 ab f1 ff ff       	call   140007ca8 <__lo0bits_D2A>
   140008afd:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008b00:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b03:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b07:	89 10                	mov    DWORD PTR [rax],edx
   140008b09:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b0d:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008b14:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b18:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b1b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b1e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008b22:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008b26:	74 26                	je     140008b4e <__d2b_D2A+0x162>
   140008b28:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b2b:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008b31:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b34:	01 c2                	add    edx,eax
   140008b36:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b3a:	89 10                	mov    DWORD PTR [rax],edx
   140008b3c:	b8 35 00 00 00       	mov    eax,0x35
   140008b41:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008b44:	89 c2                	mov    edx,eax
   140008b46:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b4a:	89 10                	mov    DWORD PTR [rax],edx
   140008b4c:	eb 43                	jmp    140008b91 <__d2b_D2A+0x1a5>
   140008b4e:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b51:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008b57:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b5a:	01 c2                	add    edx,eax
   140008b5c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b60:	89 10                	mov    DWORD PTR [rax],edx
   140008b62:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b65:	c1 e0 05             	shl    eax,0x5
   140008b68:	89 c3                	mov    ebx,eax
   140008b6a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b6d:	48 98                	cdqe
   140008b6f:	48 c1 e0 02          	shl    rax,0x2
   140008b73:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008b77:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b7b:	48 01 d0             	add    rax,rdx
   140008b7e:	8b 00                	mov    eax,DWORD PTR [rax]
   140008b80:	89 c1                	mov    ecx,eax
   140008b82:	e8 56 f1 ff ff       	call   140007cdd <__hi0bits_D2A>
   140008b87:	29 c3                	sub    ebx,eax
   140008b89:	89 da                	mov    edx,ebx
   140008b8b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b8f:	89 10                	mov    DWORD PTR [rax],edx
   140008b91:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b95:	48 83 c4 58          	add    rsp,0x58
   140008b99:	5b                   	pop    rbx
   140008b9a:	5d                   	pop    rbp
   140008b9b:	c3                   	ret

0000000140008b9c <__strcp_D2A>:
   140008b9c:	55                   	push   rbp
   140008b9d:	48 89 e5             	mov    rbp,rsp
   140008ba0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008ba4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008ba8:	eb 05                	jmp    140008baf <__strcp_D2A+0x13>
   140008baa:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008baf:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008bb3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008bb7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008bbb:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008bbe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008bc2:	88 10                	mov    BYTE PTR [rax],dl
   140008bc4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008bc8:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008bcb:	84 c0                	test   al,al
   140008bcd:	75 db                	jne    140008baa <__strcp_D2A+0xe>
   140008bcf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008bd3:	5d                   	pop    rbp
   140008bd4:	c3                   	ret
   140008bd5:	90                   	nop
   140008bd6:	90                   	nop
   140008bd7:	90                   	nop
   140008bd8:	90                   	nop
   140008bd9:	90                   	nop
   140008bda:	90                   	nop
   140008bdb:	90                   	nop
   140008bdc:	90                   	nop
   140008bdd:	90                   	nop
   140008bde:	90                   	nop
   140008bdf:	90                   	nop

0000000140008be0 <__fpclassify>:
   140008be0:	55                   	push   rbp
   140008be1:	48 89 e5             	mov    rbp,rsp
   140008be4:	48 83 ec 10          	sub    rsp,0x10
   140008be8:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008bed:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008bf2:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008bf7:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008bfa:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008bfd:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008c00:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008c03:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008c09:	09 d0                	or     eax,edx
   140008c0b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c0e:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008c15:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c18:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c1b:	85 c0                	test   eax,eax
   140008c1d:	75 07                	jne    140008c26 <__fpclassify+0x46>
   140008c1f:	b8 00 40 00 00       	mov    eax,0x4000
   140008c24:	eb 2f                	jmp    140008c55 <__fpclassify+0x75>
   140008c26:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c2a:	75 07                	jne    140008c33 <__fpclassify+0x53>
   140008c2c:	b8 00 44 00 00       	mov    eax,0x4400
   140008c31:	eb 22                	jmp    140008c55 <__fpclassify+0x75>
   140008c33:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008c3a:	75 14                	jne    140008c50 <__fpclassify+0x70>
   140008c3c:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008c40:	74 07                	je     140008c49 <__fpclassify+0x69>
   140008c42:	b8 00 01 00 00       	mov    eax,0x100
   140008c47:	eb 0c                	jmp    140008c55 <__fpclassify+0x75>
   140008c49:	b8 00 05 00 00       	mov    eax,0x500
   140008c4e:	eb 05                	jmp    140008c55 <__fpclassify+0x75>
   140008c50:	b8 00 04 00 00       	mov    eax,0x400
   140008c55:	48 83 c4 10          	add    rsp,0x10
   140008c59:	5d                   	pop    rbp
   140008c5a:	c3                   	ret
   140008c5b:	90                   	nop
   140008c5c:	90                   	nop
   140008c5d:	90                   	nop
   140008c5e:	90                   	nop
   140008c5f:	90                   	nop

0000000140008c60 <__fpclassifyl>:
   140008c60:	55                   	push   rbp
   140008c61:	53                   	push   rbx
   140008c62:	48 83 ec 38          	sub    rsp,0x38
   140008c66:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008c6b:	48 89 cb             	mov    rbx,rcx
   140008c6e:	db 2b                	fld    TBYTE PTR [rbx]
   140008c70:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008c73:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008c76:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008c79:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008c7d:	98                   	cwde
   140008c7e:	25 ff 7f 00 00       	and    eax,0x7fff
   140008c83:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c86:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c8a:	75 25                	jne    140008cb1 <__fpclassifyl+0x51>
   140008c8c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c8f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c92:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c95:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c98:	85 c0                	test   eax,eax
   140008c9a:	75 07                	jne    140008ca3 <__fpclassifyl+0x43>
   140008c9c:	b8 00 40 00 00       	mov    eax,0x4000
   140008ca1:	eb 3d                	jmp    140008ce0 <__fpclassifyl+0x80>
   140008ca3:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008ca6:	85 c0                	test   eax,eax
   140008ca8:	78 31                	js     140008cdb <__fpclassifyl+0x7b>
   140008caa:	b8 00 44 00 00       	mov    eax,0x4400
   140008caf:	eb 2f                	jmp    140008ce0 <__fpclassifyl+0x80>
   140008cb1:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008cb8:	75 21                	jne    140008cdb <__fpclassifyl+0x7b>
   140008cba:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008cbd:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008cc2:	89 c2                	mov    edx,eax
   140008cc4:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008cc7:	09 d0                	or     eax,edx
   140008cc9:	85 c0                	test   eax,eax
   140008ccb:	75 07                	jne    140008cd4 <__fpclassifyl+0x74>
   140008ccd:	b8 00 05 00 00       	mov    eax,0x500
   140008cd2:	eb 0c                	jmp    140008ce0 <__fpclassifyl+0x80>
   140008cd4:	b8 00 01 00 00       	mov    eax,0x100
   140008cd9:	eb 05                	jmp    140008ce0 <__fpclassifyl+0x80>
   140008cdb:	b8 00 04 00 00       	mov    eax,0x400
   140008ce0:	48 83 c4 38          	add    rsp,0x38
   140008ce4:	5b                   	pop    rbx
   140008ce5:	5d                   	pop    rbp
   140008ce6:	c3                   	ret
   140008ce7:	90                   	nop
   140008ce8:	90                   	nop
   140008ce9:	90                   	nop
   140008cea:	90                   	nop
   140008ceb:	90                   	nop
   140008cec:	90                   	nop
   140008ced:	90                   	nop
   140008cee:	90                   	nop
   140008cef:	90                   	nop

0000000140008cf0 <__isnan>:
   140008cf0:	55                   	push   rbp
   140008cf1:	48 89 e5             	mov    rbp,rsp
   140008cf4:	48 83 ec 10          	sub    rsp,0x10
   140008cf8:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008cfd:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008d02:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008d07:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008d0a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d0d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008d10:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008d15:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d18:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d1b:	f7 d8                	neg    eax
   140008d1d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008d20:	c1 e8 1f             	shr    eax,0x1f
   140008d23:	89 c2                	mov    edx,eax
   140008d25:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d28:	09 d0                	or     eax,edx
   140008d2a:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d2d:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008d32:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008d35:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d38:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d3b:	c1 f8 1f             	sar    eax,0x1f
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

0000000140008d50 <__isnanl>:
   140008d50:	55                   	push   rbp
   140008d51:	53                   	push   rbx
   140008d52:	48 83 ec 38          	sub    rsp,0x38
   140008d56:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008d5b:	48 89 cb             	mov    rbx,rcx
   140008d5e:	db 2b                	fld    TBYTE PTR [rbx]
   140008d60:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008d63:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008d66:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008d69:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008d6d:	98                   	cwde
   140008d6e:	01 c0                	add    eax,eax
   140008d70:	25 ff ff 00 00       	and    eax,0xffff
   140008d75:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d78:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008d7b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008d7e:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008d84:	09 d0                	or     eax,edx
   140008d86:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d89:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d8c:	f7 d8                	neg    eax
   140008d8e:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008d91:	c1 e8 1f             	shr    eax,0x1f
   140008d94:	89 c2                	mov    edx,eax
   140008d96:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d99:	09 d0                	or     eax,edx
   140008d9b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d9e:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008da3:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008da6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008da9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008dac:	c1 f8 10             	sar    eax,0x10
   140008daf:	48 83 c4 38          	add    rsp,0x38
   140008db3:	5b                   	pop    rbx
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

0000000140008dc0 <wcsnlen>:
   140008dc0:	55                   	push   rbp
   140008dc1:	48 89 e5             	mov    rbp,rsp
   140008dc4:	48 83 ec 10          	sub    rsp,0x10
   140008dc8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008dcc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008dd0:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008dd7:	00 
   140008dd8:	eb 0a                	jmp    140008de4 <wcsnlen+0x24>
   140008dda:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008ddf:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008de4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008de8:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008dec:	73 0c                	jae    140008dfa <wcsnlen+0x3a>
   140008dee:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008df2:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008df5:	66 85 c0             	test   ax,ax
   140008df8:	75 e0                	jne    140008dda <wcsnlen+0x1a>
   140008dfa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dfe:	48 83 c4 10          	add    rsp,0x10
   140008e02:	5d                   	pop    rbp
   140008e03:	c3                   	ret
   140008e04:	90                   	nop
   140008e05:	90                   	nop
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

0000000140008e10 <strnlen>:
   140008e10:	55                   	push   rbp
   140008e11:	48 89 e5             	mov    rbp,rsp
   140008e14:	48 83 ec 10          	sub    rsp,0x10
   140008e18:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e1c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e20:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e24:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e28:	eb 05                	jmp    140008e2f <strnlen+0x1f>
   140008e2a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e2f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e33:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e37:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e3b:	73 0b                	jae    140008e48 <strnlen+0x38>
   140008e3d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e41:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008e44:	84 c0                	test   al,al
   140008e46:	75 e2                	jne    140008e2a <strnlen+0x1a>
   140008e48:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e4c:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e50:	48 83 c4 10          	add    rsp,0x10
   140008e54:	5d                   	pop    rbp
   140008e55:	c3                   	ret
   140008e56:	90                   	nop
   140008e57:	90                   	nop
   140008e58:	90                   	nop
   140008e59:	90                   	nop
   140008e5a:	90                   	nop
   140008e5b:	90                   	nop
   140008e5c:	90                   	nop
   140008e5d:	90                   	nop
   140008e5e:	90                   	nop
   140008e5f:	90                   	nop

0000000140008e60 <_initterm_e>:
   140008e60:	55                   	push   rbp
   140008e61:	48 89 e5             	mov    rbp,rsp
   140008e64:	48 83 ec 30          	sub    rsp,0x30
   140008e68:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e6c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e70:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e74:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e78:	eb 29                	jmp    140008ea3 <_initterm_e+0x43>
   140008e7a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e7e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e81:	48 85 c0             	test   rax,rax
   140008e84:	74 17                	je     140008e9d <_initterm_e+0x3d>
   140008e86:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e8a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e8d:	ff d0                	call   rax
   140008e8f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008e92:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008e96:	74 06                	je     140008e9e <_initterm_e+0x3e>
   140008e98:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008e9b:	eb 15                	jmp    140008eb2 <_initterm_e+0x52>
   140008e9d:	90                   	nop
   140008e9e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008ea3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008ea7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008eab:	72 cd                	jb     140008e7a <_initterm_e+0x1a>
   140008ead:	b8 00 00 00 00       	mov    eax,0x0
   140008eb2:	48 83 c4 30          	add    rsp,0x30
   140008eb6:	5d                   	pop    rbp
   140008eb7:	c3                   	ret
   140008eb8:	90                   	nop
   140008eb9:	90                   	nop
   140008eba:	90                   	nop
   140008ebb:	90                   	nop
   140008ebc:	90                   	nop
   140008ebd:	90                   	nop
   140008ebe:	90                   	nop
   140008ebf:	90                   	nop

0000000140008ec0 <__p__fmode>:
   140008ec0:	55                   	push   rbp
   140008ec1:	48 89 e5             	mov    rbp,rsp
   140008ec4:	48 8b 05 35 27 00 00 	mov    rax,QWORD PTR [rip+0x2735]        # 14000b600 <.refptr.__imp__fmode>
   140008ecb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ece:	5d                   	pop    rbp
   140008ecf:	c3                   	ret

0000000140008ed0 <__p__commode>:
   140008ed0:	55                   	push   rbp
   140008ed1:	48 89 e5             	mov    rbp,rsp
   140008ed4:	48 8b 05 15 27 00 00 	mov    rax,QWORD PTR [rip+0x2715]        # 14000b5f0 <.refptr.__imp__commode>
   140008edb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ede:	5d                   	pop    rbp
   140008edf:	c3                   	ret

0000000140008ee0 <__p___initenv>:
   140008ee0:	55                   	push   rbp
   140008ee1:	48 89 e5             	mov    rbp,rsp
   140008ee4:	48 8b 05 f5 26 00 00 	mov    rax,QWORD PTR [rip+0x26f5]        # 14000b5e0 <.refptr.__imp___initenv>
   140008eeb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008eee:	5d                   	pop    rbp
   140008eef:	c3                   	ret

0000000140008ef0 <_lock_file>:
   140008ef0:	55                   	push   rbp
   140008ef1:	48 89 e5             	mov    rbp,rsp
   140008ef4:	48 83 ec 20          	sub    rsp,0x20
   140008ef8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008efc:	b9 00 00 00 00       	mov    ecx,0x0
   140008f01:	e8 6a 01 00 00       	call   140009070 <__acrt_iob_func>
   140008f06:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008f0a:	72 52                	jb     140008f5e <_lock_file+0x6e>
   140008f0c:	b9 13 00 00 00       	mov    ecx,0x13
   140008f11:	e8 5a 01 00 00       	call   140009070 <__acrt_iob_func>
   140008f16:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f1a:	72 42                	jb     140008f5e <_lock_file+0x6e>
   140008f1c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f21:	e8 4a 01 00 00       	call   140009070 <__acrt_iob_func>
   140008f26:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f2a:	48 29 c2             	sub    rdx,rax
   140008f2d:	48 c1 fa 04          	sar    rdx,0x4
   140008f31:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008f38:	aa aa aa 
   140008f3b:	48 0f af c2          	imul   rax,rdx
   140008f3f:	83 c0 10             	add    eax,0x10
   140008f42:	89 c1                	mov    ecx,eax
   140008f44:	e8 1f 07 00 00       	call   140009668 <_lock>
   140008f49:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f4d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008f50:	80 cc 80             	or     ah,0x80
   140008f53:	89 c2                	mov    edx,eax
   140008f55:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f59:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008f5c:	eb 15                	jmp    140008f73 <_lock_file+0x83>
   140008f5e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f62:	48 83 c0 30          	add    rax,0x30
   140008f66:	48 89 c1             	mov    rcx,rax
   140008f69:	48 8b 05 80 72 00 00 	mov    rax,QWORD PTR [rip+0x7280]        # 1400101f0 <__imp_EnterCriticalSection>
   140008f70:	ff d0                	call   rax
   140008f72:	90                   	nop
   140008f73:	90                   	nop
   140008f74:	48 83 c4 20          	add    rsp,0x20
   140008f78:	5d                   	pop    rbp
   140008f79:	c3                   	ret

0000000140008f7a <_unlock_file>:
   140008f7a:	55                   	push   rbp
   140008f7b:	48 89 e5             	mov    rbp,rsp
   140008f7e:	48 83 ec 20          	sub    rsp,0x20
   140008f82:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f86:	b9 00 00 00 00       	mov    ecx,0x0
   140008f8b:	e8 e0 00 00 00       	call   140009070 <__acrt_iob_func>
   140008f90:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008f94:	72 52                	jb     140008fe8 <_unlock_file+0x6e>
   140008f96:	b9 13 00 00 00       	mov    ecx,0x13
   140008f9b:	e8 d0 00 00 00       	call   140009070 <__acrt_iob_func>
   140008fa0:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008fa4:	72 42                	jb     140008fe8 <_unlock_file+0x6e>
   140008fa6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008faa:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008fad:	80 e4 7f             	and    ah,0x7f
   140008fb0:	89 c2                	mov    edx,eax
   140008fb2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fb6:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008fb9:	b9 00 00 00 00       	mov    ecx,0x0
   140008fbe:	e8 ad 00 00 00       	call   140009070 <__acrt_iob_func>
   140008fc3:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008fc7:	48 29 c2             	sub    rdx,rax
   140008fca:	48 c1 fa 04          	sar    rdx,0x4
   140008fce:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008fd5:	aa aa aa 
   140008fd8:	48 0f af c2          	imul   rax,rdx
   140008fdc:	83 c0 10             	add    eax,0x10
   140008fdf:	89 c1                	mov    ecx,eax
   140008fe1:	e8 8a 06 00 00       	call   140009670 <_unlock>
   140008fe6:	eb 15                	jmp    140008ffd <_unlock_file+0x83>
   140008fe8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fec:	48 83 c0 30          	add    rax,0x30
   140008ff0:	48 89 c1             	mov    rcx,rax
   140008ff3:	48 8b 05 2e 72 00 00 	mov    rax,QWORD PTR [rip+0x722e]        # 140010228 <__imp_LeaveCriticalSection>
   140008ffa:	ff d0                	call   rax
   140008ffc:	90                   	nop
   140008ffd:	90                   	nop
   140008ffe:	48 83 c4 20          	add    rsp,0x20
   140009002:	5d                   	pop    rbp
   140009003:	c3                   	ret
   140009004:	90                   	nop
   140009005:	90                   	nop
   140009006:	90                   	nop
   140009007:	90                   	nop
   140009008:	90                   	nop
   140009009:	90                   	nop
   14000900a:	90                   	nop
   14000900b:	90                   	nop
   14000900c:	90                   	nop
   14000900d:	90                   	nop
   14000900e:	90                   	nop
   14000900f:	90                   	nop

0000000140009010 <_set_invalid_parameter_handler>:
   140009010:	55                   	push   rbp
   140009011:	48 89 e5             	mov    rbp,rsp
   140009014:	48 83 ec 10          	sub    rsp,0x10
   140009018:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000901c:	48 8d 05 5d 6b 00 00 	lea    rax,[rip+0x6b5d]        # 14000fb80 <handler>
   140009023:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140009027:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000902b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000902f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140009033:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140009037:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000903a:	48 89 d0             	mov    rax,rdx
   14000903d:	48 83 c4 10          	add    rsp,0x10
   140009041:	5d                   	pop    rbp
   140009042:	c3                   	ret

0000000140009043 <_get_invalid_parameter_handler>:
   140009043:	55                   	push   rbp
   140009044:	48 89 e5             	mov    rbp,rsp
   140009047:	48 8b 05 32 6b 00 00 	mov    rax,QWORD PTR [rip+0x6b32]        # 14000fb80 <handler>
   14000904e:	5d                   	pop    rbp
   14000904f:	c3                   	ret

0000000140009050 <_configthreadlocale>:
   140009050:	55                   	push   rbp
   140009051:	48 89 e5             	mov    rbp,rsp
   140009054:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140009057:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000905b:	75 07                	jne    140009064 <_configthreadlocale+0x14>
   14000905d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140009062:	eb 05                	jmp    140009069 <_configthreadlocale+0x19>
   140009064:	b8 02 00 00 00       	mov    eax,0x2
   140009069:	5d                   	pop    rbp
   14000906a:	c3                   	ret
   14000906b:	90                   	nop
   14000906c:	90                   	nop
   14000906d:	90                   	nop
   14000906e:	90                   	nop
   14000906f:	90                   	nop

0000000140009070 <__acrt_iob_func>:
   140009070:	55                   	push   rbp
   140009071:	48 89 e5             	mov    rbp,rsp
   140009074:	48 83 ec 20          	sub    rsp,0x20
   140009078:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000907b:	e8 b0 05 00 00       	call   140009630 <__iob_func>
   140009080:	48 89 c1             	mov    rcx,rax
   140009083:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140009086:	48 89 d0             	mov    rax,rdx
   140009089:	48 01 c0             	add    rax,rax
   14000908c:	48 01 d0             	add    rax,rdx
   14000908f:	48 c1 e0 04          	shl    rax,0x4
   140009093:	48 01 c8             	add    rax,rcx
   140009096:	48 83 c4 20          	add    rsp,0x20
   14000909a:	5d                   	pop    rbp
   14000909b:	c3                   	ret
   14000909c:	90                   	nop
   14000909d:	90                   	nop
   14000909e:	90                   	nop
   14000909f:	90                   	nop

00000001400090a0 <wcrtomb>:
   1400090a0:	55                   	push   rbp
   1400090a1:	48 89 e5             	mov    rbp,rsp
   1400090a4:	48 83 ec 40          	sub    rsp,0x40
   1400090a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090ac:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400090b0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090b4:	e8 5f 05 00 00       	call   140009618 <___lc_codepage_func>
   1400090b9:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400090bc:	e8 5f 05 00 00       	call   140009620 <___mb_cur_max_func>
   1400090c1:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400090c4:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   1400090c8:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   1400090cc:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   1400090d0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400090d4:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   1400090d7:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   1400090db:	48 89 c1             	mov    rcx,rax
   1400090de:	e8 7d 00 00 00       	call   140009160 <__mingw_wcrtomb_cp>
   1400090e3:	48 83 c4 40          	add    rsp,0x40
   1400090e7:	5d                   	pop    rbp
   1400090e8:	c3                   	ret
   1400090e9:	90                   	nop
   1400090ea:	90                   	nop
   1400090eb:	90                   	nop
   1400090ec:	90                   	nop
   1400090ed:	90                   	nop
   1400090ee:	90                   	nop
   1400090ef:	90                   	nop

00000001400090f0 <mbrtowc>:
   1400090f0:	55                   	push   rbp
   1400090f1:	48 89 e5             	mov    rbp,rsp
   1400090f4:	48 83 ec 40          	sub    rsp,0x40
   1400090f8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090fc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009100:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009104:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009108:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   14000910d:	75 0b                	jne    14000911a <mbrtowc+0x2a>
   14000910f:	48 8d 05 7a 6a 00 00 	lea    rax,[rip+0x6a7a]        # 14000fb90 <state_mbrtowc.0>
   140009116:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000911a:	e8 f9 04 00 00       	call   140009618 <___lc_codepage_func>
   14000911f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009122:	e8 f9 04 00 00       	call   140009620 <___mb_cur_max_func>
   140009127:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000912a:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   14000912e:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140009132:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140009136:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000913a:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   14000913d:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   140009141:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   140009144:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   140009148:	48 89 c1             	mov    rcx,rax
   14000914b:	e8 70 01 00 00       	call   1400092c0 <__mingw_mbrtowc_cp>
   140009150:	48 83 c4 40          	add    rsp,0x40
   140009154:	5d                   	pop    rbp
   140009155:	c3                   	ret
   140009156:	90                   	nop
   140009157:	90                   	nop
   140009158:	90                   	nop
   140009159:	90                   	nop
   14000915a:	90                   	nop
   14000915b:	90                   	nop
   14000915c:	90                   	nop
   14000915d:	90                   	nop
   14000915e:	90                   	nop
   14000915f:	90                   	nop

0000000140009160 <__mingw_wcrtomb_cp>:
   140009160:	55                   	push   rbp
   140009161:	48 89 e5             	mov    rbp,rsp
   140009164:	48 83 ec 50          	sub    rsp,0x50
   140009168:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000916c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009170:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009174:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   140009178:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000917d:	75 1b                	jne    14000919a <__mingw_wcrtomb_cp+0x3a>
   14000917f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009184:	74 0a                	je     140009190 <__mingw_wcrtomb_cp+0x30>
   140009186:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000918a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009190:	b8 01 00 00 00       	mov    eax,0x1
   140009195:	e9 17 01 00 00       	jmp    1400092b1 <__mingw_wcrtomb_cp+0x151>
   14000919a:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   14000919f:	74 21                	je     1400091c2 <__mingw_wcrtomb_cp+0x62>
   1400091a1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400091a5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400091a7:	85 c0                	test   eax,eax
   1400091a9:	74 17                	je     1400091c2 <__mingw_wcrtomb_cp+0x62>
   1400091ab:	e8 a8 04 00 00       	call   140009658 <_errno>
   1400091b0:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   1400091b6:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400091bd:	e9 ef 00 00 00       	jmp    1400092b1 <__mingw_wcrtomb_cp+0x151>
   1400091c2:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   1400091c6:	66 85 c0             	test   ax,ax
   1400091c9:	75 18                	jne    1400091e3 <__mingw_wcrtomb_cp+0x83>
   1400091cb:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091d0:	74 07                	je     1400091d9 <__mingw_wcrtomb_cp+0x79>
   1400091d2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400091d6:	c6 00 00             	mov    BYTE PTR [rax],0x0
   1400091d9:	b8 01 00 00 00       	mov    eax,0x1
   1400091de:	e9 ce 00 00 00       	jmp    1400092b1 <__mingw_wcrtomb_cp+0x151>
   1400091e3:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   1400091e7:	75 2b                	jne    140009214 <__mingw_wcrtomb_cp+0xb4>
   1400091e9:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   1400091ed:	66 3d ff 00          	cmp    ax,0xff
   1400091f1:	0f 87 a4 00 00 00    	ja     14000929b <__mingw_wcrtomb_cp+0x13b>
   1400091f7:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091fc:	74 0c                	je     14000920a <__mingw_wcrtomb_cp+0xaa>
   1400091fe:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009202:	89 c2                	mov    edx,eax
   140009204:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009208:	88 10                	mov    BYTE PTR [rax],dl
   14000920a:	b8 01 00 00 00       	mov    eax,0x1
   14000920f:	e9 9d 00 00 00       	jmp    1400092b1 <__mingw_wcrtomb_cp+0x151>
   140009214:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000921b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   140009221:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   140009225:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140009228:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   14000922c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140009231:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   140009238:	00 00 
   14000923a:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000923d:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140009241:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009245:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000924a:	41 b9 01 00 00 00    	mov    r9d,0x1
   140009250:	49 89 c8             	mov    r8,rcx
   140009253:	ba 00 00 00 00       	mov    edx,0x0
   140009258:	89 c1                	mov    ecx,eax
   14000925a:	48 8b 05 07 70 00 00 	mov    rax,QWORD PTR [rip+0x7007]        # 140010268 <__imp_WideCharToMultiByte>
   140009261:	ff d0                	call   rax
   140009263:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009266:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000926a:	74 32                	je     14000929e <__mingw_wcrtomb_cp+0x13e>
   14000926c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000926f:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   140009272:	7f 2a                	jg     14000929e <__mingw_wcrtomb_cp+0x13e>
   140009274:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009277:	85 c0                	test   eax,eax
   140009279:	75 23                	jne    14000929e <__mingw_wcrtomb_cp+0x13e>
   14000927b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000927e:	48 63 c8             	movsxd rcx,eax
   140009281:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009285:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009289:	49 89 c8             	mov    r8,rcx
   14000928c:	48 89 c1             	mov    rcx,rax
   14000928f:	e8 34 04 00 00       	call   1400096c8 <memcpy>
   140009294:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009297:	48 98                	cdqe
   140009299:	eb 16                	jmp    1400092b1 <__mingw_wcrtomb_cp+0x151>
   14000929b:	90                   	nop
   14000929c:	eb 01                	jmp    14000929f <__mingw_wcrtomb_cp+0x13f>
   14000929e:	90                   	nop
   14000929f:	e8 b4 03 00 00       	call   140009658 <_errno>
   1400092a4:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400092aa:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400092b1:	48 83 c4 50          	add    rsp,0x50
   1400092b5:	5d                   	pop    rbp
   1400092b6:	c3                   	ret
   1400092b7:	90                   	nop
   1400092b8:	90                   	nop
   1400092b9:	90                   	nop
   1400092ba:	90                   	nop
   1400092bb:	90                   	nop
   1400092bc:	90                   	nop
   1400092bd:	90                   	nop
   1400092be:	90                   	nop
   1400092bf:	90                   	nop

00000001400092c0 <__mingw_mbrtowc_cp>:
   1400092c0:	55                   	push   rbp
   1400092c1:	48 89 e5             	mov    rbp,rsp
   1400092c4:	48 83 ec 50          	sub    rsp,0x50
   1400092c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400092cc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400092d0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400092d4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400092d8:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   1400092dd:	75 1b                	jne    1400092fa <__mingw_mbrtowc_cp+0x3a>
   1400092df:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   1400092e6:	00 
   1400092e7:	48 8d 05 32 22 00 00 	lea    rax,[rip+0x2232]        # 14000b520 <.rdata>
   1400092ee:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400092f2:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   1400092f9:	00 
   1400092fa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400092fe:	8b 00                	mov    eax,DWORD PTR [rax]
   140009300:	3d ff 00 00 00       	cmp    eax,0xff
   140009305:	0f 87 b9 01 00 00    	ja     1400094c4 <__mingw_mbrtowc_cp+0x204>
   14000930b:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009310:	75 0c                	jne    14000931e <__mingw_mbrtowc_cp+0x5e>
   140009312:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009319:	e9 bc 01 00 00       	jmp    1400094da <__mingw_mbrtowc_cp+0x21a>
   14000931e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009322:	8b 00                	mov    eax,DWORD PTR [rax]
   140009324:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140009327:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   14000932b:	75 0c                	jne    140009339 <__mingw_mbrtowc_cp+0x79>
   14000932d:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009331:	84 c0                	test   al,al
   140009333:	0f 85 8e 01 00 00    	jne    1400094c7 <__mingw_mbrtowc_cp+0x207>
   140009339:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   14000933d:	75 2c                	jne    14000936b <__mingw_mbrtowc_cp+0xab>
   14000933f:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009344:	74 11                	je     140009357 <__mingw_mbrtowc_cp+0x97>
   140009346:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000934a:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000934d:	0f b6 d0             	movzx  edx,al
   140009350:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009354:	66 89 10             	mov    WORD PTR [rax],dx
   140009357:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000935b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000935e:	84 c0                	test   al,al
   140009360:	0f 95 c0             	setne  al
   140009363:	0f b6 c0             	movzx  eax,al
   140009366:	e9 6f 01 00 00       	jmp    1400094da <__mingw_mbrtowc_cp+0x21a>
   14000936b:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140009372:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140009379:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   14000937d:	84 c0                	test   al,al
   14000937f:	74 1a                	je     14000939b <__mingw_mbrtowc_cp+0xdb>
   140009381:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009385:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009388:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000938b:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140009392:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140009399:	eb 73                	jmp    14000940e <__mingw_mbrtowc_cp+0x14e>
   14000939b:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   14000939f:	75 5c                	jne    1400093fd <__mingw_mbrtowc_cp+0x13d>
   1400093a1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093a5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093a8:	0f b6 c0             	movzx  eax,al
   1400093ab:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   1400093ae:	89 c1                	mov    ecx,eax
   1400093b0:	e8 ab 01 00 00       	call   140009560 <__mingw_isleadbyte_cp>
   1400093b5:	85 c0                	test   eax,eax
   1400093b7:	74 44                	je     1400093fd <__mingw_mbrtowc_cp+0x13d>
   1400093b9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093bd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093c0:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   1400093c3:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   1400093c8:	77 15                	ja     1400093df <__mingw_mbrtowc_cp+0x11f>
   1400093ca:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400093cd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400093d1:	89 10                	mov    DWORD PTR [rax],edx
   1400093d3:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   1400093da:	e9 fb 00 00 00       	jmp    1400094da <__mingw_mbrtowc_cp+0x21a>
   1400093df:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093e3:	48 83 c0 01          	add    rax,0x1
   1400093e7:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093ea:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   1400093ed:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400093f4:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400093fb:	eb 11                	jmp    14000940e <__mingw_mbrtowc_cp+0x14e>
   1400093fd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009401:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009404:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009407:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000940e:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009412:	84 c0                	test   al,al
   140009414:	75 24                	jne    14000943a <__mingw_mbrtowc_cp+0x17a>
   140009416:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000941b:	74 09                	je     140009426 <__mingw_mbrtowc_cp+0x166>
   14000941d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009421:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   140009426:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000942a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009430:	b8 00 00 00 00       	mov    eax,0x0
   140009435:	e9 a0 00 00 00       	jmp    1400094da <__mingw_mbrtowc_cp+0x21a>
   14000943a:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   14000943e:	75 08                	jne    140009448 <__mingw_mbrtowc_cp+0x188>
   140009440:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   140009444:	84 c0                	test   al,al
   140009446:	74 64                	je     1400094ac <__mingw_mbrtowc_cp+0x1ec>
   140009448:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   14000944e:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   140009452:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   140009456:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   140009459:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   140009460:	00 
   140009461:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   140009465:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000946a:	45 89 c1             	mov    r9d,r8d
   14000946d:	49 89 c8             	mov    r8,rcx
   140009470:	ba 08 00 00 00       	mov    edx,0x8
   140009475:	89 c1                	mov    ecx,eax
   140009477:	48 8b 05 ba 6d 00 00 	mov    rax,QWORD PTR [rip+0x6dba]        # 140010238 <__imp_MultiByteToWideChar>
   14000947e:	ff d0                	call   rax
   140009480:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140009483:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   140009487:	75 26                	jne    1400094af <__mingw_mbrtowc_cp+0x1ef>
   140009489:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000948e:	74 0b                	je     14000949b <__mingw_mbrtowc_cp+0x1db>
   140009490:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   140009494:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009498:	66 89 10             	mov    WORD PTR [rax],dx
   14000949b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000949f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400094a5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400094a8:	48 98                	cdqe
   1400094aa:	eb 2e                	jmp    1400094da <__mingw_mbrtowc_cp+0x21a>
   1400094ac:	90                   	nop
   1400094ad:	eb 01                	jmp    1400094b0 <__mingw_mbrtowc_cp+0x1f0>
   1400094af:	90                   	nop
   1400094b0:	e8 a3 01 00 00       	call   140009658 <_errno>
   1400094b5:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400094bb:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400094c2:	eb 16                	jmp    1400094da <__mingw_mbrtowc_cp+0x21a>
   1400094c4:	90                   	nop
   1400094c5:	eb 01                	jmp    1400094c8 <__mingw_mbrtowc_cp+0x208>
   1400094c7:	90                   	nop
   1400094c8:	e8 8b 01 00 00       	call   140009658 <_errno>
   1400094cd:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   1400094d3:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400094da:	48 83 c4 50          	add    rsp,0x50
   1400094de:	5d                   	pop    rbp
   1400094df:	c3                   	ret

00000001400094e0 <fallback_IsDBCSLeadByteEx>:
   1400094e0:	55                   	push   rbp
   1400094e1:	48 89 e5             	mov    rbp,rsp
   1400094e4:	48 83 ec 40          	sub    rsp,0x40
   1400094e8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400094eb:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   1400094ee:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   1400094f2:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400094f5:	89 c1                	mov    ecx,eax
   1400094f7:	48 8b 05 02 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d02]        # 140010200 <__imp_GetCPInfo>
   1400094fe:	ff d0                	call   rax
   140009500:	85 c0                	test   eax,eax
   140009502:	74 51                	je     140009555 <fallback_IsDBCSLeadByteEx+0x75>
   140009504:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140009507:	83 f8 02             	cmp    eax,0x2
   14000950a:	75 49                	jne    140009555 <fallback_IsDBCSLeadByteEx+0x75>
   14000950c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009513:	eb 2c                	jmp    140009541 <fallback_IsDBCSLeadByteEx+0x61>
   140009515:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009518:	48 98                	cdqe
   14000951a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000951f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   140009522:	72 19                	jb     14000953d <fallback_IsDBCSLeadByteEx+0x5d>
   140009524:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009527:	83 c0 01             	add    eax,0x1
   14000952a:	48 98                	cdqe
   14000952c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009531:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   140009534:	72 07                	jb     14000953d <fallback_IsDBCSLeadByteEx+0x5d>
   140009536:	b8 01 00 00 00       	mov    eax,0x1
   14000953b:	eb 1d                	jmp    14000955a <fallback_IsDBCSLeadByteEx+0x7a>
   14000953d:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   140009541:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   140009545:	7f 0e                	jg     140009555 <fallback_IsDBCSLeadByteEx+0x75>
   140009547:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000954a:	48 98                	cdqe
   14000954c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009551:	84 c0                	test   al,al
   140009553:	75 c0                	jne    140009515 <fallback_IsDBCSLeadByteEx+0x35>
   140009555:	b8 00 00 00 00       	mov    eax,0x0
   14000955a:	48 83 c4 40          	add    rsp,0x40
   14000955e:	5d                   	pop    rbp
   14000955f:	c3                   	ret

0000000140009560 <__mingw_isleadbyte_cp>:
   140009560:	55                   	push   rbp
   140009561:	48 89 e5             	mov    rbp,rsp
   140009564:	48 83 ec 40          	sub    rsp,0x40
   140009568:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000956b:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000956e:	48 8b 05 2b 66 00 00 	mov    rax,QWORD PTR [rip+0x662b]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009575:	48 85 c0             	test   rax,rax
   140009578:	75 71                	jne    1400095eb <__mingw_isleadbyte_cp+0x8b>
   14000957a:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140009581:	00 
   140009582:	48 8d 05 a7 1f 00 00 	lea    rax,[rip+0x1fa7]        # 14000b530 <.rdata>
   140009589:	48 89 c1             	mov    rcx,rax
   14000958c:	48 8b 05 7d 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c7d]        # 140010210 <__imp_GetModuleHandleA>
   140009593:	ff d0                	call   rax
   140009595:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140009599:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000959e:	74 1b                	je     1400095bb <__mingw_isleadbyte_cp+0x5b>
   1400095a0:	48 8d 15 96 1f 00 00 	lea    rdx,[rip+0x1f96]        # 14000b53d <.rdata+0xd>
   1400095a7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400095ab:	48 89 c1             	mov    rcx,rax
   1400095ae:	48 8b 05 63 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c63]        # 140010218 <__imp_GetProcAddress>
   1400095b5:	ff d0                	call   rax
   1400095b7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400095bb:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400095c0:	75 0b                	jne    1400095cd <__mingw_isleadbyte_cp+0x6d>
   1400095c2:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 1400094e0 <fallback_IsDBCSLeadByteEx>
   1400095c9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400095cd:	48 8d 05 cc 65 00 00 	lea    rax,[rip+0x65cc]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400095d4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400095d8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400095dc:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400095e0:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   1400095e4:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400095e8:	48 87 10             	xchg   QWORD PTR [rax],rdx
   1400095eb:	4c 8b 05 ae 65 00 00 	mov    r8,QWORD PTR [rip+0x65ae]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400095f2:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400095f5:	0f b6 d0             	movzx  edx,al
   1400095f8:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400095fb:	89 c1                	mov    ecx,eax
   1400095fd:	41 ff d0             	call   r8
   140009600:	48 83 c4 40          	add    rsp,0x40
   140009604:	5d                   	pop    rbp
   140009605:	c3                   	ret
   140009606:	90                   	nop
   140009607:	90                   	nop
   140009608:	90                   	nop
   140009609:	90                   	nop
   14000960a:	90                   	nop
   14000960b:	90                   	nop
   14000960c:	90                   	nop
   14000960d:	90                   	nop
   14000960e:	90                   	nop
   14000960f:	90                   	nop

0000000140009610 <__C_specific_handler>:
   140009610:	ff 25 62 6c 00 00    	jmp    QWORD PTR [rip+0x6c62]        # 140010278 <__imp___C_specific_handler>
   140009616:	90                   	nop
   140009617:	90                   	nop

0000000140009618 <___lc_codepage_func>:
   140009618:	ff 25 62 6c 00 00    	jmp    QWORD PTR [rip+0x6c62]        # 140010280 <__imp____lc_codepage_func>
   14000961e:	90                   	nop
   14000961f:	90                   	nop

0000000140009620 <___mb_cur_max_func>:
   140009620:	ff 25 62 6c 00 00    	jmp    QWORD PTR [rip+0x6c62]        # 140010288 <__imp____mb_cur_max_func>
   140009626:	90                   	nop
   140009627:	90                   	nop

0000000140009628 <__getmainargs>:
   140009628:	ff 25 62 6c 00 00    	jmp    QWORD PTR [rip+0x6c62]        # 140010290 <__imp___getmainargs>
   14000962e:	90                   	nop
   14000962f:	90                   	nop

0000000140009630 <__iob_func>:
   140009630:	ff 25 6a 6c 00 00    	jmp    QWORD PTR [rip+0x6c6a]        # 1400102a0 <__imp___iob_func>
   140009636:	90                   	nop
   140009637:	90                   	nop

0000000140009638 <__set_app_type>:
   140009638:	ff 25 6a 6c 00 00    	jmp    QWORD PTR [rip+0x6c6a]        # 1400102a8 <__imp___set_app_type>
   14000963e:	90                   	nop
   14000963f:	90                   	nop

0000000140009640 <__setusermatherr>:
   140009640:	ff 25 6a 6c 00 00    	jmp    QWORD PTR [rip+0x6c6a]        # 1400102b0 <__imp___setusermatherr>
   140009646:	90                   	nop
   140009647:	90                   	nop

0000000140009648 <_amsg_exit>:
   140009648:	ff 25 6a 6c 00 00    	jmp    QWORD PTR [rip+0x6c6a]        # 1400102b8 <__imp__amsg_exit>
   14000964e:	90                   	nop
   14000964f:	90                   	nop

0000000140009650 <_cexit>:
   140009650:	ff 25 6a 6c 00 00    	jmp    QWORD PTR [rip+0x6c6a]        # 1400102c0 <__imp__cexit>
   140009656:	90                   	nop
   140009657:	90                   	nop

0000000140009658 <_errno>:
   140009658:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 1400102d0 <__imp__errno>
   14000965e:	90                   	nop
   14000965f:	90                   	nop

0000000140009660 <_initterm>:
   140009660:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 1400102e0 <__imp__initterm>
   140009666:	90                   	nop
   140009667:	90                   	nop

0000000140009668 <_lock>:
   140009668:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 1400102e8 <__imp__lock>
   14000966e:	90                   	nop
   14000966f:	90                   	nop

0000000140009670 <_unlock>:
   140009670:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 1400102f0 <__imp__unlock>
   140009676:	90                   	nop
   140009677:	90                   	nop

0000000140009678 <_crt_atexit>:
   140009678:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 1400102f8 <__imp__crt_atexit>
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <abort>:
   140009680:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010300 <__imp_abort>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <calloc>:
   140009688:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010308 <__imp_calloc>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <exit>:
   140009690:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010310 <__imp_exit>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <fflush>:
   140009698:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010318 <__imp_fflush>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <fprintf>:
   1400096a0:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010320 <__imp_fprintf>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <fputc>:
   1400096a8:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010328 <__imp_fputc>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <free>:
   1400096b0:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010330 <__imp_free>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <localeconv>:
   1400096b8:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010338 <__imp_localeconv>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <malloc>:
   1400096c0:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010340 <__imp_malloc>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <memcpy>:
   1400096c8:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010348 <__imp_memcpy>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <setvbuf>:
   1400096d0:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010350 <__imp_setvbuf>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <signal>:
   1400096d8:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010358 <__imp_signal>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <strerror>:
   1400096e0:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010360 <__imp_strerror>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop

00000001400096e8 <strlen>:
   1400096e8:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010368 <__imp_strlen>
   1400096ee:	90                   	nop
   1400096ef:	90                   	nop

00000001400096f0 <strncmp>:
   1400096f0:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010370 <__imp_strncmp>
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop

00000001400096f8 <vfprintf>:
   1400096f8:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010378 <__imp_vfprintf>
   1400096fe:	90                   	nop
   1400096ff:	90                   	nop

0000000140009700 <wcslen>:
   140009700:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 140010380 <__imp_wcslen>
   140009706:	90                   	nop
   140009707:	90                   	nop
   140009708:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000970f:	00 

0000000140009710 <WideCharToMultiByte>:
   140009710:	ff 25 52 6b 00 00    	jmp    QWORD PTR [rip+0x6b52]        # 140010268 <__imp_WideCharToMultiByte>
   140009716:	90                   	nop
   140009717:	90                   	nop

0000000140009718 <VirtualQuery>:
   140009718:	ff 25 42 6b 00 00    	jmp    QWORD PTR [rip+0x6b42]        # 140010260 <__imp_VirtualQuery>
   14000971e:	90                   	nop
   14000971f:	90                   	nop

0000000140009720 <VirtualProtect>:
   140009720:	ff 25 32 6b 00 00    	jmp    QWORD PTR [rip+0x6b32]        # 140010258 <__imp_VirtualProtect>
   140009726:	90                   	nop
   140009727:	90                   	nop

0000000140009728 <TlsGetValue>:
   140009728:	ff 25 22 6b 00 00    	jmp    QWORD PTR [rip+0x6b22]        # 140010250 <__imp_TlsGetValue>
   14000972e:	90                   	nop
   14000972f:	90                   	nop

0000000140009730 <Sleep>:
   140009730:	ff 25 12 6b 00 00    	jmp    QWORD PTR [rip+0x6b12]        # 140010248 <__imp_Sleep>
   140009736:	90                   	nop
   140009737:	90                   	nop

0000000140009738 <SetUnhandledExceptionFilter>:
   140009738:	ff 25 02 6b 00 00    	jmp    QWORD PTR [rip+0x6b02]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   14000973e:	90                   	nop
   14000973f:	90                   	nop

0000000140009740 <MultiByteToWideChar>:
   140009740:	ff 25 f2 6a 00 00    	jmp    QWORD PTR [rip+0x6af2]        # 140010238 <__imp_MultiByteToWideChar>
   140009746:	90                   	nop
   140009747:	90                   	nop

0000000140009748 <LoadLibraryA>:
   140009748:	ff 25 e2 6a 00 00    	jmp    QWORD PTR [rip+0x6ae2]        # 140010230 <__imp_LoadLibraryA>
   14000974e:	90                   	nop
   14000974f:	90                   	nop

0000000140009750 <LeaveCriticalSection>:
   140009750:	ff 25 d2 6a 00 00    	jmp    QWORD PTR [rip+0x6ad2]        # 140010228 <__imp_LeaveCriticalSection>
   140009756:	90                   	nop
   140009757:	90                   	nop

0000000140009758 <InitializeCriticalSection>:
   140009758:	ff 25 c2 6a 00 00    	jmp    QWORD PTR [rip+0x6ac2]        # 140010220 <__imp_InitializeCriticalSection>
   14000975e:	90                   	nop
   14000975f:	90                   	nop

0000000140009760 <GetProcAddress>:
   140009760:	ff 25 b2 6a 00 00    	jmp    QWORD PTR [rip+0x6ab2]        # 140010218 <__imp_GetProcAddress>
   140009766:	90                   	nop
   140009767:	90                   	nop

0000000140009768 <GetModuleHandleA>:
   140009768:	ff 25 a2 6a 00 00    	jmp    QWORD PTR [rip+0x6aa2]        # 140010210 <__imp_GetModuleHandleA>
   14000976e:	90                   	nop
   14000976f:	90                   	nop

0000000140009770 <GetLastError>:
   140009770:	ff 25 92 6a 00 00    	jmp    QWORD PTR [rip+0x6a92]        # 140010208 <__imp_GetLastError>
   140009776:	90                   	nop
   140009777:	90                   	nop

0000000140009778 <GetCPInfo>:
   140009778:	ff 25 82 6a 00 00    	jmp    QWORD PTR [rip+0x6a82]        # 140010200 <__imp_GetCPInfo>
   14000977e:	90                   	nop
   14000977f:	90                   	nop

0000000140009780 <FreeLibrary>:
   140009780:	ff 25 72 6a 00 00    	jmp    QWORD PTR [rip+0x6a72]        # 1400101f8 <__imp_FreeLibrary>
   140009786:	90                   	nop
   140009787:	90                   	nop

0000000140009788 <EnterCriticalSection>:
   140009788:	ff 25 62 6a 00 00    	jmp    QWORD PTR [rip+0x6a62]        # 1400101f0 <__imp_EnterCriticalSection>
   14000978e:	90                   	nop
   14000978f:	90                   	nop

0000000140009790 <DeleteCriticalSection>:
   140009790:	ff 25 52 6a 00 00    	jmp    QWORD PTR [rip+0x6a52]        # 1400101e8 <__IAT_start__>
   140009796:	90                   	nop
   140009797:	90                   	nop
   140009798:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000979f:	00 

00000001400097a0 <register_frame_ctor>:
   1400097a0:	e9 cb 7e ff ff       	jmp    140001670 <__gcc_register_frame>
   1400097a5:	90                   	nop
   1400097a6:	90                   	nop
   1400097a7:	90                   	nop
   1400097a8:	90                   	nop
   1400097a9:	90                   	nop
   1400097aa:	90                   	nop
   1400097ab:	90                   	nop
   1400097ac:	90                   	nop
   1400097ad:	90                   	nop
   1400097ae:	90                   	nop
   1400097af:	90                   	nop
