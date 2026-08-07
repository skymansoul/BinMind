
C:\Users\Administrator\Desktop\BinMind\round2\samples\uaf\cve_2017_1000410_timer\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 5f 86 00 00       	call   140009688 <fflush>
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
   14000113b:	e8 f8 84 00 00       	call   140009638 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 f8 7e 00 00       	call   140009060 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 3f 85 00 00       	call   1400096c0 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 d7 84 00 00       	call   140009670 <abort>
   140001199:	e8 c2 11 00 00       	call   140002360 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 91 f0 00 00 	mov    rax,QWORD PTR [rip+0xf091]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 36 7e 00 00       	call   140009000 <_set_invalid_parameter_handler>
   1400011ca:	e8 a1 1a 00 00       	call   140002c70 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 37 84 00 00       	call   140009628 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 2b 84 00 00       	call   140009628 <__set_app_type>
   1400011fd:	e8 ae 7c 00 00       	call   140008eb0 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 ae 7c 00 00       	call   140008ec0 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 1e 07 00 00       	call   140001940 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 03 84 00 00       	call   140009638 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 28 12 00 00       	call   14000247a <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 d6 7d 00 00       	call   140009040 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 d0 7b 00 00       	call   140008e50 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 aa 83 00 00       	call   140009638 <_amsg_exit>
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
   1400012cb:	e8 48 83 00 00       	call   140009618 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 55 83 00 00       	call   140009638 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 2e 83 00 00       	call   140009638 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 30 83 00 00       	call   140009650 <_initterm>
   140001320:	e8 f2 05 00 00       	call   140001917 <__main>
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
   14000138d:	e8 3e 7b 00 00       	call   140008ed0 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 f8 03 00 00       	call   1400017b2 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 af 82 00 00       	call   140009680 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 60 82 00 00       	call   140009640 <_cexit>
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
   140001511:	e8 9a 81 00 00       	call   1400096b0 <malloc>
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
   14000155c:	e8 77 81 00 00       	call   1400096d8 <strlen>
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
   140001585:	e8 26 81 00 00       	call   1400096b0 <malloc>
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
   1400015e8:	e8 cb 80 00 00       	call   1400096b8 <memcpy>
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
   140001642:	e8 21 80 00 00       	call   140009668 <_crt_atexit>
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

0000000140001760 <release_timer>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 20          	sub    rsp,0x20
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001770:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001773:	48 89 c1             	mov    rcx,rax
   140001776:	e8 25 7f 00 00       	call   1400096a0 <free>
   14000177b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000177f:	c7 40 08 00 00 00 00 	mov    DWORD PTR [rax+0x8],0x0
   140001786:	90                   	nop
   140001787:	48 83 c4 20          	add    rsp,0x20
   14000178b:	5d                   	pop    rbp
   14000178c:	c3                   	ret

000000014000178d <use_timer>:
   14000178d:	55                   	push   rbp
   14000178e:	48 89 e5             	mov    rbp,rsp
   140001791:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001795:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001799:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000179c:	85 c0                	test   eax,eax
   14000179e:	75 07                	jne    1400017a7 <use_timer+0x1a>
   1400017a0:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400017a5:	eb 09                	jmp    1400017b0 <use_timer+0x23>
   1400017a7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017ab:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017ae:	8b 00                	mov    eax,DWORD PTR [rax]
   1400017b0:	5d                   	pop    rbp
   1400017b1:	c3                   	ret

00000001400017b2 <main>:
   1400017b2:	55                   	push   rbp
   1400017b3:	48 89 e5             	mov    rbp,rsp
   1400017b6:	48 83 ec 30          	sub    rsp,0x30
   1400017ba:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400017bd:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400017c1:	e8 51 01 00 00       	call   140001917 <__main>
   1400017c6:	b9 10 00 00 00       	mov    ecx,0x10
   1400017cb:	e8 e0 7e 00 00       	call   1400096b0 <malloc>
   1400017d0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400017d4:	b9 14 00 00 00       	mov    ecx,0x14
   1400017d9:	e8 d2 7e 00 00       	call   1400096b0 <malloc>
   1400017de:	48 89 c2             	mov    rdx,rax
   1400017e1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017e5:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400017e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017ec:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017ef:	c7 00 07 00 00 00    	mov    DWORD PTR [rax],0x7
   1400017f5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017f9:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017fc:	48 83 c0 04          	add    rax,0x4
   140001800:	c7 00 74 69 6d 65    	mov    DWORD PTR [rax],0x656d6974
   140001806:	c7 40 03 65 72 30 00 	mov    DWORD PTR [rax+0x3],0x307265
   14000180d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001811:	c7 40 08 01 00 00 00 	mov    DWORD PTR [rax+0x8],0x1
   140001818:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000181c:	48 89 c1             	mov    rcx,rax
   14000181f:	e8 3c ff ff ff       	call   140001760 <release_timer>
   140001824:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001828:	48 89 c1             	mov    rcx,rax
   14000182b:	e8 5d ff ff ff       	call   14000178d <use_timer>
   140001830:	89 c2                	mov    edx,eax
   140001832:	48 8d 05 17 98 00 00 	lea    rax,[rip+0x9817]        # 14000b050 <.rdata>
   140001839:	48 89 c1             	mov    rcx,rax
   14000183c:	e8 2f 19 00 00       	call   140003170 <__mingw_printf>
   140001841:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001845:	48 89 c1             	mov    rcx,rax
   140001848:	e8 53 7e 00 00       	call   1400096a0 <free>
   14000184d:	b8 00 00 00 00       	mov    eax,0x0
   140001852:	48 83 c4 30          	add    rsp,0x30
   140001856:	5d                   	pop    rbp
   140001857:	c3                   	ret
   140001858:	90                   	nop
   140001859:	90                   	nop
   14000185a:	90                   	nop
   14000185b:	90                   	nop
   14000185c:	90                   	nop
   14000185d:	90                   	nop
   14000185e:	90                   	nop
   14000185f:	90                   	nop

0000000140001860 <__do_global_dtors>:
   140001860:	55                   	push   rbp
   140001861:	48 89 e5             	mov    rbp,rsp
   140001864:	48 83 ec 20          	sub    rsp,0x20
   140001868:	eb 1e                	jmp    140001888 <__do_global_dtors+0x28>
   14000186a:	48 8b 05 9f 87 00 00 	mov    rax,QWORD PTR [rip+0x879f]        # 14000a010 <p.0>
   140001871:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001874:	ff d0                	call   rax
   140001876:	48 8b 05 93 87 00 00 	mov    rax,QWORD PTR [rip+0x8793]        # 14000a010 <p.0>
   14000187d:	48 83 c0 08          	add    rax,0x8
   140001881:	48 89 05 88 87 00 00 	mov    QWORD PTR [rip+0x8788],rax        # 14000a010 <p.0>
   140001888:	48 8b 05 81 87 00 00 	mov    rax,QWORD PTR [rip+0x8781]        # 14000a010 <p.0>
   14000188f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001892:	48 85 c0             	test   rax,rax
   140001895:	75 d3                	jne    14000186a <__do_global_dtors+0xa>
   140001897:	90                   	nop
   140001898:	90                   	nop
   140001899:	48 83 c4 20          	add    rsp,0x20
   14000189d:	5d                   	pop    rbp
   14000189e:	c3                   	ret

000000014000189f <__do_global_ctors>:
   14000189f:	55                   	push   rbp
   1400018a0:	48 89 e5             	mov    rbp,rsp
   1400018a3:	48 83 ec 30          	sub    rsp,0x30
   1400018a7:	48 8b 05 c2 9c 00 00 	mov    rax,QWORD PTR [rip+0x9cc2]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018ae:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018b1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400018b4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400018b8:	75 25                	jne    1400018df <__do_global_ctors+0x40>
   1400018ba:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400018c1:	eb 04                	jmp    1400018c7 <__do_global_ctors+0x28>
   1400018c3:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400018c7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018ca:	8d 50 01             	lea    edx,[rax+0x1]
   1400018cd:	48 8b 05 9c 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c9c]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018d4:	89 d2                	mov    edx,edx
   1400018d6:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018da:	48 85 c0             	test   rax,rax
   1400018dd:	75 e4                	jne    1400018c3 <__do_global_ctors+0x24>
   1400018df:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018e2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400018e5:	eb 14                	jmp    1400018fb <__do_global_ctors+0x5c>
   1400018e7:	48 8b 05 82 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c82]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018ee:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400018f1:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018f5:	ff d0                	call   rax
   1400018f7:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400018fb:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400018ff:	75 e6                	jne    1400018e7 <__do_global_ctors+0x48>
   140001901:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001860 <__do_global_dtors>
   140001908:	48 89 c1             	mov    rcx,rax
   14000190b:	e8 1f fd ff ff       	call   14000162f <atexit>
   140001910:	90                   	nop
   140001911:	48 83 c4 30          	add    rsp,0x30
   140001915:	5d                   	pop    rbp
   140001916:	c3                   	ret

0000000140001917 <__main>:
   140001917:	55                   	push   rbp
   140001918:	48 89 e5             	mov    rbp,rsp
   14000191b:	48 83 ec 20          	sub    rsp,0x20
   14000191f:	8b 05 5b d7 00 00    	mov    eax,DWORD PTR [rip+0xd75b]        # 14000f080 <initialized>
   140001925:	85 c0                	test   eax,eax
   140001927:	75 0f                	jne    140001938 <__main+0x21>
   140001929:	c7 05 4d d7 00 00 01 	mov    DWORD PTR [rip+0xd74d],0x1        # 14000f080 <initialized>
   140001930:	00 00 00 
   140001933:	e8 67 ff ff ff       	call   14000189f <__do_global_ctors>
   140001938:	90                   	nop
   140001939:	48 83 c4 20          	add    rsp,0x20
   14000193d:	5d                   	pop    rbp
   14000193e:	c3                   	ret
   14000193f:	90                   	nop

0000000140001940 <_setargv>:
   140001940:	55                   	push   rbp
   140001941:	48 89 e5             	mov    rbp,rsp
   140001944:	b8 00 00 00 00       	mov    eax,0x0
   140001949:	5d                   	pop    rbp
   14000194a:	c3                   	ret
   14000194b:	90                   	nop
   14000194c:	90                   	nop
   14000194d:	90                   	nop
   14000194e:	90                   	nop
   14000194f:	90                   	nop

0000000140001950 <__dyn_tls_init>:
   140001950:	55                   	push   rbp
   140001951:	48 89 e5             	mov    rbp,rsp
   140001954:	48 83 ec 30          	sub    rsp,0x30
   140001958:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000195c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000195f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001963:	48 8b 05 e6 9b 00 00 	mov    rax,QWORD PTR [rip+0x9be6]        # 14000b550 <.refptr._CRT_MT>
   14000196a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000196c:	83 f8 02             	cmp    eax,0x2
   14000196f:	74 0d                	je     14000197e <__dyn_tls_init+0x2e>
   140001971:	48 8b 05 d8 9b 00 00 	mov    rax,QWORD PTR [rip+0x9bd8]        # 14000b550 <.refptr._CRT_MT>
   140001978:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000197e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001982:	74 1e                	je     1400019a2 <__dyn_tls_init+0x52>
   140001984:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001988:	75 5b                	jne    1400019e5 <__dyn_tls_init+0x95>
   14000198a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000198e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001991:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001995:	49 89 c8             	mov    r8,rcx
   140001998:	48 89 c1             	mov    rcx,rax
   14000199b:	e8 d1 11 00 00       	call   140002b71 <__mingw_TLScallback>
   1400019a0:	eb 43                	jmp    1400019e5 <__dyn_tls_init+0x95>
   1400019a2:	48 8d 05 2f 9f 00 00 	lea    rax,[rip+0x9f2f]        # 14000b8d8 <___crt_xd_start__>
   1400019a9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400019ad:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019b2:	eb 22                	jmp    1400019d6 <__dyn_tls_init+0x86>
   1400019b4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400019b8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400019bc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019c0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019c3:	48 85 c0             	test   rax,rax
   1400019c6:	74 09                	je     1400019d1 <__dyn_tls_init+0x81>
   1400019c8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019cc:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019cf:	ff d0                	call   rax
   1400019d1:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019d6:	48 8d 05 03 9f 00 00 	lea    rax,[rip+0x9f03]        # 14000b8e0 <__xd_z>
   1400019dd:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   1400019e1:	75 d1                	jne    1400019b4 <__dyn_tls_init+0x64>
   1400019e3:	eb 01                	jmp    1400019e6 <__dyn_tls_init+0x96>
   1400019e5:	90                   	nop
   1400019e6:	48 83 c4 30          	add    rsp,0x30
   1400019ea:	5d                   	pop    rbp
   1400019eb:	c3                   	ret

00000001400019ec <__tlregdtor>:
   1400019ec:	55                   	push   rbp
   1400019ed:	48 89 e5             	mov    rbp,rsp
   1400019f0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019f4:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400019f9:	75 07                	jne    140001a02 <__tlregdtor+0x16>
   1400019fb:	b8 00 00 00 00       	mov    eax,0x0
   140001a00:	eb 05                	jmp    140001a07 <__tlregdtor+0x1b>
   140001a02:	b8 00 00 00 00       	mov    eax,0x0
   140001a07:	5d                   	pop    rbp
   140001a08:	c3                   	ret

0000000140001a09 <__dyn_tls_dtor>:
   140001a09:	55                   	push   rbp
   140001a0a:	48 89 e5             	mov    rbp,rsp
   140001a0d:	48 83 ec 20          	sub    rsp,0x20
   140001a11:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a15:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a18:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a1c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a20:	74 06                	je     140001a28 <__dyn_tls_dtor+0x1f>
   140001a22:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a26:	75 18                	jne    140001a40 <__dyn_tls_dtor+0x37>
   140001a28:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a2c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a2f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a33:	49 89 c8             	mov    r8,rcx
   140001a36:	48 89 c1             	mov    rcx,rax
   140001a39:	e8 33 11 00 00       	call   140002b71 <__mingw_TLScallback>
   140001a3e:	eb 01                	jmp    140001a41 <__dyn_tls_dtor+0x38>
   140001a40:	90                   	nop
   140001a41:	48 83 c4 20          	add    rsp,0x20
   140001a45:	5d                   	pop    rbp
   140001a46:	c3                   	ret
   140001a47:	90                   	nop
   140001a48:	90                   	nop
   140001a49:	90                   	nop
   140001a4a:	90                   	nop
   140001a4b:	90                   	nop
   140001a4c:	90                   	nop
   140001a4d:	90                   	nop
   140001a4e:	90                   	nop
   140001a4f:	90                   	nop

0000000140001a50 <_matherr>:
   140001a50:	55                   	push   rbp
   140001a51:	53                   	push   rbx
   140001a52:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a59:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a5e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a62:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a66:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a6b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a6f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a73:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a75:	83 f8 06             	cmp    eax,0x6
   140001a78:	74 56                	je     140001ad0 <_matherr+0x80>
   140001a7a:	83 f8 06             	cmp    eax,0x6
   140001a7d:	7f 78                	jg     140001af7 <_matherr+0xa7>
   140001a7f:	83 f8 05             	cmp    eax,0x5
   140001a82:	74 59                	je     140001add <_matherr+0x8d>
   140001a84:	83 f8 05             	cmp    eax,0x5
   140001a87:	7f 6e                	jg     140001af7 <_matherr+0xa7>
   140001a89:	83 f8 04             	cmp    eax,0x4
   140001a8c:	74 5c                	je     140001aea <_matherr+0x9a>
   140001a8e:	83 f8 04             	cmp    eax,0x4
   140001a91:	7f 64                	jg     140001af7 <_matherr+0xa7>
   140001a93:	83 f8 03             	cmp    eax,0x3
   140001a96:	74 2b                	je     140001ac3 <_matherr+0x73>
   140001a98:	83 f8 03             	cmp    eax,0x3
   140001a9b:	7f 5a                	jg     140001af7 <_matherr+0xa7>
   140001a9d:	83 f8 01             	cmp    eax,0x1
   140001aa0:	74 07                	je     140001aa9 <_matherr+0x59>
   140001aa2:	83 f8 02             	cmp    eax,0x2
   140001aa5:	74 0f                	je     140001ab6 <_matherr+0x66>
   140001aa7:	eb 4e                	jmp    140001af7 <_matherr+0xa7>
   140001aa9:	48 8d 05 f0 95 00 00 	lea    rax,[rip+0x95f0]        # 14000b0a0 <.rdata>
   140001ab0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ab4:	eb 4d                	jmp    140001b03 <_matherr+0xb3>
   140001ab6:	48 8d 05 02 96 00 00 	lea    rax,[rip+0x9602]        # 14000b0bf <.rdata+0x1f>
   140001abd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ac1:	eb 40                	jmp    140001b03 <_matherr+0xb3>
   140001ac3:	48 8d 05 16 96 00 00 	lea    rax,[rip+0x9616]        # 14000b0e0 <.rdata+0x40>
   140001aca:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ace:	eb 33                	jmp    140001b03 <_matherr+0xb3>
   140001ad0:	48 8d 05 29 96 00 00 	lea    rax,[rip+0x9629]        # 14000b100 <.rdata+0x60>
   140001ad7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001adb:	eb 26                	jmp    140001b03 <_matherr+0xb3>
   140001add:	48 8d 05 44 96 00 00 	lea    rax,[rip+0x9644]        # 14000b128 <.rdata+0x88>
   140001ae4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ae8:	eb 19                	jmp    140001b03 <_matherr+0xb3>
   140001aea:	48 8d 05 5f 96 00 00 	lea    rax,[rip+0x965f]        # 14000b150 <.rdata+0xb0>
   140001af1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001af5:	eb 0c                	jmp    140001b03 <_matherr+0xb3>
   140001af7:	48 8d 05 88 96 00 00 	lea    rax,[rip+0x9688]        # 14000b186 <.rdata+0xe6>
   140001afe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b02:	90                   	nop
   140001b03:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b07:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b0d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b11:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b16:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b1a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b1f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b23:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b27:	b9 02 00 00 00       	mov    ecx,0x2
   140001b2c:	e8 2f 75 00 00       	call   140009060 <__acrt_iob_func>
   140001b31:	48 89 c1             	mov    rcx,rax
   140001b34:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b38:	48 8d 05 59 96 00 00 	lea    rax,[rip+0x9659]        # 14000b198 <.rdata+0xf8>
   140001b3f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b46:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b4c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b52:	49 89 d9             	mov    r9,rbx
   140001b55:	49 89 d0             	mov    r8,rdx
   140001b58:	48 89 c2             	mov    rdx,rax
   140001b5b:	e8 30 7b 00 00       	call   140009690 <fprintf>
   140001b60:	b8 00 00 00 00       	mov    eax,0x0
   140001b65:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b69:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b6d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b72:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b79:	5b                   	pop    rbx
   140001b7a:	5d                   	pop    rbp
   140001b7b:	c3                   	ret
   140001b7c:	90                   	nop
   140001b7d:	90                   	nop
   140001b7e:	90                   	nop
   140001b7f:	90                   	nop

0000000140001b80 <__report_error>:
   140001b80:	55                   	push   rbp
   140001b81:	53                   	push   rbx
   140001b82:	48 83 ec 38          	sub    rsp,0x38
   140001b86:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b8b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b8f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b93:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b97:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b9b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b9f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ba3:	b9 02 00 00 00       	mov    ecx,0x2
   140001ba8:	e8 b3 74 00 00       	call   140009060 <__acrt_iob_func>
   140001bad:	48 89 c1             	mov    rcx,rax
   140001bb0:	48 8d 05 19 96 00 00 	lea    rax,[rip+0x9619]        # 14000b1d0 <.rdata>
   140001bb7:	48 89 c2             	mov    rdx,rax
   140001bba:	e8 d1 7a 00 00       	call   140009690 <fprintf>
   140001bbf:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001bc3:	b9 02 00 00 00       	mov    ecx,0x2
   140001bc8:	e8 93 74 00 00       	call   140009060 <__acrt_iob_func>
   140001bcd:	48 89 c1             	mov    rcx,rax
   140001bd0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001bd4:	49 89 d8             	mov    r8,rbx
   140001bd7:	48 89 c2             	mov    rdx,rax
   140001bda:	e8 09 7b 00 00       	call   1400096e8 <vfprintf>
   140001bdf:	e8 8c 7a 00 00       	call   140009670 <abort>
   140001be4:	90                   	nop

0000000140001be5 <mark_section_writable>:
   140001be5:	55                   	push   rbp
   140001be6:	48 89 e5             	mov    rbp,rsp
   140001be9:	48 83 ec 60          	sub    rsp,0x60
   140001bed:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001bf1:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001bf8:	e9 82 00 00 00       	jmp    140001c7f <mark_section_writable+0x9a>
   140001bfd:	48 8b 0d dc d4 00 00 	mov    rcx,QWORD PTR [rip+0xd4dc]        # 14000f0e0 <the_secs>
   140001c04:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c07:	48 63 d0             	movsxd rdx,eax
   140001c0a:	48 89 d0             	mov    rax,rdx
   140001c0d:	48 c1 e0 02          	shl    rax,0x2
   140001c11:	48 01 d0             	add    rax,rdx
   140001c14:	48 c1 e0 03          	shl    rax,0x3
   140001c18:	48 01 c8             	add    rax,rcx
   140001c1b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c1f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c23:	72 56                	jb     140001c7b <mark_section_writable+0x96>
   140001c25:	48 8b 0d b4 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd4b4]        # 14000f0e0 <the_secs>
   140001c2c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c2f:	48 63 d0             	movsxd rdx,eax
   140001c32:	48 89 d0             	mov    rax,rdx
   140001c35:	48 c1 e0 02          	shl    rax,0x2
   140001c39:	48 01 d0             	add    rax,rdx
   140001c3c:	48 c1 e0 03          	shl    rax,0x3
   140001c40:	48 01 c8             	add    rax,rcx
   140001c43:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c47:	4c 8b 05 92 d4 00 00 	mov    r8,QWORD PTR [rip+0xd492]        # 14000f0e0 <the_secs>
   140001c4e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c51:	48 63 d0             	movsxd rdx,eax
   140001c54:	48 89 d0             	mov    rax,rdx
   140001c57:	48 c1 e0 02          	shl    rax,0x2
   140001c5b:	48 01 d0             	add    rax,rdx
   140001c5e:	48 c1 e0 03          	shl    rax,0x3
   140001c62:	4c 01 c0             	add    rax,r8
   140001c65:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c69:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c6c:	89 c0                	mov    eax,eax
   140001c6e:	48 01 c8             	add    rax,rcx
   140001c71:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c75:	0f 82 41 02 00 00    	jb     140001ebc <mark_section_writable+0x2d7>
   140001c7b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c7f:	8b 05 63 d4 00 00    	mov    eax,DWORD PTR [rip+0xd463]        # 14000f0e8 <maxSections>
   140001c85:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c88:	0f 8c 6f ff ff ff    	jl     140001bfd <mark_section_writable+0x18>
   140001c8e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c92:	48 89 c1             	mov    rcx,rax
   140001c95:	e8 c1 11 00 00       	call   140002e5b <__mingw_GetSectionForAddress>
   140001c9a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c9e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001ca3:	75 13                	jne    140001cb8 <mark_section_writable+0xd3>
   140001ca5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001ca9:	48 8d 0d 40 95 00 00 	lea    rcx,[rip+0x9540]        # 14000b1f0 <.rdata+0x20>
   140001cb0:	48 89 c2             	mov    rdx,rax
   140001cb3:	e8 c8 fe ff ff       	call   140001b80 <__report_error>
   140001cb8:	48 8b 0d 21 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd421]        # 14000f0e0 <the_secs>
   140001cbf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cc2:	48 63 d0             	movsxd rdx,eax
   140001cc5:	48 89 d0             	mov    rax,rdx
   140001cc8:	48 c1 e0 02          	shl    rax,0x2
   140001ccc:	48 01 d0             	add    rax,rdx
   140001ccf:	48 c1 e0 03          	shl    rax,0x3
   140001cd3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001cd7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001cdb:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001cdf:	48 8b 0d fa d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3fa]        # 14000f0e0 <the_secs>
   140001ce6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ce9:	48 63 d0             	movsxd rdx,eax
   140001cec:	48 89 d0             	mov    rax,rdx
   140001cef:	48 c1 e0 02          	shl    rax,0x2
   140001cf3:	48 01 d0             	add    rax,rdx
   140001cf6:	48 c1 e0 03          	shl    rax,0x3
   140001cfa:	48 01 c8             	add    rax,rcx
   140001cfd:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d03:	e8 9f 12 00 00       	call   140002fa7 <_GetPEImageBase>
   140001d08:	48 89 c1             	mov    rcx,rax
   140001d0b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d0f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d12:	41 89 c1             	mov    r9d,eax
   140001d15:	4c 8b 05 c4 d3 00 00 	mov    r8,QWORD PTR [rip+0xd3c4]        # 14000f0e0 <the_secs>
   140001d1c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d1f:	48 63 d0             	movsxd rdx,eax
   140001d22:	48 89 d0             	mov    rax,rdx
   140001d25:	48 c1 e0 02          	shl    rax,0x2
   140001d29:	48 01 d0             	add    rax,rdx
   140001d2c:	48 c1 e0 03          	shl    rax,0x3
   140001d30:	4c 01 c0             	add    rax,r8
   140001d33:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d37:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d3b:	48 8b 0d 9e d3 00 00 	mov    rcx,QWORD PTR [rip+0xd39e]        # 14000f0e0 <the_secs>
   140001d42:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d45:	48 63 d0             	movsxd rdx,eax
   140001d48:	48 89 d0             	mov    rax,rdx
   140001d4b:	48 c1 e0 02          	shl    rax,0x2
   140001d4f:	48 01 d0             	add    rax,rdx
   140001d52:	48 c1 e0 03          	shl    rax,0x3
   140001d56:	48 01 c8             	add    rax,rcx
   140001d59:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d5d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d61:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d67:	48 89 c1             	mov    rcx,rax
   140001d6a:	48 8b 05 ef e4 00 00 	mov    rax,QWORD PTR [rip+0xe4ef]        # 140010260 <__imp_VirtualQuery>
   140001d71:	ff d0                	call   rax
   140001d73:	48 85 c0             	test   rax,rax
   140001d76:	75 3f                	jne    140001db7 <mark_section_writable+0x1d2>
   140001d78:	48 8b 0d 61 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd361]        # 14000f0e0 <the_secs>
   140001d7f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d82:	48 63 d0             	movsxd rdx,eax
   140001d85:	48 89 d0             	mov    rax,rdx
   140001d88:	48 c1 e0 02          	shl    rax,0x2
   140001d8c:	48 01 d0             	add    rax,rdx
   140001d8f:	48 c1 e0 03          	shl    rax,0x3
   140001d93:	48 01 c8             	add    rax,rcx
   140001d96:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d9a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d9e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001da1:	89 c1                	mov    ecx,eax
   140001da3:	48 8d 05 66 94 00 00 	lea    rax,[rip+0x9466]        # 14000b210 <.rdata+0x40>
   140001daa:	49 89 d0             	mov    r8,rdx
   140001dad:	89 ca                	mov    edx,ecx
   140001daf:	48 89 c1             	mov    rcx,rax
   140001db2:	e8 c9 fd ff ff       	call   140001b80 <__report_error>
   140001db7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dba:	83 f8 40             	cmp    eax,0x40
   140001dbd:	0f 84 e8 00 00 00    	je     140001eab <mark_section_writable+0x2c6>
   140001dc3:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dc6:	83 f8 04             	cmp    eax,0x4
   140001dc9:	0f 84 dc 00 00 00    	je     140001eab <mark_section_writable+0x2c6>
   140001dcf:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dd2:	3d 80 00 00 00       	cmp    eax,0x80
   140001dd7:	0f 84 ce 00 00 00    	je     140001eab <mark_section_writable+0x2c6>
   140001ddd:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001de0:	83 f8 08             	cmp    eax,0x8
   140001de3:	0f 84 c2 00 00 00    	je     140001eab <mark_section_writable+0x2c6>
   140001de9:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dec:	83 f8 02             	cmp    eax,0x2
   140001def:	75 09                	jne    140001dfa <mark_section_writable+0x215>
   140001df1:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001df8:	eb 07                	jmp    140001e01 <mark_section_writable+0x21c>
   140001dfa:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e01:	48 8b 0d d8 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2d8]        # 14000f0e0 <the_secs>
   140001e08:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e0b:	48 63 d0             	movsxd rdx,eax
   140001e0e:	48 89 d0             	mov    rax,rdx
   140001e11:	48 c1 e0 02          	shl    rax,0x2
   140001e15:	48 01 d0             	add    rax,rdx
   140001e18:	48 c1 e0 03          	shl    rax,0x3
   140001e1c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e20:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e24:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e28:	48 8b 0d b1 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2b1]        # 14000f0e0 <the_secs>
   140001e2f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e32:	48 63 d0             	movsxd rdx,eax
   140001e35:	48 89 d0             	mov    rax,rdx
   140001e38:	48 c1 e0 02          	shl    rax,0x2
   140001e3c:	48 01 d0             	add    rax,rdx
   140001e3f:	48 c1 e0 03          	shl    rax,0x3
   140001e43:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e47:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e4b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e4f:	48 8b 0d 8a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd28a]        # 14000f0e0 <the_secs>
   140001e56:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e59:	48 63 d0             	movsxd rdx,eax
   140001e5c:	48 89 d0             	mov    rax,rdx
   140001e5f:	48 c1 e0 02          	shl    rax,0x2
   140001e63:	48 01 d0             	add    rax,rdx
   140001e66:	48 c1 e0 03          	shl    rax,0x3
   140001e6a:	48 01 c8             	add    rax,rcx
   140001e6d:	49 89 c0             	mov    r8,rax
   140001e70:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e74:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e78:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e7b:	4d 89 c1             	mov    r9,r8
   140001e7e:	41 89 c8             	mov    r8d,ecx
   140001e81:	48 89 c1             	mov    rcx,rax
   140001e84:	48 8b 05 cd e3 00 00 	mov    rax,QWORD PTR [rip+0xe3cd]        # 140010258 <__imp_VirtualProtect>
   140001e8b:	ff d0                	call   rax
   140001e8d:	85 c0                	test   eax,eax
   140001e8f:	75 1a                	jne    140001eab <mark_section_writable+0x2c6>
   140001e91:	48 8b 05 70 e3 00 00 	mov    rax,QWORD PTR [rip+0xe370]        # 140010208 <__imp_GetLastError>
   140001e98:	ff d0                	call   rax
   140001e9a:	89 c2                	mov    edx,eax
   140001e9c:	48 8d 05 a5 93 00 00 	lea    rax,[rip+0x93a5]        # 14000b248 <.rdata+0x78>
   140001ea3:	48 89 c1             	mov    rcx,rax
   140001ea6:	e8 d5 fc ff ff       	call   140001b80 <__report_error>
   140001eab:	8b 05 37 d2 00 00    	mov    eax,DWORD PTR [rip+0xd237]        # 14000f0e8 <maxSections>
   140001eb1:	83 c0 01             	add    eax,0x1
   140001eb4:	89 05 2e d2 00 00    	mov    DWORD PTR [rip+0xd22e],eax        # 14000f0e8 <maxSections>
   140001eba:	eb 01                	jmp    140001ebd <mark_section_writable+0x2d8>
   140001ebc:	90                   	nop
   140001ebd:	48 83 c4 60          	add    rsp,0x60
   140001ec1:	5d                   	pop    rbp
   140001ec2:	c3                   	ret

0000000140001ec3 <restore_modified_sections>:
   140001ec3:	55                   	push   rbp
   140001ec4:	48 89 e5             	mov    rbp,rsp
   140001ec7:	48 83 ec 30          	sub    rsp,0x30
   140001ecb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001ed2:	e9 ad 00 00 00       	jmp    140001f84 <restore_modified_sections+0xc1>
   140001ed7:	48 8b 0d 02 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd202]        # 14000f0e0 <the_secs>
   140001ede:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ee1:	48 63 d0             	movsxd rdx,eax
   140001ee4:	48 89 d0             	mov    rax,rdx
   140001ee7:	48 c1 e0 02          	shl    rax,0x2
   140001eeb:	48 01 d0             	add    rax,rdx
   140001eee:	48 c1 e0 03          	shl    rax,0x3
   140001ef2:	48 01 c8             	add    rax,rcx
   140001ef5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ef7:	85 c0                	test   eax,eax
   140001ef9:	0f 84 80 00 00 00    	je     140001f7f <restore_modified_sections+0xbc>
   140001eff:	48 8b 0d da d1 00 00 	mov    rcx,QWORD PTR [rip+0xd1da]        # 14000f0e0 <the_secs>
   140001f06:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f09:	48 63 d0             	movsxd rdx,eax
   140001f0c:	48 89 d0             	mov    rax,rdx
   140001f0f:	48 c1 e0 02          	shl    rax,0x2
   140001f13:	48 01 d0             	add    rax,rdx
   140001f16:	48 c1 e0 03          	shl    rax,0x3
   140001f1a:	48 01 c8             	add    rax,rcx
   140001f1d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f20:	48 8b 0d b9 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd1b9]        # 14000f0e0 <the_secs>
   140001f27:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f2a:	48 63 d0             	movsxd rdx,eax
   140001f2d:	48 89 d0             	mov    rax,rdx
   140001f30:	48 c1 e0 02          	shl    rax,0x2
   140001f34:	48 01 d0             	add    rax,rdx
   140001f37:	48 c1 e0 03          	shl    rax,0x3
   140001f3b:	48 01 c8             	add    rax,rcx
   140001f3e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f42:	4c 8b 05 97 d1 00 00 	mov    r8,QWORD PTR [rip+0xd197]        # 14000f0e0 <the_secs>
   140001f49:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f4c:	48 63 d0             	movsxd rdx,eax
   140001f4f:	48 89 d0             	mov    rax,rdx
   140001f52:	48 c1 e0 02          	shl    rax,0x2
   140001f56:	48 01 d0             	add    rax,rdx
   140001f59:	48 c1 e0 03          	shl    rax,0x3
   140001f5d:	4c 01 c0             	add    rax,r8
   140001f60:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f64:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f68:	49 89 d1             	mov    r9,rdx
   140001f6b:	45 89 d0             	mov    r8d,r10d
   140001f6e:	48 89 ca             	mov    rdx,rcx
   140001f71:	48 89 c1             	mov    rcx,rax
   140001f74:	48 8b 05 dd e2 00 00 	mov    rax,QWORD PTR [rip+0xe2dd]        # 140010258 <__imp_VirtualProtect>
   140001f7b:	ff d0                	call   rax
   140001f7d:	eb 01                	jmp    140001f80 <restore_modified_sections+0xbd>
   140001f7f:	90                   	nop
   140001f80:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f84:	8b 05 5e d1 00 00    	mov    eax,DWORD PTR [rip+0xd15e]        # 14000f0e8 <maxSections>
   140001f8a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f8d:	0f 8c 44 ff ff ff    	jl     140001ed7 <restore_modified_sections+0x14>
   140001f93:	90                   	nop
   140001f94:	90                   	nop
   140001f95:	48 83 c4 30          	add    rsp,0x30
   140001f99:	5d                   	pop    rbp
   140001f9a:	c3                   	ret

0000000140001f9b <__write_memory>:
   140001f9b:	55                   	push   rbp
   140001f9c:	48 89 e5             	mov    rbp,rsp
   140001f9f:	48 83 ec 20          	sub    rsp,0x20
   140001fa3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fa7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001fab:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001faf:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001fb4:	74 25                	je     140001fdb <__write_memory+0x40>
   140001fb6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fba:	48 89 c1             	mov    rcx,rax
   140001fbd:	e8 23 fc ff ff       	call   140001be5 <mark_section_writable>
   140001fc2:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001fc6:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001fca:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fce:	49 89 c8             	mov    r8,rcx
   140001fd1:	48 89 c1             	mov    rcx,rax
   140001fd4:	e8 df 76 00 00       	call   1400096b8 <memcpy>
   140001fd9:	eb 01                	jmp    140001fdc <__write_memory+0x41>
   140001fdb:	90                   	nop
   140001fdc:	48 83 c4 20          	add    rsp,0x20
   140001fe0:	5d                   	pop    rbp
   140001fe1:	c3                   	ret

0000000140001fe2 <do_pseudo_reloc>:
   140001fe2:	55                   	push   rbp
   140001fe3:	48 89 e5             	mov    rbp,rsp
   140001fe6:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001fea:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fee:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001ff2:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001ff6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001ffa:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001ffe:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002002:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002006:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000200a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000200f:	0f 8e 44 03 00 00    	jle    140002359 <do_pseudo_reloc+0x377>
   140002015:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000201a:	7e 25                	jle    140002041 <do_pseudo_reloc+0x5f>
   14000201c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002020:	8b 00                	mov    eax,DWORD PTR [rax]
   140002022:	85 c0                	test   eax,eax
   140002024:	75 1b                	jne    140002041 <do_pseudo_reloc+0x5f>
   140002026:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000202a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000202d:	85 c0                	test   eax,eax
   14000202f:	75 10                	jne    140002041 <do_pseudo_reloc+0x5f>
   140002031:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002035:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002038:	85 c0                	test   eax,eax
   14000203a:	75 05                	jne    140002041 <do_pseudo_reloc+0x5f>
   14000203c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002041:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002045:	8b 00                	mov    eax,DWORD PTR [rax]
   140002047:	85 c0                	test   eax,eax
   140002049:	75 0b                	jne    140002056 <do_pseudo_reloc+0x74>
   14000204b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000204f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002052:	85 c0                	test   eax,eax
   140002054:	74 59                	je     1400020af <do_pseudo_reloc+0xcd>
   140002056:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000205a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000205e:	eb 40                	jmp    1400020a0 <do_pseudo_reloc+0xbe>
   140002060:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002064:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002067:	89 c2                	mov    edx,eax
   140002069:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000206d:	48 01 d0             	add    rax,rdx
   140002070:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002074:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002078:	8b 10                	mov    edx,DWORD PTR [rax]
   14000207a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000207e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002080:	01 d0                	add    eax,edx
   140002082:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002085:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002089:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000208d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002093:	48 89 c1             	mov    rcx,rax
   140002096:	e8 00 ff ff ff       	call   140001f9b <__write_memory>
   14000209b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   1400020a0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020a4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400020a8:	72 b6                	jb     140002060 <do_pseudo_reloc+0x7e>
   1400020aa:	e9 ab 02 00 00       	jmp    14000235a <do_pseudo_reloc+0x378>
   1400020af:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020b3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020b6:	83 f8 01             	cmp    eax,0x1
   1400020b9:	74 18                	je     1400020d3 <do_pseudo_reloc+0xf1>
   1400020bb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020bf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020c2:	89 c2                	mov    edx,eax
   1400020c4:	48 8d 05 a5 91 00 00 	lea    rax,[rip+0x91a5]        # 14000b270 <.rdata+0xa0>
   1400020cb:	48 89 c1             	mov    rcx,rax
   1400020ce:	e8 ad fa ff ff       	call   140001b80 <__report_error>
   1400020d3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020d7:	48 83 c0 0c          	add    rax,0xc
   1400020db:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400020df:	e9 65 02 00 00       	jmp    140002349 <do_pseudo_reloc+0x367>
   1400020e4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020e8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020eb:	89 c2                	mov    edx,eax
   1400020ed:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020f1:	48 01 d0             	add    rax,rdx
   1400020f4:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020fc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020fe:	89 c2                	mov    edx,eax
   140002100:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002104:	48 01 d0             	add    rax,rdx
   140002107:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000210b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000210f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002112:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002116:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000211a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000211d:	0f b6 c0             	movzx  eax,al
   140002120:	83 f8 40             	cmp    eax,0x40
   140002123:	0f 84 b6 00 00 00    	je     1400021df <do_pseudo_reloc+0x1fd>
   140002129:	83 f8 40             	cmp    eax,0x40
   14000212c:	0f 87 ba 00 00 00    	ja     1400021ec <do_pseudo_reloc+0x20a>
   140002132:	83 f8 20             	cmp    eax,0x20
   140002135:	74 77                	je     1400021ae <do_pseudo_reloc+0x1cc>
   140002137:	83 f8 20             	cmp    eax,0x20
   14000213a:	0f 87 ac 00 00 00    	ja     1400021ec <do_pseudo_reloc+0x20a>
   140002140:	83 f8 08             	cmp    eax,0x8
   140002143:	74 0a                	je     14000214f <do_pseudo_reloc+0x16d>
   140002145:	83 f8 10             	cmp    eax,0x10
   140002148:	74 38                	je     140002182 <do_pseudo_reloc+0x1a0>
   14000214a:	e9 9d 00 00 00       	jmp    1400021ec <do_pseudo_reloc+0x20a>
   14000214f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002153:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002156:	0f b6 c0             	movzx  eax,al
   140002159:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000215d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002161:	25 80 00 00 00       	and    eax,0x80
   140002166:	48 85 c0             	test   rax,rax
   140002169:	0f 84 9d 00 00 00    	je     14000220c <do_pseudo_reloc+0x22a>
   14000216f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002173:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002179:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000217d:	e9 8a 00 00 00       	jmp    14000220c <do_pseudo_reloc+0x22a>
   140002182:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002186:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002189:	0f b7 c0             	movzx  eax,ax
   14000218c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002190:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002194:	25 00 80 00 00       	and    eax,0x8000
   140002199:	48 85 c0             	test   rax,rax
   14000219c:	74 71                	je     14000220f <do_pseudo_reloc+0x22d>
   14000219e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021a2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400021a8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ac:	eb 61                	jmp    14000220f <do_pseudo_reloc+0x22d>
   1400021ae:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021b2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021b4:	89 c0                	mov    eax,eax
   1400021b6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ba:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021be:	25 00 00 00 80       	and    eax,0x80000000
   1400021c3:	48 85 c0             	test   rax,rax
   1400021c6:	74 4a                	je     140002212 <do_pseudo_reloc+0x230>
   1400021c8:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021cc:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   1400021d3:	ff ff ff 
   1400021d6:	48 09 d0             	or     rax,rdx
   1400021d9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021dd:	eb 33                	jmp    140002212 <do_pseudo_reloc+0x230>
   1400021df:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021e3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400021e6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ea:	eb 27                	jmp    140002213 <do_pseudo_reloc+0x231>
   1400021ec:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   1400021f3:	00 
   1400021f4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021f8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021fb:	0f b6 c0             	movzx  eax,al
   1400021fe:	48 8d 0d a3 90 00 00 	lea    rcx,[rip+0x90a3]        # 14000b2a8 <.rdata+0xd8>
   140002205:	89 c2                	mov    edx,eax
   140002207:	e8 74 f9 ff ff       	call   140001b80 <__report_error>
   14000220c:	90                   	nop
   14000220d:	eb 04                	jmp    140002213 <do_pseudo_reloc+0x231>
   14000220f:	90                   	nop
   140002210:	eb 01                	jmp    140002213 <do_pseudo_reloc+0x231>
   140002212:	90                   	nop
   140002213:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002217:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000221b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000221d:	89 c2                	mov    edx,eax
   14000221f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002223:	48 01 c2             	add    rdx,rax
   140002226:	48 89 c8             	mov    rax,rcx
   140002229:	48 29 d0             	sub    rax,rdx
   14000222c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002230:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002234:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002238:	48 01 d0             	add    rax,rdx
   14000223b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000223f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002243:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002246:	25 ff 00 00 00       	and    eax,0xff
   14000224b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000224e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002252:	77 67                	ja     1400022bb <do_pseudo_reloc+0x2d9>
   140002254:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002257:	ba 01 00 00 00       	mov    edx,0x1
   14000225c:	89 c1                	mov    ecx,eax
   14000225e:	48 d3 e2             	shl    rdx,cl
   140002261:	48 89 d0             	mov    rax,rdx
   140002264:	48 83 e8 01          	sub    rax,0x1
   140002268:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000226c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000226f:	83 e8 01             	sub    eax,0x1
   140002272:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002279:	89 c1                	mov    ecx,eax
   14000227b:	48 d3 e2             	shl    rdx,cl
   14000227e:	48 89 d0             	mov    rax,rdx
   140002281:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002285:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002289:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000228d:	7c 0a                	jl     140002299 <do_pseudo_reloc+0x2b7>
   14000228f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002293:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002297:	7e 22                	jle    1400022bb <do_pseudo_reloc+0x2d9>
   140002299:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000229d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400022a1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400022a5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022a8:	48 8d 0d 29 90 00 00 	lea    rcx,[rip+0x9029]        # 14000b2d8 <.rdata+0x108>
   1400022af:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400022b4:	89 c2                	mov    edx,eax
   1400022b6:	e8 c5 f8 ff ff       	call   140001b80 <__report_error>
   1400022bb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022bf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022c2:	0f b6 c0             	movzx  eax,al
   1400022c5:	83 f8 40             	cmp    eax,0x40
   1400022c8:	74 63                	je     14000232d <do_pseudo_reloc+0x34b>
   1400022ca:	83 f8 40             	cmp    eax,0x40
   1400022cd:	77 75                	ja     140002344 <do_pseudo_reloc+0x362>
   1400022cf:	83 f8 20             	cmp    eax,0x20
   1400022d2:	74 41                	je     140002315 <do_pseudo_reloc+0x333>
   1400022d4:	83 f8 20             	cmp    eax,0x20
   1400022d7:	77 6b                	ja     140002344 <do_pseudo_reloc+0x362>
   1400022d9:	83 f8 08             	cmp    eax,0x8
   1400022dc:	74 07                	je     1400022e5 <do_pseudo_reloc+0x303>
   1400022de:	83 f8 10             	cmp    eax,0x10
   1400022e1:	74 1a                	je     1400022fd <do_pseudo_reloc+0x31b>
   1400022e3:	eb 5f                	jmp    140002344 <do_pseudo_reloc+0x362>
   1400022e5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022e9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022ed:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400022f3:	48 89 c1             	mov    rcx,rax
   1400022f6:	e8 a0 fc ff ff       	call   140001f9b <__write_memory>
   1400022fb:	eb 47                	jmp    140002344 <do_pseudo_reloc+0x362>
   1400022fd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002301:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002305:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000230b:	48 89 c1             	mov    rcx,rax
   14000230e:	e8 88 fc ff ff       	call   140001f9b <__write_memory>
   140002313:	eb 2f                	jmp    140002344 <do_pseudo_reloc+0x362>
   140002315:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002319:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000231d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002323:	48 89 c1             	mov    rcx,rax
   140002326:	e8 70 fc ff ff       	call   140001f9b <__write_memory>
   14000232b:	eb 17                	jmp    140002344 <do_pseudo_reloc+0x362>
   14000232d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002331:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002335:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000233b:	48 89 c1             	mov    rcx,rax
   14000233e:	e8 58 fc ff ff       	call   140001f9b <__write_memory>
   140002343:	90                   	nop
   140002344:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002349:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000234d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002351:	0f 82 8d fd ff ff    	jb     1400020e4 <do_pseudo_reloc+0x102>
   140002357:	eb 01                	jmp    14000235a <do_pseudo_reloc+0x378>
   140002359:	90                   	nop
   14000235a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000235e:	5d                   	pop    rbp
   14000235f:	c3                   	ret

0000000140002360 <_pei386_runtime_relocator>:
   140002360:	55                   	push   rbp
   140002361:	48 89 e5             	mov    rbp,rsp
   140002364:	48 83 ec 30          	sub    rsp,0x30
   140002368:	8b 05 7e cd 00 00    	mov    eax,DWORD PTR [rip+0xcd7e]        # 14000f0ec <was_init.0>
   14000236e:	85 c0                	test   eax,eax
   140002370:	0f 85 88 00 00 00    	jne    1400023fe <_pei386_runtime_relocator+0x9e>
   140002376:	8b 05 70 cd 00 00    	mov    eax,DWORD PTR [rip+0xcd70]        # 14000f0ec <was_init.0>
   14000237c:	83 c0 01             	add    eax,0x1
   14000237f:	89 05 67 cd 00 00    	mov    DWORD PTR [rip+0xcd67],eax        # 14000f0ec <was_init.0>
   140002385:	e8 21 0b 00 00       	call   140002eab <__mingw_GetSectionCount>
   14000238a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000238d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002390:	48 63 d0             	movsxd rdx,eax
   140002393:	48 89 d0             	mov    rax,rdx
   140002396:	48 c1 e0 02          	shl    rax,0x2
   14000239a:	48 01 d0             	add    rax,rdx
   14000239d:	48 c1 e0 03          	shl    rax,0x3
   1400023a1:	48 83 c0 0f          	add    rax,0xf
   1400023a5:	48 c1 e8 04          	shr    rax,0x4
   1400023a9:	48 c1 e0 04          	shl    rax,0x4
   1400023ad:	e8 7e 0d 00 00       	call   140003130 <___chkstk_ms>
   1400023b2:	48 29 c4             	sub    rsp,rax
   1400023b5:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400023ba:	48 83 c0 0f          	add    rax,0xf
   1400023be:	48 c1 e8 04          	shr    rax,0x4
   1400023c2:	48 c1 e0 04          	shl    rax,0x4
   1400023c6:	48 89 05 13 cd 00 00 	mov    QWORD PTR [rip+0xcd13],rax        # 14000f0e0 <the_secs>
   1400023cd:	c7 05 11 cd 00 00 00 	mov    DWORD PTR [rip+0xcd11],0x0        # 14000f0e8 <maxSections>
   1400023d4:	00 00 00 
   1400023d7:	48 8b 0d a2 91 00 00 	mov    rcx,QWORD PTR [rip+0x91a2]        # 14000b580 <.refptr.__ImageBase>
   1400023de:	48 8b 15 ab 91 00 00 	mov    rdx,QWORD PTR [rip+0x91ab]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   1400023e5:	48 8b 05 b4 91 00 00 	mov    rax,QWORD PTR [rip+0x91b4]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   1400023ec:	49 89 c8             	mov    r8,rcx
   1400023ef:	48 89 c1             	mov    rcx,rax
   1400023f2:	e8 eb fb ff ff       	call   140001fe2 <do_pseudo_reloc>
   1400023f7:	e8 c7 fa ff ff       	call   140001ec3 <restore_modified_sections>
   1400023fc:	eb 01                	jmp    1400023ff <_pei386_runtime_relocator+0x9f>
   1400023fe:	90                   	nop
   1400023ff:	48 89 ec             	mov    rsp,rbp
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

0000000140002410 <__mingw_raise_matherr>:
   140002410:	55                   	push   rbp
   140002411:	48 89 e5             	mov    rbp,rsp
   140002414:	48 83 ec 50          	sub    rsp,0x50
   140002418:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000241b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000241f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002424:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002429:	48 8b 05 c0 cc 00 00 	mov    rax,QWORD PTR [rip+0xccc0]        # 14000f0f0 <stUserMathErr>
   140002430:	48 85 c0             	test   rax,rax
   140002433:	74 3e                	je     140002473 <__mingw_raise_matherr+0x63>
   140002435:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002438:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000243b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000243f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002443:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002448:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000244d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002452:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002457:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000245c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002461:	48 8b 15 88 cc 00 00 	mov    rdx,QWORD PTR [rip+0xcc88]        # 14000f0f0 <stUserMathErr>
   140002468:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000246c:	48 89 c1             	mov    rcx,rax
   14000246f:	ff d2                	call   rdx
   140002471:	eb 01                	jmp    140002474 <__mingw_raise_matherr+0x64>
   140002473:	90                   	nop
   140002474:	48 83 c4 50          	add    rsp,0x50
   140002478:	5d                   	pop    rbp
   140002479:	c3                   	ret

000000014000247a <__mingw_setusermatherr>:
   14000247a:	55                   	push   rbp
   14000247b:	48 89 e5             	mov    rbp,rsp
   14000247e:	48 83 ec 20          	sub    rsp,0x20
   140002482:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002486:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000248a:	48 89 05 5f cc 00 00 	mov    QWORD PTR [rip+0xcc5f],rax        # 14000f0f0 <stUserMathErr>
   140002491:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002495:	48 89 c1             	mov    rcx,rax
   140002498:	e8 93 71 00 00       	call   140009630 <__setusermatherr>
   14000249d:	90                   	nop
   14000249e:	48 83 c4 20          	add    rsp,0x20
   1400024a2:	5d                   	pop    rbp
   1400024a3:	c3                   	ret
   1400024a4:	90                   	nop
   1400024a5:	90                   	nop
   1400024a6:	90                   	nop
   1400024a7:	90                   	nop
   1400024a8:	90                   	nop
   1400024a9:	90                   	nop
   1400024aa:	90                   	nop
   1400024ab:	90                   	nop
   1400024ac:	90                   	nop
   1400024ad:	90                   	nop
   1400024ae:	90                   	nop
   1400024af:	90                   	nop

00000001400024b0 <__mingw_SEH_error_handler>:
   1400024b0:	55                   	push   rbp
   1400024b1:	48 89 e5             	mov    rbp,rsp
   1400024b4:	48 83 ec 30          	sub    rsp,0x30
   1400024b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024bc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400024c0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400024c4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400024c8:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400024cf:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400024d6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024da:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024dd:	83 e0 02             	and    eax,0x2
   1400024e0:	85 c0                	test   eax,eax
   1400024e2:	74 0a                	je     1400024ee <__mingw_SEH_error_handler+0x3e>
   1400024e4:	b8 01 00 00 00       	mov    eax,0x1
   1400024e9:	e9 16 02 00 00       	jmp    140002704 <__mingw_SEH_error_handler+0x254>
   1400024ee:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024f2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024f4:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400024f9:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400024fe:	75 18                	jne    140002518 <__mingw_SEH_error_handler+0x68>
   140002500:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002504:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002507:	83 e0 01             	and    eax,0x1
   14000250a:	85 c0                	test   eax,eax
   14000250c:	75 0a                	jne    140002518 <__mingw_SEH_error_handler+0x68>
   14000250e:	b8 00 00 00 00       	mov    eax,0x0
   140002513:	e9 ec 01 00 00       	jmp    140002704 <__mingw_SEH_error_handler+0x254>
   140002518:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000251c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000251e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002523:	0f 84 12 01 00 00    	je     14000263b <__mingw_SEH_error_handler+0x18b>
   140002529:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000252e:	0f 87 c3 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   140002534:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002539:	0f 87 b8 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   14000253f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002544:	0f 83 4c 01 00 00    	jae    140002696 <__mingw_SEH_error_handler+0x1e6>
   14000254a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000254f:	0f 84 3a 01 00 00    	je     14000268f <__mingw_SEH_error_handler+0x1df>
   140002555:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000255a:	0f 87 97 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   140002560:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002565:	0f 84 83 01 00 00    	je     1400026ee <__mingw_SEH_error_handler+0x23e>
   14000256b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002570:	0f 87 81 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   140002576:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000257b:	0f 87 76 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   140002581:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002586:	0f 83 03 01 00 00    	jae    14000268f <__mingw_SEH_error_handler+0x1df>
   14000258c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002591:	0f 84 57 01 00 00    	je     1400026ee <__mingw_SEH_error_handler+0x23e>
   140002597:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000259c:	0f 87 55 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   1400025a2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025a7:	0f 84 8e 00 00 00    	je     14000263b <__mingw_SEH_error_handler+0x18b>
   1400025ad:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025b2:	0f 87 3f 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   1400025b8:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025bd:	0f 84 2b 01 00 00    	je     1400026ee <__mingw_SEH_error_handler+0x23e>
   1400025c3:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025c8:	0f 87 29 01 00 00    	ja     1400026f7 <__mingw_SEH_error_handler+0x247>
   1400025ce:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400025d3:	0f 84 15 01 00 00    	je     1400026ee <__mingw_SEH_error_handler+0x23e>
   1400025d9:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400025de:	0f 85 13 01 00 00    	jne    1400026f7 <__mingw_SEH_error_handler+0x247>
   1400025e4:	ba 00 00 00 00       	mov    edx,0x0
   1400025e9:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025ee:	e8 d5 70 00 00       	call   1400096c8 <signal>
   1400025f3:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025f7:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025fc:	75 1b                	jne    140002619 <__mingw_SEH_error_handler+0x169>
   1400025fe:	ba 01 00 00 00       	mov    edx,0x1
   140002603:	b9 0b 00 00 00       	mov    ecx,0xb
   140002608:	e8 bb 70 00 00       	call   1400096c8 <signal>
   14000260d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002614:	e9 e1 00 00 00       	jmp    1400026fa <__mingw_SEH_error_handler+0x24a>
   140002619:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000261e:	0f 84 d6 00 00 00    	je     1400026fa <__mingw_SEH_error_handler+0x24a>
   140002624:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002628:	b9 0b 00 00 00       	mov    ecx,0xb
   14000262d:	ff d0                	call   rax
   14000262f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002636:	e9 bf 00 00 00       	jmp    1400026fa <__mingw_SEH_error_handler+0x24a>
   14000263b:	ba 00 00 00 00       	mov    edx,0x0
   140002640:	b9 04 00 00 00       	mov    ecx,0x4
   140002645:	e8 7e 70 00 00       	call   1400096c8 <signal>
   14000264a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000264e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002653:	75 1b                	jne    140002670 <__mingw_SEH_error_handler+0x1c0>
   140002655:	ba 01 00 00 00       	mov    edx,0x1
   14000265a:	b9 04 00 00 00       	mov    ecx,0x4
   14000265f:	e8 64 70 00 00       	call   1400096c8 <signal>
   140002664:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000266b:	e9 8d 00 00 00       	jmp    1400026fd <__mingw_SEH_error_handler+0x24d>
   140002670:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002675:	0f 84 82 00 00 00    	je     1400026fd <__mingw_SEH_error_handler+0x24d>
   14000267b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000267f:	b9 04 00 00 00       	mov    ecx,0x4
   140002684:	ff d0                	call   rax
   140002686:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000268d:	eb 6e                	jmp    1400026fd <__mingw_SEH_error_handler+0x24d>
   14000268f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002696:	ba 00 00 00 00       	mov    edx,0x0
   14000269b:	b9 08 00 00 00       	mov    ecx,0x8
   1400026a0:	e8 23 70 00 00       	call   1400096c8 <signal>
   1400026a5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026a9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026ae:	75 23                	jne    1400026d3 <__mingw_SEH_error_handler+0x223>
   1400026b0:	ba 01 00 00 00       	mov    edx,0x1
   1400026b5:	b9 08 00 00 00       	mov    ecx,0x8
   1400026ba:	e8 09 70 00 00       	call   1400096c8 <signal>
   1400026bf:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400026c3:	74 05                	je     1400026ca <__mingw_SEH_error_handler+0x21a>
   1400026c5:	e8 a6 05 00 00       	call   140002c70 <_fpreset>
   1400026ca:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026d1:	eb 2d                	jmp    140002700 <__mingw_SEH_error_handler+0x250>
   1400026d3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026d8:	74 26                	je     140002700 <__mingw_SEH_error_handler+0x250>
   1400026da:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026de:	b9 08 00 00 00       	mov    ecx,0x8
   1400026e3:	ff d0                	call   rax
   1400026e5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026ec:	eb 12                	jmp    140002700 <__mingw_SEH_error_handler+0x250>
   1400026ee:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026f5:	eb 0a                	jmp    140002701 <__mingw_SEH_error_handler+0x251>
   1400026f7:	90                   	nop
   1400026f8:	eb 07                	jmp    140002701 <__mingw_SEH_error_handler+0x251>
   1400026fa:	90                   	nop
   1400026fb:	eb 04                	jmp    140002701 <__mingw_SEH_error_handler+0x251>
   1400026fd:	90                   	nop
   1400026fe:	eb 01                	jmp    140002701 <__mingw_SEH_error_handler+0x251>
   140002700:	90                   	nop
   140002701:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002704:	48 83 c4 30          	add    rsp,0x30
   140002708:	5d                   	pop    rbp
   140002709:	c3                   	ret

000000014000270a <_gnu_exception_handler>:
   14000270a:	55                   	push   rbp
   14000270b:	48 89 e5             	mov    rbp,rsp
   14000270e:	48 83 ec 30          	sub    rsp,0x30
   140002712:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002716:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000271d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002724:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002728:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000272b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000272d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002732:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002737:	75 1b                	jne    140002754 <_gnu_exception_handler+0x4a>
   140002739:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000273d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002740:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002743:	83 e0 01             	and    eax,0x1
   140002746:	85 c0                	test   eax,eax
   140002748:	75 0a                	jne    140002754 <_gnu_exception_handler+0x4a>
   14000274a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000274f:	e9 14 02 00 00       	jmp    140002968 <_gnu_exception_handler+0x25e>
   140002754:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002758:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000275b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000275d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002762:	0f 84 12 01 00 00    	je     14000287a <_gnu_exception_handler+0x170>
   140002768:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000276d:	0f 87 c3 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   140002773:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002778:	0f 87 b8 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   14000277e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002783:	0f 83 4c 01 00 00    	jae    1400028d5 <_gnu_exception_handler+0x1cb>
   140002789:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000278e:	0f 84 3a 01 00 00    	je     1400028ce <_gnu_exception_handler+0x1c4>
   140002794:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002799:	0f 87 97 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   14000279f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027a4:	0f 84 83 01 00 00    	je     14000292d <_gnu_exception_handler+0x223>
   1400027aa:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027af:	0f 87 81 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   1400027b5:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400027ba:	0f 87 76 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   1400027c0:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400027c5:	0f 83 03 01 00 00    	jae    1400028ce <_gnu_exception_handler+0x1c4>
   1400027cb:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027d0:	0f 84 57 01 00 00    	je     14000292d <_gnu_exception_handler+0x223>
   1400027d6:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027db:	0f 87 55 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   1400027e1:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027e6:	0f 84 8e 00 00 00    	je     14000287a <_gnu_exception_handler+0x170>
   1400027ec:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400027f1:	0f 87 3f 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   1400027f7:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400027fc:	0f 84 2b 01 00 00    	je     14000292d <_gnu_exception_handler+0x223>
   140002802:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002807:	0f 87 29 01 00 00    	ja     140002936 <_gnu_exception_handler+0x22c>
   14000280d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002812:	0f 84 15 01 00 00    	je     14000292d <_gnu_exception_handler+0x223>
   140002818:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000281d:	0f 85 13 01 00 00    	jne    140002936 <_gnu_exception_handler+0x22c>
   140002823:	ba 00 00 00 00       	mov    edx,0x0
   140002828:	b9 0b 00 00 00       	mov    ecx,0xb
   14000282d:	e8 96 6e 00 00       	call   1400096c8 <signal>
   140002832:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002836:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000283b:	75 1b                	jne    140002858 <_gnu_exception_handler+0x14e>
   14000283d:	ba 01 00 00 00       	mov    edx,0x1
   140002842:	b9 0b 00 00 00       	mov    ecx,0xb
   140002847:	e8 7c 6e 00 00       	call   1400096c8 <signal>
   14000284c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002853:	e9 e1 00 00 00       	jmp    140002939 <_gnu_exception_handler+0x22f>
   140002858:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000285d:	0f 84 d6 00 00 00    	je     140002939 <_gnu_exception_handler+0x22f>
   140002863:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002867:	b9 0b 00 00 00       	mov    ecx,0xb
   14000286c:	ff d0                	call   rax
   14000286e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002875:	e9 bf 00 00 00       	jmp    140002939 <_gnu_exception_handler+0x22f>
   14000287a:	ba 00 00 00 00       	mov    edx,0x0
   14000287f:	b9 04 00 00 00       	mov    ecx,0x4
   140002884:	e8 3f 6e 00 00       	call   1400096c8 <signal>
   140002889:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000288d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002892:	75 1b                	jne    1400028af <_gnu_exception_handler+0x1a5>
   140002894:	ba 01 00 00 00       	mov    edx,0x1
   140002899:	b9 04 00 00 00       	mov    ecx,0x4
   14000289e:	e8 25 6e 00 00       	call   1400096c8 <signal>
   1400028a3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028aa:	e9 8d 00 00 00       	jmp    14000293c <_gnu_exception_handler+0x232>
   1400028af:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028b4:	0f 84 82 00 00 00    	je     14000293c <_gnu_exception_handler+0x232>
   1400028ba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028be:	b9 04 00 00 00       	mov    ecx,0x4
   1400028c3:	ff d0                	call   rax
   1400028c5:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028cc:	eb 6e                	jmp    14000293c <_gnu_exception_handler+0x232>
   1400028ce:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400028d5:	ba 00 00 00 00       	mov    edx,0x0
   1400028da:	b9 08 00 00 00       	mov    ecx,0x8
   1400028df:	e8 e4 6d 00 00       	call   1400096c8 <signal>
   1400028e4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028e8:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028ed:	75 23                	jne    140002912 <_gnu_exception_handler+0x208>
   1400028ef:	ba 01 00 00 00       	mov    edx,0x1
   1400028f4:	b9 08 00 00 00       	mov    ecx,0x8
   1400028f9:	e8 ca 6d 00 00       	call   1400096c8 <signal>
   1400028fe:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002902:	74 05                	je     140002909 <_gnu_exception_handler+0x1ff>
   140002904:	e8 67 03 00 00       	call   140002c70 <_fpreset>
   140002909:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002910:	eb 2d                	jmp    14000293f <_gnu_exception_handler+0x235>
   140002912:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002917:	74 26                	je     14000293f <_gnu_exception_handler+0x235>
   140002919:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000291d:	b9 08 00 00 00       	mov    ecx,0x8
   140002922:	ff d0                	call   rax
   140002924:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000292b:	eb 12                	jmp    14000293f <_gnu_exception_handler+0x235>
   14000292d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002934:	eb 0a                	jmp    140002940 <_gnu_exception_handler+0x236>
   140002936:	90                   	nop
   140002937:	eb 07                	jmp    140002940 <_gnu_exception_handler+0x236>
   140002939:	90                   	nop
   14000293a:	eb 04                	jmp    140002940 <_gnu_exception_handler+0x236>
   14000293c:	90                   	nop
   14000293d:	eb 01                	jmp    140002940 <_gnu_exception_handler+0x236>
   14000293f:	90                   	nop
   140002940:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002944:	75 1f                	jne    140002965 <_gnu_exception_handler+0x25b>
   140002946:	48 8b 05 c3 c7 00 00 	mov    rax,QWORD PTR [rip+0xc7c3]        # 14000f110 <__mingw_oldexcpt_handler>
   14000294d:	48 85 c0             	test   rax,rax
   140002950:	74 13                	je     140002965 <_gnu_exception_handler+0x25b>
   140002952:	48 8b 15 b7 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc7b7]        # 14000f110 <__mingw_oldexcpt_handler>
   140002959:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000295d:	48 89 c1             	mov    rcx,rax
   140002960:	ff d2                	call   rdx
   140002962:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002965:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002968:	48 83 c4 30          	add    rsp,0x30
   14000296c:	5d                   	pop    rbp
   14000296d:	c3                   	ret
   14000296e:	90                   	nop
   14000296f:	90                   	nop

0000000140002970 <___w64_mingwthr_add_key_dtor>:
   140002970:	55                   	push   rbp
   140002971:	48 89 e5             	mov    rbp,rsp
   140002974:	48 83 ec 30          	sub    rsp,0x30
   140002978:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000297b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000297f:	8b 05 c3 c7 00 00    	mov    eax,DWORD PTR [rip+0xc7c3]        # 14000f148 <__mingwthr_cs_init>
   140002985:	85 c0                	test   eax,eax
   140002987:	75 07                	jne    140002990 <___w64_mingwthr_add_key_dtor+0x20>
   140002989:	b8 00 00 00 00       	mov    eax,0x0
   14000298e:	eb 7b                	jmp    140002a0b <___w64_mingwthr_add_key_dtor+0x9b>
   140002990:	ba 18 00 00 00       	mov    edx,0x18
   140002995:	b9 01 00 00 00       	mov    ecx,0x1
   14000299a:	e8 d9 6c 00 00       	call   140009678 <calloc>
   14000299f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400029a3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029a8:	75 07                	jne    1400029b1 <___w64_mingwthr_add_key_dtor+0x41>
   1400029aa:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400029af:	eb 5a                	jmp    140002a0b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029b1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029b5:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400029b8:	89 10                	mov    DWORD PTR [rax],edx
   1400029ba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029be:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400029c2:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   1400029c6:	48 8d 05 53 c7 00 00 	lea    rax,[rip+0xc753]        # 14000f120 <__mingwthr_cs>
   1400029cd:	48 89 c1             	mov    rcx,rax
   1400029d0:	48 8b 05 19 d8 00 00 	mov    rax,QWORD PTR [rip+0xd819]        # 1400101f0 <__imp_EnterCriticalSection>
   1400029d7:	ff d0                	call   rax
   1400029d9:	48 8b 15 70 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc770]        # 14000f150 <key_dtor_list>
   1400029e0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029e4:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   1400029e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029ec:	48 89 05 5d c7 00 00 	mov    QWORD PTR [rip+0xc75d],rax        # 14000f150 <key_dtor_list>
   1400029f3:	48 8d 05 26 c7 00 00 	lea    rax,[rip+0xc726]        # 14000f120 <__mingwthr_cs>
   1400029fa:	48 89 c1             	mov    rcx,rax
   1400029fd:	48 8b 05 24 d8 00 00 	mov    rax,QWORD PTR [rip+0xd824]        # 140010228 <__imp_LeaveCriticalSection>
   140002a04:	ff d0                	call   rax
   140002a06:	b8 00 00 00 00       	mov    eax,0x0
   140002a0b:	48 83 c4 30          	add    rsp,0x30
   140002a0f:	5d                   	pop    rbp
   140002a10:	c3                   	ret

0000000140002a11 <___w64_mingwthr_remove_key_dtor>:
   140002a11:	55                   	push   rbp
   140002a12:	48 89 e5             	mov    rbp,rsp
   140002a15:	48 83 ec 30          	sub    rsp,0x30
   140002a19:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a1c:	8b 05 26 c7 00 00    	mov    eax,DWORD PTR [rip+0xc726]        # 14000f148 <__mingwthr_cs_init>
   140002a22:	85 c0                	test   eax,eax
   140002a24:	75 0a                	jne    140002a30 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a26:	b8 00 00 00 00       	mov    eax,0x0
   140002a2b:	e9 9c 00 00 00       	jmp    140002acc <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a30:	48 8d 05 e9 c6 00 00 	lea    rax,[rip+0xc6e9]        # 14000f120 <__mingwthr_cs>
   140002a37:	48 89 c1             	mov    rcx,rax
   140002a3a:	48 8b 05 af d7 00 00 	mov    rax,QWORD PTR [rip+0xd7af]        # 1400101f0 <__imp_EnterCriticalSection>
   140002a41:	ff d0                	call   rax
   140002a43:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a4a:	00 
   140002a4b:	48 8b 05 fe c6 00 00 	mov    rax,QWORD PTR [rip+0xc6fe]        # 14000f150 <key_dtor_list>
   140002a52:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a56:	eb 55                	jmp    140002aad <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a58:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a5c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a5e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a61:	75 36                	jne    140002a99 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a63:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a68:	75 11                	jne    140002a7b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a6a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a6e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a72:	48 89 05 d7 c6 00 00 	mov    QWORD PTR [rip+0xc6d7],rax        # 14000f150 <key_dtor_list>
   140002a79:	eb 10                	jmp    140002a8b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a7b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a7f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a83:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a87:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a8b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a8f:	48 89 c1             	mov    rcx,rax
   140002a92:	e8 09 6c 00 00       	call   1400096a0 <free>
   140002a97:	eb 1b                	jmp    140002ab4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a99:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a9d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002aa1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aa5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002aa9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002aad:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002ab2:	75 a4                	jne    140002a58 <___w64_mingwthr_remove_key_dtor+0x47>
   140002ab4:	48 8d 05 65 c6 00 00 	lea    rax,[rip+0xc665]        # 14000f120 <__mingwthr_cs>
   140002abb:	48 89 c1             	mov    rcx,rax
   140002abe:	48 8b 05 63 d7 00 00 	mov    rax,QWORD PTR [rip+0xd763]        # 140010228 <__imp_LeaveCriticalSection>
   140002ac5:	ff d0                	call   rax
   140002ac7:	b8 00 00 00 00       	mov    eax,0x0
   140002acc:	48 83 c4 30          	add    rsp,0x30
   140002ad0:	5d                   	pop    rbp
   140002ad1:	c3                   	ret

0000000140002ad2 <__mingwthr_run_key_dtors>:
   140002ad2:	55                   	push   rbp
   140002ad3:	48 89 e5             	mov    rbp,rsp
   140002ad6:	48 83 ec 30          	sub    rsp,0x30
   140002ada:	8b 05 68 c6 00 00    	mov    eax,DWORD PTR [rip+0xc668]        # 14000f148 <__mingwthr_cs_init>
   140002ae0:	85 c0                	test   eax,eax
   140002ae2:	0f 84 82 00 00 00    	je     140002b6a <__mingwthr_run_key_dtors+0x98>
   140002ae8:	48 8d 05 31 c6 00 00 	lea    rax,[rip+0xc631]        # 14000f120 <__mingwthr_cs>
   140002aef:	48 89 c1             	mov    rcx,rax
   140002af2:	48 8b 05 f7 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6f7]        # 1400101f0 <__imp_EnterCriticalSection>
   140002af9:	ff d0                	call   rax
   140002afb:	48 8b 05 4e c6 00 00 	mov    rax,QWORD PTR [rip+0xc64e]        # 14000f150 <key_dtor_list>
   140002b02:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b06:	eb 46                	jmp    140002b4e <__mingwthr_run_key_dtors+0x7c>
   140002b08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b0c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b0e:	89 c1                	mov    ecx,eax
   140002b10:	48 8b 05 39 d7 00 00 	mov    rax,QWORD PTR [rip+0xd739]        # 140010250 <__imp_TlsGetValue>
   140002b17:	ff d0                	call   rax
   140002b19:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b1d:	48 8b 05 e4 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6e4]        # 140010208 <__imp_GetLastError>
   140002b24:	ff d0                	call   rax
   140002b26:	85 c0                	test   eax,eax
   140002b28:	75 18                	jne    140002b42 <__mingwthr_run_key_dtors+0x70>
   140002b2a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b2f:	74 11                	je     140002b42 <__mingwthr_run_key_dtors+0x70>
   140002b31:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b35:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002b39:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b3d:	48 89 c1             	mov    rcx,rax
   140002b40:	ff d2                	call   rdx
   140002b42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b46:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b4a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b4e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b53:	75 b3                	jne    140002b08 <__mingwthr_run_key_dtors+0x36>
   140002b55:	48 8d 05 c4 c5 00 00 	lea    rax,[rip+0xc5c4]        # 14000f120 <__mingwthr_cs>
   140002b5c:	48 89 c1             	mov    rcx,rax
   140002b5f:	48 8b 05 c2 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6c2]        # 140010228 <__imp_LeaveCriticalSection>
   140002b66:	ff d0                	call   rax
   140002b68:	eb 01                	jmp    140002b6b <__mingwthr_run_key_dtors+0x99>
   140002b6a:	90                   	nop
   140002b6b:	48 83 c4 30          	add    rsp,0x30
   140002b6f:	5d                   	pop    rbp
   140002b70:	c3                   	ret

0000000140002b71 <__mingw_TLScallback>:
   140002b71:	55                   	push   rbp
   140002b72:	48 89 e5             	mov    rbp,rsp
   140002b75:	48 83 ec 30          	sub    rsp,0x30
   140002b79:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b7d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b80:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b84:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b88:	0f 84 cc 00 00 00    	je     140002c5a <__mingw_TLScallback+0xe9>
   140002b8e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b92:	0f 87 ca 00 00 00    	ja     140002c62 <__mingw_TLScallback+0xf1>
   140002b98:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b9c:	0f 84 b1 00 00 00    	je     140002c53 <__mingw_TLScallback+0xe2>
   140002ba2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002ba6:	0f 87 b6 00 00 00    	ja     140002c62 <__mingw_TLScallback+0xf1>
   140002bac:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002bb0:	74 33                	je     140002be5 <__mingw_TLScallback+0x74>
   140002bb2:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002bb6:	0f 85 a6 00 00 00    	jne    140002c62 <__mingw_TLScallback+0xf1>
   140002bbc:	8b 05 86 c5 00 00    	mov    eax,DWORD PTR [rip+0xc586]        # 14000f148 <__mingwthr_cs_init>
   140002bc2:	85 c0                	test   eax,eax
   140002bc4:	75 13                	jne    140002bd9 <__mingw_TLScallback+0x68>
   140002bc6:	48 8d 05 53 c5 00 00 	lea    rax,[rip+0xc553]        # 14000f120 <__mingwthr_cs>
   140002bcd:	48 89 c1             	mov    rcx,rax
   140002bd0:	48 8b 05 49 d6 00 00 	mov    rax,QWORD PTR [rip+0xd649]        # 140010220 <__imp_InitializeCriticalSection>
   140002bd7:	ff d0                	call   rax
   140002bd9:	c7 05 65 c5 00 00 01 	mov    DWORD PTR [rip+0xc565],0x1        # 14000f148 <__mingwthr_cs_init>
   140002be0:	00 00 00 
   140002be3:	eb 7d                	jmp    140002c62 <__mingw_TLScallback+0xf1>
   140002be5:	e8 e8 fe ff ff       	call   140002ad2 <__mingwthr_run_key_dtors>
   140002bea:	8b 05 58 c5 00 00    	mov    eax,DWORD PTR [rip+0xc558]        # 14000f148 <__mingwthr_cs_init>
   140002bf0:	83 f8 01             	cmp    eax,0x1
   140002bf3:	75 6c                	jne    140002c61 <__mingw_TLScallback+0xf0>
   140002bf5:	48 8b 05 54 c5 00 00 	mov    rax,QWORD PTR [rip+0xc554]        # 14000f150 <key_dtor_list>
   140002bfc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c00:	eb 20                	jmp    140002c22 <__mingw_TLScallback+0xb1>
   140002c02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c06:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c0a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c0e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c12:	48 89 c1             	mov    rcx,rax
   140002c15:	e8 86 6a 00 00       	call   1400096a0 <free>
   140002c1a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c1e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c22:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c27:	75 d9                	jne    140002c02 <__mingw_TLScallback+0x91>
   140002c29:	48 c7 05 1c c5 00 00 	mov    QWORD PTR [rip+0xc51c],0x0        # 14000f150 <key_dtor_list>
   140002c30:	00 00 00 00 
   140002c34:	c7 05 0a c5 00 00 00 	mov    DWORD PTR [rip+0xc50a],0x0        # 14000f148 <__mingwthr_cs_init>
   140002c3b:	00 00 00 
   140002c3e:	48 8d 05 db c4 00 00 	lea    rax,[rip+0xc4db]        # 14000f120 <__mingwthr_cs>
   140002c45:	48 89 c1             	mov    rcx,rax
   140002c48:	48 8b 05 99 d5 00 00 	mov    rax,QWORD PTR [rip+0xd599]        # 1400101e8 <__IAT_start__>
   140002c4f:	ff d0                	call   rax
   140002c51:	eb 0e                	jmp    140002c61 <__mingw_TLScallback+0xf0>
   140002c53:	e8 18 00 00 00       	call   140002c70 <_fpreset>
   140002c58:	eb 08                	jmp    140002c62 <__mingw_TLScallback+0xf1>
   140002c5a:	e8 73 fe ff ff       	call   140002ad2 <__mingwthr_run_key_dtors>
   140002c5f:	eb 01                	jmp    140002c62 <__mingw_TLScallback+0xf1>
   140002c61:	90                   	nop
   140002c62:	b8 01 00 00 00       	mov    eax,0x1
   140002c67:	48 83 c4 30          	add    rsp,0x30
   140002c6b:	5d                   	pop    rbp
   140002c6c:	c3                   	ret
   140002c6d:	90                   	nop
   140002c6e:	90                   	nop
   140002c6f:	90                   	nop

0000000140002c70 <_fpreset>:
   140002c70:	55                   	push   rbp
   140002c71:	48 89 e5             	mov    rbp,rsp
   140002c74:	db e3                	fninit
   140002c76:	90                   	nop
   140002c77:	5d                   	pop    rbp
   140002c78:	c3                   	ret
   140002c79:	90                   	nop
   140002c7a:	90                   	nop
   140002c7b:	90                   	nop
   140002c7c:	90                   	nop
   140002c7d:	90                   	nop
   140002c7e:	90                   	nop
   140002c7f:	90                   	nop

0000000140002c80 <_ValidateImageBase>:
   140002c80:	55                   	push   rbp
   140002c81:	48 89 e5             	mov    rbp,rsp
   140002c84:	48 83 ec 20          	sub    rsp,0x20
   140002c88:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c8c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c90:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c98:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c9b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c9f:	74 07                	je     140002ca8 <_ValidateImageBase+0x28>
   140002ca1:	b8 00 00 00 00       	mov    eax,0x0
   140002ca6:	eb 4e                	jmp    140002cf6 <_ValidateImageBase+0x76>
   140002ca8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cac:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002caf:	48 63 d0             	movsxd rdx,eax
   140002cb2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cb6:	48 01 d0             	add    rax,rdx
   140002cb9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002cbd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002cc1:	8b 00                	mov    eax,DWORD PTR [rax]
   140002cc3:	3d 50 45 00 00       	cmp    eax,0x4550
   140002cc8:	74 07                	je     140002cd1 <_ValidateImageBase+0x51>
   140002cca:	b8 00 00 00 00       	mov    eax,0x0
   140002ccf:	eb 25                	jmp    140002cf6 <_ValidateImageBase+0x76>
   140002cd1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002cd5:	48 83 c0 18          	add    rax,0x18
   140002cd9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002cdd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ce1:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002ce4:	66 3d 0b 02          	cmp    ax,0x20b
   140002ce8:	74 07                	je     140002cf1 <_ValidateImageBase+0x71>
   140002cea:	b8 00 00 00 00       	mov    eax,0x0
   140002cef:	eb 05                	jmp    140002cf6 <_ValidateImageBase+0x76>
   140002cf1:	b8 01 00 00 00       	mov    eax,0x1
   140002cf6:	48 83 c4 20          	add    rsp,0x20
   140002cfa:	5d                   	pop    rbp
   140002cfb:	c3                   	ret

0000000140002cfc <_FindPESection>:
   140002cfc:	55                   	push   rbp
   140002cfd:	48 89 e5             	mov    rbp,rsp
   140002d00:	48 83 ec 20          	sub    rsp,0x20
   140002d04:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d08:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d0c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d10:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d13:	48 63 d0             	movsxd rdx,eax
   140002d16:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d1a:	48 01 d0             	add    rax,rdx
   140002d1d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d21:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d28:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d2c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d30:	0f b7 d0             	movzx  edx,ax
   140002d33:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d37:	48 01 d0             	add    rax,rdx
   140002d3a:	48 83 c0 18          	add    rax,0x18
   140002d3e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d42:	eb 36                	jmp    140002d7a <_FindPESection+0x7e>
   140002d44:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d48:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d4b:	89 c0                	mov    eax,eax
   140002d4d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d51:	72 1e                	jb     140002d71 <_FindPESection+0x75>
   140002d53:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d57:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d5a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d5e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d61:	01 d0                	add    eax,edx
   140002d63:	89 c0                	mov    eax,eax
   140002d65:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d69:	73 06                	jae    140002d71 <_FindPESection+0x75>
   140002d6b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d6f:	eb 1e                	jmp    140002d8f <_FindPESection+0x93>
   140002d71:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d75:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d7a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d7e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d82:	0f b7 c0             	movzx  eax,ax
   140002d85:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d88:	72 ba                	jb     140002d44 <_FindPESection+0x48>
   140002d8a:	b8 00 00 00 00       	mov    eax,0x0
   140002d8f:	48 83 c4 20          	add    rsp,0x20
   140002d93:	5d                   	pop    rbp
   140002d94:	c3                   	ret

0000000140002d95 <_FindPESectionByName>:
   140002d95:	55                   	push   rbp
   140002d96:	48 89 e5             	mov    rbp,rsp
   140002d99:	48 83 ec 40          	sub    rsp,0x40
   140002d9d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002da1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002da5:	48 89 c1             	mov    rcx,rax
   140002da8:	e8 2b 69 00 00       	call   1400096d8 <strlen>
   140002dad:	48 83 f8 08          	cmp    rax,0x8
   140002db1:	76 0a                	jbe    140002dbd <_FindPESectionByName+0x28>
   140002db3:	b8 00 00 00 00       	mov    eax,0x0
   140002db8:	e9 98 00 00 00       	jmp    140002e55 <_FindPESectionByName+0xc0>
   140002dbd:	48 8b 05 bc 87 00 00 	mov    rax,QWORD PTR [rip+0x87bc]        # 14000b580 <.refptr.__ImageBase>
   140002dc4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002dc8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dcc:	48 89 c1             	mov    rcx,rax
   140002dcf:	e8 ac fe ff ff       	call   140002c80 <_ValidateImageBase>
   140002dd4:	85 c0                	test   eax,eax
   140002dd6:	75 07                	jne    140002ddf <_FindPESectionByName+0x4a>
   140002dd8:	b8 00 00 00 00       	mov    eax,0x0
   140002ddd:	eb 76                	jmp    140002e55 <_FindPESectionByName+0xc0>
   140002ddf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002de3:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002de6:	48 63 d0             	movsxd rdx,eax
   140002de9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ded:	48 01 d0             	add    rax,rdx
   140002df0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002df4:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002dfb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dff:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e03:	0f b7 d0             	movzx  edx,ax
   140002e06:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e0a:	48 01 d0             	add    rax,rdx
   140002e0d:	48 83 c0 18          	add    rax,0x18
   140002e11:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e15:	eb 29                	jmp    140002e40 <_FindPESectionByName+0xab>
   140002e17:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e1b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e1f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e25:	48 89 c1             	mov    rcx,rax
   140002e28:	e8 b3 68 00 00       	call   1400096e0 <strncmp>
   140002e2d:	85 c0                	test   eax,eax
   140002e2f:	75 06                	jne    140002e37 <_FindPESectionByName+0xa2>
   140002e31:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e35:	eb 1e                	jmp    140002e55 <_FindPESectionByName+0xc0>
   140002e37:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e3b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e40:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e44:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e48:	0f b7 c0             	movzx  eax,ax
   140002e4b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e4e:	72 c7                	jb     140002e17 <_FindPESectionByName+0x82>
   140002e50:	b8 00 00 00 00       	mov    eax,0x0
   140002e55:	48 83 c4 40          	add    rsp,0x40
   140002e59:	5d                   	pop    rbp
   140002e5a:	c3                   	ret

0000000140002e5b <__mingw_GetSectionForAddress>:
   140002e5b:	55                   	push   rbp
   140002e5c:	48 89 e5             	mov    rbp,rsp
   140002e5f:	48 83 ec 30          	sub    rsp,0x30
   140002e63:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e67:	48 8b 05 12 87 00 00 	mov    rax,QWORD PTR [rip+0x8712]        # 14000b580 <.refptr.__ImageBase>
   140002e6e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e76:	48 89 c1             	mov    rcx,rax
   140002e79:	e8 02 fe ff ff       	call   140002c80 <_ValidateImageBase>
   140002e7e:	85 c0                	test   eax,eax
   140002e80:	75 07                	jne    140002e89 <__mingw_GetSectionForAddress+0x2e>
   140002e82:	b8 00 00 00 00       	mov    eax,0x0
   140002e87:	eb 1c                	jmp    140002ea5 <__mingw_GetSectionForAddress+0x4a>
   140002e89:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e8d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e91:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e95:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e99:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e9d:	48 89 c1             	mov    rcx,rax
   140002ea0:	e8 57 fe ff ff       	call   140002cfc <_FindPESection>
   140002ea5:	48 83 c4 30          	add    rsp,0x30
   140002ea9:	5d                   	pop    rbp
   140002eaa:	c3                   	ret

0000000140002eab <__mingw_GetSectionCount>:
   140002eab:	55                   	push   rbp
   140002eac:	48 89 e5             	mov    rbp,rsp
   140002eaf:	48 83 ec 30          	sub    rsp,0x30
   140002eb3:	48 8b 05 c6 86 00 00 	mov    rax,QWORD PTR [rip+0x86c6]        # 14000b580 <.refptr.__ImageBase>
   140002eba:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ebe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ec2:	48 89 c1             	mov    rcx,rax
   140002ec5:	e8 b6 fd ff ff       	call   140002c80 <_ValidateImageBase>
   140002eca:	85 c0                	test   eax,eax
   140002ecc:	75 07                	jne    140002ed5 <__mingw_GetSectionCount+0x2a>
   140002ece:	b8 00 00 00 00       	mov    eax,0x0
   140002ed3:	eb 20                	jmp    140002ef5 <__mingw_GetSectionCount+0x4a>
   140002ed5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ed9:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002edc:	48 63 d0             	movsxd rdx,eax
   140002edf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ee3:	48 01 d0             	add    rax,rdx
   140002ee6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002eea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002eee:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ef2:	0f b7 c0             	movzx  eax,ax
   140002ef5:	48 83 c4 30          	add    rsp,0x30
   140002ef9:	5d                   	pop    rbp
   140002efa:	c3                   	ret

0000000140002efb <_FindPESectionExec>:
   140002efb:	55                   	push   rbp
   140002efc:	48 89 e5             	mov    rbp,rsp
   140002eff:	48 83 ec 40          	sub    rsp,0x40
   140002f03:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f07:	48 8b 05 72 86 00 00 	mov    rax,QWORD PTR [rip+0x8672]        # 14000b580 <.refptr.__ImageBase>
   140002f0e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f12:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f16:	48 89 c1             	mov    rcx,rax
   140002f19:	e8 62 fd ff ff       	call   140002c80 <_ValidateImageBase>
   140002f1e:	85 c0                	test   eax,eax
   140002f20:	75 07                	jne    140002f29 <_FindPESectionExec+0x2e>
   140002f22:	b8 00 00 00 00       	mov    eax,0x0
   140002f27:	eb 78                	jmp    140002fa1 <_FindPESectionExec+0xa6>
   140002f29:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f2d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f30:	48 63 d0             	movsxd rdx,eax
   140002f33:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f37:	48 01 d0             	add    rax,rdx
   140002f3a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f3e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f45:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f49:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f4d:	0f b7 d0             	movzx  edx,ax
   140002f50:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f54:	48 01 d0             	add    rax,rdx
   140002f57:	48 83 c0 18          	add    rax,0x18
   140002f5b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f5f:	eb 2b                	jmp    140002f8c <_FindPESectionExec+0x91>
   140002f61:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f65:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f68:	25 00 00 00 20       	and    eax,0x20000000
   140002f6d:	85 c0                	test   eax,eax
   140002f6f:	74 12                	je     140002f83 <_FindPESectionExec+0x88>
   140002f71:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f76:	75 06                	jne    140002f7e <_FindPESectionExec+0x83>
   140002f78:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f7c:	eb 23                	jmp    140002fa1 <_FindPESectionExec+0xa6>
   140002f7e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f83:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f87:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f8c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f90:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f94:	0f b7 c0             	movzx  eax,ax
   140002f97:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f9a:	72 c5                	jb     140002f61 <_FindPESectionExec+0x66>
   140002f9c:	b8 00 00 00 00       	mov    eax,0x0
   140002fa1:	48 83 c4 40          	add    rsp,0x40
   140002fa5:	5d                   	pop    rbp
   140002fa6:	c3                   	ret

0000000140002fa7 <_GetPEImageBase>:
   140002fa7:	55                   	push   rbp
   140002fa8:	48 89 e5             	mov    rbp,rsp
   140002fab:	48 83 ec 30          	sub    rsp,0x30
   140002faf:	48 8b 05 ca 85 00 00 	mov    rax,QWORD PTR [rip+0x85ca]        # 14000b580 <.refptr.__ImageBase>
   140002fb6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fbe:	48 89 c1             	mov    rcx,rax
   140002fc1:	e8 ba fc ff ff       	call   140002c80 <_ValidateImageBase>
   140002fc6:	85 c0                	test   eax,eax
   140002fc8:	75 07                	jne    140002fd1 <_GetPEImageBase+0x2a>
   140002fca:	b8 00 00 00 00       	mov    eax,0x0
   140002fcf:	eb 04                	jmp    140002fd5 <_GetPEImageBase+0x2e>
   140002fd1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fd5:	48 83 c4 30          	add    rsp,0x30
   140002fd9:	5d                   	pop    rbp
   140002fda:	c3                   	ret

0000000140002fdb <_IsNonwritableInCurrentImage>:
   140002fdb:	55                   	push   rbp
   140002fdc:	48 89 e5             	mov    rbp,rsp
   140002fdf:	48 83 ec 40          	sub    rsp,0x40
   140002fe3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002fe7:	48 8b 05 92 85 00 00 	mov    rax,QWORD PTR [rip+0x8592]        # 14000b580 <.refptr.__ImageBase>
   140002fee:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ff2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ff6:	48 89 c1             	mov    rcx,rax
   140002ff9:	e8 82 fc ff ff       	call   140002c80 <_ValidateImageBase>
   140002ffe:	85 c0                	test   eax,eax
   140003000:	75 07                	jne    140003009 <_IsNonwritableInCurrentImage+0x2e>
   140003002:	b8 00 00 00 00       	mov    eax,0x0
   140003007:	eb 3d                	jmp    140003046 <_IsNonwritableInCurrentImage+0x6b>
   140003009:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000300d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003011:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003015:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003019:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000301d:	48 89 c1             	mov    rcx,rax
   140003020:	e8 d7 fc ff ff       	call   140002cfc <_FindPESection>
   140003025:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003029:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000302e:	75 07                	jne    140003037 <_IsNonwritableInCurrentImage+0x5c>
   140003030:	b8 00 00 00 00       	mov    eax,0x0
   140003035:	eb 0f                	jmp    140003046 <_IsNonwritableInCurrentImage+0x6b>
   140003037:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000303b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000303e:	f7 d0                	not    eax
   140003040:	c1 e8 1f             	shr    eax,0x1f
   140003043:	0f b6 c0             	movzx  eax,al
   140003046:	48 83 c4 40          	add    rsp,0x40
   14000304a:	5d                   	pop    rbp
   14000304b:	c3                   	ret

000000014000304c <__mingw_enum_import_library_names>:
   14000304c:	55                   	push   rbp
   14000304d:	48 89 e5             	mov    rbp,rsp
   140003050:	48 83 ec 50          	sub    rsp,0x50
   140003054:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003057:	48 8b 05 22 85 00 00 	mov    rax,QWORD PTR [rip+0x8522]        # 14000b580 <.refptr.__ImageBase>
   14000305e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003062:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003066:	48 89 c1             	mov    rcx,rax
   140003069:	e8 12 fc ff ff       	call   140002c80 <_ValidateImageBase>
   14000306e:	85 c0                	test   eax,eax
   140003070:	75 0a                	jne    14000307c <__mingw_enum_import_library_names+0x30>
   140003072:	b8 00 00 00 00       	mov    eax,0x0
   140003077:	e9 ab 00 00 00       	jmp    140003127 <__mingw_enum_import_library_names+0xdb>
   14000307c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003080:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003083:	48 63 d0             	movsxd rdx,eax
   140003086:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000308a:	48 01 d0             	add    rax,rdx
   14000308d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003091:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003095:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000309b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000309e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400030a2:	75 07                	jne    1400030ab <__mingw_enum_import_library_names+0x5f>
   1400030a4:	b8 00 00 00 00       	mov    eax,0x0
   1400030a9:	eb 7c                	jmp    140003127 <__mingw_enum_import_library_names+0xdb>
   1400030ab:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030ae:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030b2:	48 89 c1             	mov    rcx,rax
   1400030b5:	e8 42 fc ff ff       	call   140002cfc <_FindPESection>
   1400030ba:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400030be:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   1400030c3:	75 07                	jne    1400030cc <__mingw_enum_import_library_names+0x80>
   1400030c5:	b8 00 00 00 00       	mov    eax,0x0
   1400030ca:	eb 5b                	jmp    140003127 <__mingw_enum_import_library_names+0xdb>
   1400030cc:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030cf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030d3:	48 01 d0             	add    rax,rdx
   1400030d6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030da:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400030df:	75 07                	jne    1400030e8 <__mingw_enum_import_library_names+0x9c>
   1400030e1:	b8 00 00 00 00       	mov    eax,0x0
   1400030e6:	eb 3f                	jmp    140003127 <__mingw_enum_import_library_names+0xdb>
   1400030e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030ec:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400030ef:	85 c0                	test   eax,eax
   1400030f1:	75 0b                	jne    1400030fe <__mingw_enum_import_library_names+0xb2>
   1400030f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400030f7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400030fa:	85 c0                	test   eax,eax
   1400030fc:	74 23                	je     140003121 <__mingw_enum_import_library_names+0xd5>
   1400030fe:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003102:	7f 12                	jg     140003116 <__mingw_enum_import_library_names+0xca>
   140003104:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003108:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000310b:	89 c2                	mov    edx,eax
   14000310d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003111:	48 01 d0             	add    rax,rdx
   140003114:	eb 11                	jmp    140003127 <__mingw_enum_import_library_names+0xdb>
   140003116:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000311a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000311f:	eb c7                	jmp    1400030e8 <__mingw_enum_import_library_names+0x9c>
   140003121:	90                   	nop
   140003122:	b8 00 00 00 00       	mov    eax,0x0
   140003127:	48 83 c4 50          	add    rsp,0x50
   14000312b:	5d                   	pop    rbp
   14000312c:	c3                   	ret
   14000312d:	90                   	nop
   14000312e:	90                   	nop
   14000312f:	90                   	nop

0000000140003130 <___chkstk_ms>:
   140003130:	51                   	push   rcx
   140003131:	50                   	push   rax
   140003132:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003138:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000313d:	72 19                	jb     140003158 <___chkstk_ms+0x28>
   14000313f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003146:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000314a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003150:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003156:	77 e7                	ja     14000313f <___chkstk_ms+0xf>
   140003158:	48 29 c1             	sub    rcx,rax
   14000315b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000315f:	58                   	pop    rax
   140003160:	59                   	pop    rcx
   140003161:	c3                   	ret
   140003162:	90                   	nop
   140003163:	90                   	nop
   140003164:	90                   	nop
   140003165:	90                   	nop
   140003166:	90                   	nop
   140003167:	90                   	nop
   140003168:	90                   	nop
   140003169:	90                   	nop
   14000316a:	90                   	nop
   14000316b:	90                   	nop
   14000316c:	90                   	nop
   14000316d:	90                   	nop
   14000316e:	90                   	nop
   14000316f:	90                   	nop

0000000140003170 <__mingw_printf>:
   140003170:	55                   	push   rbp
   140003171:	53                   	push   rbx
   140003172:	48 83 ec 48          	sub    rsp,0x48
   140003176:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   14000317b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000317f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140003183:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003187:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   14000318b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   14000318f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003193:	b9 01 00 00 00       	mov    ecx,0x1
   140003198:	e8 c3 5e 00 00       	call   140009060 <__acrt_iob_func>
   14000319d:	48 89 c1             	mov    rcx,rax
   1400031a0:	e8 3b 5d 00 00       	call   140008ee0 <_lock_file>
   1400031a5:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   1400031a9:	b9 01 00 00 00       	mov    ecx,0x1
   1400031ae:	e8 ad 5e 00 00       	call   140009060 <__acrt_iob_func>
   1400031b3:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400031b7:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
   1400031bc:	49 89 d1             	mov    r9,rdx
   1400031bf:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400031c5:	48 89 c2             	mov    rdx,rax
   1400031c8:	b9 00 60 00 00       	mov    ecx,0x6000
   1400031cd:	e8 b1 1f 00 00       	call   140005183 <__mingw_pformat>
   1400031d2:	89 c3                	mov    ebx,eax
   1400031d4:	b9 01 00 00 00       	mov    ecx,0x1
   1400031d9:	e8 82 5e 00 00       	call   140009060 <__acrt_iob_func>
   1400031de:	48 89 c1             	mov    rcx,rax
   1400031e1:	e8 84 5d 00 00       	call   140008f6a <_unlock_file>
   1400031e6:	89 d8                	mov    eax,ebx
   1400031e8:	48 83 c4 48          	add    rsp,0x48
   1400031ec:	5b                   	pop    rbx
   1400031ed:	5d                   	pop    rbp
   1400031ee:	c3                   	ret
   1400031ef:	90                   	nop

00000001400031f0 <__pformat_putc>:
   1400031f0:	55                   	push   rbp
   1400031f1:	48 89 e5             	mov    rbp,rsp
   1400031f4:	48 83 ec 20          	sub    rsp,0x20
   1400031f8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400031fb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400031ff:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003203:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003206:	25 00 40 00 00       	and    eax,0x4000
   14000320b:	85 c0                	test   eax,eax
   14000320d:	75 12                	jne    140003221 <__pformat_putc+0x31>
   14000320f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003213:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   140003216:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000321a:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000321d:	39 c2                	cmp    edx,eax
   14000321f:	7e 3b                	jle    14000325c <__pformat_putc+0x6c>
   140003221:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003225:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003228:	25 00 20 00 00       	and    eax,0x2000
   14000322d:	85 c0                	test   eax,eax
   14000322f:	74 13                	je     140003244 <__pformat_putc+0x54>
   140003231:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003235:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003238:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000323b:	89 c1                	mov    ecx,eax
   14000323d:	e8 56 64 00 00       	call   140009698 <fputc>
   140003242:	eb 18                	jmp    14000325c <__pformat_putc+0x6c>
   140003244:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003248:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   14000324b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000324f:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003252:	48 98                	cdqe
   140003254:	48 01 d0             	add    rax,rdx
   140003257:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   14000325a:	88 10                	mov    BYTE PTR [rax],dl
   14000325c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003260:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003263:	8d 50 01             	lea    edx,[rax+0x1]
   140003266:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000326a:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   14000326d:	90                   	nop
   14000326e:	48 83 c4 20          	add    rsp,0x20
   140003272:	5d                   	pop    rbp
   140003273:	c3                   	ret

0000000140003274 <__pformat_putchars>:
   140003274:	55                   	push   rbp
   140003275:	48 89 e5             	mov    rbp,rsp
   140003278:	48 83 ec 20          	sub    rsp,0x20
   14000327c:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003280:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003283:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003287:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000328b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000328e:	85 c0                	test   eax,eax
   140003290:	78 16                	js     1400032a8 <__pformat_putchars+0x34>
   140003292:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003296:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003299:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000329c:	7e 0a                	jle    1400032a8 <__pformat_putchars+0x34>
   14000329e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032a2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032a5:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400032a8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032ac:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032af:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400032b2:	7d 15                	jge    1400032c9 <__pformat_putchars+0x55>
   1400032b4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032b8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032bb:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400032be:	89 c2                	mov    edx,eax
   1400032c0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032c4:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400032c7:	eb 0b                	jmp    1400032d4 <__pformat_putchars+0x60>
   1400032c9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032cd:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400032d4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032d8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032db:	85 c0                	test   eax,eax
   1400032dd:	7e 57                	jle    140003336 <__pformat_putchars+0xc2>
   1400032df:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032e3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400032e6:	25 00 04 00 00       	and    eax,0x400
   1400032eb:	85 c0                	test   eax,eax
   1400032ed:	75 47                	jne    140003336 <__pformat_putchars+0xc2>
   1400032ef:	eb 11                	jmp    140003302 <__pformat_putchars+0x8e>
   1400032f1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032f5:	48 89 c2             	mov    rdx,rax
   1400032f8:	b9 20 00 00 00       	mov    ecx,0x20
   1400032fd:	e8 ee fe ff ff       	call   1400031f0 <__pformat_putc>
   140003302:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003306:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003309:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000330c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003310:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003313:	85 c0                	test   eax,eax
   140003315:	75 da                	jne    1400032f1 <__pformat_putchars+0x7d>
   140003317:	eb 1d                	jmp    140003336 <__pformat_putchars+0xc2>
   140003319:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000331d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003321:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003325:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003328:	0f be c0             	movsx  eax,al
   14000332b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000332f:	89 c1                	mov    ecx,eax
   140003331:	e8 ba fe ff ff       	call   1400031f0 <__pformat_putc>
   140003336:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003339:	8d 50 ff             	lea    edx,[rax-0x1]
   14000333c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000333f:	85 c0                	test   eax,eax
   140003341:	75 d6                	jne    140003319 <__pformat_putchars+0xa5>
   140003343:	eb 11                	jmp    140003356 <__pformat_putchars+0xe2>
   140003345:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003349:	48 89 c2             	mov    rdx,rax
   14000334c:	b9 20 00 00 00       	mov    ecx,0x20
   140003351:	e8 9a fe ff ff       	call   1400031f0 <__pformat_putc>
   140003356:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000335a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000335d:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003360:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003364:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003367:	85 c0                	test   eax,eax
   140003369:	7f da                	jg     140003345 <__pformat_putchars+0xd1>
   14000336b:	90                   	nop
   14000336c:	90                   	nop
   14000336d:	48 83 c4 20          	add    rsp,0x20
   140003371:	5d                   	pop    rbp
   140003372:	c3                   	ret

0000000140003373 <__pformat_puts>:
   140003373:	55                   	push   rbp
   140003374:	48 89 e5             	mov    rbp,rsp
   140003377:	48 83 ec 20          	sub    rsp,0x20
   14000337b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000337f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003383:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140003388:	75 0b                	jne    140003395 <__pformat_puts+0x22>
   14000338a:	48 8d 05 9f 7f 00 00 	lea    rax,[rip+0x7f9f]        # 14000b330 <.rdata>
   140003391:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003395:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003399:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000339c:	85 c0                	test   eax,eax
   14000339e:	78 2f                	js     1400033cf <__pformat_puts+0x5c>
   1400033a0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400033a4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033a7:	48 63 d0             	movsxd rdx,eax
   1400033aa:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033ae:	48 89 c1             	mov    rcx,rax
   1400033b1:	e8 4a 5a 00 00       	call   140008e00 <strnlen>
   1400033b6:	89 c1                	mov    ecx,eax
   1400033b8:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400033bc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033c0:	49 89 d0             	mov    r8,rdx
   1400033c3:	89 ca                	mov    edx,ecx
   1400033c5:	48 89 c1             	mov    rcx,rax
   1400033c8:	e8 a7 fe ff ff       	call   140003274 <__pformat_putchars>
   1400033cd:	eb 23                	jmp    1400033f2 <__pformat_puts+0x7f>
   1400033cf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033d3:	48 89 c1             	mov    rcx,rax
   1400033d6:	e8 fd 62 00 00       	call   1400096d8 <strlen>
   1400033db:	89 c1                	mov    ecx,eax
   1400033dd:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400033e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033e5:	49 89 d0             	mov    r8,rdx
   1400033e8:	89 ca                	mov    edx,ecx
   1400033ea:	48 89 c1             	mov    rcx,rax
   1400033ed:	e8 82 fe ff ff       	call   140003274 <__pformat_putchars>
   1400033f2:	90                   	nop
   1400033f3:	48 83 c4 20          	add    rsp,0x20
   1400033f7:	5d                   	pop    rbp
   1400033f8:	c3                   	ret

00000001400033f9 <__pformat_wputchars>:
   1400033f9:	55                   	push   rbp
   1400033fa:	48 89 e5             	mov    rbp,rsp
   1400033fd:	48 83 ec 50          	sub    rsp,0x50
   140003401:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003405:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003408:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000340c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   140003413:	00 
   140003414:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003418:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000341b:	85 c0                	test   eax,eax
   14000341d:	78 16                	js     140003435 <__pformat_wputchars+0x3c>
   14000341f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003423:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003426:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003429:	7e 0a                	jle    140003435 <__pformat_wputchars+0x3c>
   14000342b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000342f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003432:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003435:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003439:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000343c:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000343f:	7d 15                	jge    140003456 <__pformat_wputchars+0x5d>
   140003441:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003445:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003448:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000344b:	89 c2                	mov    edx,eax
   14000344d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003451:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003454:	eb 0b                	jmp    140003461 <__pformat_wputchars+0x68>
   140003456:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000345a:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003461:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003465:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003468:	85 c0                	test   eax,eax
   14000346a:	7e 6e                	jle    1400034da <__pformat_wputchars+0xe1>
   14000346c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003470:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003473:	25 00 04 00 00       	and    eax,0x400
   140003478:	85 c0                	test   eax,eax
   14000347a:	75 5e                	jne    1400034da <__pformat_wputchars+0xe1>
   14000347c:	eb 11                	jmp    14000348f <__pformat_wputchars+0x96>
   14000347e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003482:	48 89 c2             	mov    rdx,rax
   140003485:	b9 20 00 00 00       	mov    ecx,0x20
   14000348a:	e8 61 fd ff ff       	call   1400031f0 <__pformat_putc>
   14000348f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003493:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003496:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003499:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000349d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400034a0:	85 c0                	test   eax,eax
   1400034a2:	75 da                	jne    14000347e <__pformat_wputchars+0x85>
   1400034a4:	eb 34                	jmp    1400034da <__pformat_wputchars+0xe1>
   1400034a6:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400034aa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400034ae:	eb 1d                	jmp    1400034cd <__pformat_wputchars+0xd4>
   1400034b0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400034b4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400034b8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400034bc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400034bf:	0f be c0             	movsx  eax,al
   1400034c2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034c6:	89 c1                	mov    ecx,eax
   1400034c8:	e8 23 fd ff ff       	call   1400031f0 <__pformat_putc>
   1400034cd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400034d0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400034d3:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   1400034d6:	85 c0                	test   eax,eax
   1400034d8:	7f d6                	jg     1400034b0 <__pformat_wputchars+0xb7>
   1400034da:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400034dd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400034e0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400034e3:	85 c0                	test   eax,eax
   1400034e5:	7e 41                	jle    140003528 <__pformat_wputchars+0x12f>
   1400034e7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400034eb:	48 8d 50 02          	lea    rdx,[rax+0x2]
   1400034ef:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   1400034f3:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400034f6:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   1400034fa:	0f b7 d0             	movzx  edx,ax
   1400034fd:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003501:	49 89 c8             	mov    r8,rcx
   140003504:	48 89 c1             	mov    rcx,rax
   140003507:	e8 84 5b 00 00       	call   140009090 <wcrtomb>
   14000350c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000350f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003513:	7f 91                	jg     1400034a6 <__pformat_wputchars+0xad>
   140003515:	eb 11                	jmp    140003528 <__pformat_wputchars+0x12f>
   140003517:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000351b:	48 89 c2             	mov    rdx,rax
   14000351e:	b9 20 00 00 00       	mov    ecx,0x20
   140003523:	e8 c8 fc ff ff       	call   1400031f0 <__pformat_putc>
   140003528:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000352c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000352f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003532:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003536:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003539:	85 c0                	test   eax,eax
   14000353b:	7f da                	jg     140003517 <__pformat_wputchars+0x11e>
   14000353d:	90                   	nop
   14000353e:	90                   	nop
   14000353f:	48 83 c4 50          	add    rsp,0x50
   140003543:	5d                   	pop    rbp
   140003544:	c3                   	ret

0000000140003545 <__pformat_wcputs>:
   140003545:	55                   	push   rbp
   140003546:	48 89 e5             	mov    rbp,rsp
   140003549:	48 83 ec 20          	sub    rsp,0x20
   14000354d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003551:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003555:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000355a:	75 0b                	jne    140003567 <__pformat_wcputs+0x22>
   14000355c:	48 8d 05 d5 7d 00 00 	lea    rax,[rip+0x7dd5]        # 14000b338 <.rdata+0x8>
   140003563:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003567:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000356b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000356e:	85 c0                	test   eax,eax
   140003570:	78 2f                	js     1400035a1 <__pformat_wcputs+0x5c>
   140003572:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003576:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003579:	48 63 d0             	movsxd rdx,eax
   14000357c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003580:	48 89 c1             	mov    rcx,rax
   140003583:	e8 28 58 00 00       	call   140008db0 <wcsnlen>
   140003588:	89 c1                	mov    ecx,eax
   14000358a:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000358e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003592:	49 89 d0             	mov    r8,rdx
   140003595:	89 ca                	mov    edx,ecx
   140003597:	48 89 c1             	mov    rcx,rax
   14000359a:	e8 5a fe ff ff       	call   1400033f9 <__pformat_wputchars>
   14000359f:	eb 23                	jmp    1400035c4 <__pformat_wcputs+0x7f>
   1400035a1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035a5:	48 89 c1             	mov    rcx,rax
   1400035a8:	e8 43 61 00 00       	call   1400096f0 <wcslen>
   1400035ad:	89 c1                	mov    ecx,eax
   1400035af:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400035b3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035b7:	49 89 d0             	mov    r8,rdx
   1400035ba:	89 ca                	mov    edx,ecx
   1400035bc:	48 89 c1             	mov    rcx,rax
   1400035bf:	e8 35 fe ff ff       	call   1400033f9 <__pformat_wputchars>
   1400035c4:	90                   	nop
   1400035c5:	48 83 c4 20          	add    rsp,0x20
   1400035c9:	5d                   	pop    rbp
   1400035ca:	c3                   	ret

00000001400035cb <__pformat_int_bufsiz>:
   1400035cb:	55                   	push   rbp
   1400035cc:	48 89 e5             	mov    rbp,rsp
   1400035cf:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400035d2:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400035d5:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400035d9:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035dc:	83 e8 01             	sub    eax,0x1
   1400035df:	48 98                	cdqe
   1400035e1:	48 83 c0 40          	add    rax,0x40
   1400035e5:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400035e8:	48 63 ca             	movsxd rcx,edx
   1400035eb:	ba 00 00 00 00       	mov    edx,0x0
   1400035f0:	48 f7 f1             	div    rcx
   1400035f3:	89 c2                	mov    edx,eax
   1400035f5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400035f8:	01 d0                	add    eax,edx
   1400035fa:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400035fd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003601:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003604:	ba 00 00 00 00       	mov    edx,0x0
   140003609:	85 c0                	test   eax,eax
   14000360b:	0f 48 c2             	cmovs  eax,edx
   14000360e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   140003611:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003615:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003618:	25 00 10 00 00       	and    eax,0x1000
   14000361d:	85 c0                	test   eax,eax
   14000361f:	74 29                	je     14000364a <__pformat_int_bufsiz+0x7f>
   140003621:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003625:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003629:	66 85 c0             	test   ax,ax
   14000362c:	74 1c                	je     14000364a <__pformat_int_bufsiz+0x7f>
   14000362e:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003631:	48 63 d0             	movsxd rdx,eax
   140003634:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   14000363b:	48 89 d1             	mov    rcx,rdx
   14000363e:	48 c1 e9 20          	shr    rcx,0x20
   140003642:	99                   	cdq
   140003643:	89 c8                	mov    eax,ecx
   140003645:	29 d0                	sub    eax,edx
   140003647:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   14000364a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000364e:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140003651:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003654:	39 c2                	cmp    edx,eax
   140003656:	0f 4d c2             	cmovge eax,edx
   140003659:	5d                   	pop    rbp
   14000365a:	c3                   	ret

000000014000365b <__pformat_int>:
   14000365b:	55                   	push   rbp
   14000365c:	53                   	push   rbx
   14000365d:	48 83 ec 58          	sub    rsp,0x58
   140003661:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003666:	48 89 cb             	mov    rbx,rcx
   140003669:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   14000366c:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   140003670:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   140003674:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   140003678:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000367c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003680:	49 89 c0             	mov    r8,rax
   140003683:	ba 03 00 00 00       	mov    edx,0x3
   140003688:	b9 01 00 00 00       	mov    ecx,0x1
   14000368d:	e8 39 ff ff ff       	call   1400035cb <__pformat_int_bufsiz>
   140003692:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140003695:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   14000369c:	00 
   14000369d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400036a0:	48 98                	cdqe
   1400036a2:	48 83 c0 0f          	add    rax,0xf
   1400036a6:	48 c1 e8 04          	shr    rax,0x4
   1400036aa:	48 c1 e0 04          	shl    rax,0x4
   1400036ae:	e8 7d fa ff ff       	call   140003130 <___chkstk_ms>
   1400036b3:	48 29 c4             	sub    rsp,rax
   1400036b6:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400036bb:	48 83 c0 0f          	add    rax,0xf
   1400036bf:	48 c1 e8 04          	shr    rax,0x4
   1400036c3:	48 c1 e0 04          	shl    rax,0x4
   1400036c7:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400036cb:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400036cf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400036d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036d7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400036da:	25 80 00 00 00       	and    eax,0x80
   1400036df:	85 c0                	test   eax,eax
   1400036e1:	0f 84 ea 00 00 00    	je     1400037d1 <__pformat_int+0x176>
   1400036e7:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400036eb:	48 85 c0             	test   rax,rax
   1400036ee:	79 10                	jns    140003700 <__pformat_int+0xa5>
   1400036f0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400036f4:	48 f7 d8             	neg    rax
   1400036f7:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400036fb:	e9 d1 00 00 00       	jmp    1400037d1 <__pformat_int+0x176>
   140003700:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003704:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003707:	24 7f                	and    al,0x7f
   140003709:	89 c2                	mov    edx,eax
   14000370b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000370f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003712:	e9 ba 00 00 00       	jmp    1400037d1 <__pformat_int+0x176>
   140003717:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000371b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000371f:	74 54                	je     140003775 <__pformat_int+0x11a>
   140003721:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003725:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003728:	25 00 10 00 00       	and    eax,0x1000
   14000372d:	85 c0                	test   eax,eax
   14000372f:	74 44                	je     140003775 <__pformat_int+0x11a>
   140003731:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003735:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003739:	66 85 c0             	test   ax,ax
   14000373c:	74 37                	je     140003775 <__pformat_int+0x11a>
   14000373e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003742:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   140003746:	48 89 c2             	mov    rdx,rax
   140003749:	48 89 d0             	mov    rax,rdx
   14000374c:	48 c1 f8 3f          	sar    rax,0x3f
   140003750:	48 c1 e8 3e          	shr    rax,0x3e
   140003754:	48 01 c2             	add    rdx,rax
   140003757:	83 e2 03             	and    edx,0x3
   14000375a:	48 29 c2             	sub    rdx,rax
   14000375d:	48 89 d0             	mov    rax,rdx
   140003760:	48 83 f8 03          	cmp    rax,0x3
   140003764:	75 0f                	jne    140003775 <__pformat_int+0x11a>
   140003766:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000376a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000376e:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003772:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   140003775:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   140003779:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003780:	cc cc cc 
   140003783:	48 89 c8             	mov    rax,rcx
   140003786:	48 f7 e2             	mul    rdx
   140003789:	48 c1 ea 03          	shr    rdx,0x3
   14000378d:	48 89 d0             	mov    rax,rdx
   140003790:	48 c1 e0 02          	shl    rax,0x2
   140003794:	48 01 d0             	add    rax,rdx
   140003797:	48 01 c0             	add    rax,rax
   14000379a:	48 29 c1             	sub    rcx,rax
   14000379d:	48 89 ca             	mov    rdx,rcx
   1400037a0:	89 d0                	mov    eax,edx
   1400037a2:	8d 48 30             	lea    ecx,[rax+0x30]
   1400037a5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037a9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037ad:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037b1:	89 ca                	mov    edx,ecx
   1400037b3:	88 10                	mov    BYTE PTR [rax],dl
   1400037b5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400037b9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400037c0:	cc cc cc 
   1400037c3:	48 f7 e2             	mul    rdx
   1400037c6:	48 89 d0             	mov    rax,rdx
   1400037c9:	48 c1 e8 03          	shr    rax,0x3
   1400037cd:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400037d1:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400037d5:	48 85 c0             	test   rax,rax
   1400037d8:	0f 85 39 ff ff ff    	jne    140003717 <__pformat_int+0xbc>
   1400037de:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037e2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400037e5:	85 c0                	test   eax,eax
   1400037e7:	7e 3e                	jle    140003827 <__pformat_int+0x1cc>
   1400037e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037ed:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400037f0:	89 c1                	mov    ecx,eax
   1400037f2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037f6:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400037fa:	89 c2                	mov    edx,eax
   1400037fc:	89 c8                	mov    eax,ecx
   1400037fe:	29 d0                	sub    eax,edx
   140003800:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003803:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003807:	7e 1e                	jle    140003827 <__pformat_int+0x1cc>
   140003809:	eb 0f                	jmp    14000381a <__pformat_int+0x1bf>
   14000380b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000380f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003813:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003817:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000381a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000381d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003820:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   140003823:	85 c0                	test   eax,eax
   140003825:	7f e4                	jg     14000380b <__pformat_int+0x1b0>
   140003827:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000382b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000382f:	75 1a                	jne    14000384b <__pformat_int+0x1f0>
   140003831:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003835:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003838:	85 c0                	test   eax,eax
   14000383a:	74 0f                	je     14000384b <__pformat_int+0x1f0>
   14000383c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003840:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003844:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003848:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000384b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000384f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003852:	85 c0                	test   eax,eax
   140003854:	0f 8e ce 00 00 00    	jle    140003928 <__pformat_int+0x2cd>
   14000385a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000385e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003861:	89 c1                	mov    ecx,eax
   140003863:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003867:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000386b:	89 c2                	mov    edx,eax
   14000386d:	89 c8                	mov    eax,ecx
   14000386f:	29 d0                	sub    eax,edx
   140003871:	89 c2                	mov    edx,eax
   140003873:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003877:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000387a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000387e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003881:	85 c0                	test   eax,eax
   140003883:	0f 8e 9f 00 00 00    	jle    140003928 <__pformat_int+0x2cd>
   140003889:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000388d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003890:	25 c0 01 00 00       	and    eax,0x1c0
   140003895:	85 c0                	test   eax,eax
   140003897:	74 11                	je     1400038aa <__pformat_int+0x24f>
   140003899:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000389d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038a0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400038a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038a7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400038aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ae:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400038b1:	85 c0                	test   eax,eax
   1400038b3:	79 3b                	jns    1400038f0 <__pformat_int+0x295>
   1400038b5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038b9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038bc:	25 00 06 00 00       	and    eax,0x600
   1400038c1:	3d 00 02 00 00       	cmp    eax,0x200
   1400038c6:	75 28                	jne    1400038f0 <__pformat_int+0x295>
   1400038c8:	eb 0f                	jmp    1400038d9 <__pformat_int+0x27e>
   1400038ca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038ce:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038d2:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038d6:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400038d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038dd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038e0:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400038e3:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400038e7:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400038ea:	85 c0                	test   eax,eax
   1400038ec:	7f dc                	jg     1400038ca <__pformat_int+0x26f>
   1400038ee:	eb 38                	jmp    140003928 <__pformat_int+0x2cd>
   1400038f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038f4:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038f7:	25 00 04 00 00       	and    eax,0x400
   1400038fc:	85 c0                	test   eax,eax
   1400038fe:	75 28                	jne    140003928 <__pformat_int+0x2cd>
   140003900:	eb 11                	jmp    140003913 <__pformat_int+0x2b8>
   140003902:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003906:	48 89 c2             	mov    rdx,rax
   140003909:	b9 20 00 00 00       	mov    ecx,0x20
   14000390e:	e8 dd f8 ff ff       	call   1400031f0 <__pformat_putc>
   140003913:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003917:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000391a:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000391d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003921:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003924:	85 c0                	test   eax,eax
   140003926:	7f da                	jg     140003902 <__pformat_int+0x2a7>
   140003928:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000392c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000392f:	25 80 00 00 00       	and    eax,0x80
   140003934:	85 c0                	test   eax,eax
   140003936:	74 11                	je     140003949 <__pformat_int+0x2ee>
   140003938:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000393c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003940:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003944:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   140003947:	eb 5a                	jmp    1400039a3 <__pformat_int+0x348>
   140003949:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000394d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003950:	25 00 01 00 00       	and    eax,0x100
   140003955:	85 c0                	test   eax,eax
   140003957:	74 11                	je     14000396a <__pformat_int+0x30f>
   140003959:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000395d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003961:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003965:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140003968:	eb 39                	jmp    1400039a3 <__pformat_int+0x348>
   14000396a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000396e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003971:	83 e0 40             	and    eax,0x40
   140003974:	85 c0                	test   eax,eax
   140003976:	74 2b                	je     1400039a3 <__pformat_int+0x348>
   140003978:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000397c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003980:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003984:	c6 00 20             	mov    BYTE PTR [rax],0x20
   140003987:	eb 1a                	jmp    1400039a3 <__pformat_int+0x348>
   140003989:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   14000398e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003992:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003995:	0f be c0             	movsx  eax,al
   140003998:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000399c:	89 c1                	mov    ecx,eax
   14000399e:	e8 4d f8 ff ff       	call   1400031f0 <__pformat_putc>
   1400039a3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039a7:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   1400039ab:	72 dc                	jb     140003989 <__pformat_int+0x32e>
   1400039ad:	eb 11                	jmp    1400039c0 <__pformat_int+0x365>
   1400039af:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039b3:	48 89 c2             	mov    rdx,rax
   1400039b6:	b9 20 00 00 00       	mov    ecx,0x20
   1400039bb:	e8 30 f8 ff ff       	call   1400031f0 <__pformat_putc>
   1400039c0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039c4:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400039c7:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400039ca:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400039ce:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400039d1:	85 c0                	test   eax,eax
   1400039d3:	7f da                	jg     1400039af <__pformat_int+0x354>
   1400039d5:	90                   	nop
   1400039d6:	90                   	nop
   1400039d7:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   1400039db:	5b                   	pop    rbx
   1400039dc:	5d                   	pop    rbp
   1400039dd:	c3                   	ret

00000001400039de <__pformat_xint>:
   1400039de:	55                   	push   rbp
   1400039df:	53                   	push   rbx
   1400039e0:	48 83 ec 68          	sub    rsp,0x68
   1400039e4:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   1400039e9:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   1400039ec:	48 89 d3             	mov    rbx,rdx
   1400039ef:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   1400039f2:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   1400039f6:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400039fa:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400039fe:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003a02:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a06:	74 1e                	je     140003a26 <__pformat_xint+0x48>
   140003a08:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a0c:	74 06                	je     140003a14 <__pformat_xint+0x36>
   140003a0e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a12:	75 09                	jne    140003a1d <__pformat_xint+0x3f>
   140003a14:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003a1b:	eb 10                	jmp    140003a2d <__pformat_xint+0x4f>
   140003a1d:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003a24:	eb 07                	jmp    140003a2d <__pformat_xint+0x4f>
   140003a26:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140003a2d:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003a31:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003a34:	49 89 d0             	mov    r8,rdx
   140003a37:	89 c2                	mov    edx,eax
   140003a39:	b9 02 00 00 00       	mov    ecx,0x2
   140003a3e:	e8 88 fb ff ff       	call   1400035cb <__pformat_int_bufsiz>
   140003a43:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140003a46:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   140003a4d:	00 
   140003a4e:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140003a51:	48 98                	cdqe
   140003a53:	48 83 c0 0f          	add    rax,0xf
   140003a57:	48 c1 e8 04          	shr    rax,0x4
   140003a5b:	48 c1 e0 04          	shl    rax,0x4
   140003a5f:	e8 cc f6 ff ff       	call   140003130 <___chkstk_ms>
   140003a64:	48 29 c4             	sub    rsp,rax
   140003a67:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003a6c:	48 83 c0 0f          	add    rax,0xf
   140003a70:	48 c1 e8 04          	shr    rax,0x4
   140003a74:	48 c1 e0 04          	shl    rax,0x4
   140003a78:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140003a7c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003a80:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003a84:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a88:	74 1e                	je     140003aa8 <__pformat_xint+0xca>
   140003a8a:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a8e:	74 06                	je     140003a96 <__pformat_xint+0xb8>
   140003a90:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a94:	75 09                	jne    140003a9f <__pformat_xint+0xc1>
   140003a96:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003a9d:	eb 10                	jmp    140003aaf <__pformat_xint+0xd1>
   140003a9f:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003aa6:	eb 67                	jmp    140003b0f <__pformat_xint+0x131>
   140003aa8:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003aaf:	eb 5e                	jmp    140003b0f <__pformat_xint+0x131>
   140003ab1:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003ab5:	89 c2                	mov    edx,eax
   140003ab7:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003aba:	21 d0                	and    eax,edx
   140003abc:	8d 48 30             	lea    ecx,[rax+0x30]
   140003abf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ac3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ac7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003acb:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003acf:	89 ca                	mov    edx,ecx
   140003ad1:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003ad5:	88 10                	mov    BYTE PTR [rax],dl
   140003ad7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003adb:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003ade:	3c 39                	cmp    al,0x39
   140003ae0:	7e 1a                	jle    140003afc <__pformat_xint+0x11e>
   140003ae2:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003ae6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003ae9:	83 c0 07             	add    eax,0x7
   140003aec:	89 c2                	mov    edx,eax
   140003aee:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003af1:	83 e0 20             	and    eax,0x20
   140003af4:	09 c2                	or     edx,eax
   140003af6:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003afa:	88 10                	mov    BYTE PTR [rax],dl
   140003afc:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003b00:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003b03:	89 c1                	mov    ecx,eax
   140003b05:	48 d3 ea             	shr    rdx,cl
   140003b08:	48 89 d0             	mov    rax,rdx
   140003b0b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003b0f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003b13:	48 85 c0             	test   rax,rax
   140003b16:	75 99                	jne    140003ab1 <__pformat_xint+0xd3>
   140003b18:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b1c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b20:	75 13                	jne    140003b35 <__pformat_xint+0x157>
   140003b22:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b26:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b29:	80 e4 f7             	and    ah,0xf7
   140003b2c:	89 c2                	mov    edx,eax
   140003b2e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b32:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003b35:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b39:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b3c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b3f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b43:	7e 3a                	jle    140003b7f <__pformat_xint+0x1a1>
   140003b45:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003b48:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b4c:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003b50:	89 c1                	mov    ecx,eax
   140003b52:	89 d0                	mov    eax,edx
   140003b54:	29 c8                	sub    eax,ecx
   140003b56:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b59:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b5d:	7e 20                	jle    140003b7f <__pformat_xint+0x1a1>
   140003b5f:	eb 0f                	jmp    140003b70 <__pformat_xint+0x192>
   140003b61:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b65:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b69:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b6d:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b70:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003b73:	8d 50 ff             	lea    edx,[rax-0x1]
   140003b76:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b79:	85 c0                	test   eax,eax
   140003b7b:	7f e4                	jg     140003b61 <__pformat_xint+0x183>
   140003b7d:	eb 25                	jmp    140003ba4 <__pformat_xint+0x1c6>
   140003b7f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003b83:	75 1f                	jne    140003ba4 <__pformat_xint+0x1c6>
   140003b85:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b89:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b8c:	25 00 08 00 00       	and    eax,0x800
   140003b91:	85 c0                	test   eax,eax
   140003b93:	74 0f                	je     140003ba4 <__pformat_xint+0x1c6>
   140003b95:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b99:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b9d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003ba1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003ba4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ba8:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003bac:	75 1a                	jne    140003bc8 <__pformat_xint+0x1ea>
   140003bae:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bb2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003bb5:	85 c0                	test   eax,eax
   140003bb7:	74 0f                	je     140003bc8 <__pformat_xint+0x1ea>
   140003bb9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bbd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bc1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bc5:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bc8:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bcc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003bcf:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003bd3:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003bd7:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bda:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003bdd:	7d 15                	jge    140003bf4 <__pformat_xint+0x216>
   140003bdf:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003be3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003be6:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003be9:	89 c2                	mov    edx,eax
   140003beb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bef:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003bf2:	eb 0b                	jmp    140003bff <__pformat_xint+0x221>
   140003bf4:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bf8:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003bff:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c03:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c06:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003c09:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c0d:	7e 1a                	jle    140003c29 <__pformat_xint+0x24b>
   140003c0f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c13:	74 14                	je     140003c29 <__pformat_xint+0x24b>
   140003c15:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c19:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c1c:	25 00 08 00 00       	and    eax,0x800
   140003c21:	85 c0                	test   eax,eax
   140003c23:	74 04                	je     140003c29 <__pformat_xint+0x24b>
   140003c25:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003c29:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c2d:	7e 3c                	jle    140003c6b <__pformat_xint+0x28d>
   140003c2f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c33:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003c36:	85 c0                	test   eax,eax
   140003c38:	79 31                	jns    140003c6b <__pformat_xint+0x28d>
   140003c3a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c3e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c41:	25 00 06 00 00       	and    eax,0x600
   140003c46:	3d 00 02 00 00       	cmp    eax,0x200
   140003c4b:	75 1e                	jne    140003c6b <__pformat_xint+0x28d>
   140003c4d:	eb 0f                	jmp    140003c5e <__pformat_xint+0x280>
   140003c4f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c53:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c57:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c5b:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c5e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c61:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c64:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c67:	85 c0                	test   eax,eax
   140003c69:	7f e4                	jg     140003c4f <__pformat_xint+0x271>
   140003c6b:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c6f:	74 30                	je     140003ca1 <__pformat_xint+0x2c3>
   140003c71:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c75:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c78:	25 00 08 00 00       	and    eax,0x800
   140003c7d:	85 c0                	test   eax,eax
   140003c7f:	74 20                	je     140003ca1 <__pformat_xint+0x2c3>
   140003c81:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c85:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c89:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c8d:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003c90:	88 10                	mov    BYTE PTR [rax],dl
   140003c92:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c96:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c9a:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c9e:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003ca1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003ca5:	7e 4c                	jle    140003cf3 <__pformat_xint+0x315>
   140003ca7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cab:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003cae:	25 00 04 00 00       	and    eax,0x400
   140003cb3:	85 c0                	test   eax,eax
   140003cb5:	75 3c                	jne    140003cf3 <__pformat_xint+0x315>
   140003cb7:	eb 11                	jmp    140003cca <__pformat_xint+0x2ec>
   140003cb9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cbd:	48 89 c2             	mov    rdx,rax
   140003cc0:	b9 20 00 00 00       	mov    ecx,0x20
   140003cc5:	e8 26 f5 ff ff       	call   1400031f0 <__pformat_putc>
   140003cca:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ccd:	8d 50 ff             	lea    edx,[rax-0x1]
   140003cd0:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003cd3:	85 c0                	test   eax,eax
   140003cd5:	7f e2                	jg     140003cb9 <__pformat_xint+0x2db>
   140003cd7:	eb 1a                	jmp    140003cf3 <__pformat_xint+0x315>
   140003cd9:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003cde:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ce2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003ce5:	0f be c0             	movsx  eax,al
   140003ce8:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003cec:	89 c1                	mov    ecx,eax
   140003cee:	e8 fd f4 ff ff       	call   1400031f0 <__pformat_putc>
   140003cf3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cf7:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003cfb:	72 dc                	jb     140003cd9 <__pformat_xint+0x2fb>
   140003cfd:	eb 11                	jmp    140003d10 <__pformat_xint+0x332>
   140003cff:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d03:	48 89 c2             	mov    rdx,rax
   140003d06:	b9 20 00 00 00       	mov    ecx,0x20
   140003d0b:	e8 e0 f4 ff ff       	call   1400031f0 <__pformat_putc>
   140003d10:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d13:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d16:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d19:	85 c0                	test   eax,eax
   140003d1b:	7f e2                	jg     140003cff <__pformat_xint+0x321>
   140003d1d:	90                   	nop
   140003d1e:	90                   	nop
   140003d1f:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003d23:	5b                   	pop    rbx
   140003d24:	5d                   	pop    rbp
   140003d25:	c3                   	ret

0000000140003d26 <init_fpreg_ldouble>:
   140003d26:	55                   	push   rbp
   140003d27:	53                   	push   rbx
   140003d28:	48 83 ec 28          	sub    rsp,0x28
   140003d2c:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003d31:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003d35:	48 89 d3             	mov    rbx,rdx
   140003d38:	db 2b                	fld    TBYTE PTR [rbx]
   140003d3a:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003d3d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003d40:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003d43:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003d47:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d4b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003d4f:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003d52:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003d56:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003d5a:	48 83 c4 28          	add    rsp,0x28
   140003d5e:	5b                   	pop    rbx
   140003d5f:	5d                   	pop    rbp
   140003d60:	c3                   	ret

0000000140003d61 <__pformat_cvt>:
   140003d61:	55                   	push   rbp
   140003d62:	53                   	push   rbx
   140003d63:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003d6a:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003d71:	00 
   140003d72:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003d75:	48 89 d3             	mov    rbx,rdx
   140003d78:	db 2b                	fld    TBYTE PTR [rbx]
   140003d7a:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003d7d:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003d81:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003d85:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003d8c:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003d90:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003d93:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003d96:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003d9a:	48 89 c1             	mov    rcx,rax
   140003d9d:	e8 84 ff ff ff       	call   140003d26 <init_fpreg_ldouble>
   140003da2:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003da5:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003da8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003dac:	48 89 c1             	mov    rcx,rax
   140003daf:	e8 9c 4e 00 00       	call   140008c50 <__fpclassifyl>
   140003db4:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003db7:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003dba:	25 00 01 00 00       	and    eax,0x100
   140003dbf:	85 c0                	test   eax,eax
   140003dc1:	74 1d                	je     140003de0 <__pformat_cvt+0x7f>
   140003dc3:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003dc6:	25 00 04 00 00       	and    eax,0x400
   140003dcb:	85 c0                	test   eax,eax
   140003dcd:	74 07                	je     140003dd6 <__pformat_cvt+0x75>
   140003dcf:	b8 03 00 00 00       	mov    eax,0x3
   140003dd4:	eb 05                	jmp    140003ddb <__pformat_cvt+0x7a>
   140003dd6:	b8 04 00 00 00       	mov    eax,0x4
   140003ddb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003dde:	eb 4a                	jmp    140003e2a <__pformat_cvt+0xc9>
   140003de0:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003de3:	25 00 04 00 00       	and    eax,0x400
   140003de8:	85 c0                	test   eax,eax
   140003dea:	74 37                	je     140003e23 <__pformat_cvt+0xc2>
   140003dec:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003def:	25 00 40 00 00       	and    eax,0x4000
   140003df4:	85 c0                	test   eax,eax
   140003df6:	74 10                	je     140003e08 <__pformat_cvt+0xa7>
   140003df8:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003dff:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003e06:	eb 22                	jmp    140003e2a <__pformat_cvt+0xc9>
   140003e08:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003e0f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e13:	98                   	cwde
   140003e14:	25 ff 7f 00 00       	and    eax,0x7fff
   140003e19:	2d 3e 40 00 00       	sub    eax,0x403e
   140003e1e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003e21:	eb 07                	jmp    140003e2a <__pformat_cvt+0xc9>
   140003e23:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003e2a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e2d:	83 f8 04             	cmp    eax,0x4
   140003e30:	74 0e                	je     140003e40 <__pformat_cvt+0xdf>
   140003e32:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e36:	98                   	cwde
   140003e37:	25 00 80 00 00       	and    eax,0x8000
   140003e3c:	89 c2                	mov    edx,eax
   140003e3e:	eb 05                	jmp    140003e45 <__pformat_cvt+0xe4>
   140003e40:	ba 00 00 00 00       	mov    edx,0x0
   140003e45:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003e49:	89 10                	mov    DWORD PTR [rax],edx
   140003e4b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003e4e:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003e52:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003e56:	48 8d 0d 13 62 00 00 	lea    rcx,[rip+0x6213]        # 14000a070 <fpi.0>
   140003e5d:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003e61:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003e66:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e6a:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003e6f:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003e72:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003e76:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003e79:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003e7d:	89 c2                	mov    edx,eax
   140003e7f:	e8 96 24 00 00       	call   14000631a <__gdtoa>
   140003e84:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003e8b:	5b                   	pop    rbx
   140003e8c:	5d                   	pop    rbp
   140003e8d:	c3                   	ret

0000000140003e8e <__pformat_ecvt>:
   140003e8e:	55                   	push   rbp
   140003e8f:	53                   	push   rbx
   140003e90:	48 83 ec 58          	sub    rsp,0x58
   140003e94:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003e99:	48 89 cb             	mov    rbx,rcx
   140003e9c:	db 2b                	fld    TBYTE PTR [rbx]
   140003e9e:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003ea1:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003ea4:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003ea8:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003eac:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003eaf:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003eb2:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003eb6:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003eb9:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003ebd:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003ec1:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003ec6:	4d 89 c1             	mov    r9,r8
   140003ec9:	41 89 c8             	mov    r8d,ecx
   140003ecc:	48 89 c2             	mov    rdx,rax
   140003ecf:	b9 02 00 00 00       	mov    ecx,0x2
   140003ed4:	e8 88 fe ff ff       	call   140003d61 <__pformat_cvt>
   140003ed9:	48 83 c4 58          	add    rsp,0x58
   140003edd:	5b                   	pop    rbx
   140003ede:	5d                   	pop    rbp
   140003edf:	c3                   	ret

0000000140003ee0 <__pformat_fcvt>:
   140003ee0:	55                   	push   rbp
   140003ee1:	53                   	push   rbx
   140003ee2:	48 83 ec 58          	sub    rsp,0x58
   140003ee6:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003eeb:	48 89 cb             	mov    rbx,rcx
   140003eee:	db 2b                	fld    TBYTE PTR [rbx]
   140003ef0:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003ef3:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003ef6:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003efa:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003efe:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003f01:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003f04:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003f08:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003f0b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003f0f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f13:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f18:	4d 89 c1             	mov    r9,r8
   140003f1b:	41 89 c8             	mov    r8d,ecx
   140003f1e:	48 89 c2             	mov    rdx,rax
   140003f21:	b9 03 00 00 00       	mov    ecx,0x3
   140003f26:	e8 36 fe ff ff       	call   140003d61 <__pformat_cvt>
   140003f2b:	48 83 c4 58          	add    rsp,0x58
   140003f2f:	5b                   	pop    rbx
   140003f30:	5d                   	pop    rbp
   140003f31:	c3                   	ret

0000000140003f32 <__pformat_emit_radix_point>:
   140003f32:	55                   	push   rbp
   140003f33:	53                   	push   rbx
   140003f34:	48 83 ec 68          	sub    rsp,0x68
   140003f38:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003f3d:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003f41:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f45:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f48:	83 f8 fd             	cmp    eax,0xfffffffd
   140003f4b:	75 48                	jne    140003f95 <__pformat_emit_radix_point+0x63>
   140003f4d:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003f54:	00 
   140003f55:	e8 4e 57 00 00       	call   1400096a8 <localeconv>
   140003f5a:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003f5d:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003f61:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003f65:	49 89 c9             	mov    r9,rcx
   140003f68:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003f6e:	48 89 c1             	mov    rcx,rax
   140003f71:	e8 6a 51 00 00       	call   1400090e0 <mbrtowc>
   140003f76:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003f79:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003f7d:	7e 0c                	jle    140003f8b <__pformat_emit_radix_point+0x59>
   140003f7f:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003f83:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f87:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003f8b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f8f:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003f92:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003f95:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f99:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003f9d:	66 85 c0             	test   ax,ax
   140003fa0:	0f 84 b8 00 00 00    	je     14000405e <__pformat_emit_radix_point+0x12c>
   140003fa6:	48 89 e0             	mov    rax,rsp
   140003fa9:	48 89 c3             	mov    rbx,rax
   140003fac:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fb0:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003fb3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003fb6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003fb9:	48 63 d0             	movsxd rdx,eax
   140003fbc:	48 83 ea 01          	sub    rdx,0x1
   140003fc0:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140003fc4:	48 98                	cdqe
   140003fc6:	48 83 c0 0f          	add    rax,0xf
   140003fca:	48 c1 e8 04          	shr    rax,0x4
   140003fce:	48 c1 e0 04          	shl    rax,0x4
   140003fd2:	e8 59 f1 ff ff       	call   140003130 <___chkstk_ms>
   140003fd7:	48 29 c4             	sub    rsp,rax
   140003fda:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003fdf:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003fe3:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   140003fea:	00 
   140003feb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fef:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003ff3:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140003ff7:	0f b7 d0             	movzx  edx,ax
   140003ffa:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003ffe:	49 89 c8             	mov    r8,rcx
   140004001:	48 89 c1             	mov    rcx,rax
   140004004:	e8 87 50 00 00       	call   140009090 <wcrtomb>
   140004009:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000400c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004010:	7e 36                	jle    140004048 <__pformat_emit_radix_point+0x116>
   140004012:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140004016:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000401a:	eb 1d                	jmp    140004039 <__pformat_emit_radix_point+0x107>
   14000401c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004020:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004024:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004028:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000402b:	0f be c0             	movsx  eax,al
   14000402e:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004032:	89 c1                	mov    ecx,eax
   140004034:	e8 b7 f1 ff ff       	call   1400031f0 <__pformat_putc>
   140004039:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000403c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000403f:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140004042:	85 c0                	test   eax,eax
   140004044:	7f d6                	jg     14000401c <__pformat_emit_radix_point+0xea>
   140004046:	eb 11                	jmp    140004059 <__pformat_emit_radix_point+0x127>
   140004048:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000404c:	48 89 c2             	mov    rdx,rax
   14000404f:	b9 2e 00 00 00       	mov    ecx,0x2e
   140004054:	e8 97 f1 ff ff       	call   1400031f0 <__pformat_putc>
   140004059:	48 89 dc             	mov    rsp,rbx
   14000405c:	eb 11                	jmp    14000406f <__pformat_emit_radix_point+0x13d>
   14000405e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004062:	48 89 c2             	mov    rdx,rax
   140004065:	b9 2e 00 00 00       	mov    ecx,0x2e
   14000406a:	e8 81 f1 ff ff       	call   1400031f0 <__pformat_putc>
   14000406f:	90                   	nop
   140004070:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140004074:	5b                   	pop    rbx
   140004075:	5d                   	pop    rbp
   140004076:	c3                   	ret

0000000140004077 <__pformat_emit_numeric_value>:
   140004077:	55                   	push   rbp
   140004078:	48 89 e5             	mov    rbp,rsp
   14000407b:	48 83 ec 30          	sub    rsp,0x30
   14000407f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004082:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004086:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   14000408a:	75 0e                	jne    14000409a <__pformat_emit_numeric_value+0x23>
   14000408c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004090:	48 89 c1             	mov    rcx,rax
   140004093:	e8 9a fe ff ff       	call   140003f32 <__pformat_emit_radix_point>
   140004098:	eb 43                	jmp    1400040dd <__pformat_emit_numeric_value+0x66>
   14000409a:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   14000409e:	75 2f                	jne    1400040cf <__pformat_emit_numeric_value+0x58>
   1400040a0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040a4:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400040a8:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   1400040ac:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   1400040b0:	66 85 c0             	test   ax,ax
   1400040b3:	74 28                	je     1400040dd <__pformat_emit_numeric_value+0x66>
   1400040b5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400040b9:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   1400040bd:	49 89 d0             	mov    r8,rdx
   1400040c0:	ba 01 00 00 00       	mov    edx,0x1
   1400040c5:	48 89 c1             	mov    rcx,rax
   1400040c8:	e8 2c f3 ff ff       	call   1400033f9 <__pformat_wputchars>
   1400040cd:	eb 0e                	jmp    1400040dd <__pformat_emit_numeric_value+0x66>
   1400040cf:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400040d3:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400040d6:	89 c1                	mov    ecx,eax
   1400040d8:	e8 13 f1 ff ff       	call   1400031f0 <__pformat_putc>
   1400040dd:	90                   	nop
   1400040de:	48 83 c4 30          	add    rsp,0x30
   1400040e2:	5d                   	pop    rbp
   1400040e3:	c3                   	ret

00000001400040e4 <__pformat_emit_inf_or_nan>:
   1400040e4:	55                   	push   rbp
   1400040e5:	48 89 e5             	mov    rbp,rsp
   1400040e8:	48 83 ec 40          	sub    rsp,0x40
   1400040ec:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400040ef:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400040f3:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400040f7:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400040fb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400040ff:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004103:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000410a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000410e:	74 11                	je     140004121 <__pformat_emit_inf_or_nan+0x3d>
   140004110:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004114:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004118:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000411c:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   14000411f:	eb 3e                	jmp    14000415f <__pformat_emit_inf_or_nan+0x7b>
   140004121:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004125:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004128:	25 00 01 00 00       	and    eax,0x100
   14000412d:	85 c0                	test   eax,eax
   14000412f:	74 11                	je     140004142 <__pformat_emit_inf_or_nan+0x5e>
   140004131:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004135:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004139:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000413d:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140004140:	eb 1d                	jmp    14000415f <__pformat_emit_inf_or_nan+0x7b>
   140004142:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004146:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004149:	83 e0 40             	and    eax,0x40
   14000414c:	85 c0                	test   eax,eax
   14000414e:	74 0f                	je     14000415f <__pformat_emit_inf_or_nan+0x7b>
   140004150:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004154:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004158:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000415c:	c6 00 20             	mov    BYTE PTR [rax],0x20
   14000415f:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140004166:	eb 38                	jmp    1400041a0 <__pformat_emit_inf_or_nan+0xbc>
   140004168:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000416c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004170:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004174:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004177:	83 e0 df             	and    eax,0xffffffdf
   14000417a:	41 89 c0             	mov    r8d,eax
   14000417d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004181:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004184:	83 e0 20             	and    eax,0x20
   140004187:	89 c1                	mov    ecx,eax
   140004189:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000418d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004191:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004195:	44 89 c2             	mov    edx,r8d
   140004198:	09 ca                	or     edx,ecx
   14000419a:	88 10                	mov    BYTE PTR [rax],dl
   14000419c:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400041a0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400041a4:	7f c2                	jg     140004168 <__pformat_emit_inf_or_nan+0x84>
   1400041a6:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400041aa:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400041ae:	48 29 c2             	sub    rdx,rax
   1400041b1:	89 d1                	mov    ecx,edx
   1400041b3:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400041b7:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400041bb:	49 89 d0             	mov    r8,rdx
   1400041be:	89 ca                	mov    edx,ecx
   1400041c0:	48 89 c1             	mov    rcx,rax
   1400041c3:	e8 ac f0 ff ff       	call   140003274 <__pformat_putchars>
   1400041c8:	90                   	nop
   1400041c9:	48 83 c4 40          	add    rsp,0x40
   1400041cd:	5d                   	pop    rbp
   1400041ce:	c3                   	ret

00000001400041cf <__pformat_emit_float>:
   1400041cf:	55                   	push   rbp
   1400041d0:	48 89 e5             	mov    rbp,rsp
   1400041d3:	48 83 ec 30          	sub    rsp,0x30
   1400041d7:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400041da:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400041de:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400041e2:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400041e6:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400041ea:	7e 2e                	jle    14000421a <__pformat_emit_float+0x4b>
   1400041ec:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041f0:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041f3:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   1400041f6:	7f 15                	jg     14000420d <__pformat_emit_float+0x3e>
   1400041f8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041fc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041ff:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004202:	89 c2                	mov    edx,eax
   140004204:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004208:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000420b:	eb 29                	jmp    140004236 <__pformat_emit_float+0x67>
   14000420d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004211:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004218:	eb 1c                	jmp    140004236 <__pformat_emit_float+0x67>
   14000421a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000421e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004221:	85 c0                	test   eax,eax
   140004223:	7e 11                	jle    140004236 <__pformat_emit_float+0x67>
   140004225:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004229:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000422c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000422f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004233:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004236:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000423a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000423d:	85 c0                	test   eax,eax
   14000423f:	78 2b                	js     14000426c <__pformat_emit_float+0x9d>
   140004241:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004245:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004248:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000424c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000424f:	39 c2                	cmp    edx,eax
   140004251:	7e 19                	jle    14000426c <__pformat_emit_float+0x9d>
   140004253:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004257:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   14000425a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000425e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004261:	29 c2                	sub    edx,eax
   140004263:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004267:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000426a:	eb 0b                	jmp    140004277 <__pformat_emit_float+0xa8>
   14000426c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004270:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004277:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000427b:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000427e:	85 c0                	test   eax,eax
   140004280:	7e 2c                	jle    1400042ae <__pformat_emit_float+0xdf>
   140004282:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004286:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004289:	85 c0                	test   eax,eax
   14000428b:	7f 10                	jg     14000429d <__pformat_emit_float+0xce>
   14000428d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004291:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004294:	25 00 08 00 00       	and    eax,0x800
   140004299:	85 c0                	test   eax,eax
   14000429b:	74 11                	je     1400042ae <__pformat_emit_float+0xdf>
   14000429d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042a4:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042a7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042ab:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042ae:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400042b2:	7e 64                	jle    140004318 <__pformat_emit_float+0x149>
   1400042b4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042b8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042bb:	25 00 10 00 00       	and    eax,0x1000
   1400042c0:	85 c0                	test   eax,eax
   1400042c2:	74 54                	je     140004318 <__pformat_emit_float+0x149>
   1400042c4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042c8:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400042cc:	66 85 c0             	test   ax,ax
   1400042cf:	74 47                	je     140004318 <__pformat_emit_float+0x149>
   1400042d1:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400042d4:	83 c0 02             	add    eax,0x2
   1400042d7:	48 63 d0             	movsxd rdx,eax
   1400042da:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   1400042e1:	48 c1 ea 20          	shr    rdx,0x20
   1400042e5:	c1 f8 1f             	sar    eax,0x1f
   1400042e8:	29 c2                	sub    edx,eax
   1400042ea:	8d 42 ff             	lea    eax,[rdx-0x1]
   1400042ed:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400042f0:	eb 15                	jmp    140004307 <__pformat_emit_float+0x138>
   1400042f2:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400042f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042fa:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042fd:	8d 50 ff             	lea    edx,[rax-0x1]
   140004300:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004304:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004307:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000430b:	7e 0b                	jle    140004318 <__pformat_emit_float+0x149>
   14000430d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004311:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004314:	85 c0                	test   eax,eax
   140004316:	7f da                	jg     1400042f2 <__pformat_emit_float+0x123>
   140004318:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000431c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000431f:	85 c0                	test   eax,eax
   140004321:	7e 27                	jle    14000434a <__pformat_emit_float+0x17b>
   140004323:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004327:	75 10                	jne    140004339 <__pformat_emit_float+0x16a>
   140004329:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000432d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004330:	25 c0 01 00 00       	and    eax,0x1c0
   140004335:	85 c0                	test   eax,eax
   140004337:	74 11                	je     14000434a <__pformat_emit_float+0x17b>
   140004339:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000433d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004340:	8d 50 ff             	lea    edx,[rax-0x1]
   140004343:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004347:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000434a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000434e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004351:	85 c0                	test   eax,eax
   140004353:	7e 38                	jle    14000438d <__pformat_emit_float+0x1be>
   140004355:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004359:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000435c:	25 00 06 00 00       	and    eax,0x600
   140004361:	85 c0                	test   eax,eax
   140004363:	75 28                	jne    14000438d <__pformat_emit_float+0x1be>
   140004365:	eb 11                	jmp    140004378 <__pformat_emit_float+0x1a9>
   140004367:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000436b:	48 89 c2             	mov    rdx,rax
   14000436e:	b9 20 00 00 00       	mov    ecx,0x20
   140004373:	e8 78 ee ff ff       	call   1400031f0 <__pformat_putc>
   140004378:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000437c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000437f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004382:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004386:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004389:	85 c0                	test   eax,eax
   14000438b:	7f da                	jg     140004367 <__pformat_emit_float+0x198>
   14000438d:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004391:	74 13                	je     1400043a6 <__pformat_emit_float+0x1d7>
   140004393:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004397:	48 89 c2             	mov    rdx,rax
   14000439a:	b9 2d 00 00 00       	mov    ecx,0x2d
   14000439f:	e8 4c ee ff ff       	call   1400031f0 <__pformat_putc>
   1400043a4:	eb 42                	jmp    1400043e8 <__pformat_emit_float+0x219>
   1400043a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043aa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043ad:	25 00 01 00 00       	and    eax,0x100
   1400043b2:	85 c0                	test   eax,eax
   1400043b4:	74 13                	je     1400043c9 <__pformat_emit_float+0x1fa>
   1400043b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ba:	48 89 c2             	mov    rdx,rax
   1400043bd:	b9 2b 00 00 00       	mov    ecx,0x2b
   1400043c2:	e8 29 ee ff ff       	call   1400031f0 <__pformat_putc>
   1400043c7:	eb 1f                	jmp    1400043e8 <__pformat_emit_float+0x219>
   1400043c9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043cd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043d0:	83 e0 40             	and    eax,0x40
   1400043d3:	85 c0                	test   eax,eax
   1400043d5:	74 11                	je     1400043e8 <__pformat_emit_float+0x219>
   1400043d7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043db:	48 89 c2             	mov    rdx,rax
   1400043de:	b9 20 00 00 00       	mov    ecx,0x20
   1400043e3:	e8 08 ee ff ff       	call   1400031f0 <__pformat_putc>
   1400043e8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ec:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043ef:	85 c0                	test   eax,eax
   1400043f1:	7e 3b                	jle    14000442e <__pformat_emit_float+0x25f>
   1400043f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043f7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043fa:	25 00 06 00 00       	and    eax,0x600
   1400043ff:	3d 00 02 00 00       	cmp    eax,0x200
   140004404:	75 28                	jne    14000442e <__pformat_emit_float+0x25f>
   140004406:	eb 11                	jmp    140004419 <__pformat_emit_float+0x24a>
   140004408:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000440c:	48 89 c2             	mov    rdx,rax
   14000440f:	b9 30 00 00 00       	mov    ecx,0x30
   140004414:	e8 d7 ed ff ff       	call   1400031f0 <__pformat_putc>
   140004419:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000441d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004420:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004423:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004427:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000442a:	85 c0                	test   eax,eax
   14000442c:	7f da                	jg     140004408 <__pformat_emit_float+0x239>
   14000442e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004432:	0f 8e a7 00 00 00    	jle    1400044df <__pformat_emit_float+0x310>
   140004438:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000443c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000443f:	84 c0                	test   al,al
   140004441:	74 14                	je     140004457 <__pformat_emit_float+0x288>
   140004443:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004447:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000444b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000444f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004452:	0f be c0             	movsx  eax,al
   140004455:	eb 05                	jmp    14000445c <__pformat_emit_float+0x28d>
   140004457:	b8 30 00 00 00       	mov    eax,0x30
   14000445c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004460:	89 c1                	mov    ecx,eax
   140004462:	e8 89 ed ff ff       	call   1400031f0 <__pformat_putc>
   140004467:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000446b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000446f:	74 62                	je     1400044d3 <__pformat_emit_float+0x304>
   140004471:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004475:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004478:	25 00 10 00 00       	and    eax,0x1000
   14000447d:	85 c0                	test   eax,eax
   14000447f:	74 52                	je     1400044d3 <__pformat_emit_float+0x304>
   140004481:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004485:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004489:	66 85 c0             	test   ax,ax
   14000448c:	74 45                	je     1400044d3 <__pformat_emit_float+0x304>
   14000448e:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   140004491:	48 63 c1             	movsxd rax,ecx
   140004494:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   14000449b:	48 c1 e8 20          	shr    rax,0x20
   14000449f:	48 89 c2             	mov    rdx,rax
   1400044a2:	89 c8                	mov    eax,ecx
   1400044a4:	c1 f8 1f             	sar    eax,0x1f
   1400044a7:	29 c2                	sub    edx,eax
   1400044a9:	89 d0                	mov    eax,edx
   1400044ab:	01 c0                	add    eax,eax
   1400044ad:	01 d0                	add    eax,edx
   1400044af:	29 c1                	sub    ecx,eax
   1400044b1:	89 ca                	mov    edx,ecx
   1400044b3:	85 d2                	test   edx,edx
   1400044b5:	75 1c                	jne    1400044d3 <__pformat_emit_float+0x304>
   1400044b7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044bb:	48 83 c0 20          	add    rax,0x20
   1400044bf:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044c3:	49 89 d0             	mov    r8,rdx
   1400044c6:	ba 01 00 00 00       	mov    edx,0x1
   1400044cb:	48 89 c1             	mov    rcx,rax
   1400044ce:	e8 26 ef ff ff       	call   1400033f9 <__pformat_wputchars>
   1400044d3:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044d7:	0f 8f 5b ff ff ff    	jg     140004438 <__pformat_emit_float+0x269>
   1400044dd:	eb 11                	jmp    1400044f0 <__pformat_emit_float+0x321>
   1400044df:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044e3:	48 89 c2             	mov    rdx,rax
   1400044e6:	b9 30 00 00 00       	mov    ecx,0x30
   1400044eb:	e8 00 ed ff ff       	call   1400031f0 <__pformat_putc>
   1400044f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044f4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400044f7:	85 c0                	test   eax,eax
   1400044f9:	7f 10                	jg     14000450b <__pformat_emit_float+0x33c>
   1400044fb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044ff:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004502:	25 00 08 00 00       	and    eax,0x800
   140004507:	85 c0                	test   eax,eax
   140004509:	74 0c                	je     140004517 <__pformat_emit_float+0x348>
   14000450b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000450f:	48 89 c1             	mov    rcx,rax
   140004512:	e8 1b fa ff ff       	call   140003f32 <__pformat_emit_radix_point>
   140004517:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000451b:	79 5f                	jns    14000457c <__pformat_emit_float+0x3ad>
   14000451d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004521:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004524:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004527:	01 c2                	add    edx,eax
   140004529:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000452d:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004530:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004534:	48 89 c2             	mov    rdx,rax
   140004537:	b9 30 00 00 00       	mov    ecx,0x30
   14000453c:	e8 af ec ff ff       	call   1400031f0 <__pformat_putc>
   140004541:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   140004545:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004549:	78 e5                	js     140004530 <__pformat_emit_float+0x361>
   14000454b:	eb 2f                	jmp    14000457c <__pformat_emit_float+0x3ad>
   14000454d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004551:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004554:	84 c0                	test   al,al
   140004556:	74 14                	je     14000456c <__pformat_emit_float+0x39d>
   140004558:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000455c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004560:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004564:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004567:	0f be c0             	movsx  eax,al
   14000456a:	eb 05                	jmp    140004571 <__pformat_emit_float+0x3a2>
   14000456c:	b8 30 00 00 00       	mov    eax,0x30
   140004571:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004575:	89 c1                	mov    ecx,eax
   140004577:	e8 74 ec ff ff       	call   1400031f0 <__pformat_putc>
   14000457c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004580:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004583:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004586:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000458a:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   14000458d:	85 c0                	test   eax,eax
   14000458f:	7f bc                	jg     14000454d <__pformat_emit_float+0x37e>
   140004591:	90                   	nop
   140004592:	90                   	nop
   140004593:	48 83 c4 30          	add    rsp,0x30
   140004597:	5d                   	pop    rbp
   140004598:	c3                   	ret

0000000140004599 <__pformat_emit_efloat>:
   140004599:	55                   	push   rbp
   14000459a:	48 89 e5             	mov    rbp,rsp
   14000459d:	48 83 ec 50          	sub    rsp,0x50
   1400045a1:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400045a4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400045a8:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400045ac:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400045b0:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400045b7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400045bb:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400045bf:	79 09                	jns    1400045ca <__pformat_emit_efloat+0x31>
   1400045c1:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400045c8:	eb 05                	jmp    1400045cf <__pformat_emit_efloat+0x36>
   1400045ca:	b8 00 00 00 00       	mov    eax,0x0
   1400045cf:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400045d3:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400045d6:	48 98                	cdqe
   1400045d8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400045dc:	eb 04                	jmp    1400045e2 <__pformat_emit_efloat+0x49>
   1400045de:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400045e2:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400045e5:	48 63 d0             	movsxd rdx,eax
   1400045e8:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   1400045ef:	48 c1 ea 20          	shr    rdx,0x20
   1400045f3:	89 d1                	mov    ecx,edx
   1400045f5:	c1 f9 02             	sar    ecx,0x2
   1400045f8:	99                   	cdq
   1400045f9:	89 c8                	mov    eax,ecx
   1400045fb:	29 d0                	sub    eax,edx
   1400045fd:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004600:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004604:	75 d8                	jne    1400045de <__pformat_emit_efloat+0x45>
   140004606:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000460a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000460d:	83 f8 ff             	cmp    eax,0xffffffff
   140004610:	75 0b                	jne    14000461d <__pformat_emit_efloat+0x84>
   140004612:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004616:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   14000461d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004621:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004624:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004627:	7d 0a                	jge    140004633 <__pformat_emit_efloat+0x9a>
   140004629:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000462d:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004630:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004633:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004637:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000463a:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   14000463e:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004641:	7d 15                	jge    140004658 <__pformat_emit_efloat+0xbf>
   140004643:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004647:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000464a:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   14000464d:	89 c2                	mov    edx,eax
   14000464f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004653:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004656:	eb 0b                	jmp    140004663 <__pformat_emit_efloat+0xca>
   140004658:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000465c:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004663:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004667:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000466b:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000466e:	49 89 c9             	mov    r9,rcx
   140004671:	41 b8 01 00 00 00    	mov    r8d,0x1
   140004677:	89 c1                	mov    ecx,eax
   140004679:	e8 51 fb ff ff       	call   1400041cf <__pformat_emit_float>
   14000467e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004682:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   140004685:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004689:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000468c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004690:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004693:	0d c0 01 00 00       	or     eax,0x1c0
   140004698:	89 c2                	mov    edx,eax
   14000469a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000469e:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400046a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046a5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400046a8:	83 e0 20             	and    eax,0x20
   1400046ab:	83 c8 45             	or     eax,0x45
   1400046ae:	89 c1                	mov    ecx,eax
   1400046b0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046b4:	48 89 c2             	mov    rdx,rax
   1400046b7:	e8 34 eb ff ff       	call   1400031f0 <__pformat_putc>
   1400046bc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046c0:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400046c3:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400046c6:	83 ea 01             	sub    edx,0x1
   1400046c9:	01 c2                	add    edx,eax
   1400046cb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046cf:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400046d2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400046d6:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400046da:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400046de:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   1400046e2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400046e6:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400046ea:	48 89 c1             	mov    rcx,rax
   1400046ed:	e8 69 ef ff ff       	call   14000365b <__pformat_int>
   1400046f2:	90                   	nop
   1400046f3:	48 83 c4 50          	add    rsp,0x50
   1400046f7:	5d                   	pop    rbp
   1400046f8:	c3                   	ret

00000001400046f9 <__pformat_float>:
   1400046f9:	55                   	push   rbp
   1400046fa:	53                   	push   rbx
   1400046fb:	48 83 ec 58          	sub    rsp,0x58
   1400046ff:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004704:	48 89 cb             	mov    rbx,rcx
   140004707:	db 2b                	fld    TBYTE PTR [rbx]
   140004709:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000470c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004710:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004714:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004717:	85 c0                	test   eax,eax
   140004719:	79 0b                	jns    140004726 <__pformat_float+0x2d>
   14000471b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000471f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004726:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000472a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000472d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004730:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004733:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   140004737:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000473b:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000473f:	4d 89 c1             	mov    r9,r8
   140004742:	49 89 c8             	mov    r8,rcx
   140004745:	48 89 c1             	mov    rcx,rax
   140004748:	e8 93 f7 ff ff       	call   140003ee0 <__pformat_fcvt>
   14000474d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004751:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004754:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   140004759:	75 17                	jne    140004772 <__pformat_float+0x79>
   14000475b:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000475e:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004762:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004766:	49 89 c8             	mov    r8,rcx
   140004769:	89 c1                	mov    ecx,eax
   14000476b:	e8 74 f9 ff ff       	call   1400040e4 <__pformat_emit_inf_or_nan>
   140004770:	eb 43                	jmp    1400047b5 <__pformat_float+0xbc>
   140004772:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004775:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004778:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000477c:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004780:	4d 89 c1             	mov    r9,r8
   140004783:	41 89 c8             	mov    r8d,ecx
   140004786:	89 c1                	mov    ecx,eax
   140004788:	e8 42 fa ff ff       	call   1400041cf <__pformat_emit_float>
   14000478d:	eb 11                	jmp    1400047a0 <__pformat_float+0xa7>
   14000478f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004793:	48 89 c2             	mov    rdx,rax
   140004796:	b9 20 00 00 00       	mov    ecx,0x20
   14000479b:	e8 50 ea ff ff       	call   1400031f0 <__pformat_putc>
   1400047a0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047a4:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400047a7:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400047aa:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400047ae:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400047b1:	85 c0                	test   eax,eax
   1400047b3:	7f da                	jg     14000478f <__pformat_float+0x96>
   1400047b5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400047b9:	48 89 c1             	mov    rcx,rax
   1400047bc:	e8 4e 17 00 00       	call   140005f0f <__freedtoa>
   1400047c1:	90                   	nop
   1400047c2:	48 83 c4 58          	add    rsp,0x58
   1400047c6:	5b                   	pop    rbx
   1400047c7:	5d                   	pop    rbp
   1400047c8:	c3                   	ret

00000001400047c9 <__pformat_efloat>:
   1400047c9:	55                   	push   rbp
   1400047ca:	53                   	push   rbx
   1400047cb:	48 83 ec 58          	sub    rsp,0x58
   1400047cf:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400047d4:	48 89 cb             	mov    rbx,rcx
   1400047d7:	db 2b                	fld    TBYTE PTR [rbx]
   1400047d9:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400047dc:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400047e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047e4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400047e7:	85 c0                	test   eax,eax
   1400047e9:	79 0b                	jns    1400047f6 <__pformat_efloat+0x2d>
   1400047eb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047ef:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400047f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047fa:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400047fd:	8d 50 01             	lea    edx,[rax+0x1]
   140004800:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004803:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004806:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000480a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000480e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004812:	4d 89 c1             	mov    r9,r8
   140004815:	49 89 c8             	mov    r8,rcx
   140004818:	48 89 c1             	mov    rcx,rax
   14000481b:	e8 6e f6 ff ff       	call   140003e8e <__pformat_ecvt>
   140004820:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004824:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004827:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000482c:	75 17                	jne    140004845 <__pformat_efloat+0x7c>
   14000482e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004831:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004835:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004839:	49 89 c8             	mov    r8,rcx
   14000483c:	89 c1                	mov    ecx,eax
   14000483e:	e8 a1 f8 ff ff       	call   1400040e4 <__pformat_emit_inf_or_nan>
   140004843:	eb 1b                	jmp    140004860 <__pformat_efloat+0x97>
   140004845:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004848:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000484b:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000484f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004853:	4d 89 c1             	mov    r9,r8
   140004856:	41 89 c8             	mov    r8d,ecx
   140004859:	89 c1                	mov    ecx,eax
   14000485b:	e8 39 fd ff ff       	call   140004599 <__pformat_emit_efloat>
   140004860:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004864:	48 89 c1             	mov    rcx,rax
   140004867:	e8 a3 16 00 00       	call   140005f0f <__freedtoa>
   14000486c:	90                   	nop
   14000486d:	48 83 c4 58          	add    rsp,0x58
   140004871:	5b                   	pop    rbx
   140004872:	5d                   	pop    rbp
   140004873:	c3                   	ret

0000000140004874 <__pformat_gfloat>:
   140004874:	55                   	push   rbp
   140004875:	53                   	push   rbx
   140004876:	48 83 ec 58          	sub    rsp,0x58
   14000487a:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000487f:	48 89 cb             	mov    rbx,rcx
   140004882:	db 2b                	fld    TBYTE PTR [rbx]
   140004884:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140004887:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000488b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000488f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004892:	85 c0                	test   eax,eax
   140004894:	79 0d                	jns    1400048a3 <__pformat_gfloat+0x2f>
   140004896:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000489a:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400048a1:	eb 16                	jmp    1400048b9 <__pformat_gfloat+0x45>
   1400048a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048a7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048aa:	85 c0                	test   eax,eax
   1400048ac:	75 0b                	jne    1400048b9 <__pformat_gfloat+0x45>
   1400048ae:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048b2:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   1400048b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048bd:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400048c0:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400048c3:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400048c6:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400048ca:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400048ce:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400048d2:	4d 89 c1             	mov    r9,r8
   1400048d5:	49 89 c8             	mov    r8,rcx
   1400048d8:	48 89 c1             	mov    rcx,rax
   1400048db:	e8 ae f5 ff ff       	call   140003e8e <__pformat_ecvt>
   1400048e0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400048e4:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048e7:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400048ec:	75 1a                	jne    140004908 <__pformat_gfloat+0x94>
   1400048ee:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400048f1:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400048f5:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048f9:	49 89 c8             	mov    r8,rcx
   1400048fc:	89 c1                	mov    ecx,eax
   1400048fe:	e8 e1 f7 ff ff       	call   1400040e4 <__pformat_emit_inf_or_nan>
   140004903:	e9 14 01 00 00       	jmp    140004a1c <__pformat_gfloat+0x1a8>
   140004908:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000490b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000490e:	0f 8c b2 00 00 00    	jl     1400049c6 <__pformat_gfloat+0x152>
   140004914:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004918:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000491b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000491e:	39 c2                	cmp    edx,eax
   140004920:	0f 8c a0 00 00 00    	jl     1400049c6 <__pformat_gfloat+0x152>
   140004926:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000492a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000492d:	25 00 08 00 00       	and    eax,0x800
   140004932:	85 c0                	test   eax,eax
   140004934:	74 15                	je     14000494b <__pformat_gfloat+0xd7>
   140004936:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000493a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000493d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004940:	29 c2                	sub    edx,eax
   140004942:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004946:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004949:	eb 20                	jmp    14000496b <__pformat_gfloat+0xf7>
   14000494b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000494f:	48 89 c1             	mov    rcx,rax
   140004952:	e8 81 4d 00 00       	call   1400096d8 <strlen>
   140004957:	89 c1                	mov    ecx,eax
   140004959:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000495c:	89 c2                	mov    edx,eax
   14000495e:	89 c8                	mov    eax,ecx
   140004960:	29 d0                	sub    eax,edx
   140004962:	89 c2                	mov    edx,eax
   140004964:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004968:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000496b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000496f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004972:	85 c0                	test   eax,eax
   140004974:	79 0b                	jns    140004981 <__pformat_gfloat+0x10d>
   140004976:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000497a:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   140004981:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004984:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004987:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000498b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   14000498f:	4d 89 c1             	mov    r9,r8
   140004992:	41 89 c8             	mov    r8d,ecx
   140004995:	89 c1                	mov    ecx,eax
   140004997:	e8 33 f8 ff ff       	call   1400041cf <__pformat_emit_float>
   14000499c:	eb 11                	jmp    1400049af <__pformat_gfloat+0x13b>
   14000499e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049a2:	48 89 c2             	mov    rdx,rax
   1400049a5:	b9 20 00 00 00       	mov    ecx,0x20
   1400049aa:	e8 41 e8 ff ff       	call   1400031f0 <__pformat_putc>
   1400049af:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049b3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400049b6:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400049b9:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400049bd:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400049c0:	85 c0                	test   eax,eax
   1400049c2:	7f da                	jg     14000499e <__pformat_gfloat+0x12a>
   1400049c4:	eb 56                	jmp    140004a1c <__pformat_gfloat+0x1a8>
   1400049c6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049ca:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400049cd:	25 00 08 00 00       	and    eax,0x800
   1400049d2:	85 c0                	test   eax,eax
   1400049d4:	74 13                	je     1400049e9 <__pformat_gfloat+0x175>
   1400049d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049da:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049dd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400049e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049e4:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049e7:	eb 18                	jmp    140004a01 <__pformat_gfloat+0x18d>
   1400049e9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400049ed:	48 89 c1             	mov    rcx,rax
   1400049f0:	e8 e3 4c 00 00       	call   1400096d8 <strlen>
   1400049f5:	83 e8 01             	sub    eax,0x1
   1400049f8:	89 c2                	mov    edx,eax
   1400049fa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049fe:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a01:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004a04:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004a07:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   140004a0b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004a0f:	4d 89 c1             	mov    r9,r8
   140004a12:	41 89 c8             	mov    r8d,ecx
   140004a15:	89 c1                	mov    ecx,eax
   140004a17:	e8 7d fb ff ff       	call   140004599 <__pformat_emit_efloat>
   140004a1c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a20:	48 89 c1             	mov    rcx,rax
   140004a23:	e8 e7 14 00 00       	call   140005f0f <__freedtoa>
   140004a28:	90                   	nop
   140004a29:	48 83 c4 58          	add    rsp,0x58
   140004a2d:	5b                   	pop    rbx
   140004a2e:	5d                   	pop    rbp
   140004a2f:	c3                   	ret

0000000140004a30 <__pformat_emit_xfloat>:
   140004a30:	55                   	push   rbp
   140004a31:	53                   	push   rbx
   140004a32:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140004a39:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140004a40:	00 
   140004a41:	48 89 cb             	mov    rbx,rcx
   140004a44:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004a48:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004a4c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004a50:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   140004a56:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a59:	48 85 c0             	test   rax,rax
   140004a5c:	75 09                	jne    140004a67 <__pformat_emit_xfloat+0x37>
   140004a5e:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a62:	66 85 c0             	test   ax,ax
   140004a65:	74 0b                	je     140004a72 <__pformat_emit_xfloat+0x42>
   140004a67:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a6b:	83 e8 03             	sub    eax,0x3
   140004a6e:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004a72:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a76:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a79:	85 c0                	test   eax,eax
   140004a7b:	0f 88 90 00 00 00    	js     140004b11 <__pformat_emit_xfloat+0xe1>
   140004a81:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a85:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a88:	83 f8 0e             	cmp    eax,0xe
   140004a8b:	0f 8f 80 00 00 00    	jg     140004b11 <__pformat_emit_xfloat+0xe1>
   140004a91:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a94:	48 d1 e8             	shr    rax,1
   140004a97:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a9a:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004a9d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004aa1:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004aa4:	b9 0e 00 00 00       	mov    ecx,0xe
   140004aa9:	29 c1                	sub    ecx,eax
   140004aab:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004ab2:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004ab8:	89 c1                	mov    ecx,eax
   140004aba:	49 d3 e0             	shl    r8,cl
   140004abd:	4c 89 c0             	mov    rax,r8
   140004ac0:	48 01 d0             	add    rax,rdx
   140004ac3:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004ac6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ac9:	48 85 c0             	test   rax,rax
   140004acc:	78 0b                	js     140004ad9 <__pformat_emit_xfloat+0xa9>
   140004ace:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ad1:	48 01 c0             	add    rax,rax
   140004ad4:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004ad7:	eb 15                	jmp    140004aee <__pformat_emit_xfloat+0xbe>
   140004ad9:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004add:	83 c0 04             	add    eax,0x4
   140004ae0:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004ae4:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ae7:	48 c1 e8 03          	shr    rax,0x3
   140004aeb:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004aee:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004af1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004af5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004af8:	b9 0f 00 00 00       	mov    ecx,0xf
   140004afd:	29 c1                	sub    ecx,eax
   140004aff:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004b06:	89 c1                	mov    ecx,eax
   140004b08:	48 d3 ea             	shr    rdx,cl
   140004b0b:	48 89 d0             	mov    rax,rdx
   140004b0e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b11:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b14:	48 85 c0             	test   rax,rax
   140004b17:	75 0f                	jne    140004b28 <__pformat_emit_xfloat+0xf8>
   140004b19:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b1d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b20:	85 c0                	test   eax,eax
   140004b22:	0f 8e f8 00 00 00    	jle    140004c20 <__pformat_emit_xfloat+0x1f0>
   140004b28:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b2c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b2f:	83 f8 0e             	cmp    eax,0xe
   140004b32:	7f 1a                	jg     140004b4e <__pformat_emit_xfloat+0x11e>
   140004b34:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b38:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b3b:	85 c0                	test   eax,eax
   140004b3d:	78 0f                	js     140004b4e <__pformat_emit_xfloat+0x11e>
   140004b3f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b43:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b46:	83 c0 01             	add    eax,0x1
   140004b49:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004b4c:	eb 07                	jmp    140004b55 <__pformat_emit_xfloat+0x125>
   140004b4e:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004b55:	e9 bc 00 00 00       	jmp    140004c16 <__pformat_emit_xfloat+0x1e6>
   140004b5a:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b5d:	83 e0 0f             	and    eax,0xf
   140004b60:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004b63:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004b67:	75 36                	jne    140004b9f <__pformat_emit_xfloat+0x16f>
   140004b69:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b6d:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b71:	72 1b                	jb     140004b8e <__pformat_emit_xfloat+0x15e>
   140004b73:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b77:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b7a:	25 00 08 00 00       	and    eax,0x800
   140004b7f:	85 c0                	test   eax,eax
   140004b81:	75 0b                	jne    140004b8e <__pformat_emit_xfloat+0x15e>
   140004b83:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b87:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b8a:	85 c0                	test   eax,eax
   140004b8c:	7e 2d                	jle    140004bbb <__pformat_emit_xfloat+0x18b>
   140004b8e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004b92:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004b96:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004b9a:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004b9d:	eb 1c                	jmp    140004bbb <__pformat_emit_xfloat+0x18b>
   140004b9f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ba3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ba6:	85 c0                	test   eax,eax
   140004ba8:	7e 11                	jle    140004bbb <__pformat_emit_xfloat+0x18b>
   140004baa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bae:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bb1:	8d 50 ff             	lea    edx,[rax-0x1]
   140004bb4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bb8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004bbb:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004bbf:	75 15                	jne    140004bd6 <__pformat_emit_xfloat+0x1a6>
   140004bc1:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004bc5:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004bc9:	72 0b                	jb     140004bd6 <__pformat_emit_xfloat+0x1a6>
   140004bcb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bcf:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bd2:	85 c0                	test   eax,eax
   140004bd4:	78 32                	js     140004c08 <__pformat_emit_xfloat+0x1d8>
   140004bd6:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004bda:	76 16                	jbe    140004bf2 <__pformat_emit_xfloat+0x1c2>
   140004bdc:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004bdf:	8d 50 37             	lea    edx,[rax+0x37]
   140004be2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004be6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004be9:	83 e0 20             	and    eax,0x20
   140004bec:	09 d0                	or     eax,edx
   140004bee:	89 c1                	mov    ecx,eax
   140004bf0:	eb 08                	jmp    140004bfa <__pformat_emit_xfloat+0x1ca>
   140004bf2:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004bf5:	83 c0 30             	add    eax,0x30
   140004bf8:	89 c1                	mov    ecx,eax
   140004bfa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004bfe:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c02:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c06:	88 08                	mov    BYTE PTR [rax],cl
   140004c08:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004c0b:	48 c1 e8 04          	shr    rax,0x4
   140004c0f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004c12:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004c16:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004c1a:	0f 8f 3a ff ff ff    	jg     140004b5a <__pformat_emit_xfloat+0x12a>
   140004c20:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c24:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004c28:	75 39                	jne    140004c63 <__pformat_emit_xfloat+0x233>
   140004c2a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c2e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c31:	85 c0                	test   eax,eax
   140004c33:	7f 10                	jg     140004c45 <__pformat_emit_xfloat+0x215>
   140004c35:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c39:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c3c:	25 00 08 00 00       	and    eax,0x800
   140004c41:	85 c0                	test   eax,eax
   140004c43:	74 0f                	je     140004c54 <__pformat_emit_xfloat+0x224>
   140004c45:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c49:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c4d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c51:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004c54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c58:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c5c:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c60:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004c63:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c67:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c6a:	85 c0                	test   eax,eax
   140004c6c:	0f 8e e3 00 00 00    	jle    140004d55 <__pformat_emit_xfloat+0x325>
   140004c72:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c76:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004c7a:	48 29 c2             	sub    rdx,rax
   140004c7d:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004c80:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004c84:	98                   	cwde
   140004c85:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004c88:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c8c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c8f:	85 c0                	test   eax,eax
   140004c91:	7e 0a                	jle    140004c9d <__pformat_emit_xfloat+0x26d>
   140004c93:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c97:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c9a:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c9d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ca1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ca4:	25 c0 01 00 00       	and    eax,0x1c0
   140004ca9:	85 c0                	test   eax,eax
   140004cab:	74 07                	je     140004cb4 <__pformat_emit_xfloat+0x284>
   140004cad:	b8 06 00 00 00       	mov    eax,0x6
   140004cb2:	eb 05                	jmp    140004cb9 <__pformat_emit_xfloat+0x289>
   140004cb4:	b8 05 00 00 00       	mov    eax,0x5
   140004cb9:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004cbc:	eb 0f                	jmp    140004ccd <__pformat_emit_xfloat+0x29d>
   140004cbe:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004cc2:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004cc6:	83 c0 01             	add    eax,0x1
   140004cc9:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004ccd:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004cd0:	48 63 d0             	movsxd rdx,eax
   140004cd3:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004cda:	48 c1 ea 20          	shr    rdx,0x20
   140004cde:	89 d1                	mov    ecx,edx
   140004ce0:	c1 f9 02             	sar    ecx,0x2
   140004ce3:	99                   	cdq
   140004ce4:	89 c8                	mov    eax,ecx
   140004ce6:	29 d0                	sub    eax,edx
   140004ce8:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004ceb:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004cef:	75 cd                	jne    140004cbe <__pformat_emit_xfloat+0x28e>
   140004cf1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cf5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004cf8:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004cfb:	7d 4d                	jge    140004d4a <__pformat_emit_xfloat+0x31a>
   140004cfd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d01:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d04:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004d07:	89 c2                	mov    edx,eax
   140004d09:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d0d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004d10:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d14:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d17:	25 00 06 00 00       	and    eax,0x600
   140004d1c:	85 c0                	test   eax,eax
   140004d1e:	75 35                	jne    140004d55 <__pformat_emit_xfloat+0x325>
   140004d20:	eb 11                	jmp    140004d33 <__pformat_emit_xfloat+0x303>
   140004d22:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d26:	48 89 c2             	mov    rdx,rax
   140004d29:	b9 20 00 00 00       	mov    ecx,0x20
   140004d2e:	e8 bd e4 ff ff       	call   1400031f0 <__pformat_putc>
   140004d33:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d37:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d3a:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004d3d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d41:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004d44:	85 c0                	test   eax,eax
   140004d46:	7f da                	jg     140004d22 <__pformat_emit_xfloat+0x2f2>
   140004d48:	eb 0b                	jmp    140004d55 <__pformat_emit_xfloat+0x325>
   140004d4a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d4e:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004d55:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d59:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d5c:	25 80 00 00 00       	and    eax,0x80
   140004d61:	85 c0                	test   eax,eax
   140004d63:	74 13                	je     140004d78 <__pformat_emit_xfloat+0x348>
   140004d65:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d69:	48 89 c2             	mov    rdx,rax
   140004d6c:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004d71:	e8 7a e4 ff ff       	call   1400031f0 <__pformat_putc>
   140004d76:	eb 42                	jmp    140004dba <__pformat_emit_xfloat+0x38a>
   140004d78:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d7c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d7f:	25 00 01 00 00       	and    eax,0x100
   140004d84:	85 c0                	test   eax,eax
   140004d86:	74 13                	je     140004d9b <__pformat_emit_xfloat+0x36b>
   140004d88:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d8c:	48 89 c2             	mov    rdx,rax
   140004d8f:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004d94:	e8 57 e4 ff ff       	call   1400031f0 <__pformat_putc>
   140004d99:	eb 1f                	jmp    140004dba <__pformat_emit_xfloat+0x38a>
   140004d9b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d9f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004da2:	83 e0 40             	and    eax,0x40
   140004da5:	85 c0                	test   eax,eax
   140004da7:	74 11                	je     140004dba <__pformat_emit_xfloat+0x38a>
   140004da9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dad:	48 89 c2             	mov    rdx,rax
   140004db0:	b9 20 00 00 00       	mov    ecx,0x20
   140004db5:	e8 36 e4 ff ff       	call   1400031f0 <__pformat_putc>
   140004dba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dbe:	48 89 c2             	mov    rdx,rax
   140004dc1:	b9 30 00 00 00       	mov    ecx,0x30
   140004dc6:	e8 25 e4 ff ff       	call   1400031f0 <__pformat_putc>
   140004dcb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dcf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dd2:	83 e0 20             	and    eax,0x20
   140004dd5:	83 c8 58             	or     eax,0x58
   140004dd8:	89 c1                	mov    ecx,eax
   140004dda:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dde:	48 89 c2             	mov    rdx,rax
   140004de1:	e8 0a e4 ff ff       	call   1400031f0 <__pformat_putc>
   140004de6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dea:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004ded:	85 c0                	test   eax,eax
   140004def:	7e 54                	jle    140004e45 <__pformat_emit_xfloat+0x415>
   140004df1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004df5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004df8:	25 00 02 00 00       	and    eax,0x200
   140004dfd:	85 c0                	test   eax,eax
   140004dff:	74 44                	je     140004e45 <__pformat_emit_xfloat+0x415>
   140004e01:	eb 11                	jmp    140004e14 <__pformat_emit_xfloat+0x3e4>
   140004e03:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e07:	48 89 c2             	mov    rdx,rax
   140004e0a:	b9 30 00 00 00       	mov    ecx,0x30
   140004e0f:	e8 dc e3 ff ff       	call   1400031f0 <__pformat_putc>
   140004e14:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e18:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e1b:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e1e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e22:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004e25:	85 c0                	test   eax,eax
   140004e27:	7f da                	jg     140004e03 <__pformat_emit_xfloat+0x3d3>
   140004e29:	eb 1a                	jmp    140004e45 <__pformat_emit_xfloat+0x415>
   140004e2b:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004e30:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004e34:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004e37:	0f be c0             	movsx  eax,al
   140004e3a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e3e:	89 c1                	mov    ecx,eax
   140004e40:	e8 32 f2 ff ff       	call   140004077 <__pformat_emit_numeric_value>
   140004e45:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004e49:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004e4d:	72 dc                	jb     140004e2b <__pformat_emit_xfloat+0x3fb>
   140004e4f:	eb 11                	jmp    140004e62 <__pformat_emit_xfloat+0x432>
   140004e51:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e55:	48 89 c2             	mov    rdx,rax
   140004e58:	b9 30 00 00 00       	mov    ecx,0x30
   140004e5d:	e8 8e e3 ff ff       	call   1400031f0 <__pformat_putc>
   140004e62:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e66:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004e69:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e6c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e70:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004e73:	85 c0                	test   eax,eax
   140004e75:	7f da                	jg     140004e51 <__pformat_emit_xfloat+0x421>
   140004e77:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e7b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e7e:	83 e0 20             	and    eax,0x20
   140004e81:	83 c8 50             	or     eax,0x50
   140004e84:	89 c1                	mov    ecx,eax
   140004e86:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e8a:	48 89 c2             	mov    rdx,rax
   140004e8d:	e8 5e e3 ff ff       	call   1400031f0 <__pformat_putc>
   140004e92:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e96:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004e99:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004e9d:	01 c2                	add    edx,eax
   140004e9f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ea3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004ea6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eaa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ead:	0d c0 01 00 00       	or     eax,0x1c0
   140004eb2:	89 c2                	mov    edx,eax
   140004eb4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eb8:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004ebb:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004ebf:	66 85 c0             	test   ax,ax
   140004ec2:	79 09                	jns    140004ecd <__pformat_emit_xfloat+0x49d>
   140004ec4:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004ecb:	eb 05                	jmp    140004ed2 <__pformat_emit_xfloat+0x4a2>
   140004ecd:	b8 00 00 00 00       	mov    eax,0x0
   140004ed2:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004ed6:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004eda:	48 0f bf c0          	movsx  rax,ax
   140004ede:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004ee2:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004ee6:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004eea:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004eee:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004ef2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004ef6:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004efa:	48 89 c1             	mov    rcx,rax
   140004efd:	e8 59 e7 ff ff       	call   14000365b <__pformat_int>
   140004f02:	90                   	nop
   140004f03:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004f0a:	5b                   	pop    rbx
   140004f0b:	5d                   	pop    rbp
   140004f0c:	c3                   	ret

0000000140004f0d <__pformat_xldouble>:
   140004f0d:	55                   	push   rbp
   140004f0e:	53                   	push   rbx
   140004f0f:	48 83 ec 78          	sub    rsp,0x78
   140004f13:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004f18:	48 89 cb             	mov    rbx,rcx
   140004f1b:	db 2b                	fld    TBYTE PTR [rbx]
   140004f1d:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004f20:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004f24:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004f2b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004f2f:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f32:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f35:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004f39:	48 89 c1             	mov    rcx,rax
   140004f3c:	e8 e5 ed ff ff       	call   140003d26 <init_fpreg_ldouble>
   140004f41:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f44:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f47:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f4b:	48 89 c1             	mov    rcx,rax
   140004f4e:	e8 ed 3d 00 00       	call   140008d40 <__isnanl>
   140004f53:	85 c0                	test   eax,eax
   140004f55:	74 1d                	je     140004f74 <__pformat_xldouble+0x67>
   140004f57:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f5a:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f5e:	48 8d 15 e1 63 00 00 	lea    rdx,[rip+0x63e1]        # 14000b346 <.rdata+0x16>
   140004f65:	49 89 c8             	mov    r8,rcx
   140004f68:	89 c1                	mov    ecx,eax
   140004f6a:	e8 75 f1 ff ff       	call   1400040e4 <__pformat_emit_inf_or_nan>
   140004f6f:	e9 aa 00 00 00       	jmp    14000501e <__pformat_xldouble+0x111>
   140004f74:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f78:	98                   	cwde
   140004f79:	25 00 80 00 00       	and    eax,0x8000
   140004f7e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004f81:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004f85:	74 12                	je     140004f99 <__pformat_xldouble+0x8c>
   140004f87:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f8b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004f8e:	0c 80                	or     al,0x80
   140004f90:	89 c2                	mov    edx,eax
   140004f92:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f96:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004f99:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f9c:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f9f:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004fa3:	48 89 c1             	mov    rcx,rax
   140004fa6:	e8 a5 3c 00 00       	call   140008c50 <__fpclassifyl>
   140004fab:	3d 00 05 00 00       	cmp    eax,0x500
   140004fb0:	75 1a                	jne    140004fcc <__pformat_xldouble+0xbf>
   140004fb2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004fb5:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004fb9:	48 8d 15 8a 63 00 00 	lea    rdx,[rip+0x638a]        # 14000b34a <.rdata+0x1a>
   140004fc0:	49 89 c8             	mov    r8,rcx
   140004fc3:	89 c1                	mov    ecx,eax
   140004fc5:	e8 1a f1 ff ff       	call   1400040e4 <__pformat_emit_inf_or_nan>
   140004fca:	eb 52                	jmp    14000501e <__pformat_xldouble+0x111>
   140004fcc:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fd0:	66 25 ff 7f          	and    ax,0x7fff
   140004fd4:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004fd8:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fdc:	66 85 c0             	test   ax,ax
   140004fdf:	75 11                	jne    140004ff2 <__pformat_xldouble+0xe5>
   140004fe1:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004fe5:	48 85 c0             	test   rax,rax
   140004fe8:	74 14                	je     140004ffe <__pformat_xldouble+0xf1>
   140004fea:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140004ff0:	eb 0c                	jmp    140004ffe <__pformat_xldouble+0xf1>
   140004ff2:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004ff6:	66 2d ff 3f          	sub    ax,0x3fff
   140004ffa:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004ffe:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005002:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005006:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000500a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   14000500e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140005012:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140005016:	48 89 c1             	mov    rcx,rax
   140005019:	e8 12 fa ff ff       	call   140004a30 <__pformat_emit_xfloat>
   14000501e:	90                   	nop
   14000501f:	48 83 c4 78          	add    rsp,0x78
   140005023:	5b                   	pop    rbx
   140005024:	5d                   	pop    rbp
   140005025:	c3                   	ret

0000000140005026 <__pformat_xdouble>:
   140005026:	55                   	push   rbp
   140005027:	48 89 e5             	mov    rbp,rsp
   14000502a:	48 83 ec 60          	sub    rsp,0x60
   14000502e:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140005033:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005037:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000503e:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140005041:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140005045:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140005048:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   14000504c:	48 89 c1             	mov    rcx,rax
   14000504f:	e8 d2 ec ff ff       	call   140003d26 <init_fpreg_ldouble>
   140005054:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005058:	66 48 0f 6e c0       	movq   xmm0,rax
   14000505d:	e8 7e 3c 00 00       	call   140008ce0 <__isnan>
   140005062:	85 c0                	test   eax,eax
   140005064:	74 1d                	je     140005083 <__pformat_xdouble+0x5d>
   140005066:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005069:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   14000506d:	48 8d 15 d2 62 00 00 	lea    rdx,[rip+0x62d2]        # 14000b346 <.rdata+0x16>
   140005074:	49 89 c8             	mov    r8,rcx
   140005077:	89 c1                	mov    ecx,eax
   140005079:	e8 66 f0 ff ff       	call   1400040e4 <__pformat_emit_inf_or_nan>
   14000507e:	e9 f9 00 00 00       	jmp    14000517c <__pformat_xdouble+0x156>
   140005083:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005087:	98                   	cwde
   140005088:	25 00 80 00 00       	and    eax,0x8000
   14000508d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005090:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005094:	74 12                	je     1400050a8 <__pformat_xdouble+0x82>
   140005096:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000509a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000509d:	0c 80                	or     al,0x80
   14000509f:	89 c2                	mov    edx,eax
   1400050a1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400050a5:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400050a8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400050ac:	66 48 0f 6e c0       	movq   xmm0,rax
   1400050b1:	e8 1a 3b 00 00       	call   140008bd0 <__fpclassify>
   1400050b6:	3d 00 05 00 00       	cmp    eax,0x500
   1400050bb:	75 1d                	jne    1400050da <__pformat_xdouble+0xb4>
   1400050bd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400050c0:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   1400050c4:	48 8d 15 7f 62 00 00 	lea    rdx,[rip+0x627f]        # 14000b34a <.rdata+0x1a>
   1400050cb:	49 89 c8             	mov    r8,rcx
   1400050ce:	89 c1                	mov    ecx,eax
   1400050d0:	e8 0f f0 ff ff       	call   1400040e4 <__pformat_emit_inf_or_nan>
   1400050d5:	e9 a2 00 00 00       	jmp    14000517c <__pformat_xdouble+0x156>
   1400050da:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050de:	66 25 ff 7f          	and    ax,0x7fff
   1400050e2:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400050e6:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050ea:	66 85 c0             	test   ax,ax
   1400050ed:	74 3b                	je     14000512a <__pformat_xdouble+0x104>
   1400050ef:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050f3:	66 3d 00 3c          	cmp    ax,0x3c00
   1400050f7:	7f 31                	jg     14000512a <__pformat_xdouble+0x104>
   1400050f9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050fd:	98                   	cwde
   1400050fe:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005103:	29 c2                	sub    edx,eax
   140005105:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005108:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000510c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000510f:	89 c1                	mov    ecx,eax
   140005111:	48 d3 ea             	shr    rdx,cl
   140005114:	48 89 d0             	mov    rax,rdx
   140005117:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000511b:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000511f:	89 c2                	mov    edx,eax
   140005121:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005124:	01 d0                	add    eax,edx
   140005126:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000512a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000512e:	66 85 c0             	test   ax,ax
   140005131:	75 11                	jne    140005144 <__pformat_xdouble+0x11e>
   140005133:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005137:	48 85 c0             	test   rax,rax
   14000513a:	74 14                	je     140005150 <__pformat_xdouble+0x12a>
   14000513c:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   140005142:	eb 0c                	jmp    140005150 <__pformat_xdouble+0x12a>
   140005144:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005148:	66 2d fc 3f          	sub    ax,0x3ffc
   14000514c:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005150:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005154:	48 c1 e8 03          	shr    rax,0x3
   140005158:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000515c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005160:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005164:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005168:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   14000516c:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140005170:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140005174:	48 89 c1             	mov    rcx,rax
   140005177:	e8 b4 f8 ff ff       	call   140004a30 <__pformat_emit_xfloat>
   14000517c:	90                   	nop
   14000517d:	48 83 c4 60          	add    rsp,0x60
   140005181:	5d                   	pop    rbp
   140005182:	c3                   	ret

0000000140005183 <__mingw_pformat>:
   140005183:	55                   	push   rbp
   140005184:	48 89 e5             	mov    rbp,rsp
   140005187:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   14000518e:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005191:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005195:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005199:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   14000519d:	e8 a6 44 00 00       	call   140009648 <_errno>
   1400051a2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400051a4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400051a7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400051ab:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   1400051af:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   1400051b6:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400051b9:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400051bc:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   1400051c3:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400051ca:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   1400051d1:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   1400051d7:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   1400051de:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   1400051e4:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   1400051eb:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400051ee:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   1400051f1:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   1400051f8:	e9 27 0c 00 00       	jmp    140005e24 <__mingw_pformat+0xca1>
   1400051fd:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005201:	0f 85 0f 0c 00 00    	jne    140005e16 <__mingw_pformat+0xc93>
   140005207:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000520e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005215:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005219:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000521d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005221:	48 83 c0 0c          	add    rax,0xc
   140005225:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005229:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000522c:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000522f:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005236:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140005239:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000523c:	e9 c4 0b 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005241:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005245:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005249:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000524d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005250:	0f be c0             	movsx  eax,al
   140005253:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005256:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   14000525a:	0f 84 94 09 00 00    	je     140005bf4 <__mingw_pformat+0xa71>
   140005260:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   140005264:	0f 8f 02 0b 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000526a:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   14000526e:	0f 84 eb 03 00 00    	je     14000565f <__mingw_pformat+0x4dc>
   140005274:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   140005278:	0f 8f ee 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000527e:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   140005282:	0f 84 31 09 00 00    	je     140005bb9 <__mingw_pformat+0xa36>
   140005288:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   14000528c:	0f 8f da 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005292:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005296:	0f 84 c3 03 00 00    	je     14000565f <__mingw_pformat+0x4dc>
   14000529c:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400052a0:	0f 8f c6 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400052a6:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   1400052aa:	0f 84 31 09 00 00    	je     140005be1 <__mingw_pformat+0xa5e>
   1400052b0:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   1400052b4:	0f 8f b2 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400052ba:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   1400052be:	0f 84 31 03 00 00    	je     1400055f5 <__mingw_pformat+0x472>
   1400052c4:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   1400052c8:	0f 8f 9e 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400052ce:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   1400052d2:	0f 84 28 05 00 00    	je     140005800 <__mingw_pformat+0x67d>
   1400052d8:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   1400052dc:	0f 8f 8a 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400052e2:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   1400052e6:	0f 84 73 03 00 00    	je     14000565f <__mingw_pformat+0x4dc>
   1400052ec:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   1400052f0:	0f 8f 76 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400052f6:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   1400052fa:	0f 84 4d 07 00 00    	je     140005a4d <__mingw_pformat+0x8ca>
   140005300:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005304:	0f 8f 62 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000530a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000530e:	0f 84 2d 03 00 00    	je     140005641 <__mingw_pformat+0x4be>
   140005314:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   140005318:	0f 8f 4e 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000531e:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   140005322:	0f 84 65 08 00 00    	je     140005b8d <__mingw_pformat+0xa0a>
   140005328:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   14000532c:	0f 8f 3a 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005332:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005336:	0f 84 db 07 00 00    	je     140005b17 <__mingw_pformat+0x994>
   14000533c:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005340:	0f 8f 26 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005346:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   14000534a:	0f 84 ee 03 00 00    	je     14000573e <__mingw_pformat+0x5bb>
   140005350:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   140005354:	0f 8f 12 0a 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000535a:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   14000535e:	0f 84 87 07 00 00    	je     140005aeb <__mingw_pformat+0x968>
   140005364:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   140005368:	0f 8f fe 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000536e:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   140005372:	0f 84 f3 05 00 00    	je     14000596b <__mingw_pformat+0x7e8>
   140005378:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   14000537c:	0f 8f ea 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005382:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005386:	0f 84 61 05 00 00    	je     1400058ed <__mingw_pformat+0x76a>
   14000538c:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005390:	0f 8f d6 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005396:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   14000539a:	0f 84 cf 04 00 00    	je     14000586f <__mingw_pformat+0x6ec>
   1400053a0:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400053a4:	0f 8f c2 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400053aa:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   1400053ae:	0f 84 8a 03 00 00    	je     14000573e <__mingw_pformat+0x5bb>
   1400053b4:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   1400053b8:	0f 8f ae 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400053be:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   1400053c2:	0f 84 b5 01 00 00    	je     14000557d <__mingw_pformat+0x3fa>
   1400053c8:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   1400053cc:	0f 8f 9a 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400053d2:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   1400053d6:	0f 84 83 02 00 00    	je     14000565f <__mingw_pformat+0x4dc>
   1400053dc:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   1400053e0:	0f 8f 86 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400053e6:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   1400053ea:	0f 84 f9 05 00 00    	je     1400059e9 <__mingw_pformat+0x866>
   1400053f0:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   1400053f4:	0f 8f 72 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400053fa:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   1400053fe:	0f 84 5b 02 00 00    	je     14000565f <__mingw_pformat+0x4dc>
   140005404:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005408:	0f 8f 5e 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000540e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   140005412:	0f 84 d6 01 00 00    	je     1400055ee <__mingw_pformat+0x46b>
   140005418:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   14000541c:	0f 8f 4a 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005422:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005426:	0f 84 a0 07 00 00    	je     140005bcc <__mingw_pformat+0xa49>
   14000542c:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005430:	0f 8f 36 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005436:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   14000543a:	0f 84 ea 06 00 00    	je     140005b2a <__mingw_pformat+0x9a7>
   140005440:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   140005444:	0f 8f 22 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000544a:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   14000544e:	0f 84 20 05 00 00    	je     140005974 <__mingw_pformat+0x7f1>
   140005454:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   140005458:	0f 8f 0e 09 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000545e:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   140005462:	0f 84 8e 04 00 00    	je     1400058f6 <__mingw_pformat+0x773>
   140005468:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   14000546c:	0f 8f fa 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005472:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005476:	0f 84 fc 03 00 00    	je     140005878 <__mingw_pformat+0x6f5>
   14000547c:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005480:	0f 8f e6 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005486:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   14000548a:	0f 84 e6 00 00 00    	je     140005576 <__mingw_pformat+0x3f3>
   140005490:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   140005494:	0f 8f d2 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000549a:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   14000549e:	0f 84 bb 01 00 00    	je     14000565f <__mingw_pformat+0x4dc>
   1400054a4:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400054a8:	0f 8f be 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400054ae:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   1400054b2:	0f 84 3a 05 00 00    	je     1400059f2 <__mingw_pformat+0x86f>
   1400054b8:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   1400054bc:	0f 8f aa 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400054c2:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   1400054c6:	0f 84 8c 08 00 00    	je     140005d58 <__mingw_pformat+0xbd5>
   1400054cc:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   1400054d0:	0f 8f 96 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400054d6:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   1400054da:	0f 84 27 07 00 00    	je     140005c07 <__mingw_pformat+0xa84>
   1400054e0:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   1400054e4:	0f 8f 82 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400054ea:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   1400054ee:	0f 84 db 07 00 00    	je     140005ccf <__mingw_pformat+0xb4c>
   1400054f4:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   1400054f8:	0f 8f 6e 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   1400054fe:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005502:	0f 84 af 07 00 00    	je     140005cb7 <__mingw_pformat+0xb34>
   140005508:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000550c:	0f 8f 5a 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005512:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005516:	0f 84 1c 07 00 00    	je     140005c38 <__mingw_pformat+0xab5>
   14000551c:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005520:	0f 8f 46 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   140005526:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   14000552a:	0f 84 b7 07 00 00    	je     140005ce7 <__mingw_pformat+0xb64>
   140005530:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   140005534:	0f 8f 32 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000553a:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   14000553e:	74 23                	je     140005563 <__mingw_pformat+0x3e0>
   140005540:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005544:	0f 8f 22 08 00 00    	jg     140005d6c <__mingw_pformat+0xbe9>
   14000554a:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   14000554e:	0f 84 ec 07 00 00    	je     140005d40 <__mingw_pformat+0xbbd>
   140005554:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   140005558:	0f 84 41 07 00 00    	je     140005c9f <__mingw_pformat+0xb1c>
   14000555e:	e9 09 08 00 00       	jmp    140005d6c <__mingw_pformat+0xbe9>
   140005563:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005567:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000556a:	89 c1                	mov    ecx,eax
   14000556c:	e8 7f dc ff ff       	call   1400031f0 <__pformat_putc>
   140005571:	e9 82 fc ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005576:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   14000557d:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005584:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005588:	74 06                	je     140005590 <__mingw_pformat+0x40d>
   14000558a:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000558e:	75 30                	jne    1400055c0 <__mingw_pformat+0x43d>
   140005590:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005594:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005598:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000559c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000559e:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   1400055a2:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055a6:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   1400055aa:	49 89 d0             	mov    r8,rdx
   1400055ad:	ba 01 00 00 00       	mov    edx,0x1
   1400055b2:	48 89 c1             	mov    rcx,rax
   1400055b5:	e8 3f de ff ff       	call   1400033f9 <__pformat_wputchars>
   1400055ba:	90                   	nop
   1400055bb:	e9 38 fc ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   1400055c0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055c4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055c8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055cc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055ce:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   1400055d1:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055d5:	48 8d 45 90          	lea    rax,[rbp-0x70]
   1400055d9:	49 89 d0             	mov    r8,rdx
   1400055dc:	ba 01 00 00 00       	mov    edx,0x1
   1400055e1:	48 89 c1             	mov    rcx,rax
   1400055e4:	e8 8b dc ff ff       	call   140003274 <__pformat_putchars>
   1400055e9:	e9 0a fc ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   1400055ee:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400055f5:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400055f9:	74 06                	je     140005601 <__mingw_pformat+0x47e>
   1400055fb:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055ff:	75 20                	jne    140005621 <__mingw_pformat+0x49e>
   140005601:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005605:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005609:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000560d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005610:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005614:	48 89 c1             	mov    rcx,rax
   140005617:	e8 29 df ff ff       	call   140003545 <__pformat_wcputs>
   14000561c:	e9 d7 fb ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005621:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005625:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005629:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000562d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005630:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005634:	48 89 c1             	mov    rcx,rax
   140005637:	e8 37 dd ff ff       	call   140003373 <__pformat_puts>
   14000563c:	e9 b7 fb ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005641:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140005644:	89 c1                	mov    ecx,eax
   140005646:	e8 85 40 00 00       	call   1400096d0 <strerror>
   14000564b:	48 89 c1             	mov    rcx,rax
   14000564e:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005652:	48 89 c2             	mov    rdx,rax
   140005655:	e8 19 dd ff ff       	call   140003373 <__pformat_puts>
   14000565a:	e9 99 fb ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   14000565f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005662:	80 e4 fe             	and    ah,0xfe
   140005665:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005668:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000566c:	75 15                	jne    140005683 <__mingw_pformat+0x500>
   14000566e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005672:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005676:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000567a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000567d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005681:	eb 54                	jmp    1400056d7 <__mingw_pformat+0x554>
   140005683:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005687:	75 16                	jne    14000569f <__mingw_pformat+0x51c>
   140005689:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000568d:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005691:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005695:	8b 00                	mov    eax,DWORD PTR [rax]
   140005697:	89 c0                	mov    eax,eax
   140005699:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000569d:	eb 38                	jmp    1400056d7 <__mingw_pformat+0x554>
   14000569f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056a3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056a7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056ad:	89 c0                	mov    eax,eax
   1400056af:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056b3:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400056b7:	75 0d                	jne    1400056c6 <__mingw_pformat+0x543>
   1400056b9:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   1400056bd:	0f b7 c0             	movzx  eax,ax
   1400056c0:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056c4:	eb 11                	jmp    1400056d7 <__mingw_pformat+0x554>
   1400056c6:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400056ca:	75 0b                	jne    1400056d7 <__mingw_pformat+0x554>
   1400056cc:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   1400056d0:	0f b6 c0             	movzx  eax,al
   1400056d3:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056d7:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400056db:	75 2e                	jne    14000570b <__mingw_pformat+0x588>
   1400056dd:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400056e1:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400056e5:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400056ec:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400056f3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400056f7:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400056fe:	48 89 c1             	mov    rcx,rax
   140005701:	e8 55 df ff ff       	call   14000365b <__pformat_int>
   140005706:	e9 ed fa ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   14000570b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000570f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005713:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000571a:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005721:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140005725:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   14000572c:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000572f:	49 89 c8             	mov    r8,rcx
   140005732:	89 c1                	mov    ecx,eax
   140005734:	e8 a5 e2 ff ff       	call   1400039de <__pformat_xint>
   140005739:	e9 ba fa ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   14000573e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005741:	0c 80                	or     al,0x80
   140005743:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005746:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000574a:	75 15                	jne    140005761 <__mingw_pformat+0x5de>
   14000574c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005750:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005754:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005758:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000575b:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000575f:	eb 56                	jmp    1400057b7 <__mingw_pformat+0x634>
   140005761:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005765:	75 16                	jne    14000577d <__mingw_pformat+0x5fa>
   140005767:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000576b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000576f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005773:	8b 00                	mov    eax,DWORD PTR [rax]
   140005775:	48 98                	cdqe
   140005777:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000577b:	eb 3a                	jmp    1400057b7 <__mingw_pformat+0x634>
   14000577d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005781:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005785:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005789:	8b 00                	mov    eax,DWORD PTR [rax]
   14000578b:	48 98                	cdqe
   14000578d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005791:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005795:	75 0e                	jne    1400057a5 <__mingw_pformat+0x622>
   140005797:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000579b:	48 0f bf c0          	movsx  rax,ax
   14000579f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057a3:	eb 12                	jmp    1400057b7 <__mingw_pformat+0x634>
   1400057a5:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400057a9:	75 0c                	jne    1400057b7 <__mingw_pformat+0x634>
   1400057ab:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   1400057af:	48 0f be c0          	movsx  rax,al
   1400057b3:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057b7:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057bb:	48 85 c0             	test   rax,rax
   1400057be:	79 09                	jns    1400057c9 <__mingw_pformat+0x646>
   1400057c0:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400057c7:	eb 05                	jmp    1400057ce <__mingw_pformat+0x64b>
   1400057c9:	b8 00 00 00 00       	mov    eax,0x0
   1400057ce:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   1400057d2:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057d6:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400057da:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400057e1:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400057e8:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400057ec:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400057f3:	48 89 c1             	mov    rcx,rax
   1400057f6:	e8 60 de ff ff       	call   14000365b <__pformat_int>
   1400057fb:	e9 f8 f9 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005800:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005804:	75 18                	jne    14000581e <__mingw_pformat+0x69b>
   140005806:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005809:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000580c:	75 10                	jne    14000581e <__mingw_pformat+0x69b>
   14000580e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005811:	80 cc 02             	or     ah,0x2
   140005814:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005817:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   14000581e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005822:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005826:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000582a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000582d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005831:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   140005838:	00 
   140005839:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000583d:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005841:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005848:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   14000584f:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005853:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000585a:	49 89 d0             	mov    r8,rdx
   14000585d:	48 89 c2             	mov    rdx,rax
   140005860:	b9 78 00 00 00       	mov    ecx,0x78
   140005865:	e8 74 e1 ff ff       	call   1400039de <__pformat_xint>
   14000586a:	e9 89 f9 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   14000586f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005872:	83 c8 20             	or     eax,0x20
   140005875:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005878:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000587b:	83 e0 04             	and    eax,0x4
   14000587e:	85 c0                	test   eax,eax
   140005880:	74 2f                	je     1400058b1 <__mingw_pformat+0x72e>
   140005882:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005886:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000588a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000588e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005891:	db 28                	fld    TBYTE PTR [rax]
   140005893:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005899:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000589d:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058a4:	48 89 c1             	mov    rcx,rax
   1400058a7:	e8 1d ef ff ff       	call   1400047c9 <__pformat_efloat>
   1400058ac:	e9 47 f9 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   1400058b1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058b5:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058b9:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058bd:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   1400058c1:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   1400058c8:	ff 
   1400058c9:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400058cf:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058d5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058d9:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058e0:	48 89 c1             	mov    rcx,rax
   1400058e3:	e8 e1 ee ff ff       	call   1400047c9 <__pformat_efloat>
   1400058e8:	e9 0b f9 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   1400058ed:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058f0:	83 c8 20             	or     eax,0x20
   1400058f3:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400058f6:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058f9:	83 e0 04             	and    eax,0x4
   1400058fc:	85 c0                	test   eax,eax
   1400058fe:	74 2f                	je     14000592f <__mingw_pformat+0x7ac>
   140005900:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005904:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005908:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000590c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000590f:	db 28                	fld    TBYTE PTR [rax]
   140005911:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005917:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000591b:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005922:	48 89 c1             	mov    rcx,rax
   140005925:	e8 cf ed ff ff       	call   1400046f9 <__pformat_float>
   14000592a:	e9 c9 f8 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   14000592f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005933:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005937:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000593b:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   14000593f:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   140005946:	ff 
   140005947:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000594d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005953:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005957:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000595e:	48 89 c1             	mov    rcx,rax
   140005961:	e8 93 ed ff ff       	call   1400046f9 <__pformat_float>
   140005966:	e9 8d f8 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   14000596b:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000596e:	83 c8 20             	or     eax,0x20
   140005971:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005974:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005977:	83 e0 04             	and    eax,0x4
   14000597a:	85 c0                	test   eax,eax
   14000597c:	74 2f                	je     1400059ad <__mingw_pformat+0x82a>
   14000597e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005982:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005986:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000598a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000598d:	db 28                	fld    TBYTE PTR [rax]
   14000598f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005995:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005999:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059a0:	48 89 c1             	mov    rcx,rax
   1400059a3:	e8 cc ee ff ff       	call   140004874 <__pformat_gfloat>
   1400059a8:	e9 4b f8 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   1400059ad:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059b1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059b5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059b9:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   1400059bd:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   1400059c4:	ff 
   1400059c5:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400059cb:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059d1:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059d5:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059dc:	48 89 c1             	mov    rcx,rax
   1400059df:	e8 90 ee ff ff       	call   140004874 <__pformat_gfloat>
   1400059e4:	e9 0f f8 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   1400059e9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059ec:	83 c8 20             	or     eax,0x20
   1400059ef:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400059f2:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059f5:	83 e0 04             	and    eax,0x4
   1400059f8:	85 c0                	test   eax,eax
   1400059fa:	74 2f                	je     140005a2b <__mingw_pformat+0x8a8>
   1400059fc:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a00:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a04:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a08:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a0b:	db 28                	fld    TBYTE PTR [rax]
   140005a0d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a13:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a17:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a1e:	48 89 c1             	mov    rcx,rax
   140005a21:	e8 e7 f4 ff ff       	call   140004f0d <__pformat_xldouble>
   140005a26:	e9 cd f7 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005a2b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a2f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a33:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a37:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a3a:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a3e:	66 48 0f 6e c0       	movq   xmm0,rax
   140005a43:	e8 de f5 ff ff       	call   140005026 <__pformat_xdouble>
   140005a48:	e9 ab f7 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005a4d:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005a51:	75 1b                	jne    140005a6e <__mingw_pformat+0x8eb>
   140005a53:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a56:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a5a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a5e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a62:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a65:	89 ca                	mov    edx,ecx
   140005a67:	88 10                	mov    BYTE PTR [rax],dl
   140005a69:	e9 8a f7 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005a6e:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005a72:	75 1c                	jne    140005a90 <__mingw_pformat+0x90d>
   140005a74:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a77:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a7b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a7f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a83:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a86:	89 ca                	mov    edx,ecx
   140005a88:	66 89 10             	mov    WORD PTR [rax],dx
   140005a8b:	e9 68 f7 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005a90:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005a94:	75 19                	jne    140005aaf <__mingw_pformat+0x92c>
   140005a96:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a9a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a9e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005aa2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005aa5:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005aa8:	89 10                	mov    DWORD PTR [rax],edx
   140005aaa:	e9 49 f7 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005aaf:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005ab3:	75 1d                	jne    140005ad2 <__mingw_pformat+0x94f>
   140005ab5:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005ab8:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005abc:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005ac0:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ac4:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ac7:	48 63 d1             	movsxd rdx,ecx
   140005aca:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005acd:	e9 26 f7 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005ad2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005ad6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005ada:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ade:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ae1:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005ae4:	89 10                	mov    DWORD PTR [rax],edx
   140005ae6:	e9 0d f7 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005aeb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005aef:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005af2:	3c 68                	cmp    al,0x68
   140005af4:	75 0e                	jne    140005b04 <__mingw_pformat+0x981>
   140005af6:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005afb:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005b02:	eb 07                	jmp    140005b0b <__mingw_pformat+0x988>
   140005b04:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005b0b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b12:	e9 ee 02 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005b17:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b1e:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b25:	e9 db 02 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005b2a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b2e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b31:	3c 36                	cmp    al,0x36
   140005b33:	75 1d                	jne    140005b52 <__mingw_pformat+0x9cf>
   140005b35:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b39:	48 83 c0 01          	add    rax,0x1
   140005b3d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b40:	3c 34                	cmp    al,0x34
   140005b42:	75 0e                	jne    140005b52 <__mingw_pformat+0x9cf>
   140005b44:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b4b:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b50:	eb 2f                	jmp    140005b81 <__mingw_pformat+0x9fe>
   140005b52:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b56:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b59:	3c 33                	cmp    al,0x33
   140005b5b:	75 1d                	jne    140005b7a <__mingw_pformat+0x9f7>
   140005b5d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b61:	48 83 c0 01          	add    rax,0x1
   140005b65:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b68:	3c 32                	cmp    al,0x32
   140005b6a:	75 0e                	jne    140005b7a <__mingw_pformat+0x9f7>
   140005b6c:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b73:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b78:	eb 07                	jmp    140005b81 <__mingw_pformat+0x9fe>
   140005b7a:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b81:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b88:	e9 78 02 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005b8d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b91:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b94:	3c 6c                	cmp    al,0x6c
   140005b96:	75 0e                	jne    140005ba6 <__mingw_pformat+0xa23>
   140005b98:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b9d:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005ba4:	eb 07                	jmp    140005bad <__mingw_pformat+0xa2a>
   140005ba6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005bad:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bb4:	e9 4c 02 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005bb9:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005bc0:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bc7:	e9 39 02 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005bcc:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005bcf:	83 c8 04             	or     eax,0x4
   140005bd2:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005bd5:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bdc:	e9 24 02 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005be1:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005be8:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bef:	e9 11 02 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005bf4:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bfb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c02:	e9 fe 01 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005c07:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005c0b:	77 1f                	ja     140005c2c <__mingw_pformat+0xaa9>
   140005c0d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005c14:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005c18:	48 83 c0 10          	add    rax,0x10
   140005c1c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005c20:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005c27:	e9 d9 01 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005c2c:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c33:	e9 cd 01 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005c38:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005c3d:	74 4c                	je     140005c8b <__mingw_pformat+0xb08>
   140005c3f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c43:	74 06                	je     140005c4b <__mingw_pformat+0xac8>
   140005c45:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005c49:	75 40                	jne    140005c8b <__mingw_pformat+0xb08>
   140005c4b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005c4f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005c53:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005c57:	8b 10                	mov    edx,DWORD PTR [rax]
   140005c59:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c5d:	89 10                	mov    DWORD PTR [rax],edx
   140005c5f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c63:	8b 00                	mov    eax,DWORD PTR [rax]
   140005c65:	85 c0                	test   eax,eax
   140005c67:	79 29                	jns    140005c92 <__mingw_pformat+0xb0f>
   140005c69:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c6d:	75 13                	jne    140005c82 <__mingw_pformat+0xaff>
   140005c6f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c72:	80 cc 04             	or     ah,0x4
   140005c75:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c78:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005c7b:	f7 d8                	neg    eax
   140005c7d:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005c80:	eb 10                	jmp    140005c92 <__mingw_pformat+0xb0f>
   140005c82:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005c89:	eb 07                	jmp    140005c92 <__mingw_pformat+0xb0f>
   140005c8b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c92:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005c99:	00 
   140005c9a:	e9 66 01 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005c9f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ca3:	0f 85 4f 01 00 00    	jne    140005df8 <__mingw_pformat+0xc75>
   140005ca9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cac:	80 cc 08             	or     ah,0x8
   140005caf:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cb2:	e9 41 01 00 00       	jmp    140005df8 <__mingw_pformat+0xc75>
   140005cb7:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cbb:	0f 85 3a 01 00 00    	jne    140005dfb <__mingw_pformat+0xc78>
   140005cc1:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cc4:	80 cc 01             	or     ah,0x1
   140005cc7:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cca:	e9 2c 01 00 00       	jmp    140005dfb <__mingw_pformat+0xc78>
   140005ccf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cd3:	0f 85 25 01 00 00    	jne    140005dfe <__mingw_pformat+0xc7b>
   140005cd9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cdc:	80 cc 04             	or     ah,0x4
   140005cdf:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005ce2:	e9 17 01 00 00       	jmp    140005dfe <__mingw_pformat+0xc7b>
   140005ce7:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ceb:	0f 85 10 01 00 00    	jne    140005e01 <__mingw_pformat+0xc7e>
   140005cf1:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cf4:	80 cc 10             	or     ah,0x10
   140005cf7:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cfa:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005d01:	00 
   140005d02:	e8 a1 39 00 00       	call   1400096a8 <localeconv>
   140005d07:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005d0b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005d0f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005d13:	49 89 c9             	mov    r9,rcx
   140005d16:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005d1c:	48 89 c1             	mov    rcx,rax
   140005d1f:	e8 bc 33 00 00       	call   1400090e0 <mbrtowc>
   140005d24:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005d27:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005d2b:	7e 08                	jle    140005d35 <__mingw_pformat+0xbb2>
   140005d2d:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005d31:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005d35:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005d38:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005d3b:	e9 c1 00 00 00       	jmp    140005e01 <__mingw_pformat+0xc7e>
   140005d40:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d44:	0f 85 ba 00 00 00    	jne    140005e04 <__mingw_pformat+0xc81>
   140005d4a:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d4d:	83 c8 40             	or     eax,0x40
   140005d50:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d53:	e9 ac 00 00 00       	jmp    140005e04 <__mingw_pformat+0xc81>
   140005d58:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d5c:	75 0e                	jne    140005d6c <__mingw_pformat+0xbe9>
   140005d5e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d61:	80 cc 02             	or     ah,0x2
   140005d64:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d67:	e9 99 00 00 00       	jmp    140005e05 <__mingw_pformat+0xc82>
   140005d6c:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005d70:	77 68                	ja     140005dda <__mingw_pformat+0xc57>
   140005d72:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005d76:	7f 62                	jg     140005dda <__mingw_pformat+0xc57>
   140005d78:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005d7c:	7e 5c                	jle    140005dda <__mingw_pformat+0xc57>
   140005d7e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d82:	75 09                	jne    140005d8d <__mingw_pformat+0xc0a>
   140005d84:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005d8b:	eb 0d                	jmp    140005d9a <__mingw_pformat+0xc17>
   140005d8d:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005d91:	75 07                	jne    140005d9a <__mingw_pformat+0xc17>
   140005d93:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005d9a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005d9f:	74 64                	je     140005e05 <__mingw_pformat+0xc82>
   140005da1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005da5:	8b 00                	mov    eax,DWORD PTR [rax]
   140005da7:	85 c0                	test   eax,eax
   140005da9:	79 0e                	jns    140005db9 <__mingw_pformat+0xc36>
   140005dab:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005dae:	8d 50 d0             	lea    edx,[rax-0x30]
   140005db1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005db5:	89 10                	mov    DWORD PTR [rax],edx
   140005db7:	eb 4c                	jmp    140005e05 <__mingw_pformat+0xc82>
   140005db9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005dbd:	8b 10                	mov    edx,DWORD PTR [rax]
   140005dbf:	89 d0                	mov    eax,edx
   140005dc1:	c1 e0 02             	shl    eax,0x2
   140005dc4:	01 d0                	add    eax,edx
   140005dc6:	01 c0                	add    eax,eax
   140005dc8:	89 c2                	mov    edx,eax
   140005dca:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005dcd:	01 d0                	add    eax,edx
   140005dcf:	8d 50 d0             	lea    edx,[rax-0x30]
   140005dd2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005dd6:	89 10                	mov    DWORD PTR [rax],edx
   140005dd8:	eb 2b                	jmp    140005e05 <__mingw_pformat+0xc82>
   140005dda:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005dde:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005de2:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005de6:	48 89 c2             	mov    rdx,rax
   140005de9:	b9 25 00 00 00       	mov    ecx,0x25
   140005dee:	e8 fd d3 ff ff       	call   1400031f0 <__pformat_putc>
   140005df3:	e9 00 f4 ff ff       	jmp    1400051f8 <__mingw_pformat+0x75>
   140005df8:	90                   	nop
   140005df9:	eb 0a                	jmp    140005e05 <__mingw_pformat+0xc82>
   140005dfb:	90                   	nop
   140005dfc:	eb 07                	jmp    140005e05 <__mingw_pformat+0xc82>
   140005dfe:	90                   	nop
   140005dff:	eb 04                	jmp    140005e05 <__mingw_pformat+0xc82>
   140005e01:	90                   	nop
   140005e02:	eb 01                	jmp    140005e05 <__mingw_pformat+0xc82>
   140005e04:	90                   	nop
   140005e05:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e09:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e0c:	84 c0                	test   al,al
   140005e0e:	0f 85 2d f4 ff ff    	jne    140005241 <__mingw_pformat+0xbe>
   140005e14:	eb 0e                	jmp    140005e24 <__mingw_pformat+0xca1>
   140005e16:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005e1a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e1d:	89 c1                	mov    ecx,eax
   140005e1f:	e8 cc d3 ff ff       	call   1400031f0 <__pformat_putc>
   140005e24:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e28:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e2c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005e30:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e33:	0f be c0             	movsx  eax,al
   140005e36:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005e39:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005e3d:	0f 85 ba f3 ff ff    	jne    1400051fd <__mingw_pformat+0x7a>
   140005e43:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005e46:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005e4d:	5d                   	pop    rbp
   140005e4e:	c3                   	ret
   140005e4f:	90                   	nop

0000000140005e50 <__rv_alloc_D2A>:
   140005e50:	55                   	push   rbp
   140005e51:	48 89 e5             	mov    rbp,rsp
   140005e54:	48 83 ec 30          	sub    rsp,0x30
   140005e58:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005e5b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005e62:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005e69:	eb 07                	jmp    140005e72 <__rv_alloc_D2A+0x22>
   140005e6b:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005e6f:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005e72:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005e75:	83 c0 17             	add    eax,0x17
   140005e78:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005e7b:	7f ee                	jg     140005e6b <__rv_alloc_D2A+0x1b>
   140005e7d:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005e80:	89 c1                	mov    ecx,eax
   140005e82:	e8 56 1e 00 00       	call   140007cdd <__Balloc_D2A>
   140005e87:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005e8b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e8f:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005e92:	89 10                	mov    DWORD PTR [rax],edx
   140005e94:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e98:	48 83 c0 04          	add    rax,0x4
   140005e9c:	48 83 c4 30          	add    rsp,0x30
   140005ea0:	5d                   	pop    rbp
   140005ea1:	c3                   	ret

0000000140005ea2 <__nrv_alloc_D2A>:
   140005ea2:	55                   	push   rbp
   140005ea3:	48 89 e5             	mov    rbp,rsp
   140005ea6:	48 83 ec 30          	sub    rsp,0x30
   140005eaa:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005eae:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005eb2:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005eb6:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005eb9:	89 c1                	mov    ecx,eax
   140005ebb:	e8 90 ff ff ff       	call   140005e50 <__rv_alloc_D2A>
   140005ec0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005ec4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ec8:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005ecc:	eb 05                	jmp    140005ed3 <__nrv_alloc_D2A+0x31>
   140005ece:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005ed3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005ed7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005edb:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005edf:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005ee2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ee6:	88 10                	mov    BYTE PTR [rax],dl
   140005ee8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005eec:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005eef:	84 c0                	test   al,al
   140005ef1:	75 db                	jne    140005ece <__nrv_alloc_D2A+0x2c>
   140005ef3:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005ef8:	74 0b                	je     140005f05 <__nrv_alloc_D2A+0x63>
   140005efa:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005efe:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005f02:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005f05:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f09:	48 83 c4 30          	add    rsp,0x30
   140005f0d:	5d                   	pop    rbp
   140005f0e:	c3                   	ret

0000000140005f0f <__freedtoa>:
   140005f0f:	55                   	push   rbp
   140005f10:	48 89 e5             	mov    rbp,rsp
   140005f13:	48 83 ec 30          	sub    rsp,0x30
   140005f17:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f1b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f1f:	48 83 e8 04          	sub    rax,0x4
   140005f23:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f27:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f2b:	8b 10                	mov    edx,DWORD PTR [rax]
   140005f2d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f31:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005f34:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f38:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005f3b:	ba 01 00 00 00       	mov    edx,0x1
   140005f40:	89 c1                	mov    ecx,eax
   140005f42:	d3 e2                	shl    edx,cl
   140005f44:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f48:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005f4b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f4f:	48 89 c1             	mov    rcx,rax
   140005f52:	e8 c7 1e 00 00       	call   140007e1e <__Bfree_D2A>
   140005f57:	90                   	nop
   140005f58:	48 83 c4 30          	add    rsp,0x30
   140005f5c:	5d                   	pop    rbp
   140005f5d:	c3                   	ret

0000000140005f5e <__quorem_D2A>:
   140005f5e:	55                   	push   rbp
   140005f5f:	48 89 e5             	mov    rbp,rsp
   140005f62:	48 83 ec 70          	sub    rsp,0x70
   140005f66:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f6a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005f6e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f72:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f75:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005f78:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f7c:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f7f:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005f82:	7e 0a                	jle    140005f8e <__quorem_D2A+0x30>
   140005f84:	b8 00 00 00 00       	mov    eax,0x0
   140005f89:	e9 3f 02 00 00       	jmp    1400061cd <__quorem_D2A+0x26f>
   140005f8e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f92:	48 83 c0 18          	add    rax,0x18
   140005f96:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005f9a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005f9e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005fa1:	48 98                	cdqe
   140005fa3:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005faa:	00 
   140005fab:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005faf:	48 01 d0             	add    rax,rdx
   140005fb2:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005fb6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005fba:	48 83 c0 18          	add    rax,0x18
   140005fbe:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005fc2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005fc5:	48 98                	cdqe
   140005fc7:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005fce:	00 
   140005fcf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005fd3:	48 01 d0             	add    rax,rdx
   140005fd6:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140005fda:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005fde:	8b 00                	mov    eax,DWORD PTR [rax]
   140005fe0:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140005fe4:	8b 12                	mov    edx,DWORD PTR [rdx]
   140005fe6:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140005fe9:	ba 00 00 00 00       	mov    edx,0x0
   140005fee:	f7 f1                	div    ecx
   140005ff0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140005ff3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140005ff7:	0f 84 c4 00 00 00    	je     1400060c1 <__quorem_D2A+0x163>
   140005ffd:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006004:	00 
   140006005:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000600c:	00 
   14000600d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006011:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140006015:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006019:	8b 00                	mov    eax,DWORD PTR [rax]
   14000601b:	89 c2                	mov    edx,eax
   14000601d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140006020:	48 0f af d0          	imul   rdx,rax
   140006024:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006028:	48 01 d0             	add    rax,rdx
   14000602b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000602f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006033:	48 c1 e8 20          	shr    rax,0x20
   140006037:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000603b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000603f:	8b 00                	mov    eax,DWORD PTR [rax]
   140006041:	89 c1                	mov    ecx,eax
   140006043:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006047:	89 c2                	mov    edx,eax
   140006049:	48 89 c8             	mov    rax,rcx
   14000604c:	48 29 d0             	sub    rax,rdx
   14000604f:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006053:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006057:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000605b:	48 c1 e8 20          	shr    rax,0x20
   14000605f:	83 e0 01             	and    eax,0x1
   140006062:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006066:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000606a:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000606e:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006072:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006076:	89 10                	mov    DWORD PTR [rax],edx
   140006078:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000607c:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006080:	73 8b                	jae    14000600d <__quorem_D2A+0xaf>
   140006082:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006086:	8b 00                	mov    eax,DWORD PTR [rax]
   140006088:	85 c0                	test   eax,eax
   14000608a:	75 35                	jne    1400060c1 <__quorem_D2A+0x163>
   14000608c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006090:	48 83 c0 18          	add    rax,0x18
   140006094:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006098:	eb 04                	jmp    14000609e <__quorem_D2A+0x140>
   14000609a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000609e:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400060a3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060a7:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   1400060ab:	73 0a                	jae    1400060b7 <__quorem_D2A+0x159>
   1400060ad:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060b1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060b3:	85 c0                	test   eax,eax
   1400060b5:	74 e3                	je     14000609a <__quorem_D2A+0x13c>
   1400060b7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060bb:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400060be:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400060c1:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400060c5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060c9:	48 89 c1             	mov    rcx,rax
   1400060cc:	e8 bc 24 00 00       	call   14000858d <__cmp_D2A>
   1400060d1:	85 c0                	test   eax,eax
   1400060d3:	0f 88 f1 00 00 00    	js     1400061ca <__quorem_D2A+0x26c>
   1400060d9:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   1400060dd:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400060e4:	00 
   1400060e5:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   1400060ec:	00 
   1400060ed:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060f1:	48 83 c0 18          	add    rax,0x18
   1400060f5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400060f9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400060fd:	48 83 c0 18          	add    rax,0x18
   140006101:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006105:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006109:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000610d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006111:	8b 00                	mov    eax,DWORD PTR [rax]
   140006113:	89 c2                	mov    edx,eax
   140006115:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006119:	48 01 d0             	add    rax,rdx
   14000611c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140006120:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006124:	48 c1 e8 20          	shr    rax,0x20
   140006128:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000612c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006130:	8b 00                	mov    eax,DWORD PTR [rax]
   140006132:	89 c1                	mov    ecx,eax
   140006134:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006138:	89 c2                	mov    edx,eax
   14000613a:	48 89 c8             	mov    rax,rcx
   14000613d:	48 29 d0             	sub    rax,rdx
   140006140:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006144:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006148:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000614c:	48 c1 e8 20          	shr    rax,0x20
   140006150:	83 e0 01             	and    eax,0x1
   140006153:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006157:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000615b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000615f:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006163:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006167:	89 10                	mov    DWORD PTR [rax],edx
   140006169:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000616d:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006171:	73 92                	jae    140006105 <__quorem_D2A+0x1a7>
   140006173:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006177:	48 83 c0 18          	add    rax,0x18
   14000617b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000617f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006182:	48 98                	cdqe
   140006184:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000618b:	00 
   14000618c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006190:	48 01 d0             	add    rax,rdx
   140006193:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006197:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000619b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000619d:	85 c0                	test   eax,eax
   14000619f:	75 29                	jne    1400061ca <__quorem_D2A+0x26c>
   1400061a1:	eb 04                	jmp    1400061a7 <__quorem_D2A+0x249>
   1400061a3:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400061a7:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400061ac:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061b0:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   1400061b4:	73 0a                	jae    1400061c0 <__quorem_D2A+0x262>
   1400061b6:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061ba:	8b 00                	mov    eax,DWORD PTR [rax]
   1400061bc:	85 c0                	test   eax,eax
   1400061be:	74 e3                	je     1400061a3 <__quorem_D2A+0x245>
   1400061c0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400061c4:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400061c7:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400061ca:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400061cd:	48 83 c4 70          	add    rsp,0x70
   1400061d1:	5d                   	pop    rbp
   1400061d2:	c3                   	ret
   1400061d3:	90                   	nop
   1400061d4:	90                   	nop
   1400061d5:	90                   	nop
   1400061d6:	90                   	nop
   1400061d7:	90                   	nop
   1400061d8:	90                   	nop
   1400061d9:	90                   	nop
   1400061da:	90                   	nop
   1400061db:	90                   	nop
   1400061dc:	90                   	nop
   1400061dd:	90                   	nop
   1400061de:	90                   	nop
   1400061df:	90                   	nop

00000001400061e0 <__hi0bits_D2A>:
   1400061e0:	55                   	push   rbp
   1400061e1:	48 89 e5             	mov    rbp,rsp
   1400061e4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400061e7:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   1400061eb:	83 f0 1f             	xor    eax,0x1f
   1400061ee:	5d                   	pop    rbp
   1400061ef:	c3                   	ret

00000001400061f0 <bitstob>:
   1400061f0:	55                   	push   rbp
   1400061f1:	53                   	push   rbx
   1400061f2:	48 83 ec 58          	sub    rsp,0x58
   1400061f6:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400061fb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400061ff:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006202:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006206:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000620d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140006214:	eb 07                	jmp    14000621d <bitstob+0x2d>
   140006216:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140006219:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   14000621d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006220:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   140006223:	7c f1                	jl     140006216 <bitstob+0x26>
   140006225:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140006228:	89 c1                	mov    ecx,eax
   14000622a:	e8 ae 1a 00 00       	call   140007cdd <__Balloc_D2A>
   14000622f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006233:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140006236:	83 e8 01             	sub    eax,0x1
   140006239:	c1 f8 05             	sar    eax,0x5
   14000623c:	48 98                	cdqe
   14000623e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006245:	00 
   140006246:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000624a:	48 01 d0             	add    rax,rdx
   14000624d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140006251:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006255:	48 83 c0 18          	add    rax,0x18
   140006259:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000625d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006261:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006265:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006269:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000626d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006271:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140006275:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006277:	89 10                	mov    DWORD PTR [rax],edx
   140006279:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   14000627e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006282:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140006286:	73 dd                	jae    140006265 <bitstob+0x75>
   140006288:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000628c:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140006290:	48 c1 f8 02          	sar    rax,0x2
   140006294:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140006297:	eb 1d                	jmp    1400062b6 <bitstob+0xc6>
   140006299:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000629d:	75 17                	jne    1400062b6 <bitstob+0xc6>
   14000629f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062a3:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   1400062aa:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400062ae:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400062b4:	eb 59                	jmp    14000630f <bitstob+0x11f>
   1400062b6:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400062ba:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062bd:	48 98                	cdqe
   1400062bf:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400062c6:	00 
   1400062c7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400062cb:	48 01 d0             	add    rax,rdx
   1400062ce:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062d0:	85 c0                	test   eax,eax
   1400062d2:	74 c5                	je     140006299 <bitstob+0xa9>
   1400062d4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062d7:	8d 50 01             	lea    edx,[rax+0x1]
   1400062da:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062de:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400062e1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062e4:	83 c0 01             	add    eax,0x1
   1400062e7:	c1 e0 05             	shl    eax,0x5
   1400062ea:	89 c3                	mov    ebx,eax
   1400062ec:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062f0:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400062f3:	48 63 d2             	movsxd rdx,edx
   1400062f6:	48 83 c2 04          	add    rdx,0x4
   1400062fa:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   1400062fe:	89 c1                	mov    ecx,eax
   140006300:	e8 db fe ff ff       	call   1400061e0 <__hi0bits_D2A>
   140006305:	29 c3                	sub    ebx,eax
   140006307:	89 da                	mov    edx,ebx
   140006309:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000630d:	89 10                	mov    DWORD PTR [rax],edx
   14000630f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006313:	48 83 c4 58          	add    rsp,0x58
   140006317:	5b                   	pop    rbx
   140006318:	5d                   	pop    rbp
   140006319:	c3                   	ret

000000014000631a <__gdtoa>:
   14000631a:	55                   	push   rbp
   14000631b:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   140006322:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140006329:	00 
   14000632a:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   140006331:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   140006337:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   14000633e:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   140006345:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   14000634c:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006353:	8b 00                	mov    eax,DWORD PTR [rax]
   140006355:	83 e0 cf             	and    eax,0xffffffcf
   140006358:	89 c2                	mov    edx,eax
   14000635a:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006361:	89 10                	mov    DWORD PTR [rax],edx
   140006363:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   14000636a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000636c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000636f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006372:	83 e0 07             	and    eax,0x7
   140006375:	83 f8 04             	cmp    eax,0x4
   140006378:	0f 84 b0 00 00 00    	je     14000642e <__gdtoa+0x114>
   14000637e:	83 f8 04             	cmp    eax,0x4
   140006381:	0f 8f d5 00 00 00    	jg     14000645c <__gdtoa+0x142>
   140006387:	83 f8 03             	cmp    eax,0x3
   14000638a:	74 74                	je     140006400 <__gdtoa+0xe6>
   14000638c:	83 f8 03             	cmp    eax,0x3
   14000638f:	0f 8f c7 00 00 00    	jg     14000645c <__gdtoa+0x142>
   140006395:	85 c0                	test   eax,eax
   140006397:	0f 84 05 01 00 00    	je     1400064a2 <__gdtoa+0x188>
   14000639d:	85 c0                	test   eax,eax
   14000639f:	0f 88 b7 00 00 00    	js     14000645c <__gdtoa+0x142>
   1400063a5:	83 e8 01             	sub    eax,0x1
   1400063a8:	83 f8 01             	cmp    eax,0x1
   1400063ab:	0f 87 ab 00 00 00    	ja     14000645c <__gdtoa+0x142>
   1400063b1:	90                   	nop
   1400063b2:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400063b9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063bb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400063be:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   1400063c2:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400063c5:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400063cc:	49 89 c8             	mov    r8,rcx
   1400063cf:	48 89 c1             	mov    rcx,rax
   1400063d2:	e8 19 fe ff ff       	call   1400061f0 <bitstob>
   1400063d7:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400063db:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   1400063e1:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400063e4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063e8:	48 89 c1             	mov    rcx,rax
   1400063eb:	e8 31 16 00 00       	call   140007a21 <__trailz_D2A>
   1400063f0:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400063f3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400063f6:	85 c0                	test   eax,eax
   1400063f8:	0f 84 8b 00 00 00    	je     140006489 <__gdtoa+0x16f>
   1400063fe:	eb 66                	jmp    140006466 <__gdtoa+0x14c>
   140006400:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006407:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000640d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006414:	48 8d 0d 35 4f 00 00 	lea    rcx,[rip+0x4f35]        # 14000b350 <.rdata>
   14000641b:	41 b8 08 00 00 00    	mov    r8d,0x8
   140006421:	48 89 c2             	mov    rdx,rax
   140006424:	e8 79 fa ff ff       	call   140005ea2 <__nrv_alloc_D2A>
   140006429:	e9 4d 14 00 00       	jmp    14000787b <__gdtoa+0x1561>
   14000642e:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006435:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000643b:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006442:	48 8d 0d 10 4f 00 00 	lea    rcx,[rip+0x4f10]        # 14000b359 <.rdata+0x9>
   140006449:	41 b8 03 00 00 00    	mov    r8d,0x3
   14000644f:	48 89 c2             	mov    rdx,rax
   140006452:	e8 4b fa ff ff       	call   140005ea2 <__nrv_alloc_D2A>
   140006457:	e9 1f 14 00 00       	jmp    14000787b <__gdtoa+0x1561>
   14000645c:	b8 00 00 00 00       	mov    eax,0x0
   140006461:	e9 15 14 00 00       	jmp    14000787b <__gdtoa+0x1561>
   140006466:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006469:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000646d:	48 89 c1             	mov    rcx,rax
   140006470:	e8 50 14 00 00       	call   1400078c5 <__rshift_D2A>
   140006475:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006478:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   14000647e:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006481:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006484:	29 c2                	sub    edx,eax
   140006486:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   140006489:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000648d:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006490:	85 c0                	test   eax,eax
   140006492:	75 3d                	jne    1400064d1 <__gdtoa+0x1b7>
   140006494:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006498:	48 89 c1             	mov    rcx,rax
   14000649b:	e8 7e 19 00 00       	call   140007e1e <__Bfree_D2A>
   1400064a0:	eb 01                	jmp    1400064a3 <__gdtoa+0x189>
   1400064a2:	90                   	nop
   1400064a3:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400064aa:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   1400064b0:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400064b7:	48 8d 0d 9f 4e 00 00 	lea    rcx,[rip+0x4e9f]        # 14000b35d <.rdata+0xd>
   1400064be:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400064c4:	48 89 c2             	mov    rdx,rax
   1400064c7:	e8 d6 f9 ff ff       	call   140005ea2 <__nrv_alloc_D2A>
   1400064cc:	e9 aa 13 00 00       	jmp    14000787b <__gdtoa+0x1561>
   1400064d1:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   1400064d5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064d9:	48 89 c1             	mov    rcx,rax
   1400064dc:	e8 75 23 00 00       	call   140008856 <__b2d_D2A>
   1400064e1:	66 48 0f 7e c0       	movq   rax,xmm0
   1400064e6:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   1400064ea:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400064ed:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   1400064f3:	01 d0                	add    eax,edx
   1400064f5:	83 e8 01             	sub    eax,0x1
   1400064f8:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400064fb:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   1400064fe:	25 ff ff 0f 00       	and    eax,0xfffff
   140006503:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006506:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006509:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000650e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006511:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006516:	f2 0f 10 15 42 4e 00 	movsd  xmm2,QWORD PTR [rip+0x4e42]        # 14000b360 <.rdata+0x10>
   14000651d:	00 
   14000651e:	66 0f 28 c8          	movapd xmm1,xmm0
   140006522:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006526:	f2 0f 10 05 3a 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e3a]        # 14000b368 <.rdata+0x18>
   14000652d:	00 
   14000652e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006532:	f2 0f 10 05 36 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e36]        # 14000b370 <.rdata+0x20>
   140006539:	00 
   14000653a:	f2 0f 58 c8          	addsd  xmm1,xmm0
   14000653e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006541:	66 0f ef d2          	pxor   xmm2,xmm2
   140006545:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   140006549:	f2 0f 10 05 27 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e27]        # 14000b378 <.rdata+0x28>
   140006550:	00 
   140006551:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006555:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006559:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000655e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006561:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006564:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006568:	79 03                	jns    14000656d <__gdtoa+0x253>
   14000656a:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   14000656d:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   140006574:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006578:	7e 23                	jle    14000659d <__gdtoa+0x283>
   14000657a:	66 0f ef c9          	pxor   xmm1,xmm1
   14000657e:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   140006583:	f2 0f 10 05 f5 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4df5]        # 14000b380 <.rdata+0x30>
   14000658a:	00 
   14000658b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000658f:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006594:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006598:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000659d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   1400065a2:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400065a6:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   1400065a9:	66 0f ef c0          	pxor   xmm0,xmm0
   1400065ad:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   1400065b2:	76 1b                	jbe    1400065cf <__gdtoa+0x2b5>
   1400065b4:	66 0f ef c0          	pxor   xmm0,xmm0
   1400065b8:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   1400065bd:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   1400065c2:	7a 07                	jp     1400065cb <__gdtoa+0x2b1>
   1400065c4:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   1400065c9:	74 04                	je     1400065cf <__gdtoa+0x2b5>
   1400065cb:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400065cf:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   1400065d6:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   1400065d9:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   1400065dc:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   1400065e2:	01 ca                	add    edx,ecx
   1400065e4:	83 ea 01             	sub    edx,0x1
   1400065e7:	c1 e2 14             	shl    edx,0x14
   1400065ea:	01 d0                	add    eax,edx
   1400065ec:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400065ef:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400065f3:	78 2e                	js     140006623 <__gdtoa+0x309>
   1400065f5:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   1400065f9:	7f 28                	jg     140006623 <__gdtoa+0x309>
   1400065fb:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006600:	48 8b 05 79 50 00 00 	mov    rax,QWORD PTR [rip+0x5079]        # 14000b680 <.refptr.__tens_D2A>
   140006607:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000660a:	48 63 d2             	movsxd rdx,edx
   14000660d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006612:	66 0f 2f c1          	comisd xmm0,xmm1
   140006616:	76 04                	jbe    14000661c <__gdtoa+0x302>
   140006618:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000661c:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   140006623:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006626:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006629:	29 c2                	sub    edx,eax
   14000662b:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000662e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006631:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006635:	78 0f                	js     140006646 <__gdtoa+0x32c>
   140006637:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   14000663e:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006641:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   140006644:	eb 0f                	jmp    140006655 <__gdtoa+0x33b>
   140006646:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006649:	f7 d8                	neg    eax
   14000664b:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   14000664e:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   140006655:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006659:	78 15                	js     140006670 <__gdtoa+0x356>
   14000665b:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   140006662:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006665:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   140006668:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000666b:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   14000666e:	eb 15                	jmp    140006685 <__gdtoa+0x36b>
   140006670:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006673:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006676:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006679:	f7 d8                	neg    eax
   14000667b:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   14000667e:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   140006685:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000668c:	78 09                	js     140006697 <__gdtoa+0x37d>
   14000668e:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   140006695:	7e 0a                	jle    1400066a1 <__gdtoa+0x387>
   140006697:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   14000669e:	00 00 00 
   1400066a1:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   1400066a8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400066af:	7e 10                	jle    1400066c1 <__gdtoa+0x3a7>
   1400066b1:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   1400066b8:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   1400066bf:	eb 1b                	jmp    1400066dc <__gdtoa+0x3c2>
   1400066c1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400066c4:	3d f9 03 00 00       	cmp    eax,0x3f9
   1400066c9:	7f 0a                	jg     1400066d5 <__gdtoa+0x3bb>
   1400066cb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400066ce:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   1400066d3:	7d 07                	jge    1400066dc <__gdtoa+0x3c2>
   1400066d5:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   1400066dc:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   1400066e3:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   1400066ea:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400066ed:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400066f0:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400066f7:	0f 84 c5 00 00 00    	je     1400067c2 <__gdtoa+0x4a8>
   1400066fd:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006704:	0f 8f e6 00 00 00    	jg     1400067f0 <__gdtoa+0x4d6>
   14000670a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   140006711:	74 7e                	je     140006791 <__gdtoa+0x477>
   140006713:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   14000671a:	0f 8f d0 00 00 00    	jg     1400067f0 <__gdtoa+0x4d6>
   140006720:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006727:	0f 84 8e 00 00 00    	je     1400067bb <__gdtoa+0x4a1>
   14000672d:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006734:	0f 8f b6 00 00 00    	jg     1400067f0 <__gdtoa+0x4d6>
   14000673a:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006741:	7f 0e                	jg     140006751 <__gdtoa+0x437>
   140006743:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000674a:	79 13                	jns    14000675f <__gdtoa+0x445>
   14000674c:	e9 9f 00 00 00       	jmp    1400067f0 <__gdtoa+0x4d6>
   140006751:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140006758:	74 30                	je     14000678a <__gdtoa+0x470>
   14000675a:	e9 91 00 00 00       	jmp    1400067f0 <__gdtoa+0x4d6>
   14000675f:	66 0f ef c9          	pxor   xmm1,xmm1
   140006763:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   140006768:	f2 0f 10 05 18 4c 00 	movsd  xmm0,QWORD PTR [rip+0x4c18]        # 14000b388 <.rdata+0x38>
   14000676f:	00 
   140006770:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006774:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006778:	83 c0 03             	add    eax,0x3
   14000677b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000677e:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   140006785:	00 00 00 
   140006788:	eb 66                	jmp    1400067f0 <__gdtoa+0x4d6>
   14000678a:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006791:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006798:	7f 0a                	jg     1400067a4 <__gdtoa+0x48a>
   14000679a:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   1400067a1:	00 00 00 
   1400067a4:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   1400067aa:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067ad:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067b0:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   1400067b3:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400067b6:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400067b9:	eb 35                	jmp    1400067f0 <__gdtoa+0x4d6>
   1400067bb:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   1400067c2:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   1400067c8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400067cb:	01 d0                	add    eax,edx
   1400067cd:	83 c0 01             	add    eax,0x1
   1400067d0:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067d3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067d6:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400067d9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067dc:	83 e8 01             	sub    eax,0x1
   1400067df:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   1400067e2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067e5:	85 c0                	test   eax,eax
   1400067e7:	7f 07                	jg     1400067f0 <__gdtoa+0x4d6>
   1400067e9:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400067f0:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067f3:	89 c1                	mov    ecx,eax
   1400067f5:	e8 56 f6 ff ff       	call   140005e50 <__rv_alloc_D2A>
   1400067fa:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400067fe:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006802:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006806:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000680d:	7f 09                	jg     140006818 <__gdtoa+0x4fe>
   14000680f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   140006816:	eb 38                	jmp    140006850 <__gdtoa+0x536>
   140006818:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000681f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140006822:	83 e8 01             	sub    eax,0x1
   140006825:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006828:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000682c:	74 22                	je     140006850 <__gdtoa+0x536>
   14000682e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006832:	79 07                	jns    14000683b <__gdtoa+0x521>
   140006834:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   14000683b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000683e:	83 e0 08             	and    eax,0x8
   140006841:	85 c0                	test   eax,eax
   140006843:	74 0b                	je     140006850 <__gdtoa+0x536>
   140006845:	b8 03 00 00 00       	mov    eax,0x3
   14000684a:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   14000684d:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006850:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006854:	0f 88 b9 04 00 00    	js     140006d13 <__gdtoa+0x9f9>
   14000685a:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   14000685e:	0f 8f af 04 00 00    	jg     140006d13 <__gdtoa+0x9f9>
   140006864:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   140006868:	0f 84 a5 04 00 00    	je     140006d13 <__gdtoa+0x9f9>
   14000686e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006872:	0f 85 9b 04 00 00    	jne    140006d13 <__gdtoa+0x9f9>
   140006878:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000687c:	0f 85 91 04 00 00    	jne    140006d13 <__gdtoa+0x9f9>
   140006882:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006889:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   14000688e:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   140006893:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006896:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140006899:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   14000689c:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   14000689f:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   1400068a6:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400068aa:	0f 8e 98 00 00 00    	jle    140006948 <__gdtoa+0x62e>
   1400068b0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068b3:	83 e0 0f             	and    eax,0xf
   1400068b6:	89 c2                	mov    edx,eax
   1400068b8:	48 8b 05 c1 4d 00 00 	mov    rax,QWORD PTR [rip+0x4dc1]        # 14000b680 <.refptr.__tens_D2A>
   1400068bf:	48 63 d2             	movsxd rdx,edx
   1400068c2:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400068c7:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068cc:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068cf:	c1 f8 04             	sar    eax,0x4
   1400068d2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400068d5:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400068d8:	83 e0 10             	and    eax,0x10
   1400068db:	85 c0                	test   eax,eax
   1400068dd:	74 5e                	je     14000693d <__gdtoa+0x623>
   1400068df:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   1400068e3:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400068e8:	48 8b 05 c1 4c 00 00 	mov    rax,QWORD PTR [rip+0x4cc1]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400068ef:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   1400068f4:	f2 0f 5e c1          	divsd  xmm0,xmm1
   1400068f8:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400068fd:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006901:	eb 3a                	jmp    14000693d <__gdtoa+0x623>
   140006903:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006906:	83 e0 01             	and    eax,0x1
   140006909:	85 c0                	test   eax,eax
   14000690b:	74 24                	je     140006931 <__gdtoa+0x617>
   14000690d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006911:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006914:	48 8b 05 95 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c95]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000691b:	48 63 d2             	movsxd rdx,edx
   14000691e:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006923:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006928:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000692c:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006931:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006934:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006937:	83 c0 01             	add    eax,0x1
   14000693a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000693d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006941:	75 c0                	jne    140006903 <__gdtoa+0x5e9>
   140006943:	e9 8b 00 00 00       	jmp    1400069d3 <__gdtoa+0x6b9>
   140006948:	f2 0f 10 05 40 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a40]        # 14000b390 <.rdata+0x40>
   14000694f:	00 
   140006950:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006955:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006958:	f7 d8                	neg    eax
   14000695a:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   14000695d:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140006961:	74 70                	je     1400069d3 <__gdtoa+0x6b9>
   140006963:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006968:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   14000696b:	83 e0 0f             	and    eax,0xf
   14000696e:	89 c2                	mov    edx,eax
   140006970:	48 8b 05 09 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d09]        # 14000b680 <.refptr.__tens_D2A>
   140006977:	48 63 d2             	movsxd rdx,edx
   14000697a:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   14000697f:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006983:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006988:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   14000698b:	c1 f8 04             	sar    eax,0x4
   14000698e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006991:	eb 3a                	jmp    1400069cd <__gdtoa+0x6b3>
   140006993:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006996:	83 e0 01             	and    eax,0x1
   140006999:	85 c0                	test   eax,eax
   14000699b:	74 24                	je     1400069c1 <__gdtoa+0x6a7>
   14000699d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400069a1:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069a6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400069a9:	48 8b 05 00 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c00]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400069b0:	48 63 d2             	movsxd rdx,edx
   1400069b3:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400069b8:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069bc:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069c1:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   1400069c4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400069c7:	83 c0 01             	add    eax,0x1
   1400069ca:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400069cd:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400069d1:	75 c0                	jne    140006993 <__gdtoa+0x679>
   1400069d3:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400069d7:	74 47                	je     140006a20 <__gdtoa+0x706>
   1400069d9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069de:	f2 0f 10 05 aa 49 00 	movsd  xmm0,QWORD PTR [rip+0x49aa]        # 14000b390 <.rdata+0x40>
   1400069e5:	00 
   1400069e6:	66 0f 2f c1          	comisd xmm0,xmm1
   1400069ea:	76 34                	jbe    140006a20 <__gdtoa+0x706>
   1400069ec:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400069f0:	7e 2e                	jle    140006a20 <__gdtoa+0x706>
   1400069f2:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   1400069f6:	0f 8e f5 02 00 00    	jle    140006cf1 <__gdtoa+0x9d7>
   1400069fc:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400069ff:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006a02:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006a06:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a0b:	f2 0f 10 05 85 49 00 	movsd  xmm0,QWORD PTR [rip+0x4985]        # 14000b398 <.rdata+0x48>
   140006a12:	00 
   140006a13:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a17:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a1c:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006a20:	66 0f ef c9          	pxor   xmm1,xmm1
   140006a24:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006a29:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a2e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006a32:	f2 0f 10 05 66 49 00 	movsd  xmm0,QWORD PTR [rip+0x4966]        # 14000b3a0 <.rdata+0x50>
   140006a39:	00 
   140006a3a:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006a3e:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a43:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   140006a46:	2d 00 00 40 03       	sub    eax,0x3400000
   140006a4b:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   140006a4e:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a52:	75 5f                	jne    140006ab3 <__gdtoa+0x799>
   140006a54:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006a5b:	00 
   140006a5c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006a60:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006a64:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a69:	f2 0f 10 0d 37 49 00 	movsd  xmm1,QWORD PTR [rip+0x4937]        # 14000b3a8 <.rdata+0x58>
   140006a70:	00 
   140006a71:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a75:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a7a:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a7f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006a84:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a88:	0f 87 ac 07 00 00    	ja     14000723a <__gdtoa+0xf20>
   140006a8e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a93:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006a98:	f3 0f 7e 15 10 49 00 	movq   xmm2,QWORD PTR [rip+0x4910]        # 14000b3b0 <.rdata+0x60>
   140006a9f:	00 
   140006aa0:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006aa4:	66 0f 2f c1          	comisd xmm0,xmm1
   140006aa8:	0f 87 6e 07 00 00    	ja     14000721c <__gdtoa+0xf02>
   140006aae:	e9 42 02 00 00       	jmp    140006cf5 <__gdtoa+0x9db>
   140006ab3:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006ab7:	0f 84 22 01 00 00    	je     140006bdf <__gdtoa+0x8c5>
   140006abd:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006ac2:	f2 0f 10 05 f6 48 00 	movsd  xmm0,QWORD PTR [rip+0x48f6]        # 14000b3c0 <.rdata+0x70>
   140006ac9:	00 
   140006aca:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006ace:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006ad1:	8d 50 ff             	lea    edx,[rax-0x1]
   140006ad4:	48 8b 05 a5 4b 00 00 	mov    rax,QWORD PTR [rip+0x4ba5]        # 14000b680 <.refptr.__tens_D2A>
   140006adb:	48 63 d2             	movsxd rdx,edx
   140006ade:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006ae3:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006ae7:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006aec:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006af0:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006af5:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006afc:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b01:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006b06:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006b0a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006b0d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b12:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b16:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006b1b:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006b20:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b24:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b29:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006b2c:	8d 48 30             	lea    ecx,[rax+0x30]
   140006b2f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006b33:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006b37:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006b3b:	89 ca                	mov    edx,ecx
   140006b3d:	88 10                	mov    BYTE PTR [rax],dl
   140006b3f:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b44:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b49:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b4d:	76 29                	jbe    140006b78 <__gdtoa+0x85e>
   140006b4f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b54:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b58:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b5c:	7a 0e                	jp     140006b6c <__gdtoa+0x852>
   140006b5e:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b62:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b66:	0f 84 93 0c 00 00    	je     1400077ff <__gdtoa+0x14e5>
   140006b6c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006b73:	e9 87 0c 00 00       	jmp    1400077ff <__gdtoa+0x14e5>
   140006b78:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006b7d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006b82:	66 0f 28 c8          	movapd xmm1,xmm0
   140006b86:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006b8a:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b8f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b93:	0f 87 c3 02 00 00    	ja     140006e5c <__gdtoa+0xb42>
   140006b99:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006b9c:	83 c0 01             	add    eax,0x1
   140006b9f:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006ba2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ba5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006ba8:	0f 8e 46 01 00 00    	jle    140006cf4 <__gdtoa+0x9da>
   140006bae:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006bb3:	f2 0f 10 05 dd 47 00 	movsd  xmm0,QWORD PTR [rip+0x47dd]        # 14000b398 <.rdata+0x48>
   140006bba:	00 
   140006bbb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bbf:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006bc4:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006bc9:	f2 0f 10 05 c7 47 00 	movsd  xmm0,QWORD PTR [rip+0x47c7]        # 14000b398 <.rdata+0x48>
   140006bd0:	00 
   140006bd1:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bd5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006bda:	e9 1d ff ff ff       	jmp    140006afc <__gdtoa+0x7e2>
   140006bdf:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006be4:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006be7:	8d 50 ff             	lea    edx,[rax-0x1]
   140006bea:	48 8b 05 8f 4a 00 00 	mov    rax,QWORD PTR [rip+0x4a8f]        # 14000b680 <.refptr.__tens_D2A>
   140006bf1:	48 63 d2             	movsxd rdx,edx
   140006bf4:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006bf9:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bfd:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c02:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006c09:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c0e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006c13:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006c17:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006c1a:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006c1e:	74 1c                	je     140006c3c <__gdtoa+0x922>
   140006c20:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c25:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c29:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006c2e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006c33:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006c37:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c3c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006c3f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006c42:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006c46:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006c4a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006c4e:	89 ca                	mov    edx,ecx
   140006c50:	88 10                	mov    BYTE PTR [rax],dl
   140006c52:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c55:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006c58:	75 73                	jne    140006ccd <__gdtoa+0x9b3>
   140006c5a:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006c5f:	f2 0f 10 05 59 47 00 	movsd  xmm0,QWORD PTR [rip+0x4759]        # 14000b3c0 <.rdata+0x70>
   140006c66:	00 
   140006c67:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c6b:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006c70:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c75:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c7a:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006c7f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c83:	0f 87 d6 01 00 00    	ja     140006e5f <__gdtoa+0xb45>
   140006c89:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c8e:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006c93:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006c98:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006c9c:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ca0:	77 02                	ja     140006ca4 <__gdtoa+0x98a>
   140006ca2:	eb 51                	jmp    140006cf5 <__gdtoa+0x9db>
   140006ca4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ca9:	66 0f ef c9          	pxor   xmm1,xmm1
   140006cad:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006cb1:	7a 0e                	jp     140006cc1 <__gdtoa+0x9a7>
   140006cb3:	66 0f ef c9          	pxor   xmm1,xmm1
   140006cb7:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006cbb:	0f 84 41 0b 00 00    	je     140007802 <__gdtoa+0x14e8>
   140006cc1:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006cc8:	e9 35 0b 00 00       	jmp    140007802 <__gdtoa+0x14e8>
   140006ccd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006cd0:	83 c0 01             	add    eax,0x1
   140006cd3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006cd6:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006cdb:	f2 0f 10 05 b5 46 00 	movsd  xmm0,QWORD PTR [rip+0x46b5]        # 14000b398 <.rdata+0x48>
   140006ce2:	00 
   140006ce3:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006ce7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006cec:	e9 18 ff ff ff       	jmp    140006c09 <__gdtoa+0x8ef>
   140006cf1:	90                   	nop
   140006cf2:	eb 01                	jmp    140006cf5 <__gdtoa+0x9db>
   140006cf4:	90                   	nop
   140006cf5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006cf9:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006cfd:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006d02:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d07:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006d0a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006d0d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006d10:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006d13:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006d1a:	0f 88 bf 01 00 00    	js     140006edf <__gdtoa+0xbc5>
   140006d20:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006d27:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006d2a:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006d2d:	0f 8f ac 01 00 00    	jg     140006edf <__gdtoa+0xbc5>
   140006d33:	48 8b 05 46 49 00 00 	mov    rax,QWORD PTR [rip+0x4946]        # 14000b680 <.refptr.__tens_D2A>
   140006d3a:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006d3d:	48 63 d2             	movsxd rdx,edx
   140006d40:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006d45:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006d4a:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006d51:	79 45                	jns    140006d98 <__gdtoa+0xa7e>
   140006d53:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d57:	7f 3f                	jg     140006d98 <__gdtoa+0xa7e>
   140006d59:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006d60:	00 
   140006d61:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006d65:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006d69:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d6d:	0f 88 ac 04 00 00    	js     14000721f <__gdtoa+0xf05>
   140006d73:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d78:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006d7d:	f2 0f 10 05 23 46 00 	movsd  xmm0,QWORD PTR [rip+0x4623]        # 14000b3a8 <.rdata+0x58>
   140006d84:	00 
   140006d85:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006d89:	66 0f 2f c1          	comisd xmm0,xmm1
   140006d8d:	0f 83 8c 04 00 00    	jae    14000721f <__gdtoa+0xf05>
   140006d93:	e9 a6 04 00 00       	jmp    14000723e <__gdtoa+0xf24>
   140006d98:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006d9f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006da4:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006da9:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006dad:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006db0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006db5:	66 0f ef c9          	pxor   xmm1,xmm1
   140006db9:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006dbe:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006dc3:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006dc7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006dcc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006dcf:	8d 48 30             	lea    ecx,[rax+0x30]
   140006dd2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006dd6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006dda:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006dde:	89 ca                	mov    edx,ecx
   140006de0:	88 10                	mov    BYTE PTR [rax],dl
   140006de2:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006de7:	66 0f ef c9          	pxor   xmm1,xmm1
   140006deb:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006def:	7a 0e                	jp     140006dff <__gdtoa+0xae5>
   140006df1:	66 0f ef c9          	pxor   xmm1,xmm1
   140006df5:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006df9:	0f 84 da 00 00 00    	je     140006ed9 <__gdtoa+0xbbf>
   140006dff:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e02:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006e05:	0f 85 aa 00 00 00    	jne    140006eb5 <__gdtoa+0xb9b>
   140006e0b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006e0f:	74 12                	je     140006e23 <__gdtoa+0xb09>
   140006e11:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006e15:	74 4b                	je     140006e62 <__gdtoa+0xb48>
   140006e17:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e1e:	e9 e3 09 00 00       	jmp    140007806 <__gdtoa+0x14ec>
   140006e23:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e28:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006e2c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e31:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e36:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006e3b:	77 28                	ja     140006e65 <__gdtoa+0xb4b>
   140006e3d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e42:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e47:	7a 63                	jp     140006eac <__gdtoa+0xb92>
   140006e49:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e4e:	75 5c                	jne    140006eac <__gdtoa+0xb92>
   140006e50:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006e53:	83 e0 01             	and    eax,0x1
   140006e56:	85 c0                	test   eax,eax
   140006e58:	74 52                	je     140006eac <__gdtoa+0xb92>
   140006e5a:	eb 0a                	jmp    140006e66 <__gdtoa+0xb4c>
   140006e5c:	90                   	nop
   140006e5d:	eb 07                	jmp    140006e66 <__gdtoa+0xb4c>
   140006e5f:	90                   	nop
   140006e60:	eb 04                	jmp    140006e66 <__gdtoa+0xb4c>
   140006e62:	90                   	nop
   140006e63:	eb 01                	jmp    140006e66 <__gdtoa+0xb4c>
   140006e65:	90                   	nop
   140006e66:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006e6d:	eb 17                	jmp    140006e86 <__gdtoa+0xb6c>
   140006e6f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e73:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006e77:	75 0d                	jne    140006e86 <__gdtoa+0xb6c>
   140006e79:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006e7d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e81:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006e84:	eb 10                	jmp    140006e96 <__gdtoa+0xb7c>
   140006e86:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006e8b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e8f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006e92:	3c 39                	cmp    al,0x39
   140006e94:	74 d9                	je     140006e6f <__gdtoa+0xb55>
   140006e96:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e9a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006e9e:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006ea2:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006ea5:	83 c2 01             	add    edx,0x1
   140006ea8:	88 10                	mov    BYTE PTR [rax],dl
   140006eaa:	eb 2e                	jmp    140006eda <__gdtoa+0xbc0>
   140006eac:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006eb3:	eb 25                	jmp    140006eda <__gdtoa+0xbc0>
   140006eb5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006eb8:	83 c0 01             	add    eax,0x1
   140006ebb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006ebe:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ec3:	f2 0f 10 05 cd 44 00 	movsd  xmm0,QWORD PTR [rip+0x44cd]        # 14000b398 <.rdata+0x48>
   140006eca:	00 
   140006ecb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006ecf:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006ed4:	e9 c6 fe ff ff       	jmp    140006d9f <__gdtoa+0xa85>
   140006ed9:	90                   	nop
   140006eda:	e9 27 09 00 00       	jmp    140007806 <__gdtoa+0x14ec>
   140006edf:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006ee2:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006ee5:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006ee8:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006eeb:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006ef2:	00 
   140006ef3:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006ef7:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006efb:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006eff:	0f 84 e0 00 00 00    	je     140006fe5 <__gdtoa+0xccb>
   140006f05:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006f08:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006f0b:	29 c2                	sub    edx,eax
   140006f0d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f10:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f13:	8d 50 01             	lea    edx,[rax+0x1]
   140006f16:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f19:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f1f:	29 c2                	sub    edx,eax
   140006f21:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f28:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f2b:	39 c2                	cmp    edx,eax
   140006f2d:	7d 43                	jge    140006f72 <__gdtoa+0xc58>
   140006f2f:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006f36:	74 3a                	je     140006f72 <__gdtoa+0xc58>
   140006f38:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006f3f:	74 31                	je     140006f72 <__gdtoa+0xc58>
   140006f41:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f48:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f4b:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f51:	29 c2                	sub    edx,eax
   140006f53:	8d 42 01             	lea    eax,[rdx+0x1]
   140006f56:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f59:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f60:	7e 68                	jle    140006fca <__gdtoa+0xcb0>
   140006f62:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006f66:	7e 62                	jle    140006fca <__gdtoa+0xcb0>
   140006f68:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f6b:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006f6e:	7d 5a                	jge    140006fca <__gdtoa+0xcb0>
   140006f70:	eb 0a                	jmp    140006f7c <__gdtoa+0xc62>
   140006f72:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f79:	7e 50                	jle    140006fcb <__gdtoa+0xcb1>
   140006f7b:	90                   	nop
   140006f7c:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f7f:	83 e8 01             	sub    eax,0x1
   140006f82:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006f85:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006f88:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006f8b:	7c 08                	jl     140006f95 <__gdtoa+0xc7b>
   140006f8d:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f90:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006f93:	eb 19                	jmp    140006fae <__gdtoa+0xc94>
   140006f95:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006f98:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006f9b:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f9e:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006fa1:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fa4:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006fa7:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006fae:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006fb1:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006fb4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fb7:	85 c0                	test   eax,eax
   140006fb9:	79 10                	jns    140006fcb <__gdtoa+0xcb1>
   140006fbb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fbe:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006fc1:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006fc8:	eb 01                	jmp    140006fcb <__gdtoa+0xcb1>
   140006fca:	90                   	nop
   140006fcb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fce:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140006fd1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fd4:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140006fd7:	b9 01 00 00 00       	mov    ecx,0x1
   140006fdc:	e8 f6 0f 00 00       	call   140007fd7 <__i2b_D2A>
   140006fe1:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006fe5:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140006fe9:	7e 26                	jle    140007011 <__gdtoa+0xcf7>
   140006feb:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   140006fef:	7e 20                	jle    140007011 <__gdtoa+0xcf7>
   140006ff1:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140006ff4:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140006ff7:	39 c2                	cmp    edx,eax
   140006ff9:	0f 4e c2             	cmovle eax,edx
   140006ffc:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006fff:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007002:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140007005:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007008:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   14000700b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000700e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140007011:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140007015:	7e 7e                	jle    140007095 <__gdtoa+0xd7b>
   140007017:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000701b:	74 65                	je     140007082 <__gdtoa+0xd68>
   14000701d:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140007021:	7e 3b                	jle    14000705e <__gdtoa+0xd44>
   140007023:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140007026:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000702a:	48 89 c1             	mov    rcx,rax
   14000702d:	e8 11 12 00 00       	call   140008243 <__pow5mult_D2A>
   140007032:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007036:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000703a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000703e:	48 89 c1             	mov    rcx,rax
   140007041:	e8 d7 0f 00 00       	call   14000801d <__mult_D2A>
   140007046:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000704a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000704e:	48 89 c1             	mov    rcx,rax
   140007051:	e8 c8 0d 00 00       	call   140007e1e <__Bfree_D2A>
   140007056:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000705a:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000705e:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140007061:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   140007064:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007067:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000706b:	74 28                	je     140007095 <__gdtoa+0xd7b>
   14000706d:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   140007070:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007074:	48 89 c1             	mov    rcx,rax
   140007077:	e8 c7 11 00 00       	call   140008243 <__pow5mult_D2A>
   14000707c:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007080:	eb 13                	jmp    140007095 <__gdtoa+0xd7b>
   140007082:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   140007085:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007089:	48 89 c1             	mov    rcx,rax
   14000708c:	e8 b2 11 00 00       	call   140008243 <__pow5mult_D2A>
   140007091:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007095:	b9 01 00 00 00       	mov    ecx,0x1
   14000709a:	e8 38 0f 00 00       	call   140007fd7 <__i2b_D2A>
   14000709f:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070a3:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   1400070a7:	7e 13                	jle    1400070bc <__gdtoa+0xda2>
   1400070a9:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   1400070ac:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070b0:	48 89 c1             	mov    rcx,rax
   1400070b3:	e8 8b 11 00 00       	call   140008243 <__pow5mult_D2A>
   1400070b8:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070bc:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   1400070c3:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400070ca:	7f 29                	jg     1400070f5 <__gdtoa+0xddb>
   1400070cc:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   1400070cf:	83 f8 01             	cmp    eax,0x1
   1400070d2:	75 21                	jne    1400070f5 <__gdtoa+0xddb>
   1400070d4:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400070db:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400070de:	83 c0 01             	add    eax,0x1
   1400070e1:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   1400070e4:	7e 0f                	jle    1400070f5 <__gdtoa+0xddb>
   1400070e6:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   1400070ea:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   1400070ee:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   1400070f5:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   1400070f9:	74 22                	je     14000711d <__gdtoa+0xe03>
   1400070fb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070ff:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007102:	8d 50 ff             	lea    edx,[rax-0x1]
   140007105:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007109:	48 63 d2             	movsxd rdx,edx
   14000710c:	48 83 c2 04          	add    rdx,0x4
   140007110:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   140007114:	89 c1                	mov    ecx,eax
   140007116:	e8 c5 f0 ff ff       	call   1400061e0 <__hi0bits_D2A>
   14000711b:	eb 05                	jmp    140007122 <__gdtoa+0xe08>
   14000711d:	b8 1f 00 00 00       	mov    eax,0x1f
   140007122:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   140007125:	83 e8 04             	sub    eax,0x4
   140007128:	83 e0 1f             	and    eax,0x1f
   14000712b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000712e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007131:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   140007134:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007137:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   14000713a:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   14000713e:	7e 13                	jle    140007153 <__gdtoa+0xe39>
   140007140:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   140007143:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007147:	48 89 c1             	mov    rcx,rax
   14000714a:	e8 b1 12 00 00       	call   140008400 <__lshift_D2A>
   14000714f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007153:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007156:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140007159:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000715d:	7e 13                	jle    140007172 <__gdtoa+0xe58>
   14000715f:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007162:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007166:	48 89 c1             	mov    rcx,rax
   140007169:	e8 92 12 00 00       	call   140008400 <__lshift_D2A>
   14000716e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007172:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140007176:	74 5a                	je     1400071d2 <__gdtoa+0xeb8>
   140007178:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000717c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007180:	48 89 c1             	mov    rcx,rax
   140007183:	e8 05 14 00 00       	call   14000858d <__cmp_D2A>
   140007188:	85 c0                	test   eax,eax
   14000718a:	79 46                	jns    1400071d2 <__gdtoa+0xeb8>
   14000718c:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140007190:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007194:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000719a:	ba 0a 00 00 00       	mov    edx,0xa
   14000719f:	48 89 c1             	mov    rcx,rax
   1400071a2:	e8 02 0d 00 00       	call   140007ea9 <__multadd_D2A>
   1400071a7:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400071ab:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400071af:	74 1b                	je     1400071cc <__gdtoa+0xeb2>
   1400071b1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071b5:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071bb:	ba 0a 00 00 00       	mov    edx,0xa
   1400071c0:	48 89 c1             	mov    rcx,rax
   1400071c3:	e8 e1 0c 00 00       	call   140007ea9 <__multadd_D2A>
   1400071c8:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400071cc:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400071cf:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400071d2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400071d6:	0f 8f 81 00 00 00    	jg     14000725d <__gdtoa+0xf43>
   1400071dc:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400071e3:	7e 78                	jle    14000725d <__gdtoa+0xf43>
   1400071e5:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400071e9:	78 37                	js     140007222 <__gdtoa+0xf08>
   1400071eb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400071ef:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071f5:	ba 05 00 00 00       	mov    edx,0x5
   1400071fa:	48 89 c1             	mov    rcx,rax
   1400071fd:	e8 a7 0c 00 00       	call   140007ea9 <__multadd_D2A>
   140007202:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007206:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000720a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000720e:	48 89 c1             	mov    rcx,rax
   140007211:	e8 77 13 00 00       	call   14000858d <__cmp_D2A>
   140007216:	85 c0                	test   eax,eax
   140007218:	7f 23                	jg     14000723d <__gdtoa+0xf23>
   14000721a:	eb 07                	jmp    140007223 <__gdtoa+0xf09>
   14000721c:	90                   	nop
   14000721d:	eb 04                	jmp    140007223 <__gdtoa+0xf09>
   14000721f:	90                   	nop
   140007220:	eb 01                	jmp    140007223 <__gdtoa+0xf09>
   140007222:	90                   	nop
   140007223:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   140007229:	f7 d0                	not    eax
   14000722b:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   14000722e:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007235:	e9 87 05 00 00       	jmp    1400077c1 <__gdtoa+0x14a7>
   14000723a:	90                   	nop
   14000723b:	eb 01                	jmp    14000723e <__gdtoa+0xf24>
   14000723d:	90                   	nop
   14000723e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007245:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007249:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000724d:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007251:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007254:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007258:	e9 64 05 00 00       	jmp    1400077c1 <__gdtoa+0x14a7>
   14000725d:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140007261:	0f 84 14 04 00 00    	je     14000767b <__gdtoa+0x1361>
   140007267:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   14000726b:	7e 13                	jle    140007280 <__gdtoa+0xf66>
   14000726d:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   140007270:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007274:	48 89 c1             	mov    rcx,rax
   140007277:	e8 84 11 00 00       	call   140008400 <__lshift_D2A>
   14000727c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007280:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007284:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007288:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   14000728c:	74 57                	je     1400072e5 <__gdtoa+0xfcb>
   14000728e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007292:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007295:	89 c1                	mov    ecx,eax
   140007297:	e8 41 0a 00 00       	call   140007cdd <__Balloc_D2A>
   14000729c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072a0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400072a4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400072a7:	48 98                	cdqe
   1400072a9:	48 83 c0 02          	add    rax,0x2
   1400072ad:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   1400072b4:	00 
   1400072b5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400072b9:	48 8d 50 10          	lea    rdx,[rax+0x10]
   1400072bd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072c1:	48 83 c0 10          	add    rax,0x10
   1400072c5:	49 89 c8             	mov    r8,rcx
   1400072c8:	48 89 c1             	mov    rcx,rax
   1400072cb:	e8 e8 23 00 00       	call   1400096b8 <memcpy>
   1400072d0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072d4:	ba 01 00 00 00       	mov    edx,0x1
   1400072d9:	48 89 c1             	mov    rcx,rax
   1400072dc:	e8 1f 11 00 00       	call   140008400 <__lshift_D2A>
   1400072e1:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072e5:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400072ec:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400072f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072f4:	48 89 c1             	mov    rcx,rax
   1400072f7:	e8 62 ec ff ff       	call   140005f5e <__quorem_D2A>
   1400072fc:	83 c0 30             	add    eax,0x30
   1400072ff:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007302:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007306:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000730a:	48 89 c1             	mov    rcx,rax
   14000730d:	e8 7b 12 00 00       	call   14000858d <__cmp_D2A>
   140007312:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007315:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007319:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000731d:	48 89 c1             	mov    rcx,rax
   140007320:	e8 38 13 00 00       	call   14000865d <__diff_D2A>
   140007325:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140007329:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   14000732d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140007330:	85 c0                	test   eax,eax
   140007332:	75 15                	jne    140007349 <__gdtoa+0x102f>
   140007334:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140007338:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000733c:	48 89 c1             	mov    rcx,rax
   14000733f:	e8 49 12 00 00       	call   14000858d <__cmp_D2A>
   140007344:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007347:	eb 07                	jmp    140007350 <__gdtoa+0x1036>
   140007349:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   140007350:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140007354:	48 89 c1             	mov    rcx,rax
   140007357:	e8 c2 0a 00 00       	call   140007e1e <__Bfree_D2A>
   14000735c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007360:	75 70                	jne    1400073d2 <__gdtoa+0x10b8>
   140007362:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007369:	75 67                	jne    1400073d2 <__gdtoa+0x10b8>
   14000736b:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007372:	8b 00                	mov    eax,DWORD PTR [rax]
   140007374:	83 e0 01             	and    eax,0x1
   140007377:	85 c0                	test   eax,eax
   140007379:	75 57                	jne    1400073d2 <__gdtoa+0x10b8>
   14000737b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000737f:	75 51                	jne    1400073d2 <__gdtoa+0x10b8>
   140007381:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007385:	0f 84 01 02 00 00    	je     14000758c <__gdtoa+0x1272>
   14000738b:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000738f:	7f 20                	jg     1400073b1 <__gdtoa+0x1097>
   140007391:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007395:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007398:	83 f8 01             	cmp    eax,0x1
   14000739b:	7f 0b                	jg     1400073a8 <__gdtoa+0x108e>
   14000739d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073a1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400073a4:	85 c0                	test   eax,eax
   1400073a6:	74 14                	je     1400073bc <__gdtoa+0x10a2>
   1400073a8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400073af:	eb 0b                	jmp    1400073bc <__gdtoa+0x10a2>
   1400073b1:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   1400073b5:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400073bc:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400073c0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400073c4:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400073c8:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400073cb:	88 10                	mov    BYTE PTR [rax],dl
   1400073cd:	e9 ef 03 00 00       	jmp    1400077c1 <__gdtoa+0x14a7>
   1400073d2:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073d6:	78 2b                	js     140007403 <__gdtoa+0x10e9>
   1400073d8:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073dc:	0f 85 96 01 00 00    	jne    140007578 <__gdtoa+0x125e>
   1400073e2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400073e9:	0f 85 89 01 00 00    	jne    140007578 <__gdtoa+0x125e>
   1400073ef:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400073f6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400073f8:	83 e0 01             	and    eax,0x1
   1400073fb:	85 c0                	test   eax,eax
   1400073fd:	0f 85 75 01 00 00    	jne    140007578 <__gdtoa+0x125e>
   140007403:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007407:	0f 84 db 00 00 00    	je     1400074e8 <__gdtoa+0x11ce>
   14000740d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007411:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007414:	83 f8 01             	cmp    eax,0x1
   140007417:	7f 0f                	jg     140007428 <__gdtoa+0x110e>
   140007419:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000741d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007420:	85 c0                	test   eax,eax
   140007422:	0f 84 c0 00 00 00    	je     1400074e8 <__gdtoa+0x11ce>
   140007428:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   14000742c:	0f 85 83 00 00 00    	jne    1400074b5 <__gdtoa+0x119b>
   140007432:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007439:	e9 24 01 00 00       	jmp    140007562 <__gdtoa+0x1248>
   14000743e:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007442:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007446:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000744a:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000744d:	88 10                	mov    BYTE PTR [rax],dl
   14000744f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007453:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007459:	ba 0a 00 00 00       	mov    edx,0xa
   14000745e:	48 89 c1             	mov    rcx,rax
   140007461:	e8 43 0a 00 00       	call   140007ea9 <__multadd_D2A>
   140007466:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000746a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000746e:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007472:	75 08                	jne    14000747c <__gdtoa+0x1162>
   140007474:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007478:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   14000747c:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007480:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007484:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007488:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000748e:	ba 0a 00 00 00       	mov    edx,0xa
   140007493:	48 89 c1             	mov    rcx,rax
   140007496:	e8 0e 0a 00 00       	call   140007ea9 <__multadd_D2A>
   14000749b:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000749f:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400074a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074a7:	48 89 c1             	mov    rcx,rax
   1400074aa:	e8 af ea ff ff       	call   140005f5e <__quorem_D2A>
   1400074af:	83 c0 30             	add    eax,0x30
   1400074b2:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400074b5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400074b9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400074bd:	48 89 c1             	mov    rcx,rax
   1400074c0:	e8 c8 10 00 00       	call   14000858d <__cmp_D2A>
   1400074c5:	85 c0                	test   eax,eax
   1400074c7:	0f 8f 71 ff ff ff    	jg     14000743e <__gdtoa+0x1124>
   1400074cd:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400074d0:	8d 50 01             	lea    edx,[rax+0x1]
   1400074d3:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   1400074d6:	83 f8 39             	cmp    eax,0x39
   1400074d9:	0f 84 b0 00 00 00    	je     14000758f <__gdtoa+0x1275>
   1400074df:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400074e6:	eb 7a                	jmp    140007562 <__gdtoa+0x1248>
   1400074e8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074ec:	7e 53                	jle    140007541 <__gdtoa+0x1227>
   1400074ee:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074f2:	ba 01 00 00 00       	mov    edx,0x1
   1400074f7:	48 89 c1             	mov    rcx,rax
   1400074fa:	e8 01 0f 00 00       	call   140008400 <__lshift_D2A>
   1400074ff:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007503:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007507:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000750b:	48 89 c1             	mov    rcx,rax
   14000750e:	e8 7a 10 00 00       	call   14000858d <__cmp_D2A>
   140007513:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007516:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000751a:	7f 10                	jg     14000752c <__gdtoa+0x1212>
   14000751c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007520:	75 18                	jne    14000753a <__gdtoa+0x1220>
   140007522:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007525:	83 e0 01             	and    eax,0x1
   140007528:	85 c0                	test   eax,eax
   14000752a:	74 0e                	je     14000753a <__gdtoa+0x1220>
   14000752c:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000752f:	8d 50 01             	lea    edx,[rax+0x1]
   140007532:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007535:	83 f8 39             	cmp    eax,0x39
   140007538:	74 58                	je     140007592 <__gdtoa+0x1278>
   14000753a:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007541:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007545:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007548:	83 f8 01             	cmp    eax,0x1
   14000754b:	7f 0b                	jg     140007558 <__gdtoa+0x123e>
   14000754d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007551:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007554:	85 c0                	test   eax,eax
   140007556:	74 09                	je     140007561 <__gdtoa+0x1247>
   140007558:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000755f:	eb 01                	jmp    140007562 <__gdtoa+0x1248>
   140007561:	90                   	nop
   140007562:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007566:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000756a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000756e:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007571:	88 10                	mov    BYTE PTR [rax],dl
   140007573:	e9 49 02 00 00       	jmp    1400077c1 <__gdtoa+0x14a7>
   140007578:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000757c:	7e 52                	jle    1400075d0 <__gdtoa+0x12b6>
   14000757e:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007582:	74 4c                	je     1400075d0 <__gdtoa+0x12b6>
   140007584:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007588:	75 24                	jne    1400075ae <__gdtoa+0x1294>
   14000758a:	eb 07                	jmp    140007593 <__gdtoa+0x1279>
   14000758c:	90                   	nop
   14000758d:	eb 04                	jmp    140007593 <__gdtoa+0x1279>
   14000758f:	90                   	nop
   140007590:	eb 01                	jmp    140007593 <__gdtoa+0x1279>
   140007592:	90                   	nop
   140007593:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007597:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000759b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000759f:	c6 00 39             	mov    BYTE PTR [rax],0x39
   1400075a2:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075a9:	e9 9d 01 00 00       	jmp    14000774b <__gdtoa+0x1431>
   1400075ae:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075b5:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400075b8:	8d 48 01             	lea    ecx,[rax+0x1]
   1400075bb:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075bf:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075c3:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075c7:	89 ca                	mov    edx,ecx
   1400075c9:	88 10                	mov    BYTE PTR [rax],dl
   1400075cb:	e9 f1 01 00 00       	jmp    1400077c1 <__gdtoa+0x14a7>
   1400075d0:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075d4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075d8:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075dc:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400075df:	88 10                	mov    BYTE PTR [rax],dl
   1400075e1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400075e4:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   1400075e7:	0f 84 ea 00 00 00    	je     1400076d7 <__gdtoa+0x13bd>
   1400075ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075f1:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075f7:	ba 0a 00 00 00       	mov    edx,0xa
   1400075fc:	48 89 c1             	mov    rcx,rax
   1400075ff:	e8 a5 08 00 00       	call   140007ea9 <__multadd_D2A>
   140007604:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007608:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000760c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007610:	75 25                	jne    140007637 <__gdtoa+0x131d>
   140007612:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007616:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000761c:	ba 0a 00 00 00       	mov    edx,0xa
   140007621:	48 89 c1             	mov    rcx,rax
   140007624:	e8 80 08 00 00       	call   140007ea9 <__multadd_D2A>
   140007629:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000762d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007631:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007635:	eb 36                	jmp    14000766d <__gdtoa+0x1353>
   140007637:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000763b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007641:	ba 0a 00 00 00       	mov    edx,0xa
   140007646:	48 89 c1             	mov    rcx,rax
   140007649:	e8 5b 08 00 00       	call   140007ea9 <__multadd_D2A>
   14000764e:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007652:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007656:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000765c:	ba 0a 00 00 00       	mov    edx,0xa
   140007661:	48 89 c1             	mov    rcx,rax
   140007664:	e8 40 08 00 00       	call   140007ea9 <__multadd_D2A>
   140007669:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000766d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007670:	83 c0 01             	add    eax,0x1
   140007673:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007676:	e9 71 fc ff ff       	jmp    1400072ec <__gdtoa+0xfd2>
   14000767b:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140007682:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007686:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000768a:	48 89 c1             	mov    rcx,rax
   14000768d:	e8 cc e8 ff ff       	call   140005f5e <__quorem_D2A>
   140007692:	83 c0 30             	add    eax,0x30
   140007695:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007698:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000769c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076a0:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076a4:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400076a7:	88 10                	mov    BYTE PTR [rax],dl
   1400076a9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076ac:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   1400076af:	7e 29                	jle    1400076da <__gdtoa+0x13c0>
   1400076b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076b5:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400076bb:	ba 0a 00 00 00       	mov    edx,0xa
   1400076c0:	48 89 c1             	mov    rcx,rax
   1400076c3:	e8 e1 07 00 00       	call   140007ea9 <__multadd_D2A>
   1400076c8:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400076cc:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076cf:	83 c0 01             	add    eax,0x1
   1400076d2:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400076d5:	eb ab                	jmp    140007682 <__gdtoa+0x1368>
   1400076d7:	90                   	nop
   1400076d8:	eb 01                	jmp    1400076db <__gdtoa+0x13c1>
   1400076da:	90                   	nop
   1400076db:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400076df:	74 26                	je     140007707 <__gdtoa+0x13ed>
   1400076e1:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400076e5:	0f 84 ae 00 00 00    	je     140007799 <__gdtoa+0x147f>
   1400076eb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076ef:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400076f2:	83 f8 01             	cmp    eax,0x1
   1400076f5:	7f 50                	jg     140007747 <__gdtoa+0x142d>
   1400076f7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076fb:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400076fe:	85 c0                	test   eax,eax
   140007700:	75 45                	jne    140007747 <__gdtoa+0x142d>
   140007702:	e9 92 00 00 00       	jmp    140007799 <__gdtoa+0x147f>
   140007707:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000770b:	ba 01 00 00 00       	mov    edx,0x1
   140007710:	48 89 c1             	mov    rcx,rax
   140007713:	e8 e8 0c 00 00       	call   140008400 <__lshift_D2A>
   140007718:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000771c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007720:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007724:	48 89 c1             	mov    rcx,rax
   140007727:	e8 61 0e 00 00       	call   14000858d <__cmp_D2A>
   14000772c:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   14000772f:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007733:	7f 15                	jg     14000774a <__gdtoa+0x1430>
   140007735:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007739:	75 61                	jne    14000779c <__gdtoa+0x1482>
   14000773b:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000773e:	83 e0 01             	and    eax,0x1
   140007741:	85 c0                	test   eax,eax
   140007743:	74 5a                	je     14000779f <__gdtoa+0x1485>
   140007745:	eb 04                	jmp    14000774b <__gdtoa+0x1431>
   140007747:	90                   	nop
   140007748:	eb 01                	jmp    14000774b <__gdtoa+0x1431>
   14000774a:	90                   	nop
   14000774b:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007752:	eb 1f                	jmp    140007773 <__gdtoa+0x1459>
   140007754:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007758:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000775c:	75 15                	jne    140007773 <__gdtoa+0x1459>
   14000775e:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007762:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007766:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000776a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000776e:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007771:	eb 4e                	jmp    1400077c1 <__gdtoa+0x14a7>
   140007773:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140007778:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000777c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000777f:	3c 39                	cmp    al,0x39
   140007781:	74 d1                	je     140007754 <__gdtoa+0x143a>
   140007783:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007787:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000778b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000778f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140007792:	83 c2 01             	add    edx,0x1
   140007795:	88 10                	mov    BYTE PTR [rax],dl
   140007797:	eb 28                	jmp    1400077c1 <__gdtoa+0x14a7>
   140007799:	90                   	nop
   14000779a:	eb 04                	jmp    1400077a0 <__gdtoa+0x1486>
   14000779c:	90                   	nop
   14000779d:	eb 01                	jmp    1400077a0 <__gdtoa+0x1486>
   14000779f:	90                   	nop
   1400077a0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077a4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400077a7:	83 f8 01             	cmp    eax,0x1
   1400077aa:	7f 0b                	jg     1400077b7 <__gdtoa+0x149d>
   1400077ac:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077b0:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400077b3:	85 c0                	test   eax,eax
   1400077b5:	74 09                	je     1400077c0 <__gdtoa+0x14a6>
   1400077b7:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400077be:	eb 01                	jmp    1400077c1 <__gdtoa+0x14a7>
   1400077c0:	90                   	nop
   1400077c1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400077c5:	48 89 c1             	mov    rcx,rax
   1400077c8:	e8 51 06 00 00       	call   140007e1e <__Bfree_D2A>
   1400077cd:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   1400077d2:	74 31                	je     140007805 <__gdtoa+0x14eb>
   1400077d4:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400077d9:	74 16                	je     1400077f1 <__gdtoa+0x14d7>
   1400077db:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400077df:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400077e3:	74 0c                	je     1400077f1 <__gdtoa+0x14d7>
   1400077e5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400077e9:	48 89 c1             	mov    rcx,rax
   1400077ec:	e8 2d 06 00 00       	call   140007e1e <__Bfree_D2A>
   1400077f1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400077f5:	48 89 c1             	mov    rcx,rax
   1400077f8:	e8 21 06 00 00       	call   140007e1e <__Bfree_D2A>
   1400077fd:	eb 0e                	jmp    14000780d <__gdtoa+0x14f3>
   1400077ff:	90                   	nop
   140007800:	eb 0b                	jmp    14000780d <__gdtoa+0x14f3>
   140007802:	90                   	nop
   140007803:	eb 08                	jmp    14000780d <__gdtoa+0x14f3>
   140007805:	90                   	nop
   140007806:	eb 05                	jmp    14000780d <__gdtoa+0x14f3>
   140007808:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000780d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007811:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140007815:	73 0f                	jae    140007826 <__gdtoa+0x150c>
   140007817:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000781b:	48 83 e8 01          	sub    rax,0x1
   14000781f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140007822:	3c 30                	cmp    al,0x30
   140007824:	74 e2                	je     140007808 <__gdtoa+0x14ee>
   140007826:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000782a:	48 89 c1             	mov    rcx,rax
   14000782d:	e8 ec 05 00 00       	call   140007e1e <__Bfree_D2A>
   140007832:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007836:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140007839:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000783c:	8d 50 01             	lea    edx,[rax+0x1]
   14000783f:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140007846:	89 10                	mov    DWORD PTR [rax],edx
   140007848:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   14000784f:	00 
   140007850:	74 0e                	je     140007860 <__gdtoa+0x1546>
   140007852:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140007859:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   14000785d:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007860:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007867:	8b 00                	mov    eax,DWORD PTR [rax]
   140007869:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   14000786c:	89 c2                	mov    edx,eax
   14000786e:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007875:	89 10                	mov    DWORD PTR [rax],edx
   140007877:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000787b:	48 81 c4 00 01 00 00 	add    rsp,0x100
   140007882:	5d                   	pop    rbp
   140007883:	c3                   	ret
   140007884:	90                   	nop
   140007885:	90                   	nop
   140007886:	90                   	nop
   140007887:	90                   	nop
   140007888:	90                   	nop
   140007889:	90                   	nop
   14000788a:	90                   	nop
   14000788b:	90                   	nop
   14000788c:	90                   	nop
   14000788d:	90                   	nop
   14000788e:	90                   	nop
   14000788f:	90                   	nop

0000000140007890 <__lo0bits_D2A>:
   140007890:	55                   	push   rbp
   140007891:	48 89 e5             	mov    rbp,rsp
   140007894:	48 83 ec 10          	sub    rsp,0x10
   140007898:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000789c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078a0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400078a2:	f3 0f bc c0          	tzcnt  eax,eax
   1400078a6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400078a9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078ad:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078af:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400078b2:	89 c1                	mov    ecx,eax
   1400078b4:	d3 ea                	shr    edx,cl
   1400078b6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078ba:	89 10                	mov    DWORD PTR [rax],edx
   1400078bc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400078bf:	48 83 c4 10          	add    rsp,0x10
   1400078c3:	5d                   	pop    rbp
   1400078c4:	c3                   	ret

00000001400078c5 <__rshift_D2A>:
   1400078c5:	55                   	push   rbp
   1400078c6:	48 89 e5             	mov    rbp,rsp
   1400078c9:	48 83 ec 20          	sub    rsp,0x20
   1400078cd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400078d1:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400078d4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078d8:	48 83 c0 18          	add    rax,0x18
   1400078dc:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400078e0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400078e4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400078e8:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400078eb:	c1 f8 05             	sar    eax,0x5
   1400078ee:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400078f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078f5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400078f8:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   1400078fb:	0f 8d e4 00 00 00    	jge    1400079e5 <__rshift_D2A+0x120>
   140007901:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007905:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007908:	48 98                	cdqe
   14000790a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007911:	00 
   140007912:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007916:	48 01 d0             	add    rax,rdx
   140007919:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000791d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007920:	48 98                	cdqe
   140007922:	48 c1 e0 02          	shl    rax,0x2
   140007926:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   14000792a:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000792e:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140007932:	0f 84 a3 00 00 00    	je     1400079db <__rshift_D2A+0x116>
   140007938:	b8 20 00 00 00       	mov    eax,0x20
   14000793d:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   140007940:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007943:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007947:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000794b:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000794f:	8b 10                	mov    edx,DWORD PTR [rax]
   140007951:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007954:	89 c1                	mov    ecx,eax
   140007956:	d3 ea                	shr    edx,cl
   140007958:	89 d0                	mov    eax,edx
   14000795a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000795d:	eb 3c                	jmp    14000799b <__rshift_D2A+0xd6>
   14000795f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007963:	8b 10                	mov    edx,DWORD PTR [rax]
   140007965:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007968:	89 c1                	mov    ecx,eax
   14000796a:	d3 e2                	shl    edx,cl
   14000796c:	89 d1                	mov    ecx,edx
   14000796e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007972:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007976:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000797a:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   14000797d:	89 ca                	mov    edx,ecx
   14000797f:	89 10                	mov    DWORD PTR [rax],edx
   140007981:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007985:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007989:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000798d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000798f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007992:	89 c1                	mov    ecx,eax
   140007994:	d3 ea                	shr    edx,cl
   140007996:	89 d0                	mov    eax,edx
   140007998:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000799b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000799f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   1400079a3:	72 ba                	jb     14000795f <__rshift_D2A+0x9a>
   1400079a5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079a9:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400079ac:	89 10                	mov    DWORD PTR [rax],edx
   1400079ae:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079b2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400079b4:	85 c0                	test   eax,eax
   1400079b6:	74 2d                	je     1400079e5 <__rshift_D2A+0x120>
   1400079b8:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   1400079bd:	eb 26                	jmp    1400079e5 <__rshift_D2A+0x120>
   1400079bf:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400079c3:	48 8d 42 04          	lea    rax,[rdx+0x4]
   1400079c7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400079cb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079cf:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400079d3:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   1400079d7:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400079d9:	89 10                	mov    DWORD PTR [rax],edx
   1400079db:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079df:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   1400079e3:	72 da                	jb     1400079bf <__rshift_D2A+0xfa>
   1400079e5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079e9:	48 83 c0 18          	add    rax,0x18
   1400079ed:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400079f1:	48 29 c2             	sub    rdx,rax
   1400079f4:	48 89 d0             	mov    rax,rdx
   1400079f7:	48 c1 f8 02          	sar    rax,0x2
   1400079fb:	89 c2                	mov    edx,eax
   1400079fd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a01:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007a04:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a08:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a0b:	85 c0                	test   eax,eax
   140007a0d:	75 0b                	jne    140007a1a <__rshift_D2A+0x155>
   140007a0f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a13:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   140007a1a:	90                   	nop
   140007a1b:	48 83 c4 20          	add    rsp,0x20
   140007a1f:	5d                   	pop    rbp
   140007a20:	c3                   	ret

0000000140007a21 <__trailz_D2A>:
   140007a21:	55                   	push   rbp
   140007a22:	48 89 e5             	mov    rbp,rsp
   140007a25:	48 83 ec 40          	sub    rsp,0x40
   140007a29:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007a2d:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a34:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a38:	48 83 c0 18          	add    rax,0x18
   140007a3c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a40:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a44:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a47:	48 98                	cdqe
   140007a49:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007a50:	00 
   140007a51:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a55:	48 01 d0             	add    rax,rdx
   140007a58:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007a5c:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a63:	eb 09                	jmp    140007a6e <__trailz_D2A+0x4d>
   140007a65:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   140007a69:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   140007a6e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a72:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a76:	73 0a                	jae    140007a82 <__trailz_D2A+0x61>
   140007a78:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a7c:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a7e:	85 c0                	test   eax,eax
   140007a80:	74 e3                	je     140007a65 <__trailz_D2A+0x44>
   140007a82:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a86:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a8a:	73 18                	jae    140007aa4 <__trailz_D2A+0x83>
   140007a8c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a90:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a92:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007a95:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007a99:	48 89 c1             	mov    rcx,rax
   140007a9c:	e8 ef fd ff ff       	call   140007890 <__lo0bits_D2A>
   140007aa1:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007aa4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007aa7:	48 83 c4 40          	add    rsp,0x40
   140007aab:	5d                   	pop    rbp
   140007aac:	c3                   	ret
   140007aad:	90                   	nop
   140007aae:	90                   	nop
   140007aaf:	90                   	nop

0000000140007ab0 <dtoa_lock_cleanup>:
   140007ab0:	55                   	push   rbp
   140007ab1:	48 89 e5             	mov    rbp,rsp
   140007ab4:	48 83 ec 40          	sub    rsp,0x40
   140007ab8:	48 8d 05 31 77 00 00 	lea    rax,[rip+0x7731]        # 14000f1f0 <dtoa_CS_init>
   140007abf:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007ac3:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007aca:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007acd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007ad1:	87 10                	xchg   DWORD PTR [rax],edx
   140007ad3:	89 d0                	mov    eax,edx
   140007ad5:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007ad8:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007adc:	75 3d                	jne    140007b1b <dtoa_lock_cleanup+0x6b>
   140007ade:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007ae5:	eb 2e                	jmp    140007b15 <dtoa_lock_cleanup+0x65>
   140007ae7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007aea:	48 63 d0             	movsxd rdx,eax
   140007aed:	48 89 d0             	mov    rax,rdx
   140007af0:	48 c1 e0 02          	shl    rax,0x2
   140007af4:	48 01 d0             	add    rax,rdx
   140007af7:	48 c1 e0 03          	shl    rax,0x3
   140007afb:	48 8d 15 9e 76 00 00 	lea    rdx,[rip+0x769e]        # 14000f1a0 <dtoa_CritSec>
   140007b02:	48 01 d0             	add    rax,rdx
   140007b05:	48 89 c1             	mov    rcx,rax
   140007b08:	48 8b 05 d9 86 00 00 	mov    rax,QWORD PTR [rip+0x86d9]        # 1400101e8 <__IAT_start__>
   140007b0f:	ff d0                	call   rax
   140007b11:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b15:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b19:	7e cc                	jle    140007ae7 <dtoa_lock_cleanup+0x37>
   140007b1b:	90                   	nop
   140007b1c:	48 83 c4 40          	add    rsp,0x40
   140007b20:	5d                   	pop    rbp
   140007b21:	c3                   	ret

0000000140007b22 <dtoa_lock>:
   140007b22:	55                   	push   rbp
   140007b23:	48 89 e5             	mov    rbp,rsp
   140007b26:	48 83 ec 40          	sub    rsp,0x40
   140007b2a:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007b2d:	8b 05 bd 76 00 00    	mov    eax,DWORD PTR [rip+0x76bd]        # 14000f1f0 <dtoa_CS_init>
   140007b33:	83 f8 02             	cmp    eax,0x2
   140007b36:	75 2c                	jne    140007b64 <dtoa_lock+0x42>
   140007b38:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007b3b:	48 89 d0             	mov    rax,rdx
   140007b3e:	48 c1 e0 02          	shl    rax,0x2
   140007b42:	48 01 d0             	add    rax,rdx
   140007b45:	48 c1 e0 03          	shl    rax,0x3
   140007b49:	48 8d 15 50 76 00 00 	lea    rdx,[rip+0x7650]        # 14000f1a0 <dtoa_CritSec>
   140007b50:	48 01 d0             	add    rax,rdx
   140007b53:	48 89 c1             	mov    rcx,rax
   140007b56:	48 8b 05 93 86 00 00 	mov    rax,QWORD PTR [rip+0x8693]        # 1400101f0 <__imp_EnterCriticalSection>
   140007b5d:	ff d0                	call   rax
   140007b5f:	e9 ea 00 00 00       	jmp    140007c4e <dtoa_lock+0x12c>
   140007b64:	8b 05 86 76 00 00    	mov    eax,DWORD PTR [rip+0x7686]        # 14000f1f0 <dtoa_CS_init>
   140007b6a:	85 c0                	test   eax,eax
   140007b6c:	0f 85 9e 00 00 00    	jne    140007c10 <dtoa_lock+0xee>
   140007b72:	48 8d 05 77 76 00 00 	lea    rax,[rip+0x7677]        # 14000f1f0 <dtoa_CS_init>
   140007b79:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007b7d:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007b84:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007b87:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007b8b:	87 10                	xchg   DWORD PTR [rax],edx
   140007b8d:	89 d0                	mov    eax,edx
   140007b8f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007b92:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007b96:	75 58                	jne    140007bf0 <dtoa_lock+0xce>
   140007b98:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007b9f:	eb 2e                	jmp    140007bcf <dtoa_lock+0xad>
   140007ba1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007ba4:	48 63 d0             	movsxd rdx,eax
   140007ba7:	48 89 d0             	mov    rax,rdx
   140007baa:	48 c1 e0 02          	shl    rax,0x2
   140007bae:	48 01 d0             	add    rax,rdx
   140007bb1:	48 c1 e0 03          	shl    rax,0x3
   140007bb5:	48 8d 15 e4 75 00 00 	lea    rdx,[rip+0x75e4]        # 14000f1a0 <dtoa_CritSec>
   140007bbc:	48 01 d0             	add    rax,rdx
   140007bbf:	48 89 c1             	mov    rcx,rax
   140007bc2:	48 8b 05 57 86 00 00 	mov    rax,QWORD PTR [rip+0x8657]        # 140010220 <__imp_InitializeCriticalSection>
   140007bc9:	ff d0                	call   rax
   140007bcb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007bcf:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007bd3:	7e cc                	jle    140007ba1 <dtoa_lock+0x7f>
   140007bd5:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007ab0 <dtoa_lock_cleanup>
   140007bdc:	48 89 c1             	mov    rcx,rax
   140007bdf:	e8 4b 9a ff ff       	call   14000162f <atexit>
   140007be4:	c7 05 02 76 00 00 02 	mov    DWORD PTR [rip+0x7602],0x2        # 14000f1f0 <dtoa_CS_init>
   140007beb:	00 00 00 
   140007bee:	eb 20                	jmp    140007c10 <dtoa_lock+0xee>
   140007bf0:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007bf4:	75 1a                	jne    140007c10 <dtoa_lock+0xee>
   140007bf6:	c7 05 f0 75 00 00 02 	mov    DWORD PTR [rip+0x75f0],0x2        # 14000f1f0 <dtoa_CS_init>
   140007bfd:	00 00 00 
   140007c00:	eb 0e                	jmp    140007c10 <dtoa_lock+0xee>
   140007c02:	b9 01 00 00 00       	mov    ecx,0x1
   140007c07:	48 8b 05 3a 86 00 00 	mov    rax,QWORD PTR [rip+0x863a]        # 140010248 <__imp_Sleep>
   140007c0e:	ff d0                	call   rax
   140007c10:	8b 05 da 75 00 00    	mov    eax,DWORD PTR [rip+0x75da]        # 14000f1f0 <dtoa_CS_init>
   140007c16:	83 f8 01             	cmp    eax,0x1
   140007c19:	74 e7                	je     140007c02 <dtoa_lock+0xe0>
   140007c1b:	8b 05 cf 75 00 00    	mov    eax,DWORD PTR [rip+0x75cf]        # 14000f1f0 <dtoa_CS_init>
   140007c21:	83 f8 02             	cmp    eax,0x2
   140007c24:	75 28                	jne    140007c4e <dtoa_lock+0x12c>
   140007c26:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c29:	48 89 d0             	mov    rax,rdx
   140007c2c:	48 c1 e0 02          	shl    rax,0x2
   140007c30:	48 01 d0             	add    rax,rdx
   140007c33:	48 c1 e0 03          	shl    rax,0x3
   140007c37:	48 8d 15 62 75 00 00 	lea    rdx,[rip+0x7562]        # 14000f1a0 <dtoa_CritSec>
   140007c3e:	48 01 d0             	add    rax,rdx
   140007c41:	48 89 c1             	mov    rcx,rax
   140007c44:	48 8b 05 a5 85 00 00 	mov    rax,QWORD PTR [rip+0x85a5]        # 1400101f0 <__imp_EnterCriticalSection>
   140007c4b:	ff d0                	call   rax
   140007c4d:	90                   	nop
   140007c4e:	48 83 c4 40          	add    rsp,0x40
   140007c52:	5d                   	pop    rbp
   140007c53:	c3                   	ret

0000000140007c54 <dtoa_unlock>:
   140007c54:	55                   	push   rbp
   140007c55:	48 89 e5             	mov    rbp,rsp
   140007c58:	48 83 ec 20          	sub    rsp,0x20
   140007c5c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c5f:	8b 05 8b 75 00 00    	mov    eax,DWORD PTR [rip+0x758b]        # 14000f1f0 <dtoa_CS_init>
   140007c65:	83 f8 02             	cmp    eax,0x2
   140007c68:	75 27                	jne    140007c91 <dtoa_unlock+0x3d>
   140007c6a:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c6d:	48 89 d0             	mov    rax,rdx
   140007c70:	48 c1 e0 02          	shl    rax,0x2
   140007c74:	48 01 d0             	add    rax,rdx
   140007c77:	48 c1 e0 03          	shl    rax,0x3
   140007c7b:	48 8d 15 1e 75 00 00 	lea    rdx,[rip+0x751e]        # 14000f1a0 <dtoa_CritSec>
   140007c82:	48 01 d0             	add    rax,rdx
   140007c85:	48 89 c1             	mov    rcx,rax
   140007c88:	48 8b 05 99 85 00 00 	mov    rax,QWORD PTR [rip+0x8599]        # 140010228 <__imp_LeaveCriticalSection>
   140007c8f:	ff d0                	call   rax
   140007c91:	90                   	nop
   140007c92:	48 83 c4 20          	add    rsp,0x20
   140007c96:	5d                   	pop    rbp
   140007c97:	c3                   	ret

0000000140007c98 <__lo0bits_D2A>:
   140007c98:	55                   	push   rbp
   140007c99:	48 89 e5             	mov    rbp,rsp
   140007c9c:	48 83 ec 10          	sub    rsp,0x10
   140007ca0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007ca4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ca8:	8b 00                	mov    eax,DWORD PTR [rax]
   140007caa:	f3 0f bc c0          	tzcnt  eax,eax
   140007cae:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007cb1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007cb5:	8b 10                	mov    edx,DWORD PTR [rax]
   140007cb7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007cba:	89 c1                	mov    ecx,eax
   140007cbc:	d3 ea                	shr    edx,cl
   140007cbe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007cc2:	89 10                	mov    DWORD PTR [rax],edx
   140007cc4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007cc7:	48 83 c4 10          	add    rsp,0x10
   140007ccb:	5d                   	pop    rbp
   140007ccc:	c3                   	ret

0000000140007ccd <__hi0bits_D2A>:
   140007ccd:	55                   	push   rbp
   140007cce:	48 89 e5             	mov    rbp,rsp
   140007cd1:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007cd4:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007cd8:	83 f0 1f             	xor    eax,0x1f
   140007cdb:	5d                   	pop    rbp
   140007cdc:	c3                   	ret

0000000140007cdd <__Balloc_D2A>:
   140007cdd:	55                   	push   rbp
   140007cde:	48 89 e5             	mov    rbp,rsp
   140007ce1:	48 83 ec 30          	sub    rsp,0x30
   140007ce5:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007ce8:	b9 00 00 00 00       	mov    ecx,0x0
   140007ced:	e8 30 fe ff ff       	call   140007b22 <dtoa_lock>
   140007cf2:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007cf6:	7f 48                	jg     140007d40 <__Balloc_D2A+0x63>
   140007cf8:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007cfb:	48 98                	cdqe
   140007cfd:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007d04:	00 
   140007d05:	48 8d 05 f4 74 00 00 	lea    rax,[rip+0x74f4]        # 14000f200 <freelist>
   140007d0c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007d10:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d14:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d19:	74 25                	je     140007d40 <__Balloc_D2A+0x63>
   140007d1b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d1f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007d22:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d25:	48 63 d2             	movsxd rdx,edx
   140007d28:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007d2f:	00 
   140007d30:	48 8d 15 c9 74 00 00 	lea    rdx,[rip+0x74c9]        # 14000f200 <freelist>
   140007d37:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007d3b:	e9 b1 00 00 00       	jmp    140007df1 <__Balloc_D2A+0x114>
   140007d40:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d43:	ba 01 00 00 00       	mov    edx,0x1
   140007d48:	89 c1                	mov    ecx,eax
   140007d4a:	d3 e2                	shl    edx,cl
   140007d4c:	89 d0                	mov    eax,edx
   140007d4e:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007d51:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007d54:	83 e8 01             	sub    eax,0x1
   140007d57:	48 98                	cdqe
   140007d59:	48 c1 e0 02          	shl    rax,0x2
   140007d5d:	48 83 c0 27          	add    rax,0x27
   140007d61:	48 c1 e8 03          	shr    rax,0x3
   140007d65:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007d68:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d6c:	7f 4e                	jg     140007dbc <__Balloc_D2A+0xdf>
   140007d6e:	48 8b 15 1b 23 00 00 	mov    rdx,QWORD PTR [rip+0x231b]        # 14000a090 <pmem_next>
   140007d75:	48 8d 05 e4 74 00 00 	lea    rax,[rip+0x74e4]        # 14000f260 <private_mem>
   140007d7c:	48 29 c2             	sub    rdx,rax
   140007d7f:	48 89 d0             	mov    rax,rdx
   140007d82:	48 c1 f8 03          	sar    rax,0x3
   140007d86:	48 89 c2             	mov    rdx,rax
   140007d89:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d8c:	48 01 d0             	add    rax,rdx
   140007d8f:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007d95:	77 25                	ja     140007dbc <__Balloc_D2A+0xdf>
   140007d97:	48 8b 05 f2 22 00 00 	mov    rax,QWORD PTR [rip+0x22f2]        # 14000a090 <pmem_next>
   140007d9e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007da2:	48 8b 05 e7 22 00 00 	mov    rax,QWORD PTR [rip+0x22e7]        # 14000a090 <pmem_next>
   140007da9:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007dac:	48 c1 e2 03          	shl    rdx,0x3
   140007db0:	48 01 d0             	add    rax,rdx
   140007db3:	48 89 05 d6 22 00 00 	mov    QWORD PTR [rip+0x22d6],rax        # 14000a090 <pmem_next>
   140007dba:	eb 21                	jmp    140007ddd <__Balloc_D2A+0x100>
   140007dbc:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007dbf:	48 c1 e0 03          	shl    rax,0x3
   140007dc3:	48 89 c1             	mov    rcx,rax
   140007dc6:	e8 e5 18 00 00       	call   1400096b0 <malloc>
   140007dcb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007dcf:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007dd4:	75 07                	jne    140007ddd <__Balloc_D2A+0x100>
   140007dd6:	b8 00 00 00 00       	mov    eax,0x0
   140007ddb:	eb 3b                	jmp    140007e18 <__Balloc_D2A+0x13b>
   140007ddd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007de1:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007de4:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007de7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007deb:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007dee:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007df1:	b9 00 00 00 00       	mov    ecx,0x0
   140007df6:	e8 59 fe ff ff       	call   140007c54 <dtoa_unlock>
   140007dfb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007dff:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007e06:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e0a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007e0d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e11:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007e14:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e18:	48 83 c4 30          	add    rsp,0x30
   140007e1c:	5d                   	pop    rbp
   140007e1d:	c3                   	ret

0000000140007e1e <__Bfree_D2A>:
   140007e1e:	55                   	push   rbp
   140007e1f:	48 89 e5             	mov    rbp,rsp
   140007e22:	48 83 ec 20          	sub    rsp,0x20
   140007e26:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e2a:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007e2f:	74 71                	je     140007ea2 <__Bfree_D2A+0x84>
   140007e31:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e35:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e38:	83 f8 09             	cmp    eax,0x9
   140007e3b:	7e 0e                	jle    140007e4b <__Bfree_D2A+0x2d>
   140007e3d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e41:	48 89 c1             	mov    rcx,rax
   140007e44:	e8 57 18 00 00       	call   1400096a0 <free>
   140007e49:	eb 57                	jmp    140007ea2 <__Bfree_D2A+0x84>
   140007e4b:	b9 00 00 00 00       	mov    ecx,0x0
   140007e50:	e8 cd fc ff ff       	call   140007b22 <dtoa_lock>
   140007e55:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e59:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e5c:	48 98                	cdqe
   140007e5e:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007e65:	00 
   140007e66:	48 8d 05 93 73 00 00 	lea    rax,[rip+0x7393]        # 14000f200 <freelist>
   140007e6d:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007e71:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e75:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007e78:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e7c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e7f:	48 98                	cdqe
   140007e81:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007e88:	00 
   140007e89:	48 8d 15 70 73 00 00 	lea    rdx,[rip+0x7370]        # 14000f200 <freelist>
   140007e90:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e94:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007e98:	b9 00 00 00 00       	mov    ecx,0x0
   140007e9d:	e8 b2 fd ff ff       	call   140007c54 <dtoa_unlock>
   140007ea2:	90                   	nop
   140007ea3:	48 83 c4 20          	add    rsp,0x20
   140007ea7:	5d                   	pop    rbp
   140007ea8:	c3                   	ret

0000000140007ea9 <__multadd_D2A>:
   140007ea9:	55                   	push   rbp
   140007eaa:	48 89 e5             	mov    rbp,rsp
   140007ead:	48 83 ec 50          	sub    rsp,0x50
   140007eb1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007eb5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007eb8:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007ebc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ec0:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ec3:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007ec6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eca:	48 83 c0 18          	add    rax,0x18
   140007ece:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007ed2:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007ed9:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007edc:	48 98                	cdqe
   140007ede:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007ee2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007ee6:	8b 00                	mov    eax,DWORD PTR [rax]
   140007ee8:	89 c2                	mov    edx,eax
   140007eea:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007eed:	48 98                	cdqe
   140007eef:	48 0f af d0          	imul   rdx,rax
   140007ef3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007ef7:	48 01 d0             	add    rax,rdx
   140007efa:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007efe:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007f02:	48 c1 e8 20          	shr    rax,0x20
   140007f06:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f0a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f0e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007f12:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007f16:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007f1a:	89 10                	mov    DWORD PTR [rax],edx
   140007f1c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007f20:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007f23:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007f26:	7c ba                	jl     140007ee2 <__multadd_D2A+0x39>
   140007f28:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007f2d:	0f 84 9a 00 00 00    	je     140007fcd <__multadd_D2A+0x124>
   140007f33:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f37:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007f3a:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007f3d:	7c 67                	jl     140007fa6 <__multadd_D2A+0xfd>
   140007f3f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f43:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007f46:	83 c0 01             	add    eax,0x1
   140007f49:	89 c1                	mov    ecx,eax
   140007f4b:	e8 8d fd ff ff       	call   140007cdd <__Balloc_D2A>
   140007f50:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007f54:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007f59:	75 07                	jne    140007f62 <__multadd_D2A+0xb9>
   140007f5b:	b8 00 00 00 00       	mov    eax,0x0
   140007f60:	eb 6f                	jmp    140007fd1 <__multadd_D2A+0x128>
   140007f62:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f66:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f69:	48 98                	cdqe
   140007f6b:	48 83 c0 02          	add    rax,0x2
   140007f6f:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007f76:	00 
   140007f77:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f7b:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007f7f:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007f83:	48 83 c0 10          	add    rax,0x10
   140007f87:	49 89 c8             	mov    r8,rcx
   140007f8a:	48 89 c1             	mov    rcx,rax
   140007f8d:	e8 26 17 00 00       	call   1400096b8 <memcpy>
   140007f92:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f96:	48 89 c1             	mov    rcx,rax
   140007f99:	e8 80 fe ff ff       	call   140007e1e <__Bfree_D2A>
   140007f9e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007fa2:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007fa6:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007fa9:	8d 50 01             	lea    edx,[rax+0x1]
   140007fac:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007faf:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140007fb3:	89 d1                	mov    ecx,edx
   140007fb5:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007fb9:	48 98                	cdqe
   140007fbb:	48 83 c0 04          	add    rax,0x4
   140007fbf:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140007fc3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fc7:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140007fca:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007fcd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fd1:	48 83 c4 50          	add    rsp,0x50
   140007fd5:	5d                   	pop    rbp
   140007fd6:	c3                   	ret

0000000140007fd7 <__i2b_D2A>:
   140007fd7:	55                   	push   rbp
   140007fd8:	48 89 e5             	mov    rbp,rsp
   140007fdb:	48 83 ec 30          	sub    rsp,0x30
   140007fdf:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007fe2:	b9 01 00 00 00       	mov    ecx,0x1
   140007fe7:	e8 f1 fc ff ff       	call   140007cdd <__Balloc_D2A>
   140007fec:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007ff0:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007ff5:	75 07                	jne    140007ffe <__i2b_D2A+0x27>
   140007ff7:	b8 00 00 00 00       	mov    eax,0x0
   140007ffc:	eb 19                	jmp    140008017 <__i2b_D2A+0x40>
   140007ffe:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008001:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008005:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008008:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000800c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008013:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008017:	48 83 c4 30          	add    rsp,0x30
   14000801b:	5d                   	pop    rbp
   14000801c:	c3                   	ret

000000014000801d <__mult_D2A>:
   14000801d:	55                   	push   rbp
   14000801e:	48 89 e5             	mov    rbp,rsp
   140008021:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140008028:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000802c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008030:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008034:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008037:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000803b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000803e:	39 c2                	cmp    edx,eax
   140008040:	7d 18                	jge    14000805a <__mult_D2A+0x3d>
   140008042:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008046:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000804a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000804e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008052:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008056:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000805a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000805e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008061:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008064:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008068:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000806b:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   14000806e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008072:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008075:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   140008078:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   14000807b:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   14000807e:	01 d0                	add    eax,edx
   140008080:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008083:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008087:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000808a:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   14000808d:	7e 04                	jle    140008093 <__mult_D2A+0x76>
   14000808f:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008093:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008096:	89 c1                	mov    ecx,eax
   140008098:	e8 40 fc ff ff       	call   140007cdd <__Balloc_D2A>
   14000809d:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400080a1:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   1400080a6:	75 0a                	jne    1400080b2 <__mult_D2A+0x95>
   1400080a8:	b8 00 00 00 00       	mov    eax,0x0
   1400080ad:	e9 88 01 00 00       	jmp    14000823a <__mult_D2A+0x21d>
   1400080b2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400080b6:	48 83 c0 18          	add    rax,0x18
   1400080ba:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400080be:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400080c1:	48 98                	cdqe
   1400080c3:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400080ca:	00 
   1400080cb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080cf:	48 01 d0             	add    rax,rdx
   1400080d2:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400080d6:	eb 0f                	jmp    1400080e7 <__mult_D2A+0xca>
   1400080d8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080dc:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400080e2:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   1400080e7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080eb:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   1400080ef:	72 e7                	jb     1400080d8 <__mult_D2A+0xbb>
   1400080f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080f5:	48 83 c0 18          	add    rax,0x18
   1400080f9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400080fd:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008100:	48 98                	cdqe
   140008102:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008109:	00 
   14000810a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000810e:	48 01 d0             	add    rax,rdx
   140008111:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008115:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008119:	48 83 c0 18          	add    rax,0x18
   14000811d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008121:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140008124:	48 98                	cdqe
   140008126:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000812d:	00 
   14000812e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008132:	48 01 d0             	add    rax,rdx
   140008135:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   140008139:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000813d:	48 83 c0 18          	add    rax,0x18
   140008141:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008145:	e9 95 00 00 00       	jmp    1400081df <__mult_D2A+0x1c2>
   14000814a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000814e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008152:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008156:	8b 00                	mov    eax,DWORD PTR [rax]
   140008158:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   14000815b:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   14000815f:	74 79                	je     1400081da <__mult_D2A+0x1bd>
   140008161:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140008165:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008169:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000816d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008171:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140008178:	00 
   140008179:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000817d:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008181:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008185:	8b 00                	mov    eax,DWORD PTR [rax]
   140008187:	89 c2                	mov    edx,eax
   140008189:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   14000818c:	48 0f af d0          	imul   rdx,rax
   140008190:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008194:	8b 00                	mov    eax,DWORD PTR [rax]
   140008196:	89 c0                	mov    eax,eax
   140008198:	48 01 c2             	add    rdx,rax
   14000819b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000819f:	48 01 d0             	add    rax,rdx
   1400081a2:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   1400081a6:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   1400081aa:	48 c1 e8 20          	shr    rax,0x20
   1400081ae:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400081b2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081b6:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081ba:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400081be:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400081c2:	89 10                	mov    DWORD PTR [rax],edx
   1400081c4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400081c8:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   1400081cc:	72 ab                	jb     140008179 <__mult_D2A+0x15c>
   1400081ce:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400081d2:	89 c2                	mov    edx,eax
   1400081d4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081d8:	89 10                	mov    DWORD PTR [rax],edx
   1400081da:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   1400081df:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400081e3:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   1400081e7:	0f 82 5d ff ff ff    	jb     14000814a <__mult_D2A+0x12d>
   1400081ed:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081f1:	48 83 c0 18          	add    rax,0x18
   1400081f5:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400081f9:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400081fc:	48 98                	cdqe
   1400081fe:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008205:	00 
   140008206:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000820a:	48 01 d0             	add    rax,rdx
   14000820d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008211:	eb 04                	jmp    140008217 <__mult_D2A+0x1fa>
   140008213:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008217:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000821b:	7e 0f                	jle    14000822c <__mult_D2A+0x20f>
   14000821d:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008222:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008226:	8b 00                	mov    eax,DWORD PTR [rax]
   140008228:	85 c0                	test   eax,eax
   14000822a:	74 e7                	je     140008213 <__mult_D2A+0x1f6>
   14000822c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008230:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008233:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008236:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000823a:	48 81 c4 90 00 00 00 	add    rsp,0x90
   140008241:	5d                   	pop    rbp
   140008242:	c3                   	ret

0000000140008243 <__pow5mult_D2A>:
   140008243:	55                   	push   rbp
   140008244:	48 89 e5             	mov    rbp,rsp
   140008247:	48 83 ec 40          	sub    rsp,0x40
   14000824b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000824f:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140008252:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008255:	83 e0 03             	and    eax,0x3
   140008258:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000825b:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000825f:	74 41                	je     1400082a2 <__pow5mult_D2A+0x5f>
   140008261:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008264:	83 e8 01             	sub    eax,0x1
   140008267:	48 98                	cdqe
   140008269:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008270:	00 
   140008271:	48 8d 05 20 1e 00 00 	lea    rax,[rip+0x1e20]        # 14000a098 <p05.0>
   140008278:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   14000827b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000827f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140008285:	48 89 c1             	mov    rcx,rax
   140008288:	e8 1c fc ff ff       	call   140007ea9 <__multadd_D2A>
   14000828d:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008291:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140008296:	75 0a                	jne    1400082a2 <__pow5mult_D2A+0x5f>
   140008298:	b8 00 00 00 00       	mov    eax,0x0
   14000829d:	e9 58 01 00 00       	jmp    1400083fa <__pow5mult_D2A+0x1b7>
   1400082a2:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   1400082a6:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400082aa:	75 09                	jne    1400082b5 <__pow5mult_D2A+0x72>
   1400082ac:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082b0:	e9 45 01 00 00       	jmp    1400083fa <__pow5mult_D2A+0x1b7>
   1400082b5:	48 8b 05 a4 78 00 00 	mov    rax,QWORD PTR [rip+0x78a4]        # 14000fb60 <p5s>
   1400082bc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082c0:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400082c5:	75 5e                	jne    140008325 <__pow5mult_D2A+0xe2>
   1400082c7:	b9 01 00 00 00       	mov    ecx,0x1
   1400082cc:	e8 51 f8 ff ff       	call   140007b22 <dtoa_lock>
   1400082d1:	48 8b 05 88 78 00 00 	mov    rax,QWORD PTR [rip+0x7888]        # 14000fb60 <p5s>
   1400082d8:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082dc:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400082e1:	75 38                	jne    14000831b <__pow5mult_D2A+0xd8>
   1400082e3:	b9 71 02 00 00       	mov    ecx,0x271
   1400082e8:	e8 ea fc ff ff       	call   140007fd7 <__i2b_D2A>
   1400082ed:	48 89 05 6c 78 00 00 	mov    QWORD PTR [rip+0x786c],rax        # 14000fb60 <p5s>
   1400082f4:	48 8b 05 65 78 00 00 	mov    rax,QWORD PTR [rip+0x7865]        # 14000fb60 <p5s>
   1400082fb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082ff:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008304:	75 0a                	jne    140008310 <__pow5mult_D2A+0xcd>
   140008306:	b8 00 00 00 00       	mov    eax,0x0
   14000830b:	e9 ea 00 00 00       	jmp    1400083fa <__pow5mult_D2A+0x1b7>
   140008310:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008314:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000831b:	b9 01 00 00 00       	mov    ecx,0x1
   140008320:	e8 2f f9 ff ff       	call   140007c54 <dtoa_unlock>
   140008325:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008328:	83 e0 01             	and    eax,0x1
   14000832b:	85 c0                	test   eax,eax
   14000832d:	74 39                	je     140008368 <__pow5mult_D2A+0x125>
   14000832f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008333:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008337:	48 89 c1             	mov    rcx,rax
   14000833a:	e8 de fc ff ff       	call   14000801d <__mult_D2A>
   14000833f:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008343:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   140008348:	75 0a                	jne    140008354 <__pow5mult_D2A+0x111>
   14000834a:	b8 00 00 00 00       	mov    eax,0x0
   14000834f:	e9 a6 00 00 00       	jmp    1400083fa <__pow5mult_D2A+0x1b7>
   140008354:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008358:	48 89 c1             	mov    rcx,rax
   14000835b:	e8 be fa ff ff       	call   140007e1e <__Bfree_D2A>
   140008360:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008364:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008368:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   14000836b:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000836f:	0f 84 80 00 00 00    	je     1400083f5 <__pow5mult_D2A+0x1b2>
   140008375:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008379:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000837c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008380:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008385:	75 61                	jne    1400083e8 <__pow5mult_D2A+0x1a5>
   140008387:	b9 01 00 00 00       	mov    ecx,0x1
   14000838c:	e8 91 f7 ff ff       	call   140007b22 <dtoa_lock>
   140008391:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008395:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008398:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000839c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083a1:	75 3b                	jne    1400083de <__pow5mult_D2A+0x19b>
   1400083a3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083a7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083ab:	48 89 c1             	mov    rcx,rax
   1400083ae:	e8 6a fc ff ff       	call   14000801d <__mult_D2A>
   1400083b3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083b7:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400083ba:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083be:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083c1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083c5:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083ca:	75 07                	jne    1400083d3 <__pow5mult_D2A+0x190>
   1400083cc:	b8 00 00 00 00       	mov    eax,0x0
   1400083d1:	eb 27                	jmp    1400083fa <__pow5mult_D2A+0x1b7>
   1400083d3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400083d7:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   1400083de:	b9 01 00 00 00       	mov    ecx,0x1
   1400083e3:	e8 6c f8 ff ff       	call   140007c54 <dtoa_unlock>
   1400083e8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400083ec:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400083f0:	e9 30 ff ff ff       	jmp    140008325 <__pow5mult_D2A+0xe2>
   1400083f5:	90                   	nop
   1400083f6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083fa:	48 83 c4 40          	add    rsp,0x40
   1400083fe:	5d                   	pop    rbp
   1400083ff:	c3                   	ret

0000000140008400 <__lshift_D2A>:
   140008400:	55                   	push   rbp
   140008401:	48 89 e5             	mov    rbp,rsp
   140008404:	48 83 ec 60          	sub    rsp,0x60
   140008408:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000840c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000840f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008412:	c1 f8 05             	sar    eax,0x5
   140008415:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   140008418:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000841c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000841f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008422:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008426:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008429:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   14000842c:	01 d0                	add    eax,edx
   14000842e:	83 c0 01             	add    eax,0x1
   140008431:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008434:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008438:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000843b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000843e:	eb 07                	jmp    140008447 <__lshift_D2A+0x47>
   140008440:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140008444:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140008447:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000844a:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   14000844d:	7f f1                	jg     140008440 <__lshift_D2A+0x40>
   14000844f:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008452:	89 c1                	mov    ecx,eax
   140008454:	e8 84 f8 ff ff       	call   140007cdd <__Balloc_D2A>
   140008459:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000845d:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008462:	75 0a                	jne    14000846e <__lshift_D2A+0x6e>
   140008464:	b8 00 00 00 00       	mov    eax,0x0
   140008469:	e9 19 01 00 00       	jmp    140008587 <__lshift_D2A+0x187>
   14000846e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008472:	48 83 c0 18          	add    rax,0x18
   140008476:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000847a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008481:	eb 16                	jmp    140008499 <__lshift_D2A+0x99>
   140008483:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008487:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000848b:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000848f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008495:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008499:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000849c:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   14000849f:	7c e2                	jl     140008483 <__lshift_D2A+0x83>
   1400084a1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084a5:	48 83 c0 18          	add    rax,0x18
   1400084a9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400084ad:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084b1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400084b4:	48 98                	cdqe
   1400084b6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400084bd:	00 
   1400084be:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084c2:	48 01 d0             	add    rax,rdx
   1400084c5:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400084c9:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   1400084cd:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400084d1:	74 71                	je     140008544 <__lshift_D2A+0x144>
   1400084d3:	b8 20 00 00 00       	mov    eax,0x20
   1400084d8:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400084db:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400084de:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   1400084e5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084e9:	8b 10                	mov    edx,DWORD PTR [rax]
   1400084eb:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400084ee:	89 c1                	mov    ecx,eax
   1400084f0:	d3 e2                	shl    edx,cl
   1400084f2:	89 d1                	mov    ecx,edx
   1400084f4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084f8:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400084fc:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008500:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008503:	89 ca                	mov    edx,ecx
   140008505:	89 10                	mov    DWORD PTR [rax],edx
   140008507:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000850b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000850f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008513:	8b 10                	mov    edx,DWORD PTR [rax]
   140008515:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008518:	89 c1                	mov    ecx,eax
   14000851a:	d3 ea                	shr    edx,cl
   14000851c:	89 d0                	mov    eax,edx
   14000851e:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008521:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008525:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008529:	72 ba                	jb     1400084e5 <__lshift_D2A+0xe5>
   14000852b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000852f:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   140008532:	89 10                	mov    DWORD PTR [rax],edx
   140008534:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008538:	8b 00                	mov    eax,DWORD PTR [rax]
   14000853a:	85 c0                	test   eax,eax
   14000853c:	74 2c                	je     14000856a <__lshift_D2A+0x16a>
   14000853e:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140008542:	eb 26                	jmp    14000856a <__lshift_D2A+0x16a>
   140008544:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008548:	48 8d 42 04          	lea    rax,[rdx+0x4]
   14000854c:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008550:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008554:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140008558:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   14000855c:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000855e:	89 10                	mov    DWORD PTR [rax],edx
   140008560:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008564:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008568:	72 da                	jb     140008544 <__lshift_D2A+0x144>
   14000856a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000856d:	8d 50 ff             	lea    edx,[rax-0x1]
   140008570:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008574:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008577:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000857b:	48 89 c1             	mov    rcx,rax
   14000857e:	e8 9b f8 ff ff       	call   140007e1e <__Bfree_D2A>
   140008583:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008587:	48 83 c4 60          	add    rsp,0x60
   14000858b:	5d                   	pop    rbp
   14000858c:	c3                   	ret

000000014000858d <__cmp_D2A>:
   14000858d:	55                   	push   rbp
   14000858e:	48 89 e5             	mov    rbp,rsp
   140008591:	48 83 ec 30          	sub    rsp,0x30
   140008595:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008599:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000859d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085a1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400085a4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400085a7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400085ab:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400085ae:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400085b1:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085b4:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   1400085b7:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400085bb:	74 08                	je     1400085c5 <__cmp_D2A+0x38>
   1400085bd:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400085c0:	e9 92 00 00 00       	jmp    140008657 <__cmp_D2A+0xca>
   1400085c5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085c9:	48 83 c0 18          	add    rax,0x18
   1400085cd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400085d1:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085d4:	48 98                	cdqe
   1400085d6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400085dd:	00 
   1400085de:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400085e2:	48 01 d0             	add    rax,rdx
   1400085e5:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400085e9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400085ed:	48 83 c0 18          	add    rax,0x18
   1400085f1:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400085f5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085f8:	48 98                	cdqe
   1400085fa:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008601:	00 
   140008602:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008606:	48 01 d0             	add    rax,rdx
   140008609:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000860d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008612:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008616:	8b 10                	mov    edx,DWORD PTR [rax]
   140008618:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   14000861d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008621:	8b 00                	mov    eax,DWORD PTR [rax]
   140008623:	39 c2                	cmp    edx,eax
   140008625:	74 1e                	je     140008645 <__cmp_D2A+0xb8>
   140008627:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000862b:	8b 10                	mov    edx,DWORD PTR [rax]
   14000862d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008631:	8b 00                	mov    eax,DWORD PTR [rax]
   140008633:	39 c2                	cmp    edx,eax
   140008635:	73 07                	jae    14000863e <__cmp_D2A+0xb1>
   140008637:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000863c:	eb 19                	jmp    140008657 <__cmp_D2A+0xca>
   14000863e:	b8 01 00 00 00       	mov    eax,0x1
   140008643:	eb 12                	jmp    140008657 <__cmp_D2A+0xca>
   140008645:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008649:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000864d:	73 02                	jae    140008651 <__cmp_D2A+0xc4>
   14000864f:	eb bc                	jmp    14000860d <__cmp_D2A+0x80>
   140008651:	90                   	nop
   140008652:	b8 00 00 00 00       	mov    eax,0x0
   140008657:	48 83 c4 30          	add    rsp,0x30
   14000865b:	5d                   	pop    rbp
   14000865c:	c3                   	ret

000000014000865d <__diff_D2A>:
   14000865d:	55                   	push   rbp
   14000865e:	48 89 e5             	mov    rbp,rsp
   140008661:	48 83 ec 70          	sub    rsp,0x70
   140008665:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008669:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000866d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140008671:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008675:	48 89 c1             	mov    rcx,rax
   140008678:	e8 10 ff ff ff       	call   14000858d <__cmp_D2A>
   14000867d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008680:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008684:	75 3e                	jne    1400086c4 <__diff_D2A+0x67>
   140008686:	b9 00 00 00 00       	mov    ecx,0x0
   14000868b:	e8 4d f6 ff ff       	call   140007cdd <__Balloc_D2A>
   140008690:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008694:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008699:	75 0a                	jne    1400086a5 <__diff_D2A+0x48>
   14000869b:	b8 00 00 00 00       	mov    eax,0x0
   1400086a0:	e9 ab 01 00 00       	jmp    140008850 <__diff_D2A+0x1f3>
   1400086a5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086a9:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   1400086b0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086b4:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   1400086bb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086bf:	e9 8c 01 00 00       	jmp    140008850 <__diff_D2A+0x1f3>
   1400086c4:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400086c8:	79 21                	jns    1400086eb <__diff_D2A+0x8e>
   1400086ca:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086ce:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400086d2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086d6:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400086da:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086de:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400086e2:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400086e9:	eb 07                	jmp    1400086f2 <__diff_D2A+0x95>
   1400086eb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400086f2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086f6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400086f9:	89 c1                	mov    ecx,eax
   1400086fb:	e8 dd f5 ff ff       	call   140007cdd <__Balloc_D2A>
   140008700:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008704:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008709:	75 0a                	jne    140008715 <__diff_D2A+0xb8>
   14000870b:	b8 00 00 00 00       	mov    eax,0x0
   140008710:	e9 3b 01 00 00       	jmp    140008850 <__diff_D2A+0x1f3>
   140008715:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008719:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000871c:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000871f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008723:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008726:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008729:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000872d:	48 83 c0 18          	add    rax,0x18
   140008731:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008735:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008738:	48 98                	cdqe
   14000873a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008741:	00 
   140008742:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008746:	48 01 d0             	add    rax,rdx
   140008749:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000874d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008751:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008754:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   140008757:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000875b:	48 83 c0 18          	add    rax,0x18
   14000875f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008763:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008766:	48 98                	cdqe
   140008768:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000876f:	00 
   140008770:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008774:	48 01 d0             	add    rax,rdx
   140008777:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000877b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000877f:	48 83 c0 18          	add    rax,0x18
   140008783:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008787:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   14000878e:	00 
   14000878f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008793:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008797:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000879b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000879d:	89 c1                	mov    ecx,eax
   14000879f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087a3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087a7:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400087ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087ad:	89 c2                	mov    edx,eax
   1400087af:	48 89 c8             	mov    rax,rcx
   1400087b2:	48 29 d0             	sub    rax,rdx
   1400087b5:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400087b9:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400087bd:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400087c1:	48 c1 e8 20          	shr    rax,0x20
   1400087c5:	83 e0 01             	and    eax,0x1
   1400087c8:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400087cc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087d0:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087d4:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400087d8:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400087dc:	89 10                	mov    DWORD PTR [rax],edx
   1400087de:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087e2:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   1400087e6:	72 a7                	jb     14000878f <__diff_D2A+0x132>
   1400087e8:	eb 39                	jmp    140008823 <__diff_D2A+0x1c6>
   1400087ea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087ee:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087f2:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400087f6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087f8:	89 c0                	mov    eax,eax
   1400087fa:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400087fe:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008802:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008806:	48 c1 e8 20          	shr    rax,0x20
   14000880a:	83 e0 01             	and    eax,0x1
   14000880d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008811:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008815:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008819:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000881d:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140008821:	89 10                	mov    DWORD PTR [rax],edx
   140008823:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008827:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   14000882b:	72 bd                	jb     1400087ea <__diff_D2A+0x18d>
   14000882d:	eb 04                	jmp    140008833 <__diff_D2A+0x1d6>
   14000882f:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008833:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008838:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000883c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000883e:	85 c0                	test   eax,eax
   140008840:	74 ed                	je     14000882f <__diff_D2A+0x1d2>
   140008842:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008846:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008849:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000884c:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008850:	48 83 c4 70          	add    rsp,0x70
   140008854:	5d                   	pop    rbp
   140008855:	c3                   	ret

0000000140008856 <__b2d_D2A>:
   140008856:	55                   	push   rbp
   140008857:	48 89 e5             	mov    rbp,rsp
   14000885a:	48 83 ec 50          	sub    rsp,0x50
   14000885e:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008862:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008866:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000886a:	48 83 c0 18          	add    rax,0x18
   14000886e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008872:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008876:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008879:	48 98                	cdqe
   14000887b:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008882:	00 
   140008883:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008887:	48 01 d0             	add    rax,rdx
   14000888a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000888e:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008893:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008897:	8b 00                	mov    eax,DWORD PTR [rax]
   140008899:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   14000889c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000889f:	89 c1                	mov    ecx,eax
   1400088a1:	e8 27 f4 ff ff       	call   140007ccd <__hi0bits_D2A>
   1400088a6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400088a9:	b8 20 00 00 00       	mov    eax,0x20
   1400088ae:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088b1:	89 c2                	mov    edx,eax
   1400088b3:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400088b7:	89 10                	mov    DWORD PTR [rax],edx
   1400088b9:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   1400088bd:	7f 66                	jg     140008925 <__b2d_D2A+0xcf>
   1400088bf:	b8 0b 00 00 00       	mov    eax,0xb
   1400088c4:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088c7:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400088ca:	89 c1                	mov    ecx,eax
   1400088cc:	d3 ea                	shr    edx,cl
   1400088ce:	89 d0                	mov    eax,edx
   1400088d0:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400088d5:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400088d8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088dc:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400088e0:	73 10                	jae    1400088f2 <__b2d_D2A+0x9c>
   1400088e2:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088e7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088ed:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400088f0:	eb 07                	jmp    1400088f9 <__b2d_D2A+0xa3>
   1400088f2:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400088f9:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400088fc:	83 c0 15             	add    eax,0x15
   1400088ff:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008902:	89 c1                	mov    ecx,eax
   140008904:	d3 e2                	shl    edx,cl
   140008906:	41 89 d0             	mov    r8d,edx
   140008909:	b8 0b 00 00 00       	mov    eax,0xb
   14000890e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008911:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140008914:	89 c1                	mov    ecx,eax
   140008916:	d3 ea                	shr    edx,cl
   140008918:	89 d0                	mov    eax,edx
   14000891a:	44 09 c0             	or     eax,r8d
   14000891d:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008920:	e9 ac 00 00 00       	jmp    1400089d1 <__b2d_D2A+0x17b>
   140008925:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008929:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000892d:	73 10                	jae    14000893f <__b2d_D2A+0xe9>
   14000892f:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008934:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008938:	8b 00                	mov    eax,DWORD PTR [rax]
   14000893a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000893d:	eb 07                	jmp    140008946 <__b2d_D2A+0xf0>
   14000893f:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   140008946:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   14000894a:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   14000894e:	74 70                	je     1400089c0 <__b2d_D2A+0x16a>
   140008950:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008953:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008956:	89 c1                	mov    ecx,eax
   140008958:	d3 e2                	shl    edx,cl
   14000895a:	41 89 d0             	mov    r8d,edx
   14000895d:	b8 20 00 00 00       	mov    eax,0x20
   140008962:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008965:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008968:	89 c1                	mov    ecx,eax
   14000896a:	d3 ea                	shr    edx,cl
   14000896c:	89 d0                	mov    eax,edx
   14000896e:	44 09 c0             	or     eax,r8d
   140008971:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008976:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008979:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000897d:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008981:	73 10                	jae    140008993 <__b2d_D2A+0x13d>
   140008983:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008988:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000898c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000898e:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140008991:	eb 07                	jmp    14000899a <__b2d_D2A+0x144>
   140008993:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   14000899a:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000899d:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400089a0:	89 c1                	mov    ecx,eax
   1400089a2:	d3 e2                	shl    edx,cl
   1400089a4:	41 89 d0             	mov    r8d,edx
   1400089a7:	b8 20 00 00 00       	mov    eax,0x20
   1400089ac:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400089af:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400089b2:	89 c1                	mov    ecx,eax
   1400089b4:	d3 ea                	shr    edx,cl
   1400089b6:	89 d0                	mov    eax,edx
   1400089b8:	44 09 c0             	or     eax,r8d
   1400089bb:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089be:	eb 11                	jmp    1400089d1 <__b2d_D2A+0x17b>
   1400089c0:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400089c3:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400089c8:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089cb:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400089ce:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089d1:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   1400089d6:	48 83 c4 50          	add    rsp,0x50
   1400089da:	5d                   	pop    rbp
   1400089db:	c3                   	ret

00000001400089dc <__d2b_D2A>:
   1400089dc:	55                   	push   rbp
   1400089dd:	53                   	push   rbx
   1400089de:	48 83 ec 58          	sub    rsp,0x58
   1400089e2:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400089e7:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   1400089ec:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400089f0:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400089f4:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400089f9:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   1400089fe:	b9 01 00 00 00       	mov    ecx,0x1
   140008a03:	e8 d5 f2 ff ff       	call   140007cdd <__Balloc_D2A>
   140008a08:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008a0c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008a11:	75 0a                	jne    140008a1d <__d2b_D2A+0x41>
   140008a13:	b8 00 00 00 00       	mov    eax,0x0
   140008a18:	e9 68 01 00 00       	jmp    140008b85 <__d2b_D2A+0x1a9>
   140008a1d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a21:	48 83 c0 18          	add    rax,0x18
   140008a25:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008a29:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a2c:	25 ff ff 0f 00       	and    eax,0xfffff
   140008a31:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a34:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a37:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008a3c:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008a3f:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a42:	c1 e8 14             	shr    eax,0x14
   140008a45:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140008a48:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008a4c:	74 0b                	je     140008a59 <__d2b_D2A+0x7d>
   140008a4e:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   140008a51:	0d 00 00 10 00       	or     eax,0x100000
   140008a56:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a59:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140008a5c:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008a5f:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008a62:	85 c0                	test   eax,eax
   140008a64:	74 7b                	je     140008ae1 <__d2b_D2A+0x105>
   140008a66:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   140008a6a:	48 89 c1             	mov    rcx,rax
   140008a6d:	e8 26 f2 ff ff       	call   140007c98 <__lo0bits_D2A>
   140008a72:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008a75:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008a79:	74 2b                	je     140008aa6 <__d2b_D2A+0xca>
   140008a7b:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a7e:	b8 20 00 00 00       	mov    eax,0x20
   140008a83:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008a86:	89 c1                	mov    ecx,eax
   140008a88:	d3 e2                	shl    edx,cl
   140008a8a:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008a8d:	09 c2                	or     edx,eax
   140008a8f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a93:	89 10                	mov    DWORD PTR [rax],edx
   140008a95:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a98:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008a9b:	89 c1                	mov    ecx,eax
   140008a9d:	d3 ea                	shr    edx,cl
   140008a9f:	89 d0                	mov    eax,edx
   140008aa1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008aa4:	eb 09                	jmp    140008aaf <__d2b_D2A+0xd3>
   140008aa6:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008aa9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008aad:	89 10                	mov    DWORD PTR [rax],edx
   140008aaf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008ab3:	48 83 c0 04          	add    rax,0x4
   140008ab7:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008aba:	89 10                	mov    DWORD PTR [rax],edx
   140008abc:	8b 00                	mov    eax,DWORD PTR [rax]
   140008abe:	85 c0                	test   eax,eax
   140008ac0:	74 07                	je     140008ac9 <__d2b_D2A+0xed>
   140008ac2:	ba 02 00 00 00       	mov    edx,0x2
   140008ac7:	eb 05                	jmp    140008ace <__d2b_D2A+0xf2>
   140008ac9:	ba 01 00 00 00       	mov    edx,0x1
   140008ace:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ad2:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008ad5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ad9:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008adc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008adf:	eb 31                	jmp    140008b12 <__d2b_D2A+0x136>
   140008ae1:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008ae5:	48 89 c1             	mov    rcx,rax
   140008ae8:	e8 ab f1 ff ff       	call   140007c98 <__lo0bits_D2A>
   140008aed:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008af0:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008af3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008af7:	89 10                	mov    DWORD PTR [rax],edx
   140008af9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008afd:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008b04:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b08:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b0b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b0e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008b12:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008b16:	74 26                	je     140008b3e <__d2b_D2A+0x162>
   140008b18:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b1b:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008b21:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b24:	01 c2                	add    edx,eax
   140008b26:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b2a:	89 10                	mov    DWORD PTR [rax],edx
   140008b2c:	b8 35 00 00 00       	mov    eax,0x35
   140008b31:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008b34:	89 c2                	mov    edx,eax
   140008b36:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b3a:	89 10                	mov    DWORD PTR [rax],edx
   140008b3c:	eb 43                	jmp    140008b81 <__d2b_D2A+0x1a5>
   140008b3e:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b41:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008b47:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b4a:	01 c2                	add    edx,eax
   140008b4c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b50:	89 10                	mov    DWORD PTR [rax],edx
   140008b52:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b55:	c1 e0 05             	shl    eax,0x5
   140008b58:	89 c3                	mov    ebx,eax
   140008b5a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b5d:	48 98                	cdqe
   140008b5f:	48 c1 e0 02          	shl    rax,0x2
   140008b63:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008b67:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b6b:	48 01 d0             	add    rax,rdx
   140008b6e:	8b 00                	mov    eax,DWORD PTR [rax]
   140008b70:	89 c1                	mov    ecx,eax
   140008b72:	e8 56 f1 ff ff       	call   140007ccd <__hi0bits_D2A>
   140008b77:	29 c3                	sub    ebx,eax
   140008b79:	89 da                	mov    edx,ebx
   140008b7b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b7f:	89 10                	mov    DWORD PTR [rax],edx
   140008b81:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b85:	48 83 c4 58          	add    rsp,0x58
   140008b89:	5b                   	pop    rbx
   140008b8a:	5d                   	pop    rbp
   140008b8b:	c3                   	ret

0000000140008b8c <__strcp_D2A>:
   140008b8c:	55                   	push   rbp
   140008b8d:	48 89 e5             	mov    rbp,rsp
   140008b90:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008b94:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008b98:	eb 05                	jmp    140008b9f <__strcp_D2A+0x13>
   140008b9a:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008b9f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008ba3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008ba7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008bab:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008bae:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008bb2:	88 10                	mov    BYTE PTR [rax],dl
   140008bb4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008bb8:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008bbb:	84 c0                	test   al,al
   140008bbd:	75 db                	jne    140008b9a <__strcp_D2A+0xe>
   140008bbf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008bc3:	5d                   	pop    rbp
   140008bc4:	c3                   	ret
   140008bc5:	90                   	nop
   140008bc6:	90                   	nop
   140008bc7:	90                   	nop
   140008bc8:	90                   	nop
   140008bc9:	90                   	nop
   140008bca:	90                   	nop
   140008bcb:	90                   	nop
   140008bcc:	90                   	nop
   140008bcd:	90                   	nop
   140008bce:	90                   	nop
   140008bcf:	90                   	nop

0000000140008bd0 <__fpclassify>:
   140008bd0:	55                   	push   rbp
   140008bd1:	48 89 e5             	mov    rbp,rsp
   140008bd4:	48 83 ec 10          	sub    rsp,0x10
   140008bd8:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008bdd:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008be2:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008be7:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008bea:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008bed:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008bf0:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008bf3:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008bf9:	09 d0                	or     eax,edx
   140008bfb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008bfe:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008c05:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c08:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c0b:	85 c0                	test   eax,eax
   140008c0d:	75 07                	jne    140008c16 <__fpclassify+0x46>
   140008c0f:	b8 00 40 00 00       	mov    eax,0x4000
   140008c14:	eb 2f                	jmp    140008c45 <__fpclassify+0x75>
   140008c16:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c1a:	75 07                	jne    140008c23 <__fpclassify+0x53>
   140008c1c:	b8 00 44 00 00       	mov    eax,0x4400
   140008c21:	eb 22                	jmp    140008c45 <__fpclassify+0x75>
   140008c23:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008c2a:	75 14                	jne    140008c40 <__fpclassify+0x70>
   140008c2c:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008c30:	74 07                	je     140008c39 <__fpclassify+0x69>
   140008c32:	b8 00 01 00 00       	mov    eax,0x100
   140008c37:	eb 0c                	jmp    140008c45 <__fpclassify+0x75>
   140008c39:	b8 00 05 00 00       	mov    eax,0x500
   140008c3e:	eb 05                	jmp    140008c45 <__fpclassify+0x75>
   140008c40:	b8 00 04 00 00       	mov    eax,0x400
   140008c45:	48 83 c4 10          	add    rsp,0x10
   140008c49:	5d                   	pop    rbp
   140008c4a:	c3                   	ret
   140008c4b:	90                   	nop
   140008c4c:	90                   	nop
   140008c4d:	90                   	nop
   140008c4e:	90                   	nop
   140008c4f:	90                   	nop

0000000140008c50 <__fpclassifyl>:
   140008c50:	55                   	push   rbp
   140008c51:	53                   	push   rbx
   140008c52:	48 83 ec 38          	sub    rsp,0x38
   140008c56:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008c5b:	48 89 cb             	mov    rbx,rcx
   140008c5e:	db 2b                	fld    TBYTE PTR [rbx]
   140008c60:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008c63:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008c66:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008c69:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008c6d:	98                   	cwde
   140008c6e:	25 ff 7f 00 00       	and    eax,0x7fff
   140008c73:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c76:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c7a:	75 25                	jne    140008ca1 <__fpclassifyl+0x51>
   140008c7c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c7f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c82:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c85:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c88:	85 c0                	test   eax,eax
   140008c8a:	75 07                	jne    140008c93 <__fpclassifyl+0x43>
   140008c8c:	b8 00 40 00 00       	mov    eax,0x4000
   140008c91:	eb 3d                	jmp    140008cd0 <__fpclassifyl+0x80>
   140008c93:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c96:	85 c0                	test   eax,eax
   140008c98:	78 31                	js     140008ccb <__fpclassifyl+0x7b>
   140008c9a:	b8 00 44 00 00       	mov    eax,0x4400
   140008c9f:	eb 2f                	jmp    140008cd0 <__fpclassifyl+0x80>
   140008ca1:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008ca8:	75 21                	jne    140008ccb <__fpclassifyl+0x7b>
   140008caa:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008cad:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008cb2:	89 c2                	mov    edx,eax
   140008cb4:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008cb7:	09 d0                	or     eax,edx
   140008cb9:	85 c0                	test   eax,eax
   140008cbb:	75 07                	jne    140008cc4 <__fpclassifyl+0x74>
   140008cbd:	b8 00 05 00 00       	mov    eax,0x500
   140008cc2:	eb 0c                	jmp    140008cd0 <__fpclassifyl+0x80>
   140008cc4:	b8 00 01 00 00       	mov    eax,0x100
   140008cc9:	eb 05                	jmp    140008cd0 <__fpclassifyl+0x80>
   140008ccb:	b8 00 04 00 00       	mov    eax,0x400
   140008cd0:	48 83 c4 38          	add    rsp,0x38
   140008cd4:	5b                   	pop    rbx
   140008cd5:	5d                   	pop    rbp
   140008cd6:	c3                   	ret
   140008cd7:	90                   	nop
   140008cd8:	90                   	nop
   140008cd9:	90                   	nop
   140008cda:	90                   	nop
   140008cdb:	90                   	nop
   140008cdc:	90                   	nop
   140008cdd:	90                   	nop
   140008cde:	90                   	nop
   140008cdf:	90                   	nop

0000000140008ce0 <__isnan>:
   140008ce0:	55                   	push   rbp
   140008ce1:	48 89 e5             	mov    rbp,rsp
   140008ce4:	48 83 ec 10          	sub    rsp,0x10
   140008ce8:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008ced:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008cf2:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008cf7:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008cfa:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cfd:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008d00:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008d05:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d08:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d0b:	f7 d8                	neg    eax
   140008d0d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008d10:	c1 e8 1f             	shr    eax,0x1f
   140008d13:	89 c2                	mov    edx,eax
   140008d15:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d18:	09 d0                	or     eax,edx
   140008d1a:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d1d:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008d22:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008d25:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d28:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d2b:	c1 f8 1f             	sar    eax,0x1f
   140008d2e:	48 83 c4 10          	add    rsp,0x10
   140008d32:	5d                   	pop    rbp
   140008d33:	c3                   	ret
   140008d34:	90                   	nop
   140008d35:	90                   	nop
   140008d36:	90                   	nop
   140008d37:	90                   	nop
   140008d38:	90                   	nop
   140008d39:	90                   	nop
   140008d3a:	90                   	nop
   140008d3b:	90                   	nop
   140008d3c:	90                   	nop
   140008d3d:	90                   	nop
   140008d3e:	90                   	nop
   140008d3f:	90                   	nop

0000000140008d40 <__isnanl>:
   140008d40:	55                   	push   rbp
   140008d41:	53                   	push   rbx
   140008d42:	48 83 ec 38          	sub    rsp,0x38
   140008d46:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008d4b:	48 89 cb             	mov    rbx,rcx
   140008d4e:	db 2b                	fld    TBYTE PTR [rbx]
   140008d50:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008d53:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008d56:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008d59:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008d5d:	98                   	cwde
   140008d5e:	01 c0                	add    eax,eax
   140008d60:	25 ff ff 00 00       	and    eax,0xffff
   140008d65:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d68:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008d6b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008d6e:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008d74:	09 d0                	or     eax,edx
   140008d76:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d79:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d7c:	f7 d8                	neg    eax
   140008d7e:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008d81:	c1 e8 1f             	shr    eax,0x1f
   140008d84:	89 c2                	mov    edx,eax
   140008d86:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d89:	09 d0                	or     eax,edx
   140008d8b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d8e:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008d93:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008d96:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d99:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d9c:	c1 f8 10             	sar    eax,0x10
   140008d9f:	48 83 c4 38          	add    rsp,0x38
   140008da3:	5b                   	pop    rbx
   140008da4:	5d                   	pop    rbp
   140008da5:	c3                   	ret
   140008da6:	90                   	nop
   140008da7:	90                   	nop
   140008da8:	90                   	nop
   140008da9:	90                   	nop
   140008daa:	90                   	nop
   140008dab:	90                   	nop
   140008dac:	90                   	nop
   140008dad:	90                   	nop
   140008dae:	90                   	nop
   140008daf:	90                   	nop

0000000140008db0 <wcsnlen>:
   140008db0:	55                   	push   rbp
   140008db1:	48 89 e5             	mov    rbp,rsp
   140008db4:	48 83 ec 10          	sub    rsp,0x10
   140008db8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008dbc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008dc0:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008dc7:	00 
   140008dc8:	eb 0a                	jmp    140008dd4 <wcsnlen+0x24>
   140008dca:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008dcf:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008dd4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dd8:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008ddc:	73 0c                	jae    140008dea <wcsnlen+0x3a>
   140008dde:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008de2:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008de5:	66 85 c0             	test   ax,ax
   140008de8:	75 e0                	jne    140008dca <wcsnlen+0x1a>
   140008dea:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dee:	48 83 c4 10          	add    rsp,0x10
   140008df2:	5d                   	pop    rbp
   140008df3:	c3                   	ret
   140008df4:	90                   	nop
   140008df5:	90                   	nop
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

0000000140008e00 <strnlen>:
   140008e00:	55                   	push   rbp
   140008e01:	48 89 e5             	mov    rbp,rsp
   140008e04:	48 83 ec 10          	sub    rsp,0x10
   140008e08:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e0c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e10:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e14:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e18:	eb 05                	jmp    140008e1f <strnlen+0x1f>
   140008e1a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e1f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e23:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e27:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e2b:	73 0b                	jae    140008e38 <strnlen+0x38>
   140008e2d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e31:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008e34:	84 c0                	test   al,al
   140008e36:	75 e2                	jne    140008e1a <strnlen+0x1a>
   140008e38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e3c:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e40:	48 83 c4 10          	add    rsp,0x10
   140008e44:	5d                   	pop    rbp
   140008e45:	c3                   	ret
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

0000000140008e50 <_initterm_e>:
   140008e50:	55                   	push   rbp
   140008e51:	48 89 e5             	mov    rbp,rsp
   140008e54:	48 83 ec 30          	sub    rsp,0x30
   140008e58:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e5c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e60:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e64:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e68:	eb 29                	jmp    140008e93 <_initterm_e+0x43>
   140008e6a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e6e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e71:	48 85 c0             	test   rax,rax
   140008e74:	74 17                	je     140008e8d <_initterm_e+0x3d>
   140008e76:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e7a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e7d:	ff d0                	call   rax
   140008e7f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008e82:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008e86:	74 06                	je     140008e8e <_initterm_e+0x3e>
   140008e88:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008e8b:	eb 15                	jmp    140008ea2 <_initterm_e+0x52>
   140008e8d:	90                   	nop
   140008e8e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008e93:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e97:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e9b:	72 cd                	jb     140008e6a <_initterm_e+0x1a>
   140008e9d:	b8 00 00 00 00       	mov    eax,0x0
   140008ea2:	48 83 c4 30          	add    rsp,0x30
   140008ea6:	5d                   	pop    rbp
   140008ea7:	c3                   	ret
   140008ea8:	90                   	nop
   140008ea9:	90                   	nop
   140008eaa:	90                   	nop
   140008eab:	90                   	nop
   140008eac:	90                   	nop
   140008ead:	90                   	nop
   140008eae:	90                   	nop
   140008eaf:	90                   	nop

0000000140008eb0 <__p__fmode>:
   140008eb0:	55                   	push   rbp
   140008eb1:	48 89 e5             	mov    rbp,rsp
   140008eb4:	48 8b 05 45 27 00 00 	mov    rax,QWORD PTR [rip+0x2745]        # 14000b600 <.refptr.__imp__fmode>
   140008ebb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ebe:	5d                   	pop    rbp
   140008ebf:	c3                   	ret

0000000140008ec0 <__p__commode>:
   140008ec0:	55                   	push   rbp
   140008ec1:	48 89 e5             	mov    rbp,rsp
   140008ec4:	48 8b 05 25 27 00 00 	mov    rax,QWORD PTR [rip+0x2725]        # 14000b5f0 <.refptr.__imp__commode>
   140008ecb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ece:	5d                   	pop    rbp
   140008ecf:	c3                   	ret

0000000140008ed0 <__p___initenv>:
   140008ed0:	55                   	push   rbp
   140008ed1:	48 89 e5             	mov    rbp,rsp
   140008ed4:	48 8b 05 05 27 00 00 	mov    rax,QWORD PTR [rip+0x2705]        # 14000b5e0 <.refptr.__imp___initenv>
   140008edb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ede:	5d                   	pop    rbp
   140008edf:	c3                   	ret

0000000140008ee0 <_lock_file>:
   140008ee0:	55                   	push   rbp
   140008ee1:	48 89 e5             	mov    rbp,rsp
   140008ee4:	48 83 ec 20          	sub    rsp,0x20
   140008ee8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008eec:	b9 00 00 00 00       	mov    ecx,0x0
   140008ef1:	e8 6a 01 00 00       	call   140009060 <__acrt_iob_func>
   140008ef6:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008efa:	72 52                	jb     140008f4e <_lock_file+0x6e>
   140008efc:	b9 13 00 00 00       	mov    ecx,0x13
   140008f01:	e8 5a 01 00 00       	call   140009060 <__acrt_iob_func>
   140008f06:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f0a:	72 42                	jb     140008f4e <_lock_file+0x6e>
   140008f0c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f11:	e8 4a 01 00 00       	call   140009060 <__acrt_iob_func>
   140008f16:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f1a:	48 29 c2             	sub    rdx,rax
   140008f1d:	48 c1 fa 04          	sar    rdx,0x4
   140008f21:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008f28:	aa aa aa 
   140008f2b:	48 0f af c2          	imul   rax,rdx
   140008f2f:	83 c0 10             	add    eax,0x10
   140008f32:	89 c1                	mov    ecx,eax
   140008f34:	e8 1f 07 00 00       	call   140009658 <_lock>
   140008f39:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f3d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008f40:	80 cc 80             	or     ah,0x80
   140008f43:	89 c2                	mov    edx,eax
   140008f45:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f49:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008f4c:	eb 15                	jmp    140008f63 <_lock_file+0x83>
   140008f4e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f52:	48 83 c0 30          	add    rax,0x30
   140008f56:	48 89 c1             	mov    rcx,rax
   140008f59:	48 8b 05 90 72 00 00 	mov    rax,QWORD PTR [rip+0x7290]        # 1400101f0 <__imp_EnterCriticalSection>
   140008f60:	ff d0                	call   rax
   140008f62:	90                   	nop
   140008f63:	90                   	nop
   140008f64:	48 83 c4 20          	add    rsp,0x20
   140008f68:	5d                   	pop    rbp
   140008f69:	c3                   	ret

0000000140008f6a <_unlock_file>:
   140008f6a:	55                   	push   rbp
   140008f6b:	48 89 e5             	mov    rbp,rsp
   140008f6e:	48 83 ec 20          	sub    rsp,0x20
   140008f72:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f76:	b9 00 00 00 00       	mov    ecx,0x0
   140008f7b:	e8 e0 00 00 00       	call   140009060 <__acrt_iob_func>
   140008f80:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008f84:	72 52                	jb     140008fd8 <_unlock_file+0x6e>
   140008f86:	b9 13 00 00 00       	mov    ecx,0x13
   140008f8b:	e8 d0 00 00 00       	call   140009060 <__acrt_iob_func>
   140008f90:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f94:	72 42                	jb     140008fd8 <_unlock_file+0x6e>
   140008f96:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f9a:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008f9d:	80 e4 7f             	and    ah,0x7f
   140008fa0:	89 c2                	mov    edx,eax
   140008fa2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fa6:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008fa9:	b9 00 00 00 00       	mov    ecx,0x0
   140008fae:	e8 ad 00 00 00       	call   140009060 <__acrt_iob_func>
   140008fb3:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008fb7:	48 29 c2             	sub    rdx,rax
   140008fba:	48 c1 fa 04          	sar    rdx,0x4
   140008fbe:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008fc5:	aa aa aa 
   140008fc8:	48 0f af c2          	imul   rax,rdx
   140008fcc:	83 c0 10             	add    eax,0x10
   140008fcf:	89 c1                	mov    ecx,eax
   140008fd1:	e8 8a 06 00 00       	call   140009660 <_unlock>
   140008fd6:	eb 15                	jmp    140008fed <_unlock_file+0x83>
   140008fd8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fdc:	48 83 c0 30          	add    rax,0x30
   140008fe0:	48 89 c1             	mov    rcx,rax
   140008fe3:	48 8b 05 3e 72 00 00 	mov    rax,QWORD PTR [rip+0x723e]        # 140010228 <__imp_LeaveCriticalSection>
   140008fea:	ff d0                	call   rax
   140008fec:	90                   	nop
   140008fed:	90                   	nop
   140008fee:	48 83 c4 20          	add    rsp,0x20
   140008ff2:	5d                   	pop    rbp
   140008ff3:	c3                   	ret
   140008ff4:	90                   	nop
   140008ff5:	90                   	nop
   140008ff6:	90                   	nop
   140008ff7:	90                   	nop
   140008ff8:	90                   	nop
   140008ff9:	90                   	nop
   140008ffa:	90                   	nop
   140008ffb:	90                   	nop
   140008ffc:	90                   	nop
   140008ffd:	90                   	nop
   140008ffe:	90                   	nop
   140008fff:	90                   	nop

0000000140009000 <_set_invalid_parameter_handler>:
   140009000:	55                   	push   rbp
   140009001:	48 89 e5             	mov    rbp,rsp
   140009004:	48 83 ec 10          	sub    rsp,0x10
   140009008:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000900c:	48 8d 05 6d 6b 00 00 	lea    rax,[rip+0x6b6d]        # 14000fb80 <handler>
   140009013:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140009017:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000901b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000901f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140009023:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140009027:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000902a:	48 89 d0             	mov    rax,rdx
   14000902d:	48 83 c4 10          	add    rsp,0x10
   140009031:	5d                   	pop    rbp
   140009032:	c3                   	ret

0000000140009033 <_get_invalid_parameter_handler>:
   140009033:	55                   	push   rbp
   140009034:	48 89 e5             	mov    rbp,rsp
   140009037:	48 8b 05 42 6b 00 00 	mov    rax,QWORD PTR [rip+0x6b42]        # 14000fb80 <handler>
   14000903e:	5d                   	pop    rbp
   14000903f:	c3                   	ret

0000000140009040 <_configthreadlocale>:
   140009040:	55                   	push   rbp
   140009041:	48 89 e5             	mov    rbp,rsp
   140009044:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140009047:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000904b:	75 07                	jne    140009054 <_configthreadlocale+0x14>
   14000904d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140009052:	eb 05                	jmp    140009059 <_configthreadlocale+0x19>
   140009054:	b8 02 00 00 00       	mov    eax,0x2
   140009059:	5d                   	pop    rbp
   14000905a:	c3                   	ret
   14000905b:	90                   	nop
   14000905c:	90                   	nop
   14000905d:	90                   	nop
   14000905e:	90                   	nop
   14000905f:	90                   	nop

0000000140009060 <__acrt_iob_func>:
   140009060:	55                   	push   rbp
   140009061:	48 89 e5             	mov    rbp,rsp
   140009064:	48 83 ec 20          	sub    rsp,0x20
   140009068:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000906b:	e8 b0 05 00 00       	call   140009620 <__iob_func>
   140009070:	48 89 c1             	mov    rcx,rax
   140009073:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140009076:	48 89 d0             	mov    rax,rdx
   140009079:	48 01 c0             	add    rax,rax
   14000907c:	48 01 d0             	add    rax,rdx
   14000907f:	48 c1 e0 04          	shl    rax,0x4
   140009083:	48 01 c8             	add    rax,rcx
   140009086:	48 83 c4 20          	add    rsp,0x20
   14000908a:	5d                   	pop    rbp
   14000908b:	c3                   	ret
   14000908c:	90                   	nop
   14000908d:	90                   	nop
   14000908e:	90                   	nop
   14000908f:	90                   	nop

0000000140009090 <wcrtomb>:
   140009090:	55                   	push   rbp
   140009091:	48 89 e5             	mov    rbp,rsp
   140009094:	48 83 ec 40          	sub    rsp,0x40
   140009098:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000909c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400090a0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090a4:	e8 5f 05 00 00       	call   140009608 <___lc_codepage_func>
   1400090a9:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400090ac:	e8 5f 05 00 00       	call   140009610 <___mb_cur_max_func>
   1400090b1:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400090b4:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   1400090b8:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   1400090bc:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   1400090c0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400090c4:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   1400090c7:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   1400090cb:	48 89 c1             	mov    rcx,rax
   1400090ce:	e8 7d 00 00 00       	call   140009150 <__mingw_wcrtomb_cp>
   1400090d3:	48 83 c4 40          	add    rsp,0x40
   1400090d7:	5d                   	pop    rbp
   1400090d8:	c3                   	ret
   1400090d9:	90                   	nop
   1400090da:	90                   	nop
   1400090db:	90                   	nop
   1400090dc:	90                   	nop
   1400090dd:	90                   	nop
   1400090de:	90                   	nop
   1400090df:	90                   	nop

00000001400090e0 <mbrtowc>:
   1400090e0:	55                   	push   rbp
   1400090e1:	48 89 e5             	mov    rbp,rsp
   1400090e4:	48 83 ec 40          	sub    rsp,0x40
   1400090e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090ec:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400090f0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090f4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400090f8:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   1400090fd:	75 0b                	jne    14000910a <mbrtowc+0x2a>
   1400090ff:	48 8d 05 8a 6a 00 00 	lea    rax,[rip+0x6a8a]        # 14000fb90 <state_mbrtowc.0>
   140009106:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000910a:	e8 f9 04 00 00       	call   140009608 <___lc_codepage_func>
   14000910f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009112:	e8 f9 04 00 00       	call   140009610 <___mb_cur_max_func>
   140009117:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000911a:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   14000911e:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140009122:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140009126:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000912a:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   14000912d:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   140009131:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   140009134:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   140009138:	48 89 c1             	mov    rcx,rax
   14000913b:	e8 70 01 00 00       	call   1400092b0 <__mingw_mbrtowc_cp>
   140009140:	48 83 c4 40          	add    rsp,0x40
   140009144:	5d                   	pop    rbp
   140009145:	c3                   	ret
   140009146:	90                   	nop
   140009147:	90                   	nop
   140009148:	90                   	nop
   140009149:	90                   	nop
   14000914a:	90                   	nop
   14000914b:	90                   	nop
   14000914c:	90                   	nop
   14000914d:	90                   	nop
   14000914e:	90                   	nop
   14000914f:	90                   	nop

0000000140009150 <__mingw_wcrtomb_cp>:
   140009150:	55                   	push   rbp
   140009151:	48 89 e5             	mov    rbp,rsp
   140009154:	48 83 ec 50          	sub    rsp,0x50
   140009158:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000915c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009160:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009164:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   140009168:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000916d:	75 1b                	jne    14000918a <__mingw_wcrtomb_cp+0x3a>
   14000916f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009174:	74 0a                	je     140009180 <__mingw_wcrtomb_cp+0x30>
   140009176:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000917a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009180:	b8 01 00 00 00       	mov    eax,0x1
   140009185:	e9 17 01 00 00       	jmp    1400092a1 <__mingw_wcrtomb_cp+0x151>
   14000918a:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   14000918f:	74 21                	je     1400091b2 <__mingw_wcrtomb_cp+0x62>
   140009191:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140009195:	8b 00                	mov    eax,DWORD PTR [rax]
   140009197:	85 c0                	test   eax,eax
   140009199:	74 17                	je     1400091b2 <__mingw_wcrtomb_cp+0x62>
   14000919b:	e8 a8 04 00 00       	call   140009648 <_errno>
   1400091a0:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   1400091a6:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400091ad:	e9 ef 00 00 00       	jmp    1400092a1 <__mingw_wcrtomb_cp+0x151>
   1400091b2:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   1400091b6:	66 85 c0             	test   ax,ax
   1400091b9:	75 18                	jne    1400091d3 <__mingw_wcrtomb_cp+0x83>
   1400091bb:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091c0:	74 07                	je     1400091c9 <__mingw_wcrtomb_cp+0x79>
   1400091c2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400091c6:	c6 00 00             	mov    BYTE PTR [rax],0x0
   1400091c9:	b8 01 00 00 00       	mov    eax,0x1
   1400091ce:	e9 ce 00 00 00       	jmp    1400092a1 <__mingw_wcrtomb_cp+0x151>
   1400091d3:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   1400091d7:	75 2b                	jne    140009204 <__mingw_wcrtomb_cp+0xb4>
   1400091d9:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   1400091dd:	66 3d ff 00          	cmp    ax,0xff
   1400091e1:	0f 87 a4 00 00 00    	ja     14000928b <__mingw_wcrtomb_cp+0x13b>
   1400091e7:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091ec:	74 0c                	je     1400091fa <__mingw_wcrtomb_cp+0xaa>
   1400091ee:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   1400091f2:	89 c2                	mov    edx,eax
   1400091f4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400091f8:	88 10                	mov    BYTE PTR [rax],dl
   1400091fa:	b8 01 00 00 00       	mov    eax,0x1
   1400091ff:	e9 9d 00 00 00       	jmp    1400092a1 <__mingw_wcrtomb_cp+0x151>
   140009204:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000920b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   140009211:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   140009215:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140009218:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   14000921c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140009221:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   140009228:	00 00 
   14000922a:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000922d:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140009231:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009235:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000923a:	41 b9 01 00 00 00    	mov    r9d,0x1
   140009240:	49 89 c8             	mov    r8,rcx
   140009243:	ba 00 00 00 00       	mov    edx,0x0
   140009248:	89 c1                	mov    ecx,eax
   14000924a:	48 8b 05 17 70 00 00 	mov    rax,QWORD PTR [rip+0x7017]        # 140010268 <__imp_WideCharToMultiByte>
   140009251:	ff d0                	call   rax
   140009253:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009256:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000925a:	74 32                	je     14000928e <__mingw_wcrtomb_cp+0x13e>
   14000925c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000925f:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   140009262:	7f 2a                	jg     14000928e <__mingw_wcrtomb_cp+0x13e>
   140009264:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009267:	85 c0                	test   eax,eax
   140009269:	75 23                	jne    14000928e <__mingw_wcrtomb_cp+0x13e>
   14000926b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000926e:	48 63 c8             	movsxd rcx,eax
   140009271:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009275:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009279:	49 89 c8             	mov    r8,rcx
   14000927c:	48 89 c1             	mov    rcx,rax
   14000927f:	e8 34 04 00 00       	call   1400096b8 <memcpy>
   140009284:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009287:	48 98                	cdqe
   140009289:	eb 16                	jmp    1400092a1 <__mingw_wcrtomb_cp+0x151>
   14000928b:	90                   	nop
   14000928c:	eb 01                	jmp    14000928f <__mingw_wcrtomb_cp+0x13f>
   14000928e:	90                   	nop
   14000928f:	e8 b4 03 00 00       	call   140009648 <_errno>
   140009294:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000929a:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400092a1:	48 83 c4 50          	add    rsp,0x50
   1400092a5:	5d                   	pop    rbp
   1400092a6:	c3                   	ret
   1400092a7:	90                   	nop
   1400092a8:	90                   	nop
   1400092a9:	90                   	nop
   1400092aa:	90                   	nop
   1400092ab:	90                   	nop
   1400092ac:	90                   	nop
   1400092ad:	90                   	nop
   1400092ae:	90                   	nop
   1400092af:	90                   	nop

00000001400092b0 <__mingw_mbrtowc_cp>:
   1400092b0:	55                   	push   rbp
   1400092b1:	48 89 e5             	mov    rbp,rsp
   1400092b4:	48 83 ec 50          	sub    rsp,0x50
   1400092b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400092bc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400092c0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400092c4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400092c8:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   1400092cd:	75 1b                	jne    1400092ea <__mingw_mbrtowc_cp+0x3a>
   1400092cf:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   1400092d6:	00 
   1400092d7:	48 8d 05 42 22 00 00 	lea    rax,[rip+0x2242]        # 14000b520 <.rdata>
   1400092de:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400092e2:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   1400092e9:	00 
   1400092ea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400092ee:	8b 00                	mov    eax,DWORD PTR [rax]
   1400092f0:	3d ff 00 00 00       	cmp    eax,0xff
   1400092f5:	0f 87 b9 01 00 00    	ja     1400094b4 <__mingw_mbrtowc_cp+0x204>
   1400092fb:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009300:	75 0c                	jne    14000930e <__mingw_mbrtowc_cp+0x5e>
   140009302:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009309:	e9 bc 01 00 00       	jmp    1400094ca <__mingw_mbrtowc_cp+0x21a>
   14000930e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009312:	8b 00                	mov    eax,DWORD PTR [rax]
   140009314:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140009317:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   14000931b:	75 0c                	jne    140009329 <__mingw_mbrtowc_cp+0x79>
   14000931d:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009321:	84 c0                	test   al,al
   140009323:	0f 85 8e 01 00 00    	jne    1400094b7 <__mingw_mbrtowc_cp+0x207>
   140009329:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   14000932d:	75 2c                	jne    14000935b <__mingw_mbrtowc_cp+0xab>
   14000932f:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009334:	74 11                	je     140009347 <__mingw_mbrtowc_cp+0x97>
   140009336:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000933a:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000933d:	0f b6 d0             	movzx  edx,al
   140009340:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009344:	66 89 10             	mov    WORD PTR [rax],dx
   140009347:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000934b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000934e:	84 c0                	test   al,al
   140009350:	0f 95 c0             	setne  al
   140009353:	0f b6 c0             	movzx  eax,al
   140009356:	e9 6f 01 00 00       	jmp    1400094ca <__mingw_mbrtowc_cp+0x21a>
   14000935b:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140009362:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140009369:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   14000936d:	84 c0                	test   al,al
   14000936f:	74 1a                	je     14000938b <__mingw_mbrtowc_cp+0xdb>
   140009371:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009375:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009378:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000937b:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140009382:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140009389:	eb 73                	jmp    1400093fe <__mingw_mbrtowc_cp+0x14e>
   14000938b:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   14000938f:	75 5c                	jne    1400093ed <__mingw_mbrtowc_cp+0x13d>
   140009391:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009395:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009398:	0f b6 c0             	movzx  eax,al
   14000939b:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000939e:	89 c1                	mov    ecx,eax
   1400093a0:	e8 ab 01 00 00       	call   140009550 <__mingw_isleadbyte_cp>
   1400093a5:	85 c0                	test   eax,eax
   1400093a7:	74 44                	je     1400093ed <__mingw_mbrtowc_cp+0x13d>
   1400093a9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093ad:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093b0:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   1400093b3:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   1400093b8:	77 15                	ja     1400093cf <__mingw_mbrtowc_cp+0x11f>
   1400093ba:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400093bd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400093c1:	89 10                	mov    DWORD PTR [rax],edx
   1400093c3:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   1400093ca:	e9 fb 00 00 00       	jmp    1400094ca <__mingw_mbrtowc_cp+0x21a>
   1400093cf:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093d3:	48 83 c0 01          	add    rax,0x1
   1400093d7:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093da:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   1400093dd:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400093e4:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400093eb:	eb 11                	jmp    1400093fe <__mingw_mbrtowc_cp+0x14e>
   1400093ed:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093f1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093f4:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   1400093f7:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400093fe:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009402:	84 c0                	test   al,al
   140009404:	75 24                	jne    14000942a <__mingw_mbrtowc_cp+0x17a>
   140009406:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000940b:	74 09                	je     140009416 <__mingw_mbrtowc_cp+0x166>
   14000940d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009411:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   140009416:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000941a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009420:	b8 00 00 00 00       	mov    eax,0x0
   140009425:	e9 a0 00 00 00       	jmp    1400094ca <__mingw_mbrtowc_cp+0x21a>
   14000942a:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   14000942e:	75 08                	jne    140009438 <__mingw_mbrtowc_cp+0x188>
   140009430:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   140009434:	84 c0                	test   al,al
   140009436:	74 64                	je     14000949c <__mingw_mbrtowc_cp+0x1ec>
   140009438:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   14000943e:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   140009442:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   140009446:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   140009449:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   140009450:	00 
   140009451:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   140009455:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000945a:	45 89 c1             	mov    r9d,r8d
   14000945d:	49 89 c8             	mov    r8,rcx
   140009460:	ba 08 00 00 00       	mov    edx,0x8
   140009465:	89 c1                	mov    ecx,eax
   140009467:	48 8b 05 ca 6d 00 00 	mov    rax,QWORD PTR [rip+0x6dca]        # 140010238 <__imp_MultiByteToWideChar>
   14000946e:	ff d0                	call   rax
   140009470:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140009473:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   140009477:	75 26                	jne    14000949f <__mingw_mbrtowc_cp+0x1ef>
   140009479:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000947e:	74 0b                	je     14000948b <__mingw_mbrtowc_cp+0x1db>
   140009480:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   140009484:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009488:	66 89 10             	mov    WORD PTR [rax],dx
   14000948b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000948f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009495:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009498:	48 98                	cdqe
   14000949a:	eb 2e                	jmp    1400094ca <__mingw_mbrtowc_cp+0x21a>
   14000949c:	90                   	nop
   14000949d:	eb 01                	jmp    1400094a0 <__mingw_mbrtowc_cp+0x1f0>
   14000949f:	90                   	nop
   1400094a0:	e8 a3 01 00 00       	call   140009648 <_errno>
   1400094a5:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400094ab:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400094b2:	eb 16                	jmp    1400094ca <__mingw_mbrtowc_cp+0x21a>
   1400094b4:	90                   	nop
   1400094b5:	eb 01                	jmp    1400094b8 <__mingw_mbrtowc_cp+0x208>
   1400094b7:	90                   	nop
   1400094b8:	e8 8b 01 00 00       	call   140009648 <_errno>
   1400094bd:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   1400094c3:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400094ca:	48 83 c4 50          	add    rsp,0x50
   1400094ce:	5d                   	pop    rbp
   1400094cf:	c3                   	ret

00000001400094d0 <fallback_IsDBCSLeadByteEx>:
   1400094d0:	55                   	push   rbp
   1400094d1:	48 89 e5             	mov    rbp,rsp
   1400094d4:	48 83 ec 40          	sub    rsp,0x40
   1400094d8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400094db:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   1400094de:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   1400094e2:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400094e5:	89 c1                	mov    ecx,eax
   1400094e7:	48 8b 05 12 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d12]        # 140010200 <__imp_GetCPInfo>
   1400094ee:	ff d0                	call   rax
   1400094f0:	85 c0                	test   eax,eax
   1400094f2:	74 51                	je     140009545 <fallback_IsDBCSLeadByteEx+0x75>
   1400094f4:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   1400094f7:	83 f8 02             	cmp    eax,0x2
   1400094fa:	75 49                	jne    140009545 <fallback_IsDBCSLeadByteEx+0x75>
   1400094fc:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009503:	eb 2c                	jmp    140009531 <fallback_IsDBCSLeadByteEx+0x61>
   140009505:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009508:	48 98                	cdqe
   14000950a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000950f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   140009512:	72 19                	jb     14000952d <fallback_IsDBCSLeadByteEx+0x5d>
   140009514:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009517:	83 c0 01             	add    eax,0x1
   14000951a:	48 98                	cdqe
   14000951c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009521:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   140009524:	72 07                	jb     14000952d <fallback_IsDBCSLeadByteEx+0x5d>
   140009526:	b8 01 00 00 00       	mov    eax,0x1
   14000952b:	eb 1d                	jmp    14000954a <fallback_IsDBCSLeadByteEx+0x7a>
   14000952d:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   140009531:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   140009535:	7f 0e                	jg     140009545 <fallback_IsDBCSLeadByteEx+0x75>
   140009537:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000953a:	48 98                	cdqe
   14000953c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009541:	84 c0                	test   al,al
   140009543:	75 c0                	jne    140009505 <fallback_IsDBCSLeadByteEx+0x35>
   140009545:	b8 00 00 00 00       	mov    eax,0x0
   14000954a:	48 83 c4 40          	add    rsp,0x40
   14000954e:	5d                   	pop    rbp
   14000954f:	c3                   	ret

0000000140009550 <__mingw_isleadbyte_cp>:
   140009550:	55                   	push   rbp
   140009551:	48 89 e5             	mov    rbp,rsp
   140009554:	48 83 ec 40          	sub    rsp,0x40
   140009558:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000955b:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000955e:	48 8b 05 3b 66 00 00 	mov    rax,QWORD PTR [rip+0x663b]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009565:	48 85 c0             	test   rax,rax
   140009568:	75 71                	jne    1400095db <__mingw_isleadbyte_cp+0x8b>
   14000956a:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140009571:	00 
   140009572:	48 8d 05 b7 1f 00 00 	lea    rax,[rip+0x1fb7]        # 14000b530 <.rdata>
   140009579:	48 89 c1             	mov    rcx,rax
   14000957c:	48 8b 05 8d 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c8d]        # 140010210 <__imp_GetModuleHandleA>
   140009583:	ff d0                	call   rax
   140009585:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140009589:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000958e:	74 1b                	je     1400095ab <__mingw_isleadbyte_cp+0x5b>
   140009590:	48 8d 15 a6 1f 00 00 	lea    rdx,[rip+0x1fa6]        # 14000b53d <.rdata+0xd>
   140009597:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000959b:	48 89 c1             	mov    rcx,rax
   14000959e:	48 8b 05 73 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c73]        # 140010218 <__imp_GetProcAddress>
   1400095a5:	ff d0                	call   rax
   1400095a7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400095ab:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400095b0:	75 0b                	jne    1400095bd <__mingw_isleadbyte_cp+0x6d>
   1400095b2:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 1400094d0 <fallback_IsDBCSLeadByteEx>
   1400095b9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400095bd:	48 8d 05 dc 65 00 00 	lea    rax,[rip+0x65dc]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400095c4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400095c8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400095cc:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400095d0:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   1400095d4:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400095d8:	48 87 10             	xchg   QWORD PTR [rax],rdx
   1400095db:	4c 8b 05 be 65 00 00 	mov    r8,QWORD PTR [rip+0x65be]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400095e2:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400095e5:	0f b6 d0             	movzx  edx,al
   1400095e8:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400095eb:	89 c1                	mov    ecx,eax
   1400095ed:	41 ff d0             	call   r8
   1400095f0:	48 83 c4 40          	add    rsp,0x40
   1400095f4:	5d                   	pop    rbp
   1400095f5:	c3                   	ret
   1400095f6:	90                   	nop
   1400095f7:	90                   	nop
   1400095f8:	90                   	nop
   1400095f9:	90                   	nop
   1400095fa:	90                   	nop
   1400095fb:	90                   	nop
   1400095fc:	90                   	nop
   1400095fd:	90                   	nop
   1400095fe:	90                   	nop
   1400095ff:	90                   	nop

0000000140009600 <__C_specific_handler>:
   140009600:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010278 <__imp___C_specific_handler>
   140009606:	90                   	nop
   140009607:	90                   	nop

0000000140009608 <___lc_codepage_func>:
   140009608:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010280 <__imp____lc_codepage_func>
   14000960e:	90                   	nop
   14000960f:	90                   	nop

0000000140009610 <___mb_cur_max_func>:
   140009610:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010288 <__imp____mb_cur_max_func>
   140009616:	90                   	nop
   140009617:	90                   	nop

0000000140009618 <__getmainargs>:
   140009618:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010290 <__imp___getmainargs>
   14000961e:	90                   	nop
   14000961f:	90                   	nop

0000000140009620 <__iob_func>:
   140009620:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 1400102a0 <__imp___iob_func>
   140009626:	90                   	nop
   140009627:	90                   	nop

0000000140009628 <__set_app_type>:
   140009628:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 1400102a8 <__imp___set_app_type>
   14000962e:	90                   	nop
   14000962f:	90                   	nop

0000000140009630 <__setusermatherr>:
   140009630:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 1400102b0 <__imp___setusermatherr>
   140009636:	90                   	nop
   140009637:	90                   	nop

0000000140009638 <_amsg_exit>:
   140009638:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 1400102b8 <__imp__amsg_exit>
   14000963e:	90                   	nop
   14000963f:	90                   	nop

0000000140009640 <_cexit>:
   140009640:	ff 25 7a 6c 00 00    	jmp    QWORD PTR [rip+0x6c7a]        # 1400102c0 <__imp__cexit>
   140009646:	90                   	nop
   140009647:	90                   	nop

0000000140009648 <_errno>:
   140009648:	ff 25 82 6c 00 00    	jmp    QWORD PTR [rip+0x6c82]        # 1400102d0 <__imp__errno>
   14000964e:	90                   	nop
   14000964f:	90                   	nop

0000000140009650 <_initterm>:
   140009650:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 1400102e0 <__imp__initterm>
   140009656:	90                   	nop
   140009657:	90                   	nop

0000000140009658 <_lock>:
   140009658:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 1400102e8 <__imp__lock>
   14000965e:	90                   	nop
   14000965f:	90                   	nop

0000000140009660 <_unlock>:
   140009660:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 1400102f0 <__imp__unlock>
   140009666:	90                   	nop
   140009667:	90                   	nop

0000000140009668 <_crt_atexit>:
   140009668:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 1400102f8 <__imp__crt_atexit>
   14000966e:	90                   	nop
   14000966f:	90                   	nop

0000000140009670 <abort>:
   140009670:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010300 <__imp_abort>
   140009676:	90                   	nop
   140009677:	90                   	nop

0000000140009678 <calloc>:
   140009678:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010308 <__imp_calloc>
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <exit>:
   140009680:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010310 <__imp_exit>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <fflush>:
   140009688:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010318 <__imp_fflush>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <fprintf>:
   140009690:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010320 <__imp_fprintf>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <fputc>:
   140009698:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010328 <__imp_fputc>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <free>:
   1400096a0:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010330 <__imp_free>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <localeconv>:
   1400096a8:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010338 <__imp_localeconv>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <malloc>:
   1400096b0:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010340 <__imp_malloc>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <memcpy>:
   1400096b8:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010348 <__imp_memcpy>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <setvbuf>:
   1400096c0:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010350 <__imp_setvbuf>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <signal>:
   1400096c8:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010358 <__imp_signal>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <strerror>:
   1400096d0:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010360 <__imp_strerror>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <strlen>:
   1400096d8:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010368 <__imp_strlen>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <strncmp>:
   1400096e0:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010370 <__imp_strncmp>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop

00000001400096e8 <vfprintf>:
   1400096e8:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010378 <__imp_vfprintf>
   1400096ee:	90                   	nop
   1400096ef:	90                   	nop

00000001400096f0 <wcslen>:
   1400096f0:	ff 25 8a 6c 00 00    	jmp    QWORD PTR [rip+0x6c8a]        # 140010380 <__imp_wcslen>
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop
   1400096f8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   1400096ff:	00 

0000000140009700 <WideCharToMultiByte>:
   140009700:	ff 25 62 6b 00 00    	jmp    QWORD PTR [rip+0x6b62]        # 140010268 <__imp_WideCharToMultiByte>
   140009706:	90                   	nop
   140009707:	90                   	nop

0000000140009708 <VirtualQuery>:
   140009708:	ff 25 52 6b 00 00    	jmp    QWORD PTR [rip+0x6b52]        # 140010260 <__imp_VirtualQuery>
   14000970e:	90                   	nop
   14000970f:	90                   	nop

0000000140009710 <VirtualProtect>:
   140009710:	ff 25 42 6b 00 00    	jmp    QWORD PTR [rip+0x6b42]        # 140010258 <__imp_VirtualProtect>
   140009716:	90                   	nop
   140009717:	90                   	nop

0000000140009718 <TlsGetValue>:
   140009718:	ff 25 32 6b 00 00    	jmp    QWORD PTR [rip+0x6b32]        # 140010250 <__imp_TlsGetValue>
   14000971e:	90                   	nop
   14000971f:	90                   	nop

0000000140009720 <Sleep>:
   140009720:	ff 25 22 6b 00 00    	jmp    QWORD PTR [rip+0x6b22]        # 140010248 <__imp_Sleep>
   140009726:	90                   	nop
   140009727:	90                   	nop

0000000140009728 <SetUnhandledExceptionFilter>:
   140009728:	ff 25 12 6b 00 00    	jmp    QWORD PTR [rip+0x6b12]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   14000972e:	90                   	nop
   14000972f:	90                   	nop

0000000140009730 <MultiByteToWideChar>:
   140009730:	ff 25 02 6b 00 00    	jmp    QWORD PTR [rip+0x6b02]        # 140010238 <__imp_MultiByteToWideChar>
   140009736:	90                   	nop
   140009737:	90                   	nop

0000000140009738 <LoadLibraryA>:
   140009738:	ff 25 f2 6a 00 00    	jmp    QWORD PTR [rip+0x6af2]        # 140010230 <__imp_LoadLibraryA>
   14000973e:	90                   	nop
   14000973f:	90                   	nop

0000000140009740 <LeaveCriticalSection>:
   140009740:	ff 25 e2 6a 00 00    	jmp    QWORD PTR [rip+0x6ae2]        # 140010228 <__imp_LeaveCriticalSection>
   140009746:	90                   	nop
   140009747:	90                   	nop

0000000140009748 <InitializeCriticalSection>:
   140009748:	ff 25 d2 6a 00 00    	jmp    QWORD PTR [rip+0x6ad2]        # 140010220 <__imp_InitializeCriticalSection>
   14000974e:	90                   	nop
   14000974f:	90                   	nop

0000000140009750 <GetProcAddress>:
   140009750:	ff 25 c2 6a 00 00    	jmp    QWORD PTR [rip+0x6ac2]        # 140010218 <__imp_GetProcAddress>
   140009756:	90                   	nop
   140009757:	90                   	nop

0000000140009758 <GetModuleHandleA>:
   140009758:	ff 25 b2 6a 00 00    	jmp    QWORD PTR [rip+0x6ab2]        # 140010210 <__imp_GetModuleHandleA>
   14000975e:	90                   	nop
   14000975f:	90                   	nop

0000000140009760 <GetLastError>:
   140009760:	ff 25 a2 6a 00 00    	jmp    QWORD PTR [rip+0x6aa2]        # 140010208 <__imp_GetLastError>
   140009766:	90                   	nop
   140009767:	90                   	nop

0000000140009768 <GetCPInfo>:
   140009768:	ff 25 92 6a 00 00    	jmp    QWORD PTR [rip+0x6a92]        # 140010200 <__imp_GetCPInfo>
   14000976e:	90                   	nop
   14000976f:	90                   	nop

0000000140009770 <FreeLibrary>:
   140009770:	ff 25 82 6a 00 00    	jmp    QWORD PTR [rip+0x6a82]        # 1400101f8 <__imp_FreeLibrary>
   140009776:	90                   	nop
   140009777:	90                   	nop

0000000140009778 <EnterCriticalSection>:
   140009778:	ff 25 72 6a 00 00    	jmp    QWORD PTR [rip+0x6a72]        # 1400101f0 <__imp_EnterCriticalSection>
   14000977e:	90                   	nop
   14000977f:	90                   	nop

0000000140009780 <DeleteCriticalSection>:
   140009780:	ff 25 62 6a 00 00    	jmp    QWORD PTR [rip+0x6a62]        # 1400101e8 <__IAT_start__>
   140009786:	90                   	nop
   140009787:	90                   	nop
   140009788:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000978f:	00 

0000000140009790 <register_frame_ctor>:
   140009790:	e9 db 7e ff ff       	jmp    140001670 <__gcc_register_frame>
   140009795:	90                   	nop
   140009796:	90                   	nop
   140009797:	90                   	nop
   140009798:	90                   	nop
   140009799:	90                   	nop
   14000979a:	90                   	nop
   14000979b:	90                   	nop
   14000979c:	90                   	nop
   14000979d:	90                   	nop
   14000979e:	90                   	nop
   14000979f:	90                   	nop
