
C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\test_samples\fmt_cve\fmt_09_printf_heap_fmt\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 ef 85 00 00       	call   140009618 <fflush>
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
   14000113b:	e8 88 84 00 00       	call   1400095c8 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 88 7e 00 00       	call   140008ff0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 cf 84 00 00       	call   140009650 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 67 84 00 00       	call   140009600 <abort>
   140001199:	e8 52 11 00 00       	call   1400022f0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 99 f0 00 00 	mov    rax,QWORD PTR [rip+0xf099]        # 140010248 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 c6 7d 00 00       	call   140008f90 <_set_invalid_parameter_handler>
   1400011ca:	e8 31 1a 00 00       	call   140002c00 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 c7 83 00 00       	call   1400095b8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 bb 83 00 00       	call   1400095b8 <__set_app_type>
   1400011fd:	e8 3e 7c 00 00       	call   140008e40 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 3e 7c 00 00       	call   140008e50 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 ae 06 00 00       	call   1400018d0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 93 83 00 00       	call   1400095c8 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 b8 11 00 00       	call   14000240a <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 66 7d 00 00       	call   140008fd0 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 60 7b 00 00       	call   140008de0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 3a 83 00 00       	call   1400095c8 <_amsg_exit>
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
   1400012cb:	e8 d8 82 00 00       	call   1400095a8 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 e5 82 00 00       	call   1400095c8 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 be 82 00 00       	call   1400095c8 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 c0 82 00 00       	call   1400095e0 <_initterm>
   140001320:	e8 82 05 00 00       	call   1400018a7 <__main>
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
   14000138d:	e8 ce 7a 00 00       	call   140008e60 <__p___initenv>
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
   1400013cc:	e8 3f 82 00 00       	call   140009610 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 f0 81 00 00       	call   1400095d0 <_cexit>
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
   140001511:	e8 2a 81 00 00       	call   140009640 <malloc>
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
   14000155c:	e8 0f 81 00 00       	call   140009670 <strlen>
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
   140001585:	e8 b6 80 00 00       	call   140009640 <malloc>
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
   1400015e8:	e8 5b 80 00 00       	call   140009648 <memcpy>
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
   140001642:	e8 b1 7f 00 00       	call   1400095f8 <_crt_atexit>
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

0000000140001760 <main>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 30          	sub    rsp,0x30
   140001768:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000176b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000176f:	e8 33 01 00 00       	call   1400018a7 <__main>
   140001774:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   140001778:	7f 07                	jg     140001781 <main+0x21>
   14000177a:	b8 00 00 00 00       	mov    eax,0x0
   14000177f:	eb 65                	jmp    1400017e6 <main+0x86>
   140001781:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001785:	48 83 c0 08          	add    rax,0x8
   140001789:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000178c:	48 89 c1             	mov    rcx,rax
   14000178f:	e8 dc 7e 00 00       	call   140009670 <strlen>
   140001794:	48 83 c0 01          	add    rax,0x1
   140001798:	48 89 c1             	mov    rcx,rax
   14000179b:	e8 a0 7e 00 00       	call   140009640 <malloc>
   1400017a0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400017a4:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400017a9:	75 07                	jne    1400017b2 <main+0x52>
   1400017ab:	b8 01 00 00 00       	mov    eax,0x1
   1400017b0:	eb 34                	jmp    1400017e6 <main+0x86>
   1400017b2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400017b6:	48 83 c0 08          	add    rax,0x8
   1400017ba:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400017bd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017c1:	48 89 c1             	mov    rcx,rax
   1400017c4:	e8 97 7e 00 00       	call   140009660 <strcpy>
   1400017c9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017cd:	48 89 c1             	mov    rcx,rax
   1400017d0:	e8 2b 19 00 00       	call   140003100 <__mingw_printf>
   1400017d5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017d9:	48 89 c1             	mov    rcx,rax
   1400017dc:	e8 4f 7e 00 00       	call   140009630 <free>
   1400017e1:	b8 00 00 00 00       	mov    eax,0x0
   1400017e6:	48 83 c4 30          	add    rsp,0x30
   1400017ea:	5d                   	pop    rbp
   1400017eb:	c3                   	ret
   1400017ec:	90                   	nop
   1400017ed:	90                   	nop
   1400017ee:	90                   	nop
   1400017ef:	90                   	nop

00000001400017f0 <__do_global_dtors>:
   1400017f0:	55                   	push   rbp
   1400017f1:	48 89 e5             	mov    rbp,rsp
   1400017f4:	48 83 ec 20          	sub    rsp,0x20
   1400017f8:	eb 1e                	jmp    140001818 <__do_global_dtors+0x28>
   1400017fa:	48 8b 05 0f 88 00 00 	mov    rax,QWORD PTR [rip+0x880f]        # 14000a010 <p.0>
   140001801:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001804:	ff d0                	call   rax
   140001806:	48 8b 05 03 88 00 00 	mov    rax,QWORD PTR [rip+0x8803]        # 14000a010 <p.0>
   14000180d:	48 83 c0 08          	add    rax,0x8
   140001811:	48 89 05 f8 87 00 00 	mov    QWORD PTR [rip+0x87f8],rax        # 14000a010 <p.0>
   140001818:	48 8b 05 f1 87 00 00 	mov    rax,QWORD PTR [rip+0x87f1]        # 14000a010 <p.0>
   14000181f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001822:	48 85 c0             	test   rax,rax
   140001825:	75 d3                	jne    1400017fa <__do_global_dtors+0xa>
   140001827:	90                   	nop
   140001828:	90                   	nop
   140001829:	48 83 c4 20          	add    rsp,0x20
   14000182d:	5d                   	pop    rbp
   14000182e:	c3                   	ret

000000014000182f <__do_global_ctors>:
   14000182f:	55                   	push   rbp
   140001830:	48 89 e5             	mov    rbp,rsp
   140001833:	48 83 ec 30          	sub    rsp,0x30
   140001837:	48 8b 05 32 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d32]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000183e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001841:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001844:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001848:	75 25                	jne    14000186f <__do_global_ctors+0x40>
   14000184a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001851:	eb 04                	jmp    140001857 <__do_global_ctors+0x28>
   140001853:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001857:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000185a:	8d 50 01             	lea    edx,[rax+0x1]
   14000185d:	48 8b 05 0c 9d 00 00 	mov    rax,QWORD PTR [rip+0x9d0c]        # 14000b570 <.refptr.__CTOR_LIST__>
   140001864:	89 d2                	mov    edx,edx
   140001866:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000186a:	48 85 c0             	test   rax,rax
   14000186d:	75 e4                	jne    140001853 <__do_global_ctors+0x24>
   14000186f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001872:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001875:	eb 14                	jmp    14000188b <__do_global_ctors+0x5c>
   140001877:	48 8b 05 f2 9c 00 00 	mov    rax,QWORD PTR [rip+0x9cf2]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000187e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001881:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001885:	ff d0                	call   rax
   140001887:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000188b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000188f:	75 e6                	jne    140001877 <__do_global_ctors+0x48>
   140001891:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400017f0 <__do_global_dtors>
   140001898:	48 89 c1             	mov    rcx,rax
   14000189b:	e8 8f fd ff ff       	call   14000162f <atexit>
   1400018a0:	90                   	nop
   1400018a1:	48 83 c4 30          	add    rsp,0x30
   1400018a5:	5d                   	pop    rbp
   1400018a6:	c3                   	ret

00000001400018a7 <__main>:
   1400018a7:	55                   	push   rbp
   1400018a8:	48 89 e5             	mov    rbp,rsp
   1400018ab:	48 83 ec 20          	sub    rsp,0x20
   1400018af:	8b 05 cb d7 00 00    	mov    eax,DWORD PTR [rip+0xd7cb]        # 14000f080 <initialized>
   1400018b5:	85 c0                	test   eax,eax
   1400018b7:	75 0f                	jne    1400018c8 <__main+0x21>
   1400018b9:	c7 05 bd d7 00 00 01 	mov    DWORD PTR [rip+0xd7bd],0x1        # 14000f080 <initialized>
   1400018c0:	00 00 00 
   1400018c3:	e8 67 ff ff ff       	call   14000182f <__do_global_ctors>
   1400018c8:	90                   	nop
   1400018c9:	48 83 c4 20          	add    rsp,0x20
   1400018cd:	5d                   	pop    rbp
   1400018ce:	c3                   	ret
   1400018cf:	90                   	nop

00000001400018d0 <_setargv>:
   1400018d0:	55                   	push   rbp
   1400018d1:	48 89 e5             	mov    rbp,rsp
   1400018d4:	b8 00 00 00 00       	mov    eax,0x0
   1400018d9:	5d                   	pop    rbp
   1400018da:	c3                   	ret
   1400018db:	90                   	nop
   1400018dc:	90                   	nop
   1400018dd:	90                   	nop
   1400018de:	90                   	nop
   1400018df:	90                   	nop

00000001400018e0 <__dyn_tls_init>:
   1400018e0:	55                   	push   rbp
   1400018e1:	48 89 e5             	mov    rbp,rsp
   1400018e4:	48 83 ec 30          	sub    rsp,0x30
   1400018e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400018ec:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400018ef:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400018f3:	48 8b 05 56 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c56]        # 14000b550 <.refptr._CRT_MT>
   1400018fa:	8b 00                	mov    eax,DWORD PTR [rax]
   1400018fc:	83 f8 02             	cmp    eax,0x2
   1400018ff:	74 0d                	je     14000190e <__dyn_tls_init+0x2e>
   140001901:	48 8b 05 48 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c48]        # 14000b550 <.refptr._CRT_MT>
   140001908:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000190e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001912:	74 1e                	je     140001932 <__dyn_tls_init+0x52>
   140001914:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001918:	75 5b                	jne    140001975 <__dyn_tls_init+0x95>
   14000191a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   14000191e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001921:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001925:	49 89 c8             	mov    r8,rcx
   140001928:	48 89 c1             	mov    rcx,rax
   14000192b:	e8 d1 11 00 00       	call   140002b01 <__mingw_TLScallback>
   140001930:	eb 43                	jmp    140001975 <__dyn_tls_init+0x95>
   140001932:	48 8d 05 9f 9f 00 00 	lea    rax,[rip+0x9f9f]        # 14000b8d8 <___crt_xd_start__>
   140001939:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000193d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001942:	eb 22                	jmp    140001966 <__dyn_tls_init+0x86>
   140001944:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001948:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000194c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001950:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001953:	48 85 c0             	test   rax,rax
   140001956:	74 09                	je     140001961 <__dyn_tls_init+0x81>
   140001958:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000195c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000195f:	ff d0                	call   rax
   140001961:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001966:	48 8d 05 73 9f 00 00 	lea    rax,[rip+0x9f73]        # 14000b8e0 <__xd_z>
   14000196d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001971:	75 d1                	jne    140001944 <__dyn_tls_init+0x64>
   140001973:	eb 01                	jmp    140001976 <__dyn_tls_init+0x96>
   140001975:	90                   	nop
   140001976:	48 83 c4 30          	add    rsp,0x30
   14000197a:	5d                   	pop    rbp
   14000197b:	c3                   	ret

000000014000197c <__tlregdtor>:
   14000197c:	55                   	push   rbp
   14000197d:	48 89 e5             	mov    rbp,rsp
   140001980:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001984:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001989:	75 07                	jne    140001992 <__tlregdtor+0x16>
   14000198b:	b8 00 00 00 00       	mov    eax,0x0
   140001990:	eb 05                	jmp    140001997 <__tlregdtor+0x1b>
   140001992:	b8 00 00 00 00       	mov    eax,0x0
   140001997:	5d                   	pop    rbp
   140001998:	c3                   	ret

0000000140001999 <__dyn_tls_dtor>:
   140001999:	55                   	push   rbp
   14000199a:	48 89 e5             	mov    rbp,rsp
   14000199d:	48 83 ec 20          	sub    rsp,0x20
   1400019a1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019a5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019a8:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019ac:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   1400019b0:	74 06                	je     1400019b8 <__dyn_tls_dtor+0x1f>
   1400019b2:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400019b6:	75 18                	jne    1400019d0 <__dyn_tls_dtor+0x37>
   1400019b8:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019bc:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019bf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019c3:	49 89 c8             	mov    r8,rcx
   1400019c6:	48 89 c1             	mov    rcx,rax
   1400019c9:	e8 33 11 00 00       	call   140002b01 <__mingw_TLScallback>
   1400019ce:	eb 01                	jmp    1400019d1 <__dyn_tls_dtor+0x38>
   1400019d0:	90                   	nop
   1400019d1:	48 83 c4 20          	add    rsp,0x20
   1400019d5:	5d                   	pop    rbp
   1400019d6:	c3                   	ret
   1400019d7:	90                   	nop
   1400019d8:	90                   	nop
   1400019d9:	90                   	nop
   1400019da:	90                   	nop
   1400019db:	90                   	nop
   1400019dc:	90                   	nop
   1400019dd:	90                   	nop
   1400019de:	90                   	nop
   1400019df:	90                   	nop

00000001400019e0 <_matherr>:
   1400019e0:	55                   	push   rbp
   1400019e1:	53                   	push   rbx
   1400019e2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400019e9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400019ee:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   1400019f2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   1400019f6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   1400019fb:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   1400019ff:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a03:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a05:	83 f8 06             	cmp    eax,0x6
   140001a08:	74 56                	je     140001a60 <_matherr+0x80>
   140001a0a:	83 f8 06             	cmp    eax,0x6
   140001a0d:	7f 78                	jg     140001a87 <_matherr+0xa7>
   140001a0f:	83 f8 05             	cmp    eax,0x5
   140001a12:	74 59                	je     140001a6d <_matherr+0x8d>
   140001a14:	83 f8 05             	cmp    eax,0x5
   140001a17:	7f 6e                	jg     140001a87 <_matherr+0xa7>
   140001a19:	83 f8 04             	cmp    eax,0x4
   140001a1c:	74 5c                	je     140001a7a <_matherr+0x9a>
   140001a1e:	83 f8 04             	cmp    eax,0x4
   140001a21:	7f 64                	jg     140001a87 <_matherr+0xa7>
   140001a23:	83 f8 03             	cmp    eax,0x3
   140001a26:	74 2b                	je     140001a53 <_matherr+0x73>
   140001a28:	83 f8 03             	cmp    eax,0x3
   140001a2b:	7f 5a                	jg     140001a87 <_matherr+0xa7>
   140001a2d:	83 f8 01             	cmp    eax,0x1
   140001a30:	74 07                	je     140001a39 <_matherr+0x59>
   140001a32:	83 f8 02             	cmp    eax,0x2
   140001a35:	74 0f                	je     140001a46 <_matherr+0x66>
   140001a37:	eb 4e                	jmp    140001a87 <_matherr+0xa7>
   140001a39:	48 8d 05 60 96 00 00 	lea    rax,[rip+0x9660]        # 14000b0a0 <.rdata>
   140001a40:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a44:	eb 4d                	jmp    140001a93 <_matherr+0xb3>
   140001a46:	48 8d 05 72 96 00 00 	lea    rax,[rip+0x9672]        # 14000b0bf <.rdata+0x1f>
   140001a4d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a51:	eb 40                	jmp    140001a93 <_matherr+0xb3>
   140001a53:	48 8d 05 86 96 00 00 	lea    rax,[rip+0x9686]        # 14000b0e0 <.rdata+0x40>
   140001a5a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a5e:	eb 33                	jmp    140001a93 <_matherr+0xb3>
   140001a60:	48 8d 05 99 96 00 00 	lea    rax,[rip+0x9699]        # 14000b100 <.rdata+0x60>
   140001a67:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a6b:	eb 26                	jmp    140001a93 <_matherr+0xb3>
   140001a6d:	48 8d 05 b4 96 00 00 	lea    rax,[rip+0x96b4]        # 14000b128 <.rdata+0x88>
   140001a74:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a78:	eb 19                	jmp    140001a93 <_matherr+0xb3>
   140001a7a:	48 8d 05 cf 96 00 00 	lea    rax,[rip+0x96cf]        # 14000b150 <.rdata+0xb0>
   140001a81:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a85:	eb 0c                	jmp    140001a93 <_matherr+0xb3>
   140001a87:	48 8d 05 f8 96 00 00 	lea    rax,[rip+0x96f8]        # 14000b186 <.rdata+0xe6>
   140001a8e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a92:	90                   	nop
   140001a93:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a97:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001a9d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001aa1:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001aa6:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001aaa:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001aaf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ab3:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001ab7:	b9 02 00 00 00       	mov    ecx,0x2
   140001abc:	e8 2f 75 00 00       	call   140008ff0 <__acrt_iob_func>
   140001ac1:	48 89 c1             	mov    rcx,rax
   140001ac4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001ac8:	48 8d 05 c9 96 00 00 	lea    rax,[rip+0x96c9]        # 14000b198 <.rdata+0xf8>
   140001acf:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001ad6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001adc:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001ae2:	49 89 d9             	mov    r9,rbx
   140001ae5:	49 89 d0             	mov    r8,rdx
   140001ae8:	48 89 c2             	mov    rdx,rax
   140001aeb:	e8 30 7b 00 00       	call   140009620 <fprintf>
   140001af0:	b8 00 00 00 00       	mov    eax,0x0
   140001af5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001af9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001afd:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b02:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b09:	5b                   	pop    rbx
   140001b0a:	5d                   	pop    rbp
   140001b0b:	c3                   	ret
   140001b0c:	90                   	nop
   140001b0d:	90                   	nop
   140001b0e:	90                   	nop
   140001b0f:	90                   	nop

0000000140001b10 <__report_error>:
   140001b10:	55                   	push   rbp
   140001b11:	53                   	push   rbx
   140001b12:	48 83 ec 38          	sub    rsp,0x38
   140001b16:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001b1b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001b1f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001b23:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001b27:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001b2b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001b2f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b33:	b9 02 00 00 00       	mov    ecx,0x2
   140001b38:	e8 b3 74 00 00       	call   140008ff0 <__acrt_iob_func>
   140001b3d:	48 89 c1             	mov    rcx,rax
   140001b40:	48 8d 05 89 96 00 00 	lea    rax,[rip+0x9689]        # 14000b1d0 <.rdata>
   140001b47:	48 89 c2             	mov    rdx,rax
   140001b4a:	e8 d1 7a 00 00       	call   140009620 <fprintf>
   140001b4f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b53:	b9 02 00 00 00       	mov    ecx,0x2
   140001b58:	e8 93 74 00 00       	call   140008ff0 <__acrt_iob_func>
   140001b5d:	48 89 c1             	mov    rcx,rax
   140001b60:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b64:	49 89 d8             	mov    r8,rbx
   140001b67:	48 89 c2             	mov    rdx,rax
   140001b6a:	e8 11 7b 00 00       	call   140009680 <vfprintf>
   140001b6f:	e8 8c 7a 00 00       	call   140009600 <abort>
   140001b74:	90                   	nop

0000000140001b75 <mark_section_writable>:
   140001b75:	55                   	push   rbp
   140001b76:	48 89 e5             	mov    rbp,rsp
   140001b79:	48 83 ec 60          	sub    rsp,0x60
   140001b7d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001b81:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001b88:	e9 82 00 00 00       	jmp    140001c0f <mark_section_writable+0x9a>
   140001b8d:	48 8b 0d 4c d5 00 00 	mov    rcx,QWORD PTR [rip+0xd54c]        # 14000f0e0 <the_secs>
   140001b94:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001b97:	48 63 d0             	movsxd rdx,eax
   140001b9a:	48 89 d0             	mov    rax,rdx
   140001b9d:	48 c1 e0 02          	shl    rax,0x2
   140001ba1:	48 01 d0             	add    rax,rdx
   140001ba4:	48 c1 e0 03          	shl    rax,0x3
   140001ba8:	48 01 c8             	add    rax,rcx
   140001bab:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001baf:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001bb3:	72 56                	jb     140001c0b <mark_section_writable+0x96>
   140001bb5:	48 8b 0d 24 d5 00 00 	mov    rcx,QWORD PTR [rip+0xd524]        # 14000f0e0 <the_secs>
   140001bbc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001bbf:	48 63 d0             	movsxd rdx,eax
   140001bc2:	48 89 d0             	mov    rax,rdx
   140001bc5:	48 c1 e0 02          	shl    rax,0x2
   140001bc9:	48 01 d0             	add    rax,rdx
   140001bcc:	48 c1 e0 03          	shl    rax,0x3
   140001bd0:	48 01 c8             	add    rax,rcx
   140001bd3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001bd7:	4c 8b 05 02 d5 00 00 	mov    r8,QWORD PTR [rip+0xd502]        # 14000f0e0 <the_secs>
   140001bde:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001be1:	48 63 d0             	movsxd rdx,eax
   140001be4:	48 89 d0             	mov    rax,rdx
   140001be7:	48 c1 e0 02          	shl    rax,0x2
   140001beb:	48 01 d0             	add    rax,rdx
   140001bee:	48 c1 e0 03          	shl    rax,0x3
   140001bf2:	4c 01 c0             	add    rax,r8
   140001bf5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001bf9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001bfc:	89 c0                	mov    eax,eax
   140001bfe:	48 01 c8             	add    rax,rcx
   140001c01:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c05:	0f 82 41 02 00 00    	jb     140001e4c <mark_section_writable+0x2d7>
   140001c0b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c0f:	8b 05 d3 d4 00 00    	mov    eax,DWORD PTR [rip+0xd4d3]        # 14000f0e8 <maxSections>
   140001c15:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001c18:	0f 8c 6f ff ff ff    	jl     140001b8d <mark_section_writable+0x18>
   140001c1e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c22:	48 89 c1             	mov    rcx,rax
   140001c25:	e8 c1 11 00 00       	call   140002deb <__mingw_GetSectionForAddress>
   140001c2a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001c2e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001c33:	75 13                	jne    140001c48 <mark_section_writable+0xd3>
   140001c35:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001c39:	48 8d 0d b0 95 00 00 	lea    rcx,[rip+0x95b0]        # 14000b1f0 <.rdata+0x20>
   140001c40:	48 89 c2             	mov    rdx,rax
   140001c43:	e8 c8 fe ff ff       	call   140001b10 <__report_error>
   140001c48:	48 8b 0d 91 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd491]        # 14000f0e0 <the_secs>
   140001c4f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c52:	48 63 d0             	movsxd rdx,eax
   140001c55:	48 89 d0             	mov    rax,rdx
   140001c58:	48 c1 e0 02          	shl    rax,0x2
   140001c5c:	48 01 d0             	add    rax,rdx
   140001c5f:	48 c1 e0 03          	shl    rax,0x3
   140001c63:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001c67:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c6b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001c6f:	48 8b 0d 6a d4 00 00 	mov    rcx,QWORD PTR [rip+0xd46a]        # 14000f0e0 <the_secs>
   140001c76:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c79:	48 63 d0             	movsxd rdx,eax
   140001c7c:	48 89 d0             	mov    rax,rdx
   140001c7f:	48 c1 e0 02          	shl    rax,0x2
   140001c83:	48 01 d0             	add    rax,rdx
   140001c86:	48 c1 e0 03          	shl    rax,0x3
   140001c8a:	48 01 c8             	add    rax,rcx
   140001c8d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001c93:	e8 9f 12 00 00       	call   140002f37 <_GetPEImageBase>
   140001c98:	48 89 c1             	mov    rcx,rax
   140001c9b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001c9f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001ca2:	41 89 c1             	mov    r9d,eax
   140001ca5:	4c 8b 05 34 d4 00 00 	mov    r8,QWORD PTR [rip+0xd434]        # 14000f0e0 <the_secs>
   140001cac:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001caf:	48 63 d0             	movsxd rdx,eax
   140001cb2:	48 89 d0             	mov    rax,rdx
   140001cb5:	48 c1 e0 02          	shl    rax,0x2
   140001cb9:	48 01 d0             	add    rax,rdx
   140001cbc:	48 c1 e0 03          	shl    rax,0x3
   140001cc0:	4c 01 c0             	add    rax,r8
   140001cc3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001cc7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001ccb:	48 8b 0d 0e d4 00 00 	mov    rcx,QWORD PTR [rip+0xd40e]        # 14000f0e0 <the_secs>
   140001cd2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cd5:	48 63 d0             	movsxd rdx,eax
   140001cd8:	48 89 d0             	mov    rax,rdx
   140001cdb:	48 c1 e0 02          	shl    rax,0x2
   140001cdf:	48 01 d0             	add    rax,rdx
   140001ce2:	48 c1 e0 03          	shl    rax,0x3
   140001ce6:	48 01 c8             	add    rax,rcx
   140001ce9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001ced:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001cf1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001cf7:	48 89 c1             	mov    rcx,rax
   140001cfa:	48 8b 05 67 e5 00 00 	mov    rax,QWORD PTR [rip+0xe567]        # 140010268 <__imp_VirtualQuery>
   140001d01:	ff d0                	call   rax
   140001d03:	48 85 c0             	test   rax,rax
   140001d06:	75 3f                	jne    140001d47 <mark_section_writable+0x1d2>
   140001d08:	48 8b 0d d1 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3d1]        # 14000f0e0 <the_secs>
   140001d0f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d12:	48 63 d0             	movsxd rdx,eax
   140001d15:	48 89 d0             	mov    rax,rdx
   140001d18:	48 c1 e0 02          	shl    rax,0x2
   140001d1c:	48 01 d0             	add    rax,rdx
   140001d1f:	48 c1 e0 03          	shl    rax,0x3
   140001d23:	48 01 c8             	add    rax,rcx
   140001d26:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001d2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d2e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001d31:	89 c1                	mov    ecx,eax
   140001d33:	48 8d 05 d6 94 00 00 	lea    rax,[rip+0x94d6]        # 14000b210 <.rdata+0x40>
   140001d3a:	49 89 d0             	mov    r8,rdx
   140001d3d:	89 ca                	mov    edx,ecx
   140001d3f:	48 89 c1             	mov    rcx,rax
   140001d42:	e8 c9 fd ff ff       	call   140001b10 <__report_error>
   140001d47:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d4a:	83 f8 40             	cmp    eax,0x40
   140001d4d:	0f 84 e8 00 00 00    	je     140001e3b <mark_section_writable+0x2c6>
   140001d53:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d56:	83 f8 04             	cmp    eax,0x4
   140001d59:	0f 84 dc 00 00 00    	je     140001e3b <mark_section_writable+0x2c6>
   140001d5f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d62:	3d 80 00 00 00       	cmp    eax,0x80
   140001d67:	0f 84 ce 00 00 00    	je     140001e3b <mark_section_writable+0x2c6>
   140001d6d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d70:	83 f8 08             	cmp    eax,0x8
   140001d73:	0f 84 c2 00 00 00    	je     140001e3b <mark_section_writable+0x2c6>
   140001d79:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001d7c:	83 f8 02             	cmp    eax,0x2
   140001d7f:	75 09                	jne    140001d8a <mark_section_writable+0x215>
   140001d81:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001d88:	eb 07                	jmp    140001d91 <mark_section_writable+0x21c>
   140001d8a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001d91:	48 8b 0d 48 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd348]        # 14000f0e0 <the_secs>
   140001d98:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d9b:	48 63 d0             	movsxd rdx,eax
   140001d9e:	48 89 d0             	mov    rax,rdx
   140001da1:	48 c1 e0 02          	shl    rax,0x2
   140001da5:	48 01 d0             	add    rax,rdx
   140001da8:	48 c1 e0 03          	shl    rax,0x3
   140001dac:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001db0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001db4:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001db8:	48 8b 0d 21 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd321]        # 14000f0e0 <the_secs>
   140001dbf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dc2:	48 63 d0             	movsxd rdx,eax
   140001dc5:	48 89 d0             	mov    rax,rdx
   140001dc8:	48 c1 e0 02          	shl    rax,0x2
   140001dcc:	48 01 d0             	add    rax,rdx
   140001dcf:	48 c1 e0 03          	shl    rax,0x3
   140001dd3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001dd7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001ddb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001ddf:	48 8b 0d fa d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2fa]        # 14000f0e0 <the_secs>
   140001de6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001de9:	48 63 d0             	movsxd rdx,eax
   140001dec:	48 89 d0             	mov    rax,rdx
   140001def:	48 c1 e0 02          	shl    rax,0x2
   140001df3:	48 01 d0             	add    rax,rdx
   140001df6:	48 c1 e0 03          	shl    rax,0x3
   140001dfa:	48 01 c8             	add    rax,rcx
   140001dfd:	49 89 c0             	mov    r8,rax
   140001e00:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e04:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e08:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e0b:	4d 89 c1             	mov    r9,r8
   140001e0e:	41 89 c8             	mov    r8d,ecx
   140001e11:	48 89 c1             	mov    rcx,rax
   140001e14:	48 8b 05 45 e4 00 00 	mov    rax,QWORD PTR [rip+0xe445]        # 140010260 <__imp_VirtualProtect>
   140001e1b:	ff d0                	call   rax
   140001e1d:	85 c0                	test   eax,eax
   140001e1f:	75 1a                	jne    140001e3b <mark_section_writable+0x2c6>
   140001e21:	48 8b 05 e8 e3 00 00 	mov    rax,QWORD PTR [rip+0xe3e8]        # 140010210 <__imp_GetLastError>
   140001e28:	ff d0                	call   rax
   140001e2a:	89 c2                	mov    edx,eax
   140001e2c:	48 8d 05 15 94 00 00 	lea    rax,[rip+0x9415]        # 14000b248 <.rdata+0x78>
   140001e33:	48 89 c1             	mov    rcx,rax
   140001e36:	e8 d5 fc ff ff       	call   140001b10 <__report_error>
   140001e3b:	8b 05 a7 d2 00 00    	mov    eax,DWORD PTR [rip+0xd2a7]        # 14000f0e8 <maxSections>
   140001e41:	83 c0 01             	add    eax,0x1
   140001e44:	89 05 9e d2 00 00    	mov    DWORD PTR [rip+0xd29e],eax        # 14000f0e8 <maxSections>
   140001e4a:	eb 01                	jmp    140001e4d <mark_section_writable+0x2d8>
   140001e4c:	90                   	nop
   140001e4d:	48 83 c4 60          	add    rsp,0x60
   140001e51:	5d                   	pop    rbp
   140001e52:	c3                   	ret

0000000140001e53 <restore_modified_sections>:
   140001e53:	55                   	push   rbp
   140001e54:	48 89 e5             	mov    rbp,rsp
   140001e57:	48 83 ec 30          	sub    rsp,0x30
   140001e5b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001e62:	e9 ad 00 00 00       	jmp    140001f14 <restore_modified_sections+0xc1>
   140001e67:	48 8b 0d 72 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd272]        # 14000f0e0 <the_secs>
   140001e6e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e71:	48 63 d0             	movsxd rdx,eax
   140001e74:	48 89 d0             	mov    rax,rdx
   140001e77:	48 c1 e0 02          	shl    rax,0x2
   140001e7b:	48 01 d0             	add    rax,rdx
   140001e7e:	48 c1 e0 03          	shl    rax,0x3
   140001e82:	48 01 c8             	add    rax,rcx
   140001e85:	8b 00                	mov    eax,DWORD PTR [rax]
   140001e87:	85 c0                	test   eax,eax
   140001e89:	0f 84 80 00 00 00    	je     140001f0f <restore_modified_sections+0xbc>
   140001e8f:	48 8b 0d 4a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd24a]        # 14000f0e0 <the_secs>
   140001e96:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e99:	48 63 d0             	movsxd rdx,eax
   140001e9c:	48 89 d0             	mov    rax,rdx
   140001e9f:	48 c1 e0 02          	shl    rax,0x2
   140001ea3:	48 01 d0             	add    rax,rdx
   140001ea6:	48 c1 e0 03          	shl    rax,0x3
   140001eaa:	48 01 c8             	add    rax,rcx
   140001ead:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001eb0:	48 8b 0d 29 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd229]        # 14000f0e0 <the_secs>
   140001eb7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eba:	48 63 d0             	movsxd rdx,eax
   140001ebd:	48 89 d0             	mov    rax,rdx
   140001ec0:	48 c1 e0 02          	shl    rax,0x2
   140001ec4:	48 01 d0             	add    rax,rdx
   140001ec7:	48 c1 e0 03          	shl    rax,0x3
   140001ecb:	48 01 c8             	add    rax,rcx
   140001ece:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001ed2:	4c 8b 05 07 d2 00 00 	mov    r8,QWORD PTR [rip+0xd207]        # 14000f0e0 <the_secs>
   140001ed9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001edc:	48 63 d0             	movsxd rdx,eax
   140001edf:	48 89 d0             	mov    rax,rdx
   140001ee2:	48 c1 e0 02          	shl    rax,0x2
   140001ee6:	48 01 d0             	add    rax,rdx
   140001ee9:	48 c1 e0 03          	shl    rax,0x3
   140001eed:	4c 01 c0             	add    rax,r8
   140001ef0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001ef4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001ef8:	49 89 d1             	mov    r9,rdx
   140001efb:	45 89 d0             	mov    r8d,r10d
   140001efe:	48 89 ca             	mov    rdx,rcx
   140001f01:	48 89 c1             	mov    rcx,rax
   140001f04:	48 8b 05 55 e3 00 00 	mov    rax,QWORD PTR [rip+0xe355]        # 140010260 <__imp_VirtualProtect>
   140001f0b:	ff d0                	call   rax
   140001f0d:	eb 01                	jmp    140001f10 <restore_modified_sections+0xbd>
   140001f0f:	90                   	nop
   140001f10:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001f14:	8b 05 ce d1 00 00    	mov    eax,DWORD PTR [rip+0xd1ce]        # 14000f0e8 <maxSections>
   140001f1a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001f1d:	0f 8c 44 ff ff ff    	jl     140001e67 <restore_modified_sections+0x14>
   140001f23:	90                   	nop
   140001f24:	90                   	nop
   140001f25:	48 83 c4 30          	add    rsp,0x30
   140001f29:	5d                   	pop    rbp
   140001f2a:	c3                   	ret

0000000140001f2b <__write_memory>:
   140001f2b:	55                   	push   rbp
   140001f2c:	48 89 e5             	mov    rbp,rsp
   140001f2f:	48 83 ec 20          	sub    rsp,0x20
   140001f33:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f37:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f3b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f3f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001f44:	74 25                	je     140001f6b <__write_memory+0x40>
   140001f46:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f4a:	48 89 c1             	mov    rcx,rax
   140001f4d:	e8 23 fc ff ff       	call   140001b75 <mark_section_writable>
   140001f52:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001f56:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001f5a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f5e:	49 89 c8             	mov    r8,rcx
   140001f61:	48 89 c1             	mov    rcx,rax
   140001f64:	e8 df 76 00 00       	call   140009648 <memcpy>
   140001f69:	eb 01                	jmp    140001f6c <__write_memory+0x41>
   140001f6b:	90                   	nop
   140001f6c:	48 83 c4 20          	add    rsp,0x20
   140001f70:	5d                   	pop    rbp
   140001f71:	c3                   	ret

0000000140001f72 <do_pseudo_reloc>:
   140001f72:	55                   	push   rbp
   140001f73:	48 89 e5             	mov    rbp,rsp
   140001f76:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   140001f7a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001f7e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001f82:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001f86:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140001f8a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140001f8e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001f92:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001f96:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001f9a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   140001f9f:	0f 8e 44 03 00 00    	jle    1400022e9 <do_pseudo_reloc+0x377>
   140001fa5:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   140001faa:	7e 25                	jle    140001fd1 <do_pseudo_reloc+0x5f>
   140001fac:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fb0:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fb2:	85 c0                	test   eax,eax
   140001fb4:	75 1b                	jne    140001fd1 <do_pseudo_reloc+0x5f>
   140001fb6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fba:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fbd:	85 c0                	test   eax,eax
   140001fbf:	75 10                	jne    140001fd1 <do_pseudo_reloc+0x5f>
   140001fc1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fc5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001fc8:	85 c0                	test   eax,eax
   140001fca:	75 05                	jne    140001fd1 <do_pseudo_reloc+0x5f>
   140001fcc:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140001fd1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fd5:	8b 00                	mov    eax,DWORD PTR [rax]
   140001fd7:	85 c0                	test   eax,eax
   140001fd9:	75 0b                	jne    140001fe6 <do_pseudo_reloc+0x74>
   140001fdb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fdf:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001fe2:	85 c0                	test   eax,eax
   140001fe4:	74 59                	je     14000203f <do_pseudo_reloc+0xcd>
   140001fe6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001fea:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001fee:	eb 40                	jmp    140002030 <do_pseudo_reloc+0xbe>
   140001ff0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001ff4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001ff7:	89 c2                	mov    edx,eax
   140001ff9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001ffd:	48 01 d0             	add    rax,rdx
   140002000:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002004:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002008:	8b 10                	mov    edx,DWORD PTR [rax]
   14000200a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000200e:	8b 00                	mov    eax,DWORD PTR [rax]
   140002010:	01 d0                	add    eax,edx
   140002012:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002015:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002019:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000201d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002023:	48 89 c1             	mov    rcx,rax
   140002026:	e8 00 ff ff ff       	call   140001f2b <__write_memory>
   14000202b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002030:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002034:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002038:	72 b6                	jb     140001ff0 <do_pseudo_reloc+0x7e>
   14000203a:	e9 ab 02 00 00       	jmp    1400022ea <do_pseudo_reloc+0x378>
   14000203f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002043:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002046:	83 f8 01             	cmp    eax,0x1
   140002049:	74 18                	je     140002063 <do_pseudo_reloc+0xf1>
   14000204b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000204f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002052:	89 c2                	mov    edx,eax
   140002054:	48 8d 05 15 92 00 00 	lea    rax,[rip+0x9215]        # 14000b270 <.rdata+0xa0>
   14000205b:	48 89 c1             	mov    rcx,rax
   14000205e:	e8 ad fa ff ff       	call   140001b10 <__report_error>
   140002063:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002067:	48 83 c0 0c          	add    rax,0xc
   14000206b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000206f:	e9 65 02 00 00       	jmp    1400022d9 <do_pseudo_reloc+0x367>
   140002074:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002078:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000207b:	89 c2                	mov    edx,eax
   14000207d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002081:	48 01 d0             	add    rax,rdx
   140002084:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002088:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000208c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000208e:	89 c2                	mov    edx,eax
   140002090:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002094:	48 01 d0             	add    rax,rdx
   140002097:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000209b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000209f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400020a2:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400020a6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400020aa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020ad:	0f b6 c0             	movzx  eax,al
   1400020b0:	83 f8 40             	cmp    eax,0x40
   1400020b3:	0f 84 b6 00 00 00    	je     14000216f <do_pseudo_reloc+0x1fd>
   1400020b9:	83 f8 40             	cmp    eax,0x40
   1400020bc:	0f 87 ba 00 00 00    	ja     14000217c <do_pseudo_reloc+0x20a>
   1400020c2:	83 f8 20             	cmp    eax,0x20
   1400020c5:	74 77                	je     14000213e <do_pseudo_reloc+0x1cc>
   1400020c7:	83 f8 20             	cmp    eax,0x20
   1400020ca:	0f 87 ac 00 00 00    	ja     14000217c <do_pseudo_reloc+0x20a>
   1400020d0:	83 f8 08             	cmp    eax,0x8
   1400020d3:	74 0a                	je     1400020df <do_pseudo_reloc+0x16d>
   1400020d5:	83 f8 10             	cmp    eax,0x10
   1400020d8:	74 38                	je     140002112 <do_pseudo_reloc+0x1a0>
   1400020da:	e9 9d 00 00 00       	jmp    14000217c <do_pseudo_reloc+0x20a>
   1400020df:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020e3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400020e6:	0f b6 c0             	movzx  eax,al
   1400020e9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400020ed:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400020f1:	25 80 00 00 00       	and    eax,0x80
   1400020f6:	48 85 c0             	test   rax,rax
   1400020f9:	0f 84 9d 00 00 00    	je     14000219c <do_pseudo_reloc+0x22a>
   1400020ff:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002103:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002109:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000210d:	e9 8a 00 00 00       	jmp    14000219c <do_pseudo_reloc+0x22a>
   140002112:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002116:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002119:	0f b7 c0             	movzx  eax,ax
   14000211c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002120:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002124:	25 00 80 00 00       	and    eax,0x8000
   140002129:	48 85 c0             	test   rax,rax
   14000212c:	74 71                	je     14000219f <do_pseudo_reloc+0x22d>
   14000212e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002132:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002138:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000213c:	eb 61                	jmp    14000219f <do_pseudo_reloc+0x22d>
   14000213e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002142:	8b 00                	mov    eax,DWORD PTR [rax]
   140002144:	89 c0                	mov    eax,eax
   140002146:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000214a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000214e:	25 00 00 00 80       	and    eax,0x80000000
   140002153:	48 85 c0             	test   rax,rax
   140002156:	74 4a                	je     1400021a2 <do_pseudo_reloc+0x230>
   140002158:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000215c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002163:	ff ff ff 
   140002166:	48 09 d0             	or     rax,rdx
   140002169:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000216d:	eb 33                	jmp    1400021a2 <do_pseudo_reloc+0x230>
   14000216f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002173:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002176:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000217a:	eb 27                	jmp    1400021a3 <do_pseudo_reloc+0x231>
   14000217c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002183:	00 
   140002184:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002188:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000218b:	0f b6 c0             	movzx  eax,al
   14000218e:	48 8d 0d 13 91 00 00 	lea    rcx,[rip+0x9113]        # 14000b2a8 <.rdata+0xd8>
   140002195:	89 c2                	mov    edx,eax
   140002197:	e8 74 f9 ff ff       	call   140001b10 <__report_error>
   14000219c:	90                   	nop
   14000219d:	eb 04                	jmp    1400021a3 <do_pseudo_reloc+0x231>
   14000219f:	90                   	nop
   1400021a0:	eb 01                	jmp    1400021a3 <do_pseudo_reloc+0x231>
   1400021a2:	90                   	nop
   1400021a3:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   1400021a7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021ad:	89 c2                	mov    edx,eax
   1400021af:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400021b3:	48 01 c2             	add    rdx,rax
   1400021b6:	48 89 c8             	mov    rax,rcx
   1400021b9:	48 29 d0             	sub    rax,rdx
   1400021bc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021c0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400021c4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400021c8:	48 01 d0             	add    rax,rdx
   1400021cb:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021cf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400021d3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400021d6:	25 ff 00 00 00       	and    eax,0xff
   1400021db:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400021de:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400021e2:	77 67                	ja     14000224b <do_pseudo_reloc+0x2d9>
   1400021e4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021e7:	ba 01 00 00 00       	mov    edx,0x1
   1400021ec:	89 c1                	mov    ecx,eax
   1400021ee:	48 d3 e2             	shl    rdx,cl
   1400021f1:	48 89 d0             	mov    rax,rdx
   1400021f4:	48 83 e8 01          	sub    rax,0x1
   1400021f8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400021fc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400021ff:	83 e8 01             	sub    eax,0x1
   140002202:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002209:	89 c1                	mov    ecx,eax
   14000220b:	48 d3 e2             	shl    rdx,cl
   14000220e:	48 89 d0             	mov    rax,rdx
   140002211:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002215:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002219:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000221d:	7c 0a                	jl     140002229 <do_pseudo_reloc+0x2b7>
   14000221f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002223:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002227:	7e 22                	jle    14000224b <do_pseudo_reloc+0x2d9>
   140002229:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000222d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002231:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002235:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002238:	48 8d 0d 99 90 00 00 	lea    rcx,[rip+0x9099]        # 14000b2d8 <.rdata+0x108>
   14000223f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002244:	89 c2                	mov    edx,eax
   140002246:	e8 c5 f8 ff ff       	call   140001b10 <__report_error>
   14000224b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000224f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002252:	0f b6 c0             	movzx  eax,al
   140002255:	83 f8 40             	cmp    eax,0x40
   140002258:	74 63                	je     1400022bd <do_pseudo_reloc+0x34b>
   14000225a:	83 f8 40             	cmp    eax,0x40
   14000225d:	77 75                	ja     1400022d4 <do_pseudo_reloc+0x362>
   14000225f:	83 f8 20             	cmp    eax,0x20
   140002262:	74 41                	je     1400022a5 <do_pseudo_reloc+0x333>
   140002264:	83 f8 20             	cmp    eax,0x20
   140002267:	77 6b                	ja     1400022d4 <do_pseudo_reloc+0x362>
   140002269:	83 f8 08             	cmp    eax,0x8
   14000226c:	74 07                	je     140002275 <do_pseudo_reloc+0x303>
   14000226e:	83 f8 10             	cmp    eax,0x10
   140002271:	74 1a                	je     14000228d <do_pseudo_reloc+0x31b>
   140002273:	eb 5f                	jmp    1400022d4 <do_pseudo_reloc+0x362>
   140002275:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002279:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000227d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002283:	48 89 c1             	mov    rcx,rax
   140002286:	e8 a0 fc ff ff       	call   140001f2b <__write_memory>
   14000228b:	eb 47                	jmp    1400022d4 <do_pseudo_reloc+0x362>
   14000228d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002291:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002295:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000229b:	48 89 c1             	mov    rcx,rax
   14000229e:	e8 88 fc ff ff       	call   140001f2b <__write_memory>
   1400022a3:	eb 2f                	jmp    1400022d4 <do_pseudo_reloc+0x362>
   1400022a5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022a9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022ad:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400022b3:	48 89 c1             	mov    rcx,rax
   1400022b6:	e8 70 fc ff ff       	call   140001f2b <__write_memory>
   1400022bb:	eb 17                	jmp    1400022d4 <do_pseudo_reloc+0x362>
   1400022bd:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400022c1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400022c5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400022cb:	48 89 c1             	mov    rcx,rax
   1400022ce:	e8 58 fc ff ff       	call   140001f2b <__write_memory>
   1400022d3:	90                   	nop
   1400022d4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400022d9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022dd:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400022e1:	0f 82 8d fd ff ff    	jb     140002074 <do_pseudo_reloc+0x102>
   1400022e7:	eb 01                	jmp    1400022ea <do_pseudo_reloc+0x378>
   1400022e9:	90                   	nop
   1400022ea:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400022ee:	5d                   	pop    rbp
   1400022ef:	c3                   	ret

00000001400022f0 <_pei386_runtime_relocator>:
   1400022f0:	55                   	push   rbp
   1400022f1:	48 89 e5             	mov    rbp,rsp
   1400022f4:	48 83 ec 30          	sub    rsp,0x30
   1400022f8:	8b 05 ee cd 00 00    	mov    eax,DWORD PTR [rip+0xcdee]        # 14000f0ec <was_init.0>
   1400022fe:	85 c0                	test   eax,eax
   140002300:	0f 85 88 00 00 00    	jne    14000238e <_pei386_runtime_relocator+0x9e>
   140002306:	8b 05 e0 cd 00 00    	mov    eax,DWORD PTR [rip+0xcde0]        # 14000f0ec <was_init.0>
   14000230c:	83 c0 01             	add    eax,0x1
   14000230f:	89 05 d7 cd 00 00    	mov    DWORD PTR [rip+0xcdd7],eax        # 14000f0ec <was_init.0>
   140002315:	e8 21 0b 00 00       	call   140002e3b <__mingw_GetSectionCount>
   14000231a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000231d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002320:	48 63 d0             	movsxd rdx,eax
   140002323:	48 89 d0             	mov    rax,rdx
   140002326:	48 c1 e0 02          	shl    rax,0x2
   14000232a:	48 01 d0             	add    rax,rdx
   14000232d:	48 c1 e0 03          	shl    rax,0x3
   140002331:	48 83 c0 0f          	add    rax,0xf
   140002335:	48 c1 e8 04          	shr    rax,0x4
   140002339:	48 c1 e0 04          	shl    rax,0x4
   14000233d:	e8 7e 0d 00 00       	call   1400030c0 <___chkstk_ms>
   140002342:	48 29 c4             	sub    rsp,rax
   140002345:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000234a:	48 83 c0 0f          	add    rax,0xf
   14000234e:	48 c1 e8 04          	shr    rax,0x4
   140002352:	48 c1 e0 04          	shl    rax,0x4
   140002356:	48 89 05 83 cd 00 00 	mov    QWORD PTR [rip+0xcd83],rax        # 14000f0e0 <the_secs>
   14000235d:	c7 05 81 cd 00 00 00 	mov    DWORD PTR [rip+0xcd81],0x0        # 14000f0e8 <maxSections>
   140002364:	00 00 00 
   140002367:	48 8b 0d 12 92 00 00 	mov    rcx,QWORD PTR [rip+0x9212]        # 14000b580 <.refptr.__ImageBase>
   14000236e:	48 8b 15 1b 92 00 00 	mov    rdx,QWORD PTR [rip+0x921b]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002375:	48 8b 05 24 92 00 00 	mov    rax,QWORD PTR [rip+0x9224]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000237c:	49 89 c8             	mov    r8,rcx
   14000237f:	48 89 c1             	mov    rcx,rax
   140002382:	e8 eb fb ff ff       	call   140001f72 <do_pseudo_reloc>
   140002387:	e8 c7 fa ff ff       	call   140001e53 <restore_modified_sections>
   14000238c:	eb 01                	jmp    14000238f <_pei386_runtime_relocator+0x9f>
   14000238e:	90                   	nop
   14000238f:	48 89 ec             	mov    rsp,rbp
   140002392:	5d                   	pop    rbp
   140002393:	c3                   	ret
   140002394:	90                   	nop
   140002395:	90                   	nop
   140002396:	90                   	nop
   140002397:	90                   	nop
   140002398:	90                   	nop
   140002399:	90                   	nop
   14000239a:	90                   	nop
   14000239b:	90                   	nop
   14000239c:	90                   	nop
   14000239d:	90                   	nop
   14000239e:	90                   	nop
   14000239f:	90                   	nop

00000001400023a0 <__mingw_raise_matherr>:
   1400023a0:	55                   	push   rbp
   1400023a1:	48 89 e5             	mov    rbp,rsp
   1400023a4:	48 83 ec 50          	sub    rsp,0x50
   1400023a8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400023ab:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400023af:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   1400023b4:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   1400023b9:	48 8b 05 30 cd 00 00 	mov    rax,QWORD PTR [rip+0xcd30]        # 14000f0f0 <stUserMathErr>
   1400023c0:	48 85 c0             	test   rax,rax
   1400023c3:	74 3e                	je     140002403 <__mingw_raise_matherr+0x63>
   1400023c5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400023c8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400023cb:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400023cf:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400023d3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400023d8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400023dd:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400023e2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400023e7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400023ec:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400023f1:	48 8b 15 f8 cc 00 00 	mov    rdx,QWORD PTR [rip+0xccf8]        # 14000f0f0 <stUserMathErr>
   1400023f8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400023fc:	48 89 c1             	mov    rcx,rax
   1400023ff:	ff d2                	call   rdx
   140002401:	eb 01                	jmp    140002404 <__mingw_raise_matherr+0x64>
   140002403:	90                   	nop
   140002404:	48 83 c4 50          	add    rsp,0x50
   140002408:	5d                   	pop    rbp
   140002409:	c3                   	ret

000000014000240a <__mingw_setusermatherr>:
   14000240a:	55                   	push   rbp
   14000240b:	48 89 e5             	mov    rbp,rsp
   14000240e:	48 83 ec 20          	sub    rsp,0x20
   140002412:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002416:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000241a:	48 89 05 cf cc 00 00 	mov    QWORD PTR [rip+0xcccf],rax        # 14000f0f0 <stUserMathErr>
   140002421:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002425:	48 89 c1             	mov    rcx,rax
   140002428:	e8 93 71 00 00       	call   1400095c0 <__setusermatherr>
   14000242d:	90                   	nop
   14000242e:	48 83 c4 20          	add    rsp,0x20
   140002432:	5d                   	pop    rbp
   140002433:	c3                   	ret
   140002434:	90                   	nop
   140002435:	90                   	nop
   140002436:	90                   	nop
   140002437:	90                   	nop
   140002438:	90                   	nop
   140002439:	90                   	nop
   14000243a:	90                   	nop
   14000243b:	90                   	nop
   14000243c:	90                   	nop
   14000243d:	90                   	nop
   14000243e:	90                   	nop
   14000243f:	90                   	nop

0000000140002440 <__mingw_SEH_error_handler>:
   140002440:	55                   	push   rbp
   140002441:	48 89 e5             	mov    rbp,rsp
   140002444:	48 83 ec 30          	sub    rsp,0x30
   140002448:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000244c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002450:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002454:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002458:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000245f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002466:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000246a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000246d:	83 e0 02             	and    eax,0x2
   140002470:	85 c0                	test   eax,eax
   140002472:	74 0a                	je     14000247e <__mingw_SEH_error_handler+0x3e>
   140002474:	b8 01 00 00 00       	mov    eax,0x1
   140002479:	e9 16 02 00 00       	jmp    140002694 <__mingw_SEH_error_handler+0x254>
   14000247e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002482:	8b 00                	mov    eax,DWORD PTR [rax]
   140002484:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002489:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000248e:	75 18                	jne    1400024a8 <__mingw_SEH_error_handler+0x68>
   140002490:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002494:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002497:	83 e0 01             	and    eax,0x1
   14000249a:	85 c0                	test   eax,eax
   14000249c:	75 0a                	jne    1400024a8 <__mingw_SEH_error_handler+0x68>
   14000249e:	b8 00 00 00 00       	mov    eax,0x0
   1400024a3:	e9 ec 01 00 00       	jmp    140002694 <__mingw_SEH_error_handler+0x254>
   1400024a8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024ac:	8b 00                	mov    eax,DWORD PTR [rax]
   1400024ae:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024b3:	0f 84 12 01 00 00    	je     1400025cb <__mingw_SEH_error_handler+0x18b>
   1400024b9:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400024be:	0f 87 c3 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   1400024c4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400024c9:	0f 87 b8 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   1400024cf:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400024d4:	0f 83 4c 01 00 00    	jae    140002626 <__mingw_SEH_error_handler+0x1e6>
   1400024da:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024df:	0f 84 3a 01 00 00    	je     14000261f <__mingw_SEH_error_handler+0x1df>
   1400024e5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400024ea:	0f 87 97 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   1400024f0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400024f5:	0f 84 83 01 00 00    	je     14000267e <__mingw_SEH_error_handler+0x23e>
   1400024fb:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002500:	0f 87 81 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   140002506:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000250b:	0f 87 76 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   140002511:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002516:	0f 83 03 01 00 00    	jae    14000261f <__mingw_SEH_error_handler+0x1df>
   14000251c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002521:	0f 84 57 01 00 00    	je     14000267e <__mingw_SEH_error_handler+0x23e>
   140002527:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000252c:	0f 87 55 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   140002532:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002537:	0f 84 8e 00 00 00    	je     1400025cb <__mingw_SEH_error_handler+0x18b>
   14000253d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002542:	0f 87 3f 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   140002548:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000254d:	0f 84 2b 01 00 00    	je     14000267e <__mingw_SEH_error_handler+0x23e>
   140002553:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002558:	0f 87 29 01 00 00    	ja     140002687 <__mingw_SEH_error_handler+0x247>
   14000255e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002563:	0f 84 15 01 00 00    	je     14000267e <__mingw_SEH_error_handler+0x23e>
   140002569:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000256e:	0f 85 13 01 00 00    	jne    140002687 <__mingw_SEH_error_handler+0x247>
   140002574:	ba 00 00 00 00       	mov    edx,0x0
   140002579:	b9 0b 00 00 00       	mov    ecx,0xb
   14000257e:	e8 d5 70 00 00       	call   140009658 <signal>
   140002583:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002587:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000258c:	75 1b                	jne    1400025a9 <__mingw_SEH_error_handler+0x169>
   14000258e:	ba 01 00 00 00       	mov    edx,0x1
   140002593:	b9 0b 00 00 00       	mov    ecx,0xb
   140002598:	e8 bb 70 00 00       	call   140009658 <signal>
   14000259d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025a4:	e9 e1 00 00 00       	jmp    14000268a <__mingw_SEH_error_handler+0x24a>
   1400025a9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400025ae:	0f 84 d6 00 00 00    	je     14000268a <__mingw_SEH_error_handler+0x24a>
   1400025b4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400025b8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400025bd:	ff d0                	call   rax
   1400025bf:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025c6:	e9 bf 00 00 00       	jmp    14000268a <__mingw_SEH_error_handler+0x24a>
   1400025cb:	ba 00 00 00 00       	mov    edx,0x0
   1400025d0:	b9 04 00 00 00       	mov    ecx,0x4
   1400025d5:	e8 7e 70 00 00       	call   140009658 <signal>
   1400025da:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025de:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025e3:	75 1b                	jne    140002600 <__mingw_SEH_error_handler+0x1c0>
   1400025e5:	ba 01 00 00 00       	mov    edx,0x1
   1400025ea:	b9 04 00 00 00       	mov    ecx,0x4
   1400025ef:	e8 64 70 00 00       	call   140009658 <signal>
   1400025f4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400025fb:	e9 8d 00 00 00       	jmp    14000268d <__mingw_SEH_error_handler+0x24d>
   140002600:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002605:	0f 84 82 00 00 00    	je     14000268d <__mingw_SEH_error_handler+0x24d>
   14000260b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000260f:	b9 04 00 00 00       	mov    ecx,0x4
   140002614:	ff d0                	call   rax
   140002616:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000261d:	eb 6e                	jmp    14000268d <__mingw_SEH_error_handler+0x24d>
   14000261f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002626:	ba 00 00 00 00       	mov    edx,0x0
   14000262b:	b9 08 00 00 00       	mov    ecx,0x8
   140002630:	e8 23 70 00 00       	call   140009658 <signal>
   140002635:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002639:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000263e:	75 23                	jne    140002663 <__mingw_SEH_error_handler+0x223>
   140002640:	ba 01 00 00 00       	mov    edx,0x1
   140002645:	b9 08 00 00 00       	mov    ecx,0x8
   14000264a:	e8 09 70 00 00       	call   140009658 <signal>
   14000264f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002653:	74 05                	je     14000265a <__mingw_SEH_error_handler+0x21a>
   140002655:	e8 a6 05 00 00       	call   140002c00 <_fpreset>
   14000265a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002661:	eb 2d                	jmp    140002690 <__mingw_SEH_error_handler+0x250>
   140002663:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002668:	74 26                	je     140002690 <__mingw_SEH_error_handler+0x250>
   14000266a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000266e:	b9 08 00 00 00       	mov    ecx,0x8
   140002673:	ff d0                	call   rax
   140002675:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000267c:	eb 12                	jmp    140002690 <__mingw_SEH_error_handler+0x250>
   14000267e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002685:	eb 0a                	jmp    140002691 <__mingw_SEH_error_handler+0x251>
   140002687:	90                   	nop
   140002688:	eb 07                	jmp    140002691 <__mingw_SEH_error_handler+0x251>
   14000268a:	90                   	nop
   14000268b:	eb 04                	jmp    140002691 <__mingw_SEH_error_handler+0x251>
   14000268d:	90                   	nop
   14000268e:	eb 01                	jmp    140002691 <__mingw_SEH_error_handler+0x251>
   140002690:	90                   	nop
   140002691:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002694:	48 83 c4 30          	add    rsp,0x30
   140002698:	5d                   	pop    rbp
   140002699:	c3                   	ret

000000014000269a <_gnu_exception_handler>:
   14000269a:	55                   	push   rbp
   14000269b:	48 89 e5             	mov    rbp,rsp
   14000269e:	48 83 ec 30          	sub    rsp,0x30
   1400026a2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400026a6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026ad:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400026b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026b8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026bb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026bd:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400026c2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400026c7:	75 1b                	jne    1400026e4 <_gnu_exception_handler+0x4a>
   1400026c9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026cd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026d0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400026d3:	83 e0 01             	and    eax,0x1
   1400026d6:	85 c0                	test   eax,eax
   1400026d8:	75 0a                	jne    1400026e4 <_gnu_exception_handler+0x4a>
   1400026da:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400026df:	e9 14 02 00 00       	jmp    1400028f8 <_gnu_exception_handler+0x25e>
   1400026e4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400026e8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400026eb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400026ed:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026f2:	0f 84 12 01 00 00    	je     14000280a <_gnu_exception_handler+0x170>
   1400026f8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400026fd:	0f 87 c3 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   140002703:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002708:	0f 87 b8 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   14000270e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002713:	0f 83 4c 01 00 00    	jae    140002865 <_gnu_exception_handler+0x1cb>
   140002719:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000271e:	0f 84 3a 01 00 00    	je     14000285e <_gnu_exception_handler+0x1c4>
   140002724:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002729:	0f 87 97 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   14000272f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002734:	0f 84 83 01 00 00    	je     1400028bd <_gnu_exception_handler+0x223>
   14000273a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000273f:	0f 87 81 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   140002745:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000274a:	0f 87 76 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   140002750:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002755:	0f 83 03 01 00 00    	jae    14000285e <_gnu_exception_handler+0x1c4>
   14000275b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002760:	0f 84 57 01 00 00    	je     1400028bd <_gnu_exception_handler+0x223>
   140002766:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000276b:	0f 87 55 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   140002771:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002776:	0f 84 8e 00 00 00    	je     14000280a <_gnu_exception_handler+0x170>
   14000277c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002781:	0f 87 3f 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   140002787:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000278c:	0f 84 2b 01 00 00    	je     1400028bd <_gnu_exception_handler+0x223>
   140002792:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002797:	0f 87 29 01 00 00    	ja     1400028c6 <_gnu_exception_handler+0x22c>
   14000279d:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400027a2:	0f 84 15 01 00 00    	je     1400028bd <_gnu_exception_handler+0x223>
   1400027a8:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400027ad:	0f 85 13 01 00 00    	jne    1400028c6 <_gnu_exception_handler+0x22c>
   1400027b3:	ba 00 00 00 00       	mov    edx,0x0
   1400027b8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027bd:	e8 96 6e 00 00       	call   140009658 <signal>
   1400027c2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027c6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027cb:	75 1b                	jne    1400027e8 <_gnu_exception_handler+0x14e>
   1400027cd:	ba 01 00 00 00       	mov    edx,0x1
   1400027d2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027d7:	e8 7c 6e 00 00       	call   140009658 <signal>
   1400027dc:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400027e3:	e9 e1 00 00 00       	jmp    1400028c9 <_gnu_exception_handler+0x22f>
   1400027e8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400027ed:	0f 84 d6 00 00 00    	je     1400028c9 <_gnu_exception_handler+0x22f>
   1400027f3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400027f7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027fc:	ff d0                	call   rax
   1400027fe:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002805:	e9 bf 00 00 00       	jmp    1400028c9 <_gnu_exception_handler+0x22f>
   14000280a:	ba 00 00 00 00       	mov    edx,0x0
   14000280f:	b9 04 00 00 00       	mov    ecx,0x4
   140002814:	e8 3f 6e 00 00       	call   140009658 <signal>
   140002819:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000281d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002822:	75 1b                	jne    14000283f <_gnu_exception_handler+0x1a5>
   140002824:	ba 01 00 00 00       	mov    edx,0x1
   140002829:	b9 04 00 00 00       	mov    ecx,0x4
   14000282e:	e8 25 6e 00 00       	call   140009658 <signal>
   140002833:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000283a:	e9 8d 00 00 00       	jmp    1400028cc <_gnu_exception_handler+0x232>
   14000283f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002844:	0f 84 82 00 00 00    	je     1400028cc <_gnu_exception_handler+0x232>
   14000284a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000284e:	b9 04 00 00 00       	mov    ecx,0x4
   140002853:	ff d0                	call   rax
   140002855:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000285c:	eb 6e                	jmp    1400028cc <_gnu_exception_handler+0x232>
   14000285e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002865:	ba 00 00 00 00       	mov    edx,0x0
   14000286a:	b9 08 00 00 00       	mov    ecx,0x8
   14000286f:	e8 e4 6d 00 00       	call   140009658 <signal>
   140002874:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002878:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000287d:	75 23                	jne    1400028a2 <_gnu_exception_handler+0x208>
   14000287f:	ba 01 00 00 00       	mov    edx,0x1
   140002884:	b9 08 00 00 00       	mov    ecx,0x8
   140002889:	e8 ca 6d 00 00       	call   140009658 <signal>
   14000288e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002892:	74 05                	je     140002899 <_gnu_exception_handler+0x1ff>
   140002894:	e8 67 03 00 00       	call   140002c00 <_fpreset>
   140002899:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028a0:	eb 2d                	jmp    1400028cf <_gnu_exception_handler+0x235>
   1400028a2:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028a7:	74 26                	je     1400028cf <_gnu_exception_handler+0x235>
   1400028a9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028ad:	b9 08 00 00 00       	mov    ecx,0x8
   1400028b2:	ff d0                	call   rax
   1400028b4:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028bb:	eb 12                	jmp    1400028cf <_gnu_exception_handler+0x235>
   1400028bd:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028c4:	eb 0a                	jmp    1400028d0 <_gnu_exception_handler+0x236>
   1400028c6:	90                   	nop
   1400028c7:	eb 07                	jmp    1400028d0 <_gnu_exception_handler+0x236>
   1400028c9:	90                   	nop
   1400028ca:	eb 04                	jmp    1400028d0 <_gnu_exception_handler+0x236>
   1400028cc:	90                   	nop
   1400028cd:	eb 01                	jmp    1400028d0 <_gnu_exception_handler+0x236>
   1400028cf:	90                   	nop
   1400028d0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400028d4:	75 1f                	jne    1400028f5 <_gnu_exception_handler+0x25b>
   1400028d6:	48 8b 05 33 c8 00 00 	mov    rax,QWORD PTR [rip+0xc833]        # 14000f110 <__mingw_oldexcpt_handler>
   1400028dd:	48 85 c0             	test   rax,rax
   1400028e0:	74 13                	je     1400028f5 <_gnu_exception_handler+0x25b>
   1400028e2:	48 8b 15 27 c8 00 00 	mov    rdx,QWORD PTR [rip+0xc827]        # 14000f110 <__mingw_oldexcpt_handler>
   1400028e9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400028ed:	48 89 c1             	mov    rcx,rax
   1400028f0:	ff d2                	call   rdx
   1400028f2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400028f5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400028f8:	48 83 c4 30          	add    rsp,0x30
   1400028fc:	5d                   	pop    rbp
   1400028fd:	c3                   	ret
   1400028fe:	90                   	nop
   1400028ff:	90                   	nop

0000000140002900 <___w64_mingwthr_add_key_dtor>:
   140002900:	55                   	push   rbp
   140002901:	48 89 e5             	mov    rbp,rsp
   140002904:	48 83 ec 30          	sub    rsp,0x30
   140002908:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000290b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000290f:	8b 05 33 c8 00 00    	mov    eax,DWORD PTR [rip+0xc833]        # 14000f148 <__mingwthr_cs_init>
   140002915:	85 c0                	test   eax,eax
   140002917:	75 07                	jne    140002920 <___w64_mingwthr_add_key_dtor+0x20>
   140002919:	b8 00 00 00 00       	mov    eax,0x0
   14000291e:	eb 7b                	jmp    14000299b <___w64_mingwthr_add_key_dtor+0x9b>
   140002920:	ba 18 00 00 00       	mov    edx,0x18
   140002925:	b9 01 00 00 00       	mov    ecx,0x1
   14000292a:	e8 d9 6c 00 00       	call   140009608 <calloc>
   14000292f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002933:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002938:	75 07                	jne    140002941 <___w64_mingwthr_add_key_dtor+0x41>
   14000293a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000293f:	eb 5a                	jmp    14000299b <___w64_mingwthr_add_key_dtor+0x9b>
   140002941:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002945:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002948:	89 10                	mov    DWORD PTR [rax],edx
   14000294a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000294e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002952:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002956:	48 8d 05 c3 c7 00 00 	lea    rax,[rip+0xc7c3]        # 14000f120 <__mingwthr_cs>
   14000295d:	48 89 c1             	mov    rcx,rax
   140002960:	48 8b 05 91 d8 00 00 	mov    rax,QWORD PTR [rip+0xd891]        # 1400101f8 <__imp_EnterCriticalSection>
   140002967:	ff d0                	call   rax
   140002969:	48 8b 15 e0 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc7e0]        # 14000f150 <key_dtor_list>
   140002970:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002974:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002978:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000297c:	48 89 05 cd c7 00 00 	mov    QWORD PTR [rip+0xc7cd],rax        # 14000f150 <key_dtor_list>
   140002983:	48 8d 05 96 c7 00 00 	lea    rax,[rip+0xc796]        # 14000f120 <__mingwthr_cs>
   14000298a:	48 89 c1             	mov    rcx,rax
   14000298d:	48 8b 05 9c d8 00 00 	mov    rax,QWORD PTR [rip+0xd89c]        # 140010230 <__imp_LeaveCriticalSection>
   140002994:	ff d0                	call   rax
   140002996:	b8 00 00 00 00       	mov    eax,0x0
   14000299b:	48 83 c4 30          	add    rsp,0x30
   14000299f:	5d                   	pop    rbp
   1400029a0:	c3                   	ret

00000001400029a1 <___w64_mingwthr_remove_key_dtor>:
   1400029a1:	55                   	push   rbp
   1400029a2:	48 89 e5             	mov    rbp,rsp
   1400029a5:	48 83 ec 30          	sub    rsp,0x30
   1400029a9:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029ac:	8b 05 96 c7 00 00    	mov    eax,DWORD PTR [rip+0xc796]        # 14000f148 <__mingwthr_cs_init>
   1400029b2:	85 c0                	test   eax,eax
   1400029b4:	75 0a                	jne    1400029c0 <___w64_mingwthr_remove_key_dtor+0x1f>
   1400029b6:	b8 00 00 00 00       	mov    eax,0x0
   1400029bb:	e9 9c 00 00 00       	jmp    140002a5c <___w64_mingwthr_remove_key_dtor+0xbb>
   1400029c0:	48 8d 05 59 c7 00 00 	lea    rax,[rip+0xc759]        # 14000f120 <__mingwthr_cs>
   1400029c7:	48 89 c1             	mov    rcx,rax
   1400029ca:	48 8b 05 27 d8 00 00 	mov    rax,QWORD PTR [rip+0xd827]        # 1400101f8 <__imp_EnterCriticalSection>
   1400029d1:	ff d0                	call   rax
   1400029d3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400029da:	00 
   1400029db:	48 8b 05 6e c7 00 00 	mov    rax,QWORD PTR [rip+0xc76e]        # 14000f150 <key_dtor_list>
   1400029e2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400029e6:	eb 55                	jmp    140002a3d <___w64_mingwthr_remove_key_dtor+0x9c>
   1400029e8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029ec:	8b 00                	mov    eax,DWORD PTR [rax]
   1400029ee:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   1400029f1:	75 36                	jne    140002a29 <___w64_mingwthr_remove_key_dtor+0x88>
   1400029f3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029f8:	75 11                	jne    140002a0b <___w64_mingwthr_remove_key_dtor+0x6a>
   1400029fa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400029fe:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a02:	48 89 05 47 c7 00 00 	mov    QWORD PTR [rip+0xc747],rax        # 14000f150 <key_dtor_list>
   140002a09:	eb 10                	jmp    140002a1b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a0b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a0f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002a13:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a17:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a1b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a1f:	48 89 c1             	mov    rcx,rax
   140002a22:	e8 09 6c 00 00       	call   140009630 <free>
   140002a27:	eb 1b                	jmp    140002a44 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002a29:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a2d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a31:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a35:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a39:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a3d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002a42:	75 a4                	jne    1400029e8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002a44:	48 8d 05 d5 c6 00 00 	lea    rax,[rip+0xc6d5]        # 14000f120 <__mingwthr_cs>
   140002a4b:	48 89 c1             	mov    rcx,rax
   140002a4e:	48 8b 05 db d7 00 00 	mov    rax,QWORD PTR [rip+0xd7db]        # 140010230 <__imp_LeaveCriticalSection>
   140002a55:	ff d0                	call   rax
   140002a57:	b8 00 00 00 00       	mov    eax,0x0
   140002a5c:	48 83 c4 30          	add    rsp,0x30
   140002a60:	5d                   	pop    rbp
   140002a61:	c3                   	ret

0000000140002a62 <__mingwthr_run_key_dtors>:
   140002a62:	55                   	push   rbp
   140002a63:	48 89 e5             	mov    rbp,rsp
   140002a66:	48 83 ec 30          	sub    rsp,0x30
   140002a6a:	8b 05 d8 c6 00 00    	mov    eax,DWORD PTR [rip+0xc6d8]        # 14000f148 <__mingwthr_cs_init>
   140002a70:	85 c0                	test   eax,eax
   140002a72:	0f 84 82 00 00 00    	je     140002afa <__mingwthr_run_key_dtors+0x98>
   140002a78:	48 8d 05 a1 c6 00 00 	lea    rax,[rip+0xc6a1]        # 14000f120 <__mingwthr_cs>
   140002a7f:	48 89 c1             	mov    rcx,rax
   140002a82:	48 8b 05 6f d7 00 00 	mov    rax,QWORD PTR [rip+0xd76f]        # 1400101f8 <__imp_EnterCriticalSection>
   140002a89:	ff d0                	call   rax
   140002a8b:	48 8b 05 be c6 00 00 	mov    rax,QWORD PTR [rip+0xc6be]        # 14000f150 <key_dtor_list>
   140002a92:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a96:	eb 46                	jmp    140002ade <__mingwthr_run_key_dtors+0x7c>
   140002a98:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a9c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a9e:	89 c1                	mov    ecx,eax
   140002aa0:	48 8b 05 b1 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7b1]        # 140010258 <__imp_TlsGetValue>
   140002aa7:	ff d0                	call   rax
   140002aa9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002aad:	48 8b 05 5c d7 00 00 	mov    rax,QWORD PTR [rip+0xd75c]        # 140010210 <__imp_GetLastError>
   140002ab4:	ff d0                	call   rax
   140002ab6:	85 c0                	test   eax,eax
   140002ab8:	75 18                	jne    140002ad2 <__mingwthr_run_key_dtors+0x70>
   140002aba:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002abf:	74 11                	je     140002ad2 <__mingwthr_run_key_dtors+0x70>
   140002ac1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ac5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002ac9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002acd:	48 89 c1             	mov    rcx,rax
   140002ad0:	ff d2                	call   rdx
   140002ad2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ad6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ada:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ade:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ae3:	75 b3                	jne    140002a98 <__mingwthr_run_key_dtors+0x36>
   140002ae5:	48 8d 05 34 c6 00 00 	lea    rax,[rip+0xc634]        # 14000f120 <__mingwthr_cs>
   140002aec:	48 89 c1             	mov    rcx,rax
   140002aef:	48 8b 05 3a d7 00 00 	mov    rax,QWORD PTR [rip+0xd73a]        # 140010230 <__imp_LeaveCriticalSection>
   140002af6:	ff d0                	call   rax
   140002af8:	eb 01                	jmp    140002afb <__mingwthr_run_key_dtors+0x99>
   140002afa:	90                   	nop
   140002afb:	48 83 c4 30          	add    rsp,0x30
   140002aff:	5d                   	pop    rbp
   140002b00:	c3                   	ret

0000000140002b01 <__mingw_TLScallback>:
   140002b01:	55                   	push   rbp
   140002b02:	48 89 e5             	mov    rbp,rsp
   140002b05:	48 83 ec 30          	sub    rsp,0x30
   140002b09:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b0d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002b10:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002b14:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b18:	0f 84 cc 00 00 00    	je     140002bea <__mingw_TLScallback+0xe9>
   140002b1e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002b22:	0f 87 ca 00 00 00    	ja     140002bf2 <__mingw_TLScallback+0xf1>
   140002b28:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b2c:	0f 84 b1 00 00 00    	je     140002be3 <__mingw_TLScallback+0xe2>
   140002b32:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002b36:	0f 87 b6 00 00 00    	ja     140002bf2 <__mingw_TLScallback+0xf1>
   140002b3c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002b40:	74 33                	je     140002b75 <__mingw_TLScallback+0x74>
   140002b42:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002b46:	0f 85 a6 00 00 00    	jne    140002bf2 <__mingw_TLScallback+0xf1>
   140002b4c:	8b 05 f6 c5 00 00    	mov    eax,DWORD PTR [rip+0xc5f6]        # 14000f148 <__mingwthr_cs_init>
   140002b52:	85 c0                	test   eax,eax
   140002b54:	75 13                	jne    140002b69 <__mingw_TLScallback+0x68>
   140002b56:	48 8d 05 c3 c5 00 00 	lea    rax,[rip+0xc5c3]        # 14000f120 <__mingwthr_cs>
   140002b5d:	48 89 c1             	mov    rcx,rax
   140002b60:	48 8b 05 c1 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6c1]        # 140010228 <__imp_InitializeCriticalSection>
   140002b67:	ff d0                	call   rax
   140002b69:	c7 05 d5 c5 00 00 01 	mov    DWORD PTR [rip+0xc5d5],0x1        # 14000f148 <__mingwthr_cs_init>
   140002b70:	00 00 00 
   140002b73:	eb 7d                	jmp    140002bf2 <__mingw_TLScallback+0xf1>
   140002b75:	e8 e8 fe ff ff       	call   140002a62 <__mingwthr_run_key_dtors>
   140002b7a:	8b 05 c8 c5 00 00    	mov    eax,DWORD PTR [rip+0xc5c8]        # 14000f148 <__mingwthr_cs_init>
   140002b80:	83 f8 01             	cmp    eax,0x1
   140002b83:	75 6c                	jne    140002bf1 <__mingw_TLScallback+0xf0>
   140002b85:	48 8b 05 c4 c5 00 00 	mov    rax,QWORD PTR [rip+0xc5c4]        # 14000f150 <key_dtor_list>
   140002b8c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b90:	eb 20                	jmp    140002bb2 <__mingw_TLScallback+0xb1>
   140002b92:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b96:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b9a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b9e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ba2:	48 89 c1             	mov    rcx,rax
   140002ba5:	e8 86 6a 00 00       	call   140009630 <free>
   140002baa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bb2:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002bb7:	75 d9                	jne    140002b92 <__mingw_TLScallback+0x91>
   140002bb9:	48 c7 05 8c c5 00 00 	mov    QWORD PTR [rip+0xc58c],0x0        # 14000f150 <key_dtor_list>
   140002bc0:	00 00 00 00 
   140002bc4:	c7 05 7a c5 00 00 00 	mov    DWORD PTR [rip+0xc57a],0x0        # 14000f148 <__mingwthr_cs_init>
   140002bcb:	00 00 00 
   140002bce:	48 8d 05 4b c5 00 00 	lea    rax,[rip+0xc54b]        # 14000f120 <__mingwthr_cs>
   140002bd5:	48 89 c1             	mov    rcx,rax
   140002bd8:	48 8b 05 11 d6 00 00 	mov    rax,QWORD PTR [rip+0xd611]        # 1400101f0 <__IAT_start__>
   140002bdf:	ff d0                	call   rax
   140002be1:	eb 0e                	jmp    140002bf1 <__mingw_TLScallback+0xf0>
   140002be3:	e8 18 00 00 00       	call   140002c00 <_fpreset>
   140002be8:	eb 08                	jmp    140002bf2 <__mingw_TLScallback+0xf1>
   140002bea:	e8 73 fe ff ff       	call   140002a62 <__mingwthr_run_key_dtors>
   140002bef:	eb 01                	jmp    140002bf2 <__mingw_TLScallback+0xf1>
   140002bf1:	90                   	nop
   140002bf2:	b8 01 00 00 00       	mov    eax,0x1
   140002bf7:	48 83 c4 30          	add    rsp,0x30
   140002bfb:	5d                   	pop    rbp
   140002bfc:	c3                   	ret
   140002bfd:	90                   	nop
   140002bfe:	90                   	nop
   140002bff:	90                   	nop

0000000140002c00 <_fpreset>:
   140002c00:	55                   	push   rbp
   140002c01:	48 89 e5             	mov    rbp,rsp
   140002c04:	db e3                	fninit
   140002c06:	90                   	nop
   140002c07:	5d                   	pop    rbp
   140002c08:	c3                   	ret
   140002c09:	90                   	nop
   140002c0a:	90                   	nop
   140002c0b:	90                   	nop
   140002c0c:	90                   	nop
   140002c0d:	90                   	nop
   140002c0e:	90                   	nop
   140002c0f:	90                   	nop

0000000140002c10 <_ValidateImageBase>:
   140002c10:	55                   	push   rbp
   140002c11:	48 89 e5             	mov    rbp,rsp
   140002c14:	48 83 ec 20          	sub    rsp,0x20
   140002c18:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c1c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002c20:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c24:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c28:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c2b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002c2f:	74 07                	je     140002c38 <_ValidateImageBase+0x28>
   140002c31:	b8 00 00 00 00       	mov    eax,0x0
   140002c36:	eb 4e                	jmp    140002c86 <_ValidateImageBase+0x76>
   140002c38:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c3c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002c3f:	48 63 d0             	movsxd rdx,eax
   140002c42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c46:	48 01 d0             	add    rax,rdx
   140002c49:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c4d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c51:	8b 00                	mov    eax,DWORD PTR [rax]
   140002c53:	3d 50 45 00 00       	cmp    eax,0x4550
   140002c58:	74 07                	je     140002c61 <_ValidateImageBase+0x51>
   140002c5a:	b8 00 00 00 00       	mov    eax,0x0
   140002c5f:	eb 25                	jmp    140002c86 <_ValidateImageBase+0x76>
   140002c61:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c65:	48 83 c0 18          	add    rax,0x18
   140002c69:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002c6d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002c71:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002c74:	66 3d 0b 02          	cmp    ax,0x20b
   140002c78:	74 07                	je     140002c81 <_ValidateImageBase+0x71>
   140002c7a:	b8 00 00 00 00       	mov    eax,0x0
   140002c7f:	eb 05                	jmp    140002c86 <_ValidateImageBase+0x76>
   140002c81:	b8 01 00 00 00       	mov    eax,0x1
   140002c86:	48 83 c4 20          	add    rsp,0x20
   140002c8a:	5d                   	pop    rbp
   140002c8b:	c3                   	ret

0000000140002c8c <_FindPESection>:
   140002c8c:	55                   	push   rbp
   140002c8d:	48 89 e5             	mov    rbp,rsp
   140002c90:	48 83 ec 20          	sub    rsp,0x20
   140002c94:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002c98:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002c9c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ca0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ca3:	48 63 d0             	movsxd rdx,eax
   140002ca6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002caa:	48 01 d0             	add    rax,rdx
   140002cad:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002cb1:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002cb8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cbc:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002cc0:	0f b7 d0             	movzx  edx,ax
   140002cc3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002cc7:	48 01 d0             	add    rax,rdx
   140002cca:	48 83 c0 18          	add    rax,0x18
   140002cce:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cd2:	eb 36                	jmp    140002d0a <_FindPESection+0x7e>
   140002cd4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cd8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002cdb:	89 c0                	mov    eax,eax
   140002cdd:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002ce1:	72 1e                	jb     140002d01 <_FindPESection+0x75>
   140002ce3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ce7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002cea:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cee:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002cf1:	01 d0                	add    eax,edx
   140002cf3:	89 c0                	mov    eax,eax
   140002cf5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002cf9:	73 06                	jae    140002d01 <_FindPESection+0x75>
   140002cfb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cff:	eb 1e                	jmp    140002d1f <_FindPESection+0x93>
   140002d01:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d05:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d0a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d0e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002d12:	0f b7 c0             	movzx  eax,ax
   140002d15:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002d18:	72 ba                	jb     140002cd4 <_FindPESection+0x48>
   140002d1a:	b8 00 00 00 00       	mov    eax,0x0
   140002d1f:	48 83 c4 20          	add    rsp,0x20
   140002d23:	5d                   	pop    rbp
   140002d24:	c3                   	ret

0000000140002d25 <_FindPESectionByName>:
   140002d25:	55                   	push   rbp
   140002d26:	48 89 e5             	mov    rbp,rsp
   140002d29:	48 83 ec 40          	sub    rsp,0x40
   140002d2d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d31:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d35:	48 89 c1             	mov    rcx,rax
   140002d38:	e8 33 69 00 00       	call   140009670 <strlen>
   140002d3d:	48 83 f8 08          	cmp    rax,0x8
   140002d41:	76 0a                	jbe    140002d4d <_FindPESectionByName+0x28>
   140002d43:	b8 00 00 00 00       	mov    eax,0x0
   140002d48:	e9 98 00 00 00       	jmp    140002de5 <_FindPESectionByName+0xc0>
   140002d4d:	48 8b 05 2c 88 00 00 	mov    rax,QWORD PTR [rip+0x882c]        # 14000b580 <.refptr.__ImageBase>
   140002d54:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d58:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d5c:	48 89 c1             	mov    rcx,rax
   140002d5f:	e8 ac fe ff ff       	call   140002c10 <_ValidateImageBase>
   140002d64:	85 c0                	test   eax,eax
   140002d66:	75 07                	jne    140002d6f <_FindPESectionByName+0x4a>
   140002d68:	b8 00 00 00 00       	mov    eax,0x0
   140002d6d:	eb 76                	jmp    140002de5 <_FindPESectionByName+0xc0>
   140002d6f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d73:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d76:	48 63 d0             	movsxd rdx,eax
   140002d79:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d7d:	48 01 d0             	add    rax,rdx
   140002d80:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002d84:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d8b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d8f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d93:	0f b7 d0             	movzx  edx,ax
   140002d96:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002d9a:	48 01 d0             	add    rax,rdx
   140002d9d:	48 83 c0 18          	add    rax,0x18
   140002da1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002da5:	eb 29                	jmp    140002dd0 <_FindPESectionByName+0xab>
   140002da7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dab:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002daf:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002db5:	48 89 c1             	mov    rcx,rax
   140002db8:	e8 bb 68 00 00       	call   140009678 <strncmp>
   140002dbd:	85 c0                	test   eax,eax
   140002dbf:	75 06                	jne    140002dc7 <_FindPESectionByName+0xa2>
   140002dc1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dc5:	eb 1e                	jmp    140002de5 <_FindPESectionByName+0xc0>
   140002dc7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002dcb:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002dd0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002dd4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002dd8:	0f b7 c0             	movzx  eax,ax
   140002ddb:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002dde:	72 c7                	jb     140002da7 <_FindPESectionByName+0x82>
   140002de0:	b8 00 00 00 00       	mov    eax,0x0
   140002de5:	48 83 c4 40          	add    rsp,0x40
   140002de9:	5d                   	pop    rbp
   140002dea:	c3                   	ret

0000000140002deb <__mingw_GetSectionForAddress>:
   140002deb:	55                   	push   rbp
   140002dec:	48 89 e5             	mov    rbp,rsp
   140002def:	48 83 ec 30          	sub    rsp,0x30
   140002df3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002df7:	48 8b 05 82 87 00 00 	mov    rax,QWORD PTR [rip+0x8782]        # 14000b580 <.refptr.__ImageBase>
   140002dfe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e06:	48 89 c1             	mov    rcx,rax
   140002e09:	e8 02 fe ff ff       	call   140002c10 <_ValidateImageBase>
   140002e0e:	85 c0                	test   eax,eax
   140002e10:	75 07                	jne    140002e19 <__mingw_GetSectionForAddress+0x2e>
   140002e12:	b8 00 00 00 00       	mov    eax,0x0
   140002e17:	eb 1c                	jmp    140002e35 <__mingw_GetSectionForAddress+0x4a>
   140002e19:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e1d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002e21:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e25:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002e29:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e2d:	48 89 c1             	mov    rcx,rax
   140002e30:	e8 57 fe ff ff       	call   140002c8c <_FindPESection>
   140002e35:	48 83 c4 30          	add    rsp,0x30
   140002e39:	5d                   	pop    rbp
   140002e3a:	c3                   	ret

0000000140002e3b <__mingw_GetSectionCount>:
   140002e3b:	55                   	push   rbp
   140002e3c:	48 89 e5             	mov    rbp,rsp
   140002e3f:	48 83 ec 30          	sub    rsp,0x30
   140002e43:	48 8b 05 36 87 00 00 	mov    rax,QWORD PTR [rip+0x8736]        # 14000b580 <.refptr.__ImageBase>
   140002e4a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e4e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e52:	48 89 c1             	mov    rcx,rax
   140002e55:	e8 b6 fd ff ff       	call   140002c10 <_ValidateImageBase>
   140002e5a:	85 c0                	test   eax,eax
   140002e5c:	75 07                	jne    140002e65 <__mingw_GetSectionCount+0x2a>
   140002e5e:	b8 00 00 00 00       	mov    eax,0x0
   140002e63:	eb 20                	jmp    140002e85 <__mingw_GetSectionCount+0x4a>
   140002e65:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e69:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e6c:	48 63 d0             	movsxd rdx,eax
   140002e6f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e73:	48 01 d0             	add    rax,rdx
   140002e76:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002e7a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002e7e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e82:	0f b7 c0             	movzx  eax,ax
   140002e85:	48 83 c4 30          	add    rsp,0x30
   140002e89:	5d                   	pop    rbp
   140002e8a:	c3                   	ret

0000000140002e8b <_FindPESectionExec>:
   140002e8b:	55                   	push   rbp
   140002e8c:	48 89 e5             	mov    rbp,rsp
   140002e8f:	48 83 ec 40          	sub    rsp,0x40
   140002e93:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e97:	48 8b 05 e2 86 00 00 	mov    rax,QWORD PTR [rip+0x86e2]        # 14000b580 <.refptr.__ImageBase>
   140002e9e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002ea2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ea6:	48 89 c1             	mov    rcx,rax
   140002ea9:	e8 62 fd ff ff       	call   140002c10 <_ValidateImageBase>
   140002eae:	85 c0                	test   eax,eax
   140002eb0:	75 07                	jne    140002eb9 <_FindPESectionExec+0x2e>
   140002eb2:	b8 00 00 00 00       	mov    eax,0x0
   140002eb7:	eb 78                	jmp    140002f31 <_FindPESectionExec+0xa6>
   140002eb9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ebd:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ec0:	48 63 d0             	movsxd rdx,eax
   140002ec3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002ec7:	48 01 d0             	add    rax,rdx
   140002eca:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002ece:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002ed5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ed9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002edd:	0f b7 d0             	movzx  edx,ax
   140002ee0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ee4:	48 01 d0             	add    rax,rdx
   140002ee7:	48 83 c0 18          	add    rax,0x18
   140002eeb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002eef:	eb 2b                	jmp    140002f1c <_FindPESectionExec+0x91>
   140002ef1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ef5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002ef8:	25 00 00 00 20       	and    eax,0x20000000
   140002efd:	85 c0                	test   eax,eax
   140002eff:	74 12                	je     140002f13 <_FindPESectionExec+0x88>
   140002f01:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f06:	75 06                	jne    140002f0e <_FindPESectionExec+0x83>
   140002f08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f0c:	eb 23                	jmp    140002f31 <_FindPESectionExec+0xa6>
   140002f0e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002f13:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002f17:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002f1c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f20:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f24:	0f b7 c0             	movzx  eax,ax
   140002f27:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002f2a:	72 c5                	jb     140002ef1 <_FindPESectionExec+0x66>
   140002f2c:	b8 00 00 00 00       	mov    eax,0x0
   140002f31:	48 83 c4 40          	add    rsp,0x40
   140002f35:	5d                   	pop    rbp
   140002f36:	c3                   	ret

0000000140002f37 <_GetPEImageBase>:
   140002f37:	55                   	push   rbp
   140002f38:	48 89 e5             	mov    rbp,rsp
   140002f3b:	48 83 ec 30          	sub    rsp,0x30
   140002f3f:	48 8b 05 3a 86 00 00 	mov    rax,QWORD PTR [rip+0x863a]        # 14000b580 <.refptr.__ImageBase>
   140002f46:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f4a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f4e:	48 89 c1             	mov    rcx,rax
   140002f51:	e8 ba fc ff ff       	call   140002c10 <_ValidateImageBase>
   140002f56:	85 c0                	test   eax,eax
   140002f58:	75 07                	jne    140002f61 <_GetPEImageBase+0x2a>
   140002f5a:	b8 00 00 00 00       	mov    eax,0x0
   140002f5f:	eb 04                	jmp    140002f65 <_GetPEImageBase+0x2e>
   140002f61:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f65:	48 83 c4 30          	add    rsp,0x30
   140002f69:	5d                   	pop    rbp
   140002f6a:	c3                   	ret

0000000140002f6b <_IsNonwritableInCurrentImage>:
   140002f6b:	55                   	push   rbp
   140002f6c:	48 89 e5             	mov    rbp,rsp
   140002f6f:	48 83 ec 40          	sub    rsp,0x40
   140002f73:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f77:	48 8b 05 02 86 00 00 	mov    rax,QWORD PTR [rip+0x8602]        # 14000b580 <.refptr.__ImageBase>
   140002f7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f82:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f86:	48 89 c1             	mov    rcx,rax
   140002f89:	e8 82 fc ff ff       	call   140002c10 <_ValidateImageBase>
   140002f8e:	85 c0                	test   eax,eax
   140002f90:	75 07                	jne    140002f99 <_IsNonwritableInCurrentImage+0x2e>
   140002f92:	b8 00 00 00 00       	mov    eax,0x0
   140002f97:	eb 3d                	jmp    140002fd6 <_IsNonwritableInCurrentImage+0x6b>
   140002f99:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f9d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002fa1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002fa5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002fa9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fad:	48 89 c1             	mov    rcx,rax
   140002fb0:	e8 d7 fc ff ff       	call   140002c8c <_FindPESection>
   140002fb5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002fb9:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140002fbe:	75 07                	jne    140002fc7 <_IsNonwritableInCurrentImage+0x5c>
   140002fc0:	b8 00 00 00 00       	mov    eax,0x0
   140002fc5:	eb 0f                	jmp    140002fd6 <_IsNonwritableInCurrentImage+0x6b>
   140002fc7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002fcb:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fce:	f7 d0                	not    eax
   140002fd0:	c1 e8 1f             	shr    eax,0x1f
   140002fd3:	0f b6 c0             	movzx  eax,al
   140002fd6:	48 83 c4 40          	add    rsp,0x40
   140002fda:	5d                   	pop    rbp
   140002fdb:	c3                   	ret

0000000140002fdc <__mingw_enum_import_library_names>:
   140002fdc:	55                   	push   rbp
   140002fdd:	48 89 e5             	mov    rbp,rsp
   140002fe0:	48 83 ec 50          	sub    rsp,0x50
   140002fe4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002fe7:	48 8b 05 92 85 00 00 	mov    rax,QWORD PTR [rip+0x8592]        # 14000b580 <.refptr.__ImageBase>
   140002fee:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ff2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ff6:	48 89 c1             	mov    rcx,rax
   140002ff9:	e8 12 fc ff ff       	call   140002c10 <_ValidateImageBase>
   140002ffe:	85 c0                	test   eax,eax
   140003000:	75 0a                	jne    14000300c <__mingw_enum_import_library_names+0x30>
   140003002:	b8 00 00 00 00       	mov    eax,0x0
   140003007:	e9 ab 00 00 00       	jmp    1400030b7 <__mingw_enum_import_library_names+0xdb>
   14000300c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003010:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003013:	48 63 d0             	movsxd rdx,eax
   140003016:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000301a:	48 01 d0             	add    rax,rdx
   14000301d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003021:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003025:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000302b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000302e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003032:	75 07                	jne    14000303b <__mingw_enum_import_library_names+0x5f>
   140003034:	b8 00 00 00 00       	mov    eax,0x0
   140003039:	eb 7c                	jmp    1400030b7 <__mingw_enum_import_library_names+0xdb>
   14000303b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000303e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003042:	48 89 c1             	mov    rcx,rax
   140003045:	e8 42 fc ff ff       	call   140002c8c <_FindPESection>
   14000304a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000304e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003053:	75 07                	jne    14000305c <__mingw_enum_import_library_names+0x80>
   140003055:	b8 00 00 00 00       	mov    eax,0x0
   14000305a:	eb 5b                	jmp    1400030b7 <__mingw_enum_import_library_names+0xdb>
   14000305c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000305f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003063:	48 01 d0             	add    rax,rdx
   140003066:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000306a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000306f:	75 07                	jne    140003078 <__mingw_enum_import_library_names+0x9c>
   140003071:	b8 00 00 00 00       	mov    eax,0x0
   140003076:	eb 3f                	jmp    1400030b7 <__mingw_enum_import_library_names+0xdb>
   140003078:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000307c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000307f:	85 c0                	test   eax,eax
   140003081:	75 0b                	jne    14000308e <__mingw_enum_import_library_names+0xb2>
   140003083:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003087:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000308a:	85 c0                	test   eax,eax
   14000308c:	74 23                	je     1400030b1 <__mingw_enum_import_library_names+0xd5>
   14000308e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003092:	7f 12                	jg     1400030a6 <__mingw_enum_import_library_names+0xca>
   140003094:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003098:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000309b:	89 c2                	mov    edx,eax
   14000309d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030a1:	48 01 d0             	add    rax,rdx
   1400030a4:	eb 11                	jmp    1400030b7 <__mingw_enum_import_library_names+0xdb>
   1400030a6:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   1400030aa:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   1400030af:	eb c7                	jmp    140003078 <__mingw_enum_import_library_names+0x9c>
   1400030b1:	90                   	nop
   1400030b2:	b8 00 00 00 00       	mov    eax,0x0
   1400030b7:	48 83 c4 50          	add    rsp,0x50
   1400030bb:	5d                   	pop    rbp
   1400030bc:	c3                   	ret
   1400030bd:	90                   	nop
   1400030be:	90                   	nop
   1400030bf:	90                   	nop

00000001400030c0 <___chkstk_ms>:
   1400030c0:	51                   	push   rcx
   1400030c1:	50                   	push   rax
   1400030c2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030c8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400030cd:	72 19                	jb     1400030e8 <___chkstk_ms+0x28>
   1400030cf:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400030d6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030da:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400030e0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400030e6:	77 e7                	ja     1400030cf <___chkstk_ms+0xf>
   1400030e8:	48 29 c1             	sub    rcx,rax
   1400030eb:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400030ef:	58                   	pop    rax
   1400030f0:	59                   	pop    rcx
   1400030f1:	c3                   	ret
   1400030f2:	90                   	nop
   1400030f3:	90                   	nop
   1400030f4:	90                   	nop
   1400030f5:	90                   	nop
   1400030f6:	90                   	nop
   1400030f7:	90                   	nop
   1400030f8:	90                   	nop
   1400030f9:	90                   	nop
   1400030fa:	90                   	nop
   1400030fb:	90                   	nop
   1400030fc:	90                   	nop
   1400030fd:	90                   	nop
   1400030fe:	90                   	nop
   1400030ff:	90                   	nop

0000000140003100 <__mingw_printf>:
   140003100:	55                   	push   rbp
   140003101:	53                   	push   rbx
   140003102:	48 83 ec 48          	sub    rsp,0x48
   140003106:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   14000310b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000310f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140003113:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003117:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   14000311b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   14000311f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003123:	b9 01 00 00 00       	mov    ecx,0x1
   140003128:	e8 c3 5e 00 00       	call   140008ff0 <__acrt_iob_func>
   14000312d:	48 89 c1             	mov    rcx,rax
   140003130:	e8 3b 5d 00 00       	call   140008e70 <_lock_file>
   140003135:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140003139:	b9 01 00 00 00       	mov    ecx,0x1
   14000313e:	e8 ad 5e 00 00       	call   140008ff0 <__acrt_iob_func>
   140003143:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003147:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
   14000314c:	49 89 d1             	mov    r9,rdx
   14000314f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140003155:	48 89 c2             	mov    rdx,rax
   140003158:	b9 00 60 00 00       	mov    ecx,0x6000
   14000315d:	e8 b1 1f 00 00       	call   140005113 <__mingw_pformat>
   140003162:	89 c3                	mov    ebx,eax
   140003164:	b9 01 00 00 00       	mov    ecx,0x1
   140003169:	e8 82 5e 00 00       	call   140008ff0 <__acrt_iob_func>
   14000316e:	48 89 c1             	mov    rcx,rax
   140003171:	e8 84 5d 00 00       	call   140008efa <_unlock_file>
   140003176:	89 d8                	mov    eax,ebx
   140003178:	48 83 c4 48          	add    rsp,0x48
   14000317c:	5b                   	pop    rbx
   14000317d:	5d                   	pop    rbp
   14000317e:	c3                   	ret
   14000317f:	90                   	nop

0000000140003180 <__pformat_putc>:
   140003180:	55                   	push   rbp
   140003181:	48 89 e5             	mov    rbp,rsp
   140003184:	48 83 ec 20          	sub    rsp,0x20
   140003188:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000318b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000318f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003193:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003196:	25 00 40 00 00       	and    eax,0x4000
   14000319b:	85 c0                	test   eax,eax
   14000319d:	75 12                	jne    1400031b1 <__pformat_putc+0x31>
   14000319f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031a3:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   1400031a6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031aa:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031ad:	39 c2                	cmp    edx,eax
   1400031af:	7e 3b                	jle    1400031ec <__pformat_putc+0x6c>
   1400031b1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031b5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400031b8:	25 00 20 00 00       	and    eax,0x2000
   1400031bd:	85 c0                	test   eax,eax
   1400031bf:	74 13                	je     1400031d4 <__pformat_putc+0x54>
   1400031c1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031c5:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400031c8:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400031cb:	89 c1                	mov    ecx,eax
   1400031cd:	e8 56 64 00 00       	call   140009628 <fputc>
   1400031d2:	eb 18                	jmp    1400031ec <__pformat_putc+0x6c>
   1400031d4:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031d8:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400031db:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031df:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031e2:	48 98                	cdqe
   1400031e4:	48 01 d0             	add    rax,rdx
   1400031e7:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400031ea:	88 10                	mov    BYTE PTR [rax],dl
   1400031ec:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031f0:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031f3:	8d 50 01             	lea    edx,[rax+0x1]
   1400031f6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031fa:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   1400031fd:	90                   	nop
   1400031fe:	48 83 c4 20          	add    rsp,0x20
   140003202:	5d                   	pop    rbp
   140003203:	c3                   	ret

0000000140003204 <__pformat_putchars>:
   140003204:	55                   	push   rbp
   140003205:	48 89 e5             	mov    rbp,rsp
   140003208:	48 83 ec 20          	sub    rsp,0x20
   14000320c:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003210:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003213:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003217:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000321b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000321e:	85 c0                	test   eax,eax
   140003220:	78 16                	js     140003238 <__pformat_putchars+0x34>
   140003222:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003226:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003229:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000322c:	7e 0a                	jle    140003238 <__pformat_putchars+0x34>
   14000322e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003232:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003235:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003238:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000323c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000323f:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003242:	7d 15                	jge    140003259 <__pformat_putchars+0x55>
   140003244:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003248:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000324b:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000324e:	89 c2                	mov    edx,eax
   140003250:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003254:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003257:	eb 0b                	jmp    140003264 <__pformat_putchars+0x60>
   140003259:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000325d:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003264:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003268:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000326b:	85 c0                	test   eax,eax
   14000326d:	7e 57                	jle    1400032c6 <__pformat_putchars+0xc2>
   14000326f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003273:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003276:	25 00 04 00 00       	and    eax,0x400
   14000327b:	85 c0                	test   eax,eax
   14000327d:	75 47                	jne    1400032c6 <__pformat_putchars+0xc2>
   14000327f:	eb 11                	jmp    140003292 <__pformat_putchars+0x8e>
   140003281:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003285:	48 89 c2             	mov    rdx,rax
   140003288:	b9 20 00 00 00       	mov    ecx,0x20
   14000328d:	e8 ee fe ff ff       	call   140003180 <__pformat_putc>
   140003292:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003296:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003299:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000329c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400032a0:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400032a3:	85 c0                	test   eax,eax
   1400032a5:	75 da                	jne    140003281 <__pformat_putchars+0x7d>
   1400032a7:	eb 1d                	jmp    1400032c6 <__pformat_putchars+0xc2>
   1400032a9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400032ad:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400032b1:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   1400032b5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400032b8:	0f be c0             	movsx  eax,al
   1400032bb:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400032bf:	89 c1                	mov    ecx,eax
   1400032c1:	e8 ba fe ff ff       	call   140003180 <__pformat_putc>
   1400032c6:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400032c9:	8d 50 ff             	lea    edx,[rax-0x1]
   1400032cc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400032cf:	85 c0                	test   eax,eax
   1400032d1:	75 d6                	jne    1400032a9 <__pformat_putchars+0xa5>
   1400032d3:	eb 11                	jmp    1400032e6 <__pformat_putchars+0xe2>
   1400032d5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032d9:	48 89 c2             	mov    rdx,rax
   1400032dc:	b9 20 00 00 00       	mov    ecx,0x20
   1400032e1:	e8 9a fe ff ff       	call   140003180 <__pformat_putc>
   1400032e6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032ea:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032ed:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400032f0:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400032f4:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400032f7:	85 c0                	test   eax,eax
   1400032f9:	7f da                	jg     1400032d5 <__pformat_putchars+0xd1>
   1400032fb:	90                   	nop
   1400032fc:	90                   	nop
   1400032fd:	48 83 c4 20          	add    rsp,0x20
   140003301:	5d                   	pop    rbp
   140003302:	c3                   	ret

0000000140003303 <__pformat_puts>:
   140003303:	55                   	push   rbp
   140003304:	48 89 e5             	mov    rbp,rsp
   140003307:	48 83 ec 20          	sub    rsp,0x20
   14000330b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000330f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003313:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140003318:	75 0b                	jne    140003325 <__pformat_puts+0x22>
   14000331a:	48 8d 05 0f 80 00 00 	lea    rax,[rip+0x800f]        # 14000b330 <.rdata>
   140003321:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003325:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003329:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000332c:	85 c0                	test   eax,eax
   14000332e:	78 2f                	js     14000335f <__pformat_puts+0x5c>
   140003330:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003334:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003337:	48 63 d0             	movsxd rdx,eax
   14000333a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000333e:	48 89 c1             	mov    rcx,rax
   140003341:	e8 4a 5a 00 00       	call   140008d90 <strnlen>
   140003346:	89 c1                	mov    ecx,eax
   140003348:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000334c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003350:	49 89 d0             	mov    r8,rdx
   140003353:	89 ca                	mov    edx,ecx
   140003355:	48 89 c1             	mov    rcx,rax
   140003358:	e8 a7 fe ff ff       	call   140003204 <__pformat_putchars>
   14000335d:	eb 23                	jmp    140003382 <__pformat_puts+0x7f>
   14000335f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003363:	48 89 c1             	mov    rcx,rax
   140003366:	e8 05 63 00 00       	call   140009670 <strlen>
   14000336b:	89 c1                	mov    ecx,eax
   14000336d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003371:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003375:	49 89 d0             	mov    r8,rdx
   140003378:	89 ca                	mov    edx,ecx
   14000337a:	48 89 c1             	mov    rcx,rax
   14000337d:	e8 82 fe ff ff       	call   140003204 <__pformat_putchars>
   140003382:	90                   	nop
   140003383:	48 83 c4 20          	add    rsp,0x20
   140003387:	5d                   	pop    rbp
   140003388:	c3                   	ret

0000000140003389 <__pformat_wputchars>:
   140003389:	55                   	push   rbp
   14000338a:	48 89 e5             	mov    rbp,rsp
   14000338d:	48 83 ec 50          	sub    rsp,0x50
   140003391:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003395:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003398:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000339c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   1400033a3:	00 
   1400033a4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033a8:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033ab:	85 c0                	test   eax,eax
   1400033ad:	78 16                	js     1400033c5 <__pformat_wputchars+0x3c>
   1400033af:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033b3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033b6:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400033b9:	7e 0a                	jle    1400033c5 <__pformat_wputchars+0x3c>
   1400033bb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033bf:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033c2:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400033c5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033c9:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033cc:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400033cf:	7d 15                	jge    1400033e6 <__pformat_wputchars+0x5d>
   1400033d1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033d5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033d8:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400033db:	89 c2                	mov    edx,eax
   1400033dd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033e1:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400033e4:	eb 0b                	jmp    1400033f1 <__pformat_wputchars+0x68>
   1400033e6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033ea:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400033f1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033f5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033f8:	85 c0                	test   eax,eax
   1400033fa:	7e 6e                	jle    14000346a <__pformat_wputchars+0xe1>
   1400033fc:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003400:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003403:	25 00 04 00 00       	and    eax,0x400
   140003408:	85 c0                	test   eax,eax
   14000340a:	75 5e                	jne    14000346a <__pformat_wputchars+0xe1>
   14000340c:	eb 11                	jmp    14000341f <__pformat_wputchars+0x96>
   14000340e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003412:	48 89 c2             	mov    rdx,rax
   140003415:	b9 20 00 00 00       	mov    ecx,0x20
   14000341a:	e8 61 fd ff ff       	call   140003180 <__pformat_putc>
   14000341f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003423:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003426:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003429:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000342d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003430:	85 c0                	test   eax,eax
   140003432:	75 da                	jne    14000340e <__pformat_wputchars+0x85>
   140003434:	eb 34                	jmp    14000346a <__pformat_wputchars+0xe1>
   140003436:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   14000343a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000343e:	eb 1d                	jmp    14000345d <__pformat_wputchars+0xd4>
   140003440:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003444:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003448:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000344c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000344f:	0f be c0             	movsx  eax,al
   140003452:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003456:	89 c1                	mov    ecx,eax
   140003458:	e8 23 fd ff ff       	call   140003180 <__pformat_putc>
   14000345d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003460:	8d 50 ff             	lea    edx,[rax-0x1]
   140003463:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003466:	85 c0                	test   eax,eax
   140003468:	7f d6                	jg     140003440 <__pformat_wputchars+0xb7>
   14000346a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000346d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003470:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003473:	85 c0                	test   eax,eax
   140003475:	7e 41                	jle    1400034b8 <__pformat_wputchars+0x12f>
   140003477:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000347b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000347f:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003483:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140003486:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   14000348a:	0f b7 d0             	movzx  edx,ax
   14000348d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003491:	49 89 c8             	mov    r8,rcx
   140003494:	48 89 c1             	mov    rcx,rax
   140003497:	e8 84 5b 00 00       	call   140009020 <wcrtomb>
   14000349c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000349f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400034a3:	7f 91                	jg     140003436 <__pformat_wputchars+0xad>
   1400034a5:	eb 11                	jmp    1400034b8 <__pformat_wputchars+0x12f>
   1400034a7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034ab:	48 89 c2             	mov    rdx,rax
   1400034ae:	b9 20 00 00 00       	mov    ecx,0x20
   1400034b3:	e8 c8 fc ff ff       	call   140003180 <__pformat_putc>
   1400034b8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034bc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034bf:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400034c2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034c6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400034c9:	85 c0                	test   eax,eax
   1400034cb:	7f da                	jg     1400034a7 <__pformat_wputchars+0x11e>
   1400034cd:	90                   	nop
   1400034ce:	90                   	nop
   1400034cf:	48 83 c4 50          	add    rsp,0x50
   1400034d3:	5d                   	pop    rbp
   1400034d4:	c3                   	ret

00000001400034d5 <__pformat_wcputs>:
   1400034d5:	55                   	push   rbp
   1400034d6:	48 89 e5             	mov    rbp,rsp
   1400034d9:	48 83 ec 20          	sub    rsp,0x20
   1400034dd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400034e1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400034e5:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400034ea:	75 0b                	jne    1400034f7 <__pformat_wcputs+0x22>
   1400034ec:	48 8d 05 45 7e 00 00 	lea    rax,[rip+0x7e45]        # 14000b338 <.rdata+0x8>
   1400034f3:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400034f7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400034fb:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400034fe:	85 c0                	test   eax,eax
   140003500:	78 2f                	js     140003531 <__pformat_wcputs+0x5c>
   140003502:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003506:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003509:	48 63 d0             	movsxd rdx,eax
   14000350c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003510:	48 89 c1             	mov    rcx,rax
   140003513:	e8 28 58 00 00       	call   140008d40 <wcsnlen>
   140003518:	89 c1                	mov    ecx,eax
   14000351a:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000351e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003522:	49 89 d0             	mov    r8,rdx
   140003525:	89 ca                	mov    edx,ecx
   140003527:	48 89 c1             	mov    rcx,rax
   14000352a:	e8 5a fe ff ff       	call   140003389 <__pformat_wputchars>
   14000352f:	eb 23                	jmp    140003554 <__pformat_wcputs+0x7f>
   140003531:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003535:	48 89 c1             	mov    rcx,rax
   140003538:	e8 4b 61 00 00       	call   140009688 <wcslen>
   14000353d:	89 c1                	mov    ecx,eax
   14000353f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003543:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003547:	49 89 d0             	mov    r8,rdx
   14000354a:	89 ca                	mov    edx,ecx
   14000354c:	48 89 c1             	mov    rcx,rax
   14000354f:	e8 35 fe ff ff       	call   140003389 <__pformat_wputchars>
   140003554:	90                   	nop
   140003555:	48 83 c4 20          	add    rsp,0x20
   140003559:	5d                   	pop    rbp
   14000355a:	c3                   	ret

000000014000355b <__pformat_int_bufsiz>:
   14000355b:	55                   	push   rbp
   14000355c:	48 89 e5             	mov    rbp,rsp
   14000355f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003562:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003565:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003569:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000356c:	83 e8 01             	sub    eax,0x1
   14000356f:	48 98                	cdqe
   140003571:	48 83 c0 40          	add    rax,0x40
   140003575:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140003578:	48 63 ca             	movsxd rcx,edx
   14000357b:	ba 00 00 00 00       	mov    edx,0x0
   140003580:	48 f7 f1             	div    rcx
   140003583:	89 c2                	mov    edx,eax
   140003585:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140003588:	01 d0                	add    eax,edx
   14000358a:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   14000358d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003591:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003594:	ba 00 00 00 00       	mov    edx,0x0
   140003599:	85 c0                	test   eax,eax
   14000359b:	0f 48 c2             	cmovs  eax,edx
   14000359e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   1400035a1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035a5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400035a8:	25 00 10 00 00       	and    eax,0x1000
   1400035ad:	85 c0                	test   eax,eax
   1400035af:	74 29                	je     1400035da <__pformat_int_bufsiz+0x7f>
   1400035b1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035b5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400035b9:	66 85 c0             	test   ax,ax
   1400035bc:	74 1c                	je     1400035da <__pformat_int_bufsiz+0x7f>
   1400035be:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035c1:	48 63 d0             	movsxd rdx,eax
   1400035c4:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   1400035cb:	48 89 d1             	mov    rcx,rdx
   1400035ce:	48 c1 e9 20          	shr    rcx,0x20
   1400035d2:	99                   	cdq
   1400035d3:	89 c8                	mov    eax,ecx
   1400035d5:	29 d0                	sub    eax,edx
   1400035d7:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   1400035da:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035de:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400035e1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035e4:	39 c2                	cmp    edx,eax
   1400035e6:	0f 4d c2             	cmovge eax,edx
   1400035e9:	5d                   	pop    rbp
   1400035ea:	c3                   	ret

00000001400035eb <__pformat_int>:
   1400035eb:	55                   	push   rbp
   1400035ec:	53                   	push   rbx
   1400035ed:	48 83 ec 58          	sub    rsp,0x58
   1400035f1:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400035f6:	48 89 cb             	mov    rbx,rcx
   1400035f9:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   1400035fc:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   140003600:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   140003604:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   140003608:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000360c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003610:	49 89 c0             	mov    r8,rax
   140003613:	ba 03 00 00 00       	mov    edx,0x3
   140003618:	b9 01 00 00 00       	mov    ecx,0x1
   14000361d:	e8 39 ff ff ff       	call   14000355b <__pformat_int_bufsiz>
   140003622:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140003625:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   14000362c:	00 
   14000362d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140003630:	48 98                	cdqe
   140003632:	48 83 c0 0f          	add    rax,0xf
   140003636:	48 c1 e8 04          	shr    rax,0x4
   14000363a:	48 c1 e0 04          	shl    rax,0x4
   14000363e:	e8 7d fa ff ff       	call   1400030c0 <___chkstk_ms>
   140003643:	48 29 c4             	sub    rsp,rax
   140003646:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000364b:	48 83 c0 0f          	add    rax,0xf
   14000364f:	48 c1 e8 04          	shr    rax,0x4
   140003653:	48 c1 e0 04          	shl    rax,0x4
   140003657:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000365b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000365f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003663:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003667:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000366a:	25 80 00 00 00       	and    eax,0x80
   14000366f:	85 c0                	test   eax,eax
   140003671:	0f 84 ea 00 00 00    	je     140003761 <__pformat_int+0x176>
   140003677:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000367b:	48 85 c0             	test   rax,rax
   14000367e:	79 10                	jns    140003690 <__pformat_int+0xa5>
   140003680:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003684:	48 f7 d8             	neg    rax
   140003687:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000368b:	e9 d1 00 00 00       	jmp    140003761 <__pformat_int+0x176>
   140003690:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003694:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003697:	24 7f                	and    al,0x7f
   140003699:	89 c2                	mov    edx,eax
   14000369b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000369f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400036a2:	e9 ba 00 00 00       	jmp    140003761 <__pformat_int+0x176>
   1400036a7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036ab:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400036af:	74 54                	je     140003705 <__pformat_int+0x11a>
   1400036b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036b5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400036b8:	25 00 10 00 00       	and    eax,0x1000
   1400036bd:	85 c0                	test   eax,eax
   1400036bf:	74 44                	je     140003705 <__pformat_int+0x11a>
   1400036c1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036c5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400036c9:	66 85 c0             	test   ax,ax
   1400036cc:	74 37                	je     140003705 <__pformat_int+0x11a>
   1400036ce:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036d2:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400036d6:	48 89 c2             	mov    rdx,rax
   1400036d9:	48 89 d0             	mov    rax,rdx
   1400036dc:	48 c1 f8 3f          	sar    rax,0x3f
   1400036e0:	48 c1 e8 3e          	shr    rax,0x3e
   1400036e4:	48 01 c2             	add    rdx,rax
   1400036e7:	83 e2 03             	and    edx,0x3
   1400036ea:	48 29 c2             	sub    rdx,rax
   1400036ed:	48 89 d0             	mov    rax,rdx
   1400036f0:	48 83 f8 03          	cmp    rax,0x3
   1400036f4:	75 0f                	jne    140003705 <__pformat_int+0x11a>
   1400036f6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036fa:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400036fe:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003702:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   140003705:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   140003709:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003710:	cc cc cc 
   140003713:	48 89 c8             	mov    rax,rcx
   140003716:	48 f7 e2             	mul    rdx
   140003719:	48 c1 ea 03          	shr    rdx,0x3
   14000371d:	48 89 d0             	mov    rax,rdx
   140003720:	48 c1 e0 02          	shl    rax,0x2
   140003724:	48 01 d0             	add    rax,rdx
   140003727:	48 01 c0             	add    rax,rax
   14000372a:	48 29 c1             	sub    rcx,rax
   14000372d:	48 89 ca             	mov    rdx,rcx
   140003730:	89 d0                	mov    eax,edx
   140003732:	8d 48 30             	lea    ecx,[rax+0x30]
   140003735:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003739:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000373d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003741:	89 ca                	mov    edx,ecx
   140003743:	88 10                	mov    BYTE PTR [rax],dl
   140003745:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003749:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003750:	cc cc cc 
   140003753:	48 f7 e2             	mul    rdx
   140003756:	48 89 d0             	mov    rax,rdx
   140003759:	48 c1 e8 03          	shr    rax,0x3
   14000375d:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140003761:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003765:	48 85 c0             	test   rax,rax
   140003768:	0f 85 39 ff ff ff    	jne    1400036a7 <__pformat_int+0xbc>
   14000376e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003772:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003775:	85 c0                	test   eax,eax
   140003777:	7e 3e                	jle    1400037b7 <__pformat_int+0x1cc>
   140003779:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000377d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003780:	89 c1                	mov    ecx,eax
   140003782:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003786:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000378a:	89 c2                	mov    edx,eax
   14000378c:	89 c8                	mov    eax,ecx
   14000378e:	29 d0                	sub    eax,edx
   140003790:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003793:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003797:	7e 1e                	jle    1400037b7 <__pformat_int+0x1cc>
   140003799:	eb 0f                	jmp    1400037aa <__pformat_int+0x1bf>
   14000379b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000379f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037a3:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037a7:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400037aa:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400037ad:	8d 50 ff             	lea    edx,[rax-0x1]
   1400037b0:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   1400037b3:	85 c0                	test   eax,eax
   1400037b5:	7f e4                	jg     14000379b <__pformat_int+0x1b0>
   1400037b7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037bb:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400037bf:	75 1a                	jne    1400037db <__pformat_int+0x1f0>
   1400037c1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037c5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400037c8:	85 c0                	test   eax,eax
   1400037ca:	74 0f                	je     1400037db <__pformat_int+0x1f0>
   1400037cc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037d0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037d4:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037d8:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400037db:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037df:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037e2:	85 c0                	test   eax,eax
   1400037e4:	0f 8e ce 00 00 00    	jle    1400038b8 <__pformat_int+0x2cd>
   1400037ea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037ee:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037f1:	89 c1                	mov    ecx,eax
   1400037f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037f7:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400037fb:	89 c2                	mov    edx,eax
   1400037fd:	89 c8                	mov    eax,ecx
   1400037ff:	29 d0                	sub    eax,edx
   140003801:	89 c2                	mov    edx,eax
   140003803:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003807:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000380a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000380e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003811:	85 c0                	test   eax,eax
   140003813:	0f 8e 9f 00 00 00    	jle    1400038b8 <__pformat_int+0x2cd>
   140003819:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000381d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003820:	25 c0 01 00 00       	and    eax,0x1c0
   140003825:	85 c0                	test   eax,eax
   140003827:	74 11                	je     14000383a <__pformat_int+0x24f>
   140003829:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000382d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003830:	8d 50 ff             	lea    edx,[rax-0x1]
   140003833:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003837:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000383a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000383e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003841:	85 c0                	test   eax,eax
   140003843:	79 3b                	jns    140003880 <__pformat_int+0x295>
   140003845:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003849:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000384c:	25 00 06 00 00       	and    eax,0x600
   140003851:	3d 00 02 00 00       	cmp    eax,0x200
   140003856:	75 28                	jne    140003880 <__pformat_int+0x295>
   140003858:	eb 0f                	jmp    140003869 <__pformat_int+0x27e>
   14000385a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000385e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003862:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003866:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003869:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000386d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003870:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003873:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003877:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000387a:	85 c0                	test   eax,eax
   14000387c:	7f dc                	jg     14000385a <__pformat_int+0x26f>
   14000387e:	eb 38                	jmp    1400038b8 <__pformat_int+0x2cd>
   140003880:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003884:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003887:	25 00 04 00 00       	and    eax,0x400
   14000388c:	85 c0                	test   eax,eax
   14000388e:	75 28                	jne    1400038b8 <__pformat_int+0x2cd>
   140003890:	eb 11                	jmp    1400038a3 <__pformat_int+0x2b8>
   140003892:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003896:	48 89 c2             	mov    rdx,rax
   140003899:	b9 20 00 00 00       	mov    ecx,0x20
   14000389e:	e8 dd f8 ff ff       	call   140003180 <__pformat_putc>
   1400038a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038a7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038aa:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400038ad:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400038b1:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400038b4:	85 c0                	test   eax,eax
   1400038b6:	7f da                	jg     140003892 <__pformat_int+0x2a7>
   1400038b8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038bc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038bf:	25 80 00 00 00       	and    eax,0x80
   1400038c4:	85 c0                	test   eax,eax
   1400038c6:	74 11                	je     1400038d9 <__pformat_int+0x2ee>
   1400038c8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038cc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038d0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038d4:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   1400038d7:	eb 5a                	jmp    140003933 <__pformat_int+0x348>
   1400038d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038dd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038e0:	25 00 01 00 00       	and    eax,0x100
   1400038e5:	85 c0                	test   eax,eax
   1400038e7:	74 11                	je     1400038fa <__pformat_int+0x30f>
   1400038e9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038ed:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038f1:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038f5:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400038f8:	eb 39                	jmp    140003933 <__pformat_int+0x348>
   1400038fa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038fe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003901:	83 e0 40             	and    eax,0x40
   140003904:	85 c0                	test   eax,eax
   140003906:	74 2b                	je     140003933 <__pformat_int+0x348>
   140003908:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000390c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003910:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003914:	c6 00 20             	mov    BYTE PTR [rax],0x20
   140003917:	eb 1a                	jmp    140003933 <__pformat_int+0x348>
   140003919:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   14000391e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003922:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003925:	0f be c0             	movsx  eax,al
   140003928:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000392c:	89 c1                	mov    ecx,eax
   14000392e:	e8 4d f8 ff ff       	call   140003180 <__pformat_putc>
   140003933:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003937:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   14000393b:	72 dc                	jb     140003919 <__pformat_int+0x32e>
   14000393d:	eb 11                	jmp    140003950 <__pformat_int+0x365>
   14000393f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003943:	48 89 c2             	mov    rdx,rax
   140003946:	b9 20 00 00 00       	mov    ecx,0x20
   14000394b:	e8 30 f8 ff ff       	call   140003180 <__pformat_putc>
   140003950:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003954:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003957:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000395a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000395e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003961:	85 c0                	test   eax,eax
   140003963:	7f da                	jg     14000393f <__pformat_int+0x354>
   140003965:	90                   	nop
   140003966:	90                   	nop
   140003967:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   14000396b:	5b                   	pop    rbx
   14000396c:	5d                   	pop    rbp
   14000396d:	c3                   	ret

000000014000396e <__pformat_xint>:
   14000396e:	55                   	push   rbp
   14000396f:	53                   	push   rbx
   140003970:	48 83 ec 68          	sub    rsp,0x68
   140003974:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003979:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   14000397c:	48 89 d3             	mov    rbx,rdx
   14000397f:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140003982:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   140003986:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   14000398a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   14000398e:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003992:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003996:	74 1e                	je     1400039b6 <__pformat_xint+0x48>
   140003998:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   14000399c:	74 06                	je     1400039a4 <__pformat_xint+0x36>
   14000399e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   1400039a2:	75 09                	jne    1400039ad <__pformat_xint+0x3f>
   1400039a4:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400039ab:	eb 10                	jmp    1400039bd <__pformat_xint+0x4f>
   1400039ad:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   1400039b4:	eb 07                	jmp    1400039bd <__pformat_xint+0x4f>
   1400039b6:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   1400039bd:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   1400039c1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400039c4:	49 89 d0             	mov    r8,rdx
   1400039c7:	89 c2                	mov    edx,eax
   1400039c9:	b9 02 00 00 00       	mov    ecx,0x2
   1400039ce:	e8 88 fb ff ff       	call   14000355b <__pformat_int_bufsiz>
   1400039d3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400039d6:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   1400039dd:	00 
   1400039de:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400039e1:	48 98                	cdqe
   1400039e3:	48 83 c0 0f          	add    rax,0xf
   1400039e7:	48 c1 e8 04          	shr    rax,0x4
   1400039eb:	48 c1 e0 04          	shl    rax,0x4
   1400039ef:	e8 cc f6 ff ff       	call   1400030c0 <___chkstk_ms>
   1400039f4:	48 29 c4             	sub    rsp,rax
   1400039f7:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400039fc:	48 83 c0 0f          	add    rax,0xf
   140003a00:	48 c1 e8 04          	shr    rax,0x4
   140003a04:	48 c1 e0 04          	shl    rax,0x4
   140003a08:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140003a0c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003a10:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003a14:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a18:	74 1e                	je     140003a38 <__pformat_xint+0xca>
   140003a1a:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a1e:	74 06                	je     140003a26 <__pformat_xint+0xb8>
   140003a20:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a24:	75 09                	jne    140003a2f <__pformat_xint+0xc1>
   140003a26:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003a2d:	eb 10                	jmp    140003a3f <__pformat_xint+0xd1>
   140003a2f:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003a36:	eb 67                	jmp    140003a9f <__pformat_xint+0x131>
   140003a38:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003a3f:	eb 5e                	jmp    140003a9f <__pformat_xint+0x131>
   140003a41:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003a45:	89 c2                	mov    edx,eax
   140003a47:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003a4a:	21 d0                	and    eax,edx
   140003a4c:	8d 48 30             	lea    ecx,[rax+0x30]
   140003a4f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003a53:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003a57:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003a5b:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003a5f:	89 ca                	mov    edx,ecx
   140003a61:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a65:	88 10                	mov    BYTE PTR [rax],dl
   140003a67:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a6b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a6e:	3c 39                	cmp    al,0x39
   140003a70:	7e 1a                	jle    140003a8c <__pformat_xint+0x11e>
   140003a72:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a76:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a79:	83 c0 07             	add    eax,0x7
   140003a7c:	89 c2                	mov    edx,eax
   140003a7e:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003a81:	83 e0 20             	and    eax,0x20
   140003a84:	09 c2                	or     edx,eax
   140003a86:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a8a:	88 10                	mov    BYTE PTR [rax],dl
   140003a8c:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003a90:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003a93:	89 c1                	mov    ecx,eax
   140003a95:	48 d3 ea             	shr    rdx,cl
   140003a98:	48 89 d0             	mov    rax,rdx
   140003a9b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003a9f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003aa3:	48 85 c0             	test   rax,rax
   140003aa6:	75 99                	jne    140003a41 <__pformat_xint+0xd3>
   140003aa8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003aac:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003ab0:	75 13                	jne    140003ac5 <__pformat_xint+0x157>
   140003ab2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ab6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003ab9:	80 e4 f7             	and    ah,0xf7
   140003abc:	89 c2                	mov    edx,eax
   140003abe:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ac2:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003ac5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ac9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003acc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003acf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003ad3:	7e 3a                	jle    140003b0f <__pformat_xint+0x1a1>
   140003ad5:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003ad8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003adc:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003ae0:	89 c1                	mov    ecx,eax
   140003ae2:	89 d0                	mov    eax,edx
   140003ae4:	29 c8                	sub    eax,ecx
   140003ae6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003ae9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003aed:	7e 20                	jle    140003b0f <__pformat_xint+0x1a1>
   140003aef:	eb 0f                	jmp    140003b00 <__pformat_xint+0x192>
   140003af1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003af5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003af9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003afd:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b00:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003b03:	8d 50 ff             	lea    edx,[rax-0x1]
   140003b06:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b09:	85 c0                	test   eax,eax
   140003b0b:	7f e4                	jg     140003af1 <__pformat_xint+0x183>
   140003b0d:	eb 25                	jmp    140003b34 <__pformat_xint+0x1c6>
   140003b0f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003b13:	75 1f                	jne    140003b34 <__pformat_xint+0x1c6>
   140003b15:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b19:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b1c:	25 00 08 00 00       	and    eax,0x800
   140003b21:	85 c0                	test   eax,eax
   140003b23:	74 0f                	je     140003b34 <__pformat_xint+0x1c6>
   140003b25:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b29:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b2d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b31:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b34:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b38:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b3c:	75 1a                	jne    140003b58 <__pformat_xint+0x1ea>
   140003b3e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b42:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b45:	85 c0                	test   eax,eax
   140003b47:	74 0f                	je     140003b58 <__pformat_xint+0x1ea>
   140003b49:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b4d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b51:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b55:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b58:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b5c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b5f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003b63:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003b67:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b6a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003b6d:	7d 15                	jge    140003b84 <__pformat_xint+0x216>
   140003b6f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b73:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b76:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003b79:	89 c2                	mov    edx,eax
   140003b7b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b7f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003b82:	eb 0b                	jmp    140003b8f <__pformat_xint+0x221>
   140003b84:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b88:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003b8f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b93:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b96:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b99:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b9d:	7e 1a                	jle    140003bb9 <__pformat_xint+0x24b>
   140003b9f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003ba3:	74 14                	je     140003bb9 <__pformat_xint+0x24b>
   140003ba5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ba9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bac:	25 00 08 00 00       	and    eax,0x800
   140003bb1:	85 c0                	test   eax,eax
   140003bb3:	74 04                	je     140003bb9 <__pformat_xint+0x24b>
   140003bb5:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003bb9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003bbd:	7e 3c                	jle    140003bfb <__pformat_xint+0x28d>
   140003bbf:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bc3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003bc6:	85 c0                	test   eax,eax
   140003bc8:	79 31                	jns    140003bfb <__pformat_xint+0x28d>
   140003bca:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bce:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bd1:	25 00 06 00 00       	and    eax,0x600
   140003bd6:	3d 00 02 00 00       	cmp    eax,0x200
   140003bdb:	75 1e                	jne    140003bfb <__pformat_xint+0x28d>
   140003bdd:	eb 0f                	jmp    140003bee <__pformat_xint+0x280>
   140003bdf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003be3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003be7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003beb:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bee:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003bf1:	8d 50 ff             	lea    edx,[rax-0x1]
   140003bf4:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bf7:	85 c0                	test   eax,eax
   140003bf9:	7f e4                	jg     140003bdf <__pformat_xint+0x271>
   140003bfb:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003bff:	74 30                	je     140003c31 <__pformat_xint+0x2c3>
   140003c01:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c05:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c08:	25 00 08 00 00       	and    eax,0x800
   140003c0d:	85 c0                	test   eax,eax
   140003c0f:	74 20                	je     140003c31 <__pformat_xint+0x2c3>
   140003c11:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c15:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c19:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c1d:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003c20:	88 10                	mov    BYTE PTR [rax],dl
   140003c22:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c26:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c2a:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c2e:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c31:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c35:	7e 4c                	jle    140003c83 <__pformat_xint+0x315>
   140003c37:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c3b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c3e:	25 00 04 00 00       	and    eax,0x400
   140003c43:	85 c0                	test   eax,eax
   140003c45:	75 3c                	jne    140003c83 <__pformat_xint+0x315>
   140003c47:	eb 11                	jmp    140003c5a <__pformat_xint+0x2ec>
   140003c49:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c4d:	48 89 c2             	mov    rdx,rax
   140003c50:	b9 20 00 00 00       	mov    ecx,0x20
   140003c55:	e8 26 f5 ff ff       	call   140003180 <__pformat_putc>
   140003c5a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c5d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c60:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c63:	85 c0                	test   eax,eax
   140003c65:	7f e2                	jg     140003c49 <__pformat_xint+0x2db>
   140003c67:	eb 1a                	jmp    140003c83 <__pformat_xint+0x315>
   140003c69:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003c6e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c72:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003c75:	0f be c0             	movsx  eax,al
   140003c78:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003c7c:	89 c1                	mov    ecx,eax
   140003c7e:	e8 fd f4 ff ff       	call   140003180 <__pformat_putc>
   140003c83:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c87:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003c8b:	72 dc                	jb     140003c69 <__pformat_xint+0x2fb>
   140003c8d:	eb 11                	jmp    140003ca0 <__pformat_xint+0x332>
   140003c8f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c93:	48 89 c2             	mov    rdx,rax
   140003c96:	b9 20 00 00 00       	mov    ecx,0x20
   140003c9b:	e8 e0 f4 ff ff       	call   140003180 <__pformat_putc>
   140003ca0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ca3:	8d 50 ff             	lea    edx,[rax-0x1]
   140003ca6:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003ca9:	85 c0                	test   eax,eax
   140003cab:	7f e2                	jg     140003c8f <__pformat_xint+0x321>
   140003cad:	90                   	nop
   140003cae:	90                   	nop
   140003caf:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003cb3:	5b                   	pop    rbx
   140003cb4:	5d                   	pop    rbp
   140003cb5:	c3                   	ret

0000000140003cb6 <init_fpreg_ldouble>:
   140003cb6:	55                   	push   rbp
   140003cb7:	53                   	push   rbx
   140003cb8:	48 83 ec 28          	sub    rsp,0x28
   140003cbc:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003cc1:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003cc5:	48 89 d3             	mov    rbx,rdx
   140003cc8:	db 2b                	fld    TBYTE PTR [rbx]
   140003cca:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003ccd:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003cd0:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003cd3:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003cd7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cdb:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003cdf:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003ce2:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003ce6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003cea:	48 83 c4 28          	add    rsp,0x28
   140003cee:	5b                   	pop    rbx
   140003cef:	5d                   	pop    rbp
   140003cf0:	c3                   	ret

0000000140003cf1 <__pformat_cvt>:
   140003cf1:	55                   	push   rbp
   140003cf2:	53                   	push   rbx
   140003cf3:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003cfa:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003d01:	00 
   140003d02:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003d05:	48 89 d3             	mov    rbx,rdx
   140003d08:	db 2b                	fld    TBYTE PTR [rbx]
   140003d0a:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003d0d:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003d11:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003d15:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003d1c:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003d20:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003d23:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003d26:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003d2a:	48 89 c1             	mov    rcx,rax
   140003d2d:	e8 84 ff ff ff       	call   140003cb6 <init_fpreg_ldouble>
   140003d32:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003d35:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003d38:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003d3c:	48 89 c1             	mov    rcx,rax
   140003d3f:	e8 9c 4e 00 00       	call   140008be0 <__fpclassifyl>
   140003d44:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d47:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d4a:	25 00 01 00 00       	and    eax,0x100
   140003d4f:	85 c0                	test   eax,eax
   140003d51:	74 1d                	je     140003d70 <__pformat_cvt+0x7f>
   140003d53:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d56:	25 00 04 00 00       	and    eax,0x400
   140003d5b:	85 c0                	test   eax,eax
   140003d5d:	74 07                	je     140003d66 <__pformat_cvt+0x75>
   140003d5f:	b8 03 00 00 00       	mov    eax,0x3
   140003d64:	eb 05                	jmp    140003d6b <__pformat_cvt+0x7a>
   140003d66:	b8 04 00 00 00       	mov    eax,0x4
   140003d6b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d6e:	eb 4a                	jmp    140003dba <__pformat_cvt+0xc9>
   140003d70:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d73:	25 00 04 00 00       	and    eax,0x400
   140003d78:	85 c0                	test   eax,eax
   140003d7a:	74 37                	je     140003db3 <__pformat_cvt+0xc2>
   140003d7c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d7f:	25 00 40 00 00       	and    eax,0x4000
   140003d84:	85 c0                	test   eax,eax
   140003d86:	74 10                	je     140003d98 <__pformat_cvt+0xa7>
   140003d88:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003d8f:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003d96:	eb 22                	jmp    140003dba <__pformat_cvt+0xc9>
   140003d98:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003d9f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003da3:	98                   	cwde
   140003da4:	25 ff 7f 00 00       	and    eax,0x7fff
   140003da9:	2d 3e 40 00 00       	sub    eax,0x403e
   140003dae:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003db1:	eb 07                	jmp    140003dba <__pformat_cvt+0xc9>
   140003db3:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003dba:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003dbd:	83 f8 04             	cmp    eax,0x4
   140003dc0:	74 0e                	je     140003dd0 <__pformat_cvt+0xdf>
   140003dc2:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003dc6:	98                   	cwde
   140003dc7:	25 00 80 00 00       	and    eax,0x8000
   140003dcc:	89 c2                	mov    edx,eax
   140003dce:	eb 05                	jmp    140003dd5 <__pformat_cvt+0xe4>
   140003dd0:	ba 00 00 00 00       	mov    edx,0x0
   140003dd5:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003dd9:	89 10                	mov    DWORD PTR [rax],edx
   140003ddb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003dde:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003de2:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003de6:	48 8d 0d 83 62 00 00 	lea    rcx,[rip+0x6283]        # 14000a070 <fpi.0>
   140003ded:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003df1:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003df6:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003dfa:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003dff:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003e02:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003e06:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003e09:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003e0d:	89 c2                	mov    edx,eax
   140003e0f:	e8 96 24 00 00       	call   1400062aa <__gdtoa>
   140003e14:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003e1b:	5b                   	pop    rbx
   140003e1c:	5d                   	pop    rbp
   140003e1d:	c3                   	ret

0000000140003e1e <__pformat_ecvt>:
   140003e1e:	55                   	push   rbp
   140003e1f:	53                   	push   rbx
   140003e20:	48 83 ec 58          	sub    rsp,0x58
   140003e24:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003e29:	48 89 cb             	mov    rbx,rcx
   140003e2c:	db 2b                	fld    TBYTE PTR [rbx]
   140003e2e:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003e31:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003e34:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003e38:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003e3c:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003e3f:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003e42:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003e46:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003e49:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e4d:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e51:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003e56:	4d 89 c1             	mov    r9,r8
   140003e59:	41 89 c8             	mov    r8d,ecx
   140003e5c:	48 89 c2             	mov    rdx,rax
   140003e5f:	b9 02 00 00 00       	mov    ecx,0x2
   140003e64:	e8 88 fe ff ff       	call   140003cf1 <__pformat_cvt>
   140003e69:	48 83 c4 58          	add    rsp,0x58
   140003e6d:	5b                   	pop    rbx
   140003e6e:	5d                   	pop    rbp
   140003e6f:	c3                   	ret

0000000140003e70 <__pformat_fcvt>:
   140003e70:	55                   	push   rbp
   140003e71:	53                   	push   rbx
   140003e72:	48 83 ec 58          	sub    rsp,0x58
   140003e76:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003e7b:	48 89 cb             	mov    rbx,rcx
   140003e7e:	db 2b                	fld    TBYTE PTR [rbx]
   140003e80:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003e83:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003e86:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003e8a:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003e8e:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003e91:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003e94:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003e98:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003e9b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e9f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003ea3:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003ea8:	4d 89 c1             	mov    r9,r8
   140003eab:	41 89 c8             	mov    r8d,ecx
   140003eae:	48 89 c2             	mov    rdx,rax
   140003eb1:	b9 03 00 00 00       	mov    ecx,0x3
   140003eb6:	e8 36 fe ff ff       	call   140003cf1 <__pformat_cvt>
   140003ebb:	48 83 c4 58          	add    rsp,0x58
   140003ebf:	5b                   	pop    rbx
   140003ec0:	5d                   	pop    rbp
   140003ec1:	c3                   	ret

0000000140003ec2 <__pformat_emit_radix_point>:
   140003ec2:	55                   	push   rbp
   140003ec3:	53                   	push   rbx
   140003ec4:	48 83 ec 68          	sub    rsp,0x68
   140003ec8:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003ecd:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003ed1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003ed5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003ed8:	83 f8 fd             	cmp    eax,0xfffffffd
   140003edb:	75 48                	jne    140003f25 <__pformat_emit_radix_point+0x63>
   140003edd:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003ee4:	00 
   140003ee5:	e8 4e 57 00 00       	call   140009638 <localeconv>
   140003eea:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003eed:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003ef1:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003ef5:	49 89 c9             	mov    r9,rcx
   140003ef8:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003efe:	48 89 c1             	mov    rcx,rax
   140003f01:	e8 6a 51 00 00       	call   140009070 <mbrtowc>
   140003f06:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003f09:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003f0d:	7e 0c                	jle    140003f1b <__pformat_emit_radix_point+0x59>
   140003f0f:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003f13:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f17:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003f1b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f1f:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003f22:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003f25:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f29:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003f2d:	66 85 c0             	test   ax,ax
   140003f30:	0f 84 b8 00 00 00    	je     140003fee <__pformat_emit_radix_point+0x12c>
   140003f36:	48 89 e0             	mov    rax,rsp
   140003f39:	48 89 c3             	mov    rbx,rax
   140003f3c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f40:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f43:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003f46:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003f49:	48 63 d0             	movsxd rdx,eax
   140003f4c:	48 83 ea 01          	sub    rdx,0x1
   140003f50:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140003f54:	48 98                	cdqe
   140003f56:	48 83 c0 0f          	add    rax,0xf
   140003f5a:	48 c1 e8 04          	shr    rax,0x4
   140003f5e:	48 c1 e0 04          	shl    rax,0x4
   140003f62:	e8 59 f1 ff ff       	call   1400030c0 <___chkstk_ms>
   140003f67:	48 29 c4             	sub    rsp,rax
   140003f6a:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003f6f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003f73:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   140003f7a:	00 
   140003f7b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f7f:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003f83:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140003f87:	0f b7 d0             	movzx  edx,ax
   140003f8a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003f8e:	49 89 c8             	mov    r8,rcx
   140003f91:	48 89 c1             	mov    rcx,rax
   140003f94:	e8 87 50 00 00       	call   140009020 <wcrtomb>
   140003f99:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003f9c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003fa0:	7e 36                	jle    140003fd8 <__pformat_emit_radix_point+0x116>
   140003fa2:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003fa6:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003faa:	eb 1d                	jmp    140003fc9 <__pformat_emit_radix_point+0x107>
   140003fac:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003fb0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003fb4:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003fb8:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003fbb:	0f be c0             	movsx  eax,al
   140003fbe:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003fc2:	89 c1                	mov    ecx,eax
   140003fc4:	e8 b7 f1 ff ff       	call   140003180 <__pformat_putc>
   140003fc9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003fcc:	8d 50 ff             	lea    edx,[rax-0x1]
   140003fcf:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003fd2:	85 c0                	test   eax,eax
   140003fd4:	7f d6                	jg     140003fac <__pformat_emit_radix_point+0xea>
   140003fd6:	eb 11                	jmp    140003fe9 <__pformat_emit_radix_point+0x127>
   140003fd8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fdc:	48 89 c2             	mov    rdx,rax
   140003fdf:	b9 2e 00 00 00       	mov    ecx,0x2e
   140003fe4:	e8 97 f1 ff ff       	call   140003180 <__pformat_putc>
   140003fe9:	48 89 dc             	mov    rsp,rbx
   140003fec:	eb 11                	jmp    140003fff <__pformat_emit_radix_point+0x13d>
   140003fee:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003ff2:	48 89 c2             	mov    rdx,rax
   140003ff5:	b9 2e 00 00 00       	mov    ecx,0x2e
   140003ffa:	e8 81 f1 ff ff       	call   140003180 <__pformat_putc>
   140003fff:	90                   	nop
   140004000:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140004004:	5b                   	pop    rbx
   140004005:	5d                   	pop    rbp
   140004006:	c3                   	ret

0000000140004007 <__pformat_emit_numeric_value>:
   140004007:	55                   	push   rbp
   140004008:	48 89 e5             	mov    rbp,rsp
   14000400b:	48 83 ec 30          	sub    rsp,0x30
   14000400f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004012:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004016:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   14000401a:	75 0e                	jne    14000402a <__pformat_emit_numeric_value+0x23>
   14000401c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004020:	48 89 c1             	mov    rcx,rax
   140004023:	e8 9a fe ff ff       	call   140003ec2 <__pformat_emit_radix_point>
   140004028:	eb 43                	jmp    14000406d <__pformat_emit_numeric_value+0x66>
   14000402a:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   14000402e:	75 2f                	jne    14000405f <__pformat_emit_numeric_value+0x58>
   140004030:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004034:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004038:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   14000403c:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   140004040:	66 85 c0             	test   ax,ax
   140004043:	74 28                	je     14000406d <__pformat_emit_numeric_value+0x66>
   140004045:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004049:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   14000404d:	49 89 d0             	mov    r8,rdx
   140004050:	ba 01 00 00 00       	mov    edx,0x1
   140004055:	48 89 c1             	mov    rcx,rax
   140004058:	e8 2c f3 ff ff       	call   140003389 <__pformat_wputchars>
   14000405d:	eb 0e                	jmp    14000406d <__pformat_emit_numeric_value+0x66>
   14000405f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004063:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140004066:	89 c1                	mov    ecx,eax
   140004068:	e8 13 f1 ff ff       	call   140003180 <__pformat_putc>
   14000406d:	90                   	nop
   14000406e:	48 83 c4 30          	add    rsp,0x30
   140004072:	5d                   	pop    rbp
   140004073:	c3                   	ret

0000000140004074 <__pformat_emit_inf_or_nan>:
   140004074:	55                   	push   rbp
   140004075:	48 89 e5             	mov    rbp,rsp
   140004078:	48 83 ec 40          	sub    rsp,0x40
   14000407c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000407f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004083:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140004087:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000408b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000408f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004093:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000409a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000409e:	74 11                	je     1400040b1 <__pformat_emit_inf_or_nan+0x3d>
   1400040a0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040a4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040a8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040ac:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   1400040af:	eb 3e                	jmp    1400040ef <__pformat_emit_inf_or_nan+0x7b>
   1400040b1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040b5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400040b8:	25 00 01 00 00       	and    eax,0x100
   1400040bd:	85 c0                	test   eax,eax
   1400040bf:	74 11                	je     1400040d2 <__pformat_emit_inf_or_nan+0x5e>
   1400040c1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040c5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040c9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040cd:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400040d0:	eb 1d                	jmp    1400040ef <__pformat_emit_inf_or_nan+0x7b>
   1400040d2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040d6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400040d9:	83 e0 40             	and    eax,0x40
   1400040dc:	85 c0                	test   eax,eax
   1400040de:	74 0f                	je     1400040ef <__pformat_emit_inf_or_nan+0x7b>
   1400040e0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040e4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040e8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040ec:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400040ef:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   1400040f6:	eb 38                	jmp    140004130 <__pformat_emit_inf_or_nan+0xbc>
   1400040f8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040fc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004100:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004104:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004107:	83 e0 df             	and    eax,0xffffffdf
   14000410a:	41 89 c0             	mov    r8d,eax
   14000410d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004111:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004114:	83 e0 20             	and    eax,0x20
   140004117:	89 c1                	mov    ecx,eax
   140004119:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000411d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004121:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004125:	44 89 c2             	mov    edx,r8d
   140004128:	09 ca                	or     edx,ecx
   14000412a:	88 10                	mov    BYTE PTR [rax],dl
   14000412c:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004130:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004134:	7f c2                	jg     1400040f8 <__pformat_emit_inf_or_nan+0x84>
   140004136:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000413a:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   14000413e:	48 29 c2             	sub    rdx,rax
   140004141:	89 d1                	mov    ecx,edx
   140004143:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004147:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000414b:	49 89 d0             	mov    r8,rdx
   14000414e:	89 ca                	mov    edx,ecx
   140004150:	48 89 c1             	mov    rcx,rax
   140004153:	e8 ac f0 ff ff       	call   140003204 <__pformat_putchars>
   140004158:	90                   	nop
   140004159:	48 83 c4 40          	add    rsp,0x40
   14000415d:	5d                   	pop    rbp
   14000415e:	c3                   	ret

000000014000415f <__pformat_emit_float>:
   14000415f:	55                   	push   rbp
   140004160:	48 89 e5             	mov    rbp,rsp
   140004163:	48 83 ec 30          	sub    rsp,0x30
   140004167:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000416a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000416e:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140004172:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004176:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000417a:	7e 2e                	jle    1400041aa <__pformat_emit_float+0x4b>
   14000417c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004180:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004183:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   140004186:	7f 15                	jg     14000419d <__pformat_emit_float+0x3e>
   140004188:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000418c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000418f:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004192:	89 c2                	mov    edx,eax
   140004194:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004198:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000419b:	eb 29                	jmp    1400041c6 <__pformat_emit_float+0x67>
   14000419d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041a1:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400041a8:	eb 1c                	jmp    1400041c6 <__pformat_emit_float+0x67>
   1400041aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041ae:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041b1:	85 c0                	test   eax,eax
   1400041b3:	7e 11                	jle    1400041c6 <__pformat_emit_float+0x67>
   1400041b5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041b9:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041bc:	8d 50 ff             	lea    edx,[rax-0x1]
   1400041bf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041c3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400041c6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041ca:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041cd:	85 c0                	test   eax,eax
   1400041cf:	78 2b                	js     1400041fc <__pformat_emit_float+0x9d>
   1400041d1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041d5:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400041d8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041dc:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400041df:	39 c2                	cmp    edx,eax
   1400041e1:	7e 19                	jle    1400041fc <__pformat_emit_float+0x9d>
   1400041e3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041e7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400041ea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041ee:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400041f1:	29 c2                	sub    edx,eax
   1400041f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041f7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400041fa:	eb 0b                	jmp    140004207 <__pformat_emit_float+0xa8>
   1400041fc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004200:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004207:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000420b:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000420e:	85 c0                	test   eax,eax
   140004210:	7e 2c                	jle    14000423e <__pformat_emit_float+0xdf>
   140004212:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004216:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004219:	85 c0                	test   eax,eax
   14000421b:	7f 10                	jg     14000422d <__pformat_emit_float+0xce>
   14000421d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004221:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004224:	25 00 08 00 00       	and    eax,0x800
   140004229:	85 c0                	test   eax,eax
   14000422b:	74 11                	je     14000423e <__pformat_emit_float+0xdf>
   14000422d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004231:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004234:	8d 50 ff             	lea    edx,[rax-0x1]
   140004237:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000423b:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000423e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004242:	7e 64                	jle    1400042a8 <__pformat_emit_float+0x149>
   140004244:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004248:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000424b:	25 00 10 00 00       	and    eax,0x1000
   140004250:	85 c0                	test   eax,eax
   140004252:	74 54                	je     1400042a8 <__pformat_emit_float+0x149>
   140004254:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004258:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   14000425c:	66 85 c0             	test   ax,ax
   14000425f:	74 47                	je     1400042a8 <__pformat_emit_float+0x149>
   140004261:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004264:	83 c0 02             	add    eax,0x2
   140004267:	48 63 d0             	movsxd rdx,eax
   14000426a:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   140004271:	48 c1 ea 20          	shr    rdx,0x20
   140004275:	c1 f8 1f             	sar    eax,0x1f
   140004278:	29 c2                	sub    edx,eax
   14000427a:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000427d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004280:	eb 15                	jmp    140004297 <__pformat_emit_float+0x138>
   140004282:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004286:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000428a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000428d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004290:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004294:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004297:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000429b:	7e 0b                	jle    1400042a8 <__pformat_emit_float+0x149>
   14000429d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042a4:	85 c0                	test   eax,eax
   1400042a6:	7f da                	jg     140004282 <__pformat_emit_float+0x123>
   1400042a8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042ac:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042af:	85 c0                	test   eax,eax
   1400042b1:	7e 27                	jle    1400042da <__pformat_emit_float+0x17b>
   1400042b3:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400042b7:	75 10                	jne    1400042c9 <__pformat_emit_float+0x16a>
   1400042b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042bd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042c0:	25 c0 01 00 00       	and    eax,0x1c0
   1400042c5:	85 c0                	test   eax,eax
   1400042c7:	74 11                	je     1400042da <__pformat_emit_float+0x17b>
   1400042c9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042cd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042d0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042d7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042da:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042de:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042e1:	85 c0                	test   eax,eax
   1400042e3:	7e 38                	jle    14000431d <__pformat_emit_float+0x1be>
   1400042e5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042e9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042ec:	25 00 06 00 00       	and    eax,0x600
   1400042f1:	85 c0                	test   eax,eax
   1400042f3:	75 28                	jne    14000431d <__pformat_emit_float+0x1be>
   1400042f5:	eb 11                	jmp    140004308 <__pformat_emit_float+0x1a9>
   1400042f7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042fb:	48 89 c2             	mov    rdx,rax
   1400042fe:	b9 20 00 00 00       	mov    ecx,0x20
   140004303:	e8 78 ee ff ff       	call   140003180 <__pformat_putc>
   140004308:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000430c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000430f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004312:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004316:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004319:	85 c0                	test   eax,eax
   14000431b:	7f da                	jg     1400042f7 <__pformat_emit_float+0x198>
   14000431d:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004321:	74 13                	je     140004336 <__pformat_emit_float+0x1d7>
   140004323:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004327:	48 89 c2             	mov    rdx,rax
   14000432a:	b9 2d 00 00 00       	mov    ecx,0x2d
   14000432f:	e8 4c ee ff ff       	call   140003180 <__pformat_putc>
   140004334:	eb 42                	jmp    140004378 <__pformat_emit_float+0x219>
   140004336:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000433a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000433d:	25 00 01 00 00       	and    eax,0x100
   140004342:	85 c0                	test   eax,eax
   140004344:	74 13                	je     140004359 <__pformat_emit_float+0x1fa>
   140004346:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000434a:	48 89 c2             	mov    rdx,rax
   14000434d:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004352:	e8 29 ee ff ff       	call   140003180 <__pformat_putc>
   140004357:	eb 1f                	jmp    140004378 <__pformat_emit_float+0x219>
   140004359:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000435d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004360:	83 e0 40             	and    eax,0x40
   140004363:	85 c0                	test   eax,eax
   140004365:	74 11                	je     140004378 <__pformat_emit_float+0x219>
   140004367:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000436b:	48 89 c2             	mov    rdx,rax
   14000436e:	b9 20 00 00 00       	mov    ecx,0x20
   140004373:	e8 08 ee ff ff       	call   140003180 <__pformat_putc>
   140004378:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000437c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000437f:	85 c0                	test   eax,eax
   140004381:	7e 3b                	jle    1400043be <__pformat_emit_float+0x25f>
   140004383:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004387:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000438a:	25 00 06 00 00       	and    eax,0x600
   14000438f:	3d 00 02 00 00       	cmp    eax,0x200
   140004394:	75 28                	jne    1400043be <__pformat_emit_float+0x25f>
   140004396:	eb 11                	jmp    1400043a9 <__pformat_emit_float+0x24a>
   140004398:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000439c:	48 89 c2             	mov    rdx,rax
   14000439f:	b9 30 00 00 00       	mov    ecx,0x30
   1400043a4:	e8 d7 ed ff ff       	call   140003180 <__pformat_putc>
   1400043a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ad:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043b0:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400043b3:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400043b7:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400043ba:	85 c0                	test   eax,eax
   1400043bc:	7f da                	jg     140004398 <__pformat_emit_float+0x239>
   1400043be:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400043c2:	0f 8e a7 00 00 00    	jle    14000446f <__pformat_emit_float+0x310>
   1400043c8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400043cc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400043cf:	84 c0                	test   al,al
   1400043d1:	74 14                	je     1400043e7 <__pformat_emit_float+0x288>
   1400043d3:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400043d7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400043db:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400043df:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400043e2:	0f be c0             	movsx  eax,al
   1400043e5:	eb 05                	jmp    1400043ec <__pformat_emit_float+0x28d>
   1400043e7:	b8 30 00 00 00       	mov    eax,0x30
   1400043ec:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400043f0:	89 c1                	mov    ecx,eax
   1400043f2:	e8 89 ed ff ff       	call   140003180 <__pformat_putc>
   1400043f7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400043fb:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400043ff:	74 62                	je     140004463 <__pformat_emit_float+0x304>
   140004401:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004405:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004408:	25 00 10 00 00       	and    eax,0x1000
   14000440d:	85 c0                	test   eax,eax
   14000440f:	74 52                	je     140004463 <__pformat_emit_float+0x304>
   140004411:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004415:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004419:	66 85 c0             	test   ax,ax
   14000441c:	74 45                	je     140004463 <__pformat_emit_float+0x304>
   14000441e:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   140004421:	48 63 c1             	movsxd rax,ecx
   140004424:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   14000442b:	48 c1 e8 20          	shr    rax,0x20
   14000442f:	48 89 c2             	mov    rdx,rax
   140004432:	89 c8                	mov    eax,ecx
   140004434:	c1 f8 1f             	sar    eax,0x1f
   140004437:	29 c2                	sub    edx,eax
   140004439:	89 d0                	mov    eax,edx
   14000443b:	01 c0                	add    eax,eax
   14000443d:	01 d0                	add    eax,edx
   14000443f:	29 c1                	sub    ecx,eax
   140004441:	89 ca                	mov    edx,ecx
   140004443:	85 d2                	test   edx,edx
   140004445:	75 1c                	jne    140004463 <__pformat_emit_float+0x304>
   140004447:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000444b:	48 83 c0 20          	add    rax,0x20
   14000444f:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004453:	49 89 d0             	mov    r8,rdx
   140004456:	ba 01 00 00 00       	mov    edx,0x1
   14000445b:	48 89 c1             	mov    rcx,rax
   14000445e:	e8 26 ef ff ff       	call   140003389 <__pformat_wputchars>
   140004463:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004467:	0f 8f 5b ff ff ff    	jg     1400043c8 <__pformat_emit_float+0x269>
   14000446d:	eb 11                	jmp    140004480 <__pformat_emit_float+0x321>
   14000446f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004473:	48 89 c2             	mov    rdx,rax
   140004476:	b9 30 00 00 00       	mov    ecx,0x30
   14000447b:	e8 00 ed ff ff       	call   140003180 <__pformat_putc>
   140004480:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004484:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004487:	85 c0                	test   eax,eax
   140004489:	7f 10                	jg     14000449b <__pformat_emit_float+0x33c>
   14000448b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000448f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004492:	25 00 08 00 00       	and    eax,0x800
   140004497:	85 c0                	test   eax,eax
   140004499:	74 0c                	je     1400044a7 <__pformat_emit_float+0x348>
   14000449b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000449f:	48 89 c1             	mov    rcx,rax
   1400044a2:	e8 1b fa ff ff       	call   140003ec2 <__pformat_emit_radix_point>
   1400044a7:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044ab:	79 5f                	jns    14000450c <__pformat_emit_float+0x3ad>
   1400044ad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044b1:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400044b4:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400044b7:	01 c2                	add    edx,eax
   1400044b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044bd:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400044c0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044c4:	48 89 c2             	mov    rdx,rax
   1400044c7:	b9 30 00 00 00       	mov    ecx,0x30
   1400044cc:	e8 af ec ff ff       	call   140003180 <__pformat_putc>
   1400044d1:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   1400044d5:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044d9:	78 e5                	js     1400044c0 <__pformat_emit_float+0x361>
   1400044db:	eb 2f                	jmp    14000450c <__pformat_emit_float+0x3ad>
   1400044dd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044e1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044e4:	84 c0                	test   al,al
   1400044e6:	74 14                	je     1400044fc <__pformat_emit_float+0x39d>
   1400044e8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044ec:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400044f0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400044f4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044f7:	0f be c0             	movsx  eax,al
   1400044fa:	eb 05                	jmp    140004501 <__pformat_emit_float+0x3a2>
   1400044fc:	b8 30 00 00 00       	mov    eax,0x30
   140004501:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004505:	89 c1                	mov    ecx,eax
   140004507:	e8 74 ec ff ff       	call   140003180 <__pformat_putc>
   14000450c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004510:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004513:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004516:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000451a:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   14000451d:	85 c0                	test   eax,eax
   14000451f:	7f bc                	jg     1400044dd <__pformat_emit_float+0x37e>
   140004521:	90                   	nop
   140004522:	90                   	nop
   140004523:	48 83 c4 30          	add    rsp,0x30
   140004527:	5d                   	pop    rbp
   140004528:	c3                   	ret

0000000140004529 <__pformat_emit_efloat>:
   140004529:	55                   	push   rbp
   14000452a:	48 89 e5             	mov    rbp,rsp
   14000452d:	48 83 ec 50          	sub    rsp,0x50
   140004531:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004534:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004538:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   14000453c:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004540:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140004547:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000454b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000454f:	79 09                	jns    14000455a <__pformat_emit_efloat+0x31>
   140004551:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004558:	eb 05                	jmp    14000455f <__pformat_emit_efloat+0x36>
   14000455a:	b8 00 00 00 00       	mov    eax,0x0
   14000455f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140004563:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004566:	48 98                	cdqe
   140004568:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000456c:	eb 04                	jmp    140004572 <__pformat_emit_efloat+0x49>
   14000456e:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140004572:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004575:	48 63 d0             	movsxd rdx,eax
   140004578:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   14000457f:	48 c1 ea 20          	shr    rdx,0x20
   140004583:	89 d1                	mov    ecx,edx
   140004585:	c1 f9 02             	sar    ecx,0x2
   140004588:	99                   	cdq
   140004589:	89 c8                	mov    eax,ecx
   14000458b:	29 d0                	sub    eax,edx
   14000458d:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004590:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004594:	75 d8                	jne    14000456e <__pformat_emit_efloat+0x45>
   140004596:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000459a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000459d:	83 f8 ff             	cmp    eax,0xffffffff
   1400045a0:	75 0b                	jne    1400045ad <__pformat_emit_efloat+0x84>
   1400045a2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045a6:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   1400045ad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045b1:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   1400045b4:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   1400045b7:	7d 0a                	jge    1400045c3 <__pformat_emit_efloat+0x9a>
   1400045b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045bd:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   1400045c0:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400045c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045c7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400045ca:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400045ce:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   1400045d1:	7d 15                	jge    1400045e8 <__pformat_emit_efloat+0xbf>
   1400045d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045d7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400045da:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   1400045dd:	89 c2                	mov    edx,eax
   1400045df:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045e3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400045e6:	eb 0b                	jmp    1400045f3 <__pformat_emit_efloat+0xca>
   1400045e8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045ec:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400045f3:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400045f7:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400045fb:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400045fe:	49 89 c9             	mov    r9,rcx
   140004601:	41 b8 01 00 00 00    	mov    r8d,0x1
   140004607:	89 c1                	mov    ecx,eax
   140004609:	e8 51 fb ff ff       	call   14000415f <__pformat_emit_float>
   14000460e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004612:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   140004615:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004619:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000461c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004620:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004623:	0d c0 01 00 00       	or     eax,0x1c0
   140004628:	89 c2                	mov    edx,eax
   14000462a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000462e:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004631:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004635:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004638:	83 e0 20             	and    eax,0x20
   14000463b:	83 c8 45             	or     eax,0x45
   14000463e:	89 c1                	mov    ecx,eax
   140004640:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004644:	48 89 c2             	mov    rdx,rax
   140004647:	e8 34 eb ff ff       	call   140003180 <__pformat_putc>
   14000464c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004650:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004653:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140004656:	83 ea 01             	sub    edx,0x1
   140004659:	01 c2                	add    edx,eax
   14000465b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000465f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004662:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004666:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   14000466a:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000466e:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140004672:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004676:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000467a:	48 89 c1             	mov    rcx,rax
   14000467d:	e8 69 ef ff ff       	call   1400035eb <__pformat_int>
   140004682:	90                   	nop
   140004683:	48 83 c4 50          	add    rsp,0x50
   140004687:	5d                   	pop    rbp
   140004688:	c3                   	ret

0000000140004689 <__pformat_float>:
   140004689:	55                   	push   rbp
   14000468a:	53                   	push   rbx
   14000468b:	48 83 ec 58          	sub    rsp,0x58
   14000468f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004694:	48 89 cb             	mov    rbx,rcx
   140004697:	db 2b                	fld    TBYTE PTR [rbx]
   140004699:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000469c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400046a0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046a4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400046a7:	85 c0                	test   eax,eax
   1400046a9:	79 0b                	jns    1400046b6 <__pformat_float+0x2d>
   1400046ab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046af:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400046b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046ba:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400046bd:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400046c0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400046c3:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400046c7:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400046cb:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400046cf:	4d 89 c1             	mov    r9,r8
   1400046d2:	49 89 c8             	mov    r8,rcx
   1400046d5:	48 89 c1             	mov    rcx,rax
   1400046d8:	e8 93 f7 ff ff       	call   140003e70 <__pformat_fcvt>
   1400046dd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400046e1:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400046e4:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400046e9:	75 17                	jne    140004702 <__pformat_float+0x79>
   1400046eb:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400046ee:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400046f2:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400046f6:	49 89 c8             	mov    r8,rcx
   1400046f9:	89 c1                	mov    ecx,eax
   1400046fb:	e8 74 f9 ff ff       	call   140004074 <__pformat_emit_inf_or_nan>
   140004700:	eb 43                	jmp    140004745 <__pformat_float+0xbc>
   140004702:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004705:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004708:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000470c:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004710:	4d 89 c1             	mov    r9,r8
   140004713:	41 89 c8             	mov    r8d,ecx
   140004716:	89 c1                	mov    ecx,eax
   140004718:	e8 42 fa ff ff       	call   14000415f <__pformat_emit_float>
   14000471d:	eb 11                	jmp    140004730 <__pformat_float+0xa7>
   14000471f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004723:	48 89 c2             	mov    rdx,rax
   140004726:	b9 20 00 00 00       	mov    ecx,0x20
   14000472b:	e8 50 ea ff ff       	call   140003180 <__pformat_putc>
   140004730:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004734:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004737:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000473a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000473e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004741:	85 c0                	test   eax,eax
   140004743:	7f da                	jg     14000471f <__pformat_float+0x96>
   140004745:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004749:	48 89 c1             	mov    rcx,rax
   14000474c:	e8 4e 17 00 00       	call   140005e9f <__freedtoa>
   140004751:	90                   	nop
   140004752:	48 83 c4 58          	add    rsp,0x58
   140004756:	5b                   	pop    rbx
   140004757:	5d                   	pop    rbp
   140004758:	c3                   	ret

0000000140004759 <__pformat_efloat>:
   140004759:	55                   	push   rbp
   14000475a:	53                   	push   rbx
   14000475b:	48 83 ec 58          	sub    rsp,0x58
   14000475f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004764:	48 89 cb             	mov    rbx,rcx
   140004767:	db 2b                	fld    TBYTE PTR [rbx]
   140004769:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000476c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004770:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004774:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004777:	85 c0                	test   eax,eax
   140004779:	79 0b                	jns    140004786 <__pformat_efloat+0x2d>
   14000477b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000477f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004786:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000478a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000478d:	8d 50 01             	lea    edx,[rax+0x1]
   140004790:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004793:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004796:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000479a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000479e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400047a2:	4d 89 c1             	mov    r9,r8
   1400047a5:	49 89 c8             	mov    r8,rcx
   1400047a8:	48 89 c1             	mov    rcx,rax
   1400047ab:	e8 6e f6 ff ff       	call   140003e1e <__pformat_ecvt>
   1400047b0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400047b4:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400047b7:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400047bc:	75 17                	jne    1400047d5 <__pformat_efloat+0x7c>
   1400047be:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047c1:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400047c5:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047c9:	49 89 c8             	mov    r8,rcx
   1400047cc:	89 c1                	mov    ecx,eax
   1400047ce:	e8 a1 f8 ff ff       	call   140004074 <__pformat_emit_inf_or_nan>
   1400047d3:	eb 1b                	jmp    1400047f0 <__pformat_efloat+0x97>
   1400047d5:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400047d8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047db:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400047df:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047e3:	4d 89 c1             	mov    r9,r8
   1400047e6:	41 89 c8             	mov    r8d,ecx
   1400047e9:	89 c1                	mov    ecx,eax
   1400047eb:	e8 39 fd ff ff       	call   140004529 <__pformat_emit_efloat>
   1400047f0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400047f4:	48 89 c1             	mov    rcx,rax
   1400047f7:	e8 a3 16 00 00       	call   140005e9f <__freedtoa>
   1400047fc:	90                   	nop
   1400047fd:	48 83 c4 58          	add    rsp,0x58
   140004801:	5b                   	pop    rbx
   140004802:	5d                   	pop    rbp
   140004803:	c3                   	ret

0000000140004804 <__pformat_gfloat>:
   140004804:	55                   	push   rbp
   140004805:	53                   	push   rbx
   140004806:	48 83 ec 58          	sub    rsp,0x58
   14000480a:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000480f:	48 89 cb             	mov    rbx,rcx
   140004812:	db 2b                	fld    TBYTE PTR [rbx]
   140004814:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140004817:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000481b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000481f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004822:	85 c0                	test   eax,eax
   140004824:	79 0d                	jns    140004833 <__pformat_gfloat+0x2f>
   140004826:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000482a:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004831:	eb 16                	jmp    140004849 <__pformat_gfloat+0x45>
   140004833:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004837:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000483a:	85 c0                	test   eax,eax
   14000483c:	75 0b                	jne    140004849 <__pformat_gfloat+0x45>
   14000483e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004842:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   140004849:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000484d:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004850:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004853:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004856:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000485a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000485e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004862:	4d 89 c1             	mov    r9,r8
   140004865:	49 89 c8             	mov    r8,rcx
   140004868:	48 89 c1             	mov    rcx,rax
   14000486b:	e8 ae f5 ff ff       	call   140003e1e <__pformat_ecvt>
   140004870:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004874:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004877:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000487c:	75 1a                	jne    140004898 <__pformat_gfloat+0x94>
   14000487e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004881:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004885:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004889:	49 89 c8             	mov    r8,rcx
   14000488c:	89 c1                	mov    ecx,eax
   14000488e:	e8 e1 f7 ff ff       	call   140004074 <__pformat_emit_inf_or_nan>
   140004893:	e9 14 01 00 00       	jmp    1400049ac <__pformat_gfloat+0x1a8>
   140004898:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000489b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000489e:	0f 8c b2 00 00 00    	jl     140004956 <__pformat_gfloat+0x152>
   1400048a4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048a8:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400048ab:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048ae:	39 c2                	cmp    edx,eax
   1400048b0:	0f 8c a0 00 00 00    	jl     140004956 <__pformat_gfloat+0x152>
   1400048b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048ba:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400048bd:	25 00 08 00 00       	and    eax,0x800
   1400048c2:	85 c0                	test   eax,eax
   1400048c4:	74 15                	je     1400048db <__pformat_gfloat+0xd7>
   1400048c6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048ca:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400048cd:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048d0:	29 c2                	sub    edx,eax
   1400048d2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048d6:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400048d9:	eb 20                	jmp    1400048fb <__pformat_gfloat+0xf7>
   1400048db:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400048df:	48 89 c1             	mov    rcx,rax
   1400048e2:	e8 89 4d 00 00       	call   140009670 <strlen>
   1400048e7:	89 c1                	mov    ecx,eax
   1400048e9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048ec:	89 c2                	mov    edx,eax
   1400048ee:	89 c8                	mov    eax,ecx
   1400048f0:	29 d0                	sub    eax,edx
   1400048f2:	89 c2                	mov    edx,eax
   1400048f4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048f8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400048fb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048ff:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004902:	85 c0                	test   eax,eax
   140004904:	79 0b                	jns    140004911 <__pformat_gfloat+0x10d>
   140004906:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000490a:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   140004911:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004914:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004917:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000491b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   14000491f:	4d 89 c1             	mov    r9,r8
   140004922:	41 89 c8             	mov    r8d,ecx
   140004925:	89 c1                	mov    ecx,eax
   140004927:	e8 33 f8 ff ff       	call   14000415f <__pformat_emit_float>
   14000492c:	eb 11                	jmp    14000493f <__pformat_gfloat+0x13b>
   14000492e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004932:	48 89 c2             	mov    rdx,rax
   140004935:	b9 20 00 00 00       	mov    ecx,0x20
   14000493a:	e8 41 e8 ff ff       	call   140003180 <__pformat_putc>
   14000493f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004943:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004946:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004949:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000494d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004950:	85 c0                	test   eax,eax
   140004952:	7f da                	jg     14000492e <__pformat_gfloat+0x12a>
   140004954:	eb 56                	jmp    1400049ac <__pformat_gfloat+0x1a8>
   140004956:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000495a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000495d:	25 00 08 00 00       	and    eax,0x800
   140004962:	85 c0                	test   eax,eax
   140004964:	74 13                	je     140004979 <__pformat_gfloat+0x175>
   140004966:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000496a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000496d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004970:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004974:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004977:	eb 18                	jmp    140004991 <__pformat_gfloat+0x18d>
   140004979:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000497d:	48 89 c1             	mov    rcx,rax
   140004980:	e8 eb 4c 00 00       	call   140009670 <strlen>
   140004985:	83 e8 01             	sub    eax,0x1
   140004988:	89 c2                	mov    edx,eax
   14000498a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000498e:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004991:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004994:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004997:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000499b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   14000499f:	4d 89 c1             	mov    r9,r8
   1400049a2:	41 89 c8             	mov    r8d,ecx
   1400049a5:	89 c1                	mov    ecx,eax
   1400049a7:	e8 7d fb ff ff       	call   140004529 <__pformat_emit_efloat>
   1400049ac:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400049b0:	48 89 c1             	mov    rcx,rax
   1400049b3:	e8 e7 14 00 00       	call   140005e9f <__freedtoa>
   1400049b8:	90                   	nop
   1400049b9:	48 83 c4 58          	add    rsp,0x58
   1400049bd:	5b                   	pop    rbx
   1400049be:	5d                   	pop    rbp
   1400049bf:	c3                   	ret

00000001400049c0 <__pformat_emit_xfloat>:
   1400049c0:	55                   	push   rbp
   1400049c1:	53                   	push   rbx
   1400049c2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   1400049c9:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   1400049d0:	00 
   1400049d1:	48 89 cb             	mov    rbx,rcx
   1400049d4:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400049d8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   1400049dc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400049e0:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   1400049e6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   1400049e9:	48 85 c0             	test   rax,rax
   1400049ec:	75 09                	jne    1400049f7 <__pformat_emit_xfloat+0x37>
   1400049ee:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   1400049f2:	66 85 c0             	test   ax,ax
   1400049f5:	74 0b                	je     140004a02 <__pformat_emit_xfloat+0x42>
   1400049f7:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   1400049fb:	83 e8 03             	sub    eax,0x3
   1400049fe:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004a02:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a06:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a09:	85 c0                	test   eax,eax
   140004a0b:	0f 88 90 00 00 00    	js     140004aa1 <__pformat_emit_xfloat+0xe1>
   140004a11:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a15:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a18:	83 f8 0e             	cmp    eax,0xe
   140004a1b:	0f 8f 80 00 00 00    	jg     140004aa1 <__pformat_emit_xfloat+0xe1>
   140004a21:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a24:	48 d1 e8             	shr    rax,1
   140004a27:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a2a:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004a2d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a31:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a34:	b9 0e 00 00 00       	mov    ecx,0xe
   140004a39:	29 c1                	sub    ecx,eax
   140004a3b:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004a42:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004a48:	89 c1                	mov    ecx,eax
   140004a4a:	49 d3 e0             	shl    r8,cl
   140004a4d:	4c 89 c0             	mov    rax,r8
   140004a50:	48 01 d0             	add    rax,rdx
   140004a53:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a56:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a59:	48 85 c0             	test   rax,rax
   140004a5c:	78 0b                	js     140004a69 <__pformat_emit_xfloat+0xa9>
   140004a5e:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a61:	48 01 c0             	add    rax,rax
   140004a64:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a67:	eb 15                	jmp    140004a7e <__pformat_emit_xfloat+0xbe>
   140004a69:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a6d:	83 c0 04             	add    eax,0x4
   140004a70:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004a74:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a77:	48 c1 e8 03          	shr    rax,0x3
   140004a7b:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a7e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004a81:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a85:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a88:	b9 0f 00 00 00       	mov    ecx,0xf
   140004a8d:	29 c1                	sub    ecx,eax
   140004a8f:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004a96:	89 c1                	mov    ecx,eax
   140004a98:	48 d3 ea             	shr    rdx,cl
   140004a9b:	48 89 d0             	mov    rax,rdx
   140004a9e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004aa1:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004aa4:	48 85 c0             	test   rax,rax
   140004aa7:	75 0f                	jne    140004ab8 <__pformat_emit_xfloat+0xf8>
   140004aa9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004aad:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ab0:	85 c0                	test   eax,eax
   140004ab2:	0f 8e f8 00 00 00    	jle    140004bb0 <__pformat_emit_xfloat+0x1f0>
   140004ab8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004abc:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004abf:	83 f8 0e             	cmp    eax,0xe
   140004ac2:	7f 1a                	jg     140004ade <__pformat_emit_xfloat+0x11e>
   140004ac4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ac8:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004acb:	85 c0                	test   eax,eax
   140004acd:	78 0f                	js     140004ade <__pformat_emit_xfloat+0x11e>
   140004acf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ad3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ad6:	83 c0 01             	add    eax,0x1
   140004ad9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004adc:	eb 07                	jmp    140004ae5 <__pformat_emit_xfloat+0x125>
   140004ade:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004ae5:	e9 bc 00 00 00       	jmp    140004ba6 <__pformat_emit_xfloat+0x1e6>
   140004aea:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004aed:	83 e0 0f             	and    eax,0xf
   140004af0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004af3:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004af7:	75 36                	jne    140004b2f <__pformat_emit_xfloat+0x16f>
   140004af9:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004afd:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b01:	72 1b                	jb     140004b1e <__pformat_emit_xfloat+0x15e>
   140004b03:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b07:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b0a:	25 00 08 00 00       	and    eax,0x800
   140004b0f:	85 c0                	test   eax,eax
   140004b11:	75 0b                	jne    140004b1e <__pformat_emit_xfloat+0x15e>
   140004b13:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b17:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b1a:	85 c0                	test   eax,eax
   140004b1c:	7e 2d                	jle    140004b4b <__pformat_emit_xfloat+0x18b>
   140004b1e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004b22:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004b26:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004b2a:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004b2d:	eb 1c                	jmp    140004b4b <__pformat_emit_xfloat+0x18b>
   140004b2f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b33:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b36:	85 c0                	test   eax,eax
   140004b38:	7e 11                	jle    140004b4b <__pformat_emit_xfloat+0x18b>
   140004b3a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b3e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b41:	8d 50 ff             	lea    edx,[rax-0x1]
   140004b44:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b48:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004b4b:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004b4f:	75 15                	jne    140004b66 <__pformat_emit_xfloat+0x1a6>
   140004b51:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b55:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b59:	72 0b                	jb     140004b66 <__pformat_emit_xfloat+0x1a6>
   140004b5b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b5f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b62:	85 c0                	test   eax,eax
   140004b64:	78 32                	js     140004b98 <__pformat_emit_xfloat+0x1d8>
   140004b66:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004b6a:	76 16                	jbe    140004b82 <__pformat_emit_xfloat+0x1c2>
   140004b6c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004b6f:	8d 50 37             	lea    edx,[rax+0x37]
   140004b72:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b76:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b79:	83 e0 20             	and    eax,0x20
   140004b7c:	09 d0                	or     eax,edx
   140004b7e:	89 c1                	mov    ecx,eax
   140004b80:	eb 08                	jmp    140004b8a <__pformat_emit_xfloat+0x1ca>
   140004b82:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004b85:	83 c0 30             	add    eax,0x30
   140004b88:	89 c1                	mov    ecx,eax
   140004b8a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004b8e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004b92:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004b96:	88 08                	mov    BYTE PTR [rax],cl
   140004b98:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b9b:	48 c1 e8 04          	shr    rax,0x4
   140004b9f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004ba2:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004ba6:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004baa:	0f 8f 3a ff ff ff    	jg     140004aea <__pformat_emit_xfloat+0x12a>
   140004bb0:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004bb4:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004bb8:	75 39                	jne    140004bf3 <__pformat_emit_xfloat+0x233>
   140004bba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bbe:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bc1:	85 c0                	test   eax,eax
   140004bc3:	7f 10                	jg     140004bd5 <__pformat_emit_xfloat+0x215>
   140004bc5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bc9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004bcc:	25 00 08 00 00       	and    eax,0x800
   140004bd1:	85 c0                	test   eax,eax
   140004bd3:	74 0f                	je     140004be4 <__pformat_emit_xfloat+0x224>
   140004bd5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004bd9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004bdd:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004be1:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004be4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004be8:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004bec:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004bf0:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004bf3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bf7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004bfa:	85 c0                	test   eax,eax
   140004bfc:	0f 8e e3 00 00 00    	jle    140004ce5 <__pformat_emit_xfloat+0x325>
   140004c02:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c06:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004c0a:	48 29 c2             	sub    rdx,rax
   140004c0d:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004c10:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004c14:	98                   	cwde
   140004c15:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004c18:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c1c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c1f:	85 c0                	test   eax,eax
   140004c21:	7e 0a                	jle    140004c2d <__pformat_emit_xfloat+0x26d>
   140004c23:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c27:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c2a:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c2d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c31:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c34:	25 c0 01 00 00       	and    eax,0x1c0
   140004c39:	85 c0                	test   eax,eax
   140004c3b:	74 07                	je     140004c44 <__pformat_emit_xfloat+0x284>
   140004c3d:	b8 06 00 00 00       	mov    eax,0x6
   140004c42:	eb 05                	jmp    140004c49 <__pformat_emit_xfloat+0x289>
   140004c44:	b8 05 00 00 00       	mov    eax,0x5
   140004c49:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c4c:	eb 0f                	jmp    140004c5d <__pformat_emit_xfloat+0x29d>
   140004c4e:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004c52:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004c56:	83 c0 01             	add    eax,0x1
   140004c59:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004c5d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004c60:	48 63 d0             	movsxd rdx,eax
   140004c63:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004c6a:	48 c1 ea 20          	shr    rdx,0x20
   140004c6e:	89 d1                	mov    ecx,edx
   140004c70:	c1 f9 02             	sar    ecx,0x2
   140004c73:	99                   	cdq
   140004c74:	89 c8                	mov    eax,ecx
   140004c76:	29 d0                	sub    eax,edx
   140004c78:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004c7b:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004c7f:	75 cd                	jne    140004c4e <__pformat_emit_xfloat+0x28e>
   140004c81:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c85:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c88:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004c8b:	7d 4d                	jge    140004cda <__pformat_emit_xfloat+0x31a>
   140004c8d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c91:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c94:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004c97:	89 c2                	mov    edx,eax
   140004c99:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c9d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004ca0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ca4:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ca7:	25 00 06 00 00       	and    eax,0x600
   140004cac:	85 c0                	test   eax,eax
   140004cae:	75 35                	jne    140004ce5 <__pformat_emit_xfloat+0x325>
   140004cb0:	eb 11                	jmp    140004cc3 <__pformat_emit_xfloat+0x303>
   140004cb2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cb6:	48 89 c2             	mov    rdx,rax
   140004cb9:	b9 20 00 00 00       	mov    ecx,0x20
   140004cbe:	e8 bd e4 ff ff       	call   140003180 <__pformat_putc>
   140004cc3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cc7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004cca:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004ccd:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004cd1:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004cd4:	85 c0                	test   eax,eax
   140004cd6:	7f da                	jg     140004cb2 <__pformat_emit_xfloat+0x2f2>
   140004cd8:	eb 0b                	jmp    140004ce5 <__pformat_emit_xfloat+0x325>
   140004cda:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cde:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004ce5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ce9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cec:	25 80 00 00 00       	and    eax,0x80
   140004cf1:	85 c0                	test   eax,eax
   140004cf3:	74 13                	je     140004d08 <__pformat_emit_xfloat+0x348>
   140004cf5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cf9:	48 89 c2             	mov    rdx,rax
   140004cfc:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004d01:	e8 7a e4 ff ff       	call   140003180 <__pformat_putc>
   140004d06:	eb 42                	jmp    140004d4a <__pformat_emit_xfloat+0x38a>
   140004d08:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d0c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d0f:	25 00 01 00 00       	and    eax,0x100
   140004d14:	85 c0                	test   eax,eax
   140004d16:	74 13                	je     140004d2b <__pformat_emit_xfloat+0x36b>
   140004d18:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d1c:	48 89 c2             	mov    rdx,rax
   140004d1f:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004d24:	e8 57 e4 ff ff       	call   140003180 <__pformat_putc>
   140004d29:	eb 1f                	jmp    140004d4a <__pformat_emit_xfloat+0x38a>
   140004d2b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d2f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d32:	83 e0 40             	and    eax,0x40
   140004d35:	85 c0                	test   eax,eax
   140004d37:	74 11                	je     140004d4a <__pformat_emit_xfloat+0x38a>
   140004d39:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d3d:	48 89 c2             	mov    rdx,rax
   140004d40:	b9 20 00 00 00       	mov    ecx,0x20
   140004d45:	e8 36 e4 ff ff       	call   140003180 <__pformat_putc>
   140004d4a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d4e:	48 89 c2             	mov    rdx,rax
   140004d51:	b9 30 00 00 00       	mov    ecx,0x30
   140004d56:	e8 25 e4 ff ff       	call   140003180 <__pformat_putc>
   140004d5b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d5f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d62:	83 e0 20             	and    eax,0x20
   140004d65:	83 c8 58             	or     eax,0x58
   140004d68:	89 c1                	mov    ecx,eax
   140004d6a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d6e:	48 89 c2             	mov    rdx,rax
   140004d71:	e8 0a e4 ff ff       	call   140003180 <__pformat_putc>
   140004d76:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d7a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d7d:	85 c0                	test   eax,eax
   140004d7f:	7e 54                	jle    140004dd5 <__pformat_emit_xfloat+0x415>
   140004d81:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d85:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d88:	25 00 02 00 00       	and    eax,0x200
   140004d8d:	85 c0                	test   eax,eax
   140004d8f:	74 44                	je     140004dd5 <__pformat_emit_xfloat+0x415>
   140004d91:	eb 11                	jmp    140004da4 <__pformat_emit_xfloat+0x3e4>
   140004d93:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d97:	48 89 c2             	mov    rdx,rax
   140004d9a:	b9 30 00 00 00       	mov    ecx,0x30
   140004d9f:	e8 dc e3 ff ff       	call   140003180 <__pformat_putc>
   140004da4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004da8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004dab:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004dae:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004db2:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004db5:	85 c0                	test   eax,eax
   140004db7:	7f da                	jg     140004d93 <__pformat_emit_xfloat+0x3d3>
   140004db9:	eb 1a                	jmp    140004dd5 <__pformat_emit_xfloat+0x415>
   140004dbb:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004dc0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004dc4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004dc7:	0f be c0             	movsx  eax,al
   140004dca:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004dce:	89 c1                	mov    ecx,eax
   140004dd0:	e8 32 f2 ff ff       	call   140004007 <__pformat_emit_numeric_value>
   140004dd5:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004dd9:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004ddd:	72 dc                	jb     140004dbb <__pformat_emit_xfloat+0x3fb>
   140004ddf:	eb 11                	jmp    140004df2 <__pformat_emit_xfloat+0x432>
   140004de1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004de5:	48 89 c2             	mov    rdx,rax
   140004de8:	b9 30 00 00 00       	mov    ecx,0x30
   140004ded:	e8 8e e3 ff ff       	call   140003180 <__pformat_putc>
   140004df2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004df6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004df9:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004dfc:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e00:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004e03:	85 c0                	test   eax,eax
   140004e05:	7f da                	jg     140004de1 <__pformat_emit_xfloat+0x421>
   140004e07:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e0b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e0e:	83 e0 20             	and    eax,0x20
   140004e11:	83 c8 50             	or     eax,0x50
   140004e14:	89 c1                	mov    ecx,eax
   140004e16:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e1a:	48 89 c2             	mov    rdx,rax
   140004e1d:	e8 5e e3 ff ff       	call   140003180 <__pformat_putc>
   140004e22:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e26:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004e29:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004e2d:	01 c2                	add    edx,eax
   140004e2f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e33:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004e36:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e3a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e3d:	0d c0 01 00 00       	or     eax,0x1c0
   140004e42:	89 c2                	mov    edx,eax
   140004e44:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e48:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004e4b:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e4f:	66 85 c0             	test   ax,ax
   140004e52:	79 09                	jns    140004e5d <__pformat_emit_xfloat+0x49d>
   140004e54:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004e5b:	eb 05                	jmp    140004e62 <__pformat_emit_xfloat+0x4a2>
   140004e5d:	b8 00 00 00 00       	mov    eax,0x0
   140004e62:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004e66:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e6a:	48 0f bf c0          	movsx  rax,ax
   140004e6e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004e72:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004e76:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004e7a:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004e7e:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004e82:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e86:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004e8a:	48 89 c1             	mov    rcx,rax
   140004e8d:	e8 59 e7 ff ff       	call   1400035eb <__pformat_int>
   140004e92:	90                   	nop
   140004e93:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004e9a:	5b                   	pop    rbx
   140004e9b:	5d                   	pop    rbp
   140004e9c:	c3                   	ret

0000000140004e9d <__pformat_xldouble>:
   140004e9d:	55                   	push   rbp
   140004e9e:	53                   	push   rbx
   140004e9f:	48 83 ec 78          	sub    rsp,0x78
   140004ea3:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004ea8:	48 89 cb             	mov    rbx,rcx
   140004eab:	db 2b                	fld    TBYTE PTR [rbx]
   140004ead:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004eb0:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004eb4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004ebb:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004ebf:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004ec2:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004ec5:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004ec9:	48 89 c1             	mov    rcx,rax
   140004ecc:	e8 e5 ed ff ff       	call   140003cb6 <init_fpreg_ldouble>
   140004ed1:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004ed4:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004ed7:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004edb:	48 89 c1             	mov    rcx,rax
   140004ede:	e8 ed 3d 00 00       	call   140008cd0 <__isnanl>
   140004ee3:	85 c0                	test   eax,eax
   140004ee5:	74 1d                	je     140004f04 <__pformat_xldouble+0x67>
   140004ee7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004eea:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004eee:	48 8d 15 51 64 00 00 	lea    rdx,[rip+0x6451]        # 14000b346 <.rdata+0x16>
   140004ef5:	49 89 c8             	mov    r8,rcx
   140004ef8:	89 c1                	mov    ecx,eax
   140004efa:	e8 75 f1 ff ff       	call   140004074 <__pformat_emit_inf_or_nan>
   140004eff:	e9 aa 00 00 00       	jmp    140004fae <__pformat_xldouble+0x111>
   140004f04:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f08:	98                   	cwde
   140004f09:	25 00 80 00 00       	and    eax,0x8000
   140004f0e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004f11:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004f15:	74 12                	je     140004f29 <__pformat_xldouble+0x8c>
   140004f17:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f1b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004f1e:	0c 80                	or     al,0x80
   140004f20:	89 c2                	mov    edx,eax
   140004f22:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f26:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004f29:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f2c:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f2f:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f33:	48 89 c1             	mov    rcx,rax
   140004f36:	e8 a5 3c 00 00       	call   140008be0 <__fpclassifyl>
   140004f3b:	3d 00 05 00 00       	cmp    eax,0x500
   140004f40:	75 1a                	jne    140004f5c <__pformat_xldouble+0xbf>
   140004f42:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f45:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f49:	48 8d 15 fa 63 00 00 	lea    rdx,[rip+0x63fa]        # 14000b34a <.rdata+0x1a>
   140004f50:	49 89 c8             	mov    r8,rcx
   140004f53:	89 c1                	mov    ecx,eax
   140004f55:	e8 1a f1 ff ff       	call   140004074 <__pformat_emit_inf_or_nan>
   140004f5a:	eb 52                	jmp    140004fae <__pformat_xldouble+0x111>
   140004f5c:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f60:	66 25 ff 7f          	and    ax,0x7fff
   140004f64:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004f68:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f6c:	66 85 c0             	test   ax,ax
   140004f6f:	75 11                	jne    140004f82 <__pformat_xldouble+0xe5>
   140004f71:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004f75:	48 85 c0             	test   rax,rax
   140004f78:	74 14                	je     140004f8e <__pformat_xldouble+0xf1>
   140004f7a:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140004f80:	eb 0c                	jmp    140004f8e <__pformat_xldouble+0xf1>
   140004f82:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f86:	66 2d ff 3f          	sub    ax,0x3fff
   140004f8a:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004f8e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004f92:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140004f96:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004f9a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   140004f9e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004fa2:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140004fa6:	48 89 c1             	mov    rcx,rax
   140004fa9:	e8 12 fa ff ff       	call   1400049c0 <__pformat_emit_xfloat>
   140004fae:	90                   	nop
   140004faf:	48 83 c4 78          	add    rsp,0x78
   140004fb3:	5b                   	pop    rbx
   140004fb4:	5d                   	pop    rbp
   140004fb5:	c3                   	ret

0000000140004fb6 <__pformat_xdouble>:
   140004fb6:	55                   	push   rbp
   140004fb7:	48 89 e5             	mov    rbp,rsp
   140004fba:	48 83 ec 60          	sub    rsp,0x60
   140004fbe:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140004fc3:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004fc7:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004fce:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140004fd1:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004fd5:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004fd8:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   140004fdc:	48 89 c1             	mov    rcx,rax
   140004fdf:	e8 d2 ec ff ff       	call   140003cb6 <init_fpreg_ldouble>
   140004fe4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140004fe8:	66 48 0f 6e c0       	movq   xmm0,rax
   140004fed:	e8 7e 3c 00 00       	call   140008c70 <__isnan>
   140004ff2:	85 c0                	test   eax,eax
   140004ff4:	74 1d                	je     140005013 <__pformat_xdouble+0x5d>
   140004ff6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004ff9:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140004ffd:	48 8d 15 42 63 00 00 	lea    rdx,[rip+0x6342]        # 14000b346 <.rdata+0x16>
   140005004:	49 89 c8             	mov    r8,rcx
   140005007:	89 c1                	mov    ecx,eax
   140005009:	e8 66 f0 ff ff       	call   140004074 <__pformat_emit_inf_or_nan>
   14000500e:	e9 f9 00 00 00       	jmp    14000510c <__pformat_xdouble+0x156>
   140005013:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005017:	98                   	cwde
   140005018:	25 00 80 00 00       	and    eax,0x8000
   14000501d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005020:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005024:	74 12                	je     140005038 <__pformat_xdouble+0x82>
   140005026:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000502a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000502d:	0c 80                	or     al,0x80
   14000502f:	89 c2                	mov    edx,eax
   140005031:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005035:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005038:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000503c:	66 48 0f 6e c0       	movq   xmm0,rax
   140005041:	e8 1a 3b 00 00       	call   140008b60 <__fpclassify>
   140005046:	3d 00 05 00 00       	cmp    eax,0x500
   14000504b:	75 1d                	jne    14000506a <__pformat_xdouble+0xb4>
   14000504d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005050:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140005054:	48 8d 15 ef 62 00 00 	lea    rdx,[rip+0x62ef]        # 14000b34a <.rdata+0x1a>
   14000505b:	49 89 c8             	mov    r8,rcx
   14000505e:	89 c1                	mov    ecx,eax
   140005060:	e8 0f f0 ff ff       	call   140004074 <__pformat_emit_inf_or_nan>
   140005065:	e9 a2 00 00 00       	jmp    14000510c <__pformat_xdouble+0x156>
   14000506a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000506e:	66 25 ff 7f          	and    ax,0x7fff
   140005072:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005076:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000507a:	66 85 c0             	test   ax,ax
   14000507d:	74 3b                	je     1400050ba <__pformat_xdouble+0x104>
   14000507f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005083:	66 3d 00 3c          	cmp    ax,0x3c00
   140005087:	7f 31                	jg     1400050ba <__pformat_xdouble+0x104>
   140005089:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000508d:	98                   	cwde
   14000508e:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005093:	29 c2                	sub    edx,eax
   140005095:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005098:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000509c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000509f:	89 c1                	mov    ecx,eax
   1400050a1:	48 d3 ea             	shr    rdx,cl
   1400050a4:	48 89 d0             	mov    rax,rdx
   1400050a7:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400050ab:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050af:	89 c2                	mov    edx,eax
   1400050b1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400050b4:	01 d0                	add    eax,edx
   1400050b6:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400050ba:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050be:	66 85 c0             	test   ax,ax
   1400050c1:	75 11                	jne    1400050d4 <__pformat_xdouble+0x11e>
   1400050c3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050c7:	48 85 c0             	test   rax,rax
   1400050ca:	74 14                	je     1400050e0 <__pformat_xdouble+0x12a>
   1400050cc:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   1400050d2:	eb 0c                	jmp    1400050e0 <__pformat_xdouble+0x12a>
   1400050d4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050d8:	66 2d fc 3f          	sub    ax,0x3ffc
   1400050dc:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400050e0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050e4:	48 c1 e8 03          	shr    rax,0x3
   1400050e8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400050ec:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050f0:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400050f4:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400050f8:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400050fc:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140005100:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140005104:	48 89 c1             	mov    rcx,rax
   140005107:	e8 b4 f8 ff ff       	call   1400049c0 <__pformat_emit_xfloat>
   14000510c:	90                   	nop
   14000510d:	48 83 c4 60          	add    rsp,0x60
   140005111:	5d                   	pop    rbp
   140005112:	c3                   	ret

0000000140005113 <__mingw_pformat>:
   140005113:	55                   	push   rbp
   140005114:	48 89 e5             	mov    rbp,rsp
   140005117:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   14000511e:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005121:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005125:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005129:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   14000512d:	e8 a6 44 00 00       	call   1400095d8 <_errno>
   140005132:	8b 00                	mov    eax,DWORD PTR [rax]
   140005134:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140005137:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000513b:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   14000513f:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   140005146:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140005149:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000514c:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   140005153:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   14000515a:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   140005161:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   140005167:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   14000516e:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   140005174:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   14000517b:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   14000517e:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   140005181:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   140005188:	e9 27 0c 00 00       	jmp    140005db4 <__mingw_pformat+0xca1>
   14000518d:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005191:	0f 85 0f 0c 00 00    	jne    140005da6 <__mingw_pformat+0xc93>
   140005197:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000519e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400051a5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400051a9:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400051ad:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400051b1:	48 83 c0 0c          	add    rax,0xc
   1400051b5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400051b9:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400051bc:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400051bf:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400051c6:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400051c9:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400051cc:	e9 c4 0b 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   1400051d1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400051d5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400051d9:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400051dd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400051e0:	0f be c0             	movsx  eax,al
   1400051e3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400051e6:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400051ea:	0f 84 94 09 00 00    	je     140005b84 <__mingw_pformat+0xa71>
   1400051f0:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400051f4:	0f 8f 02 0b 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400051fa:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400051fe:	0f 84 eb 03 00 00    	je     1400055ef <__mingw_pformat+0x4dc>
   140005204:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   140005208:	0f 8f ee 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000520e:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   140005212:	0f 84 31 09 00 00    	je     140005b49 <__mingw_pformat+0xa36>
   140005218:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   14000521c:	0f 8f da 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005222:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005226:	0f 84 c3 03 00 00    	je     1400055ef <__mingw_pformat+0x4dc>
   14000522c:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005230:	0f 8f c6 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005236:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   14000523a:	0f 84 31 09 00 00    	je     140005b71 <__mingw_pformat+0xa5e>
   140005240:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   140005244:	0f 8f b2 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000524a:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   14000524e:	0f 84 31 03 00 00    	je     140005585 <__mingw_pformat+0x472>
   140005254:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   140005258:	0f 8f 9e 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000525e:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   140005262:	0f 84 28 05 00 00    	je     140005790 <__mingw_pformat+0x67d>
   140005268:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   14000526c:	0f 8f 8a 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005272:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005276:	0f 84 73 03 00 00    	je     1400055ef <__mingw_pformat+0x4dc>
   14000527c:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005280:	0f 8f 76 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005286:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   14000528a:	0f 84 4d 07 00 00    	je     1400059dd <__mingw_pformat+0x8ca>
   140005290:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005294:	0f 8f 62 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000529a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000529e:	0f 84 2d 03 00 00    	je     1400055d1 <__mingw_pformat+0x4be>
   1400052a4:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   1400052a8:	0f 8f 4e 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400052ae:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   1400052b2:	0f 84 65 08 00 00    	je     140005b1d <__mingw_pformat+0xa0a>
   1400052b8:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   1400052bc:	0f 8f 3a 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400052c2:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   1400052c6:	0f 84 db 07 00 00    	je     140005aa7 <__mingw_pformat+0x994>
   1400052cc:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   1400052d0:	0f 8f 26 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400052d6:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400052da:	0f 84 ee 03 00 00    	je     1400056ce <__mingw_pformat+0x5bb>
   1400052e0:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400052e4:	0f 8f 12 0a 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400052ea:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400052ee:	0f 84 87 07 00 00    	je     140005a7b <__mingw_pformat+0x968>
   1400052f4:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400052f8:	0f 8f fe 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400052fe:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   140005302:	0f 84 f3 05 00 00    	je     1400058fb <__mingw_pformat+0x7e8>
   140005308:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   14000530c:	0f 8f ea 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005312:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005316:	0f 84 61 05 00 00    	je     14000587d <__mingw_pformat+0x76a>
   14000531c:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005320:	0f 8f d6 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005326:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   14000532a:	0f 84 cf 04 00 00    	je     1400057ff <__mingw_pformat+0x6ec>
   140005330:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   140005334:	0f 8f c2 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000533a:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   14000533e:	0f 84 8a 03 00 00    	je     1400056ce <__mingw_pformat+0x5bb>
   140005344:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   140005348:	0f 8f ae 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000534e:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   140005352:	0f 84 b5 01 00 00    	je     14000550d <__mingw_pformat+0x3fa>
   140005358:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   14000535c:	0f 8f 9a 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005362:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005366:	0f 84 83 02 00 00    	je     1400055ef <__mingw_pformat+0x4dc>
   14000536c:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005370:	0f 8f 86 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005376:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   14000537a:	0f 84 f9 05 00 00    	je     140005979 <__mingw_pformat+0x866>
   140005380:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   140005384:	0f 8f 72 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000538a:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   14000538e:	0f 84 5b 02 00 00    	je     1400055ef <__mingw_pformat+0x4dc>
   140005394:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005398:	0f 8f 5e 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000539e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   1400053a2:	0f 84 d6 01 00 00    	je     14000557e <__mingw_pformat+0x46b>
   1400053a8:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   1400053ac:	0f 8f 4a 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400053b2:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   1400053b6:	0f 84 a0 07 00 00    	je     140005b5c <__mingw_pformat+0xa49>
   1400053bc:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   1400053c0:	0f 8f 36 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400053c6:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   1400053ca:	0f 84 ea 06 00 00    	je     140005aba <__mingw_pformat+0x9a7>
   1400053d0:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   1400053d4:	0f 8f 22 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400053da:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400053de:	0f 84 20 05 00 00    	je     140005904 <__mingw_pformat+0x7f1>
   1400053e4:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400053e8:	0f 8f 0e 09 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400053ee:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400053f2:	0f 84 8e 04 00 00    	je     140005886 <__mingw_pformat+0x773>
   1400053f8:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400053fc:	0f 8f fa 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005402:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005406:	0f 84 fc 03 00 00    	je     140005808 <__mingw_pformat+0x6f5>
   14000540c:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005410:	0f 8f e6 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005416:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   14000541a:	0f 84 e6 00 00 00    	je     140005506 <__mingw_pformat+0x3f3>
   140005420:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   140005424:	0f 8f d2 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000542a:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   14000542e:	0f 84 bb 01 00 00    	je     1400055ef <__mingw_pformat+0x4dc>
   140005434:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   140005438:	0f 8f be 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000543e:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   140005442:	0f 84 3a 05 00 00    	je     140005982 <__mingw_pformat+0x86f>
   140005448:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   14000544c:	0f 8f aa 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005452:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005456:	0f 84 8c 08 00 00    	je     140005ce8 <__mingw_pformat+0xbd5>
   14000545c:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005460:	0f 8f 96 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   140005466:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   14000546a:	0f 84 27 07 00 00    	je     140005b97 <__mingw_pformat+0xa84>
   140005470:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   140005474:	0f 8f 82 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000547a:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   14000547e:	0f 84 db 07 00 00    	je     140005c5f <__mingw_pformat+0xb4c>
   140005484:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   140005488:	0f 8f 6e 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   14000548e:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005492:	0f 84 af 07 00 00    	je     140005c47 <__mingw_pformat+0xb34>
   140005498:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000549c:	0f 8f 5a 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400054a2:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   1400054a6:	0f 84 1c 07 00 00    	je     140005bc8 <__mingw_pformat+0xab5>
   1400054ac:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   1400054b0:	0f 8f 46 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400054b6:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   1400054ba:	0f 84 b7 07 00 00    	je     140005c77 <__mingw_pformat+0xb64>
   1400054c0:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   1400054c4:	0f 8f 32 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400054ca:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400054ce:	74 23                	je     1400054f3 <__mingw_pformat+0x3e0>
   1400054d0:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400054d4:	0f 8f 22 08 00 00    	jg     140005cfc <__mingw_pformat+0xbe9>
   1400054da:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   1400054de:	0f 84 ec 07 00 00    	je     140005cd0 <__mingw_pformat+0xbbd>
   1400054e4:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   1400054e8:	0f 84 41 07 00 00    	je     140005c2f <__mingw_pformat+0xb1c>
   1400054ee:	e9 09 08 00 00       	jmp    140005cfc <__mingw_pformat+0xbe9>
   1400054f3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400054f7:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400054fa:	89 c1                	mov    ecx,eax
   1400054fc:	e8 7f dc ff ff       	call   140003180 <__pformat_putc>
   140005501:	e9 82 fc ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   140005506:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   14000550d:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005514:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005518:	74 06                	je     140005520 <__mingw_pformat+0x40d>
   14000551a:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000551e:	75 30                	jne    140005550 <__mingw_pformat+0x43d>
   140005520:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005524:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005528:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000552c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000552e:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   140005532:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005536:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   14000553a:	49 89 d0             	mov    r8,rdx
   14000553d:	ba 01 00 00 00       	mov    edx,0x1
   140005542:	48 89 c1             	mov    rcx,rax
   140005545:	e8 3f de ff ff       	call   140003389 <__pformat_wputchars>
   14000554a:	90                   	nop
   14000554b:	e9 38 fc ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   140005550:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005554:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005558:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000555c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000555e:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   140005561:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005565:	48 8d 45 90          	lea    rax,[rbp-0x70]
   140005569:	49 89 d0             	mov    r8,rdx
   14000556c:	ba 01 00 00 00       	mov    edx,0x1
   140005571:	48 89 c1             	mov    rcx,rax
   140005574:	e8 8b dc ff ff       	call   140003204 <__pformat_putchars>
   140005579:	e9 0a fc ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   14000557e:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005585:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005589:	74 06                	je     140005591 <__mingw_pformat+0x47e>
   14000558b:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000558f:	75 20                	jne    1400055b1 <__mingw_pformat+0x49e>
   140005591:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005595:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005599:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000559d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400055a0:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055a4:	48 89 c1             	mov    rcx,rax
   1400055a7:	e8 29 df ff ff       	call   1400034d5 <__pformat_wcputs>
   1400055ac:	e9 d7 fb ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   1400055b1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055b5:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055b9:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055bd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400055c0:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055c4:	48 89 c1             	mov    rcx,rax
   1400055c7:	e8 37 dd ff ff       	call   140003303 <__pformat_puts>
   1400055cc:	e9 b7 fb ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   1400055d1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400055d4:	89 c1                	mov    ecx,eax
   1400055d6:	e8 8d 40 00 00       	call   140009668 <strerror>
   1400055db:	48 89 c1             	mov    rcx,rax
   1400055de:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400055e2:	48 89 c2             	mov    rdx,rax
   1400055e5:	e8 19 dd ff ff       	call   140003303 <__pformat_puts>
   1400055ea:	e9 99 fb ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   1400055ef:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400055f2:	80 e4 fe             	and    ah,0xfe
   1400055f5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400055f8:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055fc:	75 15                	jne    140005613 <__mingw_pformat+0x500>
   1400055fe:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005602:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005606:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000560a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000560d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005611:	eb 54                	jmp    140005667 <__mingw_pformat+0x554>
   140005613:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005617:	75 16                	jne    14000562f <__mingw_pformat+0x51c>
   140005619:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000561d:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005621:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005625:	8b 00                	mov    eax,DWORD PTR [rax]
   140005627:	89 c0                	mov    eax,eax
   140005629:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000562d:	eb 38                	jmp    140005667 <__mingw_pformat+0x554>
   14000562f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005633:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005637:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000563b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000563d:	89 c0                	mov    eax,eax
   14000563f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005643:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005647:	75 0d                	jne    140005656 <__mingw_pformat+0x543>
   140005649:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000564d:	0f b7 c0             	movzx  eax,ax
   140005650:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005654:	eb 11                	jmp    140005667 <__mingw_pformat+0x554>
   140005656:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   14000565a:	75 0b                	jne    140005667 <__mingw_pformat+0x554>
   14000565c:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   140005660:	0f b6 c0             	movzx  eax,al
   140005663:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005667:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   14000566b:	75 2e                	jne    14000569b <__mingw_pformat+0x588>
   14000566d:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005671:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005675:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000567c:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005683:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005687:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000568e:	48 89 c1             	mov    rcx,rax
   140005691:	e8 55 df ff ff       	call   1400035eb <__pformat_int>
   140005696:	e9 ed fa ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   14000569b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000569f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400056a3:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400056aa:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400056b1:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   1400056b5:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   1400056bc:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400056bf:	49 89 c8             	mov    r8,rcx
   1400056c2:	89 c1                	mov    ecx,eax
   1400056c4:	e8 a5 e2 ff ff       	call   14000396e <__pformat_xint>
   1400056c9:	e9 ba fa ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   1400056ce:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400056d1:	0c 80                	or     al,0x80
   1400056d3:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400056d6:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400056da:	75 15                	jne    1400056f1 <__mingw_pformat+0x5de>
   1400056dc:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056e0:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056e4:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056e8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400056eb:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056ef:	eb 56                	jmp    140005747 <__mingw_pformat+0x634>
   1400056f1:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400056f5:	75 16                	jne    14000570d <__mingw_pformat+0x5fa>
   1400056f7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056fb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056ff:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005703:	8b 00                	mov    eax,DWORD PTR [rax]
   140005705:	48 98                	cdqe
   140005707:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000570b:	eb 3a                	jmp    140005747 <__mingw_pformat+0x634>
   14000570d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005711:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005715:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005719:	8b 00                	mov    eax,DWORD PTR [rax]
   14000571b:	48 98                	cdqe
   14000571d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005721:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005725:	75 0e                	jne    140005735 <__mingw_pformat+0x622>
   140005727:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000572b:	48 0f bf c0          	movsx  rax,ax
   14000572f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005733:	eb 12                	jmp    140005747 <__mingw_pformat+0x634>
   140005735:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005739:	75 0c                	jne    140005747 <__mingw_pformat+0x634>
   14000573b:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   14000573f:	48 0f be c0          	movsx  rax,al
   140005743:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005747:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000574b:	48 85 c0             	test   rax,rax
   14000574e:	79 09                	jns    140005759 <__mingw_pformat+0x646>
   140005750:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140005757:	eb 05                	jmp    14000575e <__mingw_pformat+0x64b>
   140005759:	b8 00 00 00 00       	mov    eax,0x0
   14000575e:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140005762:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005766:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   14000576a:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005771:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005778:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000577c:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   140005783:	48 89 c1             	mov    rcx,rax
   140005786:	e8 60 de ff ff       	call   1400035eb <__pformat_int>
   14000578b:	e9 f8 f9 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   140005790:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005794:	75 18                	jne    1400057ae <__mingw_pformat+0x69b>
   140005796:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005799:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000579c:	75 10                	jne    1400057ae <__mingw_pformat+0x69b>
   14000579e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057a1:	80 cc 02             	or     ah,0x2
   1400057a4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400057a7:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   1400057ae:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057b2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057b6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057ba:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400057bd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057c1:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   1400057c8:	00 
   1400057c9:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057cd:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400057d1:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400057d8:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400057df:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400057e3:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400057ea:	49 89 d0             	mov    r8,rdx
   1400057ed:	48 89 c2             	mov    rdx,rax
   1400057f0:	b9 78 00 00 00       	mov    ecx,0x78
   1400057f5:	e8 74 e1 ff ff       	call   14000396e <__pformat_xint>
   1400057fa:	e9 89 f9 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   1400057ff:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005802:	83 c8 20             	or     eax,0x20
   140005805:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005808:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000580b:	83 e0 04             	and    eax,0x4
   14000580e:	85 c0                	test   eax,eax
   140005810:	74 2f                	je     140005841 <__mingw_pformat+0x72e>
   140005812:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005816:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000581a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000581e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005821:	db 28                	fld    TBYTE PTR [rax]
   140005823:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005829:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000582d:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005834:	48 89 c1             	mov    rcx,rax
   140005837:	e8 1d ef ff ff       	call   140004759 <__pformat_efloat>
   14000583c:	e9 47 f9 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   140005841:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005845:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005849:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000584d:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   140005851:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   140005858:	ff 
   140005859:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000585f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005865:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005869:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005870:	48 89 c1             	mov    rcx,rax
   140005873:	e8 e1 ee ff ff       	call   140004759 <__pformat_efloat>
   140005878:	e9 0b f9 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   14000587d:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005880:	83 c8 20             	or     eax,0x20
   140005883:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005886:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005889:	83 e0 04             	and    eax,0x4
   14000588c:	85 c0                	test   eax,eax
   14000588e:	74 2f                	je     1400058bf <__mingw_pformat+0x7ac>
   140005890:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005894:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005898:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000589c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000589f:	db 28                	fld    TBYTE PTR [rax]
   1400058a1:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058a7:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058ab:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058b2:	48 89 c1             	mov    rcx,rax
   1400058b5:	e8 cf ed ff ff       	call   140004689 <__pformat_float>
   1400058ba:	e9 c9 f8 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   1400058bf:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058c3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058c7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058cb:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   1400058cf:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   1400058d6:	ff 
   1400058d7:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400058dd:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058e3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058e7:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058ee:	48 89 c1             	mov    rcx,rax
   1400058f1:	e8 93 ed ff ff       	call   140004689 <__pformat_float>
   1400058f6:	e9 8d f8 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   1400058fb:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058fe:	83 c8 20             	or     eax,0x20
   140005901:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005904:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005907:	83 e0 04             	and    eax,0x4
   14000590a:	85 c0                	test   eax,eax
   14000590c:	74 2f                	je     14000593d <__mingw_pformat+0x82a>
   14000590e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005912:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005916:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000591a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000591d:	db 28                	fld    TBYTE PTR [rax]
   14000591f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005925:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005929:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005930:	48 89 c1             	mov    rcx,rax
   140005933:	e8 cc ee ff ff       	call   140004804 <__pformat_gfloat>
   140005938:	e9 4b f8 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   14000593d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005941:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005945:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005949:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   14000594d:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   140005954:	ff 
   140005955:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000595b:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005961:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005965:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000596c:	48 89 c1             	mov    rcx,rax
   14000596f:	e8 90 ee ff ff       	call   140004804 <__pformat_gfloat>
   140005974:	e9 0f f8 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   140005979:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000597c:	83 c8 20             	or     eax,0x20
   14000597f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005982:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005985:	83 e0 04             	and    eax,0x4
   140005988:	85 c0                	test   eax,eax
   14000598a:	74 2f                	je     1400059bb <__mingw_pformat+0x8a8>
   14000598c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005990:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005994:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005998:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000599b:	db 28                	fld    TBYTE PTR [rax]
   14000599d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059a3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059a7:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059ae:	48 89 c1             	mov    rcx,rax
   1400059b1:	e8 e7 f4 ff ff       	call   140004e9d <__pformat_xldouble>
   1400059b6:	e9 cd f7 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   1400059bb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059bf:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059c3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059c7:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059ca:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059ce:	66 48 0f 6e c0       	movq   xmm0,rax
   1400059d3:	e8 de f5 ff ff       	call   140004fb6 <__pformat_xdouble>
   1400059d8:	e9 ab f7 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   1400059dd:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400059e1:	75 1b                	jne    1400059fe <__mingw_pformat+0x8eb>
   1400059e3:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   1400059e6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059ea:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059ee:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059f2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059f5:	89 ca                	mov    edx,ecx
   1400059f7:	88 10                	mov    BYTE PTR [rax],dl
   1400059f9:	e9 8a f7 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   1400059fe:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005a02:	75 1c                	jne    140005a20 <__mingw_pformat+0x90d>
   140005a04:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a07:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a0b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a0f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a13:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a16:	89 ca                	mov    edx,ecx
   140005a18:	66 89 10             	mov    WORD PTR [rax],dx
   140005a1b:	e9 68 f7 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   140005a20:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005a24:	75 19                	jne    140005a3f <__mingw_pformat+0x92c>
   140005a26:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a2a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a2e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a32:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a35:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005a38:	89 10                	mov    DWORD PTR [rax],edx
   140005a3a:	e9 49 f7 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   140005a3f:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005a43:	75 1d                	jne    140005a62 <__mingw_pformat+0x94f>
   140005a45:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a48:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a4c:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a50:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a54:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a57:	48 63 d1             	movsxd rdx,ecx
   140005a5a:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005a5d:	e9 26 f7 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   140005a62:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a66:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a6a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a6e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a71:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005a74:	89 10                	mov    DWORD PTR [rax],edx
   140005a76:	e9 0d f7 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   140005a7b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005a7f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005a82:	3c 68                	cmp    al,0x68
   140005a84:	75 0e                	jne    140005a94 <__mingw_pformat+0x981>
   140005a86:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005a8b:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005a92:	eb 07                	jmp    140005a9b <__mingw_pformat+0x988>
   140005a94:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005a9b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005aa2:	e9 ee 02 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005aa7:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005aae:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ab5:	e9 db 02 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005aba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005abe:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ac1:	3c 36                	cmp    al,0x36
   140005ac3:	75 1d                	jne    140005ae2 <__mingw_pformat+0x9cf>
   140005ac5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ac9:	48 83 c0 01          	add    rax,0x1
   140005acd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ad0:	3c 34                	cmp    al,0x34
   140005ad2:	75 0e                	jne    140005ae2 <__mingw_pformat+0x9cf>
   140005ad4:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005adb:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005ae0:	eb 2f                	jmp    140005b11 <__mingw_pformat+0x9fe>
   140005ae2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ae6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ae9:	3c 33                	cmp    al,0x33
   140005aeb:	75 1d                	jne    140005b0a <__mingw_pformat+0x9f7>
   140005aed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005af1:	48 83 c0 01          	add    rax,0x1
   140005af5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005af8:	3c 32                	cmp    al,0x32
   140005afa:	75 0e                	jne    140005b0a <__mingw_pformat+0x9f7>
   140005afc:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b03:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b08:	eb 07                	jmp    140005b11 <__mingw_pformat+0x9fe>
   140005b0a:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b11:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b18:	e9 78 02 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005b1d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b21:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b24:	3c 6c                	cmp    al,0x6c
   140005b26:	75 0e                	jne    140005b36 <__mingw_pformat+0xa23>
   140005b28:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b2d:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b34:	eb 07                	jmp    140005b3d <__mingw_pformat+0xa2a>
   140005b36:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b3d:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b44:	e9 4c 02 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005b49:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b50:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b57:	e9 39 02 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005b5c:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005b5f:	83 c8 04             	or     eax,0x4
   140005b62:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005b65:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b6c:	e9 24 02 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005b71:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b78:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b7f:	e9 11 02 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005b84:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b8b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b92:	e9 fe 01 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005b97:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005b9b:	77 1f                	ja     140005bbc <__mingw_pformat+0xaa9>
   140005b9d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005ba4:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005ba8:	48 83 c0 10          	add    rax,0x10
   140005bac:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005bb0:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005bb7:	e9 d9 01 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005bbc:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bc3:	e9 cd 01 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005bc8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005bcd:	74 4c                	je     140005c1b <__mingw_pformat+0xb08>
   140005bcf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005bd3:	74 06                	je     140005bdb <__mingw_pformat+0xac8>
   140005bd5:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005bd9:	75 40                	jne    140005c1b <__mingw_pformat+0xb08>
   140005bdb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005bdf:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005be3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005be7:	8b 10                	mov    edx,DWORD PTR [rax]
   140005be9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005bed:	89 10                	mov    DWORD PTR [rax],edx
   140005bef:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005bf3:	8b 00                	mov    eax,DWORD PTR [rax]
   140005bf5:	85 c0                	test   eax,eax
   140005bf7:	79 29                	jns    140005c22 <__mingw_pformat+0xb0f>
   140005bf9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005bfd:	75 13                	jne    140005c12 <__mingw_pformat+0xaff>
   140005bff:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c02:	80 cc 04             	or     ah,0x4
   140005c05:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c08:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005c0b:	f7 d8                	neg    eax
   140005c0d:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005c10:	eb 10                	jmp    140005c22 <__mingw_pformat+0xb0f>
   140005c12:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005c19:	eb 07                	jmp    140005c22 <__mingw_pformat+0xb0f>
   140005c1b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c22:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005c29:	00 
   140005c2a:	e9 66 01 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005c2f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c33:	0f 85 4f 01 00 00    	jne    140005d88 <__mingw_pformat+0xc75>
   140005c39:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c3c:	80 cc 08             	or     ah,0x8
   140005c3f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c42:	e9 41 01 00 00       	jmp    140005d88 <__mingw_pformat+0xc75>
   140005c47:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c4b:	0f 85 3a 01 00 00    	jne    140005d8b <__mingw_pformat+0xc78>
   140005c51:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c54:	80 cc 01             	or     ah,0x1
   140005c57:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c5a:	e9 2c 01 00 00       	jmp    140005d8b <__mingw_pformat+0xc78>
   140005c5f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c63:	0f 85 25 01 00 00    	jne    140005d8e <__mingw_pformat+0xc7b>
   140005c69:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c6c:	80 cc 04             	or     ah,0x4
   140005c6f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c72:	e9 17 01 00 00       	jmp    140005d8e <__mingw_pformat+0xc7b>
   140005c77:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c7b:	0f 85 10 01 00 00    	jne    140005d91 <__mingw_pformat+0xc7e>
   140005c81:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c84:	80 cc 10             	or     ah,0x10
   140005c87:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c8a:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005c91:	00 
   140005c92:	e8 a1 39 00 00       	call   140009638 <localeconv>
   140005c97:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005c9b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005c9f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005ca3:	49 89 c9             	mov    r9,rcx
   140005ca6:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005cac:	48 89 c1             	mov    rcx,rax
   140005caf:	e8 bc 33 00 00       	call   140009070 <mbrtowc>
   140005cb4:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005cb7:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005cbb:	7e 08                	jle    140005cc5 <__mingw_pformat+0xbb2>
   140005cbd:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005cc1:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005cc5:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005cc8:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005ccb:	e9 c1 00 00 00       	jmp    140005d91 <__mingw_pformat+0xc7e>
   140005cd0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cd4:	0f 85 ba 00 00 00    	jne    140005d94 <__mingw_pformat+0xc81>
   140005cda:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cdd:	83 c8 40             	or     eax,0x40
   140005ce0:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005ce3:	e9 ac 00 00 00       	jmp    140005d94 <__mingw_pformat+0xc81>
   140005ce8:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cec:	75 0e                	jne    140005cfc <__mingw_pformat+0xbe9>
   140005cee:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cf1:	80 cc 02             	or     ah,0x2
   140005cf4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cf7:	e9 99 00 00 00       	jmp    140005d95 <__mingw_pformat+0xc82>
   140005cfc:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005d00:	77 68                	ja     140005d6a <__mingw_pformat+0xc57>
   140005d02:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005d06:	7f 62                	jg     140005d6a <__mingw_pformat+0xc57>
   140005d08:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005d0c:	7e 5c                	jle    140005d6a <__mingw_pformat+0xc57>
   140005d0e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d12:	75 09                	jne    140005d1d <__mingw_pformat+0xc0a>
   140005d14:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005d1b:	eb 0d                	jmp    140005d2a <__mingw_pformat+0xc17>
   140005d1d:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005d21:	75 07                	jne    140005d2a <__mingw_pformat+0xc17>
   140005d23:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005d2a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005d2f:	74 64                	je     140005d95 <__mingw_pformat+0xc82>
   140005d31:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d35:	8b 00                	mov    eax,DWORD PTR [rax]
   140005d37:	85 c0                	test   eax,eax
   140005d39:	79 0e                	jns    140005d49 <__mingw_pformat+0xc36>
   140005d3b:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d3e:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d41:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d45:	89 10                	mov    DWORD PTR [rax],edx
   140005d47:	eb 4c                	jmp    140005d95 <__mingw_pformat+0xc82>
   140005d49:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d4d:	8b 10                	mov    edx,DWORD PTR [rax]
   140005d4f:	89 d0                	mov    eax,edx
   140005d51:	c1 e0 02             	shl    eax,0x2
   140005d54:	01 d0                	add    eax,edx
   140005d56:	01 c0                	add    eax,eax
   140005d58:	89 c2                	mov    edx,eax
   140005d5a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d5d:	01 d0                	add    eax,edx
   140005d5f:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d62:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d66:	89 10                	mov    DWORD PTR [rax],edx
   140005d68:	eb 2b                	jmp    140005d95 <__mingw_pformat+0xc82>
   140005d6a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005d6e:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005d72:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005d76:	48 89 c2             	mov    rdx,rax
   140005d79:	b9 25 00 00 00       	mov    ecx,0x25
   140005d7e:	e8 fd d3 ff ff       	call   140003180 <__pformat_putc>
   140005d83:	e9 00 f4 ff ff       	jmp    140005188 <__mingw_pformat+0x75>
   140005d88:	90                   	nop
   140005d89:	eb 0a                	jmp    140005d95 <__mingw_pformat+0xc82>
   140005d8b:	90                   	nop
   140005d8c:	eb 07                	jmp    140005d95 <__mingw_pformat+0xc82>
   140005d8e:	90                   	nop
   140005d8f:	eb 04                	jmp    140005d95 <__mingw_pformat+0xc82>
   140005d91:	90                   	nop
   140005d92:	eb 01                	jmp    140005d95 <__mingw_pformat+0xc82>
   140005d94:	90                   	nop
   140005d95:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005d99:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005d9c:	84 c0                	test   al,al
   140005d9e:	0f 85 2d f4 ff ff    	jne    1400051d1 <__mingw_pformat+0xbe>
   140005da4:	eb 0e                	jmp    140005db4 <__mingw_pformat+0xca1>
   140005da6:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005daa:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005dad:	89 c1                	mov    ecx,eax
   140005daf:	e8 cc d3 ff ff       	call   140003180 <__pformat_putc>
   140005db4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005db8:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005dbc:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005dc0:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005dc3:	0f be c0             	movsx  eax,al
   140005dc6:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005dc9:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005dcd:	0f 85 ba f3 ff ff    	jne    14000518d <__mingw_pformat+0x7a>
   140005dd3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005dd6:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005ddd:	5d                   	pop    rbp
   140005dde:	c3                   	ret
   140005ddf:	90                   	nop

0000000140005de0 <__rv_alloc_D2A>:
   140005de0:	55                   	push   rbp
   140005de1:	48 89 e5             	mov    rbp,rsp
   140005de4:	48 83 ec 30          	sub    rsp,0x30
   140005de8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005deb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005df2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005df9:	eb 07                	jmp    140005e02 <__rv_alloc_D2A+0x22>
   140005dfb:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005dff:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005e02:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005e05:	83 c0 17             	add    eax,0x17
   140005e08:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005e0b:	7f ee                	jg     140005dfb <__rv_alloc_D2A+0x1b>
   140005e0d:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005e10:	89 c1                	mov    ecx,eax
   140005e12:	e8 56 1e 00 00       	call   140007c6d <__Balloc_D2A>
   140005e17:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005e1b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e1f:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005e22:	89 10                	mov    DWORD PTR [rax],edx
   140005e24:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e28:	48 83 c0 04          	add    rax,0x4
   140005e2c:	48 83 c4 30          	add    rsp,0x30
   140005e30:	5d                   	pop    rbp
   140005e31:	c3                   	ret

0000000140005e32 <__nrv_alloc_D2A>:
   140005e32:	55                   	push   rbp
   140005e33:	48 89 e5             	mov    rbp,rsp
   140005e36:	48 83 ec 30          	sub    rsp,0x30
   140005e3a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005e3e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005e42:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005e46:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005e49:	89 c1                	mov    ecx,eax
   140005e4b:	e8 90 ff ff ff       	call   140005de0 <__rv_alloc_D2A>
   140005e50:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005e54:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e58:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005e5c:	eb 05                	jmp    140005e63 <__nrv_alloc_D2A+0x31>
   140005e5e:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005e63:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005e67:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e6b:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005e6f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005e72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e76:	88 10                	mov    BYTE PTR [rax],dl
   140005e78:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e7c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e7f:	84 c0                	test   al,al
   140005e81:	75 db                	jne    140005e5e <__nrv_alloc_D2A+0x2c>
   140005e83:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005e88:	74 0b                	je     140005e95 <__nrv_alloc_D2A+0x63>
   140005e8a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005e8e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005e92:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005e95:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e99:	48 83 c4 30          	add    rsp,0x30
   140005e9d:	5d                   	pop    rbp
   140005e9e:	c3                   	ret

0000000140005e9f <__freedtoa>:
   140005e9f:	55                   	push   rbp
   140005ea0:	48 89 e5             	mov    rbp,rsp
   140005ea3:	48 83 ec 30          	sub    rsp,0x30
   140005ea7:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005eab:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005eaf:	48 83 e8 04          	sub    rax,0x4
   140005eb3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005eb7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ebb:	8b 10                	mov    edx,DWORD PTR [rax]
   140005ebd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ec1:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005ec4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ec8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005ecb:	ba 01 00 00 00       	mov    edx,0x1
   140005ed0:	89 c1                	mov    ecx,eax
   140005ed2:	d3 e2                	shl    edx,cl
   140005ed4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ed8:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005edb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005edf:	48 89 c1             	mov    rcx,rax
   140005ee2:	e8 c7 1e 00 00       	call   140007dae <__Bfree_D2A>
   140005ee7:	90                   	nop
   140005ee8:	48 83 c4 30          	add    rsp,0x30
   140005eec:	5d                   	pop    rbp
   140005eed:	c3                   	ret

0000000140005eee <__quorem_D2A>:
   140005eee:	55                   	push   rbp
   140005eef:	48 89 e5             	mov    rbp,rsp
   140005ef2:	48 83 ec 70          	sub    rsp,0x70
   140005ef6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005efa:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005efe:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f02:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f05:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005f08:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f0c:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f0f:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005f12:	7e 0a                	jle    140005f1e <__quorem_D2A+0x30>
   140005f14:	b8 00 00 00 00       	mov    eax,0x0
   140005f19:	e9 3f 02 00 00       	jmp    14000615d <__quorem_D2A+0x26f>
   140005f1e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f22:	48 83 c0 18          	add    rax,0x18
   140005f26:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005f2a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005f2e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005f31:	48 98                	cdqe
   140005f33:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005f3a:	00 
   140005f3b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005f3f:	48 01 d0             	add    rax,rdx
   140005f42:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005f46:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f4a:	48 83 c0 18          	add    rax,0x18
   140005f4e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005f52:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005f55:	48 98                	cdqe
   140005f57:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005f5e:	00 
   140005f5f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f63:	48 01 d0             	add    rax,rdx
   140005f66:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140005f6a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005f6e:	8b 00                	mov    eax,DWORD PTR [rax]
   140005f70:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140005f74:	8b 12                	mov    edx,DWORD PTR [rdx]
   140005f76:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140005f79:	ba 00 00 00 00       	mov    edx,0x0
   140005f7e:	f7 f1                	div    ecx
   140005f80:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140005f83:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140005f87:	0f 84 c4 00 00 00    	je     140006051 <__quorem_D2A+0x163>
   140005f8d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140005f94:	00 
   140005f95:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   140005f9c:	00 
   140005f9d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005fa1:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140005fa5:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140005fa9:	8b 00                	mov    eax,DWORD PTR [rax]
   140005fab:	89 c2                	mov    edx,eax
   140005fad:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140005fb0:	48 0f af d0          	imul   rdx,rax
   140005fb4:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140005fb8:	48 01 d0             	add    rax,rdx
   140005fbb:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140005fbf:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140005fc3:	48 c1 e8 20          	shr    rax,0x20
   140005fc7:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140005fcb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005fcf:	8b 00                	mov    eax,DWORD PTR [rax]
   140005fd1:	89 c1                	mov    ecx,eax
   140005fd3:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140005fd7:	89 c2                	mov    edx,eax
   140005fd9:	48 89 c8             	mov    rax,rcx
   140005fdc:	48 29 d0             	sub    rax,rdx
   140005fdf:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140005fe3:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140005fe7:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140005feb:	48 c1 e8 20          	shr    rax,0x20
   140005fef:	83 e0 01             	and    eax,0x1
   140005ff2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140005ff6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ffa:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140005ffe:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006002:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006006:	89 10                	mov    DWORD PTR [rax],edx
   140006008:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000600c:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006010:	73 8b                	jae    140005f9d <__quorem_D2A+0xaf>
   140006012:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006016:	8b 00                	mov    eax,DWORD PTR [rax]
   140006018:	85 c0                	test   eax,eax
   14000601a:	75 35                	jne    140006051 <__quorem_D2A+0x163>
   14000601c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006020:	48 83 c0 18          	add    rax,0x18
   140006024:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006028:	eb 04                	jmp    14000602e <__quorem_D2A+0x140>
   14000602a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000602e:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   140006033:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006037:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   14000603b:	73 0a                	jae    140006047 <__quorem_D2A+0x159>
   14000603d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006041:	8b 00                	mov    eax,DWORD PTR [rax]
   140006043:	85 c0                	test   eax,eax
   140006045:	74 e3                	je     14000602a <__quorem_D2A+0x13c>
   140006047:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000604b:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000604e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006051:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140006055:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006059:	48 89 c1             	mov    rcx,rax
   14000605c:	e8 bc 24 00 00       	call   14000851d <__cmp_D2A>
   140006061:	85 c0                	test   eax,eax
   140006063:	0f 88 f1 00 00 00    	js     14000615a <__quorem_D2A+0x26c>
   140006069:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   14000606d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006074:	00 
   140006075:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000607c:	00 
   14000607d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006081:	48 83 c0 18          	add    rax,0x18
   140006085:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006089:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000608d:	48 83 c0 18          	add    rax,0x18
   140006091:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006095:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006099:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000609d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   1400060a1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060a3:	89 c2                	mov    edx,eax
   1400060a5:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400060a9:	48 01 d0             	add    rax,rdx
   1400060ac:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400060b0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400060b4:	48 c1 e8 20          	shr    rax,0x20
   1400060b8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400060bc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060c0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060c2:	89 c1                	mov    ecx,eax
   1400060c4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400060c8:	89 c2                	mov    edx,eax
   1400060ca:	48 89 c8             	mov    rax,rcx
   1400060cd:	48 29 d0             	sub    rax,rdx
   1400060d0:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   1400060d4:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400060d8:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400060dc:	48 c1 e8 20          	shr    rax,0x20
   1400060e0:	83 e0 01             	and    eax,0x1
   1400060e3:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400060e7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060eb:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400060ef:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400060f3:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400060f7:	89 10                	mov    DWORD PTR [rax],edx
   1400060f9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400060fd:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006101:	73 92                	jae    140006095 <__quorem_D2A+0x1a7>
   140006103:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006107:	48 83 c0 18          	add    rax,0x18
   14000610b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000610f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006112:	48 98                	cdqe
   140006114:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000611b:	00 
   14000611c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006120:	48 01 d0             	add    rax,rdx
   140006123:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006127:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000612b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000612d:	85 c0                	test   eax,eax
   14000612f:	75 29                	jne    14000615a <__quorem_D2A+0x26c>
   140006131:	eb 04                	jmp    140006137 <__quorem_D2A+0x249>
   140006133:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140006137:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   14000613c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006140:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   140006144:	73 0a                	jae    140006150 <__quorem_D2A+0x262>
   140006146:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000614a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000614c:	85 c0                	test   eax,eax
   14000614e:	74 e3                	je     140006133 <__quorem_D2A+0x245>
   140006150:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006154:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006157:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000615a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   14000615d:	48 83 c4 70          	add    rsp,0x70
   140006161:	5d                   	pop    rbp
   140006162:	c3                   	ret
   140006163:	90                   	nop
   140006164:	90                   	nop
   140006165:	90                   	nop
   140006166:	90                   	nop
   140006167:	90                   	nop
   140006168:	90                   	nop
   140006169:	90                   	nop
   14000616a:	90                   	nop
   14000616b:	90                   	nop
   14000616c:	90                   	nop
   14000616d:	90                   	nop
   14000616e:	90                   	nop
   14000616f:	90                   	nop

0000000140006170 <__hi0bits_D2A>:
   140006170:	55                   	push   rbp
   140006171:	48 89 e5             	mov    rbp,rsp
   140006174:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140006177:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   14000617b:	83 f0 1f             	xor    eax,0x1f
   14000617e:	5d                   	pop    rbp
   14000617f:	c3                   	ret

0000000140006180 <bitstob>:
   140006180:	55                   	push   rbp
   140006181:	53                   	push   rbx
   140006182:	48 83 ec 58          	sub    rsp,0x58
   140006186:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000618b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000618f:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006192:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006196:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000619d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400061a4:	eb 07                	jmp    1400061ad <bitstob+0x2d>
   1400061a6:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   1400061a9:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   1400061ad:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400061b0:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   1400061b3:	7c f1                	jl     1400061a6 <bitstob+0x26>
   1400061b5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400061b8:	89 c1                	mov    ecx,eax
   1400061ba:	e8 ae 1a 00 00       	call   140007c6d <__Balloc_D2A>
   1400061bf:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400061c3:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   1400061c6:	83 e8 01             	sub    eax,0x1
   1400061c9:	c1 f8 05             	sar    eax,0x5
   1400061cc:	48 98                	cdqe
   1400061ce:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400061d5:	00 
   1400061d6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400061da:	48 01 d0             	add    rax,rdx
   1400061dd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400061e1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061e5:	48 83 c0 18          	add    rax,0x18
   1400061e9:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400061ed:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400061f1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400061f5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061f9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400061fd:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006201:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140006205:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006207:	89 10                	mov    DWORD PTR [rax],edx
   140006209:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   14000620e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006212:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140006216:	73 dd                	jae    1400061f5 <bitstob+0x75>
   140006218:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000621c:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140006220:	48 c1 f8 02          	sar    rax,0x2
   140006224:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140006227:	eb 1d                	jmp    140006246 <bitstob+0xc6>
   140006229:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000622d:	75 17                	jne    140006246 <bitstob+0xc6>
   14000622f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006233:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   14000623a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000623e:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140006244:	eb 59                	jmp    14000629f <bitstob+0x11f>
   140006246:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000624a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000624d:	48 98                	cdqe
   14000624f:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006256:	00 
   140006257:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000625b:	48 01 d0             	add    rax,rdx
   14000625e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006260:	85 c0                	test   eax,eax
   140006262:	74 c5                	je     140006229 <bitstob+0xa9>
   140006264:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006267:	8d 50 01             	lea    edx,[rax+0x1]
   14000626a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000626e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006271:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006274:	83 c0 01             	add    eax,0x1
   140006277:	c1 e0 05             	shl    eax,0x5
   14000627a:	89 c3                	mov    ebx,eax
   14000627c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006280:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006283:	48 63 d2             	movsxd rdx,edx
   140006286:	48 83 c2 04          	add    rdx,0x4
   14000628a:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   14000628e:	89 c1                	mov    ecx,eax
   140006290:	e8 db fe ff ff       	call   140006170 <__hi0bits_D2A>
   140006295:	29 c3                	sub    ebx,eax
   140006297:	89 da                	mov    edx,ebx
   140006299:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000629d:	89 10                	mov    DWORD PTR [rax],edx
   14000629f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062a3:	48 83 c4 58          	add    rsp,0x58
   1400062a7:	5b                   	pop    rbx
   1400062a8:	5d                   	pop    rbp
   1400062a9:	c3                   	ret

00000001400062aa <__gdtoa>:
   1400062aa:	55                   	push   rbp
   1400062ab:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   1400062b2:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   1400062b9:	00 
   1400062ba:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   1400062c1:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   1400062c7:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   1400062ce:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   1400062d5:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   1400062dc:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062e3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062e5:	83 e0 cf             	and    eax,0xffffffcf
   1400062e8:	89 c2                	mov    edx,eax
   1400062ea:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062f1:	89 10                	mov    DWORD PTR [rax],edx
   1400062f3:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062fa:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062fc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400062ff:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006302:	83 e0 07             	and    eax,0x7
   140006305:	83 f8 04             	cmp    eax,0x4
   140006308:	0f 84 b0 00 00 00    	je     1400063be <__gdtoa+0x114>
   14000630e:	83 f8 04             	cmp    eax,0x4
   140006311:	0f 8f d5 00 00 00    	jg     1400063ec <__gdtoa+0x142>
   140006317:	83 f8 03             	cmp    eax,0x3
   14000631a:	74 74                	je     140006390 <__gdtoa+0xe6>
   14000631c:	83 f8 03             	cmp    eax,0x3
   14000631f:	0f 8f c7 00 00 00    	jg     1400063ec <__gdtoa+0x142>
   140006325:	85 c0                	test   eax,eax
   140006327:	0f 84 05 01 00 00    	je     140006432 <__gdtoa+0x188>
   14000632d:	85 c0                	test   eax,eax
   14000632f:	0f 88 b7 00 00 00    	js     1400063ec <__gdtoa+0x142>
   140006335:	83 e8 01             	sub    eax,0x1
   140006338:	83 f8 01             	cmp    eax,0x1
   14000633b:	0f 87 ab 00 00 00    	ja     1400063ec <__gdtoa+0x142>
   140006341:	90                   	nop
   140006342:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006349:	8b 00                	mov    eax,DWORD PTR [rax]
   14000634b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000634e:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   140006352:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006355:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   14000635c:	49 89 c8             	mov    r8,rcx
   14000635f:	48 89 c1             	mov    rcx,rax
   140006362:	e8 19 fe ff ff       	call   140006180 <bitstob>
   140006367:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000636b:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006371:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140006374:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006378:	48 89 c1             	mov    rcx,rax
   14000637b:	e8 31 16 00 00       	call   1400079b1 <__trailz_D2A>
   140006380:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006383:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006386:	85 c0                	test   eax,eax
   140006388:	0f 84 8b 00 00 00    	je     140006419 <__gdtoa+0x16f>
   14000638e:	eb 66                	jmp    1400063f6 <__gdtoa+0x14c>
   140006390:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006397:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000639d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400063a4:	48 8d 0d a5 4f 00 00 	lea    rcx,[rip+0x4fa5]        # 14000b350 <.rdata>
   1400063ab:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400063b1:	48 89 c2             	mov    rdx,rax
   1400063b4:	e8 79 fa ff ff       	call   140005e32 <__nrv_alloc_D2A>
   1400063b9:	e9 4d 14 00 00       	jmp    14000780b <__gdtoa+0x1561>
   1400063be:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400063c5:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   1400063cb:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400063d2:	48 8d 0d 80 4f 00 00 	lea    rcx,[rip+0x4f80]        # 14000b359 <.rdata+0x9>
   1400063d9:	41 b8 03 00 00 00    	mov    r8d,0x3
   1400063df:	48 89 c2             	mov    rdx,rax
   1400063e2:	e8 4b fa ff ff       	call   140005e32 <__nrv_alloc_D2A>
   1400063e7:	e9 1f 14 00 00       	jmp    14000780b <__gdtoa+0x1561>
   1400063ec:	b8 00 00 00 00       	mov    eax,0x0
   1400063f1:	e9 15 14 00 00       	jmp    14000780b <__gdtoa+0x1561>
   1400063f6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400063f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063fd:	48 89 c1             	mov    rcx,rax
   140006400:	e8 50 14 00 00       	call   140007855 <__rshift_D2A>
   140006405:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006408:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   14000640e:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006411:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006414:	29 c2                	sub    edx,eax
   140006416:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   140006419:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000641d:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006420:	85 c0                	test   eax,eax
   140006422:	75 3d                	jne    140006461 <__gdtoa+0x1b7>
   140006424:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006428:	48 89 c1             	mov    rcx,rax
   14000642b:	e8 7e 19 00 00       	call   140007dae <__Bfree_D2A>
   140006430:	eb 01                	jmp    140006433 <__gdtoa+0x189>
   140006432:	90                   	nop
   140006433:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   14000643a:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140006440:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006447:	48 8d 0d 0f 4f 00 00 	lea    rcx,[rip+0x4f0f]        # 14000b35d <.rdata+0xd>
   14000644e:	41 b8 01 00 00 00    	mov    r8d,0x1
   140006454:	48 89 c2             	mov    rdx,rax
   140006457:	e8 d6 f9 ff ff       	call   140005e32 <__nrv_alloc_D2A>
   14000645c:	e9 aa 13 00 00       	jmp    14000780b <__gdtoa+0x1561>
   140006461:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   140006465:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006469:	48 89 c1             	mov    rcx,rax
   14000646c:	e8 75 23 00 00       	call   1400087e6 <__b2d_D2A>
   140006471:	66 48 0f 7e c0       	movq   rax,xmm0
   140006476:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   14000647a:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   14000647d:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006483:	01 d0                	add    eax,edx
   140006485:	83 e8 01             	sub    eax,0x1
   140006488:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000648b:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   14000648e:	25 ff ff 0f 00       	and    eax,0xfffff
   140006493:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006496:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006499:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000649e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400064a1:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400064a6:	f2 0f 10 15 b2 4e 00 	movsd  xmm2,QWORD PTR [rip+0x4eb2]        # 14000b360 <.rdata+0x10>
   1400064ad:	00 
   1400064ae:	66 0f 28 c8          	movapd xmm1,xmm0
   1400064b2:	f2 0f 5c ca          	subsd  xmm1,xmm2
   1400064b6:	f2 0f 10 05 aa 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4eaa]        # 14000b368 <.rdata+0x18>
   1400064bd:	00 
   1400064be:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   1400064c2:	f2 0f 10 05 a6 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4ea6]        # 14000b370 <.rdata+0x20>
   1400064c9:	00 
   1400064ca:	f2 0f 58 c8          	addsd  xmm1,xmm0
   1400064ce:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064d1:	66 0f ef d2          	pxor   xmm2,xmm2
   1400064d5:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   1400064d9:	f2 0f 10 05 97 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e97]        # 14000b378 <.rdata+0x28>
   1400064e0:	00 
   1400064e1:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   1400064e5:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400064e9:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400064ee:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064f1:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400064f4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400064f8:	79 03                	jns    1400064fd <__gdtoa+0x253>
   1400064fa:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   1400064fd:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   140006504:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006508:	7e 23                	jle    14000652d <__gdtoa+0x283>
   14000650a:	66 0f ef c9          	pxor   xmm1,xmm1
   14000650e:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   140006513:	f2 0f 10 05 65 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e65]        # 14000b380 <.rdata+0x30>
   14000651a:	00 
   14000651b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000651f:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006524:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006528:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000652d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006532:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006536:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006539:	66 0f ef c0          	pxor   xmm0,xmm0
   14000653d:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006542:	76 1b                	jbe    14000655f <__gdtoa+0x2b5>
   140006544:	66 0f ef c0          	pxor   xmm0,xmm0
   140006548:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   14000654d:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006552:	7a 07                	jp     14000655b <__gdtoa+0x2b1>
   140006554:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006559:	74 04                	je     14000655f <__gdtoa+0x2b5>
   14000655b:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000655f:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   140006566:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006569:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   14000656c:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006572:	01 ca                	add    edx,ecx
   140006574:	83 ea 01             	sub    edx,0x1
   140006577:	c1 e2 14             	shl    edx,0x14
   14000657a:	01 d0                	add    eax,edx
   14000657c:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000657f:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006583:	78 2e                	js     1400065b3 <__gdtoa+0x309>
   140006585:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   140006589:	7f 28                	jg     1400065b3 <__gdtoa+0x309>
   14000658b:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006590:	48 8b 05 e9 50 00 00 	mov    rax,QWORD PTR [rip+0x50e9]        # 14000b680 <.refptr.__tens_D2A>
   140006597:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000659a:	48 63 d2             	movsxd rdx,edx
   14000659d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400065a2:	66 0f 2f c1          	comisd xmm0,xmm1
   1400065a6:	76 04                	jbe    1400065ac <__gdtoa+0x302>
   1400065a8:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400065ac:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   1400065b3:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400065b6:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400065b9:	29 c2                	sub    edx,eax
   1400065bb:	8d 42 ff             	lea    eax,[rdx-0x1]
   1400065be:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400065c1:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065c5:	78 0f                	js     1400065d6 <__gdtoa+0x32c>
   1400065c7:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   1400065ce:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400065d1:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   1400065d4:	eb 0f                	jmp    1400065e5 <__gdtoa+0x33b>
   1400065d6:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400065d9:	f7 d8                	neg    eax
   1400065db:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   1400065de:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   1400065e5:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400065e9:	78 15                	js     140006600 <__gdtoa+0x356>
   1400065eb:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   1400065f2:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065f5:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   1400065f8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065fb:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400065fe:	eb 15                	jmp    140006615 <__gdtoa+0x36b>
   140006600:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006603:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006606:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006609:	f7 d8                	neg    eax
   14000660b:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   14000660e:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   140006615:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000661c:	78 09                	js     140006627 <__gdtoa+0x37d>
   14000661e:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   140006625:	7e 0a                	jle    140006631 <__gdtoa+0x387>
   140006627:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   14000662e:	00 00 00 
   140006631:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   140006638:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   14000663f:	7e 10                	jle    140006651 <__gdtoa+0x3a7>
   140006641:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   140006648:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000664f:	eb 1b                	jmp    14000666c <__gdtoa+0x3c2>
   140006651:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006654:	3d f9 03 00 00       	cmp    eax,0x3f9
   140006659:	7f 0a                	jg     140006665 <__gdtoa+0x3bb>
   14000665b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000665e:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   140006663:	7d 07                	jge    14000666c <__gdtoa+0x3c2>
   140006665:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000666c:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   140006673:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   14000667a:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000667d:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006680:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006687:	0f 84 c5 00 00 00    	je     140006752 <__gdtoa+0x4a8>
   14000668d:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006694:	0f 8f e6 00 00 00    	jg     140006780 <__gdtoa+0x4d6>
   14000669a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   1400066a1:	74 7e                	je     140006721 <__gdtoa+0x477>
   1400066a3:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   1400066aa:	0f 8f d0 00 00 00    	jg     140006780 <__gdtoa+0x4d6>
   1400066b0:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   1400066b7:	0f 84 8e 00 00 00    	je     14000674b <__gdtoa+0x4a1>
   1400066bd:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   1400066c4:	0f 8f b6 00 00 00    	jg     140006780 <__gdtoa+0x4d6>
   1400066ca:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400066d1:	7f 0e                	jg     1400066e1 <__gdtoa+0x437>
   1400066d3:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400066da:	79 13                	jns    1400066ef <__gdtoa+0x445>
   1400066dc:	e9 9f 00 00 00       	jmp    140006780 <__gdtoa+0x4d6>
   1400066e1:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400066e8:	74 30                	je     14000671a <__gdtoa+0x470>
   1400066ea:	e9 91 00 00 00       	jmp    140006780 <__gdtoa+0x4d6>
   1400066ef:	66 0f ef c9          	pxor   xmm1,xmm1
   1400066f3:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   1400066f8:	f2 0f 10 05 88 4c 00 	movsd  xmm0,QWORD PTR [rip+0x4c88]        # 14000b388 <.rdata+0x38>
   1400066ff:	00 
   140006700:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006704:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006708:	83 c0 03             	add    eax,0x3
   14000670b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000670e:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   140006715:	00 00 00 
   140006718:	eb 66                	jmp    140006780 <__gdtoa+0x4d6>
   14000671a:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006721:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006728:	7f 0a                	jg     140006734 <__gdtoa+0x48a>
   14000672a:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   140006731:	00 00 00 
   140006734:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   14000673a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000673d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006740:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006743:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006746:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006749:	eb 35                	jmp    140006780 <__gdtoa+0x4d6>
   14000674b:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006752:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   140006758:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000675b:	01 d0                	add    eax,edx
   14000675d:	83 c0 01             	add    eax,0x1
   140006760:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006763:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006766:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006769:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000676c:	83 e8 01             	sub    eax,0x1
   14000676f:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006772:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006775:	85 c0                	test   eax,eax
   140006777:	7f 07                	jg     140006780 <__gdtoa+0x4d6>
   140006779:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006780:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006783:	89 c1                	mov    ecx,eax
   140006785:	e8 56 f6 ff ff       	call   140005de0 <__rv_alloc_D2A>
   14000678a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000678e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006792:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006796:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000679d:	7f 09                	jg     1400067a8 <__gdtoa+0x4fe>
   14000679f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   1400067a6:	eb 38                	jmp    1400067e0 <__gdtoa+0x536>
   1400067a8:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400067af:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400067b2:	83 e8 01             	sub    eax,0x1
   1400067b5:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   1400067b8:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400067bc:	74 22                	je     1400067e0 <__gdtoa+0x536>
   1400067be:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400067c2:	79 07                	jns    1400067cb <__gdtoa+0x521>
   1400067c4:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   1400067cb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400067ce:	83 e0 08             	and    eax,0x8
   1400067d1:	85 c0                	test   eax,eax
   1400067d3:	74 0b                	je     1400067e0 <__gdtoa+0x536>
   1400067d5:	b8 03 00 00 00       	mov    eax,0x3
   1400067da:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   1400067dd:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   1400067e0:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400067e4:	0f 88 b9 04 00 00    	js     140006ca3 <__gdtoa+0x9f9>
   1400067ea:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   1400067ee:	0f 8f af 04 00 00    	jg     140006ca3 <__gdtoa+0x9f9>
   1400067f4:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   1400067f8:	0f 84 a5 04 00 00    	je     140006ca3 <__gdtoa+0x9f9>
   1400067fe:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006802:	0f 85 9b 04 00 00    	jne    140006ca3 <__gdtoa+0x9f9>
   140006808:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000680c:	0f 85 91 04 00 00    	jne    140006ca3 <__gdtoa+0x9f9>
   140006812:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006819:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   14000681e:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   140006823:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006826:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140006829:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   14000682c:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   14000682f:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   140006836:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000683a:	0f 8e 98 00 00 00    	jle    1400068d8 <__gdtoa+0x62e>
   140006840:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006843:	83 e0 0f             	and    eax,0xf
   140006846:	89 c2                	mov    edx,eax
   140006848:	48 8b 05 31 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e31]        # 14000b680 <.refptr.__tens_D2A>
   14000684f:	48 63 d2             	movsxd rdx,edx
   140006852:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006857:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000685c:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000685f:	c1 f8 04             	sar    eax,0x4
   140006862:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006865:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006868:	83 e0 10             	and    eax,0x10
   14000686b:	85 c0                	test   eax,eax
   14000686d:	74 5e                	je     1400068cd <__gdtoa+0x623>
   14000686f:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   140006873:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006878:	48 8b 05 31 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d31]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000687f:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   140006884:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006888:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000688d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006891:	eb 3a                	jmp    1400068cd <__gdtoa+0x623>
   140006893:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006896:	83 e0 01             	and    eax,0x1
   140006899:	85 c0                	test   eax,eax
   14000689b:	74 24                	je     1400068c1 <__gdtoa+0x617>
   14000689d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400068a1:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400068a4:	48 8b 05 05 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d05]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400068ab:	48 63 d2             	movsxd rdx,edx
   1400068ae:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400068b3:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   1400068b8:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400068bc:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068c1:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   1400068c4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400068c7:	83 c0 01             	add    eax,0x1
   1400068ca:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400068cd:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400068d1:	75 c0                	jne    140006893 <__gdtoa+0x5e9>
   1400068d3:	e9 8b 00 00 00       	jmp    140006963 <__gdtoa+0x6b9>
   1400068d8:	f2 0f 10 05 b0 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4ab0]        # 14000b390 <.rdata+0x40>
   1400068df:	00 
   1400068e0:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068e5:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068e8:	f7 d8                	neg    eax
   1400068ea:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400068ed:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400068f1:	74 70                	je     140006963 <__gdtoa+0x6b9>
   1400068f3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400068f8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400068fb:	83 e0 0f             	and    eax,0xf
   1400068fe:	89 c2                	mov    edx,eax
   140006900:	48 8b 05 79 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d79]        # 14000b680 <.refptr.__tens_D2A>
   140006907:	48 63 d2             	movsxd rdx,edx
   14000690a:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   14000690f:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006913:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006918:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   14000691b:	c1 f8 04             	sar    eax,0x4
   14000691e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006921:	eb 3a                	jmp    14000695d <__gdtoa+0x6b3>
   140006923:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006926:	83 e0 01             	and    eax,0x1
   140006929:	85 c0                	test   eax,eax
   14000692b:	74 24                	je     140006951 <__gdtoa+0x6a7>
   14000692d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006931:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006936:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006939:	48 8b 05 70 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c70]        # 14000b5b0 <.refptr.__bigtens_D2A>
   140006940:	48 63 d2             	movsxd rdx,edx
   140006943:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006948:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000694c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006951:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006954:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006957:	83 c0 01             	add    eax,0x1
   14000695a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000695d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006961:	75 c0                	jne    140006923 <__gdtoa+0x679>
   140006963:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140006967:	74 47                	je     1400069b0 <__gdtoa+0x706>
   140006969:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   14000696e:	f2 0f 10 05 1a 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a1a]        # 14000b390 <.rdata+0x40>
   140006975:	00 
   140006976:	66 0f 2f c1          	comisd xmm0,xmm1
   14000697a:	76 34                	jbe    1400069b0 <__gdtoa+0x706>
   14000697c:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006980:	7e 2e                	jle    1400069b0 <__gdtoa+0x706>
   140006982:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   140006986:	0f 8e f5 02 00 00    	jle    140006c81 <__gdtoa+0x9d7>
   14000698c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000698f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006992:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006996:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   14000699b:	f2 0f 10 05 f5 49 00 	movsd  xmm0,QWORD PTR [rip+0x49f5]        # 14000b398 <.rdata+0x48>
   1400069a2:	00 
   1400069a3:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069a7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069ac:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400069b0:	66 0f ef c9          	pxor   xmm1,xmm1
   1400069b4:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   1400069b9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400069be:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   1400069c2:	f2 0f 10 05 d6 49 00 	movsd  xmm0,QWORD PTR [rip+0x49d6]        # 14000b3a0 <.rdata+0x50>
   1400069c9:	00 
   1400069ca:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400069ce:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   1400069d3:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   1400069d6:	2d 00 00 40 03       	sub    eax,0x3400000
   1400069db:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   1400069de:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400069e2:	75 5f                	jne    140006a43 <__gdtoa+0x799>
   1400069e4:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   1400069eb:	00 
   1400069ec:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400069f0:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400069f4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400069f9:	f2 0f 10 0d a7 49 00 	movsd  xmm1,QWORD PTR [rip+0x49a7]        # 14000b3a8 <.rdata+0x58>
   140006a00:	00 
   140006a01:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a05:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a0a:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a0f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006a14:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a18:	0f 87 ac 07 00 00    	ja     1400071ca <__gdtoa+0xf20>
   140006a1e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a23:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006a28:	f3 0f 7e 15 80 49 00 	movq   xmm2,QWORD PTR [rip+0x4980]        # 14000b3b0 <.rdata+0x60>
   140006a2f:	00 
   140006a30:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006a34:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a38:	0f 87 6e 07 00 00    	ja     1400071ac <__gdtoa+0xf02>
   140006a3e:	e9 42 02 00 00       	jmp    140006c85 <__gdtoa+0x9db>
   140006a43:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006a47:	0f 84 22 01 00 00    	je     140006b6f <__gdtoa+0x8c5>
   140006a4d:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006a52:	f2 0f 10 05 66 49 00 	movsd  xmm0,QWORD PTR [rip+0x4966]        # 14000b3c0 <.rdata+0x70>
   140006a59:	00 
   140006a5a:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a5e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006a61:	8d 50 ff             	lea    edx,[rax-0x1]
   140006a64:	48 8b 05 15 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c15]        # 14000b680 <.refptr.__tens_D2A>
   140006a6b:	48 63 d2             	movsxd rdx,edx
   140006a6e:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006a73:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006a77:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006a7c:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a80:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a85:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006a8c:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a91:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006a96:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006a9a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006a9d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006aa2:	66 0f ef c9          	pxor   xmm1,xmm1
   140006aa6:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006aab:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006ab0:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006ab4:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006ab9:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006abc:	8d 48 30             	lea    ecx,[rax+0x30]
   140006abf:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ac3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006ac7:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006acb:	89 ca                	mov    edx,ecx
   140006acd:	88 10                	mov    BYTE PTR [rax],dl
   140006acf:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ad4:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006ad9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006add:	76 29                	jbe    140006b08 <__gdtoa+0x85e>
   140006adf:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ae4:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ae8:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006aec:	7a 0e                	jp     140006afc <__gdtoa+0x852>
   140006aee:	66 0f ef c9          	pxor   xmm1,xmm1
   140006af2:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006af6:	0f 84 93 0c 00 00    	je     14000778f <__gdtoa+0x14e5>
   140006afc:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006b03:	e9 87 0c 00 00       	jmp    14000778f <__gdtoa+0x14e5>
   140006b08:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006b0d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006b12:	66 0f 28 c8          	movapd xmm1,xmm0
   140006b16:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006b1a:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b1f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b23:	0f 87 c3 02 00 00    	ja     140006dec <__gdtoa+0xb42>
   140006b29:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006b2c:	83 c0 01             	add    eax,0x1
   140006b2f:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006b32:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006b35:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006b38:	0f 8e 46 01 00 00    	jle    140006c84 <__gdtoa+0x9da>
   140006b3e:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b43:	f2 0f 10 05 4d 48 00 	movsd  xmm0,QWORD PTR [rip+0x484d]        # 14000b398 <.rdata+0x48>
   140006b4a:	00 
   140006b4b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b4f:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b54:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b59:	f2 0f 10 05 37 48 00 	movsd  xmm0,QWORD PTR [rip+0x4837]        # 14000b398 <.rdata+0x48>
   140006b60:	00 
   140006b61:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b65:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b6a:	e9 1d ff ff ff       	jmp    140006a8c <__gdtoa+0x7e2>
   140006b6f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b74:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006b77:	8d 50 ff             	lea    edx,[rax-0x1]
   140006b7a:	48 8b 05 ff 4a 00 00 	mov    rax,QWORD PTR [rip+0x4aff]        # 14000b680 <.refptr.__tens_D2A>
   140006b81:	48 63 d2             	movsxd rdx,edx
   140006b84:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006b89:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b8d:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b92:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006b99:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b9e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006ba3:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006ba7:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006baa:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006bae:	74 1c                	je     140006bcc <__gdtoa+0x922>
   140006bb0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006bb5:	66 0f ef c9          	pxor   xmm1,xmm1
   140006bb9:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006bbe:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006bc3:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006bc7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006bcc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006bcf:	8d 48 30             	lea    ecx,[rax+0x30]
   140006bd2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006bd6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006bda:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006bde:	89 ca                	mov    edx,ecx
   140006be0:	88 10                	mov    BYTE PTR [rax],dl
   140006be2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006be5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006be8:	75 73                	jne    140006c5d <__gdtoa+0x9b3>
   140006bea:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006bef:	f2 0f 10 05 c9 47 00 	movsd  xmm0,QWORD PTR [rip+0x47c9]        # 14000b3c0 <.rdata+0x70>
   140006bf6:	00 
   140006bf7:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bfb:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006c00:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c05:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c0a:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006c0f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c13:	0f 87 d6 01 00 00    	ja     140006def <__gdtoa+0xb45>
   140006c19:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c1e:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006c23:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006c28:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006c2c:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c30:	77 02                	ja     140006c34 <__gdtoa+0x98a>
   140006c32:	eb 51                	jmp    140006c85 <__gdtoa+0x9db>
   140006c34:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c39:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c3d:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c41:	7a 0e                	jp     140006c51 <__gdtoa+0x9a7>
   140006c43:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c47:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c4b:	0f 84 41 0b 00 00    	je     140007792 <__gdtoa+0x14e8>
   140006c51:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006c58:	e9 35 0b 00 00       	jmp    140007792 <__gdtoa+0x14e8>
   140006c5d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c60:	83 c0 01             	add    eax,0x1
   140006c63:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006c66:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c6b:	f2 0f 10 05 25 47 00 	movsd  xmm0,QWORD PTR [rip+0x4725]        # 14000b398 <.rdata+0x48>
   140006c72:	00 
   140006c73:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c77:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c7c:	e9 18 ff ff ff       	jmp    140006b99 <__gdtoa+0x8ef>
   140006c81:	90                   	nop
   140006c82:	eb 01                	jmp    140006c85 <__gdtoa+0x9db>
   140006c84:	90                   	nop
   140006c85:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006c89:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006c8d:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006c92:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c97:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006c9a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006c9d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006ca0:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006ca3:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006caa:	0f 88 bf 01 00 00    	js     140006e6f <__gdtoa+0xbc5>
   140006cb0:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006cb7:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006cba:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006cbd:	0f 8f ac 01 00 00    	jg     140006e6f <__gdtoa+0xbc5>
   140006cc3:	48 8b 05 b6 49 00 00 	mov    rax,QWORD PTR [rip+0x49b6]        # 14000b680 <.refptr.__tens_D2A>
   140006cca:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006ccd:	48 63 d2             	movsxd rdx,edx
   140006cd0:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006cd5:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006cda:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006ce1:	79 45                	jns    140006d28 <__gdtoa+0xa7e>
   140006ce3:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006ce7:	7f 3f                	jg     140006d28 <__gdtoa+0xa7e>
   140006ce9:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006cf0:	00 
   140006cf1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006cf5:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006cf9:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006cfd:	0f 88 ac 04 00 00    	js     1400071af <__gdtoa+0xf05>
   140006d03:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d08:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006d0d:	f2 0f 10 05 93 46 00 	movsd  xmm0,QWORD PTR [rip+0x4693]        # 14000b3a8 <.rdata+0x58>
   140006d14:	00 
   140006d15:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006d19:	66 0f 2f c1          	comisd xmm0,xmm1
   140006d1d:	0f 83 8c 04 00 00    	jae    1400071af <__gdtoa+0xf05>
   140006d23:	e9 a6 04 00 00       	jmp    1400071ce <__gdtoa+0xf24>
   140006d28:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006d2f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d34:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006d39:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006d3d:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006d40:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d45:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d49:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006d4e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006d53:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006d57:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d5c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006d5f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006d62:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006d66:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006d6a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006d6e:	89 ca                	mov    edx,ecx
   140006d70:	88 10                	mov    BYTE PTR [rax],dl
   140006d72:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d77:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d7b:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d7f:	7a 0e                	jp     140006d8f <__gdtoa+0xae5>
   140006d81:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d85:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d89:	0f 84 da 00 00 00    	je     140006e69 <__gdtoa+0xbbf>
   140006d8f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006d92:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006d95:	0f 85 aa 00 00 00    	jne    140006e45 <__gdtoa+0xb9b>
   140006d9b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006d9f:	74 12                	je     140006db3 <__gdtoa+0xb09>
   140006da1:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006da5:	74 4b                	je     140006df2 <__gdtoa+0xb48>
   140006da7:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006dae:	e9 e3 09 00 00       	jmp    140007796 <__gdtoa+0x14ec>
   140006db3:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006db8:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006dbc:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006dc1:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006dc6:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006dcb:	77 28                	ja     140006df5 <__gdtoa+0xb4b>
   140006dcd:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006dd2:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006dd7:	7a 63                	jp     140006e3c <__gdtoa+0xb92>
   140006dd9:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006dde:	75 5c                	jne    140006e3c <__gdtoa+0xb92>
   140006de0:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006de3:	83 e0 01             	and    eax,0x1
   140006de6:	85 c0                	test   eax,eax
   140006de8:	74 52                	je     140006e3c <__gdtoa+0xb92>
   140006dea:	eb 0a                	jmp    140006df6 <__gdtoa+0xb4c>
   140006dec:	90                   	nop
   140006ded:	eb 07                	jmp    140006df6 <__gdtoa+0xb4c>
   140006def:	90                   	nop
   140006df0:	eb 04                	jmp    140006df6 <__gdtoa+0xb4c>
   140006df2:	90                   	nop
   140006df3:	eb 01                	jmp    140006df6 <__gdtoa+0xb4c>
   140006df5:	90                   	nop
   140006df6:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006dfd:	eb 17                	jmp    140006e16 <__gdtoa+0xb6c>
   140006dff:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e03:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006e07:	75 0d                	jne    140006e16 <__gdtoa+0xb6c>
   140006e09:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006e0d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e11:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006e14:	eb 10                	jmp    140006e26 <__gdtoa+0xb7c>
   140006e16:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006e1b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e1f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006e22:	3c 39                	cmp    al,0x39
   140006e24:	74 d9                	je     140006dff <__gdtoa+0xb55>
   140006e26:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e2a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006e2e:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006e32:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006e35:	83 c2 01             	add    edx,0x1
   140006e38:	88 10                	mov    BYTE PTR [rax],dl
   140006e3a:	eb 2e                	jmp    140006e6a <__gdtoa+0xbc0>
   140006e3c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e43:	eb 25                	jmp    140006e6a <__gdtoa+0xbc0>
   140006e45:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e48:	83 c0 01             	add    eax,0x1
   140006e4b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006e4e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006e53:	f2 0f 10 05 3d 45 00 	movsd  xmm0,QWORD PTR [rip+0x453d]        # 14000b398 <.rdata+0x48>
   140006e5a:	00 
   140006e5b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006e5f:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e64:	e9 c6 fe ff ff       	jmp    140006d2f <__gdtoa+0xa85>
   140006e69:	90                   	nop
   140006e6a:	e9 27 09 00 00       	jmp    140007796 <__gdtoa+0x14ec>
   140006e6f:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006e72:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006e75:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006e78:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006e7b:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006e82:	00 
   140006e83:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006e87:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006e8b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006e8f:	0f 84 e0 00 00 00    	je     140006f75 <__gdtoa+0xccb>
   140006e95:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006e98:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006e9b:	29 c2                	sub    edx,eax
   140006e9d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006ea0:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ea3:	8d 50 01             	lea    edx,[rax+0x1]
   140006ea6:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006ea9:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006eaf:	29 c2                	sub    edx,eax
   140006eb1:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006eb8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006ebb:	39 c2                	cmp    edx,eax
   140006ebd:	7d 43                	jge    140006f02 <__gdtoa+0xc58>
   140006ebf:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006ec6:	74 3a                	je     140006f02 <__gdtoa+0xc58>
   140006ec8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006ecf:	74 31                	je     140006f02 <__gdtoa+0xc58>
   140006ed1:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006ed8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006edb:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006ee1:	29 c2                	sub    edx,eax
   140006ee3:	8d 42 01             	lea    eax,[rdx+0x1]
   140006ee6:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006ee9:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006ef0:	7e 68                	jle    140006f5a <__gdtoa+0xcb0>
   140006ef2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006ef6:	7e 62                	jle    140006f5a <__gdtoa+0xcb0>
   140006ef8:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006efb:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006efe:	7d 5a                	jge    140006f5a <__gdtoa+0xcb0>
   140006f00:	eb 0a                	jmp    140006f0c <__gdtoa+0xc62>
   140006f02:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f09:	7e 50                	jle    140006f5b <__gdtoa+0xcb1>
   140006f0b:	90                   	nop
   140006f0c:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f0f:	83 e8 01             	sub    eax,0x1
   140006f12:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006f15:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006f18:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006f1b:	7c 08                	jl     140006f25 <__gdtoa+0xc7b>
   140006f1d:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f20:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006f23:	eb 19                	jmp    140006f3e <__gdtoa+0xc94>
   140006f25:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006f28:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006f2b:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f2e:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006f31:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f34:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006f37:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006f3e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f41:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f44:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f47:	85 c0                	test   eax,eax
   140006f49:	79 10                	jns    140006f5b <__gdtoa+0xcb1>
   140006f4b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f4e:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006f51:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006f58:	eb 01                	jmp    140006f5b <__gdtoa+0xcb1>
   140006f5a:	90                   	nop
   140006f5b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f5e:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140006f61:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f64:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140006f67:	b9 01 00 00 00       	mov    ecx,0x1
   140006f6c:	e8 f6 0f 00 00       	call   140007f67 <__i2b_D2A>
   140006f71:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f75:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140006f79:	7e 26                	jle    140006fa1 <__gdtoa+0xcf7>
   140006f7b:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   140006f7f:	7e 20                	jle    140006fa1 <__gdtoa+0xcf7>
   140006f81:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140006f84:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140006f87:	39 c2                	cmp    edx,eax
   140006f89:	0f 4e c2             	cmovle eax,edx
   140006f8c:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f8f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f92:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006f95:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f98:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006f9b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f9e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140006fa1:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140006fa5:	7e 7e                	jle    140007025 <__gdtoa+0xd7b>
   140006fa7:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006fab:	74 65                	je     140007012 <__gdtoa+0xd68>
   140006fad:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140006fb1:	7e 3b                	jle    140006fee <__gdtoa+0xd44>
   140006fb3:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140006fb6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006fba:	48 89 c1             	mov    rcx,rax
   140006fbd:	e8 11 12 00 00       	call   1400081d3 <__pow5mult_D2A>
   140006fc2:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006fc6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140006fca:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006fce:	48 89 c1             	mov    rcx,rax
   140006fd1:	e8 d7 0f 00 00       	call   140007fad <__mult_D2A>
   140006fd6:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140006fda:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006fde:	48 89 c1             	mov    rcx,rax
   140006fe1:	e8 c8 0d 00 00       	call   140007dae <__Bfree_D2A>
   140006fe6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006fea:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140006fee:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006ff1:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   140006ff4:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006ff7:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006ffb:	74 28                	je     140007025 <__gdtoa+0xd7b>
   140006ffd:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   140007000:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007004:	48 89 c1             	mov    rcx,rax
   140007007:	e8 c7 11 00 00       	call   1400081d3 <__pow5mult_D2A>
   14000700c:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007010:	eb 13                	jmp    140007025 <__gdtoa+0xd7b>
   140007012:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   140007015:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007019:	48 89 c1             	mov    rcx,rax
   14000701c:	e8 b2 11 00 00       	call   1400081d3 <__pow5mult_D2A>
   140007021:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007025:	b9 01 00 00 00       	mov    ecx,0x1
   14000702a:	e8 38 0f 00 00       	call   140007f67 <__i2b_D2A>
   14000702f:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007033:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007037:	7e 13                	jle    14000704c <__gdtoa+0xda2>
   140007039:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   14000703c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007040:	48 89 c1             	mov    rcx,rax
   140007043:	e8 8b 11 00 00       	call   1400081d3 <__pow5mult_D2A>
   140007048:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000704c:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   140007053:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000705a:	7f 29                	jg     140007085 <__gdtoa+0xddb>
   14000705c:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   14000705f:	83 f8 01             	cmp    eax,0x1
   140007062:	75 21                	jne    140007085 <__gdtoa+0xddb>
   140007064:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000706b:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000706e:	83 c0 01             	add    eax,0x1
   140007071:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140007074:	7e 0f                	jle    140007085 <__gdtoa+0xddb>
   140007076:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   14000707a:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   14000707e:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   140007085:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007089:	74 22                	je     1400070ad <__gdtoa+0xe03>
   14000708b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000708f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007092:	8d 50 ff             	lea    edx,[rax-0x1]
   140007095:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007099:	48 63 d2             	movsxd rdx,edx
   14000709c:	48 83 c2 04          	add    rdx,0x4
   1400070a0:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   1400070a4:	89 c1                	mov    ecx,eax
   1400070a6:	e8 c5 f0 ff ff       	call   140006170 <__hi0bits_D2A>
   1400070ab:	eb 05                	jmp    1400070b2 <__gdtoa+0xe08>
   1400070ad:	b8 1f 00 00 00       	mov    eax,0x1f
   1400070b2:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   1400070b5:	83 e8 04             	sub    eax,0x4
   1400070b8:	83 e0 1f             	and    eax,0x1f
   1400070bb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400070be:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400070c1:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   1400070c4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400070c7:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   1400070ca:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   1400070ce:	7e 13                	jle    1400070e3 <__gdtoa+0xe39>
   1400070d0:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   1400070d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070d7:	48 89 c1             	mov    rcx,rax
   1400070da:	e8 b1 12 00 00       	call   140008390 <__lshift_D2A>
   1400070df:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070e3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400070e6:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400070e9:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   1400070ed:	7e 13                	jle    140007102 <__gdtoa+0xe58>
   1400070ef:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   1400070f2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070f6:	48 89 c1             	mov    rcx,rax
   1400070f9:	e8 92 12 00 00       	call   140008390 <__lshift_D2A>
   1400070fe:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007102:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140007106:	74 5a                	je     140007162 <__gdtoa+0xeb8>
   140007108:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000710c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007110:	48 89 c1             	mov    rcx,rax
   140007113:	e8 05 14 00 00       	call   14000851d <__cmp_D2A>
   140007118:	85 c0                	test   eax,eax
   14000711a:	79 46                	jns    140007162 <__gdtoa+0xeb8>
   14000711c:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140007120:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007124:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000712a:	ba 0a 00 00 00       	mov    edx,0xa
   14000712f:	48 89 c1             	mov    rcx,rax
   140007132:	e8 02 0d 00 00       	call   140007e39 <__multadd_D2A>
   140007137:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000713b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000713f:	74 1b                	je     14000715c <__gdtoa+0xeb2>
   140007141:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007145:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000714b:	ba 0a 00 00 00       	mov    edx,0xa
   140007150:	48 89 c1             	mov    rcx,rax
   140007153:	e8 e1 0c 00 00       	call   140007e39 <__multadd_D2A>
   140007158:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000715c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000715f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140007162:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007166:	0f 8f 81 00 00 00    	jg     1400071ed <__gdtoa+0xf43>
   14000716c:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140007173:	7e 78                	jle    1400071ed <__gdtoa+0xf43>
   140007175:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007179:	78 37                	js     1400071b2 <__gdtoa+0xf08>
   14000717b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000717f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007185:	ba 05 00 00 00       	mov    edx,0x5
   14000718a:	48 89 c1             	mov    rcx,rax
   14000718d:	e8 a7 0c 00 00       	call   140007e39 <__multadd_D2A>
   140007192:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007196:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000719a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000719e:	48 89 c1             	mov    rcx,rax
   1400071a1:	e8 77 13 00 00       	call   14000851d <__cmp_D2A>
   1400071a6:	85 c0                	test   eax,eax
   1400071a8:	7f 23                	jg     1400071cd <__gdtoa+0xf23>
   1400071aa:	eb 07                	jmp    1400071b3 <__gdtoa+0xf09>
   1400071ac:	90                   	nop
   1400071ad:	eb 04                	jmp    1400071b3 <__gdtoa+0xf09>
   1400071af:	90                   	nop
   1400071b0:	eb 01                	jmp    1400071b3 <__gdtoa+0xf09>
   1400071b2:	90                   	nop
   1400071b3:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   1400071b9:	f7 d0                	not    eax
   1400071bb:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   1400071be:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400071c5:	e9 87 05 00 00       	jmp    140007751 <__gdtoa+0x14a7>
   1400071ca:	90                   	nop
   1400071cb:	eb 01                	jmp    1400071ce <__gdtoa+0xf24>
   1400071cd:	90                   	nop
   1400071ce:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400071d5:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400071d9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400071dd:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400071e1:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400071e4:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400071e8:	e9 64 05 00 00       	jmp    140007751 <__gdtoa+0x14a7>
   1400071ed:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400071f1:	0f 84 14 04 00 00    	je     14000760b <__gdtoa+0x1361>
   1400071f7:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   1400071fb:	7e 13                	jle    140007210 <__gdtoa+0xf66>
   1400071fd:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   140007200:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007204:	48 89 c1             	mov    rcx,rax
   140007207:	e8 84 11 00 00       	call   140008390 <__lshift_D2A>
   14000720c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007210:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007214:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007218:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   14000721c:	74 57                	je     140007275 <__gdtoa+0xfcb>
   14000721e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007222:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007225:	89 c1                	mov    ecx,eax
   140007227:	e8 41 0a 00 00       	call   140007c6d <__Balloc_D2A>
   14000722c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007230:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007234:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007237:	48 98                	cdqe
   140007239:	48 83 c0 02          	add    rax,0x2
   14000723d:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007244:	00 
   140007245:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007249:	48 8d 50 10          	lea    rdx,[rax+0x10]
   14000724d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007251:	48 83 c0 10          	add    rax,0x10
   140007255:	49 89 c8             	mov    r8,rcx
   140007258:	48 89 c1             	mov    rcx,rax
   14000725b:	e8 e8 23 00 00       	call   140009648 <memcpy>
   140007260:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007264:	ba 01 00 00 00       	mov    edx,0x1
   140007269:	48 89 c1             	mov    rcx,rax
   14000726c:	e8 1f 11 00 00       	call   140008390 <__lshift_D2A>
   140007271:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007275:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   14000727c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007280:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007284:	48 89 c1             	mov    rcx,rax
   140007287:	e8 62 ec ff ff       	call   140005eee <__quorem_D2A>
   14000728c:	83 c0 30             	add    eax,0x30
   14000728f:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007292:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007296:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000729a:	48 89 c1             	mov    rcx,rax
   14000729d:	e8 7b 12 00 00       	call   14000851d <__cmp_D2A>
   1400072a2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400072a5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400072a9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400072ad:	48 89 c1             	mov    rcx,rax
   1400072b0:	e8 38 13 00 00       	call   1400085ed <__diff_D2A>
   1400072b5:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400072b9:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   1400072bd:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400072c0:	85 c0                	test   eax,eax
   1400072c2:	75 15                	jne    1400072d9 <__gdtoa+0x102f>
   1400072c4:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   1400072c8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072cc:	48 89 c1             	mov    rcx,rax
   1400072cf:	e8 49 12 00 00       	call   14000851d <__cmp_D2A>
   1400072d4:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400072d7:	eb 07                	jmp    1400072e0 <__gdtoa+0x1036>
   1400072d9:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   1400072e0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   1400072e4:	48 89 c1             	mov    rcx,rax
   1400072e7:	e8 c2 0a 00 00       	call   140007dae <__Bfree_D2A>
   1400072ec:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400072f0:	75 70                	jne    140007362 <__gdtoa+0x10b8>
   1400072f2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400072f9:	75 67                	jne    140007362 <__gdtoa+0x10b8>
   1400072fb:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007302:	8b 00                	mov    eax,DWORD PTR [rax]
   140007304:	83 e0 01             	and    eax,0x1
   140007307:	85 c0                	test   eax,eax
   140007309:	75 57                	jne    140007362 <__gdtoa+0x10b8>
   14000730b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000730f:	75 51                	jne    140007362 <__gdtoa+0x10b8>
   140007311:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007315:	0f 84 01 02 00 00    	je     14000751c <__gdtoa+0x1272>
   14000731b:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000731f:	7f 20                	jg     140007341 <__gdtoa+0x1097>
   140007321:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007325:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007328:	83 f8 01             	cmp    eax,0x1
   14000732b:	7f 0b                	jg     140007338 <__gdtoa+0x108e>
   14000732d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007331:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007334:	85 c0                	test   eax,eax
   140007336:	74 14                	je     14000734c <__gdtoa+0x10a2>
   140007338:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000733f:	eb 0b                	jmp    14000734c <__gdtoa+0x10a2>
   140007341:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   140007345:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   14000734c:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007350:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007354:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007358:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000735b:	88 10                	mov    BYTE PTR [rax],dl
   14000735d:	e9 ef 03 00 00       	jmp    140007751 <__gdtoa+0x14a7>
   140007362:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007366:	78 2b                	js     140007393 <__gdtoa+0x10e9>
   140007368:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000736c:	0f 85 96 01 00 00    	jne    140007508 <__gdtoa+0x125e>
   140007372:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007379:	0f 85 89 01 00 00    	jne    140007508 <__gdtoa+0x125e>
   14000737f:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007386:	8b 00                	mov    eax,DWORD PTR [rax]
   140007388:	83 e0 01             	and    eax,0x1
   14000738b:	85 c0                	test   eax,eax
   14000738d:	0f 85 75 01 00 00    	jne    140007508 <__gdtoa+0x125e>
   140007393:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007397:	0f 84 db 00 00 00    	je     140007478 <__gdtoa+0x11ce>
   14000739d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073a1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400073a4:	83 f8 01             	cmp    eax,0x1
   1400073a7:	7f 0f                	jg     1400073b8 <__gdtoa+0x110e>
   1400073a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073ad:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400073b0:	85 c0                	test   eax,eax
   1400073b2:	0f 84 c0 00 00 00    	je     140007478 <__gdtoa+0x11ce>
   1400073b8:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400073bc:	0f 85 83 00 00 00    	jne    140007445 <__gdtoa+0x119b>
   1400073c2:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400073c9:	e9 24 01 00 00       	jmp    1400074f2 <__gdtoa+0x1248>
   1400073ce:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400073d2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400073d6:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400073da:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400073dd:	88 10                	mov    BYTE PTR [rax],dl
   1400073df:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400073e3:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400073e9:	ba 0a 00 00 00       	mov    edx,0xa
   1400073ee:	48 89 c1             	mov    rcx,rax
   1400073f1:	e8 43 0a 00 00       	call   140007e39 <__multadd_D2A>
   1400073f6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400073fa:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400073fe:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007402:	75 08                	jne    14000740c <__gdtoa+0x1162>
   140007404:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007408:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   14000740c:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007410:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007414:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007418:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000741e:	ba 0a 00 00 00       	mov    edx,0xa
   140007423:	48 89 c1             	mov    rcx,rax
   140007426:	e8 0e 0a 00 00       	call   140007e39 <__multadd_D2A>
   14000742b:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000742f:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007433:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007437:	48 89 c1             	mov    rcx,rax
   14000743a:	e8 af ea ff ff       	call   140005eee <__quorem_D2A>
   14000743f:	83 c0 30             	add    eax,0x30
   140007442:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007445:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007449:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000744d:	48 89 c1             	mov    rcx,rax
   140007450:	e8 c8 10 00 00       	call   14000851d <__cmp_D2A>
   140007455:	85 c0                	test   eax,eax
   140007457:	0f 8f 71 ff ff ff    	jg     1400073ce <__gdtoa+0x1124>
   14000745d:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007460:	8d 50 01             	lea    edx,[rax+0x1]
   140007463:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007466:	83 f8 39             	cmp    eax,0x39
   140007469:	0f 84 b0 00 00 00    	je     14000751f <__gdtoa+0x1275>
   14000746f:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007476:	eb 7a                	jmp    1400074f2 <__gdtoa+0x1248>
   140007478:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000747c:	7e 53                	jle    1400074d1 <__gdtoa+0x1227>
   14000747e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007482:	ba 01 00 00 00       	mov    edx,0x1
   140007487:	48 89 c1             	mov    rcx,rax
   14000748a:	e8 01 0f 00 00       	call   140008390 <__lshift_D2A>
   14000748f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007493:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007497:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000749b:	48 89 c1             	mov    rcx,rax
   14000749e:	e8 7a 10 00 00       	call   14000851d <__cmp_D2A>
   1400074a3:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400074a6:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074aa:	7f 10                	jg     1400074bc <__gdtoa+0x1212>
   1400074ac:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074b0:	75 18                	jne    1400074ca <__gdtoa+0x1220>
   1400074b2:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400074b5:	83 e0 01             	and    eax,0x1
   1400074b8:	85 c0                	test   eax,eax
   1400074ba:	74 0e                	je     1400074ca <__gdtoa+0x1220>
   1400074bc:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400074bf:	8d 50 01             	lea    edx,[rax+0x1]
   1400074c2:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   1400074c5:	83 f8 39             	cmp    eax,0x39
   1400074c8:	74 58                	je     140007522 <__gdtoa+0x1278>
   1400074ca:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400074d1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074d5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400074d8:	83 f8 01             	cmp    eax,0x1
   1400074db:	7f 0b                	jg     1400074e8 <__gdtoa+0x123e>
   1400074dd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074e1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400074e4:	85 c0                	test   eax,eax
   1400074e6:	74 09                	je     1400074f1 <__gdtoa+0x1247>
   1400074e8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400074ef:	eb 01                	jmp    1400074f2 <__gdtoa+0x1248>
   1400074f1:	90                   	nop
   1400074f2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400074f6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400074fa:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400074fe:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007501:	88 10                	mov    BYTE PTR [rax],dl
   140007503:	e9 49 02 00 00       	jmp    140007751 <__gdtoa+0x14a7>
   140007508:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000750c:	7e 52                	jle    140007560 <__gdtoa+0x12b6>
   14000750e:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007512:	74 4c                	je     140007560 <__gdtoa+0x12b6>
   140007514:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007518:	75 24                	jne    14000753e <__gdtoa+0x1294>
   14000751a:	eb 07                	jmp    140007523 <__gdtoa+0x1279>
   14000751c:	90                   	nop
   14000751d:	eb 04                	jmp    140007523 <__gdtoa+0x1279>
   14000751f:	90                   	nop
   140007520:	eb 01                	jmp    140007523 <__gdtoa+0x1279>
   140007522:	90                   	nop
   140007523:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007527:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000752b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000752f:	c6 00 39             	mov    BYTE PTR [rax],0x39
   140007532:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007539:	e9 9d 01 00 00       	jmp    1400076db <__gdtoa+0x1431>
   14000753e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007545:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007548:	8d 48 01             	lea    ecx,[rax+0x1]
   14000754b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000754f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007553:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007557:	89 ca                	mov    edx,ecx
   140007559:	88 10                	mov    BYTE PTR [rax],dl
   14000755b:	e9 f1 01 00 00       	jmp    140007751 <__gdtoa+0x14a7>
   140007560:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007564:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007568:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000756c:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000756f:	88 10                	mov    BYTE PTR [rax],dl
   140007571:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007574:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140007577:	0f 84 ea 00 00 00    	je     140007667 <__gdtoa+0x13bd>
   14000757d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007581:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007587:	ba 0a 00 00 00       	mov    edx,0xa
   14000758c:	48 89 c1             	mov    rcx,rax
   14000758f:	e8 a5 08 00 00       	call   140007e39 <__multadd_D2A>
   140007594:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007598:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000759c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400075a0:	75 25                	jne    1400075c7 <__gdtoa+0x131d>
   1400075a2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400075a6:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075ac:	ba 0a 00 00 00       	mov    edx,0xa
   1400075b1:	48 89 c1             	mov    rcx,rax
   1400075b4:	e8 80 08 00 00       	call   140007e39 <__multadd_D2A>
   1400075b9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400075bd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400075c1:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400075c5:	eb 36                	jmp    1400075fd <__gdtoa+0x1353>
   1400075c7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400075cb:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075d1:	ba 0a 00 00 00       	mov    edx,0xa
   1400075d6:	48 89 c1             	mov    rcx,rax
   1400075d9:	e8 5b 08 00 00       	call   140007e39 <__multadd_D2A>
   1400075de:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400075e2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400075e6:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075ec:	ba 0a 00 00 00       	mov    edx,0xa
   1400075f1:	48 89 c1             	mov    rcx,rax
   1400075f4:	e8 40 08 00 00       	call   140007e39 <__multadd_D2A>
   1400075f9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400075fd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007600:	83 c0 01             	add    eax,0x1
   140007603:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007606:	e9 71 fc ff ff       	jmp    14000727c <__gdtoa+0xfd2>
   14000760b:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140007612:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007616:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000761a:	48 89 c1             	mov    rcx,rax
   14000761d:	e8 cc e8 ff ff       	call   140005eee <__quorem_D2A>
   140007622:	83 c0 30             	add    eax,0x30
   140007625:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007628:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000762c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007630:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007634:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007637:	88 10                	mov    BYTE PTR [rax],dl
   140007639:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000763c:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   14000763f:	7e 29                	jle    14000766a <__gdtoa+0x13c0>
   140007641:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007645:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000764b:	ba 0a 00 00 00       	mov    edx,0xa
   140007650:	48 89 c1             	mov    rcx,rax
   140007653:	e8 e1 07 00 00       	call   140007e39 <__multadd_D2A>
   140007658:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000765c:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000765f:	83 c0 01             	add    eax,0x1
   140007662:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007665:	eb ab                	jmp    140007612 <__gdtoa+0x1368>
   140007667:	90                   	nop
   140007668:	eb 01                	jmp    14000766b <__gdtoa+0x13c1>
   14000766a:	90                   	nop
   14000766b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000766f:	74 26                	je     140007697 <__gdtoa+0x13ed>
   140007671:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007675:	0f 84 ae 00 00 00    	je     140007729 <__gdtoa+0x147f>
   14000767b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000767f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007682:	83 f8 01             	cmp    eax,0x1
   140007685:	7f 50                	jg     1400076d7 <__gdtoa+0x142d>
   140007687:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000768b:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000768e:	85 c0                	test   eax,eax
   140007690:	75 45                	jne    1400076d7 <__gdtoa+0x142d>
   140007692:	e9 92 00 00 00       	jmp    140007729 <__gdtoa+0x147f>
   140007697:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000769b:	ba 01 00 00 00       	mov    edx,0x1
   1400076a0:	48 89 c1             	mov    rcx,rax
   1400076a3:	e8 e8 0c 00 00       	call   140008390 <__lshift_D2A>
   1400076a8:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400076ac:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400076b0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076b4:	48 89 c1             	mov    rcx,rax
   1400076b7:	e8 61 0e 00 00       	call   14000851d <__cmp_D2A>
   1400076bc:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400076bf:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400076c3:	7f 15                	jg     1400076da <__gdtoa+0x1430>
   1400076c5:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400076c9:	75 61                	jne    14000772c <__gdtoa+0x1482>
   1400076cb:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400076ce:	83 e0 01             	and    eax,0x1
   1400076d1:	85 c0                	test   eax,eax
   1400076d3:	74 5a                	je     14000772f <__gdtoa+0x1485>
   1400076d5:	eb 04                	jmp    1400076db <__gdtoa+0x1431>
   1400076d7:	90                   	nop
   1400076d8:	eb 01                	jmp    1400076db <__gdtoa+0x1431>
   1400076da:	90                   	nop
   1400076db:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400076e2:	eb 1f                	jmp    140007703 <__gdtoa+0x1459>
   1400076e4:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076e8:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400076ec:	75 15                	jne    140007703 <__gdtoa+0x1459>
   1400076ee:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400076f2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076f6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076fa:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076fe:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007701:	eb 4e                	jmp    140007751 <__gdtoa+0x14a7>
   140007703:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140007708:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000770c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000770f:	3c 39                	cmp    al,0x39
   140007711:	74 d1                	je     1400076e4 <__gdtoa+0x143a>
   140007713:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007717:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000771b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000771f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140007722:	83 c2 01             	add    edx,0x1
   140007725:	88 10                	mov    BYTE PTR [rax],dl
   140007727:	eb 28                	jmp    140007751 <__gdtoa+0x14a7>
   140007729:	90                   	nop
   14000772a:	eb 04                	jmp    140007730 <__gdtoa+0x1486>
   14000772c:	90                   	nop
   14000772d:	eb 01                	jmp    140007730 <__gdtoa+0x1486>
   14000772f:	90                   	nop
   140007730:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007734:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007737:	83 f8 01             	cmp    eax,0x1
   14000773a:	7f 0b                	jg     140007747 <__gdtoa+0x149d>
   14000773c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007740:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007743:	85 c0                	test   eax,eax
   140007745:	74 09                	je     140007750 <__gdtoa+0x14a6>
   140007747:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000774e:	eb 01                	jmp    140007751 <__gdtoa+0x14a7>
   140007750:	90                   	nop
   140007751:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007755:	48 89 c1             	mov    rcx,rax
   140007758:	e8 51 06 00 00       	call   140007dae <__Bfree_D2A>
   14000775d:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140007762:	74 31                	je     140007795 <__gdtoa+0x14eb>
   140007764:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140007769:	74 16                	je     140007781 <__gdtoa+0x14d7>
   14000776b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000776f:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007773:	74 0c                	je     140007781 <__gdtoa+0x14d7>
   140007775:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007779:	48 89 c1             	mov    rcx,rax
   14000777c:	e8 2d 06 00 00       	call   140007dae <__Bfree_D2A>
   140007781:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007785:	48 89 c1             	mov    rcx,rax
   140007788:	e8 21 06 00 00       	call   140007dae <__Bfree_D2A>
   14000778d:	eb 0e                	jmp    14000779d <__gdtoa+0x14f3>
   14000778f:	90                   	nop
   140007790:	eb 0b                	jmp    14000779d <__gdtoa+0x14f3>
   140007792:	90                   	nop
   140007793:	eb 08                	jmp    14000779d <__gdtoa+0x14f3>
   140007795:	90                   	nop
   140007796:	eb 05                	jmp    14000779d <__gdtoa+0x14f3>
   140007798:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000779d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077a1:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   1400077a5:	73 0f                	jae    1400077b6 <__gdtoa+0x150c>
   1400077a7:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077ab:	48 83 e8 01          	sub    rax,0x1
   1400077af:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400077b2:	3c 30                	cmp    al,0x30
   1400077b4:	74 e2                	je     140007798 <__gdtoa+0x14ee>
   1400077b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077ba:	48 89 c1             	mov    rcx,rax
   1400077bd:	e8 ec 05 00 00       	call   140007dae <__Bfree_D2A>
   1400077c2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077c6:	c6 00 00             	mov    BYTE PTR [rax],0x0
   1400077c9:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400077cc:	8d 50 01             	lea    edx,[rax+0x1]
   1400077cf:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400077d6:	89 10                	mov    DWORD PTR [rax],edx
   1400077d8:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   1400077df:	00 
   1400077e0:	74 0e                	je     1400077f0 <__gdtoa+0x1546>
   1400077e2:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400077e9:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   1400077ed:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400077f0:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400077f7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400077f9:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   1400077fc:	89 c2                	mov    edx,eax
   1400077fe:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007805:	89 10                	mov    DWORD PTR [rax],edx
   140007807:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000780b:	48 81 c4 00 01 00 00 	add    rsp,0x100
   140007812:	5d                   	pop    rbp
   140007813:	c3                   	ret
   140007814:	90                   	nop
   140007815:	90                   	nop
   140007816:	90                   	nop
   140007817:	90                   	nop
   140007818:	90                   	nop
   140007819:	90                   	nop
   14000781a:	90                   	nop
   14000781b:	90                   	nop
   14000781c:	90                   	nop
   14000781d:	90                   	nop
   14000781e:	90                   	nop
   14000781f:	90                   	nop

0000000140007820 <__lo0bits_D2A>:
   140007820:	55                   	push   rbp
   140007821:	48 89 e5             	mov    rbp,rsp
   140007824:	48 83 ec 10          	sub    rsp,0x10
   140007828:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000782c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007830:	8b 00                	mov    eax,DWORD PTR [rax]
   140007832:	f3 0f bc c0          	tzcnt  eax,eax
   140007836:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007839:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000783d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000783f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007842:	89 c1                	mov    ecx,eax
   140007844:	d3 ea                	shr    edx,cl
   140007846:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000784a:	89 10                	mov    DWORD PTR [rax],edx
   14000784c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000784f:	48 83 c4 10          	add    rsp,0x10
   140007853:	5d                   	pop    rbp
   140007854:	c3                   	ret

0000000140007855 <__rshift_D2A>:
   140007855:	55                   	push   rbp
   140007856:	48 89 e5             	mov    rbp,rsp
   140007859:	48 83 ec 20          	sub    rsp,0x20
   14000785d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007861:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007864:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007868:	48 83 c0 18          	add    rax,0x18
   14000786c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007870:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007874:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007878:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000787b:	c1 f8 05             	sar    eax,0x5
   14000787e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007881:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007885:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007888:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   14000788b:	0f 8d e4 00 00 00    	jge    140007975 <__rshift_D2A+0x120>
   140007891:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007895:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007898:	48 98                	cdqe
   14000789a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400078a1:	00 
   1400078a2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078a6:	48 01 d0             	add    rax,rdx
   1400078a9:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400078ad:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400078b0:	48 98                	cdqe
   1400078b2:	48 c1 e0 02          	shl    rax,0x2
   1400078b6:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   1400078ba:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   1400078be:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400078c2:	0f 84 a3 00 00 00    	je     14000796b <__rshift_D2A+0x116>
   1400078c8:	b8 20 00 00 00       	mov    eax,0x20
   1400078cd:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400078d0:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400078d3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078d7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400078db:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400078df:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078e1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400078e4:	89 c1                	mov    ecx,eax
   1400078e6:	d3 ea                	shr    edx,cl
   1400078e8:	89 d0                	mov    eax,edx
   1400078ea:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400078ed:	eb 3c                	jmp    14000792b <__rshift_D2A+0xd6>
   1400078ef:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078f3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078f5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400078f8:	89 c1                	mov    ecx,eax
   1400078fa:	d3 e2                	shl    edx,cl
   1400078fc:	89 d1                	mov    ecx,edx
   1400078fe:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007902:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007906:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000790a:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   14000790d:	89 ca                	mov    edx,ecx
   14000790f:	89 10                	mov    DWORD PTR [rax],edx
   140007911:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007915:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007919:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000791d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000791f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007922:	89 c1                	mov    ecx,eax
   140007924:	d3 ea                	shr    edx,cl
   140007926:	89 d0                	mov    eax,edx
   140007928:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000792b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000792f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007933:	72 ba                	jb     1400078ef <__rshift_D2A+0x9a>
   140007935:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007939:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   14000793c:	89 10                	mov    DWORD PTR [rax],edx
   14000793e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007942:	8b 00                	mov    eax,DWORD PTR [rax]
   140007944:	85 c0                	test   eax,eax
   140007946:	74 2d                	je     140007975 <__rshift_D2A+0x120>
   140007948:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   14000794d:	eb 26                	jmp    140007975 <__rshift_D2A+0x120>
   14000794f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140007953:	48 8d 42 04          	lea    rax,[rdx+0x4]
   140007957:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000795b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000795f:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140007963:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   140007967:	8b 12                	mov    edx,DWORD PTR [rdx]
   140007969:	89 10                	mov    DWORD PTR [rax],edx
   14000796b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000796f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007973:	72 da                	jb     14000794f <__rshift_D2A+0xfa>
   140007975:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007979:	48 83 c0 18          	add    rax,0x18
   14000797d:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140007981:	48 29 c2             	sub    rdx,rax
   140007984:	48 89 d0             	mov    rax,rdx
   140007987:	48 c1 f8 02          	sar    rax,0x2
   14000798b:	89 c2                	mov    edx,eax
   14000798d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007991:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007994:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007998:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000799b:	85 c0                	test   eax,eax
   14000799d:	75 0b                	jne    1400079aa <__rshift_D2A+0x155>
   14000799f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079a3:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   1400079aa:	90                   	nop
   1400079ab:	48 83 c4 20          	add    rsp,0x20
   1400079af:	5d                   	pop    rbp
   1400079b0:	c3                   	ret

00000001400079b1 <__trailz_D2A>:
   1400079b1:	55                   	push   rbp
   1400079b2:	48 89 e5             	mov    rbp,rsp
   1400079b5:	48 83 ec 40          	sub    rsp,0x40
   1400079b9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400079bd:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400079c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079c8:	48 83 c0 18          	add    rax,0x18
   1400079cc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400079d0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079d4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400079d7:	48 98                	cdqe
   1400079d9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400079e0:	00 
   1400079e1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079e5:	48 01 d0             	add    rax,rdx
   1400079e8:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400079ec:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400079f3:	eb 09                	jmp    1400079fe <__trailz_D2A+0x4d>
   1400079f5:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   1400079f9:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   1400079fe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a02:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a06:	73 0a                	jae    140007a12 <__trailz_D2A+0x61>
   140007a08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a0c:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a0e:	85 c0                	test   eax,eax
   140007a10:	74 e3                	je     1400079f5 <__trailz_D2A+0x44>
   140007a12:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a16:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a1a:	73 18                	jae    140007a34 <__trailz_D2A+0x83>
   140007a1c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a20:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a22:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007a25:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007a29:	48 89 c1             	mov    rcx,rax
   140007a2c:	e8 ef fd ff ff       	call   140007820 <__lo0bits_D2A>
   140007a31:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007a34:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007a37:	48 83 c4 40          	add    rsp,0x40
   140007a3b:	5d                   	pop    rbp
   140007a3c:	c3                   	ret
   140007a3d:	90                   	nop
   140007a3e:	90                   	nop
   140007a3f:	90                   	nop

0000000140007a40 <dtoa_lock_cleanup>:
   140007a40:	55                   	push   rbp
   140007a41:	48 89 e5             	mov    rbp,rsp
   140007a44:	48 83 ec 40          	sub    rsp,0x40
   140007a48:	48 8d 05 a1 77 00 00 	lea    rax,[rip+0x77a1]        # 14000f1f0 <dtoa_CS_init>
   140007a4f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007a53:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007a5a:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007a5d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a61:	87 10                	xchg   DWORD PTR [rax],edx
   140007a63:	89 d0                	mov    eax,edx
   140007a65:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007a68:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007a6c:	75 3d                	jne    140007aab <dtoa_lock_cleanup+0x6b>
   140007a6e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007a75:	eb 2e                	jmp    140007aa5 <dtoa_lock_cleanup+0x65>
   140007a77:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007a7a:	48 63 d0             	movsxd rdx,eax
   140007a7d:	48 89 d0             	mov    rax,rdx
   140007a80:	48 c1 e0 02          	shl    rax,0x2
   140007a84:	48 01 d0             	add    rax,rdx
   140007a87:	48 c1 e0 03          	shl    rax,0x3
   140007a8b:	48 8d 15 0e 77 00 00 	lea    rdx,[rip+0x770e]        # 14000f1a0 <dtoa_CritSec>
   140007a92:	48 01 d0             	add    rax,rdx
   140007a95:	48 89 c1             	mov    rcx,rax
   140007a98:	48 8b 05 51 87 00 00 	mov    rax,QWORD PTR [rip+0x8751]        # 1400101f0 <__IAT_start__>
   140007a9f:	ff d0                	call   rax
   140007aa1:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007aa5:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007aa9:	7e cc                	jle    140007a77 <dtoa_lock_cleanup+0x37>
   140007aab:	90                   	nop
   140007aac:	48 83 c4 40          	add    rsp,0x40
   140007ab0:	5d                   	pop    rbp
   140007ab1:	c3                   	ret

0000000140007ab2 <dtoa_lock>:
   140007ab2:	55                   	push   rbp
   140007ab3:	48 89 e5             	mov    rbp,rsp
   140007ab6:	48 83 ec 40          	sub    rsp,0x40
   140007aba:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007abd:	8b 05 2d 77 00 00    	mov    eax,DWORD PTR [rip+0x772d]        # 14000f1f0 <dtoa_CS_init>
   140007ac3:	83 f8 02             	cmp    eax,0x2
   140007ac6:	75 2c                	jne    140007af4 <dtoa_lock+0x42>
   140007ac8:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007acb:	48 89 d0             	mov    rax,rdx
   140007ace:	48 c1 e0 02          	shl    rax,0x2
   140007ad2:	48 01 d0             	add    rax,rdx
   140007ad5:	48 c1 e0 03          	shl    rax,0x3
   140007ad9:	48 8d 15 c0 76 00 00 	lea    rdx,[rip+0x76c0]        # 14000f1a0 <dtoa_CritSec>
   140007ae0:	48 01 d0             	add    rax,rdx
   140007ae3:	48 89 c1             	mov    rcx,rax
   140007ae6:	48 8b 05 0b 87 00 00 	mov    rax,QWORD PTR [rip+0x870b]        # 1400101f8 <__imp_EnterCriticalSection>
   140007aed:	ff d0                	call   rax
   140007aef:	e9 ea 00 00 00       	jmp    140007bde <dtoa_lock+0x12c>
   140007af4:	8b 05 f6 76 00 00    	mov    eax,DWORD PTR [rip+0x76f6]        # 14000f1f0 <dtoa_CS_init>
   140007afa:	85 c0                	test   eax,eax
   140007afc:	0f 85 9e 00 00 00    	jne    140007ba0 <dtoa_lock+0xee>
   140007b02:	48 8d 05 e7 76 00 00 	lea    rax,[rip+0x76e7]        # 14000f1f0 <dtoa_CS_init>
   140007b09:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007b0d:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007b14:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007b17:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007b1b:	87 10                	xchg   DWORD PTR [rax],edx
   140007b1d:	89 d0                	mov    eax,edx
   140007b1f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007b22:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007b26:	75 58                	jne    140007b80 <dtoa_lock+0xce>
   140007b28:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007b2f:	eb 2e                	jmp    140007b5f <dtoa_lock+0xad>
   140007b31:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007b34:	48 63 d0             	movsxd rdx,eax
   140007b37:	48 89 d0             	mov    rax,rdx
   140007b3a:	48 c1 e0 02          	shl    rax,0x2
   140007b3e:	48 01 d0             	add    rax,rdx
   140007b41:	48 c1 e0 03          	shl    rax,0x3
   140007b45:	48 8d 15 54 76 00 00 	lea    rdx,[rip+0x7654]        # 14000f1a0 <dtoa_CritSec>
   140007b4c:	48 01 d0             	add    rax,rdx
   140007b4f:	48 89 c1             	mov    rcx,rax
   140007b52:	48 8b 05 cf 86 00 00 	mov    rax,QWORD PTR [rip+0x86cf]        # 140010228 <__imp_InitializeCriticalSection>
   140007b59:	ff d0                	call   rax
   140007b5b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b5f:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b63:	7e cc                	jle    140007b31 <dtoa_lock+0x7f>
   140007b65:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007a40 <dtoa_lock_cleanup>
   140007b6c:	48 89 c1             	mov    rcx,rax
   140007b6f:	e8 bb 9a ff ff       	call   14000162f <atexit>
   140007b74:	c7 05 72 76 00 00 02 	mov    DWORD PTR [rip+0x7672],0x2        # 14000f1f0 <dtoa_CS_init>
   140007b7b:	00 00 00 
   140007b7e:	eb 20                	jmp    140007ba0 <dtoa_lock+0xee>
   140007b80:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007b84:	75 1a                	jne    140007ba0 <dtoa_lock+0xee>
   140007b86:	c7 05 60 76 00 00 02 	mov    DWORD PTR [rip+0x7660],0x2        # 14000f1f0 <dtoa_CS_init>
   140007b8d:	00 00 00 
   140007b90:	eb 0e                	jmp    140007ba0 <dtoa_lock+0xee>
   140007b92:	b9 01 00 00 00       	mov    ecx,0x1
   140007b97:	48 8b 05 b2 86 00 00 	mov    rax,QWORD PTR [rip+0x86b2]        # 140010250 <__imp_Sleep>
   140007b9e:	ff d0                	call   rax
   140007ba0:	8b 05 4a 76 00 00    	mov    eax,DWORD PTR [rip+0x764a]        # 14000f1f0 <dtoa_CS_init>
   140007ba6:	83 f8 01             	cmp    eax,0x1
   140007ba9:	74 e7                	je     140007b92 <dtoa_lock+0xe0>
   140007bab:	8b 05 3f 76 00 00    	mov    eax,DWORD PTR [rip+0x763f]        # 14000f1f0 <dtoa_CS_init>
   140007bb1:	83 f8 02             	cmp    eax,0x2
   140007bb4:	75 28                	jne    140007bde <dtoa_lock+0x12c>
   140007bb6:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007bb9:	48 89 d0             	mov    rax,rdx
   140007bbc:	48 c1 e0 02          	shl    rax,0x2
   140007bc0:	48 01 d0             	add    rax,rdx
   140007bc3:	48 c1 e0 03          	shl    rax,0x3
   140007bc7:	48 8d 15 d2 75 00 00 	lea    rdx,[rip+0x75d2]        # 14000f1a0 <dtoa_CritSec>
   140007bce:	48 01 d0             	add    rax,rdx
   140007bd1:	48 89 c1             	mov    rcx,rax
   140007bd4:	48 8b 05 1d 86 00 00 	mov    rax,QWORD PTR [rip+0x861d]        # 1400101f8 <__imp_EnterCriticalSection>
   140007bdb:	ff d0                	call   rax
   140007bdd:	90                   	nop
   140007bde:	48 83 c4 40          	add    rsp,0x40
   140007be2:	5d                   	pop    rbp
   140007be3:	c3                   	ret

0000000140007be4 <dtoa_unlock>:
   140007be4:	55                   	push   rbp
   140007be5:	48 89 e5             	mov    rbp,rsp
   140007be8:	48 83 ec 20          	sub    rsp,0x20
   140007bec:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007bef:	8b 05 fb 75 00 00    	mov    eax,DWORD PTR [rip+0x75fb]        # 14000f1f0 <dtoa_CS_init>
   140007bf5:	83 f8 02             	cmp    eax,0x2
   140007bf8:	75 27                	jne    140007c21 <dtoa_unlock+0x3d>
   140007bfa:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007bfd:	48 89 d0             	mov    rax,rdx
   140007c00:	48 c1 e0 02          	shl    rax,0x2
   140007c04:	48 01 d0             	add    rax,rdx
   140007c07:	48 c1 e0 03          	shl    rax,0x3
   140007c0b:	48 8d 15 8e 75 00 00 	lea    rdx,[rip+0x758e]        # 14000f1a0 <dtoa_CritSec>
   140007c12:	48 01 d0             	add    rax,rdx
   140007c15:	48 89 c1             	mov    rcx,rax
   140007c18:	48 8b 05 11 86 00 00 	mov    rax,QWORD PTR [rip+0x8611]        # 140010230 <__imp_LeaveCriticalSection>
   140007c1f:	ff d0                	call   rax
   140007c21:	90                   	nop
   140007c22:	48 83 c4 20          	add    rsp,0x20
   140007c26:	5d                   	pop    rbp
   140007c27:	c3                   	ret

0000000140007c28 <__lo0bits_D2A>:
   140007c28:	55                   	push   rbp
   140007c29:	48 89 e5             	mov    rbp,rsp
   140007c2c:	48 83 ec 10          	sub    rsp,0x10
   140007c30:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007c34:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c38:	8b 00                	mov    eax,DWORD PTR [rax]
   140007c3a:	f3 0f bc c0          	tzcnt  eax,eax
   140007c3e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007c41:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c45:	8b 10                	mov    edx,DWORD PTR [rax]
   140007c47:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c4a:	89 c1                	mov    ecx,eax
   140007c4c:	d3 ea                	shr    edx,cl
   140007c4e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c52:	89 10                	mov    DWORD PTR [rax],edx
   140007c54:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c57:	48 83 c4 10          	add    rsp,0x10
   140007c5b:	5d                   	pop    rbp
   140007c5c:	c3                   	ret

0000000140007c5d <__hi0bits_D2A>:
   140007c5d:	55                   	push   rbp
   140007c5e:	48 89 e5             	mov    rbp,rsp
   140007c61:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c64:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007c68:	83 f0 1f             	xor    eax,0x1f
   140007c6b:	5d                   	pop    rbp
   140007c6c:	c3                   	ret

0000000140007c6d <__Balloc_D2A>:
   140007c6d:	55                   	push   rbp
   140007c6e:	48 89 e5             	mov    rbp,rsp
   140007c71:	48 83 ec 30          	sub    rsp,0x30
   140007c75:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c78:	b9 00 00 00 00       	mov    ecx,0x0
   140007c7d:	e8 30 fe ff ff       	call   140007ab2 <dtoa_lock>
   140007c82:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007c86:	7f 48                	jg     140007cd0 <__Balloc_D2A+0x63>
   140007c88:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007c8b:	48 98                	cdqe
   140007c8d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007c94:	00 
   140007c95:	48 8d 05 64 75 00 00 	lea    rax,[rip+0x7564]        # 14000f200 <freelist>
   140007c9c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007ca0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007ca4:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007ca9:	74 25                	je     140007cd0 <__Balloc_D2A+0x63>
   140007cab:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007caf:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007cb2:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007cb5:	48 63 d2             	movsxd rdx,edx
   140007cb8:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007cbf:	00 
   140007cc0:	48 8d 15 39 75 00 00 	lea    rdx,[rip+0x7539]        # 14000f200 <freelist>
   140007cc7:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007ccb:	e9 b1 00 00 00       	jmp    140007d81 <__Balloc_D2A+0x114>
   140007cd0:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007cd3:	ba 01 00 00 00       	mov    edx,0x1
   140007cd8:	89 c1                	mov    ecx,eax
   140007cda:	d3 e2                	shl    edx,cl
   140007cdc:	89 d0                	mov    eax,edx
   140007cde:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007ce1:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007ce4:	83 e8 01             	sub    eax,0x1
   140007ce7:	48 98                	cdqe
   140007ce9:	48 c1 e0 02          	shl    rax,0x2
   140007ced:	48 83 c0 27          	add    rax,0x27
   140007cf1:	48 c1 e8 03          	shr    rax,0x3
   140007cf5:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007cf8:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007cfc:	7f 4e                	jg     140007d4c <__Balloc_D2A+0xdf>
   140007cfe:	48 8b 15 8b 23 00 00 	mov    rdx,QWORD PTR [rip+0x238b]        # 14000a090 <pmem_next>
   140007d05:	48 8d 05 54 75 00 00 	lea    rax,[rip+0x7554]        # 14000f260 <private_mem>
   140007d0c:	48 29 c2             	sub    rdx,rax
   140007d0f:	48 89 d0             	mov    rax,rdx
   140007d12:	48 c1 f8 03          	sar    rax,0x3
   140007d16:	48 89 c2             	mov    rdx,rax
   140007d19:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d1c:	48 01 d0             	add    rax,rdx
   140007d1f:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007d25:	77 25                	ja     140007d4c <__Balloc_D2A+0xdf>
   140007d27:	48 8b 05 62 23 00 00 	mov    rax,QWORD PTR [rip+0x2362]        # 14000a090 <pmem_next>
   140007d2e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d32:	48 8b 05 57 23 00 00 	mov    rax,QWORD PTR [rip+0x2357]        # 14000a090 <pmem_next>
   140007d39:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007d3c:	48 c1 e2 03          	shl    rdx,0x3
   140007d40:	48 01 d0             	add    rax,rdx
   140007d43:	48 89 05 46 23 00 00 	mov    QWORD PTR [rip+0x2346],rax        # 14000a090 <pmem_next>
   140007d4a:	eb 21                	jmp    140007d6d <__Balloc_D2A+0x100>
   140007d4c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d4f:	48 c1 e0 03          	shl    rax,0x3
   140007d53:	48 89 c1             	mov    rcx,rax
   140007d56:	e8 e5 18 00 00       	call   140009640 <malloc>
   140007d5b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d5f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d64:	75 07                	jne    140007d6d <__Balloc_D2A+0x100>
   140007d66:	b8 00 00 00 00       	mov    eax,0x0
   140007d6b:	eb 3b                	jmp    140007da8 <__Balloc_D2A+0x13b>
   140007d6d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d71:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d74:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007d77:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d7b:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007d7e:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007d81:	b9 00 00 00 00       	mov    ecx,0x0
   140007d86:	e8 59 fe ff ff       	call   140007be4 <dtoa_unlock>
   140007d8b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d8f:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007d96:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d9a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007d9d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007da1:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007da4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007da8:	48 83 c4 30          	add    rsp,0x30
   140007dac:	5d                   	pop    rbp
   140007dad:	c3                   	ret

0000000140007dae <__Bfree_D2A>:
   140007dae:	55                   	push   rbp
   140007daf:	48 89 e5             	mov    rbp,rsp
   140007db2:	48 83 ec 20          	sub    rsp,0x20
   140007db6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007dba:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007dbf:	74 71                	je     140007e32 <__Bfree_D2A+0x84>
   140007dc1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007dc5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007dc8:	83 f8 09             	cmp    eax,0x9
   140007dcb:	7e 0e                	jle    140007ddb <__Bfree_D2A+0x2d>
   140007dcd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007dd1:	48 89 c1             	mov    rcx,rax
   140007dd4:	e8 57 18 00 00       	call   140009630 <free>
   140007dd9:	eb 57                	jmp    140007e32 <__Bfree_D2A+0x84>
   140007ddb:	b9 00 00 00 00       	mov    ecx,0x0
   140007de0:	e8 cd fc ff ff       	call   140007ab2 <dtoa_lock>
   140007de5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007de9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007dec:	48 98                	cdqe
   140007dee:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007df5:	00 
   140007df6:	48 8d 05 03 74 00 00 	lea    rax,[rip+0x7403]        # 14000f200 <freelist>
   140007dfd:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007e01:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e05:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007e08:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e0c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e0f:	48 98                	cdqe
   140007e11:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007e18:	00 
   140007e19:	48 8d 15 e0 73 00 00 	lea    rdx,[rip+0x73e0]        # 14000f200 <freelist>
   140007e20:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e24:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007e28:	b9 00 00 00 00       	mov    ecx,0x0
   140007e2d:	e8 b2 fd ff ff       	call   140007be4 <dtoa_unlock>
   140007e32:	90                   	nop
   140007e33:	48 83 c4 20          	add    rsp,0x20
   140007e37:	5d                   	pop    rbp
   140007e38:	c3                   	ret

0000000140007e39 <__multadd_D2A>:
   140007e39:	55                   	push   rbp
   140007e3a:	48 89 e5             	mov    rbp,rsp
   140007e3d:	48 83 ec 50          	sub    rsp,0x50
   140007e41:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e45:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007e48:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007e4c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e50:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007e53:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007e56:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e5a:	48 83 c0 18          	add    rax,0x18
   140007e5e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007e62:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007e69:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007e6c:	48 98                	cdqe
   140007e6e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007e72:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007e76:	8b 00                	mov    eax,DWORD PTR [rax]
   140007e78:	89 c2                	mov    edx,eax
   140007e7a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007e7d:	48 98                	cdqe
   140007e7f:	48 0f af d0          	imul   rdx,rax
   140007e83:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007e87:	48 01 d0             	add    rax,rdx
   140007e8a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007e8e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007e92:	48 c1 e8 20          	shr    rax,0x20
   140007e96:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007e9a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007e9e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007ea2:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007ea6:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007eaa:	89 10                	mov    DWORD PTR [rax],edx
   140007eac:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007eb0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007eb3:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007eb6:	7c ba                	jl     140007e72 <__multadd_D2A+0x39>
   140007eb8:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007ebd:	0f 84 9a 00 00 00    	je     140007f5d <__multadd_D2A+0x124>
   140007ec3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ec7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007eca:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007ecd:	7c 67                	jl     140007f36 <__multadd_D2A+0xfd>
   140007ecf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ed3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007ed6:	83 c0 01             	add    eax,0x1
   140007ed9:	89 c1                	mov    ecx,eax
   140007edb:	e8 8d fd ff ff       	call   140007c6d <__Balloc_D2A>
   140007ee0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007ee4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007ee9:	75 07                	jne    140007ef2 <__multadd_D2A+0xb9>
   140007eeb:	b8 00 00 00 00       	mov    eax,0x0
   140007ef0:	eb 6f                	jmp    140007f61 <__multadd_D2A+0x128>
   140007ef2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ef6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ef9:	48 98                	cdqe
   140007efb:	48 83 c0 02          	add    rax,0x2
   140007eff:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007f06:	00 
   140007f07:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f0b:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007f0f:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007f13:	48 83 c0 10          	add    rax,0x10
   140007f17:	49 89 c8             	mov    r8,rcx
   140007f1a:	48 89 c1             	mov    rcx,rax
   140007f1d:	e8 26 17 00 00       	call   140009648 <memcpy>
   140007f22:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f26:	48 89 c1             	mov    rcx,rax
   140007f29:	e8 80 fe ff ff       	call   140007dae <__Bfree_D2A>
   140007f2e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007f32:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007f36:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007f39:	8d 50 01             	lea    edx,[rax+0x1]
   140007f3c:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007f3f:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140007f43:	89 d1                	mov    ecx,edx
   140007f45:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007f49:	48 98                	cdqe
   140007f4b:	48 83 c0 04          	add    rax,0x4
   140007f4f:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140007f53:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f57:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140007f5a:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007f5d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f61:	48 83 c4 50          	add    rsp,0x50
   140007f65:	5d                   	pop    rbp
   140007f66:	c3                   	ret

0000000140007f67 <__i2b_D2A>:
   140007f67:	55                   	push   rbp
   140007f68:	48 89 e5             	mov    rbp,rsp
   140007f6b:	48 83 ec 30          	sub    rsp,0x30
   140007f6f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007f72:	b9 01 00 00 00       	mov    ecx,0x1
   140007f77:	e8 f1 fc ff ff       	call   140007c6d <__Balloc_D2A>
   140007f7c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007f80:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007f85:	75 07                	jne    140007f8e <__i2b_D2A+0x27>
   140007f87:	b8 00 00 00 00       	mov    eax,0x0
   140007f8c:	eb 19                	jmp    140007fa7 <__i2b_D2A+0x40>
   140007f8e:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007f91:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f95:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140007f98:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f9c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140007fa3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007fa7:	48 83 c4 30          	add    rsp,0x30
   140007fab:	5d                   	pop    rbp
   140007fac:	c3                   	ret

0000000140007fad <__mult_D2A>:
   140007fad:	55                   	push   rbp
   140007fae:	48 89 e5             	mov    rbp,rsp
   140007fb1:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140007fb8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007fbc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140007fc0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fc4:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007fc7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007fcb:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fce:	39 c2                	cmp    edx,eax
   140007fd0:	7d 18                	jge    140007fea <__mult_D2A+0x3d>
   140007fd2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fd6:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140007fda:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007fde:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007fe2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140007fe6:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007fea:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fee:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007ff1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007ff4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ff8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ffb:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   140007ffe:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008002:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008005:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   140008008:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   14000800b:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   14000800e:	01 d0                	add    eax,edx
   140008010:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008013:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008017:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000801a:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   14000801d:	7e 04                	jle    140008023 <__mult_D2A+0x76>
   14000801f:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008023:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008026:	89 c1                	mov    ecx,eax
   140008028:	e8 40 fc ff ff       	call   140007c6d <__Balloc_D2A>
   14000802d:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008031:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   140008036:	75 0a                	jne    140008042 <__mult_D2A+0x95>
   140008038:	b8 00 00 00 00       	mov    eax,0x0
   14000803d:	e9 88 01 00 00       	jmp    1400081ca <__mult_D2A+0x21d>
   140008042:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008046:	48 83 c0 18          	add    rax,0x18
   14000804a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000804e:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008051:	48 98                	cdqe
   140008053:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000805a:	00 
   14000805b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000805f:	48 01 d0             	add    rax,rdx
   140008062:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140008066:	eb 0f                	jmp    140008077 <__mult_D2A+0xca>
   140008068:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000806c:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008072:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140008077:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000807b:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   14000807f:	72 e7                	jb     140008068 <__mult_D2A+0xbb>
   140008081:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008085:	48 83 c0 18          	add    rax,0x18
   140008089:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000808d:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008090:	48 98                	cdqe
   140008092:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008099:	00 
   14000809a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000809e:	48 01 d0             	add    rax,rdx
   1400080a1:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400080a5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080a9:	48 83 c0 18          	add    rax,0x18
   1400080ad:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400080b1:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   1400080b4:	48 98                	cdqe
   1400080b6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400080bd:	00 
   1400080be:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400080c2:	48 01 d0             	add    rax,rdx
   1400080c5:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   1400080c9:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400080cd:	48 83 c0 18          	add    rax,0x18
   1400080d1:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400080d5:	e9 95 00 00 00       	jmp    14000816f <__mult_D2A+0x1c2>
   1400080da:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400080de:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400080e2:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400080e6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400080e8:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   1400080eb:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   1400080ef:	74 79                	je     14000816a <__mult_D2A+0x1bd>
   1400080f1:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400080f5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400080f9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400080fd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008101:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140008108:	00 
   140008109:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000810d:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008111:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008115:	8b 00                	mov    eax,DWORD PTR [rax]
   140008117:	89 c2                	mov    edx,eax
   140008119:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   14000811c:	48 0f af d0          	imul   rdx,rax
   140008120:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008124:	8b 00                	mov    eax,DWORD PTR [rax]
   140008126:	89 c0                	mov    eax,eax
   140008128:	48 01 c2             	add    rdx,rax
   14000812b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000812f:	48 01 d0             	add    rax,rdx
   140008132:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140008136:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   14000813a:	48 c1 e8 20          	shr    rax,0x20
   14000813e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008142:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008146:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000814a:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000814e:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140008152:	89 10                	mov    DWORD PTR [rax],edx
   140008154:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008158:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   14000815c:	72 ab                	jb     140008109 <__mult_D2A+0x15c>
   14000815e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008162:	89 c2                	mov    edx,eax
   140008164:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008168:	89 10                	mov    DWORD PTR [rax],edx
   14000816a:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   14000816f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008173:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   140008177:	0f 82 5d ff ff ff    	jb     1400080da <__mult_D2A+0x12d>
   14000817d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008181:	48 83 c0 18          	add    rax,0x18
   140008185:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008189:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000818c:	48 98                	cdqe
   14000818e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008195:	00 
   140008196:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000819a:	48 01 d0             	add    rax,rdx
   14000819d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400081a1:	eb 04                	jmp    1400081a7 <__mult_D2A+0x1fa>
   1400081a3:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400081a7:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400081ab:	7e 0f                	jle    1400081bc <__mult_D2A+0x20f>
   1400081ad:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   1400081b2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081b6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081b8:	85 c0                	test   eax,eax
   1400081ba:	74 e7                	je     1400081a3 <__mult_D2A+0x1f6>
   1400081bc:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081c0:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400081c3:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400081c6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081ca:	48 81 c4 90 00 00 00 	add    rsp,0x90
   1400081d1:	5d                   	pop    rbp
   1400081d2:	c3                   	ret

00000001400081d3 <__pow5mult_D2A>:
   1400081d3:	55                   	push   rbp
   1400081d4:	48 89 e5             	mov    rbp,rsp
   1400081d7:	48 83 ec 40          	sub    rsp,0x40
   1400081db:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400081df:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400081e2:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400081e5:	83 e0 03             	and    eax,0x3
   1400081e8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400081eb:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400081ef:	74 41                	je     140008232 <__pow5mult_D2A+0x5f>
   1400081f1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400081f4:	83 e8 01             	sub    eax,0x1
   1400081f7:	48 98                	cdqe
   1400081f9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008200:	00 
   140008201:	48 8d 05 90 1e 00 00 	lea    rax,[rip+0x1e90]        # 14000a098 <p05.0>
   140008208:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   14000820b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000820f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140008215:	48 89 c1             	mov    rcx,rax
   140008218:	e8 1c fc ff ff       	call   140007e39 <__multadd_D2A>
   14000821d:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008221:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140008226:	75 0a                	jne    140008232 <__pow5mult_D2A+0x5f>
   140008228:	b8 00 00 00 00       	mov    eax,0x0
   14000822d:	e9 58 01 00 00       	jmp    14000838a <__pow5mult_D2A+0x1b7>
   140008232:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   140008236:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000823a:	75 09                	jne    140008245 <__pow5mult_D2A+0x72>
   14000823c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008240:	e9 45 01 00 00       	jmp    14000838a <__pow5mult_D2A+0x1b7>
   140008245:	48 8b 05 14 79 00 00 	mov    rax,QWORD PTR [rip+0x7914]        # 14000fb60 <p5s>
   14000824c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008250:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008255:	75 5e                	jne    1400082b5 <__pow5mult_D2A+0xe2>
   140008257:	b9 01 00 00 00       	mov    ecx,0x1
   14000825c:	e8 51 f8 ff ff       	call   140007ab2 <dtoa_lock>
   140008261:	48 8b 05 f8 78 00 00 	mov    rax,QWORD PTR [rip+0x78f8]        # 14000fb60 <p5s>
   140008268:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000826c:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008271:	75 38                	jne    1400082ab <__pow5mult_D2A+0xd8>
   140008273:	b9 71 02 00 00       	mov    ecx,0x271
   140008278:	e8 ea fc ff ff       	call   140007f67 <__i2b_D2A>
   14000827d:	48 89 05 dc 78 00 00 	mov    QWORD PTR [rip+0x78dc],rax        # 14000fb60 <p5s>
   140008284:	48 8b 05 d5 78 00 00 	mov    rax,QWORD PTR [rip+0x78d5]        # 14000fb60 <p5s>
   14000828b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000828f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008294:	75 0a                	jne    1400082a0 <__pow5mult_D2A+0xcd>
   140008296:	b8 00 00 00 00       	mov    eax,0x0
   14000829b:	e9 ea 00 00 00       	jmp    14000838a <__pow5mult_D2A+0x1b7>
   1400082a0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400082a4:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   1400082ab:	b9 01 00 00 00       	mov    ecx,0x1
   1400082b0:	e8 2f f9 ff ff       	call   140007be4 <dtoa_unlock>
   1400082b5:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400082b8:	83 e0 01             	and    eax,0x1
   1400082bb:	85 c0                	test   eax,eax
   1400082bd:	74 39                	je     1400082f8 <__pow5mult_D2A+0x125>
   1400082bf:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400082c3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082c7:	48 89 c1             	mov    rcx,rax
   1400082ca:	e8 de fc ff ff       	call   140007fad <__mult_D2A>
   1400082cf:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400082d3:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   1400082d8:	75 0a                	jne    1400082e4 <__pow5mult_D2A+0x111>
   1400082da:	b8 00 00 00 00       	mov    eax,0x0
   1400082df:	e9 a6 00 00 00       	jmp    14000838a <__pow5mult_D2A+0x1b7>
   1400082e4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082e8:	48 89 c1             	mov    rcx,rax
   1400082eb:	e8 be fa ff ff       	call   140007dae <__Bfree_D2A>
   1400082f0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400082f4:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400082f8:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   1400082fb:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400082ff:	0f 84 80 00 00 00    	je     140008385 <__pow5mult_D2A+0x1b2>
   140008305:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008309:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000830c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008310:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008315:	75 61                	jne    140008378 <__pow5mult_D2A+0x1a5>
   140008317:	b9 01 00 00 00       	mov    ecx,0x1
   14000831c:	e8 91 f7 ff ff       	call   140007ab2 <dtoa_lock>
   140008321:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008325:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008328:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000832c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008331:	75 3b                	jne    14000836e <__pow5mult_D2A+0x19b>
   140008333:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008337:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000833b:	48 89 c1             	mov    rcx,rax
   14000833e:	e8 6a fc ff ff       	call   140007fad <__mult_D2A>
   140008343:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008347:	48 89 02             	mov    QWORD PTR [rdx],rax
   14000834a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000834e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008351:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008355:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000835a:	75 07                	jne    140008363 <__pow5mult_D2A+0x190>
   14000835c:	b8 00 00 00 00       	mov    eax,0x0
   140008361:	eb 27                	jmp    14000838a <__pow5mult_D2A+0x1b7>
   140008363:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008367:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000836e:	b9 01 00 00 00       	mov    ecx,0x1
   140008373:	e8 6c f8 ff ff       	call   140007be4 <dtoa_unlock>
   140008378:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000837c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008380:	e9 30 ff ff ff       	jmp    1400082b5 <__pow5mult_D2A+0xe2>
   140008385:	90                   	nop
   140008386:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000838a:	48 83 c4 40          	add    rsp,0x40
   14000838e:	5d                   	pop    rbp
   14000838f:	c3                   	ret

0000000140008390 <__lshift_D2A>:
   140008390:	55                   	push   rbp
   140008391:	48 89 e5             	mov    rbp,rsp
   140008394:	48 83 ec 60          	sub    rsp,0x60
   140008398:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000839c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000839f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400083a2:	c1 f8 05             	sar    eax,0x5
   1400083a5:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   1400083a8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083ac:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400083af:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400083b2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083b6:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   1400083b9:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   1400083bc:	01 d0                	add    eax,edx
   1400083be:	83 c0 01             	add    eax,0x1
   1400083c1:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400083c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083c8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400083cb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400083ce:	eb 07                	jmp    1400083d7 <__lshift_D2A+0x47>
   1400083d0:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   1400083d4:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   1400083d7:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400083da:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   1400083dd:	7f f1                	jg     1400083d0 <__lshift_D2A+0x40>
   1400083df:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400083e2:	89 c1                	mov    ecx,eax
   1400083e4:	e8 84 f8 ff ff       	call   140007c6d <__Balloc_D2A>
   1400083e9:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400083ed:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400083f2:	75 0a                	jne    1400083fe <__lshift_D2A+0x6e>
   1400083f4:	b8 00 00 00 00       	mov    eax,0x0
   1400083f9:	e9 19 01 00 00       	jmp    140008517 <__lshift_D2A+0x187>
   1400083fe:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008402:	48 83 c0 18          	add    rax,0x18
   140008406:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000840a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008411:	eb 16                	jmp    140008429 <__lshift_D2A+0x99>
   140008413:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008417:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000841b:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000841f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008425:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008429:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000842c:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   14000842f:	7c e2                	jl     140008413 <__lshift_D2A+0x83>
   140008431:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008435:	48 83 c0 18          	add    rax,0x18
   140008439:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000843d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008441:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008444:	48 98                	cdqe
   140008446:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000844d:	00 
   14000844e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008452:	48 01 d0             	add    rax,rdx
   140008455:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008459:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000845d:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140008461:	74 71                	je     1400084d4 <__lshift_D2A+0x144>
   140008463:	b8 20 00 00 00       	mov    eax,0x20
   140008468:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000846b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000846e:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   140008475:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008479:	8b 10                	mov    edx,DWORD PTR [rax]
   14000847b:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000847e:	89 c1                	mov    ecx,eax
   140008480:	d3 e2                	shl    edx,cl
   140008482:	89 d1                	mov    ecx,edx
   140008484:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008488:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000848c:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008490:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008493:	89 ca                	mov    edx,ecx
   140008495:	89 10                	mov    DWORD PTR [rax],edx
   140008497:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000849b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000849f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400084a3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400084a5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400084a8:	89 c1                	mov    ecx,eax
   1400084aa:	d3 ea                	shr    edx,cl
   1400084ac:	89 d0                	mov    eax,edx
   1400084ae:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400084b1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084b5:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400084b9:	72 ba                	jb     140008475 <__lshift_D2A+0xe5>
   1400084bb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084bf:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   1400084c2:	89 10                	mov    DWORD PTR [rax],edx
   1400084c4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084c8:	8b 00                	mov    eax,DWORD PTR [rax]
   1400084ca:	85 c0                	test   eax,eax
   1400084cc:	74 2c                	je     1400084fa <__lshift_D2A+0x16a>
   1400084ce:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   1400084d2:	eb 26                	jmp    1400084fa <__lshift_D2A+0x16a>
   1400084d4:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400084d8:	48 8d 42 04          	lea    rax,[rdx+0x4]
   1400084dc:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400084e0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084e4:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400084e8:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   1400084ec:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400084ee:	89 10                	mov    DWORD PTR [rax],edx
   1400084f0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084f4:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400084f8:	72 da                	jb     1400084d4 <__lshift_D2A+0x144>
   1400084fa:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400084fd:	8d 50 ff             	lea    edx,[rax-0x1]
   140008500:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008504:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008507:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000850b:	48 89 c1             	mov    rcx,rax
   14000850e:	e8 9b f8 ff ff       	call   140007dae <__Bfree_D2A>
   140008513:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008517:	48 83 c4 60          	add    rsp,0x60
   14000851b:	5d                   	pop    rbp
   14000851c:	c3                   	ret

000000014000851d <__cmp_D2A>:
   14000851d:	55                   	push   rbp
   14000851e:	48 89 e5             	mov    rbp,rsp
   140008521:	48 83 ec 30          	sub    rsp,0x30
   140008525:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008529:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000852d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008531:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008534:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140008537:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000853b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000853e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140008541:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008544:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   140008547:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000854b:	74 08                	je     140008555 <__cmp_D2A+0x38>
   14000854d:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008550:	e9 92 00 00 00       	jmp    1400085e7 <__cmp_D2A+0xca>
   140008555:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008559:	48 83 c0 18          	add    rax,0x18
   14000855d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008561:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008564:	48 98                	cdqe
   140008566:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000856d:	00 
   14000856e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008572:	48 01 d0             	add    rax,rdx
   140008575:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008579:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000857d:	48 83 c0 18          	add    rax,0x18
   140008581:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008585:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008588:	48 98                	cdqe
   14000858a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008591:	00 
   140008592:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008596:	48 01 d0             	add    rax,rdx
   140008599:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000859d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400085a2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400085a6:	8b 10                	mov    edx,DWORD PTR [rax]
   1400085a8:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   1400085ad:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400085b1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400085b3:	39 c2                	cmp    edx,eax
   1400085b5:	74 1e                	je     1400085d5 <__cmp_D2A+0xb8>
   1400085b7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400085bb:	8b 10                	mov    edx,DWORD PTR [rax]
   1400085bd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400085c1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400085c3:	39 c2                	cmp    edx,eax
   1400085c5:	73 07                	jae    1400085ce <__cmp_D2A+0xb1>
   1400085c7:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400085cc:	eb 19                	jmp    1400085e7 <__cmp_D2A+0xca>
   1400085ce:	b8 01 00 00 00       	mov    eax,0x1
   1400085d3:	eb 12                	jmp    1400085e7 <__cmp_D2A+0xca>
   1400085d5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400085d9:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400085dd:	73 02                	jae    1400085e1 <__cmp_D2A+0xc4>
   1400085df:	eb bc                	jmp    14000859d <__cmp_D2A+0x80>
   1400085e1:	90                   	nop
   1400085e2:	b8 00 00 00 00       	mov    eax,0x0
   1400085e7:	48 83 c4 30          	add    rsp,0x30
   1400085eb:	5d                   	pop    rbp
   1400085ec:	c3                   	ret

00000001400085ed <__diff_D2A>:
   1400085ed:	55                   	push   rbp
   1400085ee:	48 89 e5             	mov    rbp,rsp
   1400085f1:	48 83 ec 70          	sub    rsp,0x70
   1400085f5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400085f9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400085fd:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140008601:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008605:	48 89 c1             	mov    rcx,rax
   140008608:	e8 10 ff ff ff       	call   14000851d <__cmp_D2A>
   14000860d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008610:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008614:	75 3e                	jne    140008654 <__diff_D2A+0x67>
   140008616:	b9 00 00 00 00       	mov    ecx,0x0
   14000861b:	e8 4d f6 ff ff       	call   140007c6d <__Balloc_D2A>
   140008620:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008624:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008629:	75 0a                	jne    140008635 <__diff_D2A+0x48>
   14000862b:	b8 00 00 00 00       	mov    eax,0x0
   140008630:	e9 ab 01 00 00       	jmp    1400087e0 <__diff_D2A+0x1f3>
   140008635:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008639:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008640:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008644:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000864b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000864f:	e9 8c 01 00 00       	jmp    1400087e0 <__diff_D2A+0x1f3>
   140008654:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008658:	79 21                	jns    14000867b <__diff_D2A+0x8e>
   14000865a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000865e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008662:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008666:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000866a:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000866e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140008672:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140008679:	eb 07                	jmp    140008682 <__diff_D2A+0x95>
   14000867b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008682:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008686:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008689:	89 c1                	mov    ecx,eax
   14000868b:	e8 dd f5 ff ff       	call   140007c6d <__Balloc_D2A>
   140008690:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008694:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008699:	75 0a                	jne    1400086a5 <__diff_D2A+0xb8>
   14000869b:	b8 00 00 00 00       	mov    eax,0x0
   1400086a0:	e9 3b 01 00 00       	jmp    1400087e0 <__diff_D2A+0x1f3>
   1400086a5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086a9:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400086ac:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400086af:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086b3:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400086b6:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400086b9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086bd:	48 83 c0 18          	add    rax,0x18
   1400086c1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400086c5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400086c8:	48 98                	cdqe
   1400086ca:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400086d1:	00 
   1400086d2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400086d6:	48 01 d0             	add    rax,rdx
   1400086d9:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400086dd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086e1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400086e4:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400086e7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086eb:	48 83 c0 18          	add    rax,0x18
   1400086ef:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400086f3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   1400086f6:	48 98                	cdqe
   1400086f8:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400086ff:	00 
   140008700:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008704:	48 01 d0             	add    rax,rdx
   140008707:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000870b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000870f:	48 83 c0 18          	add    rax,0x18
   140008713:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008717:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   14000871e:	00 
   14000871f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008723:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008727:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000872b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000872d:	89 c1                	mov    ecx,eax
   14000872f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008733:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008737:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   14000873b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000873d:	89 c2                	mov    edx,eax
   14000873f:	48 89 c8             	mov    rax,rcx
   140008742:	48 29 d0             	sub    rax,rdx
   140008745:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140008749:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000874d:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008751:	48 c1 e8 20          	shr    rax,0x20
   140008755:	83 e0 01             	and    eax,0x1
   140008758:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000875c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008760:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008764:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008768:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000876c:	89 10                	mov    DWORD PTR [rax],edx
   14000876e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008772:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   140008776:	72 a7                	jb     14000871f <__diff_D2A+0x132>
   140008778:	eb 39                	jmp    1400087b3 <__diff_D2A+0x1c6>
   14000877a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000877e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008782:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008786:	8b 00                	mov    eax,DWORD PTR [rax]
   140008788:	89 c0                	mov    eax,eax
   14000878a:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   14000878e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008792:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008796:	48 c1 e8 20          	shr    rax,0x20
   14000879a:	83 e0 01             	and    eax,0x1
   14000879d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400087a1:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087a5:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087a9:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400087ad:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400087b1:	89 10                	mov    DWORD PTR [rax],edx
   1400087b3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087b7:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400087bb:	72 bd                	jb     14000877a <__diff_D2A+0x18d>
   1400087bd:	eb 04                	jmp    1400087c3 <__diff_D2A+0x1d6>
   1400087bf:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400087c3:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   1400087c8:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087cc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087ce:	85 c0                	test   eax,eax
   1400087d0:	74 ed                	je     1400087bf <__diff_D2A+0x1d2>
   1400087d2:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087d6:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400087d9:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400087dc:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087e0:	48 83 c4 70          	add    rsp,0x70
   1400087e4:	5d                   	pop    rbp
   1400087e5:	c3                   	ret

00000001400087e6 <__b2d_D2A>:
   1400087e6:	55                   	push   rbp
   1400087e7:	48 89 e5             	mov    rbp,rsp
   1400087ea:	48 83 ec 50          	sub    rsp,0x50
   1400087ee:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400087f2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400087f6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400087fa:	48 83 c0 18          	add    rax,0x18
   1400087fe:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008802:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008806:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008809:	48 98                	cdqe
   14000880b:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008812:	00 
   140008813:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008817:	48 01 d0             	add    rax,rdx
   14000881a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000881e:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008823:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008827:	8b 00                	mov    eax,DWORD PTR [rax]
   140008829:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   14000882c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000882f:	89 c1                	mov    ecx,eax
   140008831:	e8 27 f4 ff ff       	call   140007c5d <__hi0bits_D2A>
   140008836:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008839:	b8 20 00 00 00       	mov    eax,0x20
   14000883e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008841:	89 c2                	mov    edx,eax
   140008843:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008847:	89 10                	mov    DWORD PTR [rax],edx
   140008849:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   14000884d:	7f 66                	jg     1400088b5 <__b2d_D2A+0xcf>
   14000884f:	b8 0b 00 00 00       	mov    eax,0xb
   140008854:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008857:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000885a:	89 c1                	mov    ecx,eax
   14000885c:	d3 ea                	shr    edx,cl
   14000885e:	89 d0                	mov    eax,edx
   140008860:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008865:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008868:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000886c:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008870:	73 10                	jae    140008882 <__b2d_D2A+0x9c>
   140008872:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008877:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000887b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000887d:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008880:	eb 07                	jmp    140008889 <__b2d_D2A+0xa3>
   140008882:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140008889:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000888c:	83 c0 15             	add    eax,0x15
   14000888f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008892:	89 c1                	mov    ecx,eax
   140008894:	d3 e2                	shl    edx,cl
   140008896:	41 89 d0             	mov    r8d,edx
   140008899:	b8 0b 00 00 00       	mov    eax,0xb
   14000889e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088a1:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   1400088a4:	89 c1                	mov    ecx,eax
   1400088a6:	d3 ea                	shr    edx,cl
   1400088a8:	89 d0                	mov    eax,edx
   1400088aa:	44 09 c0             	or     eax,r8d
   1400088ad:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400088b0:	e9 ac 00 00 00       	jmp    140008961 <__b2d_D2A+0x17b>
   1400088b5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088b9:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400088bd:	73 10                	jae    1400088cf <__b2d_D2A+0xe9>
   1400088bf:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088c4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088c8:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088ca:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400088cd:	eb 07                	jmp    1400088d6 <__b2d_D2A+0xf0>
   1400088cf:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   1400088d6:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   1400088da:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   1400088de:	74 70                	je     140008950 <__b2d_D2A+0x16a>
   1400088e0:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400088e3:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400088e6:	89 c1                	mov    ecx,eax
   1400088e8:	d3 e2                	shl    edx,cl
   1400088ea:	41 89 d0             	mov    r8d,edx
   1400088ed:	b8 20 00 00 00       	mov    eax,0x20
   1400088f2:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088f5:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400088f8:	89 c1                	mov    ecx,eax
   1400088fa:	d3 ea                	shr    edx,cl
   1400088fc:	89 d0                	mov    eax,edx
   1400088fe:	44 09 c0             	or     eax,r8d
   140008901:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008906:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008909:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000890d:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008911:	73 10                	jae    140008923 <__b2d_D2A+0x13d>
   140008913:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008918:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000891c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000891e:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140008921:	eb 07                	jmp    14000892a <__b2d_D2A+0x144>
   140008923:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   14000892a:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000892d:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008930:	89 c1                	mov    ecx,eax
   140008932:	d3 e2                	shl    edx,cl
   140008934:	41 89 d0             	mov    r8d,edx
   140008937:	b8 20 00 00 00       	mov    eax,0x20
   14000893c:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   14000893f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008942:	89 c1                	mov    ecx,eax
   140008944:	d3 ea                	shr    edx,cl
   140008946:	89 d0                	mov    eax,edx
   140008948:	44 09 c0             	or     eax,r8d
   14000894b:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000894e:	eb 11                	jmp    140008961 <__b2d_D2A+0x17b>
   140008950:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008953:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008958:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000895b:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   14000895e:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008961:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   140008966:	48 83 c4 50          	add    rsp,0x50
   14000896a:	5d                   	pop    rbp
   14000896b:	c3                   	ret

000000014000896c <__d2b_D2A>:
   14000896c:	55                   	push   rbp
   14000896d:	53                   	push   rbx
   14000896e:	48 83 ec 58          	sub    rsp,0x58
   140008972:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140008977:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   14000897c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140008980:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140008984:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140008989:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   14000898e:	b9 01 00 00 00       	mov    ecx,0x1
   140008993:	e8 d5 f2 ff ff       	call   140007c6d <__Balloc_D2A>
   140008998:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000899c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400089a1:	75 0a                	jne    1400089ad <__d2b_D2A+0x41>
   1400089a3:	b8 00 00 00 00       	mov    eax,0x0
   1400089a8:	e9 68 01 00 00       	jmp    140008b15 <__d2b_D2A+0x1a9>
   1400089ad:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400089b1:	48 83 c0 18          	add    rax,0x18
   1400089b5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400089b9:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089bc:	25 ff ff 0f 00       	and    eax,0xfffff
   1400089c1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089c4:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089c7:	25 ff ff ff 7f       	and    eax,0x7fffffff
   1400089cc:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400089cf:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089d2:	c1 e8 14             	shr    eax,0x14
   1400089d5:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400089d8:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400089dc:	74 0b                	je     1400089e9 <__d2b_D2A+0x7d>
   1400089de:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   1400089e1:	0d 00 00 10 00       	or     eax,0x100000
   1400089e6:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089e9:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   1400089ec:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089ef:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400089f2:	85 c0                	test   eax,eax
   1400089f4:	74 7b                	je     140008a71 <__d2b_D2A+0x105>
   1400089f6:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   1400089fa:	48 89 c1             	mov    rcx,rax
   1400089fd:	e8 26 f2 ff ff       	call   140007c28 <__lo0bits_D2A>
   140008a02:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008a05:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008a09:	74 2b                	je     140008a36 <__d2b_D2A+0xca>
   140008a0b:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a0e:	b8 20 00 00 00       	mov    eax,0x20
   140008a13:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008a16:	89 c1                	mov    ecx,eax
   140008a18:	d3 e2                	shl    edx,cl
   140008a1a:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008a1d:	09 c2                	or     edx,eax
   140008a1f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a23:	89 10                	mov    DWORD PTR [rax],edx
   140008a25:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a28:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008a2b:	89 c1                	mov    ecx,eax
   140008a2d:	d3 ea                	shr    edx,cl
   140008a2f:	89 d0                	mov    eax,edx
   140008a31:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a34:	eb 09                	jmp    140008a3f <__d2b_D2A+0xd3>
   140008a36:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008a39:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a3d:	89 10                	mov    DWORD PTR [rax],edx
   140008a3f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a43:	48 83 c0 04          	add    rax,0x4
   140008a47:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a4a:	89 10                	mov    DWORD PTR [rax],edx
   140008a4c:	8b 00                	mov    eax,DWORD PTR [rax]
   140008a4e:	85 c0                	test   eax,eax
   140008a50:	74 07                	je     140008a59 <__d2b_D2A+0xed>
   140008a52:	ba 02 00 00 00       	mov    edx,0x2
   140008a57:	eb 05                	jmp    140008a5e <__d2b_D2A+0xf2>
   140008a59:	ba 01 00 00 00       	mov    edx,0x1
   140008a5e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a62:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008a65:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a69:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008a6c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008a6f:	eb 31                	jmp    140008aa2 <__d2b_D2A+0x136>
   140008a71:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008a75:	48 89 c1             	mov    rcx,rax
   140008a78:	e8 ab f1 ff ff       	call   140007c28 <__lo0bits_D2A>
   140008a7d:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008a80:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a83:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a87:	89 10                	mov    DWORD PTR [rax],edx
   140008a89:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a8d:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008a94:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a98:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008a9b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008a9e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008aa2:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008aa6:	74 26                	je     140008ace <__d2b_D2A+0x162>
   140008aa8:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008aab:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008ab1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008ab4:	01 c2                	add    edx,eax
   140008ab6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008aba:	89 10                	mov    DWORD PTR [rax],edx
   140008abc:	b8 35 00 00 00       	mov    eax,0x35
   140008ac1:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008ac4:	89 c2                	mov    edx,eax
   140008ac6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008aca:	89 10                	mov    DWORD PTR [rax],edx
   140008acc:	eb 43                	jmp    140008b11 <__d2b_D2A+0x1a5>
   140008ace:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008ad1:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008ad7:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008ada:	01 c2                	add    edx,eax
   140008adc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008ae0:	89 10                	mov    DWORD PTR [rax],edx
   140008ae2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008ae5:	c1 e0 05             	shl    eax,0x5
   140008ae8:	89 c3                	mov    ebx,eax
   140008aea:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008aed:	48 98                	cdqe
   140008aef:	48 c1 e0 02          	shl    rax,0x2
   140008af3:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008af7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008afb:	48 01 d0             	add    rax,rdx
   140008afe:	8b 00                	mov    eax,DWORD PTR [rax]
   140008b00:	89 c1                	mov    ecx,eax
   140008b02:	e8 56 f1 ff ff       	call   140007c5d <__hi0bits_D2A>
   140008b07:	29 c3                	sub    ebx,eax
   140008b09:	89 da                	mov    edx,ebx
   140008b0b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b0f:	89 10                	mov    DWORD PTR [rax],edx
   140008b11:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b15:	48 83 c4 58          	add    rsp,0x58
   140008b19:	5b                   	pop    rbx
   140008b1a:	5d                   	pop    rbp
   140008b1b:	c3                   	ret

0000000140008b1c <__strcp_D2A>:
   140008b1c:	55                   	push   rbp
   140008b1d:	48 89 e5             	mov    rbp,rsp
   140008b20:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008b24:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008b28:	eb 05                	jmp    140008b2f <__strcp_D2A+0x13>
   140008b2a:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008b2f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008b33:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008b37:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008b3b:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008b3e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b42:	88 10                	mov    BYTE PTR [rax],dl
   140008b44:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b48:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008b4b:	84 c0                	test   al,al
   140008b4d:	75 db                	jne    140008b2a <__strcp_D2A+0xe>
   140008b4f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b53:	5d                   	pop    rbp
   140008b54:	c3                   	ret
   140008b55:	90                   	nop
   140008b56:	90                   	nop
   140008b57:	90                   	nop
   140008b58:	90                   	nop
   140008b59:	90                   	nop
   140008b5a:	90                   	nop
   140008b5b:	90                   	nop
   140008b5c:	90                   	nop
   140008b5d:	90                   	nop
   140008b5e:	90                   	nop
   140008b5f:	90                   	nop

0000000140008b60 <__fpclassify>:
   140008b60:	55                   	push   rbp
   140008b61:	48 89 e5             	mov    rbp,rsp
   140008b64:	48 83 ec 10          	sub    rsp,0x10
   140008b68:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008b6d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008b72:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008b77:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008b7a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b7d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008b80:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008b83:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008b89:	09 d0                	or     eax,edx
   140008b8b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008b8e:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008b95:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b98:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008b9b:	85 c0                	test   eax,eax
   140008b9d:	75 07                	jne    140008ba6 <__fpclassify+0x46>
   140008b9f:	b8 00 40 00 00       	mov    eax,0x4000
   140008ba4:	eb 2f                	jmp    140008bd5 <__fpclassify+0x75>
   140008ba6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008baa:	75 07                	jne    140008bb3 <__fpclassify+0x53>
   140008bac:	b8 00 44 00 00       	mov    eax,0x4400
   140008bb1:	eb 22                	jmp    140008bd5 <__fpclassify+0x75>
   140008bb3:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008bba:	75 14                	jne    140008bd0 <__fpclassify+0x70>
   140008bbc:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008bc0:	74 07                	je     140008bc9 <__fpclassify+0x69>
   140008bc2:	b8 00 01 00 00       	mov    eax,0x100
   140008bc7:	eb 0c                	jmp    140008bd5 <__fpclassify+0x75>
   140008bc9:	b8 00 05 00 00       	mov    eax,0x500
   140008bce:	eb 05                	jmp    140008bd5 <__fpclassify+0x75>
   140008bd0:	b8 00 04 00 00       	mov    eax,0x400
   140008bd5:	48 83 c4 10          	add    rsp,0x10
   140008bd9:	5d                   	pop    rbp
   140008bda:	c3                   	ret
   140008bdb:	90                   	nop
   140008bdc:	90                   	nop
   140008bdd:	90                   	nop
   140008bde:	90                   	nop
   140008bdf:	90                   	nop

0000000140008be0 <__fpclassifyl>:
   140008be0:	55                   	push   rbp
   140008be1:	53                   	push   rbx
   140008be2:	48 83 ec 38          	sub    rsp,0x38
   140008be6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008beb:	48 89 cb             	mov    rbx,rcx
   140008bee:	db 2b                	fld    TBYTE PTR [rbx]
   140008bf0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008bf3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008bf6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008bf9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008bfd:	98                   	cwde
   140008bfe:	25 ff 7f 00 00       	and    eax,0x7fff
   140008c03:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c06:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c0a:	75 25                	jne    140008c31 <__fpclassifyl+0x51>
   140008c0c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c0f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c12:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c15:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c18:	85 c0                	test   eax,eax
   140008c1a:	75 07                	jne    140008c23 <__fpclassifyl+0x43>
   140008c1c:	b8 00 40 00 00       	mov    eax,0x4000
   140008c21:	eb 3d                	jmp    140008c60 <__fpclassifyl+0x80>
   140008c23:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c26:	85 c0                	test   eax,eax
   140008c28:	78 31                	js     140008c5b <__fpclassifyl+0x7b>
   140008c2a:	b8 00 44 00 00       	mov    eax,0x4400
   140008c2f:	eb 2f                	jmp    140008c60 <__fpclassifyl+0x80>
   140008c31:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008c38:	75 21                	jne    140008c5b <__fpclassifyl+0x7b>
   140008c3a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c3d:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008c42:	89 c2                	mov    edx,eax
   140008c44:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c47:	09 d0                	or     eax,edx
   140008c49:	85 c0                	test   eax,eax
   140008c4b:	75 07                	jne    140008c54 <__fpclassifyl+0x74>
   140008c4d:	b8 00 05 00 00       	mov    eax,0x500
   140008c52:	eb 0c                	jmp    140008c60 <__fpclassifyl+0x80>
   140008c54:	b8 00 01 00 00       	mov    eax,0x100
   140008c59:	eb 05                	jmp    140008c60 <__fpclassifyl+0x80>
   140008c5b:	b8 00 04 00 00       	mov    eax,0x400
   140008c60:	48 83 c4 38          	add    rsp,0x38
   140008c64:	5b                   	pop    rbx
   140008c65:	5d                   	pop    rbp
   140008c66:	c3                   	ret
   140008c67:	90                   	nop
   140008c68:	90                   	nop
   140008c69:	90                   	nop
   140008c6a:	90                   	nop
   140008c6b:	90                   	nop
   140008c6c:	90                   	nop
   140008c6d:	90                   	nop
   140008c6e:	90                   	nop
   140008c6f:	90                   	nop

0000000140008c70 <__isnan>:
   140008c70:	55                   	push   rbp
   140008c71:	48 89 e5             	mov    rbp,rsp
   140008c74:	48 83 ec 10          	sub    rsp,0x10
   140008c78:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008c7d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008c82:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008c87:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008c8a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c8d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008c90:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008c95:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c98:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c9b:	f7 d8                	neg    eax
   140008c9d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008ca0:	c1 e8 1f             	shr    eax,0x1f
   140008ca3:	89 c2                	mov    edx,eax
   140008ca5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008ca8:	09 d0                	or     eax,edx
   140008caa:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008cad:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008cb2:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008cb5:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008cb8:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008cbb:	c1 f8 1f             	sar    eax,0x1f
   140008cbe:	48 83 c4 10          	add    rsp,0x10
   140008cc2:	5d                   	pop    rbp
   140008cc3:	c3                   	ret
   140008cc4:	90                   	nop
   140008cc5:	90                   	nop
   140008cc6:	90                   	nop
   140008cc7:	90                   	nop
   140008cc8:	90                   	nop
   140008cc9:	90                   	nop
   140008cca:	90                   	nop
   140008ccb:	90                   	nop
   140008ccc:	90                   	nop
   140008ccd:	90                   	nop
   140008cce:	90                   	nop
   140008ccf:	90                   	nop

0000000140008cd0 <__isnanl>:
   140008cd0:	55                   	push   rbp
   140008cd1:	53                   	push   rbx
   140008cd2:	48 83 ec 38          	sub    rsp,0x38
   140008cd6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008cdb:	48 89 cb             	mov    rbx,rcx
   140008cde:	db 2b                	fld    TBYTE PTR [rbx]
   140008ce0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008ce3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008ce6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008ce9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008ced:	98                   	cwde
   140008cee:	01 c0                	add    eax,eax
   140008cf0:	25 ff ff 00 00       	and    eax,0xffff
   140008cf5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cf8:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008cfb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008cfe:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008d04:	09 d0                	or     eax,edx
   140008d06:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d09:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d0c:	f7 d8                	neg    eax
   140008d0e:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008d11:	c1 e8 1f             	shr    eax,0x1f
   140008d14:	89 c2                	mov    edx,eax
   140008d16:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d19:	09 d0                	or     eax,edx
   140008d1b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d1e:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008d23:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008d26:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d29:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d2c:	c1 f8 10             	sar    eax,0x10
   140008d2f:	48 83 c4 38          	add    rsp,0x38
   140008d33:	5b                   	pop    rbx
   140008d34:	5d                   	pop    rbp
   140008d35:	c3                   	ret
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

0000000140008d40 <wcsnlen>:
   140008d40:	55                   	push   rbp
   140008d41:	48 89 e5             	mov    rbp,rsp
   140008d44:	48 83 ec 10          	sub    rsp,0x10
   140008d48:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008d4c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008d50:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008d57:	00 
   140008d58:	eb 0a                	jmp    140008d64 <wcsnlen+0x24>
   140008d5a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008d5f:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008d64:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d68:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008d6c:	73 0c                	jae    140008d7a <wcsnlen+0x3a>
   140008d6e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008d72:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008d75:	66 85 c0             	test   ax,ax
   140008d78:	75 e0                	jne    140008d5a <wcsnlen+0x1a>
   140008d7a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
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

0000000140008d90 <strnlen>:
   140008d90:	55                   	push   rbp
   140008d91:	48 89 e5             	mov    rbp,rsp
   140008d94:	48 83 ec 10          	sub    rsp,0x10
   140008d98:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008d9c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008da0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008da4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008da8:	eb 05                	jmp    140008daf <strnlen+0x1f>
   140008daa:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008daf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008db3:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008db7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008dbb:	73 0b                	jae    140008dc8 <strnlen+0x38>
   140008dbd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dc1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008dc4:	84 c0                	test   al,al
   140008dc6:	75 e2                	jne    140008daa <strnlen+0x1a>
   140008dc8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dcc:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008dd0:	48 83 c4 10          	add    rsp,0x10
   140008dd4:	5d                   	pop    rbp
   140008dd5:	c3                   	ret
   140008dd6:	90                   	nop
   140008dd7:	90                   	nop
   140008dd8:	90                   	nop
   140008dd9:	90                   	nop
   140008dda:	90                   	nop
   140008ddb:	90                   	nop
   140008ddc:	90                   	nop
   140008ddd:	90                   	nop
   140008dde:	90                   	nop
   140008ddf:	90                   	nop

0000000140008de0 <_initterm_e>:
   140008de0:	55                   	push   rbp
   140008de1:	48 89 e5             	mov    rbp,rsp
   140008de4:	48 83 ec 30          	sub    rsp,0x30
   140008de8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008dec:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008df0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008df4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008df8:	eb 29                	jmp    140008e23 <_initterm_e+0x43>
   140008dfa:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dfe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e01:	48 85 c0             	test   rax,rax
   140008e04:	74 17                	je     140008e1d <_initterm_e+0x3d>
   140008e06:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e0a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e0d:	ff d0                	call   rax
   140008e0f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008e12:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008e16:	74 06                	je     140008e1e <_initterm_e+0x3e>
   140008e18:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008e1b:	eb 15                	jmp    140008e32 <_initterm_e+0x52>
   140008e1d:	90                   	nop
   140008e1e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008e23:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e27:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e2b:	72 cd                	jb     140008dfa <_initterm_e+0x1a>
   140008e2d:	b8 00 00 00 00       	mov    eax,0x0
   140008e32:	48 83 c4 30          	add    rsp,0x30
   140008e36:	5d                   	pop    rbp
   140008e37:	c3                   	ret
   140008e38:	90                   	nop
   140008e39:	90                   	nop
   140008e3a:	90                   	nop
   140008e3b:	90                   	nop
   140008e3c:	90                   	nop
   140008e3d:	90                   	nop
   140008e3e:	90                   	nop
   140008e3f:	90                   	nop

0000000140008e40 <__p__fmode>:
   140008e40:	55                   	push   rbp
   140008e41:	48 89 e5             	mov    rbp,rsp
   140008e44:	48 8b 05 b5 27 00 00 	mov    rax,QWORD PTR [rip+0x27b5]        # 14000b600 <.refptr.__imp__fmode>
   140008e4b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e4e:	5d                   	pop    rbp
   140008e4f:	c3                   	ret

0000000140008e50 <__p__commode>:
   140008e50:	55                   	push   rbp
   140008e51:	48 89 e5             	mov    rbp,rsp
   140008e54:	48 8b 05 95 27 00 00 	mov    rax,QWORD PTR [rip+0x2795]        # 14000b5f0 <.refptr.__imp__commode>
   140008e5b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e5e:	5d                   	pop    rbp
   140008e5f:	c3                   	ret

0000000140008e60 <__p___initenv>:
   140008e60:	55                   	push   rbp
   140008e61:	48 89 e5             	mov    rbp,rsp
   140008e64:	48 8b 05 75 27 00 00 	mov    rax,QWORD PTR [rip+0x2775]        # 14000b5e0 <.refptr.__imp___initenv>
   140008e6b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e6e:	5d                   	pop    rbp
   140008e6f:	c3                   	ret

0000000140008e70 <_lock_file>:
   140008e70:	55                   	push   rbp
   140008e71:	48 89 e5             	mov    rbp,rsp
   140008e74:	48 83 ec 20          	sub    rsp,0x20
   140008e78:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e7c:	b9 00 00 00 00       	mov    ecx,0x0
   140008e81:	e8 6a 01 00 00       	call   140008ff0 <__acrt_iob_func>
   140008e86:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008e8a:	72 52                	jb     140008ede <_lock_file+0x6e>
   140008e8c:	b9 13 00 00 00       	mov    ecx,0x13
   140008e91:	e8 5a 01 00 00       	call   140008ff0 <__acrt_iob_func>
   140008e96:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008e9a:	72 42                	jb     140008ede <_lock_file+0x6e>
   140008e9c:	b9 00 00 00 00       	mov    ecx,0x0
   140008ea1:	e8 4a 01 00 00       	call   140008ff0 <__acrt_iob_func>
   140008ea6:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008eaa:	48 29 c2             	sub    rdx,rax
   140008ead:	48 c1 fa 04          	sar    rdx,0x4
   140008eb1:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008eb8:	aa aa aa 
   140008ebb:	48 0f af c2          	imul   rax,rdx
   140008ebf:	83 c0 10             	add    eax,0x10
   140008ec2:	89 c1                	mov    ecx,eax
   140008ec4:	e8 1f 07 00 00       	call   1400095e8 <_lock>
   140008ec9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ecd:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008ed0:	80 cc 80             	or     ah,0x80
   140008ed3:	89 c2                	mov    edx,eax
   140008ed5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ed9:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008edc:	eb 15                	jmp    140008ef3 <_lock_file+0x83>
   140008ede:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ee2:	48 83 c0 30          	add    rax,0x30
   140008ee6:	48 89 c1             	mov    rcx,rax
   140008ee9:	48 8b 05 08 73 00 00 	mov    rax,QWORD PTR [rip+0x7308]        # 1400101f8 <__imp_EnterCriticalSection>
   140008ef0:	ff d0                	call   rax
   140008ef2:	90                   	nop
   140008ef3:	90                   	nop
   140008ef4:	48 83 c4 20          	add    rsp,0x20
   140008ef8:	5d                   	pop    rbp
   140008ef9:	c3                   	ret

0000000140008efa <_unlock_file>:
   140008efa:	55                   	push   rbp
   140008efb:	48 89 e5             	mov    rbp,rsp
   140008efe:	48 83 ec 20          	sub    rsp,0x20
   140008f02:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f06:	b9 00 00 00 00       	mov    ecx,0x0
   140008f0b:	e8 e0 00 00 00       	call   140008ff0 <__acrt_iob_func>
   140008f10:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008f14:	72 52                	jb     140008f68 <_unlock_file+0x6e>
   140008f16:	b9 13 00 00 00       	mov    ecx,0x13
   140008f1b:	e8 d0 00 00 00       	call   140008ff0 <__acrt_iob_func>
   140008f20:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f24:	72 42                	jb     140008f68 <_unlock_file+0x6e>
   140008f26:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f2a:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008f2d:	80 e4 7f             	and    ah,0x7f
   140008f30:	89 c2                	mov    edx,eax
   140008f32:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f36:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008f39:	b9 00 00 00 00       	mov    ecx,0x0
   140008f3e:	e8 ad 00 00 00       	call   140008ff0 <__acrt_iob_func>
   140008f43:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f47:	48 29 c2             	sub    rdx,rax
   140008f4a:	48 c1 fa 04          	sar    rdx,0x4
   140008f4e:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008f55:	aa aa aa 
   140008f58:	48 0f af c2          	imul   rax,rdx
   140008f5c:	83 c0 10             	add    eax,0x10
   140008f5f:	89 c1                	mov    ecx,eax
   140008f61:	e8 8a 06 00 00       	call   1400095f0 <_unlock>
   140008f66:	eb 15                	jmp    140008f7d <_unlock_file+0x83>
   140008f68:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f6c:	48 83 c0 30          	add    rax,0x30
   140008f70:	48 89 c1             	mov    rcx,rax
   140008f73:	48 8b 05 b6 72 00 00 	mov    rax,QWORD PTR [rip+0x72b6]        # 140010230 <__imp_LeaveCriticalSection>
   140008f7a:	ff d0                	call   rax
   140008f7c:	90                   	nop
   140008f7d:	90                   	nop
   140008f7e:	48 83 c4 20          	add    rsp,0x20
   140008f82:	5d                   	pop    rbp
   140008f83:	c3                   	ret
   140008f84:	90                   	nop
   140008f85:	90                   	nop
   140008f86:	90                   	nop
   140008f87:	90                   	nop
   140008f88:	90                   	nop
   140008f89:	90                   	nop
   140008f8a:	90                   	nop
   140008f8b:	90                   	nop
   140008f8c:	90                   	nop
   140008f8d:	90                   	nop
   140008f8e:	90                   	nop
   140008f8f:	90                   	nop

0000000140008f90 <_set_invalid_parameter_handler>:
   140008f90:	55                   	push   rbp
   140008f91:	48 89 e5             	mov    rbp,rsp
   140008f94:	48 83 ec 10          	sub    rsp,0x10
   140008f98:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f9c:	48 8d 05 dd 6b 00 00 	lea    rax,[rip+0x6bdd]        # 14000fb80 <handler>
   140008fa3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008fa7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fab:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008faf:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140008fb3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008fb7:	48 87 10             	xchg   QWORD PTR [rax],rdx
   140008fba:	48 89 d0             	mov    rax,rdx
   140008fbd:	48 83 c4 10          	add    rsp,0x10
   140008fc1:	5d                   	pop    rbp
   140008fc2:	c3                   	ret

0000000140008fc3 <_get_invalid_parameter_handler>:
   140008fc3:	55                   	push   rbp
   140008fc4:	48 89 e5             	mov    rbp,rsp
   140008fc7:	48 8b 05 b2 6b 00 00 	mov    rax,QWORD PTR [rip+0x6bb2]        # 14000fb80 <handler>
   140008fce:	5d                   	pop    rbp
   140008fcf:	c3                   	ret

0000000140008fd0 <_configthreadlocale>:
   140008fd0:	55                   	push   rbp
   140008fd1:	48 89 e5             	mov    rbp,rsp
   140008fd4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008fd7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   140008fdb:	75 07                	jne    140008fe4 <_configthreadlocale+0x14>
   140008fdd:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140008fe2:	eb 05                	jmp    140008fe9 <_configthreadlocale+0x19>
   140008fe4:	b8 02 00 00 00       	mov    eax,0x2
   140008fe9:	5d                   	pop    rbp
   140008fea:	c3                   	ret
   140008feb:	90                   	nop
   140008fec:	90                   	nop
   140008fed:	90                   	nop
   140008fee:	90                   	nop
   140008fef:	90                   	nop

0000000140008ff0 <__acrt_iob_func>:
   140008ff0:	55                   	push   rbp
   140008ff1:	48 89 e5             	mov    rbp,rsp
   140008ff4:	48 83 ec 20          	sub    rsp,0x20
   140008ff8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008ffb:	e8 b0 05 00 00       	call   1400095b0 <__iob_func>
   140009000:	48 89 c1             	mov    rcx,rax
   140009003:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140009006:	48 89 d0             	mov    rax,rdx
   140009009:	48 01 c0             	add    rax,rax
   14000900c:	48 01 d0             	add    rax,rdx
   14000900f:	48 c1 e0 04          	shl    rax,0x4
   140009013:	48 01 c8             	add    rax,rcx
   140009016:	48 83 c4 20          	add    rsp,0x20
   14000901a:	5d                   	pop    rbp
   14000901b:	c3                   	ret
   14000901c:	90                   	nop
   14000901d:	90                   	nop
   14000901e:	90                   	nop
   14000901f:	90                   	nop

0000000140009020 <wcrtomb>:
   140009020:	55                   	push   rbp
   140009021:	48 89 e5             	mov    rbp,rsp
   140009024:	48 83 ec 40          	sub    rsp,0x40
   140009028:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000902c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009030:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009034:	e8 5f 05 00 00       	call   140009598 <___lc_codepage_func>
   140009039:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000903c:	e8 5f 05 00 00       	call   1400095a0 <___mb_cur_max_func>
   140009041:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140009044:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   140009048:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   14000904c:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   140009050:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009054:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140009057:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   14000905b:	48 89 c1             	mov    rcx,rax
   14000905e:	e8 7d 00 00 00       	call   1400090e0 <__mingw_wcrtomb_cp>
   140009063:	48 83 c4 40          	add    rsp,0x40
   140009067:	5d                   	pop    rbp
   140009068:	c3                   	ret
   140009069:	90                   	nop
   14000906a:	90                   	nop
   14000906b:	90                   	nop
   14000906c:	90                   	nop
   14000906d:	90                   	nop
   14000906e:	90                   	nop
   14000906f:	90                   	nop

0000000140009070 <mbrtowc>:
   140009070:	55                   	push   rbp
   140009071:	48 89 e5             	mov    rbp,rsp
   140009074:	48 83 ec 40          	sub    rsp,0x40
   140009078:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000907c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009080:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009084:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009088:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   14000908d:	75 0b                	jne    14000909a <mbrtowc+0x2a>
   14000908f:	48 8d 05 fa 6a 00 00 	lea    rax,[rip+0x6afa]        # 14000fb90 <state_mbrtowc.0>
   140009096:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000909a:	e8 f9 04 00 00       	call   140009598 <___lc_codepage_func>
   14000909f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400090a2:	e8 f9 04 00 00       	call   1400095a0 <___mb_cur_max_func>
   1400090a7:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400090aa:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   1400090ae:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   1400090b2:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400090b6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400090ba:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   1400090bd:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   1400090c1:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   1400090c4:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   1400090c8:	48 89 c1             	mov    rcx,rax
   1400090cb:	e8 70 01 00 00       	call   140009240 <__mingw_mbrtowc_cp>
   1400090d0:	48 83 c4 40          	add    rsp,0x40
   1400090d4:	5d                   	pop    rbp
   1400090d5:	c3                   	ret
   1400090d6:	90                   	nop
   1400090d7:	90                   	nop
   1400090d8:	90                   	nop
   1400090d9:	90                   	nop
   1400090da:	90                   	nop
   1400090db:	90                   	nop
   1400090dc:	90                   	nop
   1400090dd:	90                   	nop
   1400090de:	90                   	nop
   1400090df:	90                   	nop

00000001400090e0 <__mingw_wcrtomb_cp>:
   1400090e0:	55                   	push   rbp
   1400090e1:	48 89 e5             	mov    rbp,rsp
   1400090e4:	48 83 ec 50          	sub    rsp,0x50
   1400090e8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090ec:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400090f0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090f4:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   1400090f8:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400090fd:	75 1b                	jne    14000911a <__mingw_wcrtomb_cp+0x3a>
   1400090ff:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009104:	74 0a                	je     140009110 <__mingw_wcrtomb_cp+0x30>
   140009106:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000910a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009110:	b8 01 00 00 00       	mov    eax,0x1
   140009115:	e9 17 01 00 00       	jmp    140009231 <__mingw_wcrtomb_cp+0x151>
   14000911a:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   14000911f:	74 21                	je     140009142 <__mingw_wcrtomb_cp+0x62>
   140009121:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140009125:	8b 00                	mov    eax,DWORD PTR [rax]
   140009127:	85 c0                	test   eax,eax
   140009129:	74 17                	je     140009142 <__mingw_wcrtomb_cp+0x62>
   14000912b:	e8 a8 04 00 00       	call   1400095d8 <_errno>
   140009130:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009136:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000913d:	e9 ef 00 00 00       	jmp    140009231 <__mingw_wcrtomb_cp+0x151>
   140009142:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009146:	66 85 c0             	test   ax,ax
   140009149:	75 18                	jne    140009163 <__mingw_wcrtomb_cp+0x83>
   14000914b:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009150:	74 07                	je     140009159 <__mingw_wcrtomb_cp+0x79>
   140009152:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009156:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140009159:	b8 01 00 00 00       	mov    eax,0x1
   14000915e:	e9 ce 00 00 00       	jmp    140009231 <__mingw_wcrtomb_cp+0x151>
   140009163:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   140009167:	75 2b                	jne    140009194 <__mingw_wcrtomb_cp+0xb4>
   140009169:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   14000916d:	66 3d ff 00          	cmp    ax,0xff
   140009171:	0f 87 a4 00 00 00    	ja     14000921b <__mingw_wcrtomb_cp+0x13b>
   140009177:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000917c:	74 0c                	je     14000918a <__mingw_wcrtomb_cp+0xaa>
   14000917e:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009182:	89 c2                	mov    edx,eax
   140009184:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009188:	88 10                	mov    BYTE PTR [rax],dl
   14000918a:	b8 01 00 00 00       	mov    eax,0x1
   14000918f:	e9 9d 00 00 00       	jmp    140009231 <__mingw_wcrtomb_cp+0x151>
   140009194:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000919b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   1400091a1:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   1400091a5:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   1400091a8:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   1400091ac:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   1400091b1:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   1400091b8:	00 00 
   1400091ba:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   1400091bd:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   1400091c1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400091c5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400091ca:	41 b9 01 00 00 00    	mov    r9d,0x1
   1400091d0:	49 89 c8             	mov    r8,rcx
   1400091d3:	ba 00 00 00 00       	mov    edx,0x0
   1400091d8:	89 c1                	mov    ecx,eax
   1400091da:	48 8b 05 8f 70 00 00 	mov    rax,QWORD PTR [rip+0x708f]        # 140010270 <__imp_WideCharToMultiByte>
   1400091e1:	ff d0                	call   rax
   1400091e3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400091e6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400091ea:	74 32                	je     14000921e <__mingw_wcrtomb_cp+0x13e>
   1400091ec:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400091ef:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   1400091f2:	7f 2a                	jg     14000921e <__mingw_wcrtomb_cp+0x13e>
   1400091f4:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400091f7:	85 c0                	test   eax,eax
   1400091f9:	75 23                	jne    14000921e <__mingw_wcrtomb_cp+0x13e>
   1400091fb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400091fe:	48 63 c8             	movsxd rcx,eax
   140009201:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009205:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009209:	49 89 c8             	mov    r8,rcx
   14000920c:	48 89 c1             	mov    rcx,rax
   14000920f:	e8 34 04 00 00       	call   140009648 <memcpy>
   140009214:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009217:	48 98                	cdqe
   140009219:	eb 16                	jmp    140009231 <__mingw_wcrtomb_cp+0x151>
   14000921b:	90                   	nop
   14000921c:	eb 01                	jmp    14000921f <__mingw_wcrtomb_cp+0x13f>
   14000921e:	90                   	nop
   14000921f:	e8 b4 03 00 00       	call   1400095d8 <_errno>
   140009224:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000922a:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009231:	48 83 c4 50          	add    rsp,0x50
   140009235:	5d                   	pop    rbp
   140009236:	c3                   	ret
   140009237:	90                   	nop
   140009238:	90                   	nop
   140009239:	90                   	nop
   14000923a:	90                   	nop
   14000923b:	90                   	nop
   14000923c:	90                   	nop
   14000923d:	90                   	nop
   14000923e:	90                   	nop
   14000923f:	90                   	nop

0000000140009240 <__mingw_mbrtowc_cp>:
   140009240:	55                   	push   rbp
   140009241:	48 89 e5             	mov    rbp,rsp
   140009244:	48 83 ec 50          	sub    rsp,0x50
   140009248:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000924c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009250:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009254:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009258:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   14000925d:	75 1b                	jne    14000927a <__mingw_mbrtowc_cp+0x3a>
   14000925f:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   140009266:	00 
   140009267:	48 8d 05 b2 22 00 00 	lea    rax,[rip+0x22b2]        # 14000b520 <.rdata>
   14000926e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140009272:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   140009279:	00 
   14000927a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000927e:	8b 00                	mov    eax,DWORD PTR [rax]
   140009280:	3d ff 00 00 00       	cmp    eax,0xff
   140009285:	0f 87 b9 01 00 00    	ja     140009444 <__mingw_mbrtowc_cp+0x204>
   14000928b:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009290:	75 0c                	jne    14000929e <__mingw_mbrtowc_cp+0x5e>
   140009292:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009299:	e9 bc 01 00 00       	jmp    14000945a <__mingw_mbrtowc_cp+0x21a>
   14000929e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400092a2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400092a4:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400092a7:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   1400092ab:	75 0c                	jne    1400092b9 <__mingw_mbrtowc_cp+0x79>
   1400092ad:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400092b1:	84 c0                	test   al,al
   1400092b3:	0f 85 8e 01 00 00    	jne    140009447 <__mingw_mbrtowc_cp+0x207>
   1400092b9:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   1400092bd:	75 2c                	jne    1400092eb <__mingw_mbrtowc_cp+0xab>
   1400092bf:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400092c4:	74 11                	je     1400092d7 <__mingw_mbrtowc_cp+0x97>
   1400092c6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400092ca:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400092cd:	0f b6 d0             	movzx  edx,al
   1400092d0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400092d4:	66 89 10             	mov    WORD PTR [rax],dx
   1400092d7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400092db:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400092de:	84 c0                	test   al,al
   1400092e0:	0f 95 c0             	setne  al
   1400092e3:	0f b6 c0             	movzx  eax,al
   1400092e6:	e9 6f 01 00 00       	jmp    14000945a <__mingw_mbrtowc_cp+0x21a>
   1400092eb:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400092f2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400092f9:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400092fd:	84 c0                	test   al,al
   1400092ff:	74 1a                	je     14000931b <__mingw_mbrtowc_cp+0xdb>
   140009301:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009305:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009308:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000930b:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140009312:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140009319:	eb 73                	jmp    14000938e <__mingw_mbrtowc_cp+0x14e>
   14000931b:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   14000931f:	75 5c                	jne    14000937d <__mingw_mbrtowc_cp+0x13d>
   140009321:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009325:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009328:	0f b6 c0             	movzx  eax,al
   14000932b:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000932e:	89 c1                	mov    ecx,eax
   140009330:	e8 ab 01 00 00       	call   1400094e0 <__mingw_isleadbyte_cp>
   140009335:	85 c0                	test   eax,eax
   140009337:	74 44                	je     14000937d <__mingw_mbrtowc_cp+0x13d>
   140009339:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000933d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009340:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009343:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   140009348:	77 15                	ja     14000935f <__mingw_mbrtowc_cp+0x11f>
   14000934a:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000934d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009351:	89 10                	mov    DWORD PTR [rax],edx
   140009353:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   14000935a:	e9 fb 00 00 00       	jmp    14000945a <__mingw_mbrtowc_cp+0x21a>
   14000935f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009363:	48 83 c0 01          	add    rax,0x1
   140009367:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000936a:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000936d:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140009374:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   14000937b:	eb 11                	jmp    14000938e <__mingw_mbrtowc_cp+0x14e>
   14000937d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009381:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009384:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009387:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000938e:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009392:	84 c0                	test   al,al
   140009394:	75 24                	jne    1400093ba <__mingw_mbrtowc_cp+0x17a>
   140009396:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000939b:	74 09                	je     1400093a6 <__mingw_mbrtowc_cp+0x166>
   14000939d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400093a1:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   1400093a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400093aa:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400093b0:	b8 00 00 00 00       	mov    eax,0x0
   1400093b5:	e9 a0 00 00 00       	jmp    14000945a <__mingw_mbrtowc_cp+0x21a>
   1400093ba:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   1400093be:	75 08                	jne    1400093c8 <__mingw_mbrtowc_cp+0x188>
   1400093c0:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   1400093c4:	84 c0                	test   al,al
   1400093c6:	74 64                	je     14000942c <__mingw_mbrtowc_cp+0x1ec>
   1400093c8:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   1400093ce:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   1400093d2:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400093d6:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   1400093d9:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   1400093e0:	00 
   1400093e1:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   1400093e5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400093ea:	45 89 c1             	mov    r9d,r8d
   1400093ed:	49 89 c8             	mov    r8,rcx
   1400093f0:	ba 08 00 00 00       	mov    edx,0x8
   1400093f5:	89 c1                	mov    ecx,eax
   1400093f7:	48 8b 05 42 6e 00 00 	mov    rax,QWORD PTR [rip+0x6e42]        # 140010240 <__imp_MultiByteToWideChar>
   1400093fe:	ff d0                	call   rax
   140009400:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140009403:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   140009407:	75 26                	jne    14000942f <__mingw_mbrtowc_cp+0x1ef>
   140009409:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000940e:	74 0b                	je     14000941b <__mingw_mbrtowc_cp+0x1db>
   140009410:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   140009414:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009418:	66 89 10             	mov    WORD PTR [rax],dx
   14000941b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000941f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009425:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009428:	48 98                	cdqe
   14000942a:	eb 2e                	jmp    14000945a <__mingw_mbrtowc_cp+0x21a>
   14000942c:	90                   	nop
   14000942d:	eb 01                	jmp    140009430 <__mingw_mbrtowc_cp+0x1f0>
   14000942f:	90                   	nop
   140009430:	e8 a3 01 00 00       	call   1400095d8 <_errno>
   140009435:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000943b:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009442:	eb 16                	jmp    14000945a <__mingw_mbrtowc_cp+0x21a>
   140009444:	90                   	nop
   140009445:	eb 01                	jmp    140009448 <__mingw_mbrtowc_cp+0x208>
   140009447:	90                   	nop
   140009448:	e8 8b 01 00 00       	call   1400095d8 <_errno>
   14000944d:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009453:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000945a:	48 83 c4 50          	add    rsp,0x50
   14000945e:	5d                   	pop    rbp
   14000945f:	c3                   	ret

0000000140009460 <fallback_IsDBCSLeadByteEx>:
   140009460:	55                   	push   rbp
   140009461:	48 89 e5             	mov    rbp,rsp
   140009464:	48 83 ec 40          	sub    rsp,0x40
   140009468:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000946b:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   14000946e:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   140009472:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009475:	89 c1                	mov    ecx,eax
   140009477:	48 8b 05 8a 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d8a]        # 140010208 <__imp_GetCPInfo>
   14000947e:	ff d0                	call   rax
   140009480:	85 c0                	test   eax,eax
   140009482:	74 51                	je     1400094d5 <fallback_IsDBCSLeadByteEx+0x75>
   140009484:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140009487:	83 f8 02             	cmp    eax,0x2
   14000948a:	75 49                	jne    1400094d5 <fallback_IsDBCSLeadByteEx+0x75>
   14000948c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009493:	eb 2c                	jmp    1400094c1 <fallback_IsDBCSLeadByteEx+0x61>
   140009495:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009498:	48 98                	cdqe
   14000949a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000949f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   1400094a2:	72 19                	jb     1400094bd <fallback_IsDBCSLeadByteEx+0x5d>
   1400094a4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400094a7:	83 c0 01             	add    eax,0x1
   1400094aa:	48 98                	cdqe
   1400094ac:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400094b1:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   1400094b4:	72 07                	jb     1400094bd <fallback_IsDBCSLeadByteEx+0x5d>
   1400094b6:	b8 01 00 00 00       	mov    eax,0x1
   1400094bb:	eb 1d                	jmp    1400094da <fallback_IsDBCSLeadByteEx+0x7a>
   1400094bd:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400094c1:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   1400094c5:	7f 0e                	jg     1400094d5 <fallback_IsDBCSLeadByteEx+0x75>
   1400094c7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400094ca:	48 98                	cdqe
   1400094cc:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400094d1:	84 c0                	test   al,al
   1400094d3:	75 c0                	jne    140009495 <fallback_IsDBCSLeadByteEx+0x35>
   1400094d5:	b8 00 00 00 00       	mov    eax,0x0
   1400094da:	48 83 c4 40          	add    rsp,0x40
   1400094de:	5d                   	pop    rbp
   1400094df:	c3                   	ret

00000001400094e0 <__mingw_isleadbyte_cp>:
   1400094e0:	55                   	push   rbp
   1400094e1:	48 89 e5             	mov    rbp,rsp
   1400094e4:	48 83 ec 40          	sub    rsp,0x40
   1400094e8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400094eb:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400094ee:	48 8b 05 ab 66 00 00 	mov    rax,QWORD PTR [rip+0x66ab]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400094f5:	48 85 c0             	test   rax,rax
   1400094f8:	75 71                	jne    14000956b <__mingw_isleadbyte_cp+0x8b>
   1400094fa:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140009501:	00 
   140009502:	48 8d 05 27 20 00 00 	lea    rax,[rip+0x2027]        # 14000b530 <.rdata>
   140009509:	48 89 c1             	mov    rcx,rax
   14000950c:	48 8b 05 05 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d05]        # 140010218 <__imp_GetModuleHandleA>
   140009513:	ff d0                	call   rax
   140009515:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140009519:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000951e:	74 1b                	je     14000953b <__mingw_isleadbyte_cp+0x5b>
   140009520:	48 8d 15 16 20 00 00 	lea    rdx,[rip+0x2016]        # 14000b53d <.rdata+0xd>
   140009527:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000952b:	48 89 c1             	mov    rcx,rax
   14000952e:	48 8b 05 eb 6c 00 00 	mov    rax,QWORD PTR [rip+0x6ceb]        # 140010220 <__imp_GetProcAddress>
   140009535:	ff d0                	call   rax
   140009537:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000953b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140009540:	75 0b                	jne    14000954d <__mingw_isleadbyte_cp+0x6d>
   140009542:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 140009460 <fallback_IsDBCSLeadByteEx>
   140009549:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000954d:	48 8d 05 4c 66 00 00 	lea    rax,[rip+0x664c]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009554:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140009558:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000955c:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140009560:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140009564:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140009568:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000956b:	4c 8b 05 2e 66 00 00 	mov    r8,QWORD PTR [rip+0x662e]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009572:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009575:	0f b6 d0             	movzx  edx,al
   140009578:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000957b:	89 c1                	mov    ecx,eax
   14000957d:	41 ff d0             	call   r8
   140009580:	48 83 c4 40          	add    rsp,0x40
   140009584:	5d                   	pop    rbp
   140009585:	c3                   	ret
   140009586:	90                   	nop
   140009587:	90                   	nop
   140009588:	90                   	nop
   140009589:	90                   	nop
   14000958a:	90                   	nop
   14000958b:	90                   	nop
   14000958c:	90                   	nop
   14000958d:	90                   	nop
   14000958e:	90                   	nop
   14000958f:	90                   	nop

0000000140009590 <__C_specific_handler>:
   140009590:	ff 25 ea 6c 00 00    	jmp    QWORD PTR [rip+0x6cea]        # 140010280 <__imp___C_specific_handler>
   140009596:	90                   	nop
   140009597:	90                   	nop

0000000140009598 <___lc_codepage_func>:
   140009598:	ff 25 ea 6c 00 00    	jmp    QWORD PTR [rip+0x6cea]        # 140010288 <__imp____lc_codepage_func>
   14000959e:	90                   	nop
   14000959f:	90                   	nop

00000001400095a0 <___mb_cur_max_func>:
   1400095a0:	ff 25 ea 6c 00 00    	jmp    QWORD PTR [rip+0x6cea]        # 140010290 <__imp____mb_cur_max_func>
   1400095a6:	90                   	nop
   1400095a7:	90                   	nop

00000001400095a8 <__getmainargs>:
   1400095a8:	ff 25 ea 6c 00 00    	jmp    QWORD PTR [rip+0x6cea]        # 140010298 <__imp___getmainargs>
   1400095ae:	90                   	nop
   1400095af:	90                   	nop

00000001400095b0 <__iob_func>:
   1400095b0:	ff 25 f2 6c 00 00    	jmp    QWORD PTR [rip+0x6cf2]        # 1400102a8 <__imp___iob_func>
   1400095b6:	90                   	nop
   1400095b7:	90                   	nop

00000001400095b8 <__set_app_type>:
   1400095b8:	ff 25 f2 6c 00 00    	jmp    QWORD PTR [rip+0x6cf2]        # 1400102b0 <__imp___set_app_type>
   1400095be:	90                   	nop
   1400095bf:	90                   	nop

00000001400095c0 <__setusermatherr>:
   1400095c0:	ff 25 f2 6c 00 00    	jmp    QWORD PTR [rip+0x6cf2]        # 1400102b8 <__imp___setusermatherr>
   1400095c6:	90                   	nop
   1400095c7:	90                   	nop

00000001400095c8 <_amsg_exit>:
   1400095c8:	ff 25 f2 6c 00 00    	jmp    QWORD PTR [rip+0x6cf2]        # 1400102c0 <__imp__amsg_exit>
   1400095ce:	90                   	nop
   1400095cf:	90                   	nop

00000001400095d0 <_cexit>:
   1400095d0:	ff 25 f2 6c 00 00    	jmp    QWORD PTR [rip+0x6cf2]        # 1400102c8 <__imp__cexit>
   1400095d6:	90                   	nop
   1400095d7:	90                   	nop

00000001400095d8 <_errno>:
   1400095d8:	ff 25 fa 6c 00 00    	jmp    QWORD PTR [rip+0x6cfa]        # 1400102d8 <__imp__errno>
   1400095de:	90                   	nop
   1400095df:	90                   	nop

00000001400095e0 <_initterm>:
   1400095e0:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 1400102e8 <__imp__initterm>
   1400095e6:	90                   	nop
   1400095e7:	90                   	nop

00000001400095e8 <_lock>:
   1400095e8:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 1400102f0 <__imp__lock>
   1400095ee:	90                   	nop
   1400095ef:	90                   	nop

00000001400095f0 <_unlock>:
   1400095f0:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 1400102f8 <__imp__unlock>
   1400095f6:	90                   	nop
   1400095f7:	90                   	nop

00000001400095f8 <_crt_atexit>:
   1400095f8:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010300 <__imp__crt_atexit>
   1400095fe:	90                   	nop
   1400095ff:	90                   	nop

0000000140009600 <abort>:
   140009600:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010308 <__imp_abort>
   140009606:	90                   	nop
   140009607:	90                   	nop

0000000140009608 <calloc>:
   140009608:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010310 <__imp_calloc>
   14000960e:	90                   	nop
   14000960f:	90                   	nop

0000000140009610 <exit>:
   140009610:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010318 <__imp_exit>
   140009616:	90                   	nop
   140009617:	90                   	nop

0000000140009618 <fflush>:
   140009618:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010320 <__imp_fflush>
   14000961e:	90                   	nop
   14000961f:	90                   	nop

0000000140009620 <fprintf>:
   140009620:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010328 <__imp_fprintf>
   140009626:	90                   	nop
   140009627:	90                   	nop

0000000140009628 <fputc>:
   140009628:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010330 <__imp_fputc>
   14000962e:	90                   	nop
   14000962f:	90                   	nop

0000000140009630 <free>:
   140009630:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010338 <__imp_free>
   140009636:	90                   	nop
   140009637:	90                   	nop

0000000140009638 <localeconv>:
   140009638:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010340 <__imp_localeconv>
   14000963e:	90                   	nop
   14000963f:	90                   	nop

0000000140009640 <malloc>:
   140009640:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010348 <__imp_malloc>
   140009646:	90                   	nop
   140009647:	90                   	nop

0000000140009648 <memcpy>:
   140009648:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010350 <__imp_memcpy>
   14000964e:	90                   	nop
   14000964f:	90                   	nop

0000000140009650 <setvbuf>:
   140009650:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010358 <__imp_setvbuf>
   140009656:	90                   	nop
   140009657:	90                   	nop

0000000140009658 <signal>:
   140009658:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010360 <__imp_signal>
   14000965e:	90                   	nop
   14000965f:	90                   	nop

0000000140009660 <strcpy>:
   140009660:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010368 <__imp_strcpy>
   140009666:	90                   	nop
   140009667:	90                   	nop

0000000140009668 <strerror>:
   140009668:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010370 <__imp_strerror>
   14000966e:	90                   	nop
   14000966f:	90                   	nop

0000000140009670 <strlen>:
   140009670:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010378 <__imp_strlen>
   140009676:	90                   	nop
   140009677:	90                   	nop

0000000140009678 <strncmp>:
   140009678:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010380 <__imp_strncmp>
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <vfprintf>:
   140009680:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010388 <__imp_vfprintf>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <wcslen>:
   140009688:	ff 25 02 6d 00 00    	jmp    QWORD PTR [rip+0x6d02]        # 140010390 <__imp_wcslen>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <WideCharToMultiByte>:
   140009690:	ff 25 da 6b 00 00    	jmp    QWORD PTR [rip+0x6bda]        # 140010270 <__imp_WideCharToMultiByte>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <VirtualQuery>:
   140009698:	ff 25 ca 6b 00 00    	jmp    QWORD PTR [rip+0x6bca]        # 140010268 <__imp_VirtualQuery>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <VirtualProtect>:
   1400096a0:	ff 25 ba 6b 00 00    	jmp    QWORD PTR [rip+0x6bba]        # 140010260 <__imp_VirtualProtect>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <TlsGetValue>:
   1400096a8:	ff 25 aa 6b 00 00    	jmp    QWORD PTR [rip+0x6baa]        # 140010258 <__imp_TlsGetValue>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <Sleep>:
   1400096b0:	ff 25 9a 6b 00 00    	jmp    QWORD PTR [rip+0x6b9a]        # 140010250 <__imp_Sleep>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <SetUnhandledExceptionFilter>:
   1400096b8:	ff 25 8a 6b 00 00    	jmp    QWORD PTR [rip+0x6b8a]        # 140010248 <__imp_SetUnhandledExceptionFilter>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <MultiByteToWideChar>:
   1400096c0:	ff 25 7a 6b 00 00    	jmp    QWORD PTR [rip+0x6b7a]        # 140010240 <__imp_MultiByteToWideChar>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <LoadLibraryA>:
   1400096c8:	ff 25 6a 6b 00 00    	jmp    QWORD PTR [rip+0x6b6a]        # 140010238 <__imp_LoadLibraryA>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <LeaveCriticalSection>:
   1400096d0:	ff 25 5a 6b 00 00    	jmp    QWORD PTR [rip+0x6b5a]        # 140010230 <__imp_LeaveCriticalSection>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <InitializeCriticalSection>:
   1400096d8:	ff 25 4a 6b 00 00    	jmp    QWORD PTR [rip+0x6b4a]        # 140010228 <__imp_InitializeCriticalSection>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <GetProcAddress>:
   1400096e0:	ff 25 3a 6b 00 00    	jmp    QWORD PTR [rip+0x6b3a]        # 140010220 <__imp_GetProcAddress>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop

00000001400096e8 <GetModuleHandleA>:
   1400096e8:	ff 25 2a 6b 00 00    	jmp    QWORD PTR [rip+0x6b2a]        # 140010218 <__imp_GetModuleHandleA>
   1400096ee:	90                   	nop
   1400096ef:	90                   	nop

00000001400096f0 <GetLastError>:
   1400096f0:	ff 25 1a 6b 00 00    	jmp    QWORD PTR [rip+0x6b1a]        # 140010210 <__imp_GetLastError>
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop

00000001400096f8 <GetCPInfo>:
   1400096f8:	ff 25 0a 6b 00 00    	jmp    QWORD PTR [rip+0x6b0a]        # 140010208 <__imp_GetCPInfo>
   1400096fe:	90                   	nop
   1400096ff:	90                   	nop

0000000140009700 <FreeLibrary>:
   140009700:	ff 25 fa 6a 00 00    	jmp    QWORD PTR [rip+0x6afa]        # 140010200 <__imp_FreeLibrary>
   140009706:	90                   	nop
   140009707:	90                   	nop

0000000140009708 <EnterCriticalSection>:
   140009708:	ff 25 ea 6a 00 00    	jmp    QWORD PTR [rip+0x6aea]        # 1400101f8 <__imp_EnterCriticalSection>
   14000970e:	90                   	nop
   14000970f:	90                   	nop

0000000140009710 <DeleteCriticalSection>:
   140009710:	ff 25 da 6a 00 00    	jmp    QWORD PTR [rip+0x6ada]        # 1400101f0 <__IAT_start__>
   140009716:	90                   	nop
   140009717:	90                   	nop
   140009718:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000971f:	00 

0000000140009720 <register_frame_ctor>:
   140009720:	e9 4b 7f ff ff       	jmp    140001670 <__gcc_register_frame>
   140009725:	90                   	nop
   140009726:	90                   	nop
   140009727:	90                   	nop
   140009728:	90                   	nop
   140009729:	90                   	nop
   14000972a:	90                   	nop
   14000972b:	90                   	nop
   14000972c:	90                   	nop
   14000972d:	90                   	nop
   14000972e:	90                   	nop
   14000972f:	90                   	nop
